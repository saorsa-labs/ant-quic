# ADR-020: Hybrid Relay Session Negotiation and Verified Relay-to-Direct Migration

- **Status:** Accepted (2026-11-25). Accepted by David Irvine in chat, 2026-11-25, together with ADR-021 (satisfying ADR-021's acceptance-ordering constraint).
- **Date:** 2026-11-19 (amended 2026-11-22 for ant-quic 0.30.0 / #374)
- **Decision owners:** David Irvine
- **Reviewers:** to be assigned
- **Supersedes:** [ADR-016](ADR-016-hybrid-relay-data-plane.md) Decision 3 (1,200 B + margin `P_max` floor); adds rules that ADR-016 leaves open. ADR-016 itself is Accepted and is not edited.
- **Superseded by:** none
- **Related:** ant-quic PR #372, issue #374; [ADR-016](ADR-016-hybrid-relay-data-plane.md),
  [ADR-017](ADR-017-single-arbiter-connection-retirement.md),
  [ADR-009](ADR-009-masque-relay-data-plane.md), [ADR-006](ADR-006-masque-relay-fallback.md)

## Context

ADR-016 (Accepted) chose a two-lane relay data plane: small non-Initial packets as QUIC `DATAGRAM`
frames, Initial and oversized packets on the length-prefixed stream. It says the mode is per
session (Decision 6) and that `P_max` is never below "1200 B + margin" (Decision 3). It does not
say how the two ends agree on the mode, what the margin is, or how relay datagrams are told apart
from other datagrams on the same connection.

The first implementation (PR #372 at c7633a89) chose the datagram lane when the outer connection
supported QUIC datagrams. Every peer advertises that transport parameter, including 0.28.0 peers
that never read the relay datagram lane, so relay replies to them were lost. Relay datagrams carry
Context ID `0` and no session identifier, so two readers on one connection (a second relay session,
or `LinkConn::recv_datagrams`) took each other's packets.

The same PR started relay-to-direct migration. A relayed peer is stored with
`remote_addr = target`, so the address-based reuse check returned the relayed connection itself as
the "direct" result, and migration reported success without migrating.

## Decision Drivers

- Peers on 0.28.0 must keep working with no protocol break.
- No silent packet loss or packet theft between datagram readers.
- A migration counted as successful must have moved the peer's traffic to a new direct path.
- Connection retirement must stay under ADR-017.

## Considered Options

1. Use the QUIC `DATAGRAM` transport parameter as the hybrid signal. Rejected: every peer sends it.
2. A new capsule exchange after CONNECT-UDP. Rejected: an extra round trip, and an old peer would
   see an unknown capsule.
3. One flag bit in the existing CONNECT-UDP request and one in the response. Chosen: old decoders
   ignore unknown flag bits, and no message grows.

## Decision

1. **Per-session hybrid & datagram-mux signal.** A relay session uses the datagram lane only when
   both ends signal it in that session's CONNECT-UDP exchange:
   - Request bit `0x02` (`REQUEST_FLAG_HYBRID_DATAGRAM_LANE`, 0.29.0+): client accepts either
     legacy exclusive hybrid (0.29.0) or muxed hybrid (0.30.0+).
   - Request bit `0x04` (`REQUEST_FLAG_DATAGRAM_MUX_V1`, 0.30.0+): client supports RFC 9297
     Context-ID `DatagramMux`, `COMPRESSION_ASSIGN` / `ECN_COMPRESSION_ASSIGN` capsules on the
     relay stream, and 4-context ECN mapping.
   - When the outer connection negotiated the `DatagramMuxV1 (0x50C4)` QUIC transport parameter
     (`0.30.0+` ↔ `0.30.0+`), a hybrid client sets `0x04` (`REQUEST_FLAG_DATAGRAM_MUX_V1`) to
     select per-session Context-ID + compression + ECN mode; the relay answers `0x04 | 0x08`
     (`RESPONSE_FLAG_HYBRID_DATAGRAM_LANE | RESPONSE_FLAG_DATAGRAM_MUX_V1`) when in `Hybrid` mode.
   - When the peer did NOT advertise `DatagramMuxV1 (0x50C4)` (`0.28.0`/`0.29.0`), the client sets
     `0x02` only (never `0x04`) if no `LinkConn::recv_datagrams` reader is active, and stays
     stream-only (`0x00`) if an app reader is active so a `0.29.0` peer never suffers packet theft.
   - Without `0x04` (`RESPONSE_FLAG_HYBRID_DATAGRAM_LANE`) in the response, the session is
     stream-only in both directions.
   - QUIC `DATAGRAM` support (`max_datagram_frame_size`) is not a hybrid signal; `DatagramMuxV1
     (0x50C4)` negotiates connection-level Context-ID framing, and CONNECT-UDP flags negotiate
     per-session hybrid forwarding.
   - Decoders up to 0.28.0 ignore unknown bits (`0x02`/`0x04` in request, `0x04`/`0x08` in
     response) and always get stream-only. Decoders on 0.29.0 lack `0x50C4` and negotiate legacy
     exclusive hybrid only when `0x02` is set.
2. **Connection-level `DatagramMuxV1 (0x50C4)` QUIC transport parameter & RFC 9297 Context-ID
   `DatagramMux` (replaces exclusive single-reader limit on `0.30.0+` connections).**
   - `DatagramMuxV1` (`0x50C4`, zero-length empty QUIC transport parameter, enabled by default via
     `TransportConfig::datagram_mux_v1(true)`) is exchanged during the QUIC handshake. Mutual
     advertisement (`Connection::supports_datagram_mux_v1()`) makes Context-ID datagram framing a
     static, immutable property of the connection from datagram #1 to close — eliminating all
     mid-connection raw→prefixed transitions, soft windows, byte-sniffing, and abort-path races.
     `TransportParameters::validate_resumption_from` rejects any `datagram_mux_v1` mismatch on
     0-RTT resumption.
   - On a connection where `supports_datagram_mux_v1()` is `true`, a single per-connection
     `DatagramMux` reader task (tracked in `DATAGRAM_MUXES` via a `WeakConnectionHandle` with
     doubling amortized O(1) dead-entry pruning so idle connections never leak as zombies) owns
     `Connection::read_datagram()` and dispatches frames strictly by leading QUIC `VarInt`
     Context ID:
     - **Context ID `0` (even):** reserved exclusively for legacy `0.29.0` non-muxed hybrid
       sessions (`0x02` without `0x04`); NEVER used on `DatagramMuxV1` sessions.
     - **Client-allocated even Context IDs `>= 2` (disjoint per QUIC side):** ONLY the relay
       client allocates Context IDs (the relay server never self-allocates). To keep mutual
       relaying on one outer connection collision-free, `Side::Client` allocates 8-ID blocks
       `{2..=8, 18..=24, ...}` and `Side::Server` allocates `{10..=16, 26..=32, ...}`, recycling
       freed blocks after a 30-second quarantine (`CTX_BLOCK_REUSE_COOLDOWN`) so wire IDs stay
       `1–2 B` under churn without colliding with in-flight relay stream teardowns or stale
       in-flight datagrams (and any stale datagram that ever arrived on a recycled ctx after
       quarantine is still bounded to a single inner AEAD failure). Each `mux_v1` session
       registers strictly **one** uncompressed Context ID via `CompressionAssign::uncompressed`
       (re-assigning replaces and unregisters the previous one; if the relay replies
       `CompressionClose`, the client performs up to 3 bounded retries with fresh disjoint blocks),
       plus up to `max_targets` (256) compressed 4-context ECN quads; total routes per connection
       are hard-capped at `MAX_MUX_ROUTES_PER_CONNECTION = 2048` and odd Context IDs are rejected
       with `CompressionClose`.
     - **Odd Context ID `1` (`APP_DATAGRAM_CONTEXT_ID`):** multiplexed application datagrams
       (`LinkConn::send_datagram` / `LinkConn::recv_datagrams`, such as x0x voice), prefixed from
       datagram #1 on every `DatagramMuxV1` connection and disjoint from even MASQUE Context IDs.
     - **Unknown/closed Context IDs:** always dropped and counted (`mux_unknown_ctx_dropped`) and
       never passed raw to app subscribers.
   - When `supports_datagram_mux_v1()` is `false` (peers on `0.28.0`/`0.29.0` or connections with
     `datagram_mux_v1(false)`), `LinkConn::send_datagram` and `recv_datagrams` carry 100% raw
     unprefixed bytes (0 extra bytes), and legacy `0.29.0` exclusive hybrid (`0x02` without `0x04`)
     retains the single-reader lock so a `0.29.0` peer cannot suffer packet theft with
     `LinkConn::recv_datagrams`. Note: raw `Connection::send_datagram` and
     `Connection::read_datagram` remain low-level transport primitives that bypass
     `APP_DATAGRAM_CONTEXT_ID` framing (and raw `read_datagram` would race with the per-connection
     `DatagramMux` dispatcher); callers sharing a `DatagramMuxV1` connection (including x0x voice
     on the 0.30 pin bump) MUST use `LinkConn::send_datagram` and `LinkConn::recv_datagrams`.
3. **`COMPRESSION_ASSIGN` socket data plane & `draft-seemann-masque-connect-udp-ecn-01` ECN
   propagation (when `DATAGRAM_MUX_V1` is negotiated).**
   - On the relay bidirectional stream, data frames remain `[4 B BE len][UncompressedDatagram]`
     (starting with Context ID `0x00`), while control capsules are framed as
     `[4 B BE len][0xFF][Capsule]` with exact body consumption (trailing bytes rejected; never
     sent to 0.28.0/0.29.0 peers).
   - At session start, the client sends `CompressionAssign::uncompressed(u_ctx)` and waits for
     `CompressionAck(u_ctx)` before sending uncompressed datagrams (packets sent pre-ACK ride the
     stream lane with zero loss). On first outbound packet to a target, the client allocates 4
     consecutive even Context IDs `{base, base+2, base+4, base+6}` from its side's disjoint pool
     and sends `Capsule::EcnCompressionAssign (0x14)` on the stream. Once
     `Capsule::CompressionAck(base)` arrives, both sides switch that target to
     `CompressedDatagram` (`[Context ID (1–2 B)][Payload]`):
     - `base + 0`: `Not-ECT`
     - `base + 2`: `ECT(0)`
     - `base + 4`: `ECT(1)`
     - `base + 6`: `CE`
   - Per-packet relay overhead drops from `8 B` (IPv4) / `20 B` (IPv6) to `1–2 B`, while
     propagating inner ECN (`Transmit.ecn` / `RecvMeta.ecn`) end-to-end via
     `quinn_udp::UdpSocketState` (splitting Linux `UDP_GRO` `stride`-coalesced bursts into
     individual datagrams) at **0 extra bytes** per packet.
4. **Supersedes ADR-016 Decision 3 — `900 B` `P_max` floor, transport-layer sub-1200 virtual-path
   MTU clamp, locked DPLPMTUD, and inner `PATH_CHALLENGE` rule.**
   - **Floor lowered from `1,232 B` to `900 B`:** `MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET = 900`.
     `P_max = max_datagram_size(outer) - active_encapsulation_header_len` (`1–2 B` compressed,
     `8 B` v4 / `20 B` v6 uncompressed). On a 1,280 B IPv6 / WireGuard / Cloudflare WARP path
     (`max_datagram_size(outer) ≈ 1,180–1,192 B`), `P_max` clears `900 B` so hybrid uses the
     datagram lane instead of silently degrading to stream-only TCP-over-TCP.
   - **Transport-layer virtual-path sub-1200 MTU floor exemption:** Standard physical paths keep
     the `INITIAL_MTU = 1200` hard floor in `TransportConfig::initial_mtu` / `min_mtu`. Relayed
     virtual paths opt into `TransportConfig::virtual_path_max_udp_payload_size(Some(clamped))`
     (floor `MIN_VIRTUAL_PATH_MTU = 900`), where `clamped = min(P_max, 1380)` is computed from
     the outer connection's datagram budget at shared relay endpoint creation (static clamp for
     `0.30.0`; if outer MTU shrinks mid-session, live per-packet `conn.max_datagram_size()` checks
     fall back safely to the stream lane; dynamic mid-session inner re-clamping is deferred to
     Wave 4's unified socket ADR):
     1. Inner Initial packets (`SpaceId::Initial`) still pad to `MIN_INITIAL_SIZE = 1200 B` per
        RFC 9000 §14.1 (and remote endpoints accept them) because MASQUE routes all Initials on the
        reliable stream lane.
     2. Once Initial keys are discarded, all post-handshake 1-RTT (`SpaceId::Data`) packets are
        clamped to `clamped` and inner DPLPMTUD is locked at `clamped` (never probing above the
        outer datagram budget). Result: **0% steady-state stream-lane spill** at the creation-time
        outer MTU and no steady-state cross-lane packet reordering; RFC 9002 handles the
        Initial→1-RTT transition natively.
     3. **Inner `PATH_CHALLENGE` / `PATH_RESPONSE` rule (RFC 9000 §8.2.1):** Datagrams carrying
        `PATH_CHALLENGE` or `PATH_RESPONSE` retain their `1200 B` RFC 9000 §8.2.1 padding. When
        `1200 > P_max` on a sub-1200 virtual MASQUE path, `select_relay_lane` routes them over the
        reliable stream lane automatically (a virtual MASQUE path has no physical MTU to validate
        via 1,200 B probes, so stream-lane delivery avoids silent drops without violating
        RFC 9000 §8.2.1).
   - **Soak gate:** `RelayForwardMode::Hybrid` stays off by default until a netem soak at 1,280 B
     MTU confirms sustained datagram-lane delivery with zero steady-state stream spill.
5. **Migration success.** A relay-to-direct migration succeeds only when all hold:
   - a NEW direct QUIC handshake (never an existing connection) authenticates the same `PeerId`;
   - that connection becomes the peer's live connection in the connection table;
   - the peer answers an ADR-017 probe on that connection (for a peer without probe support, the
     registered connection must still be open).
   If a check fails after registration, the new connection is closed and the relay entry restored.
   After success the relayed connection is Superseded and the ADR-017 retirement executor closes it.
   At most one migration task runs per `PeerId`, and the number of tasks per endpoint is bounded.
6. **`auto_migrate` defaults to `false`.** Relay-to-direct migration is opt-in until a fleet soak
   proves it.

## Consequences

### Positive

- Mixed-version (0.28.0, 0.29.0, 0.30.0+) and mixed-mode relay sessions keep working in both
  directions with zero wire break for direct peers.
- Hybrid MASQUE and `LinkConn::recv_datagrams` (e.g., x0x voice) coexist concurrently on the same
  outer connection with zero packet theft; multiple hybrid sessions can also share one connection.
- Hybrid MASQUE now actually uses the datagram lane on 1,280 B IPv6, WireGuard, PPPoE, and
  Cloudflare WARP paths with 0% steady-state stream spill and 1–2 B compressed headers.
- End-to-end ECN propagates through the relay at 0 extra bytes per packet.
- Migration counters mean what they say, and retirement stays with ADR-017.

### Negative / Trade-offs

- On connections where both peers negotiate `DatagramMuxV1 (0x50C4)`, `LinkConn::send_datagram`
  adds a 1-byte Context ID prefix (`0x01`) from datagram #1; connections with `0.28.0`/`0.29.0`
  peers (without `0x50C4`) add 0 bytes.
- Inner Initials and 1,200 B `PATH_CHALLENGE` probes on sub-1200 virtual paths still traverse the
  stream lane, while 1-RTT data uses the datagram lane.
- Hybrid and `auto_migrate` stay off by default until the 1,280 B netem soak passes.

### Neutral / Operational

- Wire change: one connection-level zero-length QUIC transport parameter `DatagramMuxV1 (0x50C4)`
  (0.30.0+ default enabled), two per-session CONNECT-UDP flag bits (`0x04` request, `0x08`
  response), `0xFF` stream capsule framing, and `0x14` `ECN_COMPRESSION_ASSIGN` capsule — gated
  cleanly on mutual negotiation so 0.28.0/0.29.0 peers keep raw framing.

## Validation

- `src/transport_parameters.rs`: `test_datagram_mux_v1_roundtrip_and_validation`.
- `src/masque/connect.rs`: `hybrid_request_signal_is_one_flag_bit_and_backward_compatible`,
  `hybrid_response_signal_roundtrips_and_keeps_layout`,
  `datagram_mux_v1_flag_bits_roundtrip_and_stay_backward_compatible`.
- `src/masque/capsule.rs`: `ecn_compression_assign_capsule_roundtrips_v4_and_v6`.
- `src/masque/relay_socket.rs`: `datagram_budget_respects_900b_floor_and_compressed_overhead`,
  `ecn_context_id_mapping_roundtrips_all_codepoints`,
  `path_challenge_over_sub_1200_virtual_path_rides_stream_lane`.
- `src/masque/relay_server.rs`: `hybrid_server_stream_client_uses_stream_lane_both_directions`,
  `hybrid_server_hybrid_client_uses_datagram_lane_both_directions`,
  `stream_server_hybrid_client_uses_stream_lane_both_directions`,
  `hybrid_1200b_outer_mtu_uses_datagram_lane_and_spills_oversize_to_stream`,
  `hybrid_session_below_900b_floor_falls_back_to_stream_lane`,
  `hybrid_1280b_outer_mtu_uses_datagram_lane_with_compression_and_ecn`,
  `muxed_hybrid_and_link_datagrams_coexist_on_same_connection`,
  `virtual_path_sub_1200_mtu_clamps_1rtt_while_preserving_1200b_initial`,
  `split_gro_datagram_chunks_preserves_every_coalesced_packet`,
  `mutual_relaying_on_one_connection_has_disjoint_contexts`,
  `session_reuse_after_close_uses_clean_explicit_context`,
  `uncompressed_compression_assign_spam_is_bounded_and_odd_ctx_rejected`,
  `hard_mux_drops_unknown_ctx_without_leaking_to_app_subscribers`,
  `datagram_mux_v1_transport_param_prefixes_from_packet_one_and_survives_aborts`,
  `legacy_029_peer_without_datagram_mux_v1_stays_raw_and_uses_legacy_fallback`,
  `uncompressed_ctx_close_retries_fresh_block_and_reaches_datagram_lane`,
  `quarantined_freed_block_is_not_immediately_reused`,
  `dropped_connection_does_not_leak_in_datagram_muxes`,
  `one_hybrid_session_per_connection_is_enforced` (legacy 0.29.0 compat).
- `src/p2p_endpoint.rs` (`relay_migration_372`):
  `migration_probe_never_reports_success_on_relay_only_path`,
  `migration_switches_to_new_direct_connection_and_retires_relay`,
  `migration_task_ends_when_relayed_connection_closes`,
  `migration_task_registry_is_atomic_keyed_and_bounded`.
- `src/unified_config.rs`: `test_relay_forward_mode_and_migration_builder_propagate` asserts
  `auto_migrate` is false by default.
- Revisit: after the 1,280 B netem soak before flipping `Hybrid` or `auto_migrate` defaults in x0x.

## Notes for AI-assisted work

Drafted with AI assistance during the PR #372 takeover. AI tools must not mark it Accepted; only a
human does. Accepted ADRs are immutable: create a new superseding ADR rather than editing an
Accepted ADR.
