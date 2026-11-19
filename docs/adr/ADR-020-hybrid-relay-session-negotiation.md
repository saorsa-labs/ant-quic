# ADR-020: Hybrid Relay Session Negotiation and Verified Relay-to-Direct Migration

- **Status:** Proposed
- **Date:** 2026-11-19
- **Decision owners:** David Irvine
- **Reviewers:** to be assigned
- **Supersedes:** none. It adds rules that [ADR-016](ADR-016-hybrid-relay-data-plane.md) leaves
  open; ADR-016 is not edited.
- **Superseded by:** none
- **Related:** ant-quic PR #372; [ADR-016](ADR-016-hybrid-relay-data-plane.md),
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

1. **Per-session hybrid signal.** A relay session uses the datagram lane only when both ends signal
   it in that session's CONNECT-UDP exchange:
   - The client sets request flag bit `0x02` (`REQUEST_FLAG_HYBRID_DATAGRAM_LANE`) only when it runs
     `hybrid` and holds the datagram lane of the outer connection (rule 2).
   - The relay sets response flag bit `0x04` (`RESPONSE_FLAG_HYBRID_DATAGRAM_LANE`) only when it
     runs `hybrid`, the request carried `0x02`, and it holds the datagram lane of that connection.
   - Without both bits, the session is stream-only in both directions.
   - QUIC `DATAGRAM` support in transport parameters is not a signal.
   - Decoders up to 0.28.0 read only bit `0x01` of the request and bits `0x01`/`0x02` of the
     response. An old relay ignores `0x02` and never answers `0x04`; an old client never sends
     `0x02`. Old peers always get the stream lane. A message without the new bit is byte-identical
     to the 0.28.0 encoding.
2. **One datagram reader per outer connection.** A hybrid session holds a claim on the outer
   connection's datagram lane for its lifetime. While it holds the claim, a second hybrid session on
   that connection is served on the stream lane, and `LinkConn::recv_datagrams` on that connection
   returns an empty stream and logs a warning. While a `recv_datagrams` reader runs, no hybrid
   session can claim that connection (the session uses the stream lane). Consequence for
   `recv_datagrams` users such as x0x voice: when hybrid relaying is turned on and the relay
   session shares the peer connection that voice reads datagrams from, the first reader wins and
   the other is refused, not silently starved. Hybrid stays off by default, so default behaviour is
   unchanged.
3. **`P_max` floor.** `P_max = max_datagram_size(outer) - encapsulation header`. If
   `P_max < 1200 B + 32 B` (`MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET` = 1232 B), the datagram lane is not
   used. At or above the floor, every non-Initial packet of up to `P_max` bytes takes the datagram
   lane, including a full 1200 B short-header packet; every Initial takes the stream lane. A datagram
   the outer connection refuses falls back to the stream lane. **The 32 B margin is provisional**
   until the ADR-016 soak measures it.
4. **Migration success.** A relay-to-direct migration succeeds only when all hold:
   - a NEW direct QUIC handshake (never an existing connection) authenticates the same `PeerId`;
   - that connection becomes the peer's live connection in the connection table;
   - the peer answers an ADR-017 probe on that connection (for a peer without probe support, the
     registered connection must still be open).
   If a check fails after registration, the new connection is closed and the relay entry restored.
   After success the relayed connection is Superseded and the ADR-017 retirement executor closes it.
   At most one migration task runs per `PeerId`, and the number of tasks per endpoint is bounded.
5. **`auto_migrate` defaults to `false`.** Relay-to-direct migration is opt-in until a fleet soak
   proves it.

## Consequences

### Positive

- Mixed-version and mixed-mode relay sessions keep working in both directions.
- Packet loss from competing datagram readers cannot happen silently.
- Migration counters mean what they say, and retirement stays with ADR-017.

### Negative / Trade-offs

- One hybrid session per outer connection, and hybrid excludes `recv_datagrams` on that connection
  until a real demultiplexer exists.
- On paths that stay at a 1200 B MTU, hybrid uses only the stream lane.
- Migration is off unless configured.

### Neutral / Operational

- Wire change: two flag bits, used only by peers configured `hybrid`. Needs ant-quic 0.29.0.

## Validation

- `src/masque/connect.rs`: `hybrid_request_signal_is_one_flag_bit_and_backward_compatible`,
  `hybrid_response_signal_roundtrips_and_keeps_layout`.
- `src/masque/relay_server.rs`: `hybrid_server_stream_client_uses_stream_lane_both_directions`,
  `hybrid_server_hybrid_client_uses_datagram_lane_both_directions`,
  `stream_server_hybrid_client_uses_stream_lane_both_directions`,
  `hybrid_session_over_budget_floor_falls_back_to_stream_lane`,
  `one_hybrid_session_per_connection_is_enforced`.
- `src/masque/relay_socket.rs`: `datagram_budget_is_never_below_initial_size_plus_margin`.
- `src/p2p_endpoint.rs` (`relay_migration_372`):
  `migration_probe_never_reports_success_on_relay_only_path`,
  `migration_switches_to_new_direct_connection_and_retires_relay`,
  `migration_task_ends_when_relayed_connection_closes`,
  `migration_task_registry_is_atomic_keyed_and_bounded`.
- `src/unified_config.rs`: `test_relay_forward_mode_and_migration_builder_propagate` asserts
  `auto_migrate` is false by default.
- Revisit: when the ADR-016 soak reports `P_max` data (margin), when a per-session demultiplexer
  is designed (rule 2), and before `auto_migrate` defaults to true.

## Notes for AI-assisted work

Drafted with AI assistance during the PR #372 takeover. AI tools must not mark it Accepted; only a
human does. Accepted ADRs are immutable: create a new superseding ADR rather than editing an
Accepted ADR.
