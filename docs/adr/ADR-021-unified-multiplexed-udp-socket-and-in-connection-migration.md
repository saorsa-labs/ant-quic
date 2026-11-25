# ADR-021: Unified MultiplexedUdpSocket, In-Connection Relay-to-Direct Migration, Single-Process Dual-Port, and Staged Multipath/NAT64 Follow-Ons

- **Status:** Proposed
- **Date:** 2026-11-25
- **Decision owners:** David Irvine
- **Reviewers:** to be assigned
- **Supersedes:** [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 4's static creation-time-only virtual-path clamp (replaced by per-path dynamic virtual MTU hints) and Decision 5's new-handshake relay-to-direct migration path for peers negotiating `InConnectionMigrationV1` (Decision 5 remains the compatibility fallback for `<= 0.30.x` peers). Does **not** edit any Accepted ADR.
- **Superseded by:** none
- **Related:** `saorsa-labs/ant-quic#375`, `saorsa-labs/ant-quic#374`, PR `#376`, PR `#379`; [ADR-003](ADR-003-pure-post-quantum-cryptography.md), [ADR-004](ADR-004-symmetric-p2p-architecture.md), [ADR-005](ADR-005-native-quic-nat-traversal.md), [ADR-006](ADR-006-masque-relay-fallback.md), [ADR-009](ADR-009-masque-relay-data-plane.md), [ADR-011](ADR-011-transport-scope-terminology.md), [ADR-012](ADR-012-standards-basis-refresh.md), [ADR-014](ADR-014-relay-resource-governance.md), [ADR-015](ADR-015-paced-candidate-spray-punching.md), [ADR-016](ADR-016-hybrid-relay-data-plane.md), [ADR-017](ADR-017-single-arbiter-connection-retirement.md), [ADR-020](ADR-020-hybrid-relay-session-negotiation.md); downstream `x0x` ADRs `0011` (dual-listen UDP/443) and `0032` (`:443` own identity).

## Context

Three structural limitations in `ant-quic`'s current socket and connection-endpoint architecture create compounding bandwidth, CPU, memory, and operational overhead across pure-PQC deployments (`ML-KEM-768` + `ML-DSA-65`, [ADR-003](ADR-003-pure-post-quantum-cryptography.md)):

1. **Two separate QUIC `Endpoint`s prevent true RFC 9000 §9 in-connection migration.**
   Today `NatTraversalEndpoint` runs its primary `InnerEndpoint` over `DualStackSocket` (`src/high_level/runtime/dual_stack.rs`) and lazily spins up a **second** `shared_relay_endpoint: Arc<Mutex<Option<InnerEndpoint>>>` (`src/nat_traversal_api.rs:1814, 7864-7944`) over `MasqueRelaySocket` (`src/masque/relay_socket.rs:1746`). Because QUIC connection IDs and `Connection` state are owned by a single `Endpoint`, a relayed connection established on `shared_relay_endpoint` **cannot migrate in place** onto a physical direct UDP path:
   - [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 5 (`src/p2p_endpoint.rs:7513`) must therefore open a **brand-new** direct QUIC handshake (~15 KiB pure-PQC `ML-KEM-768` + `ML-DSA-65` exchange), register a new connection generation, and retire the relayed connection through [ADR-017](ADR-017-single-arbiter-connection-retirement.md).
   - That generation rollover tears down active streams, resets `saorsa-gossip` SG76 key caches and Wave 2 capability state, and triggers anti-entropy / catch-up bursts (the `x0x#2152` catch-up-spike class).
   - Furthermore, [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 4 (`src/config/transport.rs:44`, `src/connection/paths.rs:88-100`) had to attach `virtual_path_max_udp_payload_size` at the endpoint-wide `TransportConfig` level and freeze it at `shared_relay_endpoint` creation time (leaving dynamic mid-session inner re-clamping explicitly deferred to Wave 4).

2. **Single-port `DualStackSocket` prevents single-process dual-port VPS listeners (P7).**
   `DualStackSocket` (`src/high_level/runtime/dual_stack.rs:47-61`) wraps at most one IPv4 socket and one IPv6 socket and routes outbound packets strictly by address family. `NatTraversalConfig::additional_bind_addrs` (`src/nat_traversal_api.rs:2048, 3180`) only advertises additional candidate addresses — it does not bind extra sockets or preserve per-remote source-port affinity. Consequently, downstream bootstrap/relay hosts (`x0x` ADRs `0011` and `0032`) must run **two separate `x0xd` processes with two distinct identities** per VPS (one on UDP `:443` and one on UDP `:5483`), doubling per-host gossip egress, RSS, seed-list identities, and operational surface.

3. **The active Connection ID pool (`CidQueue::LEN = 5`) starves ADR-015 `N = 8` paced candidate spraying.**
   `CidQueue::LEN` is currently `5` (`src/cid_queue.rs:139`), so `TransportParameters::new` (`src/transport_parameters.rs:220`) advertises `active_connection_id_limit = 5`, while `LOC_CID_COUNT` is `8` (`src/lib.rs:679`; `issue_cids_limit()` at `src/transport_parameters.rs:279`). RFC 9000 §9.5 requires each probed path to use a previously unused Destination Connection ID for path unlinkability. With only 4 spare CIDs (`5 - 1 active`), an [ADR-015](ADR-015-paced-candidate-spray-punching.md) `N = 8` concurrent spray exhausts spare CIDs halfway through round 1. In addition, `Connection::migrate` (`src/connection/mod.rs:3801-3846`) immediately replaces `self.path` before the new path is validated — unsafe for speculative hole punching where most sprayed pairs fail.

4. **Remaining connectivity edges (mobile handoffs, IPv6-only NAT64, UDP-blocked networks).**
   Once real sockets and virtual paths live under one unified `AsyncUdpSocket`, three well-scoped follow-ons become structurally straightforward without re-architecting the transport: `draft-ietf-quic-multipath` (`PATH_STANDBY` relay failover for 0 ms Wi-Fi↔5G handoffs), `PREF64`/NAT64 synthesis (RFC 7050/8880/8781 for IPv6-only mobile carriers reaching IPv4-only relays), and an optional pure-PQC TLS 1.3 (`ML-KEM-768` + `ML-DSA-65`) over TCP/443 last-resort relay.

## Decision Drivers

- **100% Pure Post-Quantum Cryptography ([ADR-003](ADR-003-pure-post-quantum-cryptography.md)):** Every direct path, MASQUE tunnel, in-connection migration, and any optional TCP/443 last-resort relay MUST use `ML-KEM-768` + `ML-DSA-65` only — zero classical X25519/Ed25519 fallback or delegated classical keys.
- **Zero PQC re-handshake on relay-to-direct upgrade:** Upgrading a relayed connection to a punched direct path must preserve the live `Connection`, its streams, its `AuthenticatedSession` generation, and upper-layer session caches (`saorsa-gossip` SG76 + Wave 2 capabilities).
- **Non-disruptive speculative punching:** Probing `N = 8` direct candidates must never interrupt traffic flowing on the working MASQUE virtual path, must obey RFC 9000 §9.5 CID unlinkability and 3× anti-amplification ([ADR-015](ADR-015-paced-candidate-spray-punching.md)), and must promote a direct path only after valid `PATH_RESPONSE`.
- **Single-process dual-port (`:443` + `:5483`) without spoof-hijacking:** A single VPS process with one `PeerId` must reply from the exact local port (`:443` or `:5483`) each peer dialed, even if one remote client dials both ports from the same ephemeral source port, and unvalidated spoofed packets must never hijack an established connection's source-port affinity. Clients must remain unprivileged (never binding `<1024`).
- **Strict backwards compatibility (`<= 0.30.x`):** All new wire behaviour must be gated behind negotiated QUIC transport parameters ([ADR-012](ADR-012-standards-basis-refresh.md)); peers on `<= 0.30.x` must continue working with zero protocol break via [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 5's fallback.
- **ADR-017 preservation:** [ADR-017](ADR-017-single-arbiter-connection-retirement.md) single-arbiter connection retirement must remain intact for genuine multi-connection races and legacy peers.
- **Staged delivery:** Core unified socket + in-connection migration + P7 dual-port (Phase 4A) must ship and soak independently of Multipath (Phase 4B) and NAT64/TCP-443 (Phase 4C).

## Considered Options

1. **Keep dual `InnerEndpoint`s (`DualStackSocket` + `shared_relay_endpoint`) and optimize new-handshake migration.**
   - *Rejected:* Cannot avoid the ~15 KiB pure-PQC re-handshake, cannot preserve open streams or `saorsa-gossip` SG76/Wave-2 session generations across relay→direct upgrades, cannot solve single-process dual-port `:443`+`:5483` VPS consolidation, and cannot dynamically switch a connection between virtual sub-1200 MTU and physical DPLPMTUD.
2. **Unified `MultiplexedUdpSocket` using real peer `SocketAddr`s for relayed paths (reusing ADR-020's address stamping).**
   - *Rejected:* Stamping relayed packets with the target peer's real `SocketAddr` collides inside a single `Endpoint` with direct candidate probes to that same `SocketAddr` (the exact collision observed in [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Context). Quinn's `Connection::migrate` cannot distinguish a relayed path from a direct path if both carry the identical `SocketAddr`.
3. **Key multi-port (`:443` / `:5483`) source-socket affinity strictly on `remote_addr` inside `AsyncUdpSocket`.**
   - *Rejected as sole mechanism:* Vulnerable to (a) collision when a single client dials both `:443` and `:5483` from the same ephemeral source port, and (b) source-port affinity hijacking if an unauthenticated attacker spoofs a UDP packet with a victim's `remote_addr` toward the secondary port.
4. **Unified `MultiplexedUdpSocket` with `local_slot` path tagging, disjoint synthetic IPv6 virtual-path addressing (`fd00:53a0:5251::/48`), per-path virtual MTU, `CidQueue::LEN = LOC_CID_COUNT = 16`, and negotiated non-disruptive RFC 9000 §9 migration (Chosen).**
   - *Chosen:* Solves all three architectural gaps in one coherent substrate while preserving `quinn_udp` GSO/GRO/ECN, [ADR-017](ADR-017-single-arbiter-connection-retirement.md), [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) `DatagramMuxV1`, and `<= 0.30.x` backwards compatibility, and cleanly stages Multipath and NAT64/TCP-443 as Phase 4B/4C follow-ons.

## Decision

We will adopt a three-phase architecture centered on a single unified `MultiplexedUdpSocket` per `P2pEndpoint` (**Phase 4A**), followed by **Phase 4B** (QUIC Multipath `PATH_STANDBY`) and **Phase 4C** (`PREF64`/NAT64 synthesis and optional pure-PQC TCP/443 last-resort relay). Each phase ships behind opt-in config/negotiation and clears its own soak gate before any default flip.

### Phase 4A — Unified `MultiplexedUdpSocket`, P7 Dual-Port, and True In-Connection Migration

#### 1. Single `InnerEndpoint` over `MultiplexedUdpSocket: AsyncUdpSocket`

Replace `DualStackSocket` (`src/high_level/runtime/dual_stack.rs`) and the separate `shared_relay_endpoint` (`src/nat_traversal_api.rs:1814, 7864-7944`) + `MasqueRelaySocket` (`src/masque/relay_socket.rs:1746`) with a single `MultiplexedUdpSocket` implementing `AsyncUdpSocket` (`src/high_level/runtime.rs:49`) for the node's sole `InnerEndpoint`:

- **Physical socket groups (`SocketSlotId(u8)`, up to `MAX_PHYSICAL_SLOTS = 4`):**
  - Slot `0` is the primary dual-stack pair `(Option<UdpSocket v4>, Option<UdpSocket v6>)` with paired `quinn_udp::UdpSocketState`s (preserving kernel `recvmmsg`, `UDP_GRO`, `UDP_GSO`, `DF`, and ECN on both families, identical to today's `DualStackSocket`).
  - Additional bind ports (e.g. VPS listening on both `:443` in slot `0` and `:5483` in slot `1`, configured via a dedicated multi-bind config surface — keeping `NatTraversalConfig::additional_bind_addrs` semantics backward-compatible or promoting explicit local bind ports without breaking clients, which default to 1 unprivileged ephemeral slot) each allocate a `SocketSlotId` with their own `(v4, v6, UdpSocketState)`.
  - `AsyncUdpSocket::local_addrs()` returns every bound physical `SocketAddr` across all slots so shutdown and diagnostics inspect all descriptors cleanly.
- **Spoof-resistant per-path `local_slot` affinity (delivering P7 single-process dual-port):**
  - Thread a 1-byte `local_slot: SocketSlotId` alongside `RecvMeta` / `Transmit` inside `ant-quic`'s internal `Endpoint` ↔ `Connection` ↔ `PathData` path:
    1. `MultiplexedUdpSocket::poll_recv` tags every received datagram with the `SocketSlotId` of the physical socket that received it (or `SocketSlotId::VIRTUAL` for virtual MASQUE routes).
    2. `Connection::handle_packet` records `local_slot` on the validated `PathData` (`src/connection/paths.rs:23`), and `Connection::poll_transmit` propagates `self.path.local_slot` (or the speculative probe's `local_slot`) onto outbound `Transmit`s.
    3. `MultiplexedUdpSocket::send` routes every established connection packet strictly via `Transmit.local_slot`, never consulting a spoofable IP-only map.
    4. For stateless replies that have no `Connection` state (`Retry`, `VersionNegotiation`, stateless reset), the stateless reply path echoes the triggering packet's `RecvMeta.local_slot` directly (zero persistent state, zero spoof-hijacking, zero collision even when one remote client dials both `:443` and `:5483` from the exact same ephemeral port!).
    5. Outbound dials default to `SocketSlotId(0)` (e.g. `:443` on dual-port VPS, ephemeral high port on clients — preserving `x0x/ADR-0011` Decision 2 that clients never bind privileged ports).
- **Disjoint synthetic IPv6 virtual-path address space (`fd00:53a0:5251::/48`):**
  - Every active virtual MASQUE route `(relay_slot: u16, target_addr: SocketAddr)` is assigned a unique synthetic IPv6 `SocketAddr` inside the internal non-routable prefix **`fd00:53a0:5251::/48`**:
    ```text
    [ 48 bits: fd00:53a0:5251 ][ 16 bits: relay_slot ][ 32 bits: route_gen ][ 32 bits: target_idx ]
    port: target_addr.port().max(1)
    ```
  - **Hard isolation invariant:** Physical socket `send()` MUST reject any destination inside `fd00:53a0:5251::/48` with `io::ErrorKind::InvalidInput`; physical `poll_recv()` MUST drop any packet whose source IP falls inside `fd00:53a0:5251::/48` (counted as `synthetic_prefix_spoof_dropped`) so a malicious LAN peer can never inject frames into the virtual-path address space.
  - The virtual route table is hard-capped at `MAX_VIRTUAL_ROUTES = 4096` (bounded per-relay and globally per [ADR-014](ADR-014-relay-resource-governance.md)) with monotonic `route_gen` preventing route aliasing across relay reconnects.
  - Because `MultiplexedUdpSocket::local_addr()` returns an IPv6 address whenever any IPv6 socket or virtual route is enabled, Quinn normalizes IPv4 peers to `::ffff:a.b.c.d` while virtual MASQUE paths carry `fd00:53a0:5251::...` — guaranteeing 100% disjointness between a peer's relayed path and every direct IPv4/IPv6 candidate address.
  - Existing [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) MASQUE data-plane mechanics (`DatagramMuxV1 (0x50C4)`, `COMPRESSION_ASSIGN`, 4-context `draft-seemann-masque-connect-udp-ecn-01` ECN mapping, `UDP_GRO` stride splitting, `900 B` `P_max` floor, stream-lane routing for Initials and 1,200 B `PATH_CHALLENGE`s) run unchanged beneath the virtual-route driver in `MultiplexedUdpSocket`.
- **Fair receive scheduling:**
  - `MultiplexedUdpSocket::poll_recv` rotates across all active physical slots and virtual MASQUE receive queues via an atomic cursor (`poll_cursor: AtomicUsize`) with a bounded per-source burst limit so neither physical floods nor relay traffic can starve the other.

#### 2. Dynamic Per-Path Virtual MTU Clamp (Supersedes ADR-020 Decision 4 Static Clamp)

- Move the virtual-path sub-1200 MTU floor exemption from endpoint-wide `TransportConfig::virtual_path_max_udp_payload_size` (`src/config/transport.rs:44`) to **per-path `PathData`** (`src/connection/paths.rs:23`):
  - `AsyncUdpSocket` gains a default method `fn virtual_path_mtu(&self, _remote: SocketAddr) -> Option<u16> { None }`, overridden by `MultiplexedUdpSocket` to return `compute_inner_virtual_path_mtu(outer_conn.max_datagram_size(), active_overhead)` (floor `MIN_VIRTUAL_PATH_MTU = 900`, cap `1380`) when `remote` is in `fd00:53a0:5251::/48`, and `None` for physical addresses.
  - When `PathData` targets a virtual address (`Some(vp_mtu)`): inner Initials keep RFC 9000 §14.1 `1200 B` padding (routed on the MASQUE stream lane), post-handshake 1-RTT packets clamp to `vp_mtu`, inner DPLPMTUD locks at `vp_mtu`, and 1,200 B `PATH_CHALLENGE`/`PATH_RESPONSE` frames ride the stream lane when `1200 > P_max`.
  - **Dynamic mid-session outer-MTU shrink:** When the outer MASQUE connection's `max_datagram_size()` shrinks mid-session (e.g. outer DPLPMTUD blackhole detection), `MultiplexedUdpSocket` notifies active connections on that `relay_slot` (or updates a shared `AtomicU16` per `relay_slot` read by `PathData` on transmit), immediately lowering the virtual path's 1-RTT ceiling and invoking `drop_oversized_datagrams` (`src/connection/mod.rs:3838`) — closing the exact deferral noted in [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 4.
  - When the connection migrates in place to a **physical** direct path (`virtual_path_mtu(remote) == None`): `PathData::new` automatically uses standard `INITIAL_MTU = 1200` and enables full physical DPLPMTUD up to `1,452 B`!

#### 3. CID Pool Expansion (`active_connection_id_limit = 16`)

- Raise `CidQueue::LEN` (`src/cid_queue.rs:139`) from `5` to `16` and `LOC_CID_COUNT` (`src/lib.rs:679`) from `8` to `16`:
  - `TransportParameters::new` (`src/transport_parameters.rs:220`) advertises `active_connection_id_limit = 16` when CID length > 0.
  - `TransportParameters::issue_cids_limit()` (`src/transport_parameters.rs:279`) yields `min(peer_limit, 16)`: `16` between Wave-4 peers (1 active path + `N = 8` concurrent [ADR-015](ADR-015-paced-candidate-spray-punching.md) probes + 2 standby/migration slots + 5 retirement headroom), and gracefully degrades to `5` against `<= 0.30.x` peers with zero wire break.
  - **0-RTT forward compatibility:** `TransportParameters::validate_resumption_from` (`src/transport_parameters.rs:255`) checks `cached.active_connection_id_limit > self.active_connection_id_limit`, so upgrading `5 -> 16` preserves 0-RTT resumption cleanly while rolling back `16 -> 5` safely falls back to 1-RTT.
  - **CID replenishment invariant:** As soon as a probe pair fails or is cancelled upon first `PATH_RESPONSE`, the connection emits `RETIRE_CONNECTION_ID` for unused probe CIDs so the peer replenishes the 16-CID pool ahead of any future migration round.

#### 4. Negotiated Non-Disruptive In-Connection Relay-to-Direct Migration (`InConnectionMigrationV1`)

- **Wire negotiation ([ADR-012](ADR-012-standards-basis-refresh.md) compliance):**
  - Define a new zero-length QUIC transport parameter **`InConnectionMigrationV1` (`0x50C6`)** following ant-quic's even-stride private range (`PqcAlgorithms = 0x50C0`, `AckReceiveV2 = 0x50C2`, `DatagramMuxV1 = 0x50C4` in `src/transport_parameters.rs:1163-1167`), enabled by default via `TransportConfig::in_connection_migration_v1(true)` and validated in `TransportParameters::validate_resumption_from` (symmetric with `datagram_mux_v1`).
  - Author/update `docs/rfcs/ant-quic-nat-traversal.md` (currently absent per [ADR-012](ADR-012-standards-basis-refresh.md) Decision 1) as our normative specification in the implementing PR (citing expired `draft-seemann-quic-nat-traversal-02` §4.4.1 as provenance only).
- **Non-disruptive speculative probing & atomic promotion (replacing destructive pre-validation `migrate()`):**
  - Add a bounded `probing_paths` table on `Connection` (hard-capped at `MAX_CONCURRENT_PROBE_PATHS = 8` matching [ADR-015](ADR-015-paced-candidate-spray-punching.md)) separate from `self.path`:
    1. While active traffic continues uninterrupted over `self.path` (the synthetic MASQUE virtual path), `PUNCH_ME_NOW`-coordinated rounds spray up to `N = 8` `PATH_CHALLENGE` probes (padded to `1,200 B`, paced at `>= max(20 ms, min_rtt/10)`, bounded by RFC 9000 3× anti-amplification) to direct physical candidates, each using a distinct unused remote CID from `rem_cids` (RFC 9000 §9.5) and a fresh 64-bit challenge token.
    2. Incoming `PATH_RESPONSE` frames are matched by token against `probing_paths` (surviving NAT port rebinding per [ADR-015](ADR-015-paced-candidate-spray-punching.md) Decision 3).
    3. On the **first valid `PATH_RESPONSE`** on a physical direct candidate, cancel remaining probes in the round (retiring their unused probe CIDs) and promote that already-validated `PathData` into `self.path`:
       - `self.path.remote = validated_physical_addr`, `self.path.local_slot = probe.local_slot`, `self.path.validated = true`, `self.path.mtud = MtuDiscovery::new(...)` (physical DPLPMTUD active), `rem_cids` switches to the probe's DCID.
       - Move the old virtual MASQUE path into `self.prev_path` for a `3 * max(pto, prev_pto)` drain grace so any in-flight relayed packets still arrive and are acknowledged cleanly, and if the direct path immediately blackholes before completing its first 1-RTT ACK, `Connection` falls back cleanly to `prev_path` without dropping the session!
       - Emit a `PathMigrated { peer_id, old_remote, new_remote, via_relay: false }` event to `P2pEndpoint`, which updates peer path metadata **without replacing the `Connection` handle, without bumping `AuthenticatedSession::generation`, without invoking [ADR-017](ADR-017-single-arbiter-connection-retirement.md) connection retirement, and without resetting `saorsa-gossip` SG76 key caches or Wave 2 capabilities.**
    4. **Compatibility fallback (`<= 0.30.x`):** When either end did not negotiate `InConnectionMigrationV1 (0x50C6)` (or `peer.active_connection_id_limit < 10`, or server set `disable_active_migration`), `P2pEndpoint` automatically uses [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 5's verified new-handshake migration + [ADR-017](ADR-017-single-arbiter-connection-retirement.md) retirement.
  - **`auto_migrate` rollout gate:** `auto_migrate` remains `false` by default until the Wave 4 connection-lifecycle soak passes (matching [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 6).

### Phase 4B — QUIC Multipath (`PATH_STANDBY` Relay Failover)

Deferred to a follow-on PR after Phase 4A soaks cleanly:

- Adopt `draft-ietf-quic-multipath` (active IETF QUIC WG draft; negotiated via `initial_max_path_id` transport parameter, keeping wire codepoints frozen behind negotiation per [ADR-012](ADR-012-standards-basis-refresh.md)).
- Instead of closing the MASQUE virtual path after 3× PTO drain grace, retain it as a **`PATH_STANDBY`** path (`path_id = 0` or dedicated standby ID) with low-frequency keepalive while the direct physical path carries 100% of application data.
- On Wi-Fi↔5G handoff or sudden NAT mapping expiry (detected via PTO loss on the direct path), the scheduler immediately fails traffic over to the already-validated `PATH_STANDBY` relay path in **0 ms** (zero handshake, zero stream loss) while triggering a fresh non-disruptive punch for the new interface.
- **Relay governance ([ADR-014](ADR-014-relay-resource-governance.md)):** Standby MASQUE contexts must carry an idle eviction TTL (e.g. 120 s configurable) and separate quota accounting so idle standby paths cannot starve active relayed clients on VPS relays.

### Phase 4C — `PREF64`/NAT64 Synthesis & Optional Pure-PQC TCP/443 Last-Resort Relay

Deferred to independent follow-on PRs after Phase 4A:

- **`PREF64` / NAT64 synthesis (RFC 7050 / RFC 8880 / RFC 8781):**
  - When a host has IPv6-only connectivity (no default IPv4 route, common on mobile carriers) and needs to reach an IPv4-only bootstrap/relay address, discover the local NAT64 prefix via OS Router Advertisement `PREF64` (RFC 8781, where available) with RFC 7050 `ipv4only.arpa` DNS64 fallback (bounded timeout, cached per interface fingerprint alongside Happy Eyeballs v3 health state from `#374` Part B2).
  - Synthesize RFC 6052 IPv6 addresses (`nat64_prefix || ipv4`) for IPv4-only targets and feed them into the normal Happy Eyeballs v3 dialer. Never synthesize for hosts that already have native IPv4 or native IPv6 reachability to that peer.
- **Optional pure-PQC TLS 1.3 over TCP/443 last-resort relay:**
  - Strictly **opt-in** and **last-resort only** (attempted only after direct UDP, UDP/443 MASQUE, and UDP/5483 MASQUE all fail — targeting UDP-blocked corporate/hotel networks and sub-900 B MTU tunnels).
  - Must use **pure-PQC TLS 1.3 (`ML-KEM-768` + `ML-DSA-65` RPK, zero classical fallback)** per [ADR-003](ADR-003-pure-post-quantum-cryptography.md), carrying length-prefixed QUIC datagrams as a virtual route inside `MultiplexedUdpSocket` (identical `fd00:53a0:5251::/48` abstraction!).
  - Requires its own focused security/DoS review (TCP socket exhaustion, Slowloris/half-open caps, explicit VPS opt-in) before shipping.

## Consequences

### Positive

- **Zero PQC re-handshake on relay→direct upgrades:** Eliminates ~15 KiB ML-KEM-768/ML-DSA-65 handshakes, stream teardowns, [ADR-017](ADR-017-single-arbiter-connection-retirement.md) supersede cycles, and `saorsa-gossip` SG76/Wave-2 session resets during NAT traversal upgrades.
- **Single-process dual-port VPS consolidation (P7):** Enables downstream `x0x` bootstrap/relay hosts to bind both `:443` and `:5483` (IPv4 + IPv6) inside ONE process with ONE `PeerId`, cutting per-host gossip egress and RSS in half and retiring the operational complexity of dual `x0xd` + `x0xd-443` services (`x0x` ADRs `0011` and `0032`).
- **Dynamic virtual-path MTU safety:** Closes [ADR-020](ADR-020-hybrid-relay-session-negotiation.md)'s mid-session outer-MTU shrink deferral and automatically unlocks full physical DPLPMTUD (`1,200 -> 1,452 B`) the instant a connection migrates off a sub-1200 virtual MASQUE path onto a direct path.
- **Unblocked ADR-015 `N = 8` spray with RFC 9000 §9.5 unlinkability:** `CidQueue::LEN = LOC_CID_COUNT = 16` gives every concurrent spray probe its own fresh unused DCID without mid-round CID starvation.
- **Clean foundation for Multipath & NAT64:** `MultiplexedUdpSocket`'s unified virtual+physical path model makes `PATH_STANDBY` and NAT64 synthesis additive rather than disruptive rewrites.

### Negative / Trade-offs

- **Increased internal state complexity in `Connection` and `AsyncUdpSocket`:** Threading `local_slot` across `RecvMeta`/`Transmit`/`PathData`, managing `probing_paths` alongside `self.path`/`prev_path`, and maintaining the `fd00:53a0:5251::/48` virtual route table add carefully audited state-machine surface to `ant-quic`'s core transport loop.
- **Small per-connection memory increase:** Raising `CidQueue::LEN` from `5` to `16` adds ~440 B per live `Connection` (plus ~1 KiB transient state during active `N = 8` probing), negligible relative to a single ~15 KiB PQC handshake.
- **Mixed-fleet dual path during rollout:** Until the fleet upgrades past the Wave 4 release, `P2pEndpoint` must maintain both the new `InConnectionMigrationV1 (0x50C6)` path and the [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 5 new-handshake fallback for `<= 0.30.x` peers.
- **Privileged bind still required on VPS `:443`:** Single-process dual-port removes the *second* process, not OS permission (`CAP_NET_BIND_SERVICE`) on the VPS; clients continue binding only unprivileged ephemeral ports.

### Neutral / Operational

- **New wire parameter:** One zero-length QUIC transport parameter `InConnectionMigrationV1 (0x50C6)` + increased RFC 9000 `active_connection_id_limit` (`5 -> 16`, standard parameter `0x0e`). Zero breaking change for `<= 0.30.x` peers.
- **Downstream `x0x` P7 rollout:** Once `ant-quic` ships Phase 4A, `x0x` can retire `x0xd-443.service` via a separate `x0x` ADR/rollout plan configuring both `:443` and `:5483` bind slots on the primary `x0xd` instance (preserving single `machine.key` identity per host).
- **ADR-017 interaction:** [ADR-017](ADR-017-single-arbiter-connection-retirement.md) remains unmodified and authoritative whenever two distinct connections genuinely coexist (simultaneous open, reconnect, or `<= 0.30.x` fallback).

## Validation

Phase 4A implementation PRs MUST ship with the following unit, integration, and soak gates before `auto_migrate` or single-process dual-port defaults are flipped:

1. **Unit & protocol tests (CI-blocking):**
   - **Multi-port `local_slot` affinity & anti-spoof:** Client dials both `:443` (slot 0) and `:5483` (slot 1) on one `MultiplexedUdpSocket` from the **same** ephemeral source port; verify replies exit the exact local port dialed, and verify spoofed UDP packets injected on the other port with the victim's `remote_addr` NEVER alter the established connection's `local_slot`.
   - **Synthetic prefix isolation (`fd00:53a0:5251::/48`):** Physical socket `send()` rejects destinations in `fd00:53a0:5251::/48`; physical `poll_recv()` drops and counts spoofed inbound packets sourced from `fd00:53a0:5251::/48`; `route_gen` increments on relay reconnect and drops stale-generation routes; `MAX_VIRTUAL_ROUTES` cap holds under churn.
   - **CID pool & 0-RTT compatibility:** `CidQueue::LEN == 16`, `LOC_CID_COUNT == 16`, `issue_cids_limit()` returns `16` for Wave-4 peers and `5` for simulated `0.30.0` peers; `validate_resumption_from` accepts `5 -> 16` and rejects `16 -> 5`; an `N = 8` spray uses 8 distinct unused DCIDs and retires unused probe CIDs on round completion.
   - **Per-path dynamic virtual MTU:** Connection starting on a 1,280 B outer MASQUE virtual path clamps 1-RTT to `<= 1,179 B` with 0% steady-state stream spill, reacts dynamically when outer `max_datagram_size()` shrinks to `1,050 B` mid-session, and unlocks full `1,200 -> 1,452 B` physical DPLPMTUD immediately upon migrating to a direct physical path.
   - **Non-disruptive speculative probing & rollback:** During an `N = 8` probe round where all 8 direct candidates are blackholed, active streams on the MASQUE virtual path experience **0** interruptions and **0** dropped packets. When candidate #5 succeeds, `Connection` promotes it in place with **0** new handshakes, **unchanged `AuthenticatedSession::generation`**, **0** stream resets, and **0** [ADR-017](ADR-017-single-arbiter-connection-retirement.md) retirement triggers. When the promoted direct path is immediately blackholed before 1-RTT ACK, traffic falls back cleanly to `prev_path`.
   - **Mixed-version (`0.30.0` ↔ Wave 4) interop:** Without `InConnectionMigrationV1 (0x50C6)`, relay-to-direct upgrade falls back cleanly to [ADR-020](ADR-020-hybrid-relay-session-negotiation.md) Decision 5 + [ADR-017](ADR-017-single-arbiter-connection-retirement.md) with zero protocol errors.
2. **Dedicated Wave 4 connection-lifecycle soak gate (required before flipping `auto_migrate` or P7 dual-port in production):**
   - Linux network-namespace harness (cone, port-restricted, and `MASQUERADE --random-fully` symmetric NAT topologies + `netem` 1,280 B MTU + 1–2% loss + 40 ms jitter) running continuous bidirectional streams + concurrent `DatagramMuxV1` app datagrams (voice) + `saorsa-gossip` SG76 traffic across **>= 100 relay→direct migrations and NAT rebindings**:
     - **0** PQC re-handshakes during Wave-4 ↔ Wave-4 relay→direct migrations.
     - **0** dropped streams, **0** `saorsa-gossip` SG76 key-cache resets, **0** zombie `DATAGRAM_MUXES` / virtual route leaks, and bounded RSS.
     - **100%** fallback continuity under blackholed direct candidates and **100%** dual-port `:443` + `:5483` source-port preservation under simultaneous single-process load.
3. **ADR governance & revisit triggers:**
   - `python3 scripts/adr-governance.py` passes with zero edits to any Accepted ADR.
   - Revisit triggers: Phase 4A soak reveals CID-retirement lag under >8 concurrent probes, `draft-ietf-quic-multipath` reaches RFC status (update Phase 4B codepoints via superseding ADR per [ADR-012](ADR-012-standards-basis-refresh.md)), or fleet telemetry demonstrates >2% UDP-blocked clients justifying Phase 4C's TCP/443 pure-PQC relay.

## References

- Tracking issue: `saorsa-labs/ant-quic#375`; signed-off blueprint: `x0x/.planning/pure-pqc-efficiency-and-nat-plan-2026-11-22.md`
- Current implementation anchors:
  - `src/high_level/runtime/dual_stack.rs` (`DualStackSocket`)
  - `src/high_level/runtime.rs` (`AsyncUdpSocket`, `UdpSender`)
  - `src/nat_traversal_api.rs:1814, 2048, 7864-7944` (`shared_relay_endpoint`, `ensure_shared_relay_endpoint`, `additional_bind_addrs`)
  - `src/masque/relay_socket.rs:243, 1746, 2301` (`MasqueRelaySocket`, `compute_inner_virtual_path_mtu`)
  - `src/cid_queue.rs:139` (`CidQueue::LEN`), `src/lib.rs:679` (`LOC_CID_COUNT`), `src/transport_parameters.rs:217-280` (`active_connection_id_limit`, `validate_resumption_from`, `issue_cids_limit`)
  - `src/connection/mod.rs:3801-3915` (`Connection::migrate`, `migrate_to_nat_traversal_path`), `src/connection/paths.rs:23-100` (`PathData`)
  - `src/p2p_endpoint.rs:7513` (current relay-to-direct migration)
- Standards & drafts (provenance per [ADR-012](ADR-012-standards-basis-refresh.md)):
  - RFC 9000 §8.2, §9, §9.5, §14, §18.2 (QUIC path validation, migration, CID unlinkability, MTU)
  - RFC 9297 / RFC 9298 / `draft-ietf-masque-connect-udp-listen` / `draft-seemann-masque-connect-udp-ecn-01`
  - `draft-seemann-quic-nat-traversal-02` §4.4.1 (expired; provenance only; normative spec to be authored in `docs/rfcs/ant-quic-nat-traversal.md` per ADR-012)
  - `draft-ietf-quic-multipath` (Phase 4B)
  - RFC 6052, RFC 7050, RFC 8781, RFC 8880 (Phase 4C `PREF64`/NAT64)
  - NIST FIPS 203 (`ML-KEM-768`), NIST FIPS 204 (`ML-DSA-65`)

## Notes for AI-assisted work

Drafted with AI assistance for `saorsa-labs/ant-quic#375`. AI tools must **not** mark this ADR Accepted; only a human maintainer may accept it after engineering review. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
