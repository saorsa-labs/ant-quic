# ant-quic Native QUIC NAT Traversal & Relay Wire Specification

**Version:** 1.0  
**Date:** 2026-11-26  
**Status:** Normative (`ant-quic` repository specification per [ADR-012](../adr/ADR-012-standards-basis-refresh.md) and [ADR-021](../adr/ADR-021-unified-multiplexed-udp-socket-and-in-connection-migration.md))  
**Authors:** Saorsa Labs Ltd.

## Abstract

This document is the normative wire and protocol specification for `ant-quic`'s
native QUIC NAT traversal, peer address discovery, MASQUE CONNECT-UDP relay
fallback, and in-connection relay-to-direct migration extensions.

All `ant-quic` connections use **100% pure post-quantum cryptography**
(`ML-KEM-768` per FIPS 203 + `ML-DSA-65` per FIPS 204; zero classical fallbacks
or X.509 CAs) as specified in
[`ant-quic-pqc-authentication.md`](ant-quic-pqc-authentication.md). NAT
traversal operates natively inside QUIC without STUN, ICE, or TURN.

External IETF Internet-Drafts referenced herein are cited strictly as
**provenance and historical inspiration**; deployed peers speak the frozen
codepoints in this specification, and any future divergence from IETF standards
MUST be introduced via explicit transport-parameter or capsule negotiation
(ADR-012 Decision 2).

## Table of Contents

1. [Introduction & Standards Posture](#1-introduction--standards-posture)
2. [Conventions and Terminology](#2-conventions-and-terminology)
3. [Transport Parameter Registry](#3-transport-parameter-registry)
4. [NAT Traversal & Address Discovery Extension Frames](#4-nat-traversal--address-discovery-extension-frames)
5. [MASQUE CONNECT-UDP Relay Wire Protocol](#5-masque-connect-udp-relay-wire-protocol)
6. [Connection ID Pool & 0-RTT Resumption Semantics](#6-connection-id-pool--0-rtt-resumption-semantics)
7. [Paced Candidate Spray & Hole Punching](#7-paced-candidate-spray--hole-punching)
8. [In-Connection Relay-to-Direct Migration (`InConnectionMigrationV1`)](#8-in-connection-relay-to-direct-migration-inconnectionmigrationv1)
9. [Security & Isolation Considerations](#9-security--isolation-considerations)
10. [References](#10-references)

---

## 1. Introduction & Standards Posture

`ant-quic` establishes peer-to-peer connectivity across three qualitative tiers:

- **Direct:** peers reach one another immediately over UDP (IPv4 or IPv6).
- **Punched:** peers behind NAT coordinate simultaneous UDP hole punching over
  an existing QUIC connection to a shared known peer (coordinator) using native
  QUIC extension frames.
- **Relayed:** when direct punching cannot establish a direct UDP path, traffic
  traverses a peer-operated MASQUE CONNECT-UDP relay while preserving end-to-end
  pure-PQC QUIC encryption between the two endpoints.

`ant-quic` is strictly a transport layer; it provides no distributed record
storage or peer lookup service (ADR-011).

### 1.1 Wire-Compatibility Freeze (ADR-012)

All codepoints in Sections 3, 4, and 5 are **frozen**. Implementations MUST NOT
silently change deployed codepoints to track external draft updates. Any new
wire capability or format change MUST be negotiated behind an explicit QUIC
transport parameter or MASQUE session flag, preserving backwards compatibility
with deployed peers.

---

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

- **VarInt:** QUIC variable-length integer as defined in RFC 9000 §16.
- **PeerId:** 32-byte peer identifier derived as `SHA-256(ML-DSA-65 public key)`
  per [`ant-quic-pqc-authentication.md`](ant-quic-pqc-authentication.md).
- **Known peer / Coordinator:** Any mutually reachable peer over whose live QUIC
  connection two peers exchange address candidates and `PUNCH_ME_NOW`
  coordination frames. `ant-quic` is symmetric P2P (ADR-004); every node may
  simultaneously act as initiator, responder, coordinator, or relay.
- **Synthetic virtual address:** A process-internal IPv6 `SocketAddr` inside
  `fd00:53a0:5251::/48` used solely inside `MultiplexedUdpSocket` (ADR-021) to
  keep relayed paths disjoint from physical IPv4/IPv6 paths.

---

## 3. Transport Parameter Registry

All `ant-quic` transport parameters follow RFC 9000 §18 encoding:
`VarInt(id) || VarInt(len) || value[len]`. Duplicate parameters MUST be rejected
with `TRANSPORT_PARAMETER_ERROR`.

| Parameter Name | ID (Hex) | Payload | 0-RTT Resumption Rule | Reference |
|----------------|----------|---------|-----------------------|-----------|
| `active_connection_id_limit` | `0x0e` | VarInt (`>= 2`; Wave-4 default `16`, `<= 0.30.x` `5`) | `cached <= current` (RFC 9000 §7.4.1) | RFC 9000 §18.2, ADR-021 |
| `nat_traversal` | `0x3d7e9f0bca12fea6` | Empty (`ClientSupport`) or VarInt `1..=100` (`ServerSupport { concurrency_limit }`) | Standard | ADR-005, ADR-012 |
| `rfc_nat_traversal` | `0x3d7e9f0bca12fea8` | Empty (`len == 0`) | Standard | ADR-012 |
| `address_discovery` | `0x9f81a176` | VarInt (`0` = SendOnly, `1` = ReceiveOnly, `2` = SendAndReceive) | Standard | ADR-012 |
| `pqc_algorithms` | `0x50C0` | 1-byte bitfield (`bit 0 = ML-KEM-768`, `bit 1 = ML-DSA-65`; bits 2–7 reserved) | Standard | ADR-003 |
| `ack_receive_v2` | `0x50C2` | Empty (`len == 0`) | `!(cached && !current)` | Internal |
| `datagram_mux_v1` | `0x50C4` | Empty (`len == 0`) | Exact match (`cached == current`) | ADR-020 |
| `in_connection_migration_v1` | `0x50C6` | Empty (`len == 0`) | Exact match (`cached == current`) | ADR-021 |

### 3.1 `nat_traversal` (`0x3d7e9f0bca12fea6`)

- **Length `0`:** `ClientSupport` (endpoint supports NAT traversal coordination).
- **Length `> 0`:** VarInt `concurrency_limit` in `1..=100` (`ServerSupport`).
  Values `0` or `> 100` MUST be rejected with `TRANSPORT_PARAMETER_ERROR`.
- **Symmetric P2P:** Unlike client/server-only drafts, either QUIC side
  (`Client` or `Server`) MAY send either form. When both peers send
  `ServerSupport`, the effective concurrency limit is
  `min(local_limit, remote_limit)`.

### 3.2 `rfc_nat_traversal` (`0x3d7e9f0bca12fea8`)

- Zero-length parameter (`len == 0`; non-empty payload MUST be rejected as
  malformed).
- When negotiated by both peers, `ADD_ADDRESS` and `PUNCH_ME_NOW` frames use
  the compact RFC wire layout (Section 4.1 / 4.2) rather than the legacy layout.

### 3.3 `address_discovery` (`0x9f81a176`)

- Encodes a single VarInt: `0` (`SendOnly`), `1` (`ReceiveOnly`), or `2`
  (`SendAndReceive`). Any other value MUST be rejected as malformed.
- Codepoint matches `draft-ietf-quic-address-discovery-01`.

### 3.4 `datagram_mux_v1` (`0x50C4`)

- Zero-length parameter (`len == 0`; non-empty or duplicate MUST be rejected as
  malformed).
- When mutually negotiated, all RFC 9221 `DATAGRAM` frames on the connection
  carry a leading RFC 9297 VarInt Context ID from datagram #1: odd Context ID
  `1` for application datagrams and even Context IDs `>= 2` for multiplexed
  MASQUE hybrid relay sessions (ADR-020).
- On 0-RTT resumption, `cached.datagram_mux_v1 != current.datagram_mux_v1` MUST
  fail with `TransportError::PROTOCOL_VIOLATION`.

### 3.5 `in_connection_migration_v1` (`0x50C6`)

- Zero-length parameter (`len == 0`; non-empty or duplicate MUST be rejected as
  malformed). Enabled by default on Wave-4 endpoints (`TransportConfig::in_connection_migration_v1(true)`).
- When mutually negotiated AND the server has NOT advertised RFC 9000
  `disable_active_migration (0x0c)`, authorizes client-initiated in-connection
  migration from a relayed path to a validated direct server address (Section 8).
- On 0-RTT resumption, `cached.in_connection_migration_v1 != current.in_connection_migration_v1`
  MUST fail with `TransportError::PROTOCOL_VIOLATION`.

---

## 4. NAT Traversal & Address Discovery Extension Frames

All extension frames are carried in 1-RTT (and, where permitted by RFC 9000,
Handshake) packets. Frame types are encoded as QUIC VarInts.

| Frame Name | Type (Hex) | Purpose |
|------------|------------|---------|
| `ADD_ADDRESS_IPV4` | `0x3d7e90` | Advertise an IPv4 candidate socket address |
| `ADD_ADDRESS_IPV6` | `0x3d7e91` | Advertise an IPv6 candidate socket address |
| `PUNCH_ME_NOW_IPV4` | `0x3d7e92` | Request synchronized hole punch to an IPv4 target |
| `PUNCH_ME_NOW_IPV6` | `0x3d7e93` | Request synchronized hole punch to an IPv6 target |
| `REMOVE_ADDRESS` | `0x3d7e94` | Withdraw a previously advertised candidate by sequence number |
| `TRY_CONNECT_TO_IPV4` | `0x3d7e95` | Request a peer to attempt reaching an IPv4 target |
| `TRY_CONNECT_TO_IPV6` | `0x3d7e96` | Request a peer to attempt reaching an IPv6 target |
| `TRY_CONNECT_TO_RESPONSE_IPV4` | `0x3d7e97` | Report result of an IPv4 reachability attempt |
| `TRY_CONNECT_TO_RESPONSE_IPV6` | `0x3d7e98` | Report result of an IPv6 reachability attempt |
| `OBSERVED_ADDRESS_IPV4` | `0x9f81a6` | Report the peer's observed IPv4 source address |
| `OBSERVED_ADDRESS_IPV6` | `0x9f81a7` | Report the peer's observed IPv6 source address |

All integer fields below other than VarInts are big-endian (network byte order).

### 4.1 `ADD_ADDRESS` (`0x3d7e90` / `0x3d7e91`)

**Compact RFC layout (when `rfc_nat_traversal` is negotiated):**

```text
ADD_ADDRESS Frame (RFC format) {
  Type (i) = 0x3d7e90 (IPv4) | 0x3d7e91 (IPv6),
  Sequence Number (i),
  IP Address (32 for IPv4 | 128 for IPv6),
  Port (16),
}
```

**Legacy layout (backward compatibility when `rfc_nat_traversal` is absent):**

```text
ADD_ADDRESS Frame (legacy format) {
  Type (i) = 0x3d7e90 (IPv4) | 0x3d7e91 (IPv6),
  Sequence Number (i),
  Priority (i),
  IP Version (8) = 4 | 6,
  IP Address (32 for IPv4 | 128 for IPv6),
  Port (16),
  [Flow Info (32), Scope ID (32)],  // present only when IP Version == 6
}
```

### 4.2 `PUNCH_ME_NOW` (`0x3d7e92` / `0x3d7e93`)

**Compact RFC layout:**

```text
PUNCH_ME_NOW Frame (RFC format) {
  Type (i) = 0x3d7e92 (IPv4) | 0x3d7e93 (IPv6),
  Round (i),
  Paired With Sequence Number (i),
  IP Address (32 for IPv4 | 128 for IPv6),
  Port (16),
}
```

**Legacy layout:**

```text
PUNCH_ME_NOW Frame (legacy format) {
  Type (i) = 0x3d7e92 (IPv4) | 0x3d7e93 (IPv6),
  Round (i),
  Paired With Sequence Number (i),
  IP Version (8) = 4 | 6,
  IP Address (32 for IPv4 | 128 for IPv6),
  Port (16),
  [Flow Info (32), Scope ID (32)],  // present only when IP Version == 6
  Has Target Peer ID (8) = 0 | 1,
  [Target Peer ID (256)],           // present only when Has Target Peer ID == 1
}
```

### 4.3 `REMOVE_ADDRESS` (`0x3d7e94`)

Identical in both RFC and legacy modes:

```text
REMOVE_ADDRESS Frame {
  Type (i) = 0x3d7e94,
  Sequence Number (i),
}
```

### 4.4 `OBSERVED_ADDRESS` (`0x9f81a6` / `0x9f81a7`)

```text
OBSERVED_ADDRESS Frame {
  Type (i) = 0x9f81a6 (IPv4) | 0x9f81a7 (IPv6),
  Sequence Number (i),
  IP Address (32 for IPv4 | 128 for IPv6),
  Port (16),
}
```

### 4.5 `TRY_CONNECT_TO` (`0x3d7e95` / `0x3d7e96`) & `TRY_CONNECT_TO_RESPONSE` (`0x3d7e97` / `0x3d7e98`)

```text
TRY_CONNECT_TO Frame {
  Type (i) = 0x3d7e95 (IPv4) | 0x3d7e96 (IPv6),
  Request ID (i),
  Target IP Address (32 for IPv4 | 128 for IPv6),
  Target Port (16),
  Timeout Milliseconds (16),
}

TRY_CONNECT_TO_RESPONSE Frame {
  Type (i) = 0x3d7e97 (IPv4) | 0x3d7e98 (IPv6),
  Request ID (i),
  Success (8) = 0 | 1,
  [Error Code (8)],                 // present only when Success == 0
  Source IP Address (32 for IPv4 | 128 for IPv6),
  Source Port (16),
}
```

Error codes (`Success == 0`): `0` Timeout, `1` ConnectionRefused,
`2` NetworkUnreachable, `3` HostUnreachable, `4` RateLimited,
`5` InvalidAddress, `255` InternalError.

---

## 5. MASQUE CONNECT-UDP Relay Wire Protocol

Peer-operated relays carry inner QUIC packets over an outer pure-PQC QUIC
connection using the `connect-udp` / `connect-udp-bind` relay protocol
(ADR-006, ADR-009, ADR-016, ADR-020).

### 5.1 Session Negotiation Flag Bits

| Bit | Mask | Direction | Meaning |
|-----|------|-----------|---------|
| Request bit 0 | `0x01` | Client → Relay | `REQUEST_FLAG_BIND` (`connect-udp-bind` listener) |
| Request bit 1 | `0x02` | Client → Relay | `REQUEST_FLAG_HYBRID_DATAGRAM_LANE` (legacy `0.29.0` unprefixed hybrid lane) |
| Request bit 2 | `0x04` | Client → Relay | `REQUEST_FLAG_DATAGRAM_MUX_V1` (ADR-020 multiplexed Context-ID hybrid lane; requires `DatagramMuxV1 0x50C4`) |
| Response bit 0 | `0x01` | Relay → Client | `RESPONSE_FLAG_HAS_ADDRESS` |
| Response bit 1 | `0x02` | Relay → Client | `RESPONSE_FLAG_HAS_REASON` |
| Response bit 2 | `0x04` | Relay → Client | `RESPONSE_FLAG_HYBRID_DATAGRAM_LANE` |
| Response bit 3 | `0x08` | Relay → Client | `RESPONSE_FLAG_DATAGRAM_MUX_V1` |

### 5.2 Relay Capsules

Capsules are carried on the relay bidirectional control stream prefixed by
`STREAM_CAPSULE_MARKER = 0xFF` (`0xFF || VarInt(type) || VarInt(len) || value`):

| Capsule Name | Type (Hex) | Purpose |
|--------------|------------|---------|
| `COMPRESSION_ASSIGN` | `0x11` | Assign an even Context ID to a target UDP socket address (compressed header) |
| `COMPRESSION_ACK` | `0x12` | Acknowledge a `COMPRESSION_ASSIGN` or `ECN_COMPRESSION_ASSIGN` registration |
| `COMPRESSION_CLOSE` | `0x13` | Close or reject a Context ID assignment |
| `ECN_COMPRESSION_ASSIGN` | `0x14` | Register a 4-context even-stride ECN quad `{base, base+2, base+4, base+6}` mapping Not-ECT / ECT(1) / ECT(0) / CE (ADR-020; provenance: `draft-seemann-masque-connect-udp-ecn-01`) |

### 5.3 Virtual Path MTU Floor & Stream Lane Routing

- Inner QUIC Initial packets (`1,200 B` padded per RFC 9000 §14.1) and any
  inner packet exceeding the outer connection's usable datagram budget `P_max`
  (including `1,200 B` `PATH_CHALLENGE`/`PATH_RESPONSE` frames when
  `1200 > P_max`) MUST traverse the reliable relay stream lane.
- Inner post-handshake 1-RTT packets on a virtual MASQUE path clamp to
  `compute_inner_virtual_path_mtu(outer_max_datagram_size, overhead)` with floor
  `MIN_VIRTUAL_PATH_MTU = 900 B` and ceiling `1,380 B` (ADR-020 / ADR-021).

---

## 6. Connection ID Pool & 0-RTT Resumption Semantics

To support concurrent `N = 8` candidate spray probing (Section 7) with strict
RFC 9000 §9.5 path unlinkability (a distinct previously unused Destination
Connection ID per probed path):

- Wave-4 endpoints set `CidQueue::LEN = 16` and `LOC_CID_COUNT = 16`,
  advertising `active_connection_id_limit = 16` whenever CID length is non-zero
  (and RFC 9000 default `2` when CID length is `0`).
- **Issued CIDs:** An endpoint issues up to
  `min(peer.active_connection_id_limit, LOC_CID_COUNT)` CIDs to its peer:
  - Wave-4 ↔ Wave-4: `16` CIDs (`1` active + `8` concurrent probes + `2`
    standby/migration slots + `5` retirement headroom).
  - Wave-4 ↔ `<= 0.30.x`: Wave-4 issues `min(5, 16) = 5` CIDs to the `<= 0.30.x`
    peer, and receives `min(16, 8) = 8` CIDs (`7` spare) from it.
- **Dynamic probe budget:** Each probe round MUST cap its concurrent probes to
  `min(MAX_CONCURRENT_PROBE_PATHS, rem_cids.spare_count())` so a peer issuing
  fewer CIDs never stalls probing or reuses an active DCID.
- **Replenishment:** Unused probe CIDs MUST be retired via
  `RETIRE_CONNECTION_ID` upon probe failure or cancellation so the peer
  replenishes the pool ahead of future rounds.
- **0-RTT upgrade & rollback:**
  - Upgrading a server `5 -> 16` satisfies `cached (5) <= current (16)` and
    preserves 0-RTT resumption cleanly.
  - Rolling back a server `16 -> 5` violates RFC 9000 §7.4.1 if the server
    accepts a pre-rollback 0-RTT ticket (`validate_resumption_from` returns
    `TransportError::PROTOCOL_VIOLATION` on the client). Because pinned
    `rustls 0.23` performs no server-side QUIC transport-parameter check during
    early-data admission, any `16 -> 5` server rollback **MUST** disable early
    data (`max_early_data_size = 0`) or flush the server's TLS session cache for
    one ticket lifetime so pre-rollback tickets are rejected at TLS with clean
    1-RTT fallback.

---

## 7. Paced Candidate Spray & Hole Punching

Per [ADR-015](../adr/ADR-015-paced-candidate-spray-punching.md):

- Upon `PUNCH_ME_NOW` coordination, both peers spray up to
  `min(8, rem_cids.spare_count())` candidate pairs concurrently per round,
  padded to `1,200 B` (`PATH_CHALLENGE`) and paced at `>= max(20 ms, min_rtt/10)`.
- Probes to unvalidated candidate addresses MUST obey RFC 9000 §8.1 3×
  anti-amplification limits.
- Incoming `PATH_RESPONSE` frames are matched by their 64-bit challenge token
  against the active probe table, surviving symmetric NAT port rebinding.

---

## 8. In-Connection Relay-to-Direct Migration (`InConnectionMigrationV1`)

When both peers negotiate `InConnectionMigrationV1 (0x50C6)` and the server has
not advertised `disable_active_migration (0x0c)` (ADR-021):

1. **Authorization extending RFC 9000 §9.6:** Mutual negotiation of `0x50C6`
   (with server active migration enabled) explicitly authorizes the QUIC client
   to validate and migrate an active connection onto a new direct server address
   discovered during the session (not restricted to handshake-time
   `preferred_address`).
2. **Non-disruptive speculative probing:** Active application traffic continues
   uninterrupted on `self.path` (the synthetic virtual MASQUE path) while
   speculative probes run in a separate bounded `probing_paths` table
   (`MAX_CONCURRENT_PROBE_PATHS = 8`).
3. **Scoped post-decryption off-path probe admission on `Side::Client`:** Only
   when `0x50C6` was negotiated and server migration is enabled, the client
   defers dropping packets arriving from `(remote, local_slot) != self.path`
   until after AEAD decryption/authentication. Authenticated packets are
   admitted strictly if they (a) match a tracked `(remote, local_slot)` in
   `probing_paths` carrying probing frames (`PATH_CHALLENGE` / `PATH_RESPONSE`)
   or (b) carry an authenticated `PATH_CHALLENGE` seeding a new bounded probe
   entry (subject to `MAX_CONCURRENT_PROBE_PATHS` and 3× anti-amplification).
   Unauthenticated packets, non-probing packets from unvalidated addresses, and
   all off-path packets when `0x50C6` was not negotiated MUST be dropped.
4. **Asymmetric promotion (zero ping-pong):**
   - **`Side::Client` initiates migration:** On the first valid `PATH_RESPONSE`
     on a direct candidate, the client cancels remaining probes (retiring unused
     probe CIDs), promotes `(remote_addr, local_slot)` to `self.path` with
     `validated = true` and physical DPLPMTUD (`INITIAL_MTU = 1200`), retains
     the previous virtual path in `prev_path` for a `3 * max(pto, prev_pto)`
     drain/blackhole-rollback grace, and begins sending non-probing 1-RTT frames
     on the direct path.
   - **`Side::Server` responds to client migration (RFC 9000 §9.3):** The server
     marks validated direct candidates in `probing_paths` without switching
     `self.path` until the client's first non-probing 1-RTT packet arrives on
     that validated `(remote_addr, local_slot)`.
5. **Backwards compatibility (`<= 0.30.x`):** If `0x50C6` was not negotiated,
   `disable_active_migration` was set, or `rem_cids.spare_count() == 0`,
   endpoints fall back to ADR-020 Decision 5's new-handshake direct migration
   with ADR-017 single-arbiter retirement.

---

## 9. Security & Isolation Considerations

- **Pure PQC end-to-end:** All extension frames, `PATH_CHALLENGE`/`PATH_RESPONSE`
  probes, and MASQUE tunnels are protected by pure-PQC TLS 1.3 (`ML-KEM-768` +
  `ML-DSA-65`) with raw public keys.
- **Validated `(remote_addr, local_slot)` path identity:** Multi-port endpoints
  (e.g., dual-port `:443` + `:5483`) treat `(remote_addr, local_slot)` as the
  validated path tuple; even an authenticated 1-RTT packet arriving on a
  different local socket slot MUST NOT flip send-slot affinity without RFC 9000
  §8.2 `PATH_CHALLENGE`/`PATH_RESPONSE` validation on that exact slot.
- **Synthetic virtual-path isolation (`fd00:53a0:5251::/48`):** Addresses in the
  process-internal synthetic ULA prefix MUST NEVER be emitted on physical
  sockets or inside `ADD_ADDRESS` / `OBSERVED_ADDRESS` / `PUNCH_ME_NOW` frames,
  and MUST be rejected on physical ingress and before insertion into candidate
  or address caches.
- **Anti-amplification & DoS bounds:** Unvalidated candidate probes obey RFC
  9000 §8.1 3× anti-amplification; probe tables are hard-capped at
  `MAX_CONCURRENT_PROBE_PATHS = 8`; virtual routes are bounded per ADR-014.

---

## 10. References

### Normative References

- **RFC 2119**: Key words for use in RFCs to Indicate Requirement Levels
- **RFC 9000**: QUIC: A UDP-Based Multiplexed and Secure Transport
- **RFC 9221**: An Unreliable Datagram Extension to QUIC
- **RFC 9297**: HTTP Datagrams and the Capsule Protocol
- **RFC 9298**: Proxying UDP in HTTP (MASQUE CONNECT-UDP)
- **FIPS 203 / FIPS 204**: ML-KEM / ML-DSA ([`ant-quic-pqc-authentication.md`](ant-quic-pqc-authentication.md))
- **ant-quic ADRs**: [ADR-003](../adr/ADR-003-pure-post-quantum-cryptography.md), [ADR-004](../adr/ADR-004-symmetric-p2p-architecture.md), [ADR-005](../adr/ADR-005-native-quic-nat-traversal.md), [ADR-006](../adr/ADR-006-masque-relay-fallback.md), [ADR-012](../adr/ADR-012-standards-basis-refresh.md), [ADR-014](../adr/ADR-014-relay-resource-governance.md), [ADR-015](../adr/ADR-015-paced-candidate-spray-punching.md), [ADR-016](../adr/ADR-016-hybrid-relay-data-plane.md), [ADR-017](../adr/ADR-017-single-arbiter-connection-retirement.md), [ADR-020](../adr/ADR-020-hybrid-relay-session-negotiation.md), [ADR-021](../adr/ADR-021-unified-multiplexed-udp-socket-and-in-connection-migration.md)

### Informative References (Provenance Only)

- **`draft-seemann-quic-nat-traversal-02`** (expired March 2024): provenance for
  NAT traversal frames (`0x3d7e90–94`), transport parameter
  `0x3d7e9f0bca12fea6`, and §4.4.1 client-initiated direct migration concept.
- **`draft-ietf-quic-address-discovery-01`** (active IETF WG draft): provenance
  for `OBSERVED_ADDRESS` (`0x9f81a6`/`0x9f81a7`) and `0x9f81a176`.
- **`draft-ietf-masque-connect-udp-listen-16`** (RFC Editor queue): provenance
  for `connect-udp-bind` and `COMPRESSION_ASSIGN`/`ACK`/`CLOSE` capsules.
- **`draft-seemann-masque-connect-udp-ecn-01`**: provenance for 4-context ECN
  capsule mapping (`ECN_COMPRESSION_ASSIGN 0x14`).
- **`draft-bruynooghe-n0-quic-nat-traversal-00`**: related ecosystem NAT
  traversal work.
