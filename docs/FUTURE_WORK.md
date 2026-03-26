# Future Work (PQC-First Capability Roadmap)

## Goal

Build a complete transport-agnostic, multi-hop P2P networking stack in `ant-quic` that:

- Keeps 100% post-quantum cryptography on every path.
- Works across broadband and constrained transports.
- Provides strong delivery semantics, discovery, routing, and operations tooling.
- Maintains the symmetric peer model (all nodes can connect, accept, observe, coordinate, and relay).

This document is the implementation roadmap for closing remaining capability gaps.

## Non-Negotiable Constraints

1. Pure PQC only:
   - ML-KEM-768 for key exchange.
   - ML-DSA-65 for signatures and identity.
   - No classical fallback mode.
2. Symmetric P2P architecture:
   - No permanent client/server role split.
3. Native QUIC NAT traversal remains first-class:
   - `ADD_ADDRESS`, `PUNCH_ME_NOW`, `REMOVE_ADDRESS`, `OBSERVED_ADDRESS`.
4. Keep compatibility with current `P2pEndpoint` and staged migration for new APIs.

## Current Baseline (What Exists Today)

- QUIC + NAT traversal + MASQUE relay fallback.
- `P2pEndpoint` high-level API (`connect`, `connect_transport`, `send`, `recv`, events, stats).
- Transport abstraction (`TransportProvider`, `TransportRegistry`, `TransportAddr`, capabilities).
- Constrained protocol engine with connection state machine, ARQ, fragmentation, keepalive.
- Initial multi-transport address model (UDP, BLE, LoRa, Serial, AX.25, I2P, Yggdrasil variants in address space).

## Capability Workstreams

### 1) Mesh Control Plane and Multi-Hop Routing

Implement a production control plane for global reachability across mixed transports.

Components:
- Reachability announcements:
  - Signed with ML-DSA-65.
  - Include destination/service hash, next-hop metadata, hop count, timestamp/nonce, expiry.
- Path tables:
  - In-memory path cache keyed by destination hash.
  - Entry quality metrics (hops, RTT estimate, loss, freshness).
  - Expiry and garbage collection.
- Path request/response flow:
  - Request unknown destinations.
  - Answer from cache with signed response material.
  - Duplicate suppression via request tags.
- Forwarding logic:
  - Forward path traffic for known destinations.
  - Prevent loops and reflection.
  - Per-interface announce/path rate controls.
- Persistence:
  - Save/load path tables and relevant caches for restart continuity.

Definition of done:
- Unknown destination can be discovered and reached through at least one forwarding peer without static peer preconfiguration.

### 2) Destination and Service Addressing Layer

Add a destination-centric addressing model above raw transport addresses.

Components:
- Destination hash format:
  - Deterministic address derived from `PeerId` plus service/application namespace.
- Service addressing:
  - Allow multiple independent service endpoints per identity.
- Destination directory/cache:
  - Distributed public key and service metadata memory.
- API:
  - Resolve destination hash to active path(s) and next hop(s).

Definition of done:
- Applications can route by destination/service identifier, not only direct `SocketAddr`/`TransportAddr`.

### 3) Request/Response Protocol Primitive

Add a built-in request/response layer for applications.

Components:
- Outgoing request API:
  - Path string or method ID + optional payload + timeout.
- Request handlers:
  - Register/deregister handlers by route.
  - Access control policy (`allow_none`, `allow_all`, allow-list by identity).
- Request receipt lifecycle:
  - `SENT`, `DELIVERED`, `RECEIVING`, `READY`, `FAILED`.
- Automatic fallback:
  - Small requests as packets/messages.
  - Large requests promoted to resource transfer.

Definition of done:
- App-level RPC-style interactions work consistently on direct, relayed, and multi-hop paths.

### 4) Cryptographic Delivery Proofs and Receipts

Add explicit delivery verification semantics for non-stream message delivery.

Components:
- Proof packet format:
  - Receipt hash + ML-DSA signature.
- Receipt object:
  - Delivery callback, timeout callback, RTT data, proof packet capture.
- Optional implicit proof mode (if wire-efficient and safe).
- Verification pipeline integrated with identity/path cache.

Definition of done:
- Sender can verify destination-backed proof of delivery for supported message classes.

### 5) Resource Transfer Protocol (Large Data)

Add a dedicated large-object transfer subsystem.

Components:
- Advertisement and negotiation for resource transfer.
- Segmentation/reassembly with checksums and ordered recovery.
- Adaptive sliding windows and retransmission strategy.
- Optional compression and metadata support.
- Resume/cancel support for interrupted transfers.
- Progress callbacks and transfer receipts.

Definition of done:
- Reliable transfer from small blobs to large files over constrained and broadband links with progress and resumability.

### 6) Reliable Message Channels + Buffered Stream Adapters

Provide message-level reliability and stream-like wrappers above links.

Components:
- Bidirectional reliable channel abstraction:
  - Sequenced messages.
  - Retries and adaptive windows.
- Buffered reader/writer wrappers:
  - Byte-stream style interfaces over reliable messages.
- Backpressure and fairness integration with transport capabilities.

Definition of done:
- App developers can use either message mode or buffered stream mode on top of the same session.

### 7) Multi-Transport Provider Completion

Move from address modeling to full provider implementations.

Components:
- Production providers:
  - Serial.
  - LoRa (RNode/KISS style integration).
  - AX.25/KISS.
  - I2P.
  - Yggdrasil.
  - Pipe/stdin-stdout bridge.
  - Optional TCP/backbone transport wrapper for bootstrap scenarios.
- Capability mapping for each provider:
  - MTU, latency class, broadcast support, half/full duplex, expected reliability.
- Conformance tests for each provider.

Definition of done:
- Each declared transport type has an online provider implementation and integration tests, not only address enums.

### 8) Interface/Peer Discovery and Auto-Connect

Add network-side discovery for dynamic entrypoints.

Components:
- Discovery announcements:
  - Signed payloads with optional encrypted metadata.
  - Include endpoint/interface info and policy hints.
- Anti-spam stamps:
  - Configurable work factor for discovery announcement acceptance.
- Discovery filtering:
  - Allow-list trusted network identities/sources.
  - Minimum discovery stamp/value threshold.
- Auto-connect manager:
  - Maintain configurable number of active discovered interfaces/peers.
  - Replace weaker links with stronger discovered links.

Definition of done:
- Nodes can bootstrap from minimal seed connectivity and automatically discover/upgrade to better links.

### 9) Abuse Resistance and Governance Controls

Add first-class controls for operational safety in open networks.

Components:
- Local identity blocklist:
  - Reject path propagation and forwarding for blocked identities.
- Federated blocklist sourcing:
  - Pull signed policy lists from trusted identities.
  - Merge with local policy and persist.
- Publish local policy endpoint (opt-in).
- Rate enforcement:
  - Announce/request flood protection per identity/interface.

Definition of done:
- Operators can protect local network segments from announce/path abuse without centralization.

### 10) Constrained Transport PQC Hardening

Complete PQC semantics for constrained links.

Components:
- Full constrained handshake authentication:
  - Peer identity verification using ML-DSA.
  - Session key agreement using ML-KEM with fragmentation-safe exchange.
- Session key lifecycle:
  - Rotation, expiration, optional ratchet-like progression.
- Cross-transport identity consistency:
  - Same identity semantics across QUIC and constrained engines.
- Security profile tuning:
  - Memory/CPU guardrails for embedded targets.

Definition of done:
- Constrained sessions achieve the same identity/authentication guarantees as QUIC sessions.

### 11) Immediate Reliability and Correctness Cleanup

Stabilize current foundations before expanding scope.

Components:
- Replace placeholder inbound receiver behavior with real subscription model for:
  - UDP transport.
  - BLE transport.
- Complete transport read loop integration for non-UDP providers with endpoint ingestion.
- Remove "future behavior" branches in core send/connect paths by landing full routing/selection behavior.
- Eliminate synthetic-auth gaps where constrained peers are marked unauthenticated by default.

Definition of done:
- No placeholder/dummy inbound paths in production transport providers.

### 12) Ops Tooling and Remote Diagnostics

Provide operator-grade tooling for complex deployments.

Components:
- CLI suite:
  - Status, path table inspection, probe, diagnostics, transfer, request tools.
- Runtime observability:
  - Structured metrics for path convergence, announce load, proof rates, transfer health.
- Optional remote management endpoints:
  - Authenticated, rate-limited control/inspection APIs.

Definition of done:
- Multi-hop network operators can inspect and manage the mesh without custom scripts.

### 13) Test, Verification, and Performance Program

Build confidence for production deployment.

Components:
- Property tests for routing convergence and loop prevention.
- Interop tests across all transport providers.
- Soak/chaos tests for churn, latency spikes, and partition healing.
- Performance targets:
  - Constrained link viability.
  - High-bandwidth saturation on QUIC paths.
- Security tests:
  - Signature/proof forgery resistance.
  - Replay protection.
  - Flood/rate-limit enforcement.

Definition of done:
- Clear pass/fail quality gates for every release train.

## Phased Delivery Plan

### Phase 0: Foundation Hardening
- Land immediate reliability fixes (Workstream 11).
- Add feature flags for new control-plane and request/resource subsystems.

### Phase 1: Control Plane MVP
- Reachability announcements, path request/response, path table cache.
- Minimal forwarding and loop prevention.

### Phase 2: Destination + Request/Response
- Destination/service addressing layer.
- Handler registration and request receipts.

### Phase 3: Delivery Proofs + Resource Transfer
- Proof packet pipeline and receipt verification.
- Segmented transfer with retries and progress.

### Phase 4: Transport Expansion
- Serial + LoRa + AX.25 providers first.
- Integrate constrained-PQC handshake and identity verification.

### Phase 5: Overlay and Discovery
- I2P/Yggdrasil providers.
- Discovery announcements, filters, stamp checks, auto-connect.

### Phase 6: Policy and Operations
- Blocklist federation and governance controls.
- Full CLI/diagnostics tooling.

### Phase 7: Optimization and Stabilization
- Convergence/perf tuning, memory reduction, long-haul soak.
- Default-on readiness for production mesh environments.

## Cross-Cutting Implementation Rules

1. Every new wire object must have:
   - Explicit versioning strategy.
   - Authentication/authorization semantics.
   - Replay and rate-limit considerations.
2. Every new API must support:
   - Async cancellation.
   - Deterministic timeouts.
   - Structured error types (no panics/unwrap/expect in non-test code).
3. Every feature phase must ship with:
   - Tests (unit + integration).
   - Operator-facing observability hooks.
   - Documentation update in `docs/`.

## Exit Criteria for "Capability Complete"

`ant-quic` can be considered capability-complete for this roadmap when all are true:

- Multi-hop discovery and forwarding works across mixed transports.
- Destination/service addressing is primary app interface (not only direct transport addresses).
- Request/response, delivery proofs, and large-resource transfer are production APIs.
- All declared transports have real providers with conformance tests.
- Discovery/autoconnect and abuse controls are operationally usable.
- PQC identity/authentication is consistent across QUIC and constrained engines.
