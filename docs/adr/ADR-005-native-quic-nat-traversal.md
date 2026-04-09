# ADR-005: Native QUIC NAT Traversal

## Status

Accepted (2025-12-21)

## Context

### The Problem

Most Internet hosts are behind NAT (Network Address Translation), which blocks incoming connections. Traditional solutions:

- **STUN**: Discovers external address via external servers
- **TURN**: Relays all traffic through external servers
- **ICE**: Orchestrates STUN/TURN with complex state machine

These require **external infrastructure** (STUN/TURN servers) that must be:
- Operated by someone
- Highly available
- Geographically distributed
- Trusted not to manipulate addresses

### ant-quic's Scope

ant-quic should be the **smallest useful substrate** that can reliably connect machines across the public Internet without central coordinators.

**What ant-quic MUST provide**:
- Stable endpoint identity (cryptographic) distinct from network locator
- QUIC transport (streams + datagrams) with symmetric peer roles
- QUIC NAT traversal and address discovery
- Mandatory capability to coordinate and relay (with rate limits)
- Greedy bootstrap cache with peer capabilities
- Application protocol multiplexing

**What ant-quic must NOT provide**:
- DHT semantics (replication, close-groups, pricing)
- Naming, record formats, CRDTs
- Overlay-specific admission rules

## Decision

Implement **native QUIC NAT traversal** as the primary reachability mechanism using QUIC extension frames, eliminating external infrastructure. In addition, accept **router-assisted port mapping** (UPnP IGD first, with PCP/NAT-PMP as possible future follow-ons) as an additive local optimization for compatible home/edge routers.

For the current UPnP IGD implementation, standardize on `igd-next` as the
router-assist library. It best matches ant-quic's immediate needs: Tokio async
integration, simple gateway discovery, external IPv4 address lookup, UDP
add/remove port mapping, and a permissive MIT license. If we later expand
router assist beyond UPnP IGD, add a separate backend rather than replacing the
UPnP implementation outright.

### Extension Frames

| Frame | Type ID | Purpose |
|-------|---------|---------|
| ADD_ADDRESS | 0x3d7e90-91 | Advertise candidate addresses |
| PUNCH_ME_NOW | 0x3d7e92-93 | Coordinate simultaneous hole punching |
| REMOVE_ADDRESS | 0x3d7e94 | Remove invalid candidates |
| OBSERVED_ADDRESS | 0x9f81a6-a7 | Report peer's external address |

### Transport Parameters

| Parameter | ID | Purpose |
|-----------|-------|---------|
| NAT capability | 0x3d7e9f0bca12fea6 | Negotiate NAT traversal support |
| Frame format | 0x3d7e9f0bca12fea8 | RFC-compliant frame format |
| Address discovery | 0x9f81a176 | Configure observation behavior |

### How It Works

1. **Router Assist (Best Effort)**: On compatible local gateways, request/renew a UDP port mapping via UPnP IGD to improve inbound reachability
2. **Address Discovery**: Peers report observed external addresses via OBSERVED_ADDRESS (no STUN needed)
3. **Candidate Exchange**: Peers share candidates via ADD_ADDRESS frames
4. **Hole Punching**: Coordinated via PUNCH_ME_NOW (any peer can coordinate)
5. **Validation**: Test candidate pairs, promote successful paths
6. **Fallback**: If direct fails, use MASQUE relay (see ADR-006)

Router-assisted mapping is **additive only**:
- it can contribute a better external candidate address
- it does not replace peer-assisted QUIC NAT traversal
- it does not by itself prove peer-verified direct reachability
- it must fail open into the normal NAT traversal + relay flow

Current first-cut runtime status:
- implemented via `PortMappingConfig` under `NatConfig`
- implemented with `igd-next` as the UPnP IGD backend
- enabled by default, with CLI opt-out via `--no-port-mapping`
- mapped public addresses feed candidate/status surfaces, but do not flip direct-reachability truth on their own
- current implementation is intentionally narrow: UDP-only and IPv4-only

### Router-Assist Library Selection

The router-assist layer is intentionally narrower than a full generic UPnP
control-point stack. ant-quic currently needs:

- Tokio-native async gateway discovery
- external address lookup
- best-effort UDP port mapping with renew/remove
- a small dependency and maintenance surface
- a permissive license compatible with `MIT OR Apache-2.0`

`igd-next` fits that profile well and is therefore the selected library for the
UPnP IGD slice.

Future follow-on protocol support should be evaluated separately:

- **PCP/NAT-PMP**: prefer adding a dedicated backend, with `crab_nat` the
  current best candidate, rather than forcing those protocols through a UPnP
  abstraction
- **IPv6 pinholes / richer gateway capabilities / multi-gateway policy**:
  revisit the abstraction only when those capabilities become first-order
  requirements

### Layered Connectivity Strategy

| Layer | Method | Success Rate | Used When |
|-------|--------|--------------|-----------|
| 0 | Router-assisted port mapping (UPnP IGD) | Environment-dependent | Compatible home/edge router on local network |
| 1 | Direct QUIC | ~20% | No NAT, public IPs |
| 2 | Native NAT traversal | High* | Most NAT types |
| 3 | MASQUE relay (ADR-006) | ~100% | Symmetric NAT, CGNAT |

*Testing including CGNAT environments has shown excellent results. Specific success rates await broader deployment validation.

This layered approach ensures near-100% connectivity while minimizing relay usage.

### Symmetric NAT Handling

For symmetric NATs that use different ports per destination:
- Port prediction based on observed sequences
- Multiple candidate addresses with port ranges
- Higher coordination round count

## Consequences

### Benefits
- **No external servers**: Completely serverless NAT traversal
- **Lower latency**: No STUN round-trips before connecting
- **Simpler operations**: Nothing to deploy except nodes themselves
- **Native QUIC integration**: Leverages existing QUIC machinery
- **Symmetric**: Any connected peer can assist
- **Better home reachability**: UPnP IGD can improve inbound reachability on compatible consumer routers

### Trade-offs
- **Non-standard**: Custom extension frames (based on IETF drafts)
- **Requires seed peer**: Must connect to at least one peer first for pure native traversal
- **Router variance**: UPnP IGD support and behavior differ across consumer routers
- **Symmetric NAT limits**: Some challenging NAT configurations may still require relay fallback

### Standards Basis

Based on IETF drafts (not yet RFCs):
- `draft-seemann-quic-nat-traversal-02`
- `draft-ietf-quic-address-discovery-00`

## Alternatives Considered

1. **STUN/ICE/TURN**: Traditional NAT traversal stack
   - Rejected: Requires external infrastructure we don't want

2. **libp2p AutoNAT**: Higher-level protocol over QUIC
   - Rejected: Additional complexity layer, still needs coordination

3. **UPnP/PCP as the primary NAT strategy**
   - Rejected: Not universally supported, router compatibility varies, and it should not become the core connectivity dependency
   - Accepted in narrower form: UPnP IGD is useful as an additive local-router optimization layered under the native QUIC traversal strategy

4. **Switch from `igd-next` to a broader UPnP library now**
   - Rejected: ant-quic only needs a narrow IGD feature set today, and broader
     libraries add integration work without improving the core reachability
     design
   - `rupnp`: useful generic UPnP control-point library, but broader than
     needed for simple IGD mapping and would require more manual IGD service
     selection/action plumbing
   - `easy-upnp`: mostly a convenience wrapper over `igd-next`, so it does not
     materially improve capability for ant-quic
   - `oxy-upnp-igd`: focused IGD crate, but `AGPL-3.0-only`, which is a poor
     fit for this project's licensing posture

5. **Replace UPnP IGD with PCP/NAT-PMP now**
   - Rejected: PCP/NAT-PMP would expand reachability on some networks, but they
     are follow-on optimizations, not replacements for native QUIC NAT
     traversal or the current best-effort UPnP layer
   - Accepted in narrower form: when we add those protocols, prefer a separate
     backend using a focused crate such as `crab_nat`

6. **Always relay**: Route all traffic through known peers
   - Rejected: Inefficient, creates bottlenecks

## References

- Specification: `docs/rfcs/draft-seemann-quic-nat-traversal-02.txt`
- Address Discovery: `docs/rfcs/draft-ietf-quic-address-discovery-00.txt`
- Documentation: `docs/NAT_TRAVERSAL_GUIDE.md`
- Implementation: `src/nat_traversal_api.rs`, `src/connection/nat_traversal.rs`
- Frame definitions: `src/frame.rs`
- UPnP IGD crate: `igd-next`
- PCP/NAT-PMP candidate crate: `crab_nat`
