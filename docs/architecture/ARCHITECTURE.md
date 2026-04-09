# ant-quic Architecture

## Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks. It extends the QUIC protocol with native NAT traversal capabilities based on draft-seemann-quic-nat-traversal-02 and draft-ietf-quic-address-discovery-00, and its connectivity architecture also includes best-effort router-assisted port mapping via UPnP IGD as an additive local reachability optimization.

**v0.13.0+: Pure Symmetric P2P Architecture**
- Every node is identical - can connect, accept, and coordinate
- 100% Post-Quantum Cryptography (ML-KEM-768, ML-DSA-65) on every connection
- No client/server/bootstrap role distinctions
- Pure PQC Raw Public Keys for authentication (see `docs/rfcs/ant-quic-pqc-authentication.md`)

## Three-Layer Architecture

### Layer 1: Protocol Implementation (Low-Level)

This layer contains the core QUIC protocol implementation.

#### Core Components
- **`src/endpoint.rs`** - QUIC endpoint managing connections and packets
- **`src/connection/mod.rs`** - Connection state machine with NAT traversal extensions
- **`src/frame.rs`** - QUIC frames including NAT traversal extension frames:
  - `ADD_ADDRESS` (0x3d7e90 IPv4, 0x3d7e91 IPv6) - Advertise candidate addresses
  - `PUNCH_ME_NOW` (0x3d7e92 IPv4, 0x3d7e93 IPv6) - Coordinate simultaneous hole punching
  - `REMOVE_ADDRESS` (0x3d7e94) - Remove invalid candidates
  - `OBSERVED_ADDRESS` (0x9f81a6 IPv4, 0x9f81a7 IPv6) - Report observed external address
- **`src/crypto/`** - Cryptographic implementations:
  - TLS 1.3 support via rustls
  - Pure PQC Raw Public Keys with ML-DSA-65 identities and `PeerId = SHA-256(public_key)`
  - Post-Quantum Cryptography (ML-KEM-768, ML-DSA-65)
- **`src/transport_parameters.rs`** - QUIC transport parameters including:
  - `0x3d7e9f0bca12fea6` - NAT traversal capability negotiation
  - `0x3d7e9f0bca12fea8` - RFC-compliant frame format
  - `0x9f81a176` - Address discovery configuration

#### Key Features
- Full QUIC v1 (RFC 9000) implementation
- 100% Post-Quantum Cryptography (v0.13.0+)
- Zero-copy packet processing
- Congestion control (New Reno, Cubic, BBR)
- Connection migration support
- 0-RTT data support

### Layer 2: Integration APIs (High-Level)

This layer provides developer-friendly APIs wrapping the low-level protocol.

#### Primary Components
- **`src/p2p_endpoint.rs`** - `P2pEndpoint` class (v0.13.0+)
  - Primary API for symmetric P2P networking
  - Event-driven architecture
  - Address discovery and peer management

- **`src/unified_config.rs`** - Configuration types (v0.13.0+)
  - `P2pConfig` - Main configuration builder
  - `NatConfig` - NAT traversal tuning
  - `MtuConfig` - MTU settings for PQC
  - `PqcConfig` - Post-quantum crypto tuning

- **`src/nat_traversal_api.rs`** - `NatTraversalEndpoint` class
  - Low-level NAT traversal coordination
  - Session state management
  - Event-driven architecture

- **`src/quic_node.rs`** - `QuicP2PNode` class
  - Application-ready P2P node
  - Peer discovery and connection management
  - Authentication with ML-DSA-65 raw public keys
  - Chat protocol support
  - Connection state tracking and statistics

- **`src/high_level/`** - Async QUIC wrapper
  - `Endpoint` - Async endpoint management
  - `Connection` - High-level connection API
  - `SendStream`/`RecvStream` - Stream I/O with tokio integration

#### Helper Components
- **`src/candidate_discovery.rs`** - Network interface and address discovery
- **`src/port_mapping.rs`** - Best-effort router-assisted UDP port mapping lifecycle (UPnP IGD first cut)
- **`src/auth.rs`** - Authentication manager with challenge-response protocol
- **`src/chat.rs`** - Chat protocol implementation

### Layer 3: Applications (Binaries)

User-facing applications demonstrating the library capabilities.

#### Main Binary
- **`src/bin/ant-quic.rs`** - Full QUIC P2P implementation
  - Uses symmetric P2P model (v0.13.0+)
  - Implements chat with peer discovery
  - Dashboard support for monitoring
  - Uses the unified outbound connect surface (`connect_known_peers`, `connect_addr`)
  - NAT traversal event handling without exposing normal-user strategy toggles
  - Exposes `--no-port-mapping` plus stats/status output for router-assist state

#### Examples
- **`examples/chat_demo.rs`** - Chat application demo
- **`examples/simple_chat.rs`** - Minimal chat implementation
- **`examples/dashboard_demo.rs`** - Real-time statistics monitoring

## Data Flow

### Connection Establishment Flow

```
Application / CLI
    ↓
P2pEndpoint unified outbound orchestrator
    ↓
NatTraversalEndpoint + relay/NAT helpers
    ↓
high_level::Endpoint
    ↓
Low-level Endpoint → Connection → Streams
```

Normal consumers should not choose between direct, dual-stack, NAT traversal,
or relay modes. `P2pEndpoint` selects the path internally based on available
addresses, observed reachability, and fallback needs.

### NAT Traversal Flow (Symmetric P2P)

0. **Router-Assist Phase (Best Effort)**
   - On compatible home routers, the connectivity architecture may request a local UDP port mapping via UPnP IGD
   - A successful mapping contributes an additional public candidate address
   - The runtime is managed in `src/port_mapping.rs` and surfaced through endpoint/node status
   - This improves reachability but does **not** replace peer-verified direct reachability checks

1. **Discovery Phase**
   - Local interface enumeration
   - Connect to seeded known peers and refreshed runtime peers
   - Learn external address candidates via OBSERVED_ADDRESS frames when peers report them

2. **Coordination Phase**
   - Exchange candidates with target peer via any connected peer
   - Receive PUNCH_ME_NOW frame for timing

3. **Hole Punching Phase**
   - Simultaneous transmission to create NAT bindings
   - Multiple candidate pairs tested in parallel

4. **Validation Phase**
   - QUIC path validation
   - Connection migration to direct path

5. **Fallback Phase**
   - If direct paths still fail, MASQUE relay keeps connectivity available

## Key Design Decisions

### Symmetric P2P Model (v0.13.0+)

All nodes have identical capabilities:
- Can initiate connections (like a "client")
- Can accept connections (like a "server")
- Can participate in NAT traversal coordination for other peers
- Can relay traffic when direct connection fails

There are no special roles. The term "known_peers" replaces "bootstrap_nodes" - they're just addresses to connect to first.

`PeerId` is the durable identity for a peer. `SocketAddr` is only the latest
routable contact hint and can change across NAT rebinding, reconnects, or path
migration. Any durable coordinator/bootstrap cache must therefore key by
`PeerId` and treat stored addresses as mutable reachability metadata.

See [PEER_IDENTITY_AND_ADDRESSING.md](PEER_IDENTITY_AND_ADDRESSING.md) for the
short rule set we use when reviewing identity vs reachability changes.

See [UNIFIED_CONNECTIVITY_PLAN.md](UNIFIED_CONNECTIVITY_PLAN.md) for the
consumer-facing plan to unify discovery policy, connectivity orchestration, and
pure-binary VPS proof of 100% reachability.

### Why Not Use STUN/TURN?
- draft-seemann-quic-nat-traversal-02 provides QUIC-native approach
- No external coordination services are needed
- Address observation happens through normal QUIC connections
- UPnP IGD is only a local-router optimization, not a central dependency
- More efficient and simpler architecture

### Pure PQC Raw Public Keys
- Implements certificate-free operation inspired by RFC 7250
- ML-DSA-65 public keys for peer identity and authentication
- PeerId = SHA-256(ML-DSA-65 public key)
- ML-KEM-768 key exchange on every connection
- ML-DSA-65 signatures on every authenticated connection
- See `docs/rfcs/ant-quic-pqc-authentication.md` for full specification

### 100% Post-Quantum Cryptography (v0.13.0+)
- ML-KEM-768 key encapsulation on every connection
- ML-DSA-65 digital signatures (optional)
- No classical-only fallback mode
- Future-proof against quantum computers

## Integration Points

### For Library Users (v0.13.0+)

```rust
use ant_quic::{P2pConfig, P2pEndpoint};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure symmetric P2P endpoint
    let config = P2pConfig::builder()
        .known_peer("peer.example.com:9000".parse()?)
        .build()?;

    // Create endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {:?}", endpoint.peer_id());

    // Known peers are discovery/bootstrap inputs, not special-role servers
    endpoint.connect_known_peers().await?;

    // Convenience: connect to a specific address through the unified
    // outbound orchestration path
    let _peer = endpoint.connect_addr("peer.example.com:9000".parse()?).await?;

    // External address is now discoverable
    if let Some(addr) = endpoint.external_addr() {
        println!("External address: {}", addr);
    }

    Ok(())
}
```

### For Protocol Extensions

The architecture supports extensions through:
- Custom transport parameters
- Additional frame types
- Event callbacks
- Custom authentication schemes

## Current Status

### Completed
- Core QUIC protocol (RFC 9000)
- NAT traversal extension frames (0x3d7e90+, 0x9f81a6+)
- Pure PQC Raw Public Keys (ant-quic-pqc-authentication.md)
- 100% Post-Quantum Cryptography (v0.13.0+)
- Symmetric P2P architecture (v0.13.0+)
- High-level APIs (`P2pEndpoint`, `NatTraversalEndpoint`)
- Best-effort UPnP IGD port-mapping lifecycle and status surfaces
- Production binary with full functionality
- Comprehensive test suite
- Peer authentication with ML-DSA-65 raw public keys
- Secure chat protocol
- Real-time monitoring dashboard
- GitHub Actions for automated releases

### In Progress
- Session state machine polling (nat_traversal_api.rs)
- Platform-specific network discovery improvements
- Windows and Linux ARM builds in CI

### Future Work
- Performance optimizations
- Additional NAT traversal strategies
- Enhanced monitoring and metrics
- WebTransport support
- Decentralized peer discovery

## Testing

The codebase includes:
- Unit tests throughout modules
- Integration tests for NAT traversal
- Network simulation capabilities
- Stress tests for performance
- Platform-specific tests

Run tests with:
```bash
cargo test                    # All tests
cargo test nat_traversal     # NAT traversal tests
cargo test --ignored stress  # Stress tests
```

## Contributing

When contributing, maintain the three-layer architecture:
1. Protocol changes go in Layer 1
2. API improvements go in Layer 2
3. New examples/apps go in Layer 3

Ensure all changes are compatible with the core specifications:
- RFC 9000 (QUIC)
- draft-seemann-quic-nat-traversal-02
- draft-ietf-quic-address-discovery-00
- ant-quic-pqc-authentication.md (Pure PQC Raw Public Keys)
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
