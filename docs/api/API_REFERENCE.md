# ant-quic API Reference

This document provides a comprehensive API reference for ant-quic v0.13.0+.

## Table of Contents

1. [Primary API: P2pEndpoint](#primary-api-p2pendpoint)
2. [Configuration](#configuration)
3. [NAT Traversal](#nat-traversal)
4. [Transport Parameters](#transport-parameters)
5. [Extension Frames](#extension-frames)
6. [Events](#events)
7. [Error Handling](#error-handling)
8. [Code Examples](#code-examples)

## Primary API: P2pEndpoint

The primary entry point for all P2P operations. All nodes are symmetric - every node can both initiate and accept connections.

`P2pEndpoint` is the canonical connectivity surface. `Node` is a convenience façade over the same endpoint-level behavior for applications that want a simpler top-level API.

### Creating an Endpoint

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

// Simple endpoint
let config = P2pConfig::builder()
    .known_peer("quic.saorsalabs.com:9000".parse()?)
    .build()?;
let endpoint = P2pEndpoint::new(config).await?;

// With custom configuration
let config = P2pConfig::builder()
    .bind_addr("0.0.0.0:9000".parse()?)
    .known_peer("peer1.example.com:9000".parse()?)
    .known_peer("peer2.example.com:9000".parse()?)
    .max_connections(100)
    .build()?;
let endpoint = P2pEndpoint::new(config).await?;
```

### Connecting to Peers

```rust
// Seed connectivity from configured known peers
endpoint.connect_known_peers().await?;

// Connect to a specific address through the unified outbound path
let connection = endpoint.connect_addr(peer_addr).await?;

// Connect to an authenticated peer identity
let connection = endpoint.connect_peer(peer_id).await?;
```

`connect_addr()` is not a separate direct-only strategy. It is the canonical address-based connect entrypoint and goes through the endpoint's normal routing/orchestration path, including connection reuse, direct establishment, and fallback handling when applicable. Richer peer-oriented behavior comes from `connect_known_peers()` and `connect_peer()`.

### Accepting Connections

```rust
// Accept incoming connections (all endpoints can accept)
while let Some(conn) = endpoint.accept().await {
    tokio::spawn(async move {
        handle_connection(conn).await;
    });
}
```

### Working with Streams

```rust
// Bidirectional stream
let (mut send, mut recv) = connection.open_bi().await?;
send.write_all(b"Hello").await?;
send.finish()?;
let response = recv.read_to_end(4096).await?;

// Unidirectional stream
let mut send = connection.open_uni().await?;
send.write_all(b"Data").await?;
send.finish()?;
```

## Configuration

### P2pConfig Builder

```rust
let config = P2pConfig::builder()
    .bind_addr(SocketAddr)          // Local address to bind
    .known_peer(SocketAddr)         // Known peer contact hint for initial connectivity (repeatable)
    .nat(NatConfig)                 // NAT traversal configuration
    .pqc(PqcConfig)                 // Post-quantum crypto configuration
    .mtu(MtuConfig)                 // MTU configuration
    .max_connections(usize)         // Maximum concurrent connections
    .build()?;
```

Known peers are seed inputs into the symmetric peer graph. They are not privileged bootstrap servers and do not imply a separate protocol role.

`SocketAddr` values in configuration are contact hints only. Durable peer identity
is always `PeerId`, derived from the authenticated ML-DSA-65 public key.

### NatConfig

```rust
pub struct NatConfig {
    pub port_mapping: PortMappingConfig,
    pub max_candidates: usize,
    pub enable_symmetric_nat: bool,
    pub enable_relay_fallback: bool,
    pub enable_relay_service: bool,
    pub relay_nodes: Vec<SocketAddr>,
    pub max_concurrent_attempts: usize,
    pub prefer_rfc_nat_traversal: bool,
}
```

Several NAT fields are now effectively always-on in symmetric mode. They remain configurable for compatibility and tuning, but normal endpoint dialing uses one unified orchestration path rather than user-selected fallback strategies.

`port_mapping` is the additive best-effort router-assist policy. The current
runtime uses UPnP IGD internally, starts after the bound UDP port is known,
renews leases in the background, and never blocks endpoint startup.

### PortMappingConfig

```rust
pub struct PortMappingConfig {
    pub enabled: bool,                    // default: true
    pub lease_duration_secs: u32,         // default: 3600
    pub allow_random_external_port: bool, // default: true
}
```

Common ergonomic entrypoint:

```rust
let config = P2pConfig::builder()
    .port_mapping_enabled(false)
    .build()?;
```

### PqcConfig

PQC is always enabled. These options tune PQC behavior:

```rust
let pqc = PqcConfig::builder()
    .ml_kem(true)                       // Enable ML-KEM-768 (default: true)
    .ml_dsa(true)                       // Enable ML-DSA-65 (default: true)
    .memory_pool_size(10)               // Buffer pool size (default: 10)
    .handshake_timeout_multiplier(1.5)  // Timeout multiplier (default: 1.5)
    .build()?;
```

### MtuConfig

```rust
pub struct MtuConfig {
    pub initial: u16,  // Initial MTU (default: 1200)
    pub min: u16,      // Minimum MTU (default: 1200)
    pub max: u16,      // Maximum MTU (default: 1500)
}
```

## NAT Traversal

### Address Discovery

```rust
// Connect to known peers and allow external address observation
endpoint.connect_known_peers().await?;

// Connect to a specific address through the canonical address entrypoint
let _connection = endpoint.connect_addr(target_addr).await?;

// Get discovered external address
let external: Option<SocketAddr> = endpoint.external_addr();

// Port mapping contributes an extra external candidate when active
let mapped: Option<SocketAddr> = endpoint.port_mapping_addr();
let all_candidates: Vec<SocketAddr> = endpoint.all_external_addrs();
```

Address discovery primarily comes from seeded peer connectivity. Applications generally call `connect_known_peers()` to establish that context, then use `connect_addr()` for address-based dialing or `connect_peer()` for peer-oriented dialing while the endpoint applies its normal routing/orchestration behavior.

### CandidateAddress

```rust
pub struct CandidateAddress {
    pub addr: SocketAddr,
    pub source: CandidateSource,
    pub priority: u32,
}

pub enum CandidateSource {
    Local,      // Interface address
    Observed,   // Via OBSERVED_ADDRESS frame
    Predicted,  // Symmetric NAT port prediction
}
```

## Transport Parameters

### NAT Traversal Capability

| Parameter ID | Description |
|-------------|-------------|
| `0x3d7e9f0bca12fea6` | NAT traversal capability indicator |
| `0x3d7e9f0bca12fea8` | RFC-compliant frame format support |
| `0x9f81a176` | Address discovery configuration |

## Extension Frames

### ADD_ADDRESS Frame

Advertises address candidates to peer.

```
Type: 0x3d7e90 (IPv4), 0x3d7e91 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       IP Address (4/16)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Port (16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### PUNCH_ME_NOW Frame

Coordinates hole punching timing.

```
Type: 0x3d7e92 (IPv4), 0x3d7e93 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Target IP Address (4/16)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Target Port (16)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### REMOVE_ADDRESS Frame

```
Type: 0x3d7e94

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### OBSERVED_ADDRESS Frame

Reports observed external address to peer.

```
Type: 0x9f81a6 (IPv4), 0x9f81a7 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Observed IP Address (4/16)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Observed Port (16)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Events

### P2pEvent

```rust
pub enum P2pEvent {
    // Connection lifecycle
    Connected { peer_id: PeerId, addr: SocketAddr },
    Disconnected { peer_id: PeerId, reason: String },
    ConnectionFailed { peer_id: PeerId, reason: String },

    // Address discovery
    AddressDiscovered { addr: SocketAddr },
    AddressChanged { old: SocketAddr, new: SocketAddr },

    // NAT traversal
    HolePunchStarted { peer_id: PeerId },
    HolePunchSucceeded { peer_id: PeerId, addr: SocketAddr },
    HolePunchFailed { peer_id: PeerId, reason: String },

    // Candidates
    CandidatesDiscovered { peer_id: PeerId, count: usize },
}
```

### Event Handling

```rust
let mut events = endpoint.subscribe();
while let Ok(event) = events.recv().await {
    match event {
        P2pEvent::Connected { peer_id, addr } => {
            println!("Connected to {} at {}", peer_id.to_hex(), addr);
        }
        P2pEvent::AddressDiscovered { addr } => {
            println!("External address: {}", addr);
        }
        P2pEvent::HolePunchSucceeded { peer_id, addr } => {
            println!("Direct connection to {}", peer_id.to_hex());
        }
        _ => {}
    }
}
```

## Error Handling

### EndpointError

```rust
pub enum EndpointError {
    BindFailed(std::io::Error),
    ConnectionFailed(String),
    Timeout,
    InvalidConfiguration(String),
    // ...
}
```

### NatTraversalError

```rust
pub enum NatTraversalError {
    NoViableCandidates,
    CoordinationTimeout,
    HolePunchFailed(String),
    // ...
}
```

## Code Examples

### Complete P2P Node

```rust
use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, P2pEvent, PortMappingConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure endpoint
    let config = P2pConfig::builder()
        .bind_addr("0.0.0.0:9000".parse()?)
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .nat(NatConfig {
            port_mapping: PortMappingConfig::default(),
            max_candidates: 15,
            enable_symmetric_nat: true,
            ..Default::default()
        })
        .max_connections(100)
        .build()?;

    // Create endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {}", endpoint.peer_id().to_hex());

    // Seed peer connectivity and external address observation
    endpoint.connect_known_peers().await?;
    if let Some(addr) = endpoint.external_addr() {
        println!("External: {}", addr);
    }
    if let Some(mapped) = endpoint.port_mapping_addr() {
        println!("Router-mapped candidate: {}", mapped);
    }

    // Subscribe to events
    let mut events = endpoint.subscribe();
    let ep = endpoint.clone();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            println!("Event: {:?}", event);
        }
    });

    // Accept connections (all nodes can accept)
    while let Some(conn) = endpoint.accept().await {
        tokio::spawn(async move {
            // Handle streams
            while let Ok((send, recv)) = conn.accept_bi().await {
                // Echo server
                let data = recv.read_to_end(4096).await?;
                send.write_all(&data).await?;
                send.finish()?;
            }
            Ok::<_, anyhow::Error>(())
        });
    }

    Ok(())
}
```

### Statistics Monitoring

```rust
let stats = endpoint.stats().await;
println!("Active connections: {}", stats.active_connections);
println!("Discovered addresses: {}", stats.discovered_addresses);
println!("Successful punches: {}", stats.successful_hole_punches);
println!("Failed punches: {}", stats.failed_hole_punches);
println!("Bytes sent: {}", stats.bytes_sent);
println!("Bytes received: {}", stats.bytes_received);
println!("Port mapping active: {}", endpoint.port_mapping_active());
println!("Port mapping addr: {:?}", endpoint.port_mapping_addr());
```

## Removed API (v0.13.0)

The following types were **removed** in v0.13.0:

| Removed | Reason |
|---------|--------|
| `QuicNodeConfig` | Use `P2pConfig` |
| `QuicP2PNode` | Use `P2pEndpoint` |
| `EndpointRole` | All nodes are symmetric |
| `NatTraversalRole` | All nodes are symmetric |
| `PqcMode` | PQC always enabled |
| `HybridPreference` | No mode selection |
| `bootstrap_nodes` | Use `known_peer()` / `known_peers()` seed inputs |

## Support

- GitHub Issues: https://github.com/dirvine/ant-quic/issues
- Documentation: https://docs.rs/ant-quic
- Examples: https://github.com/dirvine/ant-quic/tree/main/examples
