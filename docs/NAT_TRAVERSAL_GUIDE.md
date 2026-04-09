# NAT Traversal Testing and Configuration Guide

> **v0.13.0+ Note**: ant-quic uses a symmetric P2P architecture where all nodes have equal capabilities. There are no "client", "server", or "bootstrap" roles. Every node can connect to other nodes, accept connections, and coordinate NAT traversal for peers.

This guide provides detailed information on testing and configuring NAT traversal in ant-quic, including setup instructions for different NAT types and troubleshooting common issues.

The connectivity architecture now also treats **UPnP IGD** as a
best-effort local-router assist layer for compatible home networks. It is
additive to native QUIC NAT traversal and MASQUE relay fallback, not a
replacement for them.

## Table of Contents

1. [NAT Types Overview](#nat-types-overview)
2. [Local NAT Simulation](#local-nat-simulation)
3. [Docker NAT Testing](#docker-nat-testing)
4. [Configuration Options](#configuration-options)
5. [Testing Procedures](#testing-procedures)
6. [Troubleshooting](#troubleshooting)
7. [Performance Optimization](#performance-optimization)

## NAT Types Overview

ant-quic supports traversal through four primary NAT types:

### 1. Full Cone NAT (One-to-One NAT)
- **Characteristics**: Maps internal IP:port to external IP:port
- **Behavior**: Any external host can send packets to the internal host
- **Success Rate**: ~99%
- **Common In**: Basic home routers, some enterprise networks

### 2. Address Restricted Cone NAT
- **Characteristics**: External host must receive a packet first
- **Behavior**: Filters by source IP address only
- **Success Rate**: ~95%
- **Common In**: Most home routers

### 3. Port Restricted Cone NAT
- **Characteristics**: Filters by source IP:port combination
- **Behavior**: More restrictive than address restricted
- **Success Rate**: ~90%
- **Common In**: Security-conscious networks

### 4. Symmetric NAT
- **Characteristics**: Different mapping for each destination
- **Behavior**: Most restrictive, unpredictable port allocation
- **Success Rate**: ~85%
- **Common In**: Corporate firewalls, mobile carriers

### 5. Carrier-Grade NAT (CGNAT)
- **Characteristics**: Multiple layers of NAT
- **Behavior**: Extremely restrictive, limited port range
- **Success Rate**: ~70-80%
- **Common In**: Mobile networks, large ISPs

## Local NAT Simulation

### Using iptables (Linux)

#### Full Cone NAT
```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Setup Full Cone NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

#### Symmetric NAT
```bash
# Setup Symmetric NAT with random port allocation
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

#### Port Restricted NAT
```bash
# Setup Port Restricted NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -j DROP
```

### Using Network Namespaces

Create isolated network environments for testing:

```bash
# Create network namespaces
sudo ip netns add client_ns
sudo ip netns add nat_ns
sudo ip netns add server_ns

# Create virtual ethernet pairs
sudo ip link add veth0 type veth peer name veth1
sudo ip link add veth2 type veth peer name veth3

# Connect namespaces
sudo ip link set veth1 netns client_ns
sudo ip link set veth0 netns nat_ns
sudo ip link set veth2 netns nat_ns
sudo ip link set veth3 netns server_ns

# Configure IP addresses
sudo ip netns exec client_ns ip addr add 192.168.1.2/24 dev veth1
sudo ip netns exec nat_ns ip addr add 192.168.1.1/24 dev veth0
sudo ip netns exec nat_ns ip addr add 10.0.0.1/24 dev veth2
sudo ip netns exec server_ns ip addr add 10.0.0.2/24 dev veth3

# Enable interfaces
sudo ip netns exec client_ns ip link set veth1 up
sudo ip netns exec nat_ns ip link set veth0 up
sudo ip netns exec nat_ns ip link set veth2 up
sudo ip netns exec server_ns ip link set veth3 up

# Configure NAT in nat_ns
sudo ip netns exec nat_ns iptables -t nat -A POSTROUTING -o veth2 -j MASQUERADE
sudo ip netns exec nat_ns sysctl -w net.ipv4.ip_forward=1
```

## Docker NAT Testing

### Quick Start

```bash
# Clone the repository
git clone https://github.com/dirvine/ant-quic.git
cd ant-quic/docker

# Build Docker images
docker-compose build

# Start all NAT test scenarios
docker-compose up -d

# Run specific NAT test
docker exec test-runner /app/run-test.sh full_cone_nat
docker exec test-runner /app/run-test.sh symmetric_nat
docker exec test-runner /app/run-test.sh port_restricted_nat

# View results
docker exec test-runner cat /app/results/test-*.json | jq .
```

### Docker Compose Configuration

The `docker-compose.yml` defines multiple services simulating different NAT scenarios:

```yaml
version: '3.8'

services:
  # v0.13.0+: All nodes are symmetric - no "bootstrap" role distinction
  peer-1:
    build: .
    networks:
      public_net:
        ipv4_address: 172.20.0.10
    command: ["/app/ant-quic", "--listen", "0.0.0.0:9000"]

  nat-gateway-1:
    build:
      context: .
      dockerfile: Dockerfile.nat
    networks:
      public_net:
        ipv4_address: 172.20.0.20
      private_net_1:
        ipv4_address: 10.1.0.1
    cap_add:
      - NET_ADMIN
    environment:
      NAT_TYPE: "full_cone"

  # v0.13.0+: Uses --connect instead of --bootstrap
  peer-2:
    build: .
    networks:
      private_net_1:
        ipv4_address: 10.1.0.10
    depends_on:
      - nat-gateway-1
    command: ["/app/ant-quic", "--connect", "172.20.0.10:9000"]

networks:
  public_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24

  private_net_1:
    driver: bridge
    ipam:
      config:
        - subnet: 10.1.0.0/24
```

### Custom NAT Configurations

Create custom NAT rules in `docker/nat-setup.sh`:

```bash
#!/bin/bash

NAT_TYPE="${NAT_TYPE:-full_cone}"

case $NAT_TYPE in
  "full_cone")
    # Full Cone NAT - most permissive
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A FORWARD -j ACCEPT
    ;;
    
  "symmetric")
    # Symmetric NAT - different port for each destination
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i eth0 -j DROP
    ;;
    
  "port_restricted")
    # Port Restricted NAT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i eth0 -j DROP
    ;;
    
  "cgnat")
    # Simulate CGNAT with limited port range
    iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 172.20.0.20:10000-10999
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i eth0 -j DROP
    ;;
esac

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
```

## Configuration Options

### Transport Parameters

Configure NAT traversal behavior in ant-quic:

```rust
// v0.13.0+: All nodes are symmetric - no role configuration needed
// Transport Parameters for NAT traversal:
// - 0x3d7e9f0bca12fea6: NAT traversal capability
// - 0x3d7e9f0bca12fea8: RFC-compliant frame format
// - 0x9f81a176: Address discovery

// Configure via P2pConfig
let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .nat(NatConfig {
        max_candidates: 10,
        enable_symmetric_nat: true,
        ..Default::default()
    })
    .build()?;
```

### Router-Assisted Port Mapping

ant-quic's connectivity stack now includes **best-effort UPnP IGD** on
compatible local gateways:

- it is meant to be **default-on** for home-friendly deployments
- it has a simple explicit **off switch**: `--no-port-mapping`
- a successful mapping contributes an additional public candidate address
- it does **not** replace native QUIC address observation, hole punching, or
  MASQUE relay fallback
- it does **not** by itself prove `can_receive_direct`; peer-verified inbound
  success is still the stronger signal
- runtime surfaces expose `endpoint.port_mapping_active()` and
  `endpoint.port_mapping_addr()` so operators can distinguish router assist from
  peer-observed reachability

Treat UPnP IGD as a router-local reachability assist layer, not as the primary
NAT traversal protocol.

### Scoped mDNS Discovery

ant-quic supports first-party scoped mDNS out of the box, with zero-config
browse+advertise enabled by default for non-loopback endpoints:

- `service` controls the DNS-SD service/application scope
- `namespace` constrains discoveries to the current workspace/network scope
- `mode` chooses `browse`, `advertise`, or `both`
- `auto_connect` chooses discover-only vs automatic dialing
- `metadata` publishes optional TXT key/value pairs alongside the built-in
  `peer_id`, `service`, `namespace`, and assist-role hints

mDNS results are pre-auth locator claims only. The authenticated QUIC handshake
still decides the durable `PeerId`.

ant-quic now also publishes relay/bootstrap/coordinator capability hints by
default in its discovery metadata and status surfaces. Those hints mean "this
node is willing to participate", not "this node must be used" or "this node is
currently the best assist path".

### Runtime Configuration

Configure via command-line arguments:

```bash
# Seed connectivity from known peers and print periodic stats
ant-quic --listen [::]:0 \
         --known-peers quic.saorsalabs.com:9000 \
         --stats

# Connect to a specific address through the unified outbound path
ant-quic --listen [::]:0 \
         --connect 203.0.113.10:9000

# Disable best-effort router assist on demand
ant-quic --listen [::]:0 \
         --known-peers quic.saorsalabs.com:9000 \
         --no-port-mapping

# Use the built-in default mDNS behavior (browse+advertise with auto-connect)
ant-quic --listen [::]:0 \
         --stats

# Override the default mDNS scope and mode explicitly
ant-quic --listen [::]:0 \
         --mdns-service ant-quic \
         --mdns-namespace workspace-a \
         --mdns-mode browse \
         --mdns-auto-connect enabled
```

### Programmatic Configuration

Configure the policy surface through `P2pConfig` and `NatConfig`:

```rust
use ant_quic::{NatConfig, P2pConfig, PortMappingConfig};
use ant_quic::unified_config::{AutoConnectPolicy, MdnsConfig, MdnsMode};

let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .mdns(MdnsConfig {
        enabled: true,
        service: Some("ant-quic".into()),
        namespace: Some("workspace-a".into()),
        mode: MdnsMode::Both,
        auto_connect: AutoConnectPolicy::Enabled,
        metadata: std::collections::BTreeMap::new(),
    })
    .nat(NatConfig {
        port_mapping: PortMappingConfig {
            enabled: true,
            lease_duration_secs: 1800,
            allow_random_external_port: true,
        },
        max_candidates: 10,
        ..Default::default()
    })
    .build()?;
```

## Testing Procedures

### Basic Connectivity Test

```bash
# v0.13.0+: All nodes are symmetric - no "bootstrap" role distinction
# 1. Start first peer (listening)
cargo run --bin ant-quic -- --listen 0.0.0.0:9000

# 2. Start second peer (connecting)
cargo run --bin ant-quic -- --connect localhost:9000

# 3. Verify connection
# Look for: "Successfully connected through NAT"
```

### Comprehensive NAT Test Suite

```bash
# Run all NAT traversal tests
cargo test --test nat_traversal_comprehensive -- --nocapture

# Run specific NAT scenario
cargo test --test nat_traversal_comprehensive test_symmetric_nat -- --nocapture

# Run with detailed logging
RUST_LOG=ant_quic::nat_traversal=trace cargo test nat_traversal
```

### Performance Testing

```bash
# Measure NAT traversal success rate
cargo bench --bench nat_traversal_performance

# Test under load
cargo test --test connection_lifecycle_tests stress -- --ignored

# Measure hole punching latency
cargo run --example nat_latency_test
```

### Multi-Node Testing

```bash
# v0.13.0+: All nodes are symmetric P2P nodes
# Start first peer (as initial connection target)
ant-quic --listen 0.0.0.0:9000 --log peer-0.log &

# Start multiple additional peers
for i in {1..10}; do
  ant-quic --connect localhost:9000 --peer-id "peer-$i" \
           --log "peer-$i.log" &
done

# Monitor success rate
grep "NAT traversal successful" peer-*.log | wc -l
```

## Troubleshooting

### Common Issues

#### 1. No Connection Established

**Symptoms**: Timeout errors, no successful connections

**Diagnosis**:
```bash
# Check if bootstrap is reachable
nc -zv bootstrap-host 9000

# Verify NAT type
curl https://ipinfo.io/ip  # External IP
ip addr show  # Internal IP

# Check firewall
sudo iptables -L -n | grep 9000
```

**Solutions**:
- Ensure initial peer (known_peer) has reachable IP
- Check firewall rules on both ends
- Verify network connectivity

#### 2. Low Success Rate

**Symptoms**: < 80% success rate for Full Cone NAT

**Diagnosis**:
```bash
# Enable detailed logging
RUST_LOG=ant_quic::nat_traversal=debug cargo run --bin ant-quic

# Check candidate discovery
grep "Discovered candidate" debug.log

# Verify hole punching attempts
grep "PUNCH_ME_NOW" debug.log
```

**Solutions**:
- Increase `max_candidates` setting
- Extend `punch_timeout` duration
- Enable address prediction for symmetric NAT

#### 3. Symmetric NAT Failures

**Symptoms**: Consistent failures with symmetric NAT

**Diagnosis**:
```bash
# Test port allocation pattern
./scripts/test-symmetric-nat-pattern.sh

# Check prediction accuracy
grep "Predicted port" debug.log
```

**Solutions**:
```toml
[nat_traversal]
enable_address_prediction = true
prediction_range = 200  # Increase range
symmetric_nat_retry_count = 5
```

### Debug Tools

#### Native Reachability / Mapping Hints

ant-quic does not currently ship a standalone `detect_nat_type` example and
does not perform classic STUN-style NAT classification. Instead, inspect the
native QUIC behavior hints exposed by `Node::status()`:

```rust,ignore
let status = node.status().await;

println!("NAT behavior hint: {:?}", status.nat_type);
println!("External addresses: {:?}", status.external_addrs);
println!(
    "Direct reachability scope: {:?}",
    status.direct_reachability_scope
);
println!("Port mapping active: {}", status.port_mapping_active);
println!("Relay sessions: {}", status.relay_sessions);
```

Treat this output as operational telemetry:
- externally observed addresses reported by peers
- whether direct reachability has been verified recently
- whether router-assisted port mapping is active
- whether native observations suggest endpoint-dependent mapping and relay is more likely to help

#### Connection Diagnostics

```bash
# Run connection diagnostics
cargo run --example connection_diagnostics -- --target bootstrap:9000

# Provides:
# - RTT measurements
# - Packet loss rate
# - NAT traversal attempts
# - Success/failure reasons
```

#### Packet Capture

```bash
# Capture NAT traversal packets
sudo tcpdump -i any -w nat_traversal.pcap \
  'udp and (port 9000 or port 9001)'

# Analyze with Wireshark
wireshark nat_traversal.pcap
# Filter: quic.frame_type == 0x40  # ADD_ADDRESS frames
```

## Performance Optimization

### Optimize Candidate Discovery

Use a combination of:

- multiple known peers to improve external address observation
- sufficient candidate breadth (`NatConfig::max_candidates`)
- best-effort UPnP IGD on compatible home routers to add a router-assisted
  public candidate early
- normal native QUIC NAT traversal and relay fallback after that

A practical tuning mindset is:

1. prefer more good candidates over hard-coded strategy toggles
2. treat UPnP IGD as additive signal generation, not a magic replacement layer
3. measure direct success, NAT-traversed success, and relay usage separately

### Reduce Hole Punching Latency

```toml
[nat_traversal.timing]
initial_retry_interval_ms = 100  # Start fast
retry_multiplier = 1.5          # Exponential backoff
max_retry_interval_ms = 2000    # Cap retries
punch_burst_size = 3            # Send multiple packets
```

### Connection Pooling

```rust
// Reuse successful NAT mappings
let pool = ConnectionPool::new()
    .with_nat_cache_duration(Duration::from_secs(300))
    .with_max_cached_mappings(100);
```

### Metrics and Monitoring

```bash
# Enable metrics endpoint
ant-quic --metrics-port 8080

# Query metrics
curl localhost:8080/metrics | grep nat_

# Key metrics:
# - nat_traversal_attempts_total
# - nat_traversal_success_total
# - nat_traversal_duration_seconds
# - nat_hole_punching_packets_sent
```

## Best Practices

1. **Always test with realistic NAT**
   - Use Docker containers for consistency
   - Test all NAT types in CI/CD

2. **Monitor success rates**
   - Alert on < 90% for Full Cone
   - Alert on < 80% for Symmetric

3. **Optimize for mobile networks**
   - Expect CGNAT and symmetric NAT
   - Implement aggressive retry strategies

4. **Handle failures gracefully**
   - Implement relay fallback
   - Provide clear error messages

5. **Regular testing**
   ```bash
   # Add to CI pipeline
   ./scripts/nat-traversal-regression-test.sh
   ```

## Advanced Topics

### Custom NAT Traversal Strategies

Implement custom strategies for specific network environments:

```rust
pub trait NatTraversalStrategy {
    fn discover_candidates(&self) -> Vec<CandidateAddress>;
    fn predict_symmetric_port(&self, history: &[u16]) -> u16;
    fn should_retry(&self, attempt: u32, last_error: &Error) -> bool;
}

// Example: Aggressive strategy for mobile networks
struct MobileNetworkStrategy;

impl NatTraversalStrategy for MobileNetworkStrategy {
    fn discover_candidates(&self) -> Vec<CandidateAddress> {
        // Include cellular interface addresses
        // Predict multiple port ranges
        // Add TURN relay candidates
    }
    
    fn predict_symmetric_port(&self, history: &[u16]) -> u16 {
        // Use machine learning model trained on mobile NAT behavior
    }
    
    fn should_retry(&self, attempt: u32, last_error: &Error) -> bool {
        // More aggressive retries for mobile networks
        attempt < 10 && !matches!(last_error, Error::PermanentFailure)
    }
}
```

### Protocol Extensions

ant-quic implements QUIC NAT traversal extensions per draft-seemann-quic-nat-traversal-02:

- **Transport Parameter 0x58**: Negotiates NAT traversal support
- **ADD_ADDRESS (0x3d7e90-91)**: Advertise candidate addresses
- **PUNCH_ME_NOW (0x3d7e92-93)**: Coordinate hole punching
- **REMOVE_ADDRESS (0x3d7e94)**: Remove failed candidates
- **OBSERVED_ADDRESS (0x9f81a6-a7)**: Report observed addresses (per draft-ietf-quic-address-discovery-00)

### Integration with Other Protocols

```rust
// WebRTC-style ICE integration
let ice_agent = IceAgent::new()
    .with_quic_transport(quic_endpoint)
    .with_stun_servers(vec!["stun.l.google.com:19302"]);

// Custom protocol bridging
let bridge = ProtocolBridge::new()
    .add_protocol(QuicNatTraversal::new())
    .add_protocol(WebRtcDataChannel::new())
    .with_fallback(TurnRelay::new());
```

## Conclusion

Successful NAT traversal is critical for P2P connectivity. This guide provides:

- Comprehensive testing procedures for all NAT types
- Docker-based simulation environments
- Configuration options for different scenarios
- Troubleshooting steps for common issues
- Performance optimization techniques

Regular testing with these procedures ensures ant-quic maintains high connectivity success rates across diverse network environments.
