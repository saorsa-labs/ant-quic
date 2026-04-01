# ADR-009: MASQUE Relay Data Plane Implementation

## Status

Accepted (2026-03-29)

## Context

### The Problem

ADR-006 selected MASQUE CONNECT-UDP Bind as the relay protocol and the control plane was fully implemented: session establishment, capsule encoding, and context management all work. However, the data plane was stub code -- `forward_datagram` was a no-op and `try_relay_connection` bypassed the tunnel entirely.

Testing with symmetric NAT nodes (Linux network namespaces using `MASQUERADE --random-fully`) confirmed:

- **Hole-punching fails for symmetric NAT**: Per-destination port randomization defeats prediction-based traversal
- **The relay control plane works but no data flows**: Sessions establish, contexts are allocated, but datagrams are never forwarded
- **The RFC model requires the NAT-restricted node to set up the relay proactively**: The initiator cannot reach the NAT-restricted node, so the relay must already be in place before any connection attempt

## Decision

Implement the relay data plane with the following key design decisions.

### 1. Proactive Relay Setup by NAT-Restricted Nodes

The NAT-restricted node -- not the initiator -- is responsible for establishing the relay:

1. NAT node detects symmetric NAT via `OBSERVED_ADDRESS` port diversity (multiple peers report different source ports for the same endpoint)
2. NAT node establishes a relay session with a connected cloud/bootstrap node
3. The relay address is advertised via `ADD_ADDRESS` frames, which propagate through the DHT

This is the only model that works: the initiator cannot reach the NAT-restricted node without the relay already being in place.

### 2. Stream-Based Forwarding

QUIC datagrams were the obvious choice for forwarding but are unsuitable:

- **QUIC datagram MTU is ~1120 bytes** (after QUIC header overhead)
- **QUIC Initial packets are 1200 bytes** (mandatory minimum per RFC 9000)
- Initial packets from incoming connections would be truncated and dropped

Instead, forwarding uses persistent QUIC bidirectional streams with length-prefixed framing:

```
[4-byte big-endian length][UncompressedDatagram payload]
```

This adds reliability overhead compared to unreliable UDP, but guarantees that full-size QUIC Initial packets survive the relay hop.

### 3. Secondary Quinn Endpoint

A secondary Quinn endpoint accepts relay'd connections:

```
                                          ┌─────────────────────┐
                                          │   NAT-Restricted    │
                                          │   Node              │
┌──────────┐     UDP      ┌──────────┐   │                     │
│  Client  │─────────────►│  Relay   │   │  ┌───────────────┐  │
│          │              │  Node    │───►│  │ Secondary     │  │
└──────────┘              └──────────┘   │  │ Endpoint      │  │
                           QUIC stream   │  │ (MasqueRelay  │  │
                                         │  │  Socket)      │  │
                                         │  └───────────────┘  │
                                         │                     │
                                         │  ┌───────────────┐  │
                                         │  │ Main Endpoint │  │
                                         │  │ (real UDP)    │  │
                                         │  └───────────────┘  │
                                         └─────────────────────┘
```

- **Main endpoint** stays on the real UDP socket (used for direct connections and the relay control stream itself)
- **Secondary endpoint** uses `MasqueRelaySocket`, which implements Quinn's `AsyncUdpSocket` trait
- `MasqueRelaySocket` reads and writes via the relay stream, presenting relay'd UDP packets to Quinn as if they arrived on a local socket

This avoids a circular dependency: if the main endpoint were rebound to the relay socket, the relay control stream (which runs over that endpoint) would break.

### 4. DHT Address Propagation

Relay addresses propagate through the existing address notification and DHT machinery:

1. `ADD_ADDRESS` frames are sent to connected peers
2. Frames surface as `EndpointEvent` -> `P2pEvent` -> `ConnectionEvent`
3. saorsa-core's background task calls `dht.touch_node(peer_id, relay_addr)` to update the DHT
4. **Filter**: only accept address updates where the IP differs from the connection IP (prevents a node from adding redundant entries for its own direct address)

## Consequences

### Benefits

- **Symmetric NAT nodes fully participate in the network**: No degraded mode or reduced functionality
- **Transparent to the application layer**: Quinn handles connections via the relay socket identically to direct connections
- **No special client code needed**: Clients connect to the relay address like any other address resolved from the DHT

### Trade-offs

- **Extra hop latency through relay** (~50-100ms per direction)
- **Relay node bears bandwidth cost**: All data for the NAT-restricted node flows through the relay
- **Stream-based forwarding adds reliability overhead**: TCP-like semantics where UDP unreliability would suffice, though this also prevents packet loss on the relay hop

### Implementation Status

| Component | File | Status |
|-----------|------|--------|
| Relay server UDP socket binding | `relay_server.rs` | Complete |
| Stream-based forwarding loop | `relay_server.rs` | Complete |
| MasqueRelaySocket (AsyncUdpSocket) | `relay_socket.rs` | Complete |
| OBSERVED_ADDRESS sending | `connection/mod.rs` | Complete |
| Symmetric NAT detection | `nat_traversal_api.rs` | Complete |
| Proactive relay setup | `nat_traversal_api.rs` | Complete |
| Secondary endpoint | `nat_traversal_api.rs` | Complete |
| ADD_ADDRESS -> DHT bridge | saorsa-core `network.rs` | Complete |
| Address suppression after relay | `nat_traversal_api.rs` | Complete |

## Alternatives Considered

1. **QUIC datagrams for forwarding**
   - Rejected: MTU limitation (~1120 bytes) truncates QUIC Initial packets (1200 bytes minimum)

2. **Endpoint rebind to relay socket**
   - Rejected: Circular dependency -- the relay control stream runs over the main endpoint, so rebinding it to the relay socket would sever the control path

3. **Initiator-side relay**
   - Rejected: Does not work for symmetric NAT targets -- the initiator has no way to reach the target without the relay already being established by the target

## References

- **ADR-006**: MASQUE CONNECT-UDP Bind Relay
- **ADR-005**: Native QUIC NAT Traversal
- **RFC draft-ietf-masque-connect-udp-listen-10**: MASQUE CONNECT-UDP Bind specification
- **RFC 9000**: QUIC Transport Protocol (1200-byte Initial packet minimum)
