# Node application bidirectional streams (`open_bi` / `accept_bi`)

Status: **Design + implementation** (branch `feat/node-app-bidi-streams`).
Owner: ant-quic transport. Consumer: **x0x** tailnet per-peer byte-stream forwarding.

## Problem

x0x wraps `ant_quic::Node` as its single connection handle and needs to forward a
local TCP port / SOCKS5 to a service on a peer machine — i.e. it needs
**bidirectional application byte-streams** to a connected peer. Today `Node`
exposes only message-level `send(peer, &[u8])` / `recv() -> (PeerId, Vec<u8>)`.
The underlying QUIC primitives `Connection::open_bi()` / `accept_bi()` live on
`high_level::Connection`, reachable only through the lower-level
`NatTraversalEndpoint`, and no consumer drives them from a `Node`. x0x cannot
reach byte-streams through the handle it owns.

## Decision: `open_bi` / `accept_bi` on `Node` (not `peer_connection()`)

Two candidate shapes were considered:

1. **`Node::peer_connection(peer) -> Option<Connection>`** — expose the
   high-level `Connection` so the consumer calls `open_bi`/`accept_bi` on it.
2. **`Node::open_bi(peer)` / `Node::accept_bi()`** — expose the stream
   operations directly.

We ship **(2)**. With (1) the consumer would call `accept_bi()` on the *same*
`Connection` that ant-quic's internal reader task already drives — a
cooperative-cancel race that drops ACK-v2 / relay / control bytes (the exact
hazard from issue #166's reader-task history). With (2), `Node` stays the
**single owner** of the connection, the NAT-traversal state, and the reader
task; the demux stays centralized, so app and internal traffic can never cross.

## Final public signatures

```rust
impl Node {
    /// Open a bidirectional application byte-stream to a connected peer.
    pub async fn open_bi(
        &self,
        peer: &PeerId,
    ) -> Result<(HighLevelSendStream, HighLevelRecvStream), NodeError>;

    /// Accept the next inbound application bi-stream from any peer.
    pub async fn accept_bi(
        &self,
    ) -> Result<(PeerId, HighLevelSendStream, HighLevelRecvStream), NodeError>;
}
```

`HighLevelSendStream` (`ant_quic::SendStream`) implements `tokio::io::AsyncWrite`
and `HighLevelRecvStream` (`ant_quic::RecvStream`) implements
`tokio::io::AsyncRead`, so consumers wrap them directly with `tokio::io`
adapters. `open_bi`/`accept_bi` are symmetric to the existing `send`/`recv`
message API and live on the same handle.

## How app-vs-internal stream separation is guaranteed (requirement #1)

The per-connection reader task (`P2pEndpoint::spawn_reader_task`) already owns
`accept_bi()`/`accept_uni()` for every QUIC connection (direct **and** relayed).
It demultiplexes inbound bidi streams by an 8-byte magic prefix that the opener
writes as the stream's first bytes:

| Prefix (8-byte ASCII)   | Meaning                       | Routing                         |
|-------------------------|-------------------------------|---------------------------------|
| `ANQAckB3`              | ACK-v2 request (internal)     | `handle_ack_bidi_stream`        |
| **`ANQAppB1`** (new)    | **application bi-stream**     | **forwarded to `app_bi` queue** |
| (4-byte BE length)      | MASQUE relay CONNECT-UDP      | `handle_relay_bidi_stream_*`    |
| anything else           | unknown                       | dropped                         |

Plain `Node::send`/`recv` message transport uses **unidirectional** streams, so
it is *structurally* incapable of surfacing through a bidi `accept_bi`.

The demux order in the reader's bidi branch is strictly:

1. `== ACK_BIDI_REQUEST_MAGIC` → ACK-v2 handler
2. **`== APP_BIDI_STREAM_MAGIC` → app channel** (NEW)
3. otherwise → relay handler (`handle_relay_bidi_stream_from_app_reader`)
4. otherwise → drop

**Why app is checked before relay:** the relay handler reads the prefix's first
4 bytes as a big-endian `u32` length and tries to decode a `ConnectUdpRequest`,
and it returns `true` (consuming the stream) whenever a relay server is present.
An app prefix like `ANQAppB1` would decode to length `0x414E5142` (>1024 →
"too large") and be silently eaten. Checking the app magic first guarantees app
streams are never mis-routed to the relay handler, and ACK streams (checked even
earlier) can never reach the app channel.

`Node::open_bi(peer)` writes the `ANQAppB1` magic as the stream's first 8 bytes;
the remote reader consumes those 8 bytes and forwards the positioned
`(SendStream, RecvStream)` to its `app_bi` channel, so the accepting application
sees a clean byte stream starting at offset 0.

## Relay behavior (requirement #3)

`spawn_reader_task` is invoked for **every** peer connection regardless of
traversal method — direct, hole-punched, **and** MASQUE-relayed
(`connect_via_relay`, p2p_endpoint.rs ~5593). It runs on the same
`high_level::Connection` stored under the peer id and reachable via
`get_connection(peer_id)`. Because the demux is connection-agnostic, application
streams work identically over relayed connections with no special handling.

## PQC identity (requirement #4)

Application streams are opened on an already-authenticated `Connection` (the
TLS handshake enforced ML-DSA-65 peer auth; `PeerId = SHA-256(public_key)`). The
reader task is only ever spawned for post-auth connections, so every stream
surfaced via `accept_bi` inherits the connection's ML-DSA peer identity by
construction — no additional per-stream auth is needed or performed.

## Backpressure (requirement #5)

There is **no intermediate byte buffer**. `Node::accept_bi` hands the consumer
the raw `RecvStream`/`SendStream`; reads and writes go directly against QUIC's
native, flow-controlled stream buffers. The `app_bi` handoff channel carries
only **stream handles** (metadata), bounded at capacity 256
(`APP_BIDI_CHANNEL_CAPACITY`). The reader forwards via non-blocking `try_send`;
if the channel is full it resets the surplus inbound stream (the opener observes
a reset and may retry) rather than blocking the reader — which must stay
responsive for ACK-v2, relay, and `recv()` traffic on the same connection. In
practice the queue depth is bounded by the peer's `max_concurrent_bidi_streams`,
so the reset path is a defensive ceiling, not a steady-state occurrence.

## Node stays the single owner (requirement #2)

The consumer never touches `accept_connection()` or the raw `Connection`. The
reader task, the NAT-traversal endpoint, and the connection map all remain owned
by `P2pEndpoint` (held under `Arc` inside `Node`). There is no second accept
loop competing with ant-quic's internal reader.

## Semver

Additive only. Two new `pub async fn`s on `Node` (and the corresponding
`pub async fn`s on `P2pEndpoint`), plus a new `pub(crate)` wire constant. No
existing signature changes. No new mandatory configuration. Minor version bump.
