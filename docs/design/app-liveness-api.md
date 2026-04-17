# ant-quic B — Application-Layer Liveness API

**Status**: Design — pending review, reduced scope per review feedback
**Target release**: ant-quic 0.28.0 (after 0.27.0 D ships and is
validated on VPS; may be deferred further if x0x's C path obviates
the immediate need)
**Motivation**: `P2pEndpoint::send` returning `Ok` currently means
only "QUIC stream FIN was ACKed by peer's transport". In a churning
mesh, transport-level ACK can succeed while the peer's application
reader is absent (post-cleanup, pre-migration, crashed).
D (`connection-lifecycle-sync.md`) narrows the gap at the transport
level; B closes the remaining gap for consumers that need the
stronger guarantee, and exposes health/lifecycle primitives useful
to any ant-quic consumer.

## Goals

- Expose a minimal, narrowly-defined application-layer liveness
  surface that consumers can opt into.
- Three pieces:
  1. `connection_health(peer_id) -> ConnectionHealth` — blocking-free
     snapshot.
  2. `subscribe_peer_events(peer_id) -> Receiver<PeerLifecycleEvent>`
     — lifecycle events without polling.
  3. `send_with_receive_ack(peer_id, data, timeout)` — one optional
     primitive that waits for the remote endpoint's *reader-pipeline*
     to have accepted the data. **Not** a message-delivery or
     message-processed guarantee.

## Non-goals

- **No broad reliable-messaging abstraction.** Consumers that need
  application-semantic delivery build it on top (x0x's C path is the
  canonical example).
- **No hidden payload interception via in-band magic bytes.** The
  ACK path uses a dedicated transport-owned control stream, not a
  reserved leading byte in the payload stream. (Earlier draft
  proposed `0xFE` — rejected during review.)
- **No modelling of end-user delivery semantics** (durable storage,
  user read receipts, etc.). These are consumer concerns.
- **No change to the existing `send` / `recv` / `accept` surface.**
  B is additive.
- **No peer-state synchronisation across the mesh.** Per-peer events
  and health are strictly for the local endpoint's view of one peer.

## Wire contract

### Control stream

Each authenticated connection opens one **dedicated bidirectional
control stream** immediately after handshake. This is distinct from
the payload streams that currently flow through `send` / `recv`.

- Stream ID: the first bi-stream opened by the endpoint after
  authentication completes. Both sides know this by convention — no
  negotiation needed.
- Purpose: transport-owned control messages including receive-ACKs
  (B), future coordinator-control rerouting (already exists via a
  different mechanism), and lifecycle probes.
- Framing: length-prefixed postcard-serialised `ControlFrame`s.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ControlFrame {
    /// Sent by the receiver of a payload stream to acknowledge
    /// that the stream was accepted into the receive pipeline.
    /// See ACK semantics below.
    ReceiveAck {
        /// Opaque tag that the sender chose for the corresponding
        /// `send_with_receive_ack` call. Echoed back unchanged.
        request_tag: [u8; 16],
        /// Outcome of the handoff to the receive pipeline.
        outcome: ReceiveAckOutcome,
    },
    /// Reserved for future use. Receivers MUST ignore unknown
    /// variants without closing the connection.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum ReceiveAckOutcome {
    /// The payload was delivered into the receive pipeline
    /// (`data_tx` / equivalent). Caller's `recv()` will surface it
    /// on its own schedule. Does NOT imply the consumer has read it.
    Accepted,
    /// The receive pipeline refused the payload — typically because
    /// it exceeded a size limit or the channel was full and dropped.
    Rejected { reason: ReceiveRejectReason },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum ReceiveRejectReason {
    /// `data.len()` exceeded `max_message_size`.
    Oversized,
    /// The receive channel's consumer has gone away (this indicates
    /// a bug on the consumer side — we report it rather than
    /// silently drop).
    ConsumerGone,
}
```

The control stream carries only `ControlFrame`s — never application
payload. Payload continues to flow over uni-directional streams as
today.

### Tag scope

`request_tag` is opaque to ant-quic. Callers generate a random 128-bit
tag per `send_with_receive_ack` call. ant-quic tracks an in-flight
set per-connection; duplicate tags on the same connection would
cause mismatched ACK pairing and are UB (caller's responsibility to
avoid).

## API surface

### Health snapshot

```rust
#[derive(Debug, Clone)]
pub struct ConnectionHealth {
    /// Whether a Live connection exists for the peer (per D).
    pub connected: bool,

    /// Current connection's local generation, if connected.
    /// Strictly monotonic per peer_id on this endpoint.
    pub generation: Option<u64>,

    /// Whether the receiver task for the current connection is
    /// running and draining streams. Only meaningful when
    /// `connected == true`.
    pub reader_task_active: Option<bool>,

    /// Instant of the last received packet on this connection,
    /// in local monotonic time. None when disconnected.
    pub last_received_at: Option<Instant>,

    /// Instant of the last sent packet. None when disconnected.
    pub last_sent_at: Option<Instant>,

    /// Duration since the last packet in either direction. None
    /// when disconnected.
    pub idle_for: Option<Duration>,

    /// If the connection is closing or closed, the reason.
    /// None while Live.
    pub close_reason: Option<CloseReason>,
}

impl P2pEndpoint {
    pub fn connection_health(&self, peer_id: &PeerId) -> ConnectionHealth;
}
```

When `connected == false`, `generation`, `reader_task_active`,
`last_received_at`, `last_sent_at`, and `idle_for` are all `None`.
`close_reason` may be `Some` if a recent connection closed.

### Lifecycle events

```rust
#[derive(Debug, Clone)]
pub enum PeerLifecycleEvent {
    /// A new Live connection was established for this peer.
    Established { generation: u64 },

    /// A new connection superseded the old one. Per D, both endpoints
    /// converge on the same winner; this event fires locally.
    Replaced { old_generation: u64, new_generation: u64 },

    /// Connection entered Closing state. Close reason is included.
    Closing { generation: u64, reason: CloseReason },

    /// Connection is fully closed; no Live connection exists for
    /// this peer currently.
    Closed { generation: u64, reason: CloseReason },

    /// Reader task for the current connection exited. Subsequent
    /// inbound streams will not be drained until a new connection
    /// establishes. On Live connections this is typically followed
    /// by Closing.
    ReaderExited { generation: u64 },
}

impl P2pEndpoint {
    pub fn subscribe_peer_events(
        &self,
        peer_id: &PeerId,
    ) -> tokio::sync::broadcast::Receiver<PeerLifecycleEvent>;

    /// Convenience: subscribe to events for all peers. The stream
    /// pairs each event with the peer_id it concerns.
    pub fn subscribe_all_peer_events(
        &self,
    ) -> tokio::sync::broadcast::Receiver<(PeerId, PeerLifecycleEvent)>;
}
```

Events are **not persistent** — a subscriber that misses events (slow
consumer) will see `broadcast::error::RecvError::Lagged`. Caller
handles lag by falling back to `connection_health()` for a fresh
snapshot.

### send_with_receive_ack

```rust
impl P2pEndpoint {
    /// Send data and wait for the remote endpoint's reader pipeline
    /// to acknowledge that the payload was accepted into it.
    ///
    /// Semantics:
    /// - Ok(()) means the remote ant-quic reader task has received
    ///   the full stream, ran through any control-message fast-path
    ///   (non-matching), and successfully enqueued the payload for
    ///   the consumer's `recv()` to surface.
    /// - It does NOT mean the consumer has read the payload, let
    ///   alone acted on it.
    /// - It does NOT mean the payload has been persisted.
    /// - Err(ConnectionError::AckTimeout) means no ReceiveAck arrived
    ///   within the caller-supplied timeout. The payload MAY have
    ///   been received; the caller cannot distinguish. Use request
    ///   tags + application-level idempotency if retrying.
    ///
    /// This primitive exists for consumers who need "reader accepted
    /// my message" without layering their own ACK protocol on top
    /// of `send`. It is NOT a substitute for an application-level
    /// delivery layer when the consumer's correctness depends on
    /// the recipient processing the payload.
    pub async fn send_with_receive_ack(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        timeout: Duration,
    ) -> Result<(), EndpointError>;
}
```

## Implementation sketch

### Control stream ownership

- `P2pEndpoint::new` spawns an always-running **control-stream writer**
  and **control-stream reader** per authenticated connection.
- Writer: serialises outbound `ControlFrame`s into the bi-stream,
  length-prefixed. Uses a bounded mpsc queue per connection.
- Reader: loops on `bi_stream.read_frame()` and dispatches by variant.
  `ReceiveAck` variants are matched against an in-flight
  `DashMap<[u8; 16], oneshot::Sender<ReceiveAckOutcome>>` maintained
  by the endpoint.

### Reader-task integration for ACK emission

`spawn_reader_task` (per-peer, per-connection) already owns the
`accept_uni → read_to_end → dispatch` loop. After successfully
pushing a payload into `data_tx`, if the sender opted in by prefixing
the stream with a `request_tag`, the reader sends back a `ReceiveAck`
on the control stream.

**Tag encoding on the payload stream**: prepend the payload with an
optional 17-byte prefix:

```
[0x01][tag: 16 bytes][payload bytes]   ← if caller opted into receive-ACK
[0x00][payload bytes]                  ← no ACK requested (default)
```

This single opt-in byte is a **payload-frame protocol version**, not
a magic byte. It is part of an explicit framing contract that both
sides accept. Receivers check the first byte unconditionally:

- `0x00` → strip byte, data = remainder, no ACK emitted (matches
  today's `send` / `recv` semantics exactly).
- `0x01` → strip 17 bytes, data = remainder, extract tag, emit
  `ReceiveAck { request_tag: tag, outcome }` on control stream
  after handoff to `data_tx`.
- anything else → log warn, drop stream. (Forward-compat: future
  versions of the framing reserve `0x02..`.)

**Why this isn't "in-band magic"**: every payload carries exactly
one framing byte from a defined versioned set. There is no "if the
first byte happens to be X, interpret specially" — receivers
always decode the framing. Consumers opting into ACKs just set the
framing byte to `0x01`; consumers that don't care use `0x00` and get
identical behaviour to the existing `send`.

**Backward compatibility**: older consumers that called the existing
`send` would not prepend any byte. To keep them working without
modification, the `send` implementation will continue to prepend
`0x00` transparently. Receivers on older ant-quic versions that
don't understand the framing byte would break — so this is behind a
connection-time capability advert (part of the handshake transport
parameters). Without the capability, `send` uses the raw pre-B
format (no prefix, no ACK).

### Capability negotiation

QUIC transport parameters carry a boolean `ant_quic_frame_v1_supported`
flag. Both sides advertise on handshake. If both sides set it, the
framing byte is active; otherwise, `send_with_receive_ack` returns
`EndpointError::NotSupported` immediately.

This is strictly additive — a new ant-quic talking to an old ant-quic
falls back to the pre-B framing automatically.

### In-flight ACK tracking

```rust
struct AckState {
    /// Outstanding ACK waiters keyed by request_tag.
    waiters: DashMap<[u8; 16], oneshot::Sender<ReceiveAckOutcome>>,
    /// Guard against tag reuse within a connection.
    seen_tags: bounded_LruCache<[u8; 16], ()>,
}
```

## Acceptance criteria

1. **Health snapshot semantics** — for every
   (connected, closing, closed, never-seen) state, `connection_health`
   returns the documented-Option patterns. Integration test uses
   direct state injection.

2. **Lifecycle events match D transitions** — tests/b_events_parity.rs
   drives a churn scenario and verifies `PeerLifecycleEvent` stream
   matches the state transitions from D exactly.

3. **ACK happy path** — two P2pEndpoint instances on localhost;
   `send_with_receive_ack` returns Ok within one RTT.

4. **ACK timeout path** — configure the receiver to never drain
   streams (spawn a P2pEndpoint without calling `recv`); sender's
   `send_with_receive_ack` returns `AckTimeout` within the
   user-supplied timeout. Verify the tag is cleaned from in-flight
   state.

5. **Capability-gated fallback** — pin one endpoint to a pre-B
   transport-params version; sender's `send_with_receive_ack`
   returns `NotSupported` immediately, without sending anything.

## Rollout

Strictly deferred until D has been validated on VPS via x0x's
release. If by that point x0x's C path has subsumed the need for
`send_with_receive_ack` (likely), B ships with only
`connection_health` + `subscribe_peer_events` and the ACK primitive
is deferred until a consumer actually needs it.

Sequencing is:

1. ant-quic 0.27.0 = D only.
2. x0x 0.18.0 = C (gossip DM).
3. VPS matrix verification on 0.27.0 + 0.18.0.
4. Decision point: does any consumer still need `send_with_receive_ack`?
   - Yes → ship ant-quic 0.28.0 with B in full.
   - No → ship 0.28.0 with only health + events; defer ACK primitive.

## Open questions for review

1. **Transport-params bit vs. version field** — a single "v1 frame
   supported" boolean is the simplest. If we anticipate more framing
   versions, a u16 version number is more flexible. Current design
   picks the boolean for simplicity. Decision revisitable at 0.28.0.

2. **Control-stream-per-connection vs. singleton** — per-connection
   is simpler and localises state (one dead connection doesn't take
   out others). Per-endpoint singleton would be more efficient for
   many small peers. v1 picks per-connection; revisit if we see
   scale issues.

3. **Broadcast channel lag handling** — subscribers that lag are
   told they lagged but not which events they missed. Callers must
   re-snapshot with `connection_health`. Acceptable trade-off for
   v1; a ring-buffered replay would be richer but adds complexity.
