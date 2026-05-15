# ant-quic D — Connection Lifecycle Sync

**Status**: Design — pending review
**Target release**: ant-quic 0.27.0
**Motivation**: saorsa-labs/ant-quic#166 VPS follow-up — residual delivery
failures on the 6-node bootstrap mesh when connections churn.
**Scope**: transport-layer correctness. No new application-facing API
(those belong to the separately-scoped B work).

## Problem

On a churning mesh (hole-punch replacing connections, idle timeouts,
simultaneous reconnects), sender and receiver can disagree about which
`Connection` is the live one for a given `peer_id`:

1. Receiver's reader task exits (idle timeout) → `cleanup_connection`
   fires locally → quinn's idle timeout closes the connection silently
   on the wire.
2. Sender's `inner.get_connection(peer_id)` still returns the cached
   `Connection`. The sender's quinn has no reason to know the peer
   cleaned up until its own idle timer fires.
3. Sender calls `open_uni() + write_all() + finish() + stopped()`. The
   stream FIN is ACKed by the receiver's quinn transport layer (auto-ACK
   on packet delivery — does not require the application reader).
4. `send_stream.stopped()` resolves `Ok`. `P2pEndpoint::send` returns
   `Ok(())`.
5. Data sits in the receiver's quinn receive buffer, undrained by any
   application-layer reader, until the connection fully closes.
6. From the consumer's perspective, `send` succeeded but the peer
   never processed the bytes.

This is observable on the x0x VPS bootstrap mesh (6 nodes across
DO/Hetzner/Vultr) after any churn event. It is not observable in the
2-peer localhost reproducer because local connections don't idle out
during a short test window.

## Goal

Establish a single canonical live connection per `peer_id` at all
times, and make that property observable to the sender's write path
so writes into a superseded connection fail fast rather than silently
succeed.

## Non-goals

- Peer-to-peer synchronisation of the generation counter. Generations
  stay local to each endpoint.
- Coordinator-mediated connection reconciliation.
- Any change to `P2pEndpoint` public API surface — this is an internal
  refactor. (Application-facing liveness primitives are the separate
  B work at `docs/design/app-liveness-api.md`.)
- Changes to quinn's own connection lifecycle. Everything here sits on
  top of quinn.

## Design

### Connection state machine

Every `Connection` tracked by the endpoint carries explicit state:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    /// Actively serving reads and writes. `get_connection(peer_id)`
    /// returns this one (at most one per peer_id).
    Live,
    /// Superseded by a newer connection to the same peer_id. Reader
    /// task is still draining any in-flight stream but will not accept
    /// new ones. Write path MUST NOT pick this connection. Actively
    /// closing in the background.
    Superseded { replaced_by_generation: u64 },
    /// `close()` has been initiated (locally or by peer); waiting for
    /// quinn to finalise.
    Closing { reason: CloseReason },
    /// Fully closed; entry retained briefly for diagnostics then evicted.
    Closed { reason: CloseReason, closed_at: Instant },
}
```

Transitions (local, deterministic):

```
     accept_connection / dial_succeeded
              │
              ▼
          ┌─Live─┐ ◄────────────────────────────┐
          │      │                              │
          │      │ new connection to same peer  │  (winner
          │      │ wins deterministic race      │   only)
          │      ▼                              │
          │  ┌─Superseded─┐                     │
          │  │            │                     │
          │  │ active close completes           │
          │  │ (local initiated)                │
          │  ▼                                  │
          └─Closing──────▶ Closed               │
              ▲                                 │
              │                                 │
              │  peer-initiated close / idle    │
              │  timeout / transport error      │
              └─────────────────────────────────┘
```

### Deterministic replacement rule

When a new authenticated connection `C_new` arrives for a `peer_id`
that already has a `Live` connection `C_old`, both endpoints
independently resolve the race as follows:

1. Compare `(C_new.generation, C_new.established_at_unix_ms, tiebreaker_hash)`
   with `(C_old.generation, C_old.established_at_unix_ms, tiebreaker_hash)`.
2. **Winner** = higher generation. Ties broken by newer
   `established_at_unix_ms`. Further ties broken by
   `blake3(local_peer_id || remote_peer_id || connection_id)` —
   this hash is computed identically on both endpoints, so they agree
   on the winner without exchanging any lifecycle messages.
3. Winner becomes `Live`. Loser transitions to
   `Superseded { replaced_by_generation: winner_generation }`, then to
   `Closing { reason: CloseReason::Superseded }`, then `Closed`.
4. The active close uses an ant-quic-reserved QUIC application error
   code — see *Close codes* below — so the peer's quinn surfaces a
   distinguishable error when it processes the close frame.

Both endpoints perform the same comparison on the same inputs, so they
arrive at the same winner without any inter-endpoint generation sync.
The peer's `Superseded` state does not need to match the winner's
`generation` value — only the outcome (which connection is live)
matters.

### `get_connection(peer_id)` semantics

- Returns `Some(conn)` **only** when there is exactly one `Live`
  connection for `peer_id`. Otherwise `None`.
- `Superseded`, `Closing`, `Closed` entries are never returned.
- When `get_connection` returns `Some`, the caller may still hit a
  race where the connection transitions between the lookup and the
  subsequent `open_uni()`. Callers are expected to handle `open_uni`
  errors — they were already doing this for non-lifecycle errors.

### Sender-side fast-fail

Today's flow:

```rust
let connection = self.inner.get_connection(peer_id)?...;
let mut send_stream = connection.open_uni().await?;   // can succeed on a superseded conn
send_stream.write_all(data).await?;
send_stream.finish()?;
send_stream.stopped().await?;                         // auto-ACK'd by transport
```

Post-fix: `get_connection` returns the `Live` connection (per above).
In addition, before each send we check `Connection::close_reason()`.
If the connection entered `Closing` between lookup and send, we get an
immediate error instead of proceeding with a write that will be
silently eaten.

```rust
let connection = self.inner.get_connection(peer_id)?...;
if let Some(reason) = connection.close_reason() {
    return Err(EndpointError::ConnectionClosed { reason });
}
// open_uni + write + finish + stopped unchanged
```

### Close codes

Define a small reserved range in ant-quic's QUIC application error code
namespace (0x4E-5B-00–0x4E-5B-FF — ASCII "N[":

| Code | Name | Meaning |
|---|---|---|
| `0x4E5B00` | `Superseded` | This connection was replaced by a newer one to the same peer. |
| `0x4E5B01` | `ReaderExit` | The receiver's reader task exited (idle / cooperative cancel) and is not coming back. |
| `0x4E5B02` | `PeerShutdown` | The remote endpoint is shutting down. |
| `0x4E5B03` | `Banned` | Receiver-side trust policy rejected this peer. |
| `0x4E5B04` | `LifecycleCleanup` | Generic cleanup — should be rare; prefer a specific code. |

These codes are carried in the QUIC `CONNECTION_CLOSE` frame's
application error code. Sender's close-reason detection maps these
back to `CloseReason` enum variants so callers can distinguish "peer
gone" from "peer banned me".

### Observability

All state transitions emit structured tracing at `info` level with
consistent fields:

```
target: ant_quic::p2p_endpoint::lifecycle
fields:
  peer_id = <hex prefix 8>
  generation = <u64>
  from_state, to_state = Live|Superseded|Closing|Closed
  reason = <CloseReason>
  connection_id = <quinn connection id>
```

Metrics counters (Prometheus-style names, off by default behind a
feature flag):

- `ant_quic_connection_live_total{peer_id}` — current gauge
- `ant_quic_connection_transitions_total{from, to, reason}` — counter
- `ant_quic_connection_supersede_total{winner}` — counter
- `ant_quic_connection_close_code_total{code}` — counter

Internal tracing always-on; metrics behind `features = ["metrics"]`.

## Acceptance criteria

These are the tests we must pass before tagging 0.27.0:

1. **Uniqueness** — `tests/lifecycle_canonical_live.rs`: under 100
   rapid reconnect cycles from N=8 peers against a single receiver,
   `get_connection(peer_id)` returns exactly one connection at every
   observation point, and its `generation` is monotonically
   non-decreasing.

2. **Active close on cleanup** — `tests/lifecycle_active_close.rs`:
   when the receiver's reader task exits (simulated idle timeout),
   the sender observes a `close_reason` containing `ReaderExit`
   within 2× RTT, not the default idle-close timeout (~30s).

3. **Sender fast-fail on superseded** — `tests/lifecycle_sender_stale.rs`:
   with generation-race set up so A's `C_old` loses to `C_new`,
   a write on `C_old` returns `EndpointError::ConnectionClosed
   { reason: Superseded }` rather than a silent `Ok`.

4. **Deterministic replacement under race** —
   `tests/lifecycle_simultaneous_replace.rs`: two peers simultaneously
   open connections to each other; after the race resolves, both
   endpoints' `get_connection(peer_id)` returns connections that
   share the same `connection_id` on both sides (i.e. they agree on
   which connection won).

5. **Observability** — all five transitions emit the tracing event
   with the documented fields; verified by a tracing-subscriber test
   harness.

## Test plan

- **Unit**: state-machine transitions, winner-hash determinism, close
  code mapping — all in `src/p2p_endpoint.rs` module tests.
- **Integration (single-process)**: the four regression tests above
  using two `P2pEndpoint` instances on localhost.
- **Integration (two-process)**: `tests/lifecycle_interprocess.rs`
  spawns two `ant-quic` test binaries in separate processes with
  artificial idle-timeout reduction, exercises the churn pattern.
- **VPS**: runs as part of x0x's `e2e_vps.sh` once x0x picks up the
  release. No VPS tests in ant-quic itself.

## Rollout

1. Implement on branch `claude/d-connection-lifecycle-sync`.
2. PR to master, merge after review + all acceptance-criteria tests
   pass.
3. Tag `v0.27.0`. Release-notes call out the close codes and the
   `get_connection` tightening (superseded connections no longer
   returned — minor behaviour change for consumers that relied on
   the lax semantics).
4. x0x and saorsa-gossip pick up via caret-compatible version bump in
   their own release cycles. No action required in those repos — the
   change is internally additive.

## Open questions

- **Close-reason observability in quinn**: we rely on quinn's
  `Connection::close_reason()` returning the application error code
  promptly after the peer sends `CONNECTION_CLOSE`. Need to verify
  the quinn version currently vendored exposes this without additional
  polling. If not, add a small polling task.
- **Default `idle_timeout`**: current default is quinn's default
  (30s). Consider reducing to 15s so the `Superseded` path is the
  normal cleanup route rather than idle-close. Deferred decision —
  default stays as-is for 0.27.0 unless testing reveals a reason to
  change it.
