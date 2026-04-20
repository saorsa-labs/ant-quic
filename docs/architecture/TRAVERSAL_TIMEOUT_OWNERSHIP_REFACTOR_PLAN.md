# Traversal Timeout Ownership Refactor Plan

## Purpose

Create a concrete implementation plan for refactoring NAT traversal timeout ownership so a team can implement the work in slices and reviewers can evaluate each slice against explicit acceptance criteria.

**Primary scope**
- `src/nat_traversal_api.rs`
- `src/p2p_endpoint.rs`

**Secondary follow-up scope**
- `src/candidate_discovery.rs`
- `src/coordinator_control.rs`
- `src/connection_strategy.rs`
- `src/connection/mod.rs` (only where NAT-specific magic constants leak into transport-facing logic)

## Why this refactor exists

The current stack has too many timeout owners for one traversal attempt:

- `NatTraversalEndpoint` owns session deadlines and background wakeups.
- `P2pEndpoint` wraps traversal phases in additional `timeout(...)` calls.
- Candidate discovery has its own time floors and poll cadence.
- Coordinator control adds its own fixed expiry assumptions.
- Some lower-level NAT paths still contain fixed magic durations.

This creates four concrete problems:

1. **Drift**: one traversal attempt can fail for different reasons depending on which timeout fires first.
2. **Poor retry semantics**: retries are still partially timeout/round driven rather than outcome driven.
3. **Weak observability**: logs mention backoff/retry windows that are not fully embodied in state.
4. **Overuse of polling**: time is still used to drive progression where events should be primary.

## Desired end state

After this refactor:

1. `src/nat_traversal_api.rs` is the **single owner** of NAT traversal deadlines.
2. `src/p2p_endpoint.rs` becomes **reactive** to traversal progress and terminal outcomes.
3. Timeouts mean **absence of expected progress** by an exact deadline, not "poll again later".
4. Retry decisions are based on **typed failure reasons**, not generic elapsed time.
5. Cache TTLs and housekeeping intervals are no longer used as traversal protocol deadlines.

## Explicit non-goals

Do **not** do these in the first implementation wave:

- Rework core QUIC PTO/loss/idle logic.
- Change transport-wide keepalive policy.
- Rewrite Happy Eyeballs.
- Rewrite MASQUE relay internals.
- Eliminate all background maintenance tasks repo-wide.

Those can be follow-up work once traversal ownership is clean.

---

# Architectural target

## Rule

> Protocol state advances on events. Timers only bound the absence of expected events.

## Traversal state machine ownership

A traversal session should own:

- current phase
- last progress timestamp
- next exact deadline
- retry schedule (if any)
- classified last failure
- attempt count

## Suggested internal model additions

Add the following internal types to `src/nat_traversal_api.rs`.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraversalDeadlineKind {
    DiscoveryProgress,
    CoordinationResponse,
    SynchronizationProgress,
    PunchProgress,
    ValidationProgress,
    RetryBackoff,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionDeadline {
    kind: TraversalDeadlineKind,
    at: std::time::Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraversalFailureReason {
    DiscoveryExhausted,
    CoordinatorUnavailable,
    CoordinationRejected { reason: crate::coordinator_control::RejectionReason },
    CoordinationExpired,
    SynchronizationExpired,
    PunchWindowMissed,
    ValidationTimedOut,
    ValidationFailed,
    ConnectionFailed,
    ProtocolViolation(String),
    NetworkError(String),
    ShuttingDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryDisposition {
    Never,
    Immediate,
    After(std::time::Instant),
}
```

Extend `NatTraversalSession` with:

```rust
struct NatTraversalSession {
    // existing fields...
    last_progress_at: std::time::Instant,
    next_deadline: Option<SessionDeadline>,
    retry_at: Option<std::time::Instant>,
    last_failure: Option<TraversalFailureReason>,
}
```

## Event surface additions

Do **not** delete the existing `NatTraversalEvent` variants in the first slice. Add new typed variants and migrate call sites incrementally.

Suggested additions:

```rust
pub enum NatTraversalEvent {
    // existing variants...

    TraversalProgress {
        peer_id: PeerId,
        phase: TraversalPhase,
        deadline: Option<std::time::Instant>,
    },

    CoordinationRejected {
        peer_id: PeerId,
        coordinator: SocketAddr,
        reason: crate::coordinator_control::RejectionReason,
    },

    RetryScheduled {
        peer_id: PeerId,
        attempt: u32,
        retry_at: std::time::Instant,
        reason: TraversalFailureReason,
    },

    TraversalStalled {
        peer_id: PeerId,
        phase: TraversalPhase,
        deadline_kind: TraversalDeadlineKind,
    },

    TraversalTerminated {
        peer_id: PeerId,
        reason: TraversalFailureReason,
        fallback_available: bool,
    },
}
```

`TraversalFailed` may remain temporarily as a compatibility event, but the end state should move consumers to `TraversalTerminated`.

---

# File-by-file implementation plan

## 1) `src/nat_traversal_api.rs`

### 1.1 Add exact deadline ownership to sessions

### Add
- `TraversalDeadlineKind`
- `SessionDeadline`
- `TraversalFailureReason`
- `RetryDisposition`
- new `NatTraversalSession` fields:
  - `last_progress_at`
  - `next_deadline`
  - `retry_at`
  - `last_failure`

### Add helper methods

```rust
fn mark_session_progress(
    session: &mut NatTraversalSession,
    now: Instant,
    next_deadline: Option<SessionDeadline>,
)

fn classify_phase_failure(
    &self,
    session: &NatTraversalSession,
    deadline_kind: TraversalDeadlineKind,
) -> TraversalFailureReason

fn retry_disposition(
    &self,
    session: &NatTraversalSession,
    reason: &TraversalFailureReason,
    now: Instant,
) -> RetryDisposition

fn apply_retry_decision(
    &self,
    session: &mut NatTraversalSession,
    reason: TraversalFailureReason,
    now: Instant,
    events: &mut Vec<NatTraversalEvent>,
)

fn recompute_session_deadline(
    &self,
    session: &NatTraversalSession,
    now: Instant,
) -> Option<SessionDeadline>
```

### Change
Refactor existing deadline logic so the following methods become wrappers around the new authoritative model instead of parallel logic:

- `next_session_poll_deadline(...)`
- `non_discovery_phase_timeout_deadline(...)`
- `handle_phase_failure(...)`
- `calculate_backoff(...)`

### Remove / replace

Replace these patterns:
- fixed 10 second coordinator expiries
- log-only backoff with no stored `retry_at`
- broad state-derived wakeups that use cache TTLs as protocol timing

with:
- exact per-session `SessionDeadline`
- stored `retry_at`
- protocol deadline computation derived from phase + RTT/config + coordinator health

### 1.2 Coordinator expiry must become adaptive

### Change
Current coordinator envelope expiry is a fixed local assumption.

Add:

```rust
fn coordinator_request_expiry(
    &self,
    peer_id: PeerId,
    coordinator: SocketAddr,
    now: Instant,
) -> Duration
```

Use inputs from:
- `config.coordination_timeout`
- observed session RTT
- coordinator health / recent failures

### Rules
- Never exceed the session's coordination budget.
- Never be shorter than one plausible coordination RTT window.
- Store a monotonic local deadline even if wire format still uses unix ms expiry.

### 1.3 Session updater becomes exact-deadline driven

### Change
The current background updater already improved from fixed intervals to notify + deadline wakeups. Keep that direction and finish it.

Refactor the updater to:
- wake on `traversal_event_notify`
- wake on discovery notify
- wake on the exact earliest `SessionDeadline` / `retry_at`
- stop waking for broad cache TTL maintenance unrelated to an active traversal protocol step

### Add

```rust
fn next_protocol_deadline(&self, peer_id: PeerId, now: Instant) -> Option<Instant>

fn handle_session_deadline_expiry(
    &self,
    peer_id: PeerId,
    now: Instant,
    events: &mut Vec<NatTraversalEvent>,
)
```

### 1.4 Separate traversal deadlines from cache freshness

### Rule
The following must **not** directly decide traversal failure:
- `interface_cache_ttl`
- `server_reflexive_cache_ttl`
- other discovery cache TTLs

### Change
Use those values only for:
- freshness scoring
- cache invalidation
- lazy revalidation hints

A live traversal session may consult cached data, but its **protocol** deadline comes only from:
- session phase
- RTT/config budget
- explicit retry schedule

### 1.5 Typed failure outcomes

### Add / migrate
Make failure paths produce `TraversalFailureReason` values instead of generic timeout strings wherever possible.

Minimum mapping for first wave:
- discovery no candidates -> `DiscoveryExhausted`
- fixed/no coordinator reply -> `CoordinatorUnavailable` or `CoordinationExpired`
- explicit rejection -> `CoordinationRejected { reason }`
- punch window elapsed -> `PunchWindowMissed`
- validation deadline elapsed -> `ValidationTimedOut`
- invalid frame/protocol mismatch -> `ProtocolViolation(...)`
- shutdown -> `ShuttingDown`

---

## 2) `src/p2p_endpoint.rs`

## Objective
Stop owning NAT traversal phase timing. Consume traversal outcomes instead.

### 2.1 Narrow `P2pEndpoint` timeout ownership

### Keep
`P2pEndpoint` may still own:
- direct-connect stage budgets
- overall user-facing connect cancellation
- relay stage budgets

### Move inward
`P2pEndpoint` must stop owning:
- hole-punch stage timeout
- traversal progress timeout
- round-based retry timing for NAT traversal

### 2.2 Refactor `try_hole_punch(...)`

### Today
`try_hole_punch(...)`:
- initiates traversal
- polls inner events
- checks for live connection
- calls `wait_for_traversal_progress(...)`
- returns timeout itself

### Target
Split into two responsibilities:

```rust
async fn start_hole_punch_session(
    &self,
    target: SocketAddr,
    coordinator: SocketAddr,
    peer_id: PeerId,
) -> Result<(), EndpointError>

async fn await_hole_punch_outcome(
    &self,
    peer_id: PeerId,
    overall_deadline: tokio::time::Instant,
) -> Result<PeerConnection, EndpointError>
```

`await_hole_punch_outcome(...)` should only:
- listen for typed NAT traversal events
- finalize a connection when `ConnectionEstablished` / `TraversalSucceeded` implies success
- translate `TraversalTerminated` to endpoint-level failure
- respect only the single outer user connect deadline, not a separate per-round timeout

### Delete / replace
Delete once migration is complete:
- `wait_for_traversal_progress(...)`
- generic timeout-as-progress logic for hole punch

### 2.3 Remove redundant outer `timeout(...)` around hole punch

### Today
Hole punching is wrapped in:

```rust
timeout(holepunch_timeout, self.try_hole_punch(...)).await
```

### Replace with
- initiate traversal session
- await typed outcome until the **single caller-owned overall operation deadline**

This removes the duplicate ownership conflict between:
- `strategy.holepunch_timeout()`
- `NatTraversalEndpoint` internal deadlines

### 2.4 Retry on classified outcomes, not generic timeout

### Change
In the `ConnectionStage::HolePunching` branch:
- retry only on a small allowlist of classified transient failures
- move immediately to relay on explicit hard failures

Suggested mapping:

**Retryable**
- `CoordinatorUnavailable`
- `CoordinationExpired`
- `PunchWindowMissed`
- `ValidationTimedOut`
- transient `NetworkError`

**Non-retryable**
- `CoordinationRejected { RateLimited | Unauthenticated | Expired }`
- `ProtocolViolation(...)`
- repeated `DiscoveryExhausted`

### Add helper

```rust
fn should_retry_hole_punch_reason(reason: &TraversalFailureReason) -> bool
```

### 2.5 Keep connection finalization logic, but centralize outcome translation

Do **not** rewrite the connection finalization path in the first wave.

Keep:
- `finalize_direct_connection(...)`
- `spawn_reader_task(...)`
- registration / reachability observation

Add one narrow translation helper:

```rust
fn endpoint_error_from_traversal_failure(reason: TraversalFailureReason) -> EndpointError
```

This gives reviewers one place to check mapping quality.

---

# Team implementation slices

## Slice 1 — Internal deadline model in `nat_traversal_api.rs`

### Deliverables
- new deadline/failure/retry types
- `NatTraversalSession` extended with deadline state
- backoff stored in session state
- fixed coordinator expiry replaced by helper

### Must not do yet
- do not rewrite `P2pEndpoint`
- do not remove legacy compatibility events

### Review focus
- is there exactly one authoritative protocol deadline per active session?
- are retry windows stored, not merely logged?
- are cache TTLs still leaking into protocol failure paths?

## Slice 2 — Typed traversal outcomes

### Deliverables
- new `NatTraversalEvent` variants
- phase failure classification wired through emit paths
- updater wakes only for exact deadlines / notifies

### Review focus
- are outcomes typed enough to support retry policy?
- do terminal events distinguish hard vs retryable failure?
- is background wake behavior narrower than before?

## Slice 3 — `P2pEndpoint` hole-punch de-duplication of timeout ownership

### Deliverables
- `start_hole_punch_session(...)`
- `await_hole_punch_outcome(...)`
- removal of redundant outer hole-punch timeout wrapper
- retry policy driven by `TraversalFailureReason`

### Review focus
- did outer hole-punch timeout ownership actually disappear?
- does endpoint still respect the single global connect deadline?
- do retries match the approved allowlist only?

## Slice 4 — Discovery timing cleanup

### Deliverables
- discovery completion on evidence where possible
- reduced reliance on time floors
- no cache TTL used as traversal failure deadline

### Review focus
- is discovery still safe under slow peers?
- does bounded grace remain only as fallback?
- did the team avoid changing correctness-critical cache policy accidentally?

---

# Review checklist for the team

## Architectural review
- [ ] `NatTraversalEndpoint` is the only owner of NAT traversal phase deadlines.
- [ ] `P2pEndpoint` no longer wraps hole punching in its own per-phase timeout.
- [ ] Retry/backoff exists in state, not only in logs.
- [ ] Protocol deadlines are not derived from cache TTLs.

## Correctness review
- [ ] A traversal session always has zero or one active protocol deadline.
- [ ] Terminal failure reasons are typed and stable.
- [ ] Retryable and non-retryable failures are explicitly separated.
- [ ] Shutdown produces explicit termination, not generic timeout.

## Transport boundary review
- [ ] Core QUIC PTO/loss logic was not changed except narrowly justified cleanup.
- [ ] NAT-specific timeout constants were removed or made derived/configured.
- [ ] Blocking socket timeout paths were reduced or isolated for follow-up removal.

## Observability review
- [ ] Logs mention the exact deadline kind when a traversal stalls.
- [ ] Logs include typed rejection reason for coordinator failures.
- [ ] Metrics/events distinguish discovery exhaustion vs coordination failure vs validation timeout.

## Test review
- [ ] Existing tests still pass.
- [ ] New tests cover retry classification.
- [ ] New tests cover exact deadline ownership.
- [ ] No new flake introduced by time-based tests; prefer deterministic paused time where possible.

---

# Minimum test plan

## Unit tests
Add focused tests in or near `src/nat_traversal_api.rs` for:
- `recompute_session_deadline(...)`
- `retry_disposition(...)`
- `classify_phase_failure(...)`
- coordinator expiry helper
- non-retryable rejection mapping

## Integration tests
Extend or add tests around `P2pEndpoint` to verify:
- hole punch no longer has duplicate timeout ownership
- endpoint retries on `PunchWindowMissed` but not on `CoordinationRejected(Unauthenticated)`
- overall connect deadline still aborts the public operation cleanly

## Negative tests
- shutdown mid-traversal emits explicit termination
- discovery cache freshness changes do not terminate live traversal session
- repeated coordinator rejection goes directly to relay/failure path without useless rounds

---

# Open questions for implementation review

These do **not** block Slice 1, but reviewers should watch them:

1. Should `TraversalFailureReason::NetworkError(String)` become a structured enum immediately, or can that be follow-up?
2. Should the direct connection stage also collapse nested timeouts now, or after NAT traversal ownership is cleaned?
3. Do we want to keep `TraversalFailed` event as compatibility forever, or deprecate it after one implementation wave?
4. Should `coordinator_control.rs` also get a monotonic expiry helper in the same series, or be a follow-up PR?

---

# Recommended PR sequence

1. **PR 1:** internal deadline/retry model in `nat_traversal_api.rs`
2. **PR 2:** typed traversal outcome events
3. **PR 3:** `p2p_endpoint.rs` removes redundant hole-punch timeout ownership
4. **PR 4:** discovery timing cleanup and TTL/protocol separation
5. **PR 5:** coordinator control monotonic expiry follow-up

This sequence keeps reviewable PRs small and makes it easy to reject or revise the policy layer without destabilizing QUIC core.

---

# Handoff note

This spec is intentionally detailed enough that one team can implement in slices while another team reviews against explicit architectural constraints. It is meant to guide implementation review, not replace code review.
