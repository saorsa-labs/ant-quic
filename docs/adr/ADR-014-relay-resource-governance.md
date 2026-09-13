# ADR-014: Enforced Relay Resource Governance

## Status

Accepted (2026-08-26)

## Amends / Supersedes

- [ADR-002](ADR-002-epsilon-greedy-bootstrap-cache.md) § Mandatory Relay/Coordinator Participation
  (budget promise)
- [ADR-006](ADR-006-masque-relay-fallback.md) § Every Peer is a Relay ("no opt-out... resource
  budgets prevent abuse")

The mandatory-participation decision stands. This ADR makes its precondition explicit and testable:
**open relaying without enforced budgets must not ship**.

## Context

ADR-002/006 justify mandatory relay participation through "predictable resource budgets". An audit
on 2026-08-26 found the promise only partially implemented:

| Mechanism | State |
|-----------|-------|
| Per-session bandwidth limit | ✅ Enforced - `BandwidthTracker` in `src/masque/relay_session.rs` (default 1 MiB/s) rejects over-budget bytes with `BandwidthExceeded` |
| Global bandwidth limit | ❌ **Declared, never referenced** - `MasqueServerConfig::global_bandwidth_limit` (`src/masque/relay_server.rs:61-73`) has no enforcement site |
| Per-peer fairness quota (ADR-002 table) | ❌ Not implemented at the MASQUE layer; legacy `TokenBucket` exists in `src/relay/rate_limiter.rs` but is unwired from the MASQUE path |
| Concurrent relay count cap | ⚠️ Present as config surface only; no admission control counts active relay sessions per source peer |

This is the sharpest edge in the design: every node accepting arbitrary peers' traffic under a
"mandatory, no opt-out" mandate, while aggregate load-shaping exists mostly on paper. Comparable
systems treat this carefully by construction - libp2p's Circuit Relay v2 gates forwarding behind
explicit resource-controlled reservations, and iroh relays are operated services. ant-quic's bet is
different (symmetry), so its budgets must be real.

Budgets keyed to IP address are also wrong for our threat model: CGNAT and mobile networks share
thousands of users per address, while attackers rotate addresses freely. Identity-keyed accounting
matches how we authenticate everything else ([ADR-003](ADR-003-pure-post-quantum-cryptography.md)).

## Decision

1. **Global budget enforcement (ship-blocker).**
   `global_bandwidth_limit` becomes an admission gate enforced in the relay accept path: bytes are
   counted through the same tracker family as sessions; when exhausted, new relay sessions receive a
   structured refuse capsule signalling backoff, and existing sessions continue until their own
   session budget or grace expires. Config value of 0 keeps semantics "unlimited" *only* in builds
   explicitly compiled with a development feature - shipped defaults always enforce a finite limit.

2. **Identity-keyed fair share.**
   Per-source-peer quotas key on the authenticated ML-DSA-65 endpoint identity, not network address.
   Defaults land at, or below, ADR-002's budget table; no requirement that HostKey ever be consulted
   on the wire (see [ADR-007](ADR-007-local-only-hostkey.md)).

3. **Concurrency admission control.**
   Active relay sessions counted per source peer and globally; new sessions refused above caps with
   the same structured-refuse mechanism.

4. **Legacy limiter consolidation.**
   The unwired `src/relay/rate_limiter.rs` token bucket either gets adopted as the global-limiter
   implementation or deleted during the legacy deprecation already planned in [ADR-006]; a second,
   divergent limiting vocabulary may not survive alongside it.

5. **Honesty clause.**
   If any mechanism above ships incomplete, user-facing docs must describe relay participation as
   best-effort rather than claiming bounded guarantees. The claimed invariant and the enforced
   invariant must be the same invariant.

## Consequences

### Positive

- Mandatory symmetric relaying becomes defensible to run: abuse is structurally capped, not policed.
- Budget telemetry integrates with [ADR-013](ADR-013-measured-connectivity-metrics.md) counters
  (refusals by reason become observable).
- Removes an easy DoS story against participating nodes before it is discovered in production.

### Negative

- Relay accept-path gains hot-path accounting cost (tracked-bytes increments; negligible vs
  forwarding itself).
- Behaviour changes for operators who relied on unlimited implicit budgets across upgrades.
- One-time engineering effort across server config, session admission, and tests.

## Alternatives Considered

1. **Make relaying opt-in instead**
   - Rejected for now: ADR-004/006 argue symmetry maximizes traversal reliability; abandoning that
     trade-off belongs to those ADRs' owners. This ADR instead removes the argument against symmetry.
2. **Enforce via QUIC flow-control credits only**
   - Rejected: stream-flow credits cap per-stream pressure but not aggregate cross-peer fairness,
     and refuse-on-new-session needs application-visible signalling anyway.
3. **Trust process-level cgroups/systemd budgets set by operators**
   - Rejected: out-of-process configuration cannot express per-peer identity fairness and disappears
     in library embedding contexts entirely.

## Validation

- Session budget (already enforced): `src/masque/relay_session.rs::test_rate_limit_allows_within_limit`
  and `test_rate_limit_rejects_over_limit` pin `BandwidthTracker` rejection of over-budget bytes.
- Decision 1 acceptance: the implementing PR must add a test in `src/masque/relay_server.rs` that sets
  `MasqueServerConfig::global_bandwidth_limit` low, drives sessions past it, and asserts new sessions
  receive the structured refuse capsule while existing sessions keep forwarding. It must also revise
  `src/masque/relay_session.rs::test_rate_limit_zero_means_unlimited` so 0-means-unlimited is
  asserted only under the development feature and shipped defaults are finite.
- Decision 2/3 acceptance: a test with two distinct ML-DSA-65 identities behind one `SocketAddr` must
  show independent quotas (identity-keyed, not address-keyed), and a per-source-peer concurrency cap
  test must extend the existing `src/masque/relay_server.rs::test_session_limit` /
  `tests/masque_integration_tests.rs::test_relay_server_session_limit` pattern to the per-peer
  dimension.
- Decision 4 acceptance: after the implementing PR exactly one of these holds -
  `src/relay/rate_limiter.rs` is referenced from the MASQUE accept path, or the file and its
  `pub use rate_limiter::{RateLimiter, TokenBucket}` export in `src/relay/mod.rs` are removed.
- Decision 5 (honesty clause): until every item above lands, README and `docs/architecture/` text
  describing relay participation as bounded must carry a best-effort caveat;
  `tests/release_hygiene.rs` is the established home if a doc-invariant test is added.
- Revisit trigger: ADR-004/006 owners revisit mandatory relaying (opt-in), or ADR-013 budget
  telemetry shows refusals dominating legitimate relay traffic in production.

## References

- Audit sources: `src/masque/relay_session.rs` (enforced session budget),
  `src/masque/relay_server.rs:61-73` (dead global config), `src/relay/rate_limiter.rs` (unwired bucket)
- [libp2p Circuit Relay v2 reservations](https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md)
- [iroh relay concept](https://docs.iroh.computer/concepts/nat-traversal)
- Related: [ADR-002](ADR-002-epsilon-greedy-bootstrap-cache.md),
  [ADR-006](ADR-006-masque-relay-fallback.md),
  [ADR-013](ADR-013-measured-connectivity-metrics.md)

## Notes for AI-assisted work

Drafted with AI assistance; reviewed and accepted by the project owner on 2026-08-26. Accepted ADRs are immutable: create a new superseding ADR rather than editing this one.
