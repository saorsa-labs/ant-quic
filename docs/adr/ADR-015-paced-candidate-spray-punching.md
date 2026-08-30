# ADR-015: Paced Candidate-Spray Punching

## Status

Accepted (2026-08-26)

## Amends

[ADR-005](ADR-005-native-quic-nat-traversal.md) § How It Works step 4 ("Hole Punching") and its
"Symmetric NAT Handling" section, at implementation level. ADR-005 remains immutable.

## Context

Current punching probes **one candidate pair per round**: coordination queues a single punch target
(`send_coordination_request`, `src/connection/mod.rs:1304-1340`) and each punching phase emits one
PATH_CHALLENGE to `targets[0]` (`src/connection/mod.rs:1359-1366`), across up to 3 rounds
(`max_holepunch_rounds: 3`, `src/connection_strategy.rs:186`) with adaptive jitter and RTT-scaled
grace periods in `src/connection/nat_traversal.rs`.

Contemporary systems probe candidate pairs concurrently within an attempt, because a single probe
turns any single loss, late NAT mapping, or mispredicted port into a whole wasted round:

- Tailscale's DISCO sprays endpoints and picks winners continuously
  ([how NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)).
- DCUtR retries coordinated punches three times, measurably improving aggregate success
  ([large-scale measurement, arXiv:2510.27500](https://arxiv.org/abs/2510.27500));
  operator-reported success varies 60-90%
  ([rust-libp2p #5910](https://github.com/libp2p/rust-libp2p/discussions/5910)).
- Port-prediction approaches improve odds further by trying several predicted ports near a sequence
  (classic birthday-style spraying; see libp2p symmetric-NAT discussion).

The existing machinery already produces ranked multi-candidate pairs - including linear-delta
predicted candidates (`src/connection/port_prediction.rs`) and family-filtered pairing - they simply
are not exercised concurrently per round.

## Decision

Per coordination round, replace singleton probing with a **paced spray across the top-N viable pairs**:

1. **N (spray width)**: default 8 pairs per round, configurable. Ordering follows the existing pair
   ranking (family filter → priority class → predicted candidates included at their current
   low-priority tier). N=1 reproduces today's behaviour; both limits bound memory/bandwidth on
   constrained hosts.
2. **Pacing**: inter-probe spacing of at least `max(20 ms, min_rtt/10)` within a round, plus the
   existing start-jitter. Spraying must never violate RFC 9000 anti-amplification rules: probes to an
   unvalidated address count against the 3× received-byte allowance like any other egress.
3. **Validation unchanged**: all probes carry token-keyed PATH_CHALLENGE data padded to 1200 bytes;
   promotion stays keyed by challenge token (survives rebinding), and the existing
   beats-current-path logic selects the winner. First valid PATH_RESPONSE wins; outstanding probes
   of that round are cancelled.
4. **Round count unchanged**: default 3 rounds; a sprayed round subsumes most retry patterns that
   multiple rounds previously approximated, but the round ceiling is retained as backstop.
5. **Unauthenticated trigger safety**: a PUNCH_ME_NOW causes bounded work (≤N paced probes per
   round); hostile coordinators cannot inflate probe volume beyond that without acting on an
   authenticated connection, which carries its own rate limits.
6. **Instrumentation**: per-rank probe outcome counters ship per
   [ADR-013](ADR-013-measured-connectivity-metrics.md) (`path_pair_probe_total{pair_rank}`), so
   future width tuning is evidence-based.

Rollout behind a config knob defaulting to the spray enabled after soak testing in the
network-namespace symmetric-NAT harness used for [ADR-009] validation
(`MASQUERADE --random-fully` namespaces); knob allows instant regression to N=1.

## Consequences

### Positive

- Rescues rounds previously lost to a single dropped/mispredicted probe; expected largest gain in
  port-restricted × port-restricted and port-restricted × predicted-port combinations.
- Cheap relative to payoff: ranking, validation, and promotion paths already exist.
- Per-rank telemetry turns punch tuning into a measurement exercise.

### Negative

- Marginally higher burst egress per round (bounded by pacing + amplification cap).
- More states in validation bookkeeping (per-round outstanding-probe sets) - contained churn in
  `nat_traversal.rs`.
- Symmetric×symmetric remains improbable (~15-30% even with prediction per classic studies); spray
  narrows the gap, relay fallback still owns that cell. Expectations handled by
  [ADR-013](ADR-013-measured-connectivity-metrics.md).

## Alternatives Considered

1. **More rounds instead of wider rounds**
   - Rejected: rounds already scale latency linearly (60 s default coordination timeout); width buys
     coverage inside the same wall-clock budget, which matters for interactive connect() UX.
2. **Birthday-style wide port-range scanning against symmetric NATs (dozens-hundreds of probes)**
   - Rejected as default: egress/amplification cost and firewall-tripping behaviour outweigh
     marginal wins against random-per-destination mappings; narrow linear-delta predictions capture
     most predictable cases affordably.
3. **Always N = all pairs**
   - Rejected: unbounded work triggered by unauthenticated coordination frames violates the
     bounded-trigger-cost rule (Decision 5).

## Validation

- Baseline behaviour this ADR builds on is pinned by `src/connection_strategy.rs::test_holepunch_rounds`
  (3-round ceiling, unchanged by Decision 4) and the ranked-candidate/prediction tests in
  `src/connection/port_prediction.rs` (`test_linear_prediction_increment`,
  `wrapping_delta_predictions_are_supported`, ...) that supply the pairs the spray consumes.
- Implementing PR must add unit tests in `src/connection/nat_traversal.rs` asserting: (a) a round
  emits at most N PATH_CHALLENGEs, to distinct top-ranked pairs; (b) N=1 reproduces today's
  single-probe emission; (c) inter-probe spacing is at least `max(20 ms, min_rtt/10)`; (d) the
  first valid PATH_RESPONSE cancels the round's outstanding probes.
- Anti-amplification (Decision 2): a test must show probes to an unvalidated address are withheld
  once the 3x received-byte allowance is exhausted, exercising the existing
  `validate_amplification_limits` / `is_amplification_suspicious` checks in
  `src/connection/nat_traversal.rs` rather than a new accounting path.
- Bounded trigger (Decision 5): a test must show a flood of PUNCH_ME_NOW frames from an
  unauthenticated coordinator yields no more than N paced probes per round.
- `path_pair_probe_total{pair_rank}` must ship with the feature per ADR-013, and the default-flip PR
  must cite before/after values from the symmetric-NAT namespace harness referenced by ADR-009.
- Revisit trigger: ADR-013 telemetry shows the punched-tier share unchanged after the default flip,
  or egress/amplification counters rise materially - either reopens spray width or pacing in a new
  ADR.

## References

- Current scheduling: `src/connection/nat_traversal.rs` (grace/jitter/retry math),
  `src/connection/mod.rs:1342-1426` (challenge emission/validation)
- Candidates & prediction: `src/port_prediction` usage via
  `src/connection/nat_traversal.rs:1940-2004`
- External evidence: [Tailscale NAT traversal](https://tailscale.com/blog/how-nat-traversal-works),
  [arXiv:2510.27500](https://arxiv.org/abs/2510.27500),
  [rust-libp2p #5910](https://github.com/libp2p/rust-libp2p/discussions/5910)
- Related: [ADR-005](ADR-005-native-quic-nat-traversal.md),
  [ADR-013](ADR-013-measured-connectivity-metrics.md)

## Notes for AI-assisted work

Drafted with AI assistance; reviewed and accepted by the project owner on 2026-08-26. Accepted ADRs are immutable: create a new superseding ADR rather than editing this one.
