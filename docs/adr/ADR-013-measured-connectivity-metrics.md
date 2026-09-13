# ADR-013: Measured Connectivity Metrics Replace Asserted Success Rates

## Status

Accepted (2026-08-26)

## Supersedes

All quantitative connectivity-success claims in accepted ADRs:

- [ADR-005](ADR-005-native-quic-nat-traversal.md) § Layered Connectivity Strategy ("~20%", "High*")
- [ADR-006](ADR-006-masque-relay-fallback.md) § Layered Connectivity Strategy ("~100%")
- [ADR-008](ADR-008-universal-connectivity-architecture.md) § Connectivity Matrix ("95%+", "100%")

Those tables remain in their immutable originals; this ADR replaces them as the source of truth for
expectations and requires instrumentation instead of assertion.

## Context

The percentage columns in ADR-005/006/008 were illustrative estimates at decision time. They have
two problems: they are not measurable from any artifact of this project, and they now conflict with
published measurements:

- Tailscale reports direct-connection success "well north of 90%" from internal fleet metrics
  ([nat-traversal-improvements-pt-1](https://tailscale.com/blog/nat-traversal-improvements-pt-1)).
- The first large-scale measurement of fully decentralized NAT traversal (DCUtR/libp2p;
  Trautwein et al., [arXiv:2510.27500](https://arxiv.org/abs/2510.27500)) found **70% ± 7.1%
  conditional hole-punch success**, attributing residual failure primarily to endpoint-dependent
  mapping and CGNAT - exactly the environments ant-quic targets hardest.
- iroh publicly cites ~90% direct-hole-punch success with encrypted relays as guaranteed fallback
  ([iroh docs](https://docs.iroh.computer/concepts/nat-traversal)).
- rust-libp2p operator reports range 60-90% depending on deployment
  ([rust-libp2p discussion #5910](https://github.com/libp2p/rust-libp2p/discussions/5910)).

A layered system can still reach near-total coverage via relay fallback, but the *distribution*
across layers is an empirical property of the deployed population, unknowable from design docs.

## Decision

### 1. Qualitative tiers only, in prose

Documentation describes establishment tiers qualitatively:

| Tier | Meaning (no percentages) |
|------|--------------------------|
| Direct | Existing reachability or router-assisted mapping made it work |
| Punched | Coordinated traversal through observed-only-NAT pairs succeeded |
| Relayed | Fallback guaranteed path; expected residual after punch failure |

Success *rates* belong to telemetry dashboards, never static ADR tables.

### 2. Required exported metrics

Promote the existing monitoring list ([ADR-008] § Monitoring Metrics) into concrete instrumented
counters/histograms shipped by default:

- `connection_establishment_total{method=direct|punched|relay}` (source of truth for tier ratios)
- `holepunch_attempt_total{outcome=succeeded|failed|timeout}` per round number
- `path_pair_probe_total{pair_rank}` (feeds [ADR-015](ADR-015-paced-candidate-spray-punching.md))
- `time_to_establish_seconds{method}` histogram
- `relay_upgrade_total{from=relay,to=direct}` and `relay_session_bytes_total`
- `symmetric_nat_detection_total{detected=yes|no}`
- `port_mapping_result{protocol=upnp_igd,outcome=mapped|failed|unsupported}` (extensible to PCP/NAT-PMP)
- Amplification/pacing counters from [ADR-015]

### 3. Internal SLOs set after a data window

Numeric engineering targets (e.g., minimum punched-tier share, maximum relay-tier share) are set
after ~30 days of multi-environment telemetry, tracked as issues with links to dashboard snapshots.
External studies may be cited in docs with links; unsourced constants may not.

### 4. Tuning gated on measurement

Future changes to punch-round count, spray width ([ADR-015](ADR-015-paced-candidate-spray-punching.md)),
or relay-forwarding mode ([ADR-016](ADR-016-hybrid-relay-data-plane.md)) must cite these metrics
before/after, making layer distribution a governed KPI rather than folklore.

## Consequences

### Positive

- Expectations track reality as the deployed population shifts (CGNAT growth, IPv6 growth).
- Argues for engineering investment with numbers when the punched tier lags.
- Removes maintenance burden of perpetually-outdated estimates.

### Negative

- Instrumentation work ships ahead of numeric comfort; dashboards need a home.
- Docs lose reassuring-sounding certainty until data exists - intended consequence.

## Alternatives Considered

1. **Keep percentages, add "measured" caveats to each table**
   - Rejected: leaves unverifiable numbers in accepted text and invites cargo-culting them into
     user-facing material.
2. **Copy the libp2p/Tailscale figures into our docs as expectations**
   - Rejected: different population (browser-free symmetric Rust nodes, mandatory relaying) makes
     transplanting their distributions its own form of assertion.

## Validation

- None of the Decision 2 metric names (`connection_establishment_total`, `holepunch_attempt_total`,
  `path_pair_probe_total`, `time_to_establish_seconds`, `relay_upgrade_total`,
  `symmetric_nat_detection_total`, `port_mapping_result`) exist in `src/` as of 2026-08-26. The
  implementing PR must add each as an exported counter/histogram plus a unit test per metric that
  drives the corresponding code path (a relayed connect, a timed-out punch round, ...) and asserts
  the labelled increment.
- `connection_establishment_total{method}` must be derived from the same events that already feed
  `EndpointStats`; `src/p2p_endpoint.rs::test_direct_plus_relayed_equals_active_connections_under_churn`
  and `test_record_connection_established_direct_to_relay_decrements_direct` pin that accounting
  and must keep passing.
- `tests/connection_success_rates.rs::observed_address_frames_drive_connection_success_rate_inputs`
  is the only test computing a success *rate*; it compares two simulated runs against each other
  rather than against a fixed percentage - the pattern any new rate assertion must follow.
- Reviewers reject new ADR or `docs/architecture/` text that states a connectivity-success
  percentage without a link to a dashboard snapshot or an external study; the figures in this ADR's
  Context and in ADR-015's Consequences are cited external measurements, not ant-quic claims.
- Revisit trigger: the ~30-day multi-environment telemetry window (Decision 3) closes and numeric
  SLOs are proposed - those go into a new ADR citing dashboard snapshots, not into this one.

## References

- [Tailscale: improving NAT traversal](https://tailscale.com/blog/nat-traversal-improvements-pt-1)
- [arXiv:2510.27500 - Large-scale decentralized NAT traversal measurement](https://arxiv.org/abs/2510.27500)
- [arXiv:2604.12484 - DCUtR IPFS case study](https://arxiv.org/html/2604.12484v1)
- [rust-libp2p discussion #5910](https://github.com/libp2p/rust-libp2p/discussions/5910)
- [iroh NAT traversal concepts](https://docs.iroh.computer/concepts/nat-traversal)
- Related: [ADR-008](ADR-008-universal-connectivity-architecture.md) § Monitoring Metrics (superseded list),
  [ADR-015](ADR-015-paced-candidate-spray-punching.md), [ADR-016](ADR-016-hybrid-relay-data-plane.md)

## Notes for AI-assisted work

Drafted with AI assistance; reviewed and accepted by the project owner on 2026-08-26. Accepted ADRs are immutable: create a new superseding ADR rather than editing this one.
