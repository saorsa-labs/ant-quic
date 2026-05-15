# Testability and Coverage Plan

This plan tracks the repo-wide push to make ant-quic's discovery, traversal, messaging, and transfer behavior testable without adding flaky CI dependencies.

## Current Inventory

- `tests/`: broad integration suite with NAT traversal, PQC, compatibility, lifecycle, constrained transport, and P2P delivery tests.
- `benches/`: Criterion coverage for NAT traversal, connection management, candidate discovery, address discovery, relay queue, PQC pool, and QUIC benchmarks.
- `src/mdns.rs`: production mDNS discovery with deterministic directory/state logic that should be tested without live multicast.
- `src/port_mapping.rs`: UPnP/IGD port mapping with `GatewayDiscoverer` and `GatewayControl` seams suitable for mocked tests.
- Existing coverage workflow focuses on library coverage; integration coverage should be reported separately before being used as a hard gate.

## Test Tiers

| Tier | Runs | Scope | Requirements |
| --- | --- | --- | --- |
| Quick deterministic | Every PR | Unit/model tests, encoding, mocked gateways | No real network dependencies |
| Loopback integration | Every PR | Local endpoint pairs, message send/receive, small transfers | Bind port `0`, Tokio timeouts |
| Docker/network namespace | Scheduled or labeled PR | NAT matrix, relay fallback, path behavior | Docker/network namespace support |
| Live environment | Manual/ignored | Real LAN mDNS, real router UPnP, public VPS smoke | Env var opt-in only |
| Benchmarks | Scheduled/manual; compile on PR | Throughput, message volume, traversal latency | Generated payloads, bounded profiles |

## Priority Matrix

### P0: Deterministic discovery and mapping coverage

- mDNS directory/model tests:
  - self-peer rejection
  - namespace mismatch
  - missing/invalid peer ID
  - no usable addresses
  - duplicate address deduplication
  - update/remove sequencing
  - IPv4/IPv6 handling
  - stale record cleanup using deterministic time where possible
- UPnP/IGD mocked tests:
  - discovery success/failure
  - fixed-port mapping success
  - fallback to any external port
  - mapping failure degradation
  - external IP filtering for private/CGNAT/loopback/documentation addresses
  - lease refresh without real sleeps
  - cleanup on shutdown

### P1: Loopback message correctness

- Endpoint pair send/receive.
- Small-message volume test, e.g. 1,000 bounded messages.
- Multi-peer delivery/fanout.
- Slow receiver/backpressure behavior.
- Stream reset/cancellation/shutdown while in flight.

### P2: Native NAT traversal integration matrix

Map existing tests before adding new ones. Fill only scenario gaps around public API behavior:

- `connect_known_peers()` seeds address discovery.
- `connect_addr()` and `connect_peer()` use the unified orchestration path.
- observed address is stored and surfaced.
- candidates are deduped/ranked.
- unsupported traversal peers degrade cleanly.
- simultaneous connect dedup is retained.
- Docker NAT matrix covers symmetric, restricted, dual-stack, and relay-fallback cases.

### P3: Transfer and volume benchmarks

- Add/refactor dedicated transfer throughput benchmark.
- Add/refactor message-volume benchmark.
- Generate deterministic payloads at runtime; never commit large fixtures.
- Track MiB/s, messages/s, p50/p95/p99 latency, failures, and bounded memory behavior where practical.

## Justfile Entry Points

The repository justfile provides the operational split used by this plan:

- `just full-test`: PR-style validation: formatting, clippy, library/doc/quick/standard/property tests, and benchmark compilation.
- `just coverage-integration`: warning-first integration coverage report using `cargo llvm-cov`.
- `just heavy-nat`: Docker/network-namespace NAT integration tests.
- `just heavy-long`: ignored long/stress tests.
- `just heavy-mdns`: live mDNS smoke tests; requires `ANT_QUIC_LIVE_MDNS=1`.
- `just heavy-upnp`: live UPnP smoke tests; requires `ANT_QUIC_LIVE_UPNP=1`.
- `just heavy-bench`: currently available scheduled/manual benchmark set.
- `just manual-full-test`: full PR suite plus heavy NAT, long, and benchmark suites for capable local/scheduled environments.

## CI Guidance

### PR CI

- Run deterministic unit/model tests.
- Run loopback integration tests with strict timeouts.
- Compile benchmarks.
- Do not require real mDNS, real UPnP, Docker NAT, or large-transfer benchmarks.

### Scheduled/labeled CI

- Run Docker NAT scenarios.
- Run throughput and message-volume benchmarks.
- Produce integration coverage reports.
- Upload logs/artifacts for connection timelines and benchmark summaries.

### Manual ignored tests

Use explicit environment guards:

- `ANT_QUIC_LIVE_MDNS=1`
- `ANT_QUIC_LIVE_UPNP=1`
- `ANT_QUIC_LIVE_PUBLIC_ENDPOINTS=1`

## Coverage Reporting

Keep the current fast library coverage report. Add a separate integration coverage report first as warning-only:

```bash
cargo llvm-cov --all-features --workspace --tests \
  --ignore-filename-regex '(benches/|examples/|build\.rs)'
```

Only raise thresholds after collecting a stable baseline.

## Non-Negotiable Test Rules

- Every async/network test must have a timeout.
- Use port `0`; no fixed local ports in default tests.
- Avoid fixed sleeps; prefer events, channels, or injectable clocks.
- No committed large binary fixtures.
- Real multicast and real router UPnP are never PR requirements.
- Benchmarks and correctness tests stay separate.
