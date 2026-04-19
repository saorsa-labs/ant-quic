# Cross-environment ant-quic test matrix

End-to-end test that exercises ant-quic across a realistic Saorsa deployment:

- **Local LAN** — this MacBook + 2 Mac Studios (all behind home NAT). They
  discover each other via mDNS only; no external connectivity is required for
  the LAN-only scenarios.
- **VPS fleet** — `saorsa-1..10.saorsalabs.com`. The 3 LAN nodes reach the
  VPS via the binary's built-in default bootstrap
  (`saorsa-1.saorsalabs.com:9000`, `saorsa-2.saorsalabs.com:9000`).

The harness verifies mesh formation, byte-exact data transfer, IPv4/IPv6
dual-stack, hole-punch, and relay fallback, and counts every silent-drop
event the instrumentation has surfaced.

## Layout

```
scripts/run-cross-env-matrix.sh         # top-level orchestrator
scripts/lib/cross-env-common.sh         # shared bash helpers
scripts/lib/aggregate.py                # log → SUMMARY.md aggregator
scripts/lib/scenarios/c1-lan-mdns.sh    # LAN-only mDNS mesh
scripts/lib/scenarios/c2-mesh.sh        # full LAN+VPS mesh (TODO)
scripts/lib/scenarios/c3-direct.sh      # direct UDP transfer (TODO)
scripts/lib/scenarios/c4-holepunch.sh   # NAT-to-NAT (TODO)
scripts/lib/scenarios/c5-relay.sh       # forced-relay fallback (TODO)
scripts/lib/scenarios/c6-dualstack.sh   # IPv4/IPv6 confirmation (TODO)
```

Logs are written to `target/cross-env/<timestamp>/<node-label>.log`. The
aggregator emits `SUMMARY.md` in the same directory.

## Prerequisites

```bash
# 1. macOS binary built locally
cargo build --release --bin ant-quic

# 2. Linux binary cross-compiled for the VPS fleet
cargo install cargo-zigbuild     # one-time
cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin ant-quic

# 3. SSH reachability for the Mac Studios
ssh studio1@studio1.local true
ssh studio2@studio2.local true

# 4. Registry health (if running VPS scenarios)
curl -fsS https://saorsa-1.saorsalabs.com/health
```

## Running

```bash
# All scenarios
scripts/run-cross-env-matrix.sh

# A single scenario
scripts/run-cross-env-matrix.sh --scenario c1-lan-mdns

# List discovered scenarios
scripts/run-cross-env-matrix.sh --list

# Skip preflight (use when you've already verified)
scripts/run-cross-env-matrix.sh --no-preflight --scenario c1-lan-mdns
```

Optional environment overrides:

| Variable | Default | Purpose |
|---|---|---|
| `ANT_QUIC_BIN_LOCAL` | `target/release/ant-quic` | macOS binary on this MacBook |
| `ANT_QUIC_BIN_STUDIO` | `ant-quic` (PATH on remote) | binary on the studios |
| `STUDIO1_TARGET` | (unset) | e.g. `studio1@studio1.local` |
| `STUDIO2_TARGET` | (unset) | e.g. `studio2@studio2.local` |
| `LOG_DIR` | `target/cross-env/<ts>` | per-run log directory |
| `REGISTRY_HEALTH_URL` | `https://saorsa-1.saorsalabs.com/health` | preflight probe |

## Reading SUMMARY.md

The aggregator reports a single PASS/FAIL verdict at the top, then breaks
the run down by:

- per-node peer identity (first 16 hex chars of the ML-DSA-65 PeerId)
- ConnectionEstablished count per node
- DirectPathStatus distribution (Established / Pending / Failed / BestEffortUnavailable)
- silent-drop events, grouped by node and `kind=` slug
- send-path errors per node
- relay throughput (if any)
- stale-reaper triggers (regression check on the v0.27 lifecycle fix)

The `kind=` slugs come from the `tracing::warn!(target: "ant_quic::silent_drop", kind = ...)`
instrumentation. A non-zero count is not necessarily a regression — it's the
to-fix backlog for follow-up PRs. The verdict only fails the run if mesh
formation, data integrity, or stale-reaper checks fail.

## Triage

| Symptom | First check |
|---|---|
| `nodes with ≥1 ConnectionEstablished < N` | `grep -i 'failed\|timeout' <node>.log` |
| Silent drops >0 | `grep 'kind=<slug>' <node>.log` to find offending sites |
| Relay bytes 0 in C5 | Confirm pfctl rule applied; check `<node>.log` for relay handshake |
| Stale-reaper trigger | Indicates a lifecycle regression — bisect since `0cb3c7f0` |

## Adding a scenario

Each scenario script in `scripts/lib/scenarios/` exports `run`, `verify`,
and `all` (which calls both). Source `scripts/lib/cross-env-common.sh` to
get `ssh_run_log`, `local_run_log`, `wait_for_peer_id`,
`assert_no_silent_drops`, and `count_log_pattern`. Scenarios MUST register
a cleanup trap so background nodes are stopped even on test failure.

See `scripts/lib/scenarios/c1-lan-mdns.sh` for the canonical template.
