# Cross-environment ant-quic test matrix

End-to-end test that proves, for every node-pair in a 9-node mesh:

- a connection was made and what transport carried it (direct-IPv4,
  direct-IPv6, NAT-traversed, or relayed),
- 64 MiB of SHA-256-verified data flowed,
- streams open and close cleanly under continuous counter exchange,
- and — when direct paths are blocked — the MASQUE relay carries actual
  bytes between the pair.

## Topology

Single source of truth: `scripts/lib/topology.sh`. Borrowed verbatim from
[x0x's `DEFAULT_BOOTSTRAP_PEERS`](../../../x0x/src/network.rs) but on port
**10000** instead of x0x's 5483 so the two systems coexist.

| Label | Host | Role |
|---|---|---|
| L1 | this MacBook (loopback) | LAN, mDNS |
| L2 | studio1.local | LAN, mDNS |
| L3 | studio2.local | LAN, mDNS |
| V_NYC | 142.93.199.50 (DigitalOcean NYC) | VPS |
| V_SFO | 147.182.234.192 (DigitalOcean SFO) | VPS |
| V_HEL | 65.21.157.229 (Hetzner Helsinki) | VPS |
| V_NUE | 116.203.101.172 (Hetzner Nuremberg) | VPS |
| V_SGP | 149.28.156.231 (Vultr Singapore) | VPS |
| V_TYO | 45.77.176.184 (Vultr Tokyo) | VPS |

Cross-LAN discovery uses `--known-peers` listing every VPS IPv4 on port
10000. No registry, no default bootstrap. mDNS handles LAN-only
discovery for L1/L2/L3.

Preflight probes each non-L1 node via SSH; unreachable nodes are recorded
in `LOG_DIR/skipped.txt` and excluded from later steps.

## Layout

```
scripts/
  run-cross-env-matrix.sh                # orchestrator
  lib/
    topology.sh                          # node list, ports, SSH targets
    cross-env-common.sh                  # log helpers, pfctl wrappers
    aggregate.py                         # log → SUMMARY.md
    scenarios/
      c1-mesh-up.sh                      # bring up all nodes; assert mesh
      c2-path-type.sh                    # extract direct_path_status events
      c3-pairwise-transfer.sh            # 64 MiB SHA-verified per pair
      c4-streams.sh                      # counter_test per pair
      c5-forced-relay.sh                 # pfctl block + relay byte proof
      c6-cleanup.sh                      # SIGTERM + clean-shutdown verify
```

Logs land in `target/cross-env/<timestamp>/<label>.log`. Aggregator
emits `SUMMARY.md` in the same directory.

## Prerequisites

```bash
# 1. Local macOS binary (must include --send-to flag — c233e4e0 or later)
cargo build --release --bin ant-quic

# 2. Linux binary cross-compiled for the VPS fleet
cargo install cargo-zigbuild      # one-time
cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin ant-quic
# Push to each VPS:
for ip in 142.93.199.50 147.182.234.192 65.21.157.229 116.203.101.172 149.28.156.231 45.77.176.184; do
    ssh root@${ip} 'mkdir -p /opt/ant-quic-test/bin && systemctl stop ant-quic-matrix 2>/dev/null'
    scp target/x86_64-unknown-linux-gnu/release/ant-quic root@${ip}:/opt/ant-quic-test/bin/ant-quic
    ssh root@${ip} 'chmod +x /opt/ant-quic-test/bin/ant-quic'
done

# 3. SSH reachability to LAN studios
ssh studio1@studio1.local true
ssh studio2@studio2.local true

# 4. Sudo on this MacBook (only required for C5 forced-relay's pfctl rule)
sudo -v
```

## Running

```bash
# All scenarios, full matrix
scripts/run-cross-env-matrix.sh

# A single scenario
scripts/run-cross-env-matrix.sh --scenario c3-pairwise-transfer

# List discovered scenarios
scripts/run-cross-env-matrix.sh --list

# Skip preflight (use when topology is known good)
scripts/run-cross-env-matrix.sh --no-preflight
```

Optional environment overrides:

| Variable | Default | Purpose |
|---|---|---|
| `ANT_QUIC_BIN_LOCAL` | `target/release/ant-quic` | macOS binary on L1 |
| `ANT_QUIC_PORT` | `10000` | port every node binds |
| `LOG_DIR` | `target/cross-env/<ts>` | per-run log directory |
| `MESH_TIMEOUT` | `60` | how long C1 waits for mesh formation |
| `TRANSFER_BYTES` | `67108864` | C3 payload size (64 MiB) |
| `TRANSFER_TIMEOUT` | `90` | C3 per-pair wall timeout |
| `STREAM_DURATION` | `30` | C4 counter-test window |
| `FORCED_PAIR_SENDER` / `FORCED_PAIR_RECIPIENT` | `L1` / `V_HEL` | C5 pair |
| `STUDIO1_TARGET` / `STUDIO2_TARGET` | from topology.sh | override SSH target |

## Reading SUMMARY.md

The aggregator produces one verdict, then a series of N×N matrices:

- **Connectivity matrix** — for each `(sender, recipient)`, the
  `connection_type` from the last `peer_connected` event:
  `direct`, `nat_traversed`, or `relayed`.
- **Path-type matrix** — for each pair, the most recent
  `direct_path_status` event (`Established`, `Pending`,
  `BestEffortUnavailable`, `Failed`).
- **Transfer matrix** — for each directed pair, ✓/✗ + throughput Mbps
  (from sender's `send_to_complete` event, cross-checked against
  recipient's `data_received` with `sha_match: true`).
- **Stream matrix** — counters exchanged per pair in C4.
- **Forced-relay evidence** — relay node + bytes_forwarded from
  `target=ant_quic::relay_traffic` warn lines.
- **Silent drops by kind** — listed if any. Run is FAIL if non-zero.

PASS criteria (all must hold):
1. zero silent_drop, send_error, and stale_reaper lines.
2. every reachable directed pair has a `peer_connected` event.
3. every C3 pair completed with `sha_ok: true`.
4. forced-relay observed non-zero `bytes_forwarded`.

## Triage

| Symptom | First check |
|---|---|
| Pair shows blank in connectivity matrix | `grep -i 'failed\|timeout' LOG_DIR/c1_<sender>.log` |
| Transfer ✗ for a pair | check sender `c3_send_*.log` for `send_to_complete` and recipient `c1_*.log` for `data_received` |
| C5 reports zero relay bytes | confirm pfctl block applied (`sudo pfctl -a com.saorsa/cross-env -s rules`) and a VPS hosts the MASQUE relay session; check any `c1_V_*.log` for `target=ant_quic::relay_traffic` |
| Silent drops > 0 | grep the per-node log for `kind=<slug>` to find the offending source line |
| Stale-reaper triggered | indicates a lifecycle regression; bisect against `c233e4e0` |

## Adding a scenario

Drop a new `c7-foo.sh` in `scripts/lib/scenarios/`. It MUST:

1. Source `cross-env-common.sh` and `topology.sh`.
2. Export functions `run`, `verify`, and a dispatcher matching
   `case "${1:-run}"` at the bottom (see `c1-mesh-up.sh` for the canonical
   shape).
3. Register a cleanup trap if it spawns processes.
4. Write its per-host logs to `LOG_DIR/c7_<label>.log` so the aggregator
   picks them up.

The orchestrator auto-discovers any new scenario file.

## Notes

- Sudo is only required for C5; you can omit it if you skip that scenario.
- `--send-to` and the periodic `relay_traffic` warn line both arrived in
  ant-quic v0.27.x — older binaries on the VPS will reject `--send-to`
  with a clap parse error. Always run the deploy step above before a
  full-matrix run.
- The harness deliberately does NOT restart the systemd `ant-quic-matrix`
  unit on VPS after the run — the operator does that by hand.
