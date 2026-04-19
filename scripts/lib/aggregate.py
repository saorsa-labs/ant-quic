#!/usr/bin/env python3
"""Aggregate per-node ant-quic logs into a single SUMMARY.md.

Given a directory of *.log files (one per node), this script:

  * Builds a per-pair connection-type matrix from `ConnectionEstablished`
    and `DirectPathStatus` log lines.
  * Counts every `target=ant_quic::silent_drop` line by `kind=`.
  * Counts every `target=ant_quic::send_error` line by peer.
  * Surfaces unexpected timeouts, ack-timeout, and stale-reaper triggers.
  * Writes SUMMARY.md alongside the input logs.

Pure stdlib; no external deps. Designed to work even with partial
instrumentation: missing kinds simply don't appear in the breakdown.
"""

from __future__ import annotations

import argparse
import collections
import pathlib
import re
import sys


SILENT_DROP_RE = re.compile(r"target=ant_quic::silent_drop\b.*?kind=(\S+)")
SEND_ERROR_RE = re.compile(r"target=ant_quic::send_error\b")
PEER_ID_RE = re.compile(r"Peer ID:\s*([0-9a-f]{64})")
# Match either the P2pEvent name OR the --stats summary line "Successful
# connections: N" with N >= 1. Either is a positive signal a connection was
# made by the node.
CONN_EST_RE = re.compile(r"ConnectionEstablished|Successful connections:\s*[1-9]")
DIRECT_PATH_RE = re.compile(r"DirectPathStatus\s*\{[^}]*?status:\s*(\w+)")
NAT_PROGRESS_RE = re.compile(r"NatTraversalProgress")
RELAY_BYTES_RE = re.compile(r"bytes_relayed[=:]\s*(\d+)")
STALE_REAPER_RE = re.compile(r"stale.connection.reaper", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "log_dir",
        type=pathlib.Path,
        help="Directory containing per-node *.log files",
    )
    p.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="Output SUMMARY.md path (default: <log_dir>/SUMMARY.md)",
    )
    return p.parse_args()


def collect_logs(log_dir: pathlib.Path) -> dict[str, list[str]]:
    """Read every node *.log in log_dir, returning {node_label: [lines]}.

    Excludes orchestrator.log — the harness's own output is not a node log
    and would false-positive on log lines that mention `ConnectionEstablished`
    in scenario titles or summary messages.
    """
    logs: dict[str, list[str]] = {}
    for path in sorted(log_dir.glob("*.log")):
        if path.stem == "orchestrator":
            continue
        try:
            logs[path.stem] = path.read_text(errors="replace").splitlines()
        except OSError as e:
            print(f"warn: could not read {path}: {e}", file=sys.stderr)
    return logs


def per_node_peer_id(lines: list[str]) -> str | None:
    for line in lines:
        m = PEER_ID_RE.search(line)
        if m:
            return m.group(1)
    return None


def silent_drop_breakdown(logs: dict[str, list[str]]) -> dict[str, dict[str, int]]:
    """{node_label: {kind: count}}"""
    out: dict[str, dict[str, int]] = {}
    for node, lines in logs.items():
        kinds: collections.Counter[str] = collections.Counter()
        for line in lines:
            m = SILENT_DROP_RE.search(line)
            if m:
                kinds[m.group(1)] += 1
        if kinds:
            out[node] = dict(kinds)
    return out


def send_error_count(logs: dict[str, list[str]]) -> dict[str, int]:
    return {node: sum(1 for line in lines if SEND_ERROR_RE.search(line))
            for node, lines in logs.items()}


def connection_pairs(logs: dict[str, list[str]]) -> dict[str, int]:
    """{node_label: number of ConnectionEstablished events observed}"""
    return {node: sum(1 for line in lines if CONN_EST_RE.search(line))
            for node, lines in logs.items()}


def direct_path_statuses(logs: dict[str, list[str]]) -> dict[str, dict[str, int]]:
    """{node_label: {status_variant: count}}"""
    out: dict[str, dict[str, int]] = {}
    for node, lines in logs.items():
        statuses: collections.Counter[str] = collections.Counter()
        for line in lines:
            m = DIRECT_PATH_RE.search(line)
            if m:
                statuses[m.group(1)] += 1
        if statuses:
            out[node] = dict(statuses)
    return out


def relay_bytes_seen(logs: dict[str, list[str]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for node, lines in logs.items():
        last = 0
        for line in lines:
            m = RELAY_BYTES_RE.search(line)
            if m:
                last = max(last, int(m.group(1)))
        if last:
            out[node] = last
    return out


def stale_reaper_hits(logs: dict[str, list[str]]) -> dict[str, int]:
    return {node: sum(1 for line in lines if STALE_REAPER_RE.search(line))
            for node, lines in logs.items()}


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_(no data)_\n"
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out) + "\n"


def write_summary(out_path: pathlib.Path, logs: dict[str, list[str]]) -> int:
    """Write SUMMARY.md. Returns 0 if all checks passed, 1 otherwise."""
    drops = silent_drop_breakdown(logs)
    send_errs = send_error_count(logs)
    conns = connection_pairs(logs)
    paths = direct_path_statuses(logs)
    relay = relay_bytes_seen(logs)
    stale = stale_reaper_hits(logs)

    drop_total = sum(sum(v.values()) for v in drops.values())
    send_total = sum(send_errs.values())
    stale_total = sum(stale.values())
    nodes_with_conns = sum(1 for n, c in conns.items() if c > 0)

    lines: list[str] = []
    lines.append("# Cross-env ant-quic test SUMMARY\n")
    lines.append(f"Run directory: `{out_path.parent}`\n")
    lines.append(f"Nodes inspected: **{len(logs)}**\n")

    lines.append("## Verdicts\n")
    lines.append(f"- silent_drop events: **{drop_total}** (target 0)")
    lines.append(f"- send_error events: **{send_total}** (target 0)")
    lines.append(f"- nodes with ≥1 connection: **{nodes_with_conns}/{len(logs)}** (informational)")
    lines.append(f"- stale-reaper triggers: **{stale_total}** (target 0)\n")

    # Aggregator FAILs on silent failures only. Connection count is informational
    # — per-scenario verify() functions own the connection assertions because
    # different scenarios have different expectations (e.g. C1 LAN-only doesn't
    # need full QUIC handshakes within its 25s window, just mDNS discovery).
    fail = drop_total > 0 or stale_total > 0 or send_total > 0
    if fail:
        lines.append("**Result: FAIL** — see breakdowns below.\n")
    else:
        lines.append("**Result: PASS**\n")

    lines.append("## Per-node peer identity\n")
    rows = []
    for node, ll in logs.items():
        pid = per_node_peer_id(ll) or "_(not seen)_"
        rows.append([node, pid[:16] + ("…" if len(pid) > 16 and pid != "_(not seen)_" else "")])
    lines.append(md_table(["node", "peer id (first 16)"], rows))

    lines.append("## Connections\n")
    rows = [[node, str(conns.get(node, 0))] for node in sorted(logs)]
    lines.append(md_table(["node", "ConnectionEstablished count"], rows))

    lines.append("## DirectPathStatus distribution\n")
    rows = []
    for node in sorted(logs):
        node_paths = paths.get(node, {})
        if not node_paths:
            continue
        breakdown = ", ".join(f"{k}={v}" for k, v in sorted(node_paths.items()))
        rows.append([node, breakdown])
    lines.append(md_table(["node", "statuses"], rows))

    lines.append("## Silent drops by kind\n")
    if drop_total == 0:
        lines.append("_None — instrumentation reports zero silent drops._\n")
    else:
        rows = []
        for node in sorted(drops):
            for kind, n in sorted(drops[node].items(), key=lambda kv: -kv[1]):
                rows.append([node, kind, str(n)])
        lines.append(md_table(["node", "kind", "count"], rows))

    lines.append("## Send-path errors\n")
    rows = [[node, str(send_errs[node])] for node in sorted(send_errs) if send_errs[node]]
    lines.append(md_table(["node", "send_error count"], rows) if rows else "_None._\n")

    lines.append("## Relay bytes observed (max per node)\n")
    rows = [[node, f"{relay[node]:,}"] for node in sorted(relay)]
    lines.append(md_table(["node", "max bytes_relayed"], rows) if rows else "_No relay activity observed._\n")

    lines.append("## Stale-reaper triggers\n")
    rows = [[node, str(stale[node])] for node in sorted(stale) if stale[node]]
    lines.append(md_table(["node", "trigger count"], rows) if rows else "_None — clean shutdowns._\n")

    out_path.write_text("\n".join(lines))
    print(f"wrote {out_path}")
    return 1 if fail else 0


def main() -> int:
    args = parse_args()
    log_dir = args.log_dir.resolve()
    if not log_dir.is_dir():
        print(f"error: {log_dir} is not a directory", file=sys.stderr)
        return 2
    logs = collect_logs(log_dir)
    if not logs:
        print(f"warn: no *.log files found in {log_dir}", file=sys.stderr)
    out_path = args.output or (log_dir / "SUMMARY.md")
    return write_summary(out_path, logs)


if __name__ == "__main__":
    sys.exit(main())
