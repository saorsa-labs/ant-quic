#!/usr/bin/env python3
"""Aggregate the cross-env matrix run into a single SUMMARY.md.

Reads:
  - ``LOG_DIR/c1_<label>.log`` for each long-lived c1 node.
  - ``LOG_DIR/c3_send_<sender>_to_<recipient>.log`` for transfer attempts.
  - ``LOG_DIR/c4_stream_<sender>_to_<recipient>.log`` for stream attempts.
  - ``LOG_DIR/c5_send_<sender>_to_<recipient>_relay.log`` for forced-relay.
  - ``LOG_DIR/peer_ids.tsv`` for label -> 16-char short peer id.
  - ``LOG_DIR/skipped.txt`` for nodes preflight marked unreachable.

Writes ``LOG_DIR/SUMMARY.md`` and exits 0/1 by verdict.

PASS iff zero silent_drop, zero send_error, zero stale-reaper triggers,
every reachable directed pair connected, every C3 transfer SHA-OK, and
forced-relay (if it ran) succeeded.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys
from typing import Optional


# Stable patterns the harness emits.
RE_PEER_ID = re.compile(r"Peer ID:\s*([0-9a-f]{16})")
RE_PEER_CONNECTED = re.compile(
    r'"event":"peer_connected".*?"peer_id":"([0-9a-f]+)".*?"connection_type":"([^"]+)"'
)
RE_DIRECT_PATH = re.compile(
    r'"event":"direct_path_status".*?"peer_id":"([0-9a-f]+)".*?"status":"([^"]+)"'
)
RE_SEND_TO_COMPLETE = re.compile(
    r'"event":"send_to_complete".*?"target":"([0-9a-f]+)".*?"bytes":(\d+).*?"chunks":(\d+).*?"duration_ms":(\d+).*?"throughput_mbps":([0-9.]+).*?"sha_ok":(true|false)'
)
RE_DATA_RECEIVED = re.compile(
    r'"event":"data_received".*?"peer_id":"([0-9a-f]+)".*?"sha_match":(true|false)'
)
RE_COUNTER_SENT = re.compile(r'"event":"counter_sent"')
RE_RELAY_TRAFFIC = re.compile(
    r'target=ant_quic::relay_traffic.*?bytes_forwarded=(\d+).*?datagrams=(\d+)'
)
RE_SILENT_DROP = re.compile(r"target=ant_quic::silent_drop\b.*?kind=(\S+)")
RE_SEND_ERROR = re.compile(r"target=ant_quic::send_error\b")
RE_STALE_REAPER = re.compile(r"stale.connection.reaper", re.IGNORECASE)
RE_SHUTDOWN = re.compile(r"Shutting down P2P endpoint")


def load_peer_ids(log_dir: pathlib.Path) -> dict[str, str]:
    """label -> 16-char short peer id."""
    out: dict[str, str] = {}
    p = log_dir / "peer_ids.tsv"
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        if "\t" not in line:
            continue
        label, pid = line.split("\t", 1)
        out[label.strip()] = pid.strip()
    return out


def load_skipped(log_dir: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    p = log_dir / "skipped.txt"
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        if "\t" not in line:
            continue
        label, reason = line.split("\t", 1)
        out[label.strip()] = reason.strip()
    return out


def read_log(path: pathlib.Path) -> list[str]:
    try:
        return path.read_text(errors="replace").splitlines()
    except OSError:
        return []


def build_connectivity(
    log_dir: pathlib.Path, labels: list[str], peer_ids: dict[str, str]
) -> dict[tuple[str, str], str]:
    """(sender_label, recipient_label) -> connection_type or '' if no event."""
    by_short = {pid: lab for lab, pid in peer_ids.items()}
    matrix: dict[tuple[str, str], str] = {}
    for sender in labels:
        f = log_dir / f"c1_{sender}.log"
        if not f.exists():
            continue
        for line in read_log(f):
            m = RE_PEER_CONNECTED.search(line)
            if not m:
                continue
            recipient_short, ctype = m.group(1), m.group(2)
            recipient_label = by_short.get(recipient_short)
            if recipient_label is None:
                continue
            # Last writer wins — connection_type may upgrade as path improves.
            matrix[(sender, recipient_label)] = ctype
    return matrix


def build_path_types(
    log_dir: pathlib.Path, labels: list[str], peer_ids: dict[str, str]
) -> dict[tuple[str, str], str]:
    by_short = {pid: lab for lab, pid in peer_ids.items()}
    matrix: dict[tuple[str, str], str] = {}
    for sender in labels:
        f = log_dir / f"c1_{sender}.log"
        if not f.exists():
            continue
        for line in read_log(f):
            m = RE_DIRECT_PATH.search(line)
            if not m:
                continue
            recipient_short, status = m.group(1), m.group(2)
            recipient_label = by_short.get(recipient_short)
            if recipient_label is None:
                continue
            matrix[(sender, recipient_label)] = status
    return matrix


def build_transfers(log_dir: pathlib.Path, labels: list[str]) -> dict[tuple[str, str], dict]:
    """Read c3_send_*.log for the sender's send_to_complete event, then
    cross-check the recipient's c1_*.log for a matching sha_match=true.
    """
    out: dict[tuple[str, str], dict] = {}
    for sender in labels:
        for recipient in labels:
            if sender == recipient:
                continue
            sender_log = log_dir / f"c3_send_{sender}_to_{recipient}.log"
            if not sender_log.exists():
                continue
            cell: dict = {"sent_bytes": 0, "throughput_mbps": 0.0, "sha_ok": False}
            for line in read_log(sender_log):
                m = RE_SEND_TO_COMPLETE.search(line)
                if m:
                    cell["sent_bytes"] = int(m.group(2))
                    cell["chunks"] = int(m.group(3))
                    cell["duration_ms"] = int(m.group(4))
                    cell["throughput_mbps"] = float(m.group(5))
                    cell["sha_ok"] = m.group(6) == "true"
            # Cross-check recipient
            recip_log = log_dir / f"c1_{recipient}.log"
            if recip_log.exists():
                received_chunks = 0
                for line in read_log(recip_log):
                    m = RE_DATA_RECEIVED.search(line)
                    if m and m.group(2) == "true":
                        received_chunks += 1
                cell["received_chunks"] = received_chunks
            out[(sender, recipient)] = cell
    return out


def build_streams(log_dir: pathlib.Path, labels: list[str]) -> dict[tuple[str, str], int]:
    out: dict[tuple[str, str], int] = {}
    for sender in labels:
        for recipient in labels:
            if sender == recipient:
                continue
            f = log_dir / f"c4_stream_{sender}_to_{recipient}.log"
            if not f.exists():
                continue
            n = sum(1 for line in read_log(f) if RE_COUNTER_SENT.search(line))
            out[(sender, recipient)] = n
    return out


def build_silent_drops(log_dir: pathlib.Path) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for f in sorted(log_dir.glob("*.log")):
        if f.stem in ("orchestrator", "SUMMARY"):
            continue
        kinds = collections.Counter()
        for line in read_log(f):
            m = RE_SILENT_DROP.search(line)
            if m:
                kinds[m.group(1)] += 1
        if kinds:
            out[f.stem] = dict(kinds)
    return out


def total_send_errors(log_dir: pathlib.Path) -> int:
    n = 0
    for f in sorted(log_dir.glob("*.log")):
        if f.stem in ("orchestrator", "SUMMARY"):
            continue
        for line in read_log(f):
            if RE_SEND_ERROR.search(line):
                n += 1
    return n


def total_stale_reaper(log_dir: pathlib.Path) -> int:
    n = 0
    for f in sorted(log_dir.glob("*.log")):
        if f.stem in ("orchestrator", "SUMMARY"):
            continue
        for line in read_log(f):
            if RE_STALE_REAPER.search(line):
                n += 1
    return n


def find_relay_evidence(log_dir: pathlib.Path, labels: list[str]) -> Optional[dict]:
    """Look across all c1_*.log for relay_traffic warns; return the max
    bytes_forwarded observed plus the node label that emitted it.
    """
    best: Optional[dict] = None
    for label in labels:
        f = log_dir / f"c1_{label}.log"
        if not f.exists():
            continue
        for line in read_log(f):
            m = RE_RELAY_TRAFFIC.search(line)
            if not m:
                continue
            bytes_forwarded = int(m.group(1))
            datagrams = int(m.group(2))
            if best is None or bytes_forwarded > best["bytes_forwarded"]:
                best = {
                    "node": label,
                    "bytes_forwarded": bytes_forwarded,
                    "datagrams": datagrams,
                }
    return best


def matrix_to_md(
    title: str, labels: list[str], get: callable, none_repr: str = "·"
) -> str:
    out = [f"### {title}\n"]
    out.append("| | " + " | ".join(labels) + " |")
    out.append("|---|" + "|".join(["---"] * len(labels)) + "|")
    for s in labels:
        row = [s]
        for r in labels:
            if s == r:
                row.append("—")
            else:
                row.append(get(s, r) or none_repr)
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out) + "\n"


def write_summary(log_dir: pathlib.Path, out_path: pathlib.Path) -> int:
    peer_ids = load_peer_ids(log_dir)
    skipped = load_skipped(log_dir)
    labels = sorted(peer_ids.keys())  # only reachable nodes that produced a peer id

    connectivity = build_connectivity(log_dir, labels, peer_ids)
    path_types = build_path_types(log_dir, labels, peer_ids)
    transfers = build_transfers(log_dir, labels)
    streams = build_streams(log_dir, labels)
    silent_drops = build_silent_drops(log_dir)
    send_err_total = total_send_errors(log_dir)
    stale_total = total_stale_reaper(log_dir)
    relay = find_relay_evidence(log_dir, labels)

    drop_total = sum(sum(v.values()) for v in silent_drops.values())

    expected_pairs = len(labels) * (len(labels) - 1)
    connected_pairs = sum(1 for c in connectivity.values() if c)
    transfer_ok = sum(1 for c in transfers.values() if c.get("sha_ok"))
    transfer_total = sum(1 for c in transfers.values())

    fail = (
        drop_total > 0
        or send_err_total > 0
        or stale_total > 0
        or (expected_pairs > 0 and connected_pairs < expected_pairs)
        or (transfer_total > 0 and transfer_ok < transfer_total)
        or (relay is not None and relay.get("bytes_forwarded", 0) == 0)
    )

    lines: list[str] = []
    lines.append("# Cross-env ant-quic test SUMMARY\n")
    lines.append(f"Run directory: `{log_dir}`")
    lines.append(f"Reachable nodes: **{len(labels)}**")
    if skipped:
        skip_str = ", ".join(f"{k} ({v})" for k, v in skipped.items())
        lines.append(f"Skipped: {skip_str}")
    lines.append("")

    lines.append("## Verdict")
    lines.append(f"- silent_drop: **{drop_total}** (target 0)")
    lines.append(f"- send_error: **{send_err_total}** (target 0)")
    lines.append(f"- stale_reaper: **{stale_total}** (target 0)")
    lines.append(
        f"- mesh formation: **{connected_pairs}/{expected_pairs}** directed pairs connected"
    )
    if transfer_total:
        lines.append(
            f"- pairwise transfer: **{transfer_ok}/{transfer_total}** SHA-verified"
        )
    if relay is not None:
        lines.append(
            f"- forced-relay: bytes_forwarded={relay['bytes_forwarded']:,} via {relay['node']}"
        )
    lines.append("")
    lines.append(f"**Result: {'FAIL' if fail else 'PASS'}**\n")

    lines.append("## Per-node peer identity\n")
    lines.append("| label | peer id (16) |")
    lines.append("|---|---|")
    for lab in labels:
        lines.append(f"| {lab} | `{peer_ids[lab]}` |")
    lines.append("")

    lines.append("## Connectivity matrix (sender → recipient)\n")
    lines.append(matrix_to_md(
        "connection_type",
        labels,
        lambda s, r: connectivity.get((s, r), ""),
    ))

    lines.append("## Path-type matrix (last direct_path_status per pair)\n")
    lines.append(matrix_to_md(
        "direct_path_status",
        labels,
        lambda s, r: path_types.get((s, r), ""),
    ))

    if transfers:
        lines.append("## Transfer matrix (C3 — 64 MiB SHA-verified)\n")

        def cell(s: str, r: str) -> str:
            c = transfers.get((s, r))
            if c is None:
                return ""
            mark = "✓" if c.get("sha_ok") else "✗"
            return f"{mark} {c.get('throughput_mbps', 0):.1f} Mbps"

        lines.append(matrix_to_md("transfer", labels, cell))

    if streams:
        lines.append("## Stream matrix (C4 — counter_sent per pair)\n")
        lines.append(matrix_to_md(
            "counters",
            labels,
            lambda s, r: str(streams.get((s, r), "")) if (s, r) in streams else "",
        ))

    if relay is not None:
        lines.append("## Forced-relay evidence (C5)\n")
        lines.append(f"- relay node: **{relay['node']}**")
        lines.append(f"- bytes forwarded: **{relay['bytes_forwarded']:,}**")
        lines.append(f"- datagrams: {relay['datagrams']:,}")
        lines.append("")

    if silent_drops:
        lines.append("## Silent drops by kind\n")
        lines.append("| node | kind | count |")
        lines.append("|---|---|---|")
        for node in sorted(silent_drops):
            for kind, n in sorted(silent_drops[node].items(), key=lambda kv: -kv[1]):
                lines.append(f"| {node} | `{kind}` | {n} |")
        lines.append("")

    out_path.write_text("\n".join(lines))
    print(f"wrote {out_path}")
    return 1 if fail else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log_dir", type=pathlib.Path)
    ap.add_argument("--output", type=pathlib.Path, default=None)
    args = ap.parse_args()
    log_dir = args.log_dir.resolve()
    if not log_dir.is_dir():
        print(f"error: {log_dir} is not a directory", file=sys.stderr)
        return 2
    out = args.output or (log_dir / "SUMMARY.md")
    return write_summary(log_dir, out)


if __name__ == "__main__":
    sys.exit(main())
