#!/usr/bin/env python3
"""Validate selected Criterion samples and adapt them to the existing comparator."""

import argparse
import json
import math
from pathlib import Path
import subprocess
import sys


GROUPS = {
    "current-nat": {
        "candidate_discovery", "hole_punching", "candidate_prioritization",
        "nat_type_detection", "relay_fallback", "address_mapping",
    },
    "current-conn": {
        "connection_tracking", "event_processing", "resource_cleanup",
        "concurrent_access",
    },
}

# Full selected workload at the pinned benchmark definitions. Keep this contract
# in sync when those definitions intentionally change; group presence is insufficient.
# nat_traversal_performance.rs:16,54,95,135,168,209 (23 IDs).
# connection_management.rs:123,270,375,467 (31 IDs).
EXPECTED_IDS = {
    "current-nat": (
        {f"candidate_discovery/{n}" for n in (1, 5, 10, 20)}
        | {f"hole_punching/{n}" for n in (1, 5, 10, 25)}
        | {f"candidate_prioritization/{n}" for n in (10, 50, 100, 500)}
        | {"nat_type_detection/detect_nat_type"}
        | {f"relay_fallback/{n}" for n in (1, 3, 5, 10)}
        | {f"address_mapping/{operation}/{n}"
           for operation in ("insert", "lookup") for n in (100, 1000, 10000)}
    ),
    "current-conn": (
        {f"connection_tracking/{operation}/{n}"
         for operation in ("add_connections", "lookup_connections", "remove_connections", "update_connections")
         for n in (10, 100, 1000, 5000)}
        | {f"event_processing/{operation}/{n}"
           for operation in ("queue_events", "process_events") for n in (10, 100, 1000, 10000)}
        | {f"resource_cleanup/cleanup_inactive/{n}" for n in (100, 1000, 5000)}
        | {f"concurrent_access/{operation}/{n}"
           for operation in ("read_heavy_workload", "write_heavy_workload") for n in (100, 1000)}
    ),
}


def load_json(path):
    return json.loads(path.read_text())


def positive_number(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def convert(root):
    """Read named snapshots only; never use cached base/new/report estimates."""
    records = {}
    for label, required_groups in GROUPS.items():
        observed_groups = set()
        observed_ids = set()
        for snapshot in sorted(root.glob(f"**/{label}")):
            if not snapshot.is_dir():
                raise ValueError(f"not a snapshot directory: {snapshot}")
            benchmark = load_json(snapshot / "benchmark.json")
            estimates = load_json(snapshot / "estimates.json")
            sample = load_json(snapshot / "sample.json")
            group = benchmark["group_id"]
            identity = benchmark["full_id"]
            if group not in required_groups or not isinstance(identity, str):
                raise ValueError("unexpected benchmark group or identity")
            relative = snapshot.parent.relative_to(root).as_posix()
            if benchmark["directory_name"] != relative:
                raise ValueError("benchmark directory does not match its metadata")
            if identity in records:
                raise ValueError("duplicate benchmark identity")
            for statistic in ("mean", "median"):
                if not positive_number(estimates[statistic]["point_estimate"]):
                    raise ValueError("invalid timing estimate")
            iterations, times = sample["iters"], sample["times"]
            if (not isinstance(iterations, list) or not isinstance(times, list)
                    or not iterations or len(iterations) != len(times)
                    or not all(positive_number(x) for x in iterations + times)):
                raise ValueError("missing or invalid measurement samples")
            records[identity] = {
                "type": "benchmark-complete", "id": identity,
                "mean": estimates["mean"], "median": estimates["median"],
            }
            observed_groups.add(group)
            observed_ids.add(identity)
        if observed_groups != required_groups:
            raise ValueError(f"missing groups for {label}: {sorted(required_groups - observed_groups)}")
        if observed_ids != EXPECTED_IDS[label]:
            raise ValueError(
                f"incomplete benchmark identities for {label}: "
                f"missing={sorted(EXPECTED_IDS[label] - observed_ids)}, "
                f"unexpected={sorted(observed_ids - EXPECTED_IDS[label])}"
            )
    return [records[key] for key in sorted(records)]


def write_records(path, records):
    path.write_text("".join(json.dumps(record, allow_nan=False) + "\n" for record in records))


def baseline_root(download):
    artifacts = list(download.glob("*/benchmark-results.json"))
    if len(artifacts) != 1:
        raise ValueError("expected exactly one downloaded baseline artifact")
    artifact = artifacts[0].parent
    # Older workflows archived the real samples even though their summary was empty.
    legacy = artifact / "target" / "criterion"
    return legacy if legacy.is_dir() else artifact


def compare(args):
    try:
        baseline = convert(baseline_root(args.baseline_download))
        current = convert(args.root)
        # Refuse partial or unrelated data instead of silently calling it a comparison.
        if {row["id"] for row in baseline} != {row["id"] for row in current}:
            raise ValueError("baseline and current benchmark identities differ")
        baseline_file = args.root / "baseline-results.json"
        current_file = args.root / "benchmark-results.json"
        write_records(baseline_file, baseline)
        write_records(current_file, current)
        result = subprocess.run(
            [sys.executable, str(args.comparator), str(baseline_file), str(current_file)],
            capture_output=True, text=True, check=True,
        )
        args.report.write_text(result.stdout)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        args.report.write_text(f"### Comparison unavailable\n\n{error}\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("collect", "compare"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--baseline-download", type=Path)
    parser.add_argument("--comparator", type=Path)
    args = parser.parse_args()
    args.report = args.root / "comparison-report.md"
    try:
        if args.command == "collect":
            records = convert(args.root)
            write_records(args.root / "benchmark-results.json", records)
            (args.root / "benchmark-report.md").write_text(
                f"# Benchmark Results\n\nValidated {len(records)} measured benchmarks.\n"
            )
        else:
            if args.baseline_download is None or args.comparator is None:
                parser.error("compare requires --baseline-download and --comparator")
            compare(args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"benchmark report failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
