"""Pure fixtures exercise the adapter and the actual existing comparison script."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import criterion_report as report


REPO = Path(__file__).resolve().parents[2]
HELPER = Path(__file__).with_name("criterion_report.py")
COMPARATOR = REPO / ".github/scripts/compare-benchmarks.py"


def fixture(root, mean=100):
    for label, identities in report.EXPECTED_IDS.items():
        for identity in identities:
            group = identity.split("/", 1)[0]
            snapshot = root / identity / label
            snapshot.mkdir(parents=True)
            (snapshot / "benchmark.json").write_text(json.dumps({
                "group_id": group, "full_id": identity,
                "directory_name": identity,
            }))
            (snapshot / "estimates.json").write_text(json.dumps({
                "mean": {"point_estimate": mean}, "median": {"point_estimate": mean},
            }))
            (snapshot / "sample.json").write_text(json.dumps({
                "iters": [1, 2], "times": [mean, mean * 2],
            }))


class CriterionReportTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.current = self.root / "current"
        self.download = self.root / "download"
        self.artifact = self.download / "benchmark-results-baseline"
        self.artifact.mkdir(parents=True)
        (self.artifact / "benchmark-results.json").write_text('{"results": []}\n')

    def compare(self):
        return subprocess.run([
            sys.executable, str(HELPER), "compare", "--root", str(self.current),
            "--baseline-download", str(self.download), "--comparator", str(COMPARATOR),
        ], capture_output=True, text=True)

    def test_actual_comparator_stable_and_regression(self):
        fixture(self.artifact)
        for mean, regression in ((100, False), (120, True)):
            with self.subTest(mean=mean):
                if self.current.exists():
                    shutil.rmtree(self.current)
                fixture(self.current, mean)
                result = self.compare()
                self.assertEqual(result.returncode, 0, result.stderr)
                output = (self.current / "comparison-report.md").read_text()
                self.assertEqual("REGRESSION" in output, regression)
                self.assertIn("| candidate_discovery/1 |", output)

    def test_legacy_raw_artifact_migrates_empty_aggregate(self):
        fixture(self.artifact / "target/criterion")
        fixture(self.current, 120)
        result = self.compare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REGRESSION", (self.current / "comparison-report.md").read_text())

    def test_empty_legacy_aggregate_is_not_comparison(self):
        fixture(self.current)
        result = self.compare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Comparison unavailable", (self.current / "comparison-report.md").read_text())

    def test_missing_or_multiple_baseline_artifacts_fail(self):
        fixture(self.current)
        (self.artifact / "benchmark-results.json").unlink()
        self.assertNotEqual(self.compare().returncode, 0)
        (self.artifact / "benchmark-results.json").write_text("{}")
        other = self.download / "other"
        other.mkdir()
        (other / "benchmark-results.json").write_text("{}")
        self.assertNotEqual(self.compare().returncode, 0)

    def test_partial_identity_set_fails(self):
        fixture(self.artifact)
        fixture(self.current)
        original = self.current / "candidate_discovery/1/current-nat"
        extra = self.current / "candidate_discovery/extra/current-nat"
        shutil.copytree(original, extra)
        data = json.loads((extra / "benchmark.json").read_text())
        data.update(full_id="candidate_discovery/extra", directory_name="candidate_discovery/extra")
        (extra / "benchmark.json").write_text(json.dumps(data))
        self.assertNotEqual(self.compare().returncode, 0)

    def test_same_missing_case_on_both_sides_fails_before_comparator(self):
        fixture(self.artifact)
        fixture(self.current)
        for root in (self.artifact, self.current):
            shutil.rmtree(root / "candidate_discovery/1/current-nat")
            self.assertTrue((root / "candidate_discovery/5/current-nat").is_dir())
        args = SimpleNamespace(
            baseline_download=self.download, root=self.current, comparator=COMPARATOR,
            report=self.current / "comparison-report.md",
        )
        with mock.patch.object(report.subprocess, "run") as comparator:
            with self.assertRaisesRegex(ValueError, "incomplete benchmark identities"):
                report.compare(args)
            comparator.assert_not_called()
        self.assertIn("Comparison unavailable", args.report.read_text())

    def test_substituted_identity_with_same_count_is_rejected(self):
        fixture(self.current)
        metadata = self.current / "candidate_discovery/1/current-nat/benchmark.json"
        data = json.loads(metadata.read_text())
        data["full_id"] = "candidate_discovery/substituted"
        metadata.write_text(json.dumps(data))
        self.assertEqual(len(list(self.current.glob("**/benchmark.json"))), 54)
        with self.assertRaisesRegex(ValueError, "unexpected=.*substituted"):
            report.convert(self.current)

    def test_missing_group_and_sample_rejected(self):
        fixture(self.current)
        sample = self.current / "candidate_discovery/1/current-nat/sample.json"
        sample.unlink()
        with self.assertRaises(FileNotFoundError):
            report.convert(self.current)
        shutil.rmtree(self.current / "candidate_discovery")
        with self.assertRaisesRegex(ValueError, "missing groups"):
            report.convert(self.current)

    def test_duplicate_id_rejected(self):
        fixture(self.current)
        original = self.current / "candidate_discovery/1/current-nat"
        extra = self.current / "candidate_discovery/extra/current-nat"
        shutil.copytree(original, extra)
        data = json.loads((extra / "benchmark.json").read_text())
        data["directory_name"] = "candidate_discovery/extra"
        (extra / "benchmark.json").write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            report.convert(self.current)

    def test_invalid_estimates_rejected(self):
        fixture(self.current)
        estimates = self.current / "candidate_discovery/1/current-nat/estimates.json"
        for value in (0, -1, True, "100", float("nan"), float("inf")):
            with self.subTest(value=value):
                estimates.write_text(json.dumps({"mean": {"point_estimate": value}}))
                with self.assertRaisesRegex(ValueError, "invalid timing"):
                    report.convert(self.current)

    def test_invalid_samples_rejected(self):
        fixture(self.current)
        sample = self.current / "candidate_discovery/1/current-nat/sample.json"
        for iterations, times in (([], []), ([1], [1, 2]), ([1], [0]), ([True], [2])):
            with self.subTest(iterations=iterations, times=times):
                sample.write_text(json.dumps({"iters": iterations, "times": times}))
                with self.assertRaisesRegex(ValueError, "measurement samples"):
                    report.convert(self.current)

    def test_cached_output_is_excluded_from_fresh_root(self):
        stale = self.root / "target/criterion/candidate_discovery/1/current-nat"
        stale.mkdir(parents=True)
        fixture(self.current)
        self.assertEqual(len(report.convert(self.current)), 54)
        self.assertEqual(list(stale.iterdir()), [])

    def test_comparator_failure_is_not_masked(self):
        fixture(self.artifact)
        fixture(self.current)
        result = subprocess.run([
            sys.executable, str(HELPER), "compare", "--root", str(self.current),
            "--baseline-download", str(self.download), "--comparator", str(self.root / "missing.py"),
        ], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Comparison unavailable", (self.current / "comparison-report.md").read_text())

    def test_collect_outputs_actual_comparator_schema(self):
        fixture(self.current)
        result = subprocess.run([sys.executable, str(HELPER), "collect", "--root", str(self.current)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in (self.current / "benchmark-results.json").read_text().splitlines()]
        self.assertEqual(len(records), 54)
        self.assertTrue(all(row["type"] == "benchmark-complete" for row in records))


if __name__ == "__main__":
    unittest.main()
