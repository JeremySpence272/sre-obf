import copy
import math
from pathlib import Path
import sys
import tempfile
import unittest

from integrations.revgame.benchmark import replay
from integrations.revgame.performance import SCHEMA, evaluate, evaluate_matrix


def block(n=31, clean=0.1, native=0.5):
    report = {"schema": SCHEMA, "measurement_status": "complete", "block_id": "one",
              "artifacts_unchanged": True, "requested_samples": n,
              "binaries": {"clean": {"sha256": "a" * 64}, "native": {"sha256": "b" * 64}},
              "reference_sha256": "c" * 64, "workload_id": "reference",
              "compiler_seed": "1", "minimum_clean_seconds": 0.00001, "samples": []}
    for index in range(-1, n):
        arms = ("native", "clean") if index > 0 and index % 2 else ("clean", "native")
        for arm in arms:
            seconds = clean if arm == "clean" else native
            report["samples"].append({"arm": arm, "index": index, "warmup": index == -1,
                "binary_sha256": report["binaries"][arm]["sha256"], "reference_sha256": "c" * 64,
                "status": "ok", "correct": True, "exit_code": 0, "turns": 12,
                "output_sha256": "d" * 64, "replay_seconds": seconds,
                "full_process_seconds": seconds + 0.01, "cpu_seconds": seconds / 2})
    return report


class PerformanceGate(unittest.TestCase):
    def test_boundaries_and_absolute_target(self):
        for native, status in ((1.999, "pass"), (2.0, "failed"), (2.001, "failed")):
            with self.subTest(native=native):
                result = evaluate(block(native=native))
                self.assertEqual(result["status"], status)
                self.assertFalse(result["target_met"])
        self.assertTrue(evaluate(block(native=0.999))["target_met"])
        self.assertFalse(evaluate(block(native=1.0))["target_met"])

    def test_tail_cannot_hide_behind_median(self):
        report = block()
        for row in report["samples"]:
            if row["arm"] == "native" and row["index"] in (29, 30):
                row.update(replay_seconds=2.0, full_process_seconds=2.01)
        result = evaluate(report)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["metrics"]["ratio_of_medians"], 5)
        self.assertEqual(result["metrics"]["paired_ratio_p95"], 20)

    def test_one_tail_outlier_is_above_empirical_p95(self):
        report = block()
        row = next(r for r in report["samples"] if r["arm"] == "native" and r["index"] == 30)
        row.update(replay_seconds=3, full_process_seconds=3.01)
        result = evaluate(report)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["metrics"]["protected_max_seconds"], 3)

    def test_warmups_excluded_but_failure_is_not(self):
        report = block()
        report["samples"][1].update(replay_seconds=100, full_process_seconds=101)
        self.assertEqual(evaluate(report)["metrics"]["ratio_of_medians"], 5)
        report["samples"][1]["correct"] = False
        self.assertEqual(evaluate(report)["status"], "failed")

    def test_invalid_samples_fail_closed(self):
        changes = [("replay_seconds", x) for x in (0, -1, math.nan, math.inf, True, 10**500)] + [
            ("full_process_seconds", 0.001), ("cpu_seconds", -1),
            ("binary_sha256", "e" * 64), ("reference_sha256", "e" * 64),
            ("warmup", True), ("status", "timeout"), ("correct", False),
            ("exit_code", True), ("turns", 13), ("output_sha256", None)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                report = block()
                report["samples"][2][key] = value
                self.assertEqual(evaluate(report)["status"], "failed")
        for change in (lambda r: r["samples"].pop(),
                       lambda r: r["samples"].append(copy.deepcopy(r["samples"][-1])),
                       lambda r: r["samples"].reverse(),
                       lambda r: r.update(measurement_status="running"),
                       lambda r: r.update(artifacts_unchanged=False),
                       lambda r: r.update(compiler_seed=None),
                       lambda r: r.update(schema="unknown")):
            report = block()
            change(report)
            self.assertEqual(evaluate(report)["status"], "failed")

    def test_smoke_and_clock_floor_are_never_acceptance(self):
        self.assertEqual(evaluate(block(n=3))["status"], "smoke_only")
        self.assertEqual(evaluate(block(clean=1e-6, native=5e-6))["status"], "inconclusive")

    def test_matrix_requires_every_confirmation_and_workload(self):
        one = block()
        two = copy.deepcopy(one)
        two["block_id"] = "two"
        cells = [("1", "reference", "c" * 64)]
        self.assertEqual(evaluate_matrix([one, two], cells)["status"], "pass")
        self.assertEqual(evaluate_matrix([one], cells)["status"], "failed")
        self.assertEqual(evaluate_matrix([one, one], cells)["status"], "failed")
        changed = copy.deepcopy(two)
        changed["binaries"]["native"]["sha256"] = "e" * 64
        for row in changed["samples"]:
            if row["arm"] == "native":
                row["binary_sha256"] = "e" * 64
        self.assertEqual(evaluate(changed)["status"], "pass")
        self.assertEqual(evaluate_matrix([one, changed], cells)["status"], "failed")
        extra = copy.deepcopy(two)
        extra.update(block_id="third", workload_id="operation-heavy")
        cells.append(("1", "operation-heavy", "c" * 64))
        self.assertEqual(evaluate_matrix([one, two], cells)["status"], "failed")
        for row in extra["samples"]:
            if row["arm"] == "native":
                row.update(replay_seconds=2, full_process_seconds=2.1)
        fourth = copy.deepcopy(extra)
        fourth["block_id"] = "fourth"
        self.assertEqual(evaluate_matrix([one, two, extra, fourth], cells)["status"], "failed")


class ActualTiming(unittest.TestCase):
    def fixture(self, root, body):
        binary = root / "fixture"
        binary.write_text(f"#!{sys.executable}\nimport os, time\n" + body)
        binary.chmod(0o755)
        return binary

    def test_startup_counted_and_exit_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture(root,
                "time.sleep(0.06)\nprint('Replay complete: 12 turns consumed', flush=True)\n"
                "print('Press Enter to enter the TUI...', flush=True)\n"
                "os.read(0, 1)\ntime.sleep(0.06)\n")
            result = replay(binary, root / "unused.json", root / "log", 3)
            self.assertGreaterEqual(result["replay_seconds"], 0.06)
            self.assertGreaterEqual(result["full_process_seconds"] - result["replay_seconds"], 0.05)
            self.assertGreater(result["peak_rss_kib"], 0)
            self.assertEqual(result["turns"], 12)

    def test_timeout_preserves_log_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture(root, "print(os.getpid(), flush=True)\ntime.sleep(10)\n")
            with self.assertRaises(TimeoutError):
                replay(binary, root / "unused.json", root / "log", 0.1)
            pid = int((root / "log").read_text().strip())
            import os
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
