import json
from pathlib import Path
import sys
import tempfile
import unittest

from conformance.metrics import CANARY, contains_integer, flattening_ran, normalize_c
from conformance.process import Runner, ToolFailure
from conformance.run import target_offset, test_inputs
from conformance.cc import backend_flags, compile_args


class MetricsTests(unittest.TestCase):
    def test_constant_spellings(self):
        for text in ("0x13579bdfU", "324508639", "0x0000000013579bdf"):
            self.assertTrue(contains_integer(text, CANARY))
        self.assertTrue(contains_integer("-1", 0xffffffff))
        self.assertFalse(contains_integer("local_324508639", CANARY))
        self.assertFalse(contains_integer("324508639.0", CANARY))

    def test_normalization_preserves_load_bearing_details(self):
        self.assertEqual(normalize_c("uVar1 = local_8 + 3;"),
                         normalize_c("uVar27 = local_44 + 3;"))
        self.assertNotEqual(normalize_c("uVar1 = local_8 + 3;"),
                            normalize_c("uVar1 = local_8 + 4;"))
        self.assertNotEqual(normalize_c("(int)x < 1"), normalize_c("(uint)x < 1"))

    def test_skipped_or_unchanged_is_not_flattening(self):
        for status, changed, expected in (
            ("ran", True, True), ("skipped", True, False), ("ran", False, False)):
            report = {"functions": [{"passes": [
                {"id": "flattening", "status": status, "changed": changed}]}]}
            self.assertEqual(flattening_ran(report), expected)
            self.assertFalse(flattening_ran(report, "obf_target"))

    def test_vectors_include_edges_and_are_reproducible(self):
        values = test_inputs(12)
        self.assertEqual(values, test_inputs(12))
        self.assertEqual(len(values.splitlines()), 93)
        self.assertIn(b"4294967295 2147483648\n", values)

    def test_map_requires_exact_symbol(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "map"
            path.write_text(" 0x0000000000001140 obf_target\n")
            self.assertEqual(target_offset(path), 0x1140)
            path.write_text(" 0x1140 not_obf_target\n")
            with self.assertRaises(ToolFailure):
                target_offset(path)


class ProcessTests(unittest.TestCase):
    def test_timeout_and_failure_are_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = Runner(root, root / "logs", timeout=0.1)
            with self.assertRaises(ToolFailure):
                runner.run([sys.executable, "-c", "import time; time.sleep(10)"])
            self.assertEqual(runner.records[-1]["status"], "timeout")
            with self.assertRaises(ToolFailure):
                runner.run([sys.executable, "-c", "raise SystemExit(3)"])
            self.assertEqual(runner.records[-1]["status"], "tool_error")
            self.assertEqual(len(json.loads((root / "logs/commands.json").read_text())), 2)


class AdapterTests(unittest.TestCase):
    def test_compile_order_and_backend_flags(self):
        source, output, flags = compile_args(
            ["-std=c11", "-O2", "-fPIE", "-I", "/tmp/include", "-c", "a.c", "-o", "a.o"])
        self.assertEqual(source.name, "a.c")
        self.assertEqual(output.name, "a.o")
        self.assertIn("-O2", flags)
        self.assertNotIn("-O2", backend_flags(flags))
        self.assertEqual(backend_flags(flags), ["-fPIE"])

    def test_unsupported_modes_fail_closed(self):
        for extra in ("-O3", "-flto", "-fpass-plugin=other.so", "-Xclang"):
            with self.assertRaises(ValueError):
                compile_args(["-c", "a.c", "-o", "a.o", extra])


if __name__ == "__main__":
    unittest.main()
