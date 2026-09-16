import json
from pathlib import Path
import sys
import tempfile
import unittest
import random

from conformance.metrics import CANARY, contains_integer, flattening_ran, normalize_c
from conformance.process import Runner, ToolFailure
from conformance.run import target_offset, test_inputs
from conformance.cc import backend_flags, compile_args
from conformance.compare import compare
from conformance.state_model import encode, recover, advance
from conformance.run import parser, feature_flags
from conformance.value_model import encode as encode_value, recover as recover_value, transfer


class ValueTests(unittest.TestCase):
    def test_coupled_data_control_rounds_preserve_both_relations(self):
        rng = random.Random(75)
        for width in (8, 16, 32, 64):
            modulus = 1 << width
            a, b = rng.getrandbits(width) | 1, rng.getrandbits(width) | 1
            for family in range(3):
                token, key, salt, context = 7, 11, 17, 23
                for _ in range(100):
                    x, y, rx, ry = (rng.getrandbits(width) for _ in range(4))
                    mask = (context ^ x ^ ry) % modulus
                    ex, ey = encode_value(x, rx, a, b, width), encode_value(y, ry, a, b, width)
                    value = transfer("mul", ex, rx, ey, ry, mask, a, b, width)
                    self.assertEqual(recover_value(value, mask, a, b, width), x * y % modulus)
                    context = (value ^ mask) & 0xffffffff
                    key, salt = advance(token, key, salt, 31, 53, context)
                    token = encode(101, key, salt, family)
                    self.assertEqual(recover(token, key, salt, family), 101)
                    context = token ^ salt

    def test_transfer_functions_and_recovery_at_all_supported_widths(self):
        rng = random.Random(1945)
        for width in (8, 16, 32, 64):
            mask = (1 << width) - 1
            edges = (0, 1, mask >> 1, 1 << (width - 1), mask)
            pairs = [(x, y) for x in edges for y in edges]
            pairs += [(rng.getrandbits(width), rng.getrandbits(width)) for _ in range(2000)]
            for x, y in pairs:
                a, b = rng.getrandbits(width) | 1, rng.getrandbits(width) | 1
                rx, ry, out = (rng.getrandbits(width) for _ in range(3))
                ex, ey = encode_value(x, rx, a, b, width), encode_value(y, ry, a, b, width)
                shift = rng.randrange(width)
                for op, plain in (("add", x + y), ("sub", x - y),
                                  ("mul", x * y), ("shl", x << shift)):
                    result = transfer(op, ex, rx, ey, ry, out, a, b, width, shift)
                    self.assertEqual(result, encode_value(plain, out, a, b, width))
                    self.assertEqual(recover_value(result, out, a, b, width), plain & mask)

    def test_value_and_outline_flags_are_independent(self):
        args = parser().parse_args(["--out", "/tmp/not-created", "--values"])
        self.assertIn("-native-values=1", feature_flags(args))
        self.assertIn("-native-outline=0", feature_flags(args))
        self.assertIn("-native-coupled-state=0", feature_flags(args))


class StateTests(unittest.TestCase):
    def test_every_family_is_invertible_at_wrap_edges_and_random_states(self):
        edges = (0, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff)
        rng = random.Random(712)
        cases = [(v, k, s) for v in edges for k in edges for s in edges]
        cases += [tuple(rng.getrandbits(32) for _ in range(3)) for _ in range(10000)]
        for family in range(3):
            for v, k, s in cases:
                self.assertEqual(recover(encode(v, k, s, family), k, s, family), v)

    def test_label_relation_survives_history_dependent_back_edges(self):
        for family in range(3):
            t, k, s = 5, 7, 0xffffffff
            tokens = set()
            for _ in range(100):
                k, s = advance(t, k, s, 0x12345678, 0xabcdef12)
                t = encode(42, k, s, family)
                tokens.add(t)
                self.assertEqual(recover(t, k, s, family), 42)
                self.assertNotEqual(t, encode(43, k, s, family))
            self.assertGreater(len(tokens), 90)

    def test_state_ablation_is_explicit(self):
        args = parser().parse_args(["--out", "/tmp/not-created", "--no-multistate",
                                   "--state-family", "2", "--post-o2-attack", "--threads"])
        self.assertIn("-native-multistate=0", feature_flags(args))
        self.assertIn("-native-state-family=2", feature_flags(args))
        self.assertTrue(args.post_o2_attack)
        self.assertTrue(args.threads)


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


class ComparisonTests(unittest.TestCase):
    def test_driver_changes_are_not_matched_ablations(self):
        case = {"case": "state", "seed": 1, "correctness": True,
                "source_sha256": "same", "driver_sha256": "serial"}
        other = {**case, "driver_sha256": "threaded"}
        self.assertEqual(compare({"cases": [case]}, {"cases": [other]})[0]["status"],
                         "different_or_unknown_driver")

    def test_missing_and_failed_are_not_reproducible(self):
        case = {"case": "literal", "seed": 1, "correctness": False}
        self.assertEqual(compare({"cases": [case]}, {"cases": []})[0]["status"],
                         "missing_case")
        self.assertEqual(compare({"cases": [case]}, {"cases": [case]})[0]["status"],
                         "invalid_correctness")

    def test_identical_bytes_do_not_imply_decompiler_was_measured(self):
        case = {"case": "literal", "seed": 1, "correctness": True,
                "source_sha256": "source", "protected_ir_sha256": "ir",
                "arms": {"native": {"binary_sha256": "binary", "binary_bytes": 123}}}
        row = compare({"cases": [case]}, {"cases": [case]})[0]
        self.assertTrue(row["binary_equal"])
        self.assertIsNone(row["decompiled_c_equal"])


if __name__ == "__main__":
    unittest.main()
