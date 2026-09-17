import unittest
import random
import io
import tempfile
import zipfile
from pathlib import Path
from conformance.fetch_scale import extract
from conformance.recovery_reach import check_expression, validate
from conformance.connected_model import compare, add, xor_to_additive, additive_to_xor
from conformance.whole import parser
from conformance.scale import coverage, coverage_passes


class ReplayTests(unittest.TestCase):
    def test_closed_expression_language(self):
        check_expression({"op": "arg", "width": 8, "index": 0})
        for bad in ({"op": "eval", "width": 8}, {"op": "arg", "width": 128, "index": 0},
                    {"op": "arg", "width": 8, "index": 7}):
            with self.assertRaises(ValueError):
                check_expression(bad)

    def test_model_caps_and_split_byte_guard(self):
        spec = {"schema": "sre-symbolic-reach-v1", "abi": "buffer-length", "input_bytes": 8,
                "success": [123], "split_selects": []}
        validate(spec)
        with self.assertRaises(ValueError):
            validate({**spec, "input_bytes": 257})
        with self.assertRaises(ValueError):
            validate({**spec, "split_selects": [{"condition": "eq"}]})


class ConnectedTests(unittest.TestCase):
    def test_direct_cross_family_conversions(self):
        rng = random.Random(6204)
        for width in (1, 4, 8, 16, 32, 64):
            mask = (1 << width) - 1
            for _ in range(3000):
                value, share, refresh, a, r = [rng.getrandbits(width) for _ in range(5)]
                additive = xor_to_additive((value ^ share, share), refresh, width)
                self.assertEqual((additive[0] - additive[1]) & mask, value)
                pair = additive_to_xor(additive, a, r, width)
                self.assertEqual(pair[0] ^ pair[1], value)
    def test_shared_add_sub(self):
        rng = random.Random(6203)
        for width in (1, 4, 8, 16, 32, 64):
            mask = (1 << width) - 1
            for _ in range(3000):
                x, y, r, s = [rng.getrandbits(width) for _ in range(4)]
                for subtract in (False, True):
                    ye = y ^ s ^ (mask if subtract else 0)
                    e, m = add((x ^ r, r), (ye, s), width, subtract)
                    self.assertEqual(e ^ m, (x - y if subtract else x + y) & mask)

    def test_predicate_transfers(self):
        rng = random.Random(6202)
        for width in (1, 4, 8, 16, 32, 64):
            mask, sign = (1 << width) - 1, 1 << (width-1)
            pairs = [(x, y) for x in (0, 1, sign-1, sign, mask) for y in (0, 1, sign-1, sign, mask)]
            pairs += [(rng.getrandbits(width), rng.getrandbits(width)) for _ in range(2000)]
            for x, y in pairs:
                rx, ry = rng.getrandbits(width), rng.getrandbits(width)
                for signed, equality in ((False, False), (True, False), (False, True)):
                    result = compare((x ^ rx, rx), (y ^ ry, ry), width, signed, equality)
                    sx, sy = (x ^ sign) - sign, (y ^ sign) - sign
                    expected = x == y if equality else sx < sy if signed else x < y
                    self.assertEqual(result[0] ^ result[1], expected)

    def test_v02_is_opt_in(self):
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created"])
        self.assertEqual(args.region_plan, "legacy")
        self.assertFalse(any((args.memory_ssa, args.predicate_regions, args.regional_families, args.support_regions)))
        self.assertFalse(args.scale_budget)
        self.assertEqual(args.module_insts, 250000)


class ScaleSourceTests(unittest.TestCase):
    def test_required_coverage_is_not_selection_or_eligibility(self):
        measured = {"functions_with_surviving_flattening": 0, "memory_edges": 0,
                    "eligible_closed_memory_edges": 300}
        self.assertTrue(coverage_passes(measured))
        self.assertFalse(coverage_passes(measured, require_flattening=True))
        self.assertFalse(coverage_passes(measured, require_memory=True))
        self.assertTrue(coverage_passes({**measured, "memory_edges": 1}, require_memory=True))

    def test_old_report_missing_memory_denominator_is_unknown(self):
        report = {"schema": "sre-native-v1", "input_inventory": {
            "definitions": 0, "instructions": 0, "functions": []},
            "connected_regions": [], "flattening_state": [],
            "final_inventory": {"instructions": 0, "helper_instructions": 0}}
        self.assertIsNone(coverage(report)["eligible_closed_memory_edges"])
        report["schema"] = "sre-native-v2"
        self.assertEqual(coverage(report)["eligible_closed_memory_edges"], 0)

    def test_structural_budget_is_independent_opt_in(self):
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created"])
        self.assertFalse(args.scale_structure)
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created", "--scale-budget"])
        self.assertTrue(args.scale_budget)
        self.assertFalse(args.scale_structure)

    def test_reject_archive_escape(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("../escape.c", "not extracted")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                extract(data.getvalue(), Path(directory) / "src", True)
            self.assertFalse((Path(directory) / "escape.c").exists())

    def test_reject_archive_symlink(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            entry = zipfile.ZipInfo("link")
            entry.external_attr = 0o120777 << 16
            archive.writestr(entry, "/tmp")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                extract(data.getvalue(), Path(directory) / "src", True)


if __name__ == "__main__":
    unittest.main()
