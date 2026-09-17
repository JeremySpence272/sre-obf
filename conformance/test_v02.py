import unittest
import random
import io
import tempfile
import zipfile
from pathlib import Path
from conformance.fetch_scale import extract
from conformance.recovery_reach import check_expression, validate
from conformance.connected_model import compare, add
from conformance.whole import parser


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
