import argparse
import copy
import unittest

from conformance import bundle_options
from conformance.immutable_check import immutable_violations
from conformance.immutable_run import backing_values, fixture, oracle


def report():
    return {"features": {"data": True, "bundles": True, "immutable_bundles": True},
        "data": [{"object": "table", "status": "encoded", "reason": "", "contract": "sre-immutable-tile-v1",
            "read_sites": 1, "growth_available": 1000, "growth_estimate": 192, "growth_retained": 65,
            "growth_attempted": 65, "pins": True, "family": "triangular-xor-v1", "width": 8,
            "cells": 3, "bytes": 3, "tile_cells": 4, "physical_reads_per_site": 4,
            "tail": "duplicate-last-valid-coordinate", "storage": "immutable-closed-initialized-array",
            "salts_hex": ["1", "3", "5", "7"], "rotations": [1, 2, 3, 4],
            "carrier_base_hex": "29", "carrier_step_hex": "31"}],
        "immutable_continuity": [{"schema": "sre-immutable-continuity-v1", "object": "table", "site": 0,
            "reader_at_encoding": "f", "current_reader": "f", "original_scalar_uses": 3,
            "remaining_scalar_uses": 1, "eliminated_scalar_uses": 2, "added_scalar_uses": 0,
            "scope": "after-bundles-before-legacy-lowering", "hardness_evaluated": False}]}


class ImmutableReports(unittest.TestCase):
    def test_exact_and_partial_crossings(self):
        data = report()
        self.assertEqual(immutable_violations(data), [])
        row = data["immutable_continuity"][0]
        row.update(remaining_scalar_uses=0, eliminated_scalar_uses=3)
        self.assertEqual(immutable_violations(data), [])
        row.update(remaining_scalar_uses=4, eliminated_scalar_uses=0, added_scalar_uses=1)
        self.assertEqual(immutable_violations(data), [])
        row["eliminated_scalar_uses"] = 1
        self.assertTrue(immutable_violations(data))

    def test_missing_duplicate_and_invented_reads(self):
        for kind in ("missing", "duplicate", "out-of-range", "unknown-object"):
            data = report()
            rows = data["immutable_continuity"]
            if kind == "missing": rows.clear()
            elif kind == "duplicate": rows.append(copy.deepcopy(rows[0]))
            elif kind == "out-of-range": rows[0]["site"] = 1
            else: rows[0]["object"] = "absent"
            self.assertTrue(immutable_violations(data), kind)

    def test_contract_and_budget(self):
        for key, value in (("contract", "unknown"), ("bytes", 4), ("growth_retained", 193),
                           ("growth_available", 64), ("carrier_step_hex", "30"), ("physical_reads_per_site", 3)):
            data = report()
            data["data"][0][key] = value
            self.assertTrue(immutable_violations(data), key)
        data = report()
        data["features"]["immutable_bundles"] = False
        self.assertTrue(immutable_violations(data))

    def test_budget_skip_and_rollback_are_not_coverage(self):
        data = report()
        data["immutable_continuity"] = []
        row = data["data"][0]
        row.update(status="skipped", reason="immutable-growth-budget", growth_available=128, growth_retained=0)
        self.assertEqual(immutable_violations(data), [])
        row.update(status="rolled-back", growth_available=1000, growth_attempted=193)
        self.assertEqual(immutable_violations(data), [])
        row["growth_retained"] = 1
        self.assertTrue(immutable_violations(data))

    def test_connected_stage_retains_the_original_denominator(self):
        data = report()
        data["features"]["immutable_continuity_contract"] = 2
        data["immutable_connected_continuity"] = copy.deepcopy(data["immutable_continuity"])
        row = data["immutable_connected_continuity"][0]
        row.update(scope="after-regions-before-function-driver", remaining_scalar_uses=0, eliminated_scalar_uses=3)
        self.assertEqual(immutable_violations(data), [])
        row.update(original_scalar_uses=4, eliminated_scalar_uses=4)
        self.assertTrue(immutable_violations(data))
        data["immutable_connected_continuity"] = []
        self.assertTrue(immutable_violations(data))

    def test_option_contract(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        with self.assertRaises(ValueError):
            bundle_options.validate(parser.parse_args(["--immutable-bundles"]), True)
        args = parser.parse_args(["--bundles", "--immutable-bundles"])
        bundle_options.validate(args, True)
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))

    def test_llvm_array_spellings(self):
        self.assertEqual(backing_values(r'@table = private global [3 x i8] c"\02v\85"', 8, 3), [2, 118, 133])
        self.assertEqual(backing_values(r'@table = private global [3 x i8] c"\22\5C\00"', 8, 3), [34, 92, 0])
        self.assertEqual(backing_values('@table = private global [2 x i16] [i16 -1, i16 0]', 16, 2), [65535, 0])
        self.assertEqual(backing_values('@table = private global [2 x i32] zeroinitializer', 32, 2), [0, 0])

    def test_source_semantics_and_unsigned_index(self):
        self.assertIn("zext i8 %ai to i64", fixture(8, 201))
        for width in (8, 16, 32, 64):
            for n in (1, 2, 3, 4, 5, 7):
                for a, b in ((0, 0), (n - 1, n - 1), ((1 << width) - 1, 0)):
                    out = oracle(a, b, width, n, True)
                    self.assertTrue(all(0 <= x < (1 << width) for x in out))


if __name__ == "__main__":
    unittest.main()
