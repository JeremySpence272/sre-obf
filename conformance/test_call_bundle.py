import argparse
import unittest

from conformance import bundle_options
from conformance.call_bundle_check import call_bundle_summary, call_bundle_violations, call_supply_violations
from conformance.recursive_run import fixture, oracle
from conformance.bundle_decompile import private_offset
from conformance.process import ToolFailure
from conformance.tile_run import private_fixture, private_oracle, oracle as tile_oracle


def report():
    return {"features": {"bundles": True, "encoded_calls": True, "bundle_call_inputs": True},
            "encoded_calls": [{"encoded_function": "f.sre.encoded", "status": "encoded", "encoded_parameters": 3,
                               "absorbed_arguments": 1, "partially_absorbed_arguments": 1}],
            "bundle_call_inputs": [{"function": "f.sre.encoded", "contract": "bundle-call-input-v1",
                "stage": "after-bundles-before-regions", "imported_arguments": 2,
                "fully_absorbed_arguments": 1, "partially_absorbed_arguments": 1, "remaining_scalar_uses": 2}]}


class BundlePrivateInputs(unittest.TestCase):
    def test_informed_local_symbol_is_unambiguous(self):
        self.assertEqual(private_offset("0000000000001190 t recur\n", "recur"), 0x1190)
        for symbols in ("", "1190 d recur\n", "1190 t recur\n1190 t recur\n"):
            with self.assertRaises(ToolFailure): private_offset(symbols, "recur")

    def test_valid_partial_and_summary(self):
        self.assertEqual(call_bundle_violations(report()), [])
        self.assertEqual(call_bundle_summary(report())["imported_arguments"], 2)

    def test_bad_denominators_and_contracts(self):
        for key, value in (("imported_arguments", 4), ("fully_absorbed_arguments", 2),
                           ("partially_absorbed_arguments", 0), ("remaining_scalar_uses", 0),
                           ("imported_arguments", True), ("stage", "final"), ("contract", "unknown")):
            data = report()
            data["bundle_call_inputs"][0][key] = value
            self.assertTrue(call_bundle_violations(data), key)

    def test_no_duplicate_or_unknown_owner(self):
        data = report()
        data["bundle_call_inputs"].append(dict(data["bundle_call_inputs"][0]))
        self.assertTrue(call_bundle_violations(data))
        data = report()
        data["bundle_call_inputs"][0]["function"] = "unencoded"
        self.assertTrue(call_bundle_violations(data))

    def test_lost_or_double_counted_absorption(self):
        for full, partial in ((0, 1), (1, 0)):
            data = report()
            data["encoded_calls"][0].update(absorbed_arguments=full, partially_absorbed_arguments=partial)
            self.assertTrue(call_bundle_violations(data))
        # Further connected absorption may improve a partial input, never erase it.
        data = report()
        data["encoded_calls"][0].update(absorbed_arguments=2, partially_absorbed_arguments=0)
        self.assertEqual(call_bundle_violations(data), [])

    def test_missing_or_disabled(self):
        data = report()
        del data["bundle_call_inputs"]
        self.assertTrue(call_bundle_violations(data))
        data["features"]["bundle_call_inputs"] = False
        self.assertEqual(call_bundle_violations(data), [])
        data = report()
        data["features"]["encoded_calls"] = False
        self.assertTrue(call_bundle_violations(data))

    def test_shared_options_require_both_owners(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--encoded-calls", action="store_true")
        bundle_options.add_options(parser)
        for flags in (["--bundle-call-inputs"], ["--bundle-call-inputs", "--bundles"]):
            with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(flags), True)
        args = parser.parse_args(["--bundle-call-inputs", "--bundles", "--encoded-calls"])
        bundle_options.validate(args, True)
        self.assertIn("-native-bundle-call-inputs=1", bundle_options.flags(args))
        self.assertIn("--bundle-call-inputs", bundle_options.argv(args))

    def test_straight_line_control_oracle(self):
        for width in (8, 16, 32, 64):
            self.assertNotIn("%child", fixture(width, True))
            mask = (1 << width) - 1
            def work(x, y):
                p = ((x + y) * 3) & mask
                q = (x ^ 7) | y
                left = ((p + q) * 5) & mask
                right = ((p ^ q) + left) & mask
                return (right ^ 11) if left == 0 else (left ^ right)
            for a, b in ((0, 0), (mask, mask), (1, mask), (1 << (width - 1), 7)):
                self.assertEqual(oracle(a, b, width, True)[:2], [work(a, b), work(b, a)])


def supply_report():
    return {"features": {"bundles": True, "encoded_calls": True, "bundle_call_outputs": True},
        "encoded_calls": [{"encoded_function": "f.sre.encoded", "status": "encoded", "absorbed_results": 3}],
        "bundles": [{"function": "f.sre.encoded", "status": "encoded", "regions": [
            {"call_supply_uses": 2, "call_supply_reservation": 768, "scalar_output_uses": 3}]}],
        "bundle_call_outputs": [{"function": "f.sre.encoded", "interface": "f.sre.encoded",
            "contract": "bundle-call-supply-v1", "stage": "after-bundles-before-regions",
            "argument_pairs": 1, "result_pairs": 1}]}


class BundlePrivateOutputs(unittest.TestCase):
    def test_exact_retained_supply_reservation(self):
        self.assertEqual(call_supply_violations(supply_report()), [])
        for key, value in (("call_supply_uses", 3), ("call_supply_uses", True),
                           ("call_supply_reservation", 384), ("scalar_output_uses", 1)):
            data = supply_report()
            data["bundles"][0]["regions"][0][key] = value
            self.assertTrue(call_supply_violations(data), key)

    def test_rollback_has_no_supply_coverage(self):
        data = supply_report()
        data["bundles"][0]["status"] = "rolled-back"
        self.assertTrue(call_supply_violations(data))
        data["bundle_call_outputs"] = []
        self.assertEqual(call_supply_violations(data), [])

    def test_unknown_duplicate_or_miscredited_interface(self):
        for change in ({"interface": "unknown"}, {"function": "other"}, {"contract": "unknown"},
                       {"stage": "final"}, {"argument_pairs": -1}, {"result_pairs": 2}):
            data = supply_report()
            data["bundle_call_outputs"][0].update(change)
            self.assertTrue(call_supply_violations(data), change)
        data = supply_report()
        data["bundle_call_outputs"] *= 2
        self.assertTrue(call_supply_violations(data))

    def test_final_supply_accounting_is_not_lost(self):
        data = supply_report()
        data["encoded_calls"][0]["absorbed_results"] = 1
        self.assertTrue(call_supply_violations(data))

    def test_missing_reports_dependencies_and_disabled_claims(self):
        for flag in ("bundles", "encoded_calls", "bundle_call_outputs"):
            data = supply_report()
            data["features"][flag] = False
            self.assertTrue(call_supply_violations(data))
        data = supply_report()
        del data["bundle_call_outputs"]
        self.assertTrue(call_supply_violations(data))
        data = supply_report()
        data["features"]["bundle_call_outputs"] = False
        data["bundles"] = []
        self.assertTrue(call_supply_violations(data))

    def test_tile_and_pure_supplies_share_the_same_denominator(self):
        data = supply_report()
        plan = data["bundles"].pop()["regions"][0]
        data["object_bundles"] = [{"function": "f.sre.encoded", "status": "encoded", "plan": plan}]
        self.assertEqual(call_supply_violations(data), [])

    def test_constructed_rare_return_is_live_at_every_width(self):
        for width in (8, 16, 32, 64):
            y = (1 << (width - 2)) - 13
            self.assertEqual(oracle(16, y, width, True, True)[0], 11)
            self.assertNotEqual(oracle(0, 0, width, True, True)[0], 11)
            self.assertIn(f"done:\n  ret i{width} %v7", fixture(width, True, True))

    def test_private_tile_outputs_are_real_observable_results(self):
        for width in (8, 16, 32, 64):
            for cells in (2, 3, 4):
                text = private_fixture(width, cells)
                self.assertEqual(text.count(f"call i{width} @tile_consume"), cells)
                mask = (1 << width) - 1
                for a, b in ((0, 0), (mask, mask), (1, mask)):
                    expected = tile_oracle(a, b, width, cells)
                    for k in range(cells): expected[k] = ((expected[k] * 3) & mask) ^ 55
                    self.assertEqual(private_oracle(a, b, width, cells), expected)


if __name__ == "__main__":
    unittest.main()
