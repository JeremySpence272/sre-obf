import argparse
import unittest

from conformance import bundle_options
from conformance.call_bundle_check import call_bundle_summary, call_bundle_violations
from conformance.recursive_run import fixture, oracle
from conformance.bundle_decompile import private_offset
from conformance.process import ToolFailure


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


if __name__ == "__main__":
    unittest.main()
