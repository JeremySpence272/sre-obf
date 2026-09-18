"""P5 encoded-call interface opt-in, report vocabulary and coverage accounting."""
from pathlib import Path
import tempfile
import unittest

from conformance.connected_check import (CALL_SKIPS, call_coverage, call_coverage_passes,
                                         call_violations, invariants, report_violations)
from conformance.run import CASES, feature_flags
from conformance.run import parser as case_parser
from conformance.whole import EXPERIMENTS, build
from conformance.whole import parser as whole_parser


def call_row(**overrides):
    row = {"function": "helper", "status": "encoded", "reason": "", "parameters": 2,
           "encoded_parameters": 2, "returns_pair": True, "widths": [8, 32], "callers": 2,
           "call_sites_rewritten": 3, "result_rebuilds": 1, "wrapper_retained": False,
           "representation": "xor-pair-v1", "activation_allocas": 1,
           "absorbed_arguments": 0, "absorbed_results": 0}
    row.update(overrides)
    return row


def skip_row(reason, **overrides):
    empty = {"status": "skipped", "reason": reason, "encoded_parameters": 0,
             "returns_pair": False, "result_rebuilds": 0, "call_sites_rewritten": 0,
             "activation_allocas": 0}
    empty.update(overrides)
    return call_row(**empty)


def report(*rows):
    return {"schema": "sre-native-v4", "encoded_calls": list(rows)}


class OptInTests(unittest.TestCase):
    def test_encoded_calls_are_off_by_default(self):
        args = whole_parser().parse_args(["input.c", "--out", "/tmp/not-created"])
        self.assertFalse(args.encoded_calls)
        self.assertFalse(case_parser().parse_args(["--out", "/tmp/not-created"]).encoded_calls)

    def test_flag_reaches_the_pass_as_its_own_experiment(self):
        self.assertIn("encoded-calls", EXPERIMENTS)
        args = case_parser().parse_args(["--out", "/tmp/not-created", "--encoded-calls"])
        self.assertIn("-native-encoded-calls=1", feature_flags(args))
        self.assertIn("-native-encoded-calls=0",
                      feature_flags(case_parser().parse_args(["--out", "/tmp/not-created"])))

    def test_encoded_calls_require_connected_regions(self):
        with tempfile.TemporaryDirectory() as directory:
            args = whole_parser().parse_args(
                ["input.c", "--out", str(Path(directory) / "fresh"), "--encoded-calls"])
            with self.assertRaises(ValueError):
                build(args)

    def test_the_fixture_and_its_threaded_main_exist(self):
        fixtures = Path(__file__).parent / "fixtures"
        self.assertTrue((fixtures / "encoded_calls.c").is_file())
        self.assertTrue((fixtures / "encoded_calls_threads.c").is_file())
        # The fixture is driven by whole.py, not by the per-case driver: that
        # driver always disassembles, and this fixture's arms exceed the
        # harness tool-output limit.
        self.assertNotIn("encoded_calls", CASES)


class ReportVocabularyTests(unittest.TestCase):
    def test_a_consistent_report_has_no_violations(self):
        self.assertEqual(call_violations(report(call_row(), skip_row("recursive"))), [])

    def test_missing_array_is_not_judged(self):
        self.assertEqual(call_violations({"schema": "sre-native-v4"}), [])

    def test_an_interface_without_pairs_is_not_encoded_coverage(self):
        self.assertTrue(call_violations(report(call_row(parameters=0, encoded_parameters=0,
                                                        returns_pair=False, result_rebuilds=0))))

    def test_absorbed_supplies_cannot_exceed_the_pairs_supplied(self):
        # Three sites of a two-parameter interface supply six argument pairs,
        # and its single return supplies one more.
        self.assertEqual(call_violations(report(call_row(absorbed_results=7))), [])
        self.assertTrue(call_violations(report(call_row(absorbed_results=8))))

    def test_a_pair_result_must_be_rebuilt(self):
        self.assertTrue(call_violations(report(call_row(result_rebuilds=0))))
        self.assertTrue(call_violations(report(call_row(returns_pair=False))))

    def test_a_retained_plaintext_wrapper_fails(self):
        self.assertTrue(call_violations(report(call_row(wrapper_retained=True))))

    def test_partially_encoded_parameters_fail(self):
        self.assertTrue(call_violations(report(call_row(parameters=3))))

    def test_an_encoded_row_cannot_carry_a_skip_reason(self):
        self.assertTrue(call_violations(report(call_row(reason="recursive"))))

    def test_skip_reasons_stay_inside_the_fixed_vocabulary(self):
        for reason in CALL_SKIPS:
            self.assertEqual(call_violations(report(skip_row(reason))), [])
        self.assertTrue(call_violations(report(skip_row("too-hard"))))

    def test_a_skipped_interface_cannot_report_encoded_work(self):
        self.assertTrue(call_violations(report(skip_row("recursive", call_sites_rewritten=2))))
        self.assertTrue(call_violations(report(skip_row("varargs", absorbed_results=1))))

    def test_absorption_cannot_exceed_the_interface(self):
        self.assertTrue(call_violations(report(call_row(absorbed_arguments=3))))
        self.assertEqual(call_violations(report(call_row(absorbed_arguments=2))), [])


class PlannerRowTests(unittest.TestCase):
    def test_an_unanalyzed_function_has_no_accounting_to_check(self):
        # A varargs or oversized function is skipped before planning, so its
        # row carries no cost fields. That is a skip, not a broken report.
        report = {"schema": "sre-native-v4",
                  "connected_regions": [{"function": "gather", "status": "skipped",
                                         "reason": "structure-or-size"}]}
        self.assertEqual(invariants(report), [])


class CoverageAccountingTests(unittest.TestCase):
    def test_moved_pairs_are_counted_per_call_site(self):
        measured = call_coverage(report(call_row(), skip_row("varargs")))
        self.assertEqual(measured["encoded_interfaces"], 1)
        self.assertEqual(measured["argument_pairs_moved"], 6)
        self.assertEqual(measured["result_pairs_moved"], 3)
        self.assertEqual(measured["absorbed_arguments"], 0)
        self.assertEqual(measured["absorbed_results"], 0)
        self.assertEqual(measured["skips"], {"varargs": 1})
        # absorbed_arguments counts reconstructions, one per parameter, not one
        # per call site: its denominator must not be the moved-pair count.
        self.assertEqual(measured["parameter_reconstructions"], 2)
        self.assertEqual(measured["pair_supplies"], 7)

    def test_a_void_interface_moves_arguments_only(self):
        measured = call_coverage(report(call_row(returns_pair=False, result_rebuilds=0,
                                                 parameters=1, encoded_parameters=1,
                                                 call_sites_rewritten=2)))
        self.assertEqual(measured["argument_pairs_moved"], 2)
        self.assertEqual(measured["result_pairs_moved"], 0)

    def test_a_report_without_the_array_has_unknown_denominators(self):
        measured = call_coverage({"schema": "sre-native-v2"})
        for field in ("encoded_interfaces", "argument_pairs_moved", "absorbed_arguments",
                      "parameter_reconstructions", "pair_supplies", "skips"):
            self.assertIsNone(measured[field])

    def test_coverage_requires_a_pair_that_actually_crosses(self):
        self.assertTrue(call_coverage_passes(call_coverage(report(call_row()))))
        self.assertFalse(call_coverage_passes(call_coverage(report(skip_row("recursive")))))
        self.assertFalse(call_coverage_passes(call_coverage({"schema": "sre-native-v2"})))

    def test_width_coverage_is_never_implied(self):
        narrow = call_coverage(report(call_row(widths=[32])))
        self.assertTrue(call_coverage_passes(narrow))
        self.assertFalse(call_coverage_passes(narrow, require_widths=True))
        wide = call_coverage(report(call_row(widths=[8, 16]), call_row(widths=[32, 64])))
        self.assertTrue(call_coverage_passes(wide, require_widths=True))


class ReviewInterfaceTests(unittest.TestCase):
    def current(self, **overrides):
        row = call_row(encoded_function="helper.sre.encoded.1", partially_absorbed_arguments=0)
        row.update(overrides)
        return {"schema": "sre-native-v6", "connected_regions": [], "encoded_calls": [row]}

    def test_partial_and_complete_absorption_have_separate_counts(self):
        report = self.current(absorbed_arguments=1, partially_absorbed_arguments=1)
        self.assertEqual(report_violations(report), [])
        measured = call_coverage(report)
        self.assertEqual(measured["absorbed_arguments"], 1)
        self.assertEqual(measured["partially_absorbed_arguments"], 1)

    def test_partial_parameters_cannot_be_counted_again_as_complete(self):
        self.assertTrue(report_violations(self.current(absorbed_arguments=2, partially_absorbed_arguments=1)))

    def test_missing_actual_symbol_or_counts_is_a_report_failure(self):
        for field in ("encoded_function", "partially_absorbed_arguments", "call_sites_rewritten"):
            report = self.current()
            del report["encoded_calls"][0][field]
            self.assertTrue(report_violations(report))
        self.assertTrue(report_violations(self.current(encoded_function="")))

    def test_negative_counts_and_unknown_status_cannot_pass(self):
        self.assertTrue(report_violations(self.current(absorbed_arguments=-1)))
        self.assertTrue(report_violations(self.current(status="unknown")))

    def test_feature_on_without_report_is_a_failure(self):
        self.assertTrue(report_violations({"schema": "sre-native-v6", "connected_regions": [],
                                          "features": {"encoded_calls": True}}))

    def test_old_reports_leave_partial_absorption_unknown(self):
        self.assertIsNone(call_coverage(report(call_row()))["partially_absorbed_arguments"])


if __name__ == "__main__":
    unittest.main()
