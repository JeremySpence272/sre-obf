"""W5 merge/call arbitration: opt-in, fixed vocabulary and decision accounting."""
import unittest

from conformance.call_policy import (OUTCOMES, POLICIES, REASONS, policy_coverage,
                                     policy_violations)
from conformance.connected_check import report_violations


def row(**overrides):
    base = {"function": "fold32", "policy": "encoded-interface",
            "reason": "interface-preferred", "merge_group": "_auto",
            "merge_candidate": True, "selected": True, "interface_blocker": "",
            "outcome": "encoded"}
    base.update(overrides)
    return base


def fused(**overrides):
    return row(**{"function": "climb", "policy": "fused", "reason": "interface-ineligible",
                  "interface_blocker": "recursive", "outcome": "merged", **overrides})


def boundary(**overrides):
    return row(**{"function": "main", "policy": "scalar-boundary", "reason": "not-selected",
                  "merge_group": "", "merge_candidate": False, "selected": False,
                  "interface_blocker": "not-original", "outcome": "unclaimed", **overrides})


def report(*rows, feature=True):
    # connected_regions is what the shared gate's other checks read; an empty
    # planner report keeps this file about the arbitration alone.
    return {"schema": "sre-native-v6", "features": {"call_policy": feature},
            "connected_regions": [], "call_policy": list(rows)}


class VocabularyTests(unittest.TestCase):
    def test_a_consistent_arbitration_has_no_violations(self):
        self.assertEqual(policy_violations(report(row(), fused(), boundary())), [])

    def test_the_three_vocabularies_are_disjoint_and_fixed(self):
        # A policy and an outcome are different kinds of statement; sharing a
        # word between them is how a decision gets read back as a result.
        self.assertEqual(set(POLICIES) & set(OUTCOMES), set())
        self.assertEqual(len(set(REASONS)), len(REASONS))

    def test_an_unknown_word_in_any_field_is_a_violation(self):
        for field, value in (("policy", "merged"), ("reason", "because"),
                             ("outcome", "protected")):
            self.assertTrue(policy_violations(report(row(**{field: value}))),
                            f"{field}={value} was accepted")

    def test_a_missing_field_is_named_rather_than_defaulted(self):
        broken = row()
        del broken["outcome"]
        self.assertIn("outcome", policy_violations(report(broken))[0])

    def test_one_function_is_arbitrated_once(self):
        self.assertTrue(policy_violations(report(row(), row())))


class DecisionAgreementTests(unittest.TestCase):
    def test_the_interface_policy_and_its_reason_move_together(self):
        self.assertTrue(policy_violations(report(row(reason="interface-budget"))))
        self.assertTrue(policy_violations(
            report(fused(reason="interface-preferred", interface_blocker=""))))

    def test_an_interface_cannot_be_won_with_a_blocker_against_it(self):
        self.assertTrue(policy_violations(report(row(interface_blocker="varargs"))))

    def test_ineligible_must_name_the_blocker_that_applied(self):
        self.assertTrue(policy_violations(report(fused(interface_blocker=""))))

    def test_merging_cannot_be_given_a_function_it_was_never_offered(self):
        self.assertTrue(policy_violations(report(fused(merge_candidate=False))))


class OutcomeTests(unittest.TestCase):
    """The plan's warning: merging must not consume a group and leave encoded
    calls silently credited as on. Each check below is a way that could show up."""

    def test_a_reserved_interface_that_was_not_encoded_fails(self):
        self.assertTrue(policy_violations(report(row(outcome="merged"))))
        self.assertTrue(policy_violations(report(row(outcome="unclaimed"))))

    def test_a_recorded_scalar_boundary_that_was_taken_fails(self):
        for outcome in ("encoded", "merged", "thunked"):
            self.assertTrue(policy_violations(report(boundary(outcome=outcome))))

    def test_a_function_left_to_merging_cannot_end_encoded(self):
        self.assertTrue(policy_violations(report(fused(outcome="encoded"))))

    def test_an_unreconciled_row_is_unknown_and_not_an_outcome(self):
        self.assertEqual(policy_violations(report(row(outcome="unknown"))), [])
        self.assertEqual(policy_coverage(report(row(outcome="unknown")))["outcomes"]["encoded"], 0)


class DenominatorTests(unittest.TestCase):
    def test_a_missing_array_is_unknown_not_zero(self):
        coverage = policy_coverage({"schema": "sre-native-v6"})
        self.assertIsNone(coverage["source_functions"])
        self.assertIsNone(coverage["policies"])

    def test_a_missing_array_is_only_judged_when_the_feature_claims_to_be_on(self):
        self.assertEqual(policy_violations({"features": {"call_policy": False}}), [])
        self.assertTrue(policy_violations({"features": {"call_policy": True}}))

    def test_every_source_function_is_counted_including_the_unclaimed_ones(self):
        coverage = policy_coverage(report(row(), fused(outcome="unclaimed"), boundary()))
        self.assertEqual(coverage["source_functions"], 3)
        self.assertEqual(coverage["unclaimed"], 2)
        self.assertEqual(sum(coverage["policies"].values()), 3)
        self.assertEqual(coverage["contested"], 1)

    def test_the_shared_gate_runs_the_arbitration_check(self):
        self.assertTrue(report_violations(report(row(outcome="merged"))))
        self.assertEqual(report_violations(report(row(), fused(), boundary())), [])


if __name__ == "__main__":
    unittest.main()
