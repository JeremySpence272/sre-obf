"""v03 planner accounting, shard gating and opt-in checks."""
import unittest

from conformance.connected_check import invariants
from conformance.process import ToolFailure
from conformance.run import check_value_coverage
from conformance.scale import coverage, coverage_passes
from conformance.whole import parser


def function_row(**overrides):
    row = {"function": "f", "status": "encoded", "nodes": 4, "eligible_nodes": 6,
           "predicates": 1, "memory_edges": 0, "objects": [],
           "eligible_memory_edges": 0, "eligible_memory_objects": 0,
           "skipped_components": 1, "oversized_components": 1, "sharded_components": 1,
           "shards": 2, "shard_lost_nodes": 1,
           "eligible_estimated_cost": 1000, "selected_estimated_cost": 700,
           "skipped_estimated_cost": 200, "shard_lost_estimated_cost": 100,
           "component_estimated_cost_limit": 20000, "shard_estimated_cost_limit": 5000,
           "shard_policy": "instruction-order-units-with-atomic-memory-objects",
           "regions": [{"id": 0, "component": 3, "shard": 0, "sharded": True, "nodes": 2},
                       {"id": 1, "component": 3, "shard": 1, "sharded": True, "nodes": 2}]}
    row.update(overrides)
    return row


def native_report(schema="sre-native-v3", **overrides):
    return {"schema": schema, "connected_regions": [function_row(**overrides)],
            "flattening_state": [],
            "input_inventory": {"definitions": 1, "instructions": 10, "functions": []},
            "final_inventory": {"instructions": 10, "helper_instructions": 0}}


def value_report(plan, rows):
    """A native report carrying persistent-value evidence for one planner.

    Rows are written only under the planner named by `plan`; the other array is
    empty, exactly as the compiler leaves it.
    """
    arrays = {"values": [], "connected_regions": []}
    arrays["connected_regions" if plan == "connected" else "values"] = rows
    return {"features": {"region_plan": plan}, **arrays}


def value_row(widths=(8, 16, 32, 64), phi_pairs=2, persistent_edges=7, **extra):
    row = {"function": "obf_target", "status": "encoded", "widths": list(widths),
           "phi_pairs": phi_pairs, "persistent_edges": persistent_edges}
    row.update(extra)
    return row


class ValueWidthGateTests(unittest.TestCase):
    """The values gate must read the planner that ran, and must still fail."""

    def test_legacy_evidence_passes_with_all_four_widths(self):
        check_value_coverage(value_report("legacy", [value_row()]))

    def test_connected_evidence_passes_without_any_legacy_rows(self):
        # The bug: under --region-plan connected the legacy "values" array is
        # always empty, so the gate could never pass for any reason.
        report = value_report("connected", [value_row(widths=(1, 8, 16, 32, 64))])
        self.assertEqual(report["values"], [])
        check_value_coverage(report)

    def test_widths_split_across_functions_are_pooled(self):
        rows = [value_row(widths=(8, 16), phi_pairs=0, persistent_edges=3),
                value_row(widths=(32, 64))]
        check_value_coverage(value_report("connected", rows))

    def test_incomplete_width_coverage_still_fails(self):
        for plan in ("legacy", "connected"):
            for widths in ((8, 16, 32), (8,), (1, 8, 64), ()):
                with self.subTest(plan=plan, widths=widths):
                    with self.assertRaises(ToolFailure) as caught:
                        check_value_coverage(value_report(plan, [value_row(widths=widths)]))
                    self.assertIn("width coverage is incomplete", str(caught.exception))

    def test_predicate_only_connected_coverage_fails(self):
        # A tiny node cap can leave only i1 predicates encoded. That is real
        # coverage, but it is not the required scalar width set.
        with self.assertRaises(ToolFailure):
            check_value_coverage(value_report("connected", [value_row(widths=(1,))]))

    def test_the_other_planner_rows_are_not_borrowed(self):
        rows = [value_row()]
        borrowed = {"features": {"region_plan": "legacy"},
                    "values": [], "connected_regions": rows}
        with self.assertRaises(ToolFailure):
            check_value_coverage(borrowed)

    def test_skipped_and_rolled_back_rows_are_not_coverage(self):
        rows = [{"function": "f", "status": "skipped", "reason": "connected-growth-rollback",
                 "attempted_nodes": 40}]
        with self.assertRaises(ToolFailure) as caught:
            check_value_coverage(value_report("connected", rows))
        self.assertIn("encoded no persistent values", str(caught.exception))

    def test_a_planner_that_reports_no_widths_is_not_a_pass(self):
        row = value_row()
        del row["widths"]
        with self.assertRaises(ToolFailure) as caught:
            check_value_coverage(value_report("connected", [row]))
        self.assertIn("did not report encoded widths", str(caught.exception))

    def test_loop_join_coverage_is_required_of_both_planners(self):
        for plan in ("legacy", "connected"):
            with self.subTest(plan=plan):
                with self.assertRaises(ToolFailure) as caught:
                    check_value_coverage(value_report(plan, [value_row(phi_pairs=0)]))
                self.assertIn("loop/join coverage is missing", str(caught.exception))
                with self.assertRaises(ToolFailure):
                    check_value_coverage(value_report(plan, [value_row(persistent_edges=0)]))

    def test_an_unknown_region_plan_is_not_a_pass(self):
        with self.assertRaises(ToolFailure):
            check_value_coverage(value_report("someday", [value_row()]))


class ShardOptInTests(unittest.TestCase):
    def test_shards_are_opt_in_and_need_connected_regions(self):
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created"])
        self.assertFalse(args.connected_shards)
        self.assertEqual(args.region_plan, "legacy")

    def test_shard_flag_reaches_the_pass_as_its_own_experiment(self):
        from conformance.whole import EXPERIMENTS
        self.assertIn("connected-shards", EXPERIMENTS)


class ShardAccountingTests(unittest.TestCase):
    def test_exact_cost_loss_is_reported_separately(self):
        measured = coverage(native_report())
        self.assertEqual(measured["connected_eligible_estimated_cost"], 1000)
        self.assertEqual(measured["connected_selected_estimated_cost"], 700)
        self.assertEqual(measured["connected_skipped_estimated_cost"], 200)
        self.assertEqual(measured["connected_shard_lost_estimated_cost"], 100)
        self.assertEqual(measured["connected_shards"], 2)
        self.assertEqual(measured["connected_oversized_components"], 1)
        self.assertEqual(measured["connected_sharded_components"], 1)

    def test_older_reports_have_unknown_shard_denominators(self):
        measured = coverage(native_report(schema="sre-native-v2"))
        for field in ("connected_shards", "connected_oversized_components",
                      "connected_eligible_estimated_cost", "connected_shard_lost_estimated_cost"):
            self.assertIsNone(measured[field])
        # The memory denominators predate v03 and stay known in both schemas.
        self.assertEqual(measured["eligible_closed_memory_edges"], 0)
        self.assertIsNone(coverage(native_report(schema="sre-native-v1"))["eligible_closed_memory_edges"])

    def test_required_shard_coverage_is_never_implied(self):
        measured = coverage(native_report())
        self.assertTrue(coverage_passes(measured, require_shards=True))
        unsharded = coverage(native_report(shards=0, sharded_components=0,
                                           shard_policy="whole-component-only",
                                           regions=[{"id": 0, "component": 3, "shard": 0,
                                                     "sharded": False, "nodes": 4}]))
        self.assertTrue(coverage_passes(unsharded))
        self.assertFalse(coverage_passes(unsharded, require_shards=True))
        # An old report cannot satisfy a shard gate by omission.
        self.assertFalse(coverage_passes(coverage(native_report(schema="sre-native-v2")), require_shards=True))


class PlanningInvariantTests(unittest.TestCase):
    def test_consistent_report_has_no_violations(self):
        self.assertEqual(invariants(native_report()), [])

    def test_cost_must_account_for_every_eligible_node(self):
        self.assertTrue(invariants(native_report(shard_lost_estimated_cost=0)))

    def test_selected_cost_cannot_exceed_the_component_limit(self):
        self.assertTrue(invariants(native_report(component_estimated_cost_limit=600)))

    def test_shard_counts_must_be_supported_by_regions(self):
        self.assertTrue(invariants(native_report(shards=3)))
        self.assertTrue(invariants(native_report(sharded_components=2)))

    def test_shard_ids_are_contiguous_within_one_component(self):
        rows = [{"id": 0, "component": 3, "shard": 0, "sharded": True, "nodes": 2},
                {"id": 1, "component": 3, "shard": 2, "sharded": True, "nodes": 2}]
        self.assertTrue(invariants(native_report(regions=rows)))

    def test_shards_cannot_appear_without_the_shard_policy(self):
        self.assertTrue(invariants(native_report(shard_policy="whole-component-only")))

    def test_selection_cannot_exceed_eligibility(self):
        self.assertTrue(invariants(native_report(eligible_nodes=3)))

    def test_older_schema_is_not_judged_by_v03_invariants(self):
        self.assertEqual(invariants(native_report(schema="sre-native-v2", shards=9)), [])


if __name__ == "__main__":
    unittest.main()
