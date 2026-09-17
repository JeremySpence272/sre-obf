"""v03 planner accounting, shard gating and opt-in checks."""
import unittest

from conformance.connected_check import invariants
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
