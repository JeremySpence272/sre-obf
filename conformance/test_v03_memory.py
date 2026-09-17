"""Closed aggregate memory: opt-in gating, denominator growth and self-checks."""
import unittest

from conformance.connected_check import invariants
from conformance.scale import coverage, coverage_passes
from conformance.whole import parser


def scalar_object(origin="f/alloca/0"):
    return {"object": "", "origin": origin, "status": "encoded", "layout": "scalar",
            "elements": 1, "leaves": 1, "width": 32, "loads": 2, "stores": 1,
            "implicit_load_decodes": 0}


def aggregate_object(origin="f/alloca/1"):
    return {"object": "", "origin": origin, "status": "encoded", "layout": "aggregate-leaves",
            "elements": 4, "leaves": 4, "width": None, "loads": 4, "stores": 4,
            "implicit_load_decodes": 0}


def function_row(**overrides):
    row = {"function": "f", "status": "encoded", "nodes": 4, "eligible_nodes": 6,
           "predicates": 1, "memory_edges": 11, "objects": [scalar_object(), aggregate_object()],
           "aggregate_memory_objects": 1, "aggregate_memory_edges": 8,
           "eligible_memory_edges": 11, "eligible_memory_objects": 2,
           "eligible_aggregate_memory_objects": 1, "eligible_memory_leaves": 5,
           "memory_layout_policy": "constant-index-aggregate-leaves",
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


def native_report(schema="sre-native-v4", **overrides):
    return {"schema": schema, "connected_regions": [function_row(**overrides)],
            "flattening_state": [],
            "input_inventory": {"definitions": 1, "instructions": 10, "functions": []},
            "final_inventory": {"instructions": 10, "helper_instructions": 0}}


def narrow_row(**overrides):
    """A function from a build with the aggregate experiment off."""
    base = {"objects": [scalar_object()], "aggregate_memory_objects": 0,
            "aggregate_memory_edges": 0, "memory_edges": 3,
            "eligible_memory_edges": 3, "eligible_memory_objects": 1,
            "eligible_aggregate_memory_objects": 0, "eligible_memory_leaves": 1,
            "memory_layout_policy": "scalar-and-flat-array-only"}
    base.update(overrides)
    return function_row(**base)


class AggregateOptInTests(unittest.TestCase):
    def test_aggregates_are_opt_in(self):
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created"])
        self.assertFalse(args.connected_aggregates)

    def test_aggregate_flag_is_its_own_experiment(self):
        from conformance.whole import EXPERIMENTS
        self.assertIn("connected-aggregates", EXPERIMENTS)

    def test_aggregates_require_the_connected_memory_lane(self):
        from conformance.whole import build
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created", "--values", "--values-wide",
                                    "--region-plan", "connected", "--connected-aggregates"])
        with self.assertRaises(ValueError):
            build(args)


class AggregateCoverageTests(unittest.TestCase):
    def test_aggregate_coverage_is_reported_beside_its_denominator(self):
        measured = coverage(native_report())
        self.assertEqual(measured["aggregate_memory_objects"], 1)
        self.assertEqual(measured["aggregate_memory_edges"], 8)
        self.assertEqual(measured["eligible_closed_memory_objects"], 2)
        self.assertEqual(measured["eligible_closed_aggregate_memory_objects"], 1)
        self.assertEqual(measured["eligible_closed_memory_leaves"], 5)

    def test_widening_grows_the_denominator_it_reports_against(self):
        narrow = coverage(native_report(**narrow_row()))
        wide = coverage(native_report())
        self.assertLess(narrow["eligible_closed_memory_objects"], wide["eligible_closed_memory_objects"])
        self.assertLess(narrow["eligible_closed_memory_edges"], wide["eligible_closed_memory_edges"])
        self.assertLess(narrow["memory_edges"], wide["memory_edges"])

    def test_a_report_without_the_new_denominators_leaves_them_unknown(self):
        row = function_row()
        for field in ("eligible_aggregate_memory_objects", "eligible_memory_leaves"):
            del row[field]
        report = native_report()
        report["connected_regions"] = [row]
        measured = coverage(report)
        self.assertIsNone(measured["eligible_closed_aggregate_memory_objects"])
        self.assertIsNone(measured["eligible_closed_memory_leaves"])
        self.assertIsNone(coverage(native_report(schema="sre-native-v1"))["eligible_closed_memory_leaves"])

    def test_required_aggregate_coverage_is_never_implied(self):
        self.assertTrue(coverage_passes(coverage(native_report()), require_aggregate_memory=True))
        narrow = coverage(native_report(**narrow_row()))
        self.assertTrue(coverage_passes(narrow, require_memory=True))
        self.assertFalse(coverage_passes(narrow, require_aggregate_memory=True))


class AggregateInvariantTests(unittest.TestCase):
    def test_consistent_report_has_no_violations(self):
        self.assertEqual(invariants(native_report()), [])
        self.assertEqual(invariants(native_report(**narrow_row())), [])

    def test_encoded_objects_cannot_exceed_the_eligible_objects(self):
        self.assertTrue(invariants(native_report(eligible_memory_objects=1)))

    def test_memory_edges_cannot_exceed_the_eligible_edges(self):
        self.assertTrue(invariants(native_report(eligible_memory_edges=4)))

    def test_aggregates_cannot_appear_under_the_narrow_policy(self):
        self.assertTrue(invariants(native_report(memory_layout_policy="scalar-and-flat-array-only")))

    def test_aggregate_count_must_match_the_object_rows(self):
        self.assertTrue(invariants(native_report(aggregate_memory_objects=2)))

    def test_eligible_aggregates_cannot_exceed_eligible_objects(self):
        self.assertTrue(invariants(native_report(eligible_aggregate_memory_objects=3)))


if __name__ == "__main__":
    unittest.main()
