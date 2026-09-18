"""v04 M1 typed plan and M0 boundary inventory: gate checks with constructed cases.

Every negative here is a constructed counterexample, not a sampled one. A plan
that passes these checks is internally consistent; that is not a claim that the
program it describes is protected.
"""
import unittest

from conformance.connected_check import BOUNDARY_REASONS, plan_violations, report_violations


def plan(**overrides):
    value = {
        "plan_version": 1, "function": "f", "seed_namespace": "native-connected-v1/f",
        "sealed": True, "eligible_nodes": 6, "eligible_objects": 0,
        "eligible_memory_edges": 0,
        "representations": [
            {"family": "xor-prefix-pair", "revision": 1, "name": "xor-prefix-pair-v1",
             "lanes": 2, "logical_width": None, "lane_width": 0,
             "invariant": "xor-of-lanes", "seed_namespace": "native-connected-v1/f",
             "verification": "algebraic"}],
        "operations": [
            {"origin": "f/op/0", "kind": "pure", "logical_width": 32, "effects": 0,
             "region": 0, "object": None, "estimated_cost": 320, "operands": 0,
             "scalar_uses": 1, "selected": True, "reason": None},
            {"origin": "f/op/1", "kind": "pure", "logical_width": 32, "effects": 0,
             "region": 0, "object": None, "estimated_cost": 380, "operands": 1,
             "scalar_uses": 0, "selected": True, "reason": None},
            {"origin": "f/op/2", "kind": "compare", "logical_width": 1, "effects": 0,
             "region": None, "object": None, "estimated_cost": 300, "operands": 1,
             "scalar_uses": 0, "selected": False, "reason": "component-limit"}],
        "objects": [], "storage": [], "calls": [],
        "regions": [{"origin": "f/region/0", "component": 0, "shard": 0, "sharded": False,
                     "representation": 0, "nodes": 2, "estimated_cost": 700, "score": 9}],
        "bundles": [], "transfers": [], "phases": [], "joins": [],
        "decodes": [{"origin": "f/op/0", "consumer": "return", "reason": "external-abi",
                     "uses": 1, "useful_work": 2}],
        "boundary_inventory": {
            "measured": True,
            "scalar_use_edges": dict.fromkeys(BOUNDARY_REASONS, 0) | {"external-abi": 1},
            "origins": dict.fromkeys(BOUNDARY_REASONS, 0) | {"external-abi": 1},
            "total_scalar_use_edges": 1, "absorbed_edges": 0, "constant_entries": 3,
            "protected_operations": 2, "exposures": 1,
            "useful_work_total": 2, "useful_work_max": 2,
            "vocabulary": "origin-and-reason-v1"},
        "costs": {"eligible_estimated": 1000, "selected_estimated": 700,
                  "skipped_estimated": 200, "lost_estimated": 100,
                  "component_limit": 20000, "shard_limit": 5000,
                  "reserved_structural": 0, "reserve_denied_components": 0,
                  "reserve_denied_estimated": 0, "instructions_before": 40,
                  "instructions_after": 260, "rolled_back": False,
                  "rollback_scope": "function-body"},
        "violations": []}
    value.update(overrides)
    return value


def report(**overrides):
    row = {"function": "f", "status": "encoded", "nodes": 2, "eligible_nodes": 6,
           "predicates": 1, "memory_edges": 0, "objects": [],
           "eligible_memory_edges": 0, "eligible_memory_objects": 0,
           "skipped_components": 1, "oversized_components": 0, "sharded_components": 0,
           "shards": 0, "shard_lost_nodes": 0,
           "eligible_estimated_cost": 1000, "selected_estimated_cost": 700,
           "skipped_estimated_cost": 200, "shard_lost_estimated_cost": 100,
           "component_estimated_cost_limit": 20000, "shard_estimated_cost_limit": 0,
           "shard_policy": "whole-component-only",
           "regions": [{"id": 0, "component": 0, "shard": 0, "sharded": False, "nodes": 2}],
           "plan": plan(**overrides)}
    return {"schema": "sre-native-v4", "connected_regions": [row], "flattening_state": [],
            "input_inventory": {"definitions": 1, "instructions": 10, "functions": []},
            "final_inventory": {"instructions": 10, "helper_instructions": 0}}


class PlanGate(unittest.TestCase):
    def test_constructed_valid_plan_passes(self):
        self.assertEqual(plan_violations(report()), [])
        self.assertEqual(report_violations(report()), [])

    def test_a_row_without_a_plan_is_unknown_not_a_violation(self):
        data = report()
        del data["connected_regions"][0]["plan"]
        self.assertEqual(plan_violations(data), [])

    def test_unsealed_plan_fails(self):
        self.assertTrue(any("sealing" in v for v in plan_violations(report(sealed=False))))

    def test_compiler_reported_violations_are_never_dropped(self):
        data = report(violations=["f/op/9: operand index out of range"])
        self.assertTrue(any("operand index" in v for v in plan_violations(data)))

    def test_more_planned_operations_than_eligible_fails(self):
        # A generated instruction must never reach a denominator; this is the
        # shape that would let it.
        data = report()
        data["connected_regions"][0]["plan"]["eligible_nodes"] = 2
        self.assertTrue(any("more planned operations" in v for v in plan_violations(data)))

    def test_selected_operation_carrying_a_skip_reason_fails(self):
        data = report()
        data["connected_regions"][0]["plan"]["operations"][0]["reason"] = "budget-loss"
        self.assertTrue(any("carries a skip reason" in v for v in plan_violations(data)))

    def test_dropped_operation_without_a_known_reason_fails(self):
        data = report()
        data["connected_regions"][0]["plan"]["operations"][2]["reason"] = None
        self.assertTrue(any("without a known reason" in v for v in plan_violations(data)))
        data["connected_regions"][0]["plan"]["operations"][2]["reason"] = "too-hard"
        self.assertTrue(any("without a known reason" in v for v in plan_violations(data)))

    def test_decode_outside_the_fixed_vocabulary_fails(self):
        data = report()
        data["connected_regions"][0]["plan"]["decodes"][0]["reason"] = "it-was-awkward"
        self.assertTrue(any("without a known reason" in v for v in plan_violations(data)))
        data = report()
        data["connected_regions"][0]["plan"]["decodes"][0]["consumer"] = "vibes"
        self.assertTrue(any("unknown decode consumer" in v for v in plan_violations(data)))

    def test_inventory_must_use_exactly_the_fixed_vocabulary(self):
        data = report()
        data["connected_regions"][0]["plan"]["boundary_inventory"]["scalar_use_edges"].pop("budget-loss")
        self.assertTrue(any("vocabulary is not the fixed one" in v for v in plan_violations(data)))

    def test_exposures_must_match_the_decode_sites(self):
        data = report()
        data["connected_regions"][0]["plan"]["boundary_inventory"]["exposures"] = 7
        self.assertTrue(any("exposures disagree" in v for v in plan_violations(data)))

    def test_edges_must_sum_to_the_reported_total(self):
        data = report()
        data["connected_regions"][0]["plan"]["boundary_inventory"]["total_scalar_use_edges"] = 9
        self.assertTrue(any("do not sum" in v for v in plan_violations(data)))

    def test_useful_work_cannot_exceed_the_protected_operations(self):
        data = report()
        data["connected_regions"][0]["plan"]["boundary_inventory"]["useful_work_max"] = 5
        self.assertTrue(any("useful work exceeds" in v for v in plan_violations(data)))

    def test_unmeasured_inventory_must_be_null_not_zero(self):
        data = report()
        inventory = data["connected_regions"][0]["plan"]["boundary_inventory"]
        inventory["measured"] = False
        self.assertTrue(any("instead of null" in v for v in plan_violations(data)))
        for key in ("total_scalar_use_edges", "absorbed_edges", "constant_entries",
                    "protected_operations", "exposures", "useful_work_total", "useful_work_max"):
            inventory[key] = None
        self.assertEqual(plan_violations(data), [])

    def test_costs_must_agree_with_the_row_beside_them(self):
        data = report()
        data["connected_regions"][0]["plan"]["costs"]["selected_estimated"] = 701
        self.assertTrue(any("selected_estimated disagrees" in v for v in plan_violations(data)))

    def test_representation_must_name_its_family_invariant_and_namespace(self):
        data = report()
        data["connected_regions"][0]["plan"]["representations"][0]["family"] = "magic"
        self.assertTrue(any("unknown representation family" in v for v in plan_violations(data)))
        data = report()
        data["connected_regions"][0]["plan"]["representations"][0]["invariant"] = ""
        self.assertTrue(any("without lanes, invariant or namespace" in v
                            for v in plan_violations(data)))

    def test_verification_outside_the_fixed_set_fails(self):
        data = report()
        data["connected_regions"][0]["plan"]["representations"][0]["verification"] = "proved-somehow"
        self.assertTrue(any("unknown verification" in v for v in plan_violations(data)))

    def test_rolled_back_row_keeps_its_plan_and_its_genuine_selection_loss(self):
        # A rolled-back function republishes its selection as attempted_*. Its
        # skips and shard losses are its own, not rollback loss, so they must
        # survive under their own names; the plan beside the row still says
        # what was attempted and that the body was undone.
        data = report()
        row = data["connected_regions"][0]
        row["status"] = "skipped"
        row["reason"] = "connected-growth-rollback"
        row["attempted_estimated_cost"] = row.pop("selected_estimated_cost")
        row["attempted_skipped_estimated_cost"] = row.pop("skipped_estimated_cost")
        row["attempted_shard_lost_estimated_cost"] = row.pop("shard_lost_estimated_cost")
        row["plan"]["costs"]["rolled_back"] = True
        self.assertEqual(plan_violations(data), [])
        self.assertEqual(report_violations(data), [])
        # The three loss terms still reconstruct the eligible total exactly.
        self.assertEqual(row["eligible_estimated_cost"],
                         row["attempted_estimated_cost"]
                         + row["attempted_skipped_estimated_cost"]
                         + row["attempted_shard_lost_estimated_cost"])

    def test_unsupported_plan_version_fails_without_reading_the_rest(self):
        violations = plan_violations(report(plan_version=99))
        self.assertEqual(len(violations), 1)
        self.assertIn("unsupported plan version", violations[0])

    def test_version_two_preserves_and_checks_operand_identities(self):
        data = report(plan_version=2)
        p = data["connected_regions"][0]["plan"]
        for op, operands in zip(p["operations"], ([], [0], [1])):
            op.update(operands=operands, operand_count=len(operands))
        self.assertEqual(plan_violations(data), [])
        p["operations"][1]["operands"] = [99]
        self.assertTrue(any("operand identities" in v for v in plan_violations(data)))

    def test_rollback_costs_are_compared_to_attempted_fields(self):
        data = report()
        row = data["connected_regions"][0]
        row.update(status="skipped", reason="connected-growth-rollback",
                   attempted_estimated_cost=701)
        row["plan"]["costs"]["rolled_back"] = True
        self.assertTrue(any("attempted_estimated_cost" in v for v in plan_violations(data)))


if __name__ == "__main__":
    unittest.main()
