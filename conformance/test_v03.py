"""v03 planner accounting, shard gating, joint outputs and opt-in checks."""
import random
import unittest

from conformance.connected_check import invariants, joint_coverage, joint_invariants
from conformance.connected_model import decode, joint_mix, joint_unmix
from conformance.scale import coverage, coverage_passes
from conformance.whole import parser

WIDTHS = (1, 4, 8, 16, 32, 64)


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


def joint_row(**overrides):
    row = function_row(joint_output_groups=1, joint_output_candidates=4,
                       joint_lane_uses_rewritten=5, joint_policy="pairwise-unimodular-u-v-v1",
                       joint_dependency_test="distinct-normalized-root-dependencies-both-ways"
                                             "-plus-no-dataflow-dependence")
    row.update(overrides)
    return row


class JointOutputOptInTests(unittest.TestCase):
    def test_joint_outputs_are_opt_in(self):
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created"])
        self.assertFalse(args.joint_outputs)

    def test_joint_flag_reaches_the_pass_as_its_own_experiment(self):
        from conformance.whole import EXPERIMENTS
        self.assertIn("joint-outputs", EXPERIMENTS)


class JointOutputLawTests(unittest.TestCase):
    """Inverse positive control: recover X and Y from U and V at every width."""

    def test_inverse_recovers_both_operands(self):
        rng = random.Random(6205)
        for width in WIDTHS:
            mask = (1 << width) - 1
            for affine in (True, False):
                for _ in range(1000):
                    x, y, r, s = [rng.getrandbits(width) for _ in range(4)]
                    px = ((x + r) & mask, r) if affine else (x ^ r, r)
                    py = ((y + s) & mask, s) if affine else (y ^ s, s)
                    u, v = joint_mix(px, py, width, affine)
                    self.assertEqual(decode(u, affine, width), (x + y) & mask)
                    self.assertEqual(decode(v, affine, width), (x + 2 * y) & mask)
                    rx, ry = joint_unmix(u, v, width, affine)
                    self.assertEqual(decode(rx, affine, width), x)
                    self.assertEqual(decode(ry, affine, width), y)

    def test_width_one_is_covered_by_the_same_inverse(self):
        # 2Y vanishes at width 1, so V is X there; the determinant is still
        # one and the same formulas invert exactly.
        for x in (0, 1):
            for y in (0, 1):
                for share in (0, 1):
                    u, v = joint_mix((x ^ share, share), (y, 0), 1, False)
                    rx, ry = joint_unmix(u, v, 1, False)
                    self.assertEqual((decode(rx, False, 1), decode(ry, False, 1)), (x, y))

    def test_one_joint_output_alone_leaves_both_operands_open(self):
        # A statement about the reference algebra, not a hardness claim: with U
        # fixed, every V still yields a consistent operand pair.
        rng = random.Random(6206)
        for width in (8, 32):
            mask = (1 << width) - 1
            u = (rng.getrandbits(width), rng.getrandbits(width))
            recovered = {decode(joint_unmix(u, (rng.getrandbits(width), u[1]), width, True)[0], True, width)
                         for _ in range(64)}
            self.assertGreater(len(recovered), 1)
            self.assertTrue(all(value <= mask for value in recovered))


class JointOutputAccountingTests(unittest.TestCase):
    def test_consistent_joint_row_has_no_violations(self):
        self.assertEqual(joint_invariants(joint_row(), "f"), [])

    def test_groups_cannot_exceed_half_the_candidates(self):
        self.assertTrue(joint_invariants(joint_row(joint_output_candidates=1), "f"))

    def test_groups_must_govern_at_least_one_lane_use_per_member(self):
        self.assertTrue(joint_invariants(joint_row(joint_lane_uses_rewritten=1), "f"))

    def test_disabled_policy_cannot_report_groups(self):
        self.assertTrue(joint_invariants(joint_row(joint_policy="disabled"), "f"))

    def test_report_without_joint_fields_is_unknown_not_a_violation(self):
        self.assertEqual(joint_invariants(function_row(), "f"), [])
        self.assertEqual(invariants(native_report()), [])

    def test_missing_joint_counts_are_unknown_not_zero(self):
        self.assertEqual(joint_coverage([joint_row()]), (1, 4, 5))
        self.assertEqual(joint_coverage([function_row()]), (None, None, None))
        self.assertEqual(joint_coverage([]), (None, None, None))


if __name__ == "__main__":
    unittest.main()
