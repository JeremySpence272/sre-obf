"""P6 useful data/control relation: opt-in checks and analyst-arm accounting."""
import json
import tempfile
import unittest
from pathlib import Path

from conformance import state_model
from conformance.connected_check import lane_coverage
from conformance.relation_recovery import Body, data_context_words, functions, main
from conformance.run import LANE_TRANSITIONS
from conformance.whole import parser

# A minimal module in the shape the passes emit: one dispatcher comparison whose
# expected token is built from the two flattening words, and one that also reads
# the encoded-data word. The store metadata is what marks that word as data.
MODULE = """; ModuleID = 'fixture'
define dso_local i32 @plain(i32 %0) {
  %fla.multi.key = alloca i32, align 4
  %fla.multi.salt = alloca i32, align 4
  %sre.value.context = alloca i32, align 4
  %fla.multi.key.load = load volatile i32, ptr %fla.multi.key, align 4
  %fla.multi.salt.load = load volatile i32, ptr %fla.multi.salt, align 4
  %a = or i32 %fla.multi.salt.load, 1
  %b = xor i32 %0, %fla.multi.key.load
  %fla.multi.token = mul i32 %b, %a
  %fla.multi.match = icmp eq i32 %0, %fla.multi.token
  store volatile i32 %0, ptr %sre.value.context, align 4, !sre.native.context.update !0
  ret i32 0
}

define dso_local i32 @coupled(i32 %0) {
  %fla.multi.key = alloca i32, align 4
  %fla.multi.salt = alloca i32, align 4
  %sre.value.context = alloca i32, align 4
  %fla.multi.key.load = load volatile i32, ptr %fla.multi.key, align 4
  %fla.multi.salt.load = load volatile i32, ptr %fla.multi.salt, align 4
  %fla.multi.lane.load = load volatile i32, ptr %sre.value.context, align 4
  %sre.lane.key = add i32 %fla.multi.key.load, %fla.multi.lane.load
  %a = or i32 %fla.multi.salt.load, 1
  %b = xor i32 %0, %sre.lane.key
  %fla.multi.token = mul i32 %b, %a
  %fla.multi.match = icmp eq i32 %0, %fla.multi.token
  store volatile i32 %0, ptr %sre.value.context, align 4, !sre.native.context.update !0
  ret i32 0
}

!0 = !{!"data"}
"""


class LaneOptInTests(unittest.TestCase):
    def test_lane_transitions_default_off_in_the_harness(self):
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created"])
        self.assertEqual(args.lane_transitions, "off")
        self.assertEqual(LANE_TRANSITIONS[args.lane_transitions], 0)

    def test_the_experiment_is_one_flag_with_an_explicit_attack_arm(self):
        self.assertEqual(LANE_TRANSITIONS, {"off": 0, "on": 1, "stale-relation": 2})

    def test_lane_transitions_require_the_coupled_context_word(self):
        args = parser().parse_args(["input.c", "--out", "/tmp/not-created",
                                    "--lane-transitions", "on"])
        self.assertEqual(args.lane_transitions, "on")
        self.assertFalse(args.coupled_state)
        from conformance.whole import build
        with self.assertRaises(ValueError):
            build(args)


class RelationSliceTests(unittest.TestCase):
    def test_module_splits_into_function_bodies(self):
        self.assertEqual([name for name, _ in functions(MODULE)], ["plain", "coupled"])

    def test_data_tagged_stores_identify_the_encoded_data_word(self):
        self.assertEqual(data_context_words(MODULE), {"sre.value.context"})

    def test_slice_recovers_only_the_words_a_dispatcher_reads(self):
        bodies = dict(functions(MODULE))
        plain = Body(bodies["plain"]).slice(["fla.multi.token"])
        coupled = Body(bodies["coupled"]).slice(["fla.multi.token"])
        self.assertEqual(plain["words"], {"fla.multi.key", "fla.multi.salt"})
        self.assertEqual(coupled["words"],
                         {"fla.multi.key", "fla.multi.salt", "sre.value.context"})
        self.assertGreater(coupled["visited"], plain["visited"])


class ArmReportTests(unittest.TestCase):
    def report(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "protected.ll"
            module.write_text(MODULE)
            out = Path(directory) / "relation.json"
            self.assertEqual(main([str(module), "--out", str(out), "--trials", "16"]), 0)
            return json.loads(out.read_text())

    def test_all_three_arms_are_reported(self):
        arms = self.report()["arms"]
        self.assertEqual(set(arms), {"supplied_relation", "inferred_relation", "canonical_repair"})

    def test_the_frozen_relation_transfers_only_where_no_data_word_is_read(self):
        report = self.report()
        rows = {row["function"]: row for row in report["functions"]}
        self.assertTrue(rows["plain"]["frozen_v02_relation_transfers"])
        self.assertFalse(rows["coupled"]["frozen_v02_relation_transfers"])
        repair = report["arms"]["canonical_repair"]
        self.assertEqual(repair["functions_where_frozen_relation_fails"], 1)
        self.assertEqual(repair["functions_where_frozen_relation_transfers"], 1)
        # Every word is software state, so the repair itself is never blocked.
        self.assertTrue(repair["repairable"])

    def test_the_supplied_arm_reports_residual_cost_not_a_win(self):
        supplied = self.report()["arms"]["supplied_relation"]
        self.assertFalse(supplied["search_required"])
        self.assertEqual(supplied["inversion"], "closed-form-modular-inverse")
        self.assertIn("sre.value.context", supplied["words_required"])

    def test_lane_coupling_gate_fails_when_no_dispatcher_reads_data(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "protected.ll"
            module.write_text(MODULE.split("define dso_local i32 @coupled")[0] + "\n!0 = !{!\"data\"}\n")
            out = Path(directory) / "relation.json"
            self.assertEqual(main([str(module), "--out", str(out), "--trials", "8",
                                   "--require-lane-coupling"]), 1)


class LaneCoverageTests(unittest.TestCase):
    def report(self, rows, lane=1):
        return {"schema": "sre-native-v3", "features": {"lane_transitions": lane},
                "flattening_state": rows}

    def test_denominator_counts_only_couplable_functions(self):
        rows = [{"function": "main", "words": 3, "coupled_data_updates": 0,
                 "coupled_control_updates": 0, "lane_keyed_dispatcher_reads": 0},
                {"function": "producer", "words": 3, "coupled_data_updates": 66,
                 "coupled_control_updates": 13, "lane_keyed_dispatcher_reads": 2}]
        measured = lane_coverage(self.report(rows))
        self.assertEqual(measured["flattened_functions"], 2)
        self.assertEqual(measured["couplable_flattened_functions"], 1)
        self.assertEqual(measured["lane_keyed_functions"], 1)
        self.assertEqual(measured["lane_keyed_dispatcher_reads"], 2)

    def test_a_flattened_function_without_encoded_data_cannot_be_coupled(self):
        rows = [{"function": "main", "words": 3, "coupled_data_updates": 0,
                 "coupled_control_updates": 0, "lane_keyed_dispatcher_reads": 0}]
        measured = lane_coverage(self.report(rows))
        self.assertEqual(measured["couplable_flattened_functions"], 0)
        self.assertEqual(measured["lane_keyed_dispatcher_reads"], 0)

    def test_an_older_report_leaves_the_numerator_unknown(self):
        rows = [{"function": "main", "words": 3, "coupled_data_updates": 4,
                 "coupled_control_updates": 1}]
        measured = lane_coverage(self.report(rows))
        self.assertIsNone(measured["lane_keyed_dispatcher_reads"])
        self.assertIsNone(measured["lane_keyed_functions"])
        # Unknown must not satisfy a requested gate.
        self.assertFalse(bool(measured["lane_keyed_dispatcher_reads"]))


class ReferenceRelationTests(unittest.TestCase):
    def test_every_family_round_trips_for_any_key_and_salt(self):
        for family in (0, 1, 2):
            for label, key, salt in ((0, 0, 0), (1, 2, 3), (0xffffffff, 0x9e3779b9, 0)):
                token = state_model.encode(label, key, salt, family)
                self.assertEqual(state_model.recover(token, key, salt, family), label)

    def test_a_lane_keyed_relation_is_a_relabelling_of_the_same_family(self):
        """Mixing a further word in keeps the encoding bijective in the label."""
        for family in (0, 1, 2):
            lane = 0x0badc0de
            key, salt = 0x1234, 0x5678
            mixed_key = (key + lane) & state_model.MASK
            mixed_salt = salt ^ state_model.rol(lane, 13)
            labels = {state_model.encode(l, mixed_key, mixed_salt, family) for l in range(64)}
            self.assertEqual(len(labels), 64)
            # Without the lane word the frozen relation decodes a different label.
            token = state_model.encode(7, mixed_key, mixed_salt, family)
            self.assertNotEqual(state_model.recover(token, key, salt, family), 7)


if __name__ == "__main__":
    unittest.main()
