import argparse
import copy
import itertools
import unittest

from conformance import bundle_options
from conformance.bundle_check import bundle_summary, bundle_violations
from conformance.bundle_loop_run import scalar_trace, vectors
from conformance.bundle_model import FAMILIES, replay_loop
from conformance.test_bundle_loops import loop_report


def join_report(exposed=False):
    data = loop_report(True)
    data["features"]["bundle_loop_boundaries"] = exposed
    row = data["bundles"][0]
    row["loop_boundaries"] = exposed
    row["regions"][0]["loop"].update(
        contract="sre-bundle-loop-v2", graph_scope="dominated-header-recurrence",
        next_input_slots=[], backedge_uses=4,
        backedges=[{"id": 0, "predecessor_block": 4, "next_input_slots": [1, 0]},
                   {"id": 1, "predecessor_block": 5, "next_input_slots": [0, 1]}],
        scalar_input_uses=2 if exposed else 0, scalar_input_slots=[0] if exposed else [])
    return data


class JoinReports(unittest.TestCase):
    def test_edge_counts_are_not_region_counts(self):
        data = join_report()
        self.assertEqual(bundle_violations(data), [])
        summary = bundle_summary(data)
        self.assertEqual(summary["persistent_loop_regions"], 1)
        self.assertEqual(summary["persistent_backedges"], 2)
        self.assertEqual(summary["two_phase_backedges"], 2)
        self.assertEqual(summary["multi_backedge_joins"], 1)
        self.assertEqual(summary["encoded_recurrence_uses"], 4)
        self.assertEqual(summary["scalar_header_input_uses"], 0)

    def test_exposure_is_explicit_not_full_lifetime_coverage(self):
        data = join_report(True)
        self.assertEqual(bundle_violations(data), [])
        summary = bundle_summary(data)
        self.assertEqual(summary["scalar_header_input_uses"], 2)
        self.assertEqual(summary["loop_regions_with_scalar_projections"], 1)
        self.assertIsNone(summary["final_surviving_semantic_coverage"])
        data["features"]["bundle_loop_boundaries"] = False
        data["bundles"][0]["loop_boundaries"] = False
        self.assertTrue(bundle_violations(data))

    def test_exposure_contract_mutations(self):
        for key, value in (("scalar_input_slots", [0, 0]), ("scalar_input_slots", [7]),
                           ("scalar_input_slots", []), ("scalar_input_uses", 0),
                           ("scalar_input_uses", -1), ("contract", "unknown"),
                           ("graph_scope", "whole-program")):
            data = join_report(True)
            data["bundles"][0]["regions"][0]["loop"][key] = value
            self.assertTrue(bundle_violations(data), key)

    def test_backedge_contract_mutations(self):
        for key, value in (("id", 7), ("predecessor_block", 4),
                           ("predecessor_block", -1), ("next_input_slots", [9, 0]),
                           ("next_input_slots", [0])):
            data = join_report()
            data["bundles"][0]["regions"][0]["loop"]["backedges"][1][key] = value
            self.assertTrue(bundle_violations(data), key)
        for key, value in (("backedge_uses", 2), ("backedges", []), ("next_input_slots", [1, 0])):
            data = join_report()
            data["bundles"][0]["regions"][0]["loop"][key] = value
            self.assertTrue(bundle_violations(data), key)

    def test_one_edge_compatibility_alias_must_match(self):
        data = join_report()
        loop = data["bundles"][0]["regions"][0]["loop"]
        loop.update(backedges=loop["backedges"][:1], backedge_uses=2, next_input_slots=[1, 0])
        self.assertEqual(bundle_violations(data), [])
        loop["next_input_slots"] = [0, 1]
        self.assertTrue(bundle_violations(data))

    def test_bounded_edges_and_rollback(self):
        data = join_report()
        row = data["bundles"][0]
        loop = row["regions"][0]["loop"]
        loop["backedges"] = [{"id": k, "predecessor_block": k + 4, "next_input_slots": [1, 0]} for k in range(5)]
        loop["backedge_uses"] = 10
        self.assertTrue(bundle_violations(data))
        data = join_report(True)
        row = data["bundles"][0]
        row.update(status="rolled-back", retained_operations=0, rolled_back_operations=8,
                   regions_scope="attempted", instructions_after=20)
        self.assertEqual(bundle_violations(data), [])
        summary = bundle_summary(data)
        self.assertEqual(summary["persistent_backedges"], 0)
        self.assertEqual(summary["scalar_header_input_uses"], 0)

    def test_options_cannot_hide_projection_mode(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        for args in (["--bundle-loop-boundaries"], ["--bundles", "--bundle-loop-boundaries"]):
            with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(args), True)
        args = parser.parse_args(["--bundles", "--bundle-loops", "--bundle-loop-boundaries"])
        bundle_options.validate(args, True)
        self.assertIn("-native-bundle-loop-boundaries=1", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))


class JoinReplay(unittest.TestCase):
    def test_all_short_edge_paths_both_families_and_phases(self):
        # The fixture plan's four XOR-one operations per slot are identity.
        # Only the chosen edge permutes the next logical inputs.
        for family, phases in itertools.product(FAMILIES, (False, True)):
            region = join_report()["bundles"][0]["regions"][0]
            region["family"] = family
            region["loop"]["phase_mode"] = "two-phase" if phases else "static"
            for count in range(6):
                for path in itertools.product((0, 1), repeat=count):
                    expected = (19, 237)
                    for edge in path[:-1]:
                        if edge == 0: expected = expected[::-1]
                    self.assertEqual(replay_loop(region, [19, 237], count, path), expected)

    def test_wrong_path_and_unsupplied_path_are_not_successes(self):
        region = join_report()["bundles"][0]["regions"][0]
        self.assertEqual(replay_loop(region, [19, 237], 0), (19, 237))
        with self.assertRaises(ValueError): replay_loop(region, [19, 237], 3)
        for path in ([0], [0, 7], [False, 1]):
            with self.assertRaises(ValueError): replay_loop(region, [19, 237], 2, path)
        self.assertNotEqual(replay_loop(region, [19, 237], 2, [0, 0]),
                            replay_loop(region, [19, 237], 2, [1, 0]))
        broken = copy.deepcopy(region)
        broken["loop"]["backedges"][0]["next_input_slots"] = [0, 1]
        self.assertNotEqual(replay_loop(region, [19, 237], 2, [0, 0]),
                            replay_loop(broken, [19, 237], 2, [0, 0]))

    def test_source_workload_reaches_both_join_paths(self):
        for width in (8, 16, 32, 64):
            reached = set()
            early = False
            for a, b, count in vectors(width):
                _, _, path = scalar_trace(a, b, count, width, "multi-latch")
                reached.update(path[:-1])  # The final exit does not take a backedge.
                _, _, path = scalar_trace(a, b, count, width, "multi-exit")
                early |= len(path) < count
            self.assertEqual(reached, {0, 1})
            self.assertTrue(early)


if __name__ == "__main__":
    unittest.main()
