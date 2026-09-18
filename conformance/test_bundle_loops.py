import argparse
import copy
import importlib.util
import itertools
import random
import unittest

from conformance import bundle_options
from conformance.bundle_check import bundle_summary, bundle_violations
from conformance.bundle_model import Descriptor, FAMILIES, replay_loop
from conformance.test_bundle import valid_report


def loop_report(phases=False):
    data = valid_report()
    data["features"].update(bundle_loops=True, bundle_phases=phases)
    row = data["bundles"][0]
    row.update(loops=True, phases=phases)
    row["regions"][0]["loop"] = {
        "status": "encoded", "reason": "", "law": "triangular-recurrence-rebase-v1",
        "phase_mode": "two-phase" if phases else "static", "phase_count": 2 if phases else 1,
        "initial_phase": 0, "backedge_uses": 2, "scalar_input_uses": 0, "next_input_slots": [1, 0],
    }
    return data


class LoopReports(unittest.TestCase):
    def test_both_phase_modes_and_summary(self):
        for phases in (False, True):
            data = loop_report(phases)
            self.assertEqual(bundle_violations(data), [])
            summary = bundle_summary(data)
            self.assertEqual(summary["persistent_backedges"], 1)
            self.assertEqual(summary["encoded_recurrence_uses"], 2)
            self.assertEqual(summary["two_phase_backedges"], int(phases))

    def test_phase_and_recurrence_mutations_fail(self):
        for key, value in (("status", "claimed"), ("reason", "unsupported"), ("law", "unknown"),
                           ("phase_mode", "static"), ("phase_count", 3), ("initial_phase", 1),
                           ("backedge_uses", 0), ("scalar_input_uses", 1), ("next_input_slots", [7, 0])):
            data = loop_report(True)
            data["bundles"][0]["regions"][0]["loop"][key] = value
            self.assertTrue(bundle_violations(data), key)
        data = loop_report(True)
        del data["bundles"][0]["regions"][0]["loop"]
        self.assertTrue(bundle_violations(data))
        data = loop_report(True)
        data["features"]["bundle_loops"] = False
        self.assertTrue(bundle_violations(data))

    def test_fallback_cannot_claim_continuity(self):
        data = loop_report(True)
        loop = data["bundles"][0]["regions"][0]["loop"]
        loop.update(status="straight-line", reason="recurrence-has-external-users", next_input_slots=[],
                    backedge_uses=0, phase_mode="static", phase_count=1)
        self.assertEqual(bundle_violations(data), [])
        self.assertEqual(bundle_summary(data)["persistent_backedges"], 0)
        for reason in ("unknown", "disabled"):
            wrong = copy.deepcopy(data)
            wrong["bundles"][0]["regions"][0]["loop"]["reason"] = reason
            self.assertTrue(bundle_violations(wrong))
        loop["next_input_slots"] = [0, 1]
        self.assertTrue(bundle_violations(data))

    def test_rollback_retains_no_backedge_coverage(self):
        data = loop_report(True)
        row = data["bundles"][0]
        row.update(status="rolled-back", retained_operations=0, rolled_back_operations=8,
                   regions_scope="attempted", instructions_after=20)
        self.assertEqual(bundle_violations(data), [])
        self.assertEqual(bundle_summary(data)["persistent_backedges"], 0)

    def test_flag_dependencies_and_roundtrip(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        for bad in (["--bundle-loops"], ["--bundle-phases"], ["--bundles", "--bundle-phases"]):
            with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(bad), True)
        args = parser.parse_args(["--bundles", "--bundle-loops", "--bundle-phases", "--no-bundle-pins"])
        bundle_options.validate(args, True)
        self.assertIn("-native-bundle-phases=1", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))


class LoopLaws(unittest.TestCase):
    def test_complete_tiny_domain_arbitrary_rekey_and_permutation(self):
        for family in FAMILIES:
            d = Descriptor(2, family, (1, 3), (1, 1))
            for a, b, carrier, new_carrier in itertools.product(range(4), repeat=4):
                values = a, b
                state = d.encode(values, carrier)
                for mapping in ((0, 1), (1, 0), (1, 1)):
                    rebased = d.rebase(state, carrier, mapping, new_carrier)
                    self.assertEqual(d.decode(rebased, new_carrier), tuple(values[k] for k in mapping))

    def test_all_widths_all_slots_random_rebases(self):
        rng = random.Random(926)
        for width, family, lanes in itertools.product((8, 16, 32, 64), FAMILIES, (2, 3, 4)):
            d = Descriptor(width, family, tuple(rng.getrandbits(width) for _ in range(lanes)),
                           tuple(rng.randrange(1, width) for _ in range(lanes)))
            for _ in range(32):
                values = tuple(rng.getrandbits(width) for _ in range(lanes))
                carrier = rng.getrandbits(width)
                state = d.encode(values, carrier)
                mapping = [rng.randrange(lanes) for _ in range(rng.randrange(2, lanes + 1))]
                for phase in (0, 1):
                    next_carrier = d.next_carrier(state, carrier, phase)
                    rebased = d.rebase(state, carrier, mapping, next_carrier)
                    expected = tuple(values[k] for k in mapping) + (0,) * (lanes - len(mapping))
                    self.assertEqual(d.decode(rebased, next_carrier), expected)

    def test_known_descriptor_unlocks_both_phases(self):
        # An informed semantic inverse succeeds. This must not be a hardness pass.
        for phases in (False, True):
            region = loop_report(phases)["bundles"][0]["regions"][0]
            for count in (0, 1, 2, 3, 17):
                # Four XOR-one updates per slot are identity; backedge swaps them.
                expected = (19, 237) if count == 0 or count % 2 else (237, 19)
                self.assertEqual(replay_loop(region, [19, 237], count), expected)

    def test_stale_masks_and_mapping_are_detectable(self):
        region = loop_report(True)["bundles"][0]["regions"][0]
        wrong = copy.deepcopy(region)
        wrong["loop"]["next_input_slots"] = [0, 1]
        self.assertNotEqual(replay_loop(region, [19, 237], 2), replay_loop(wrong, [19, 237], 2))
        for family in FAMILIES:
            d = Descriptor(8, family, (53, 145), (3, 5))
            state = d.encode((19, 237), 71)
            self.assertNotEqual(d.decode(state, d.next_carrier(state, 71, 0)), (19, 237))


@unittest.skipUnless(importlib.util.find_spec("z3"), "rebase proof requires pinned solver image")
class LoopRebaseProof(unittest.TestCase):
    def test_arbitrary_old_and_new_masks(self):
        import z3
        for width in (8, 16, 32, 64):
            e, old, new = z3.BitVecs("e old new", width)
            for output, expected in (((e ^ (old ^ new)) ^ new, e ^ old),
                                     (((e + new) - old) - new, e - old)):
                solver = z3.Solver()
                solver.set(timeout=1000)
                solver.add(output != expected)
                self.assertEqual(solver.check(), z3.unsat)

    def test_straightline_emitter_validator_refuses_loops(self):
        from conformance.bundle_lift import validate
        source = "define i8 @kernel(i8 %a, i8 %b) {\nentry:\n  br label %entry\n}\n"
        with self.assertRaises(ValueError): validate(source, source, "kernel", 8, 1000)


if __name__ == "__main__":
    unittest.main()
