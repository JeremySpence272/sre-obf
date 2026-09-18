import argparse
import importlib.util
import itertools
import random
import unittest

from conformance import bundle_options
from conformance.bundle_model import Descriptor, FAMILIES
from conformance.bundle_predicates import predicate, predicate_summary, predicate_violations
from conformance.test_bundle import valid_report


def predicate_report():
    report = valid_report()
    report["features"]["bundle_predicates"] = True
    region = report["bundles"][0]["regions"][0]
    region.update(scalar_output_uses=3, predicate_operand_uses=2, predicate_reservation=1024,
                  predicates=[{"id": 0, "mode": "all-equal", "input_origin": "f/input-op/13",
                    "source_operand_uses": 2, "tree_instructions": 3, "law": "exact-tuple-replacement-v1",
                    "targets": [{"output": k, "slot": k, "constant_hex": "a", "input_origin": f"f/input-op/{11+k}"} for k in range(2)]}])
    report["bundle_predicates"] = [{"function": "f", "origin": "f/native-bundle/0", "id": 0,
        "source_operand_uses": 2, "live_consumers": 1, "contract": "joint-predicate-v1",
        "stage": "after-bundles-before-regions", "hardness_evaluated": False}]
    return report


class PredicateReports(unittest.TestCase):
    def test_valid_and_source_boundary_summary(self):
        report = predicate_report()
        self.assertEqual(predicate_violations(report), [])
        summary = predicate_summary(report)
        self.assertEqual(summary["absorbed_data_uses"], 2)
        self.assertEqual(summary["remaining_scalar_data_uses"], 1)
        self.assertFalse(summary["hardness_evaluated"])

    def test_descriptor_mutations_fail(self):
        for field, value in (("id", 1), ("mode", "hash"), ("law", "checksum"),
                             ("source_operand_uses", 1), ("tree_instructions", 2), ("input_origin", "f/input-op/999")):
            data = predicate_report()
            data["bundles"][0]["regions"][0]["predicates"][0][field] = value
            self.assertTrue(predicate_violations(data), field)
        for field, value in (("output", 0), ("slot", 0), ("constant_hex", "100")):
            data = predicate_report()
            data["bundles"][0]["regions"][0]["predicates"][0]["targets"][1][field] = value
            self.assertTrue(predicate_violations(data), field)

    def test_counts_and_rollback_fail_closed(self):
        for field, value in (("predicate_operand_uses", 1), ("predicate_reservation", 0), ("scalar_output_uses", 1)):
            data = predicate_report()
            data["bundles"][0]["regions"][0][field] = value
            self.assertTrue(predicate_violations(data), field)
        data = predicate_report()
        data["bundles"][0]["status"] = "rolled-back"
        self.assertTrue(predicate_violations(data))
        data["bundle_predicates"] = []
        self.assertEqual(predicate_violations(data), [])
        self.assertEqual(predicate_summary(data)["roots"], 0)

    def test_actual_root_and_disabled_controls(self):
        for field, value in (("contract", "wrong"), ("stage", "unknown"), ("live_consumers", 0),
                             ("id", 7), ("source_operand_uses", 1), ("hardness_evaluated", True)):
            data = predicate_report()
            data["bundle_predicates"][0][field] = value
            self.assertTrue(predicate_violations(data), field)
        for mode in ("missing", "duplicate", "disabled"):
            data = predicate_report()
            if mode == "missing": data["bundle_predicates"] = []
            elif mode == "duplicate": data["bundle_predicates"] *= 2
            else: data["features"]["bundle_predicates"] = False
            self.assertTrue(predicate_violations(data), mode)
        self.assertEqual(predicate_violations({}), [])

    def test_option_contract(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(["--bundle-predicates"]), True)
        args = parser.parse_args(["--bundles", "--bundle-predicates"])
        bundle_options.validate(args, True)
        self.assertIn("-native-bundle-predicates=1", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))


class ExactPredicateLaws(unittest.TestCase):
    def test_compound_early_exit_preserves_zero_trip_and_stops_on_match(self):
        from conformance.bundle_loop_run import scalar_trace
        for width in (8, 16, 32, 64):
            out, _, edges = scalar_trace(19, 37, 0, width, "predicate-exit")
            self.assertEqual(out, (19, 37))
            self.assertEqual(edges, [])
            expected = scalar_trace(19, 37, 1, width)[0]
            for count in (1, 2, 7):
                out, _, edges = scalar_trace(19, 37, count, width, "predicate-exit")
                self.assertEqual(out, expected)
                self.assertEqual(len(edges), 1)

    def test_complete_tiny_two_value_domain(self):
        for family in FAMILIES:
            d = Descriptor(2, family, (1, 3), (1, 1))
            for a, b, x, y, carrier in itertools.product(range(4), repeat=5):
                state = d.encode((a, b), carrier)
                self.assertEqual(predicate(d, state, carrier, {0: x, 1: y}), (a, b) == (x, y))
                self.assertEqual(predicate(d, state, carrier, {0: x, 1: y}, "any-different"), (a, b) != (x, y))

    def test_all_widths_sparse_targets_positive_and_adjacent_negative(self):
        rng = random.Random(951)
        for width, lanes, family in itertools.product((8, 16, 32, 64), (2, 3, 4), FAMILIES):
            d = Descriptor(width, family, tuple(rng.getrandbits(width) for _ in range(lanes)),
                           tuple(rng.randrange(1, width) for _ in range(lanes)))
            for _ in range(16):
                values = [rng.getrandbits(width) for _ in range(lanes)]
                carrier = rng.getrandbits(width)
                state = d.encode(values, carrier)
                targets = {k: values[k] for k in rng.sample(range(lanes), 2)}
                self.assertTrue(predicate(d, state, carrier, targets))
                for k in targets:
                    wrong = dict(targets)
                    wrong[k] ^= 1
                    self.assertFalse(predicate(d, state, carrier, wrong))
                # Supplied descriptor recovery intentionally succeeds.
                self.assertEqual(d.decode(state, carrier), tuple(values))

    def test_target_validation(self):
        d = Descriptor(8, FAMILIES[0], (53, 145), (3, 5))
        for targets in ({0: 1}, {0: 1, 2: 0}, {0: 256, 1: 0}):
            with self.assertRaises(ValueError): predicate(d, (0, 0), 0, targets)


@unittest.skipUnless(importlib.util.find_spec("z3"), "exact residual proof requires pinned solver image")
class ResidualProof(unittest.TestCase):
    def test_lifted_comparison_controls_and_counterexample(self):
        from conformance.bundle_lift import validate
        source = "define i8 @kernel(i8 %a, i8 %b) {\nentry:\n  %p = icmp eq i8 %a, %b\n  %r = zext i1 %p to i8\n  ret i8 %r\n}\n"
        self.assertEqual(validate(source, source, "kernel", 8, 1000)["status"], "proved")
        self.assertEqual(validate(source, source.replace("icmp eq", "icmp ne"), "kernel", 8, 1000)["status"], "counterexample")
        with self.assertRaises(ValueError): validate(source, source.replace("icmp eq", "icmp ugt"), "kernel", 8, 1000)

    def test_full_width_reduction_has_no_collision(self):
        import z3
        for width, count in itertools.product((8, 16, 32, 64), (2, 3, 4)):
            values = z3.BitVecs(" ".join(f"r{k}" for k in range(count)), width)
            transformed, combined = [], z3.BitVecVal(0, width)
            for k, value in enumerate(values):
                transformed.append(value ^ z3.RotateLeft(transformed[-1], 1 + k % (width - 1)) if k else value)
                combined |= transformed[-1]
            solver = z3.SolverFor("QF_BV")
            solver.set(timeout=1000)
            solver.add((combined == 0) != z3.And([v == 0 for v in values]))
            self.assertEqual(solver.check(), z3.unsat)


if __name__ == "__main__":
    unittest.main()
