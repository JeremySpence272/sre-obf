import itertools
import random
import unittest
import argparse
import importlib.util
from conformance.bundle_model import Descriptor, FAMILIES, OPCODES, pair_operation, scalar
from conformance.bundle_check import bundle_summary, bundle_violations
from conformance import bundle_options


def valid_report():
    steps = [{"opcode": "xor", "destination": n % 2,
              "x": {"slot": n % 2}, "y": {"constant_hex": "1"},
              "input_origin": f"f/input-op/{n}"} for n in range(8)]
    region = {"id": 0, "width": 8, "lanes": 2, "family": FAMILIES[0],
              "salts_hex": ["35", "91"], "rotations": [3, 5],
              "inputs": 2, "outputs": 2, "output_slots": [0, 1], "steps": steps,
              "useful_operations": 8, "estimated_cost": 9856}
    row = {"function": "f", "schema": "sre-bundle-plan-v1", "eligible_operations": 10,
           "retained_operations": 8, "unselected_operations": 2, "rolled_back_operations": 0,
           "attempted_operations": 8, "status": "encoded", "regions_scope": "retained",
           "estimated_cost": 9856, "growth_allocation": 10000,
           "instructions_before": 20, "instructions_after": 900, "regions": [region]}
    return {"features": {"bundles": True}, "bundle_input_inventory": [{"function": "f", "instructions": 20}],
            "bundles": [row]}


class BundleReports(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(bundle_violations(valid_report()), [])

    def test_accounting_and_descriptor_mutations(self):
        changes = [("eligible_operations", 11), ("retained_operations", 7),
                   ("estimated_cost", 9800), ("growth_allocation", 8000),
                   ("regions_scope", "attempted"), ("instructions_after", 50000)]
        for key, value in changes:
            data = valid_report()
            data["bundles"][0][key] = value
            self.assertTrue(bundle_violations(data), key)
        for field, value in (("outputs", 1), ("output_slots", [0, 0]),
                             ("useful_operations", 9), ("id", 7)):
            data = valid_report()
            data["bundles"][0]["regions"][0][field] = value
            self.assertTrue(bundle_violations(data), field)

    def test_invalid_origin_and_shift(self):
        for mutation in ({"input_origin": "invented/input-op/0"},
                         {"input_origin": "f/input-op/30"},
                         {"opcode": "shl", "y": {"constant_hex": "8"}},
                         {"opcode": "shl", "y": {"slot": 1}}):
            data = valid_report()
            data["bundles"][0]["regions"][0]["steps"][0].update(mutation)
            self.assertTrue(bundle_violations(data))

    def test_rollback_has_no_retained_work(self):
        data = valid_report()
        row = data["bundles"][0]
        row.update(status="rolled-back", retained_operations=0, rolled_back_operations=8,
                   regions_scope="attempted", instructions_after=20)
        self.assertEqual(bundle_violations(data), [])
        row["retained_operations"] = 8
        self.assertTrue(bundle_violations(data))

    def test_missing_report_and_disabled_feature(self):
        data = valid_report()
        del data["bundle_input_inventory"]
        self.assertTrue(bundle_violations(data))

    def test_coherent_allocations_respect_module_cap(self):
        data = valid_report()
        data["bundles"][0]["module_growth_limit"] = 10000
        self.assertEqual(bundle_violations(data), [])
        data["bundles"][0]["module_growth_limit"] = 9999
        self.assertTrue(bundle_violations(data))

    def test_ancestry_is_deduplicated_and_missing_ancestry_stays_unknown(self):
        data = valid_report()
        steps = data["bundles"][0]["regions"][0]["steps"]
        steps[1]["input_origin"] = steps[0]["input_origin"]
        steps[2]["input_origin"] = None
        measured = bundle_summary(data)
        self.assertEqual(measured["retained_step_instances"], 8)
        self.assertEqual(measured["retained_unique_input_ancestry_ids"], 6)
        self.assertEqual(measured["retained_steps_without_input_ancestry"], 1)
        self.assertIsNone(measured["final_surviving_semantic_coverage"])

    def test_bundle_owner_counts_as_selected_region_not_whole_body_protection(self):
        from conformance.scale import source_ledger
        data = valid_report()
        data["input_inventory"] = {"functions": [{"function": "f", "instructions": 20}]}
        data["functions"] = [{"function": "f", "selected": True}]
        ledger = source_ledger(data)
        self.assertEqual(ledger["functions"]["encoded"], 1)
        self.assertEqual(ledger["bundle_owners"], 1)
        self.assertEqual(ledger["untouched_by_either_pass"], 0)
        data = valid_report()
        data["features"]["bundles"] = False
        self.assertTrue(bundle_violations(data))

    def test_shared_options(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        args = parser.parse_args([])
        bundle_options.validate(args, False)
        self.assertEqual(bundle_options.flags(args), [])
        for bad in (["--bundle-values", "3"], ["--no-bundle-pins"], ["--transfer-family", "xor"]):
            with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(bad), True)
        args = parser.parse_args(["--bundles", "--transfer-family", "additive", "--no-bundle-pins"])
        with self.assertRaises(ValueError): bundle_options.validate(args, False)
        bundle_options.validate(args, True)
        roundtrip = parser.parse_args(bundle_options.argv(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(roundtrip))


@unittest.skipUnless(importlib.util.find_spec("z3"), "emitter proof tests require pinned solver image")
class BundleEmitterValidation(unittest.TestCase):
    CLEAN = """define i8 @kernel(i8 %a, i8 %b) {
entry:
  %x = add i8 %a, %b
  ret i8 %x
}
"""

    def test_known_equivalent_and_counterexample_controls(self):
        from conformance.bundle_lift import validate
        self.assertEqual(validate(self.CLEAN, self.CLEAN, "kernel", 8, 1000)["status"], "proved")
        wrong = self.CLEAN.replace("add i8", "sub i8")
        self.assertEqual(validate(self.CLEAN, wrong, "kernel", 8, 1000)["status"], "counterexample")

    def test_unknown_instruction_fails_closed(self):
        from conformance.bundle_lift import validate
        for replacement in ("udiv i8", "add nsw i8", "call i8"):
            with self.assertRaises(ValueError):
                validate(self.CLEAN, self.CLEAN.replace("add i8", replacement), "kernel", 8, 1000)

    def test_owned_storage_forwarding_requires_initialization(self):
        from conformance.bundle_lift import validate
        emitted = self.CLEAN.replace("  ret i8 %x", """  %s = alloca [2 x i8], align 1, !sre.native.bundle !0
  %p = getelementptr inbounds [2 x i8], ptr %s, i32 0, i32 1, !sre.native.bundle !0
  store volatile i8 %x, ptr %p, align 1, !sre.native.bundle !0
  %r = load volatile i8, ptr %p, align 1, !sre.native.bundle !0
  ret i8 %r""")
        self.assertEqual(validate(self.CLEAN, emitted, "kernel", 8, 1000)["status"], "proved")
        with self.assertRaises(ValueError):
            validate(self.CLEAN, emitted.replace(", !sre.native.bundle !0", ""), "kernel", 8, 1000)
        with self.assertRaises(ValueError):
            validate(self.CLEAN, emitted.replace("  store volatile i8 %x, ptr %p, align 1, !sre.native.bundle !0\n", ""),
                     "kernel", 8, 1000)


class BundleLaws(unittest.TestCase):
    def test_complete_small_domain_roundtrip(self):
        for family in FAMILIES:
            d = Descriptor(2, family, (1, 3), (1, 1))
            for carrier in range(4):
                encoded = set()
                for values in itertools.product(range(4), repeat=2):
                    state = d.encode(values, carrier)
                    self.assertEqual(d.decode(state, carrier), values)
                    encoded.add(state)
                self.assertEqual(len(encoded), 16)

    def test_pair_operations_exhaustive_two_bit(self):
        for additive in (False, True):
            for a, b, r, s, fresh in itertools.product(range(4), repeat=5):
                x = ((a + r if additive else a ^ r) & 3, r)
                y = ((b + s if additive else b ^ s) & 3, s)
                for op in OPCODES[:6]:
                    out = pair_operation(op, x, y, 2, additive, fresh)
                    decoded = (out[0] - out[1] if additive else out[0] ^ out[1]) & 3
                    self.assertEqual(decoded, scalar(op, a, b, 2))

    def test_all_widths_and_destination_repairs(self):
        rng = random.Random(917)
        for width, family, lanes in itertools.product((8, 16, 32, 64), FAMILIES, (2, 3, 4)):
            d = Descriptor(width, family, tuple(rng.getrandbits(width) for _ in range(lanes)),
                           tuple(rng.randrange(1, width) for _ in range(lanes)))
            for _ in range(24):
                values = tuple(rng.getrandbits(width) for _ in range(lanes))
                carrier = rng.getrandbits(width)
                state = d.encode(values, carrier)
                self.assertEqual(d.decode(state, carrier), values)
                for dest in range(lanes):
                    for op in OPCODES:
                        x = {"slot": rng.randrange(lanes)}
                        y = ({"constant_hex": format(rng.choice((0, width - 1)), "x")}
                             if op in ("shl", "lshr", "ashr") else {"slot": rng.randrange(lanes)})
                        rhs = int(y["constant_hex"], 16) if "constant_hex" in y else values[y["slot"]]
                        expected = list(values)
                        expected[dest] = scalar(op, values[x["slot"]], rhs, width)
                        new = d.update(state, carrier, dest, op, x, y)
                        self.assertEqual(d.decode(new, carrier), tuple(expected))

    def test_descriptor_and_shift_rejections(self):
        with self.assertRaises(ValueError): Descriptor(8, FAMILIES[0], (1, 2), (8, 1))
        with self.assertRaises(ValueError): Descriptor(8, "unknown", (1, 2), (1, 1))
        for shift in (-1, 8, 64):
            for op in ("shl", "lshr", "ashr"):
                with self.assertRaises(ValueError): scalar(op, 1, shift, 8)

    def test_stale_downstream_relation_is_not_a_valid_update(self):
        # Negative control: changing the first coordinate without repairing its
        # successor must be distinguishable. This is not a hardness result.
        for family in FAMILIES:
            d = Descriptor(8, family, (53, 137), (3, 5))
            old = d.encode((11, 73), 39)
            updated = d.update(old, 39, 0, "add", {"slot": 0}, {"constant_hex": "7"})
            self.assertNotEqual(d.decode((updated[0], old[1]), 39), (18, 73))


if __name__ == "__main__":
    unittest.main()
