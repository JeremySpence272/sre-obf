import argparse
import copy
import itertools
import random
import unittest

from conformance import bundle_options
from conformance.bundle_model import Descriptor, FAMILIES
from conformance.tile_check import tile_summary, tile_violations


def valid_report():
    def access(kind, index, initial=False):
        return {"kind": kind, "index": index, "initializer": initial, "input_origin": "",
                "bounds": "constant" if index is not None else "known-bits-nonnegative-in-range"}
    accesses = [access("store", 0, True), access("store", 1, True),
                access("load", None), access("load", 1), access("store", None),
                access("load", 0), access("load", 1)]
    plan = {"width": 8, "cells": 2, "family": FAMILIES[0], "salts_hex": ["a7", "19"],
            "rotations": [3, 5], "physical_slots": [1, 0], "law": "closed-initialized-tile-v1",
            "phase_mode": "static", "ownership": "closed-entry-alloca",
            "initialization": "complete-entry-stores-dominate-accesses", "source_loads": 4,
            "source_stores": 3, "dynamic_accesses": 2, "physical_loads": 15, "physical_stores": 6,
            "scalar_input_values": 2, "scalar_output_values": 2, "scalar_output_uses": 2,
            "scalar_address_uses": 0, "accesses": accesses,
            "steps": [{"opcode": "xor", "input_origin": ""} for _ in range(6)]}
    row = {"schema": "sre-object-bundle-v1", "function": "f", "object": 0, "status": "encoded",
           "reason": "", "growth_allocation": 10400, "module_growth_limit": 12000,
           "attempted_operations": 6, "retained_operations": 6, "rolled_back_operations": 0,
           "pins": True, "hardness_evaluated": False, "plan": plan,
           "instructions_before": 40, "instructions_after": 1000, "attempted_instructions": 1000}
    return {"features": {"bundles": True, "object_bundles": True}, "object_bundles": [row]}


class TileReports(unittest.TestCase):
    def test_valid_and_summary(self):
        data = valid_report()
        self.assertEqual(tile_violations(data), [])
        summary = tile_summary(data)
        self.assertEqual(summary["retained_objects"], 1)
        self.assertEqual(summary["retained_source_loads"], 4)
        self.assertIsNone(summary["final_surviving_semantic_coverage"])

    def test_row_mutations(self):
        for key, value in (("schema", "unknown"), ("retained_operations", 7), ("object", -1),
                           ("rolled_back_operations", 1), ("growth_allocation", 10399),
                           ("module_growth_limit", 100), ("status", "other"), ("reason", "secret"),
                           ("hardness_evaluated", True), ("instructions_after", 20000), ("pins", 1)):
            with self.subTest(key=key):
                data = valid_report()
                data["object_bundles"][0][key] = value
                self.assertTrue(tile_violations(data))

    def test_plan_mutations(self):
        for key, value in (("physical_slots", [0, 0]), ("phase_mode", "magic"), ("cells", 3),
                           ("initialization", "assumed"), ("ownership", "escaped"), ("source_loads", 1),
                           ("physical_loads", 12), ("physical_stores", 3), ("source_stores", 2),
                           ("scalar_input_values", -1), ("scalar_address_uses", 3),
                           ("scalar_output_values", 3), ("dynamic_accesses", 0)):
            with self.subTest(key=key):
                data = valid_report()
                data["object_bundles"][0]["plan"][key] = value
                self.assertTrue(tile_violations(data))

    def test_initialization_and_bounds_mutations(self):
        for k, key, value in ((0, "index", 1), (1, "initializer", False),
                              (0, "kind", "load"), (2, "bounds", "inbounds-is-enough"),
                              (3, "index", -1), (3, "index", 2)):
            data = valid_report()
            data["object_bundles"][0]["plan"]["accesses"][k][key] = value
            self.assertTrue(tile_violations(data))

    def test_duplicate_owner_and_inventory(self):
        data = valid_report()
        data["object_bundles"].append(copy.deepcopy(data["object_bundles"][0]))
        self.assertTrue(tile_violations(data))
        data["object_bundles"][1]["object"] = 1
        self.assertTrue(tile_violations(data))
        data = valid_report()
        data["features"]["object_bundles"] = False
        self.assertTrue(tile_violations(data))
        data["features"]["object_bundles"] = True
        del data["object_bundles"]
        self.assertTrue(tile_violations(data))

    def test_ancestry_is_validated_and_unknown_is_not_zero_source_work(self):
        data = valid_report()
        step = data["object_bundles"][0]["plan"]["steps"][0]
        step["input_origin"] = "f/input-op/4"
        self.assertTrue(tile_violations(data))
        data["bundle_input_inventory"] = [{"function": "f", "instructions": 20}]
        self.assertEqual(tile_violations(data), [])
        summary = tile_summary(data)
        self.assertEqual(summary["retained_unique_operation_ancestry"], 1)
        self.assertEqual(summary["retained_operations_without_ancestry"], 5)
        step["input_origin"] = "f/input-op/20"
        self.assertTrue(tile_violations(data))

    def test_restored_rollback(self):
        data = valid_report()
        row = data["object_bundles"][0]
        row.update(status="rolled-back", reason="growth-budget", retained_operations=0,
                   rolled_back_operations=6, instructions_after=40, attempted_instructions=11000)
        self.assertEqual(tile_violations(data), [])
        self.assertEqual(tile_summary(data)["retained_objects"], 0)
        row["instructions_after"] = 41
        self.assertTrue(tile_violations(data))

    def test_skipped_contract(self):
        data = valid_report()
        row = data["object_bundles"][0]
        row.update(status="skipped", reason="unproved-index", growth_allocation=0,
                   attempted_operations=0, retained_operations=0)
        del row["plan"]
        self.assertEqual(tile_violations(data), [])
        row["reason"] = "ignored"
        self.assertTrue(tile_violations(data))

    def test_option_dependencies_and_roundtrip(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        with self.assertRaises(ValueError):
            bundle_options.validate(parser.parse_args(["--object-bundles"]), True)
        args = parser.parse_args(["--bundles", "--object-bundles", "--no-bundle-pins"])
        bundle_options.validate(args, True)
        self.assertIn("-native-object-bundles=1", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))

    def test_owner_is_not_whole_function_protection(self):
        from conformance.scale import source_ledger
        data = valid_report()
        data["input_inventory"] = {"functions": [{"function": "f", "instructions": 40}]}
        data["functions"] = [{"function": "f", "selected": True}]
        ledger = source_ledger(data)
        self.assertEqual(ledger["object_bundle_owners"], 1)
        self.assertEqual(ledger["functions"]["encoded"], 1)
        self.assertEqual(ledger["bundle_owners"], 0)


class TileAlgebra(unittest.TestCase):
    def test_all_small_states_and_stores(self):
        # Independent replacement law. Exhaustive at reduced width, random at
        # production widths; does not claim the compiler lowering is proved.
        for family in FAMILIES:
            d = Descriptor(2, family, (1, 3), (1, 1))
            for values in itertools.product(range(4), repeat=2):
                for carrier, slot, value in itertools.product(range(4), range(2), range(4)):
                    self.check_store(d, values, carrier, slot, value, 3)

    def check_store(self, d, values, carrier, slot, value, key):
        old = d.encode(values, carrier)
        pair = ((value + key) & d.bits, key) if d.additive else (value ^ key, key)
        new = []
        for k in range(len(values)):
            e, r = pair if k == slot else (old[k], d.mask(old, carrier, k))
            m = d.mask(new, carrier, k)
            new.append(((e + m - r) if d.additive else (e ^ r ^ m)) & d.bits)
        expected = list(values)
        expected[slot] = value
        self.assertEqual(d.decode(new, carrier), tuple(expected))

    def test_random_all_widths_and_cells(self):
        rng = random.Random(5813)
        for width, n, family in itertools.product((8, 16, 32, 64), (2, 3, 4), FAMILIES):
            d = Descriptor(width, family, tuple(rng.getrandbits(width) for _ in range(n)),
                           tuple(rng.randrange(1, width) for _ in range(n)))
            for _ in range(64):
                self.check_store(d, [rng.getrandbits(width) for _ in range(n)], rng.getrandbits(width),
                                 rng.randrange(n), rng.getrandbits(width), rng.getrandbits(width))


if __name__ == "__main__":
    unittest.main()
