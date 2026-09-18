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


def lifetime_report():
    data = valid_report()
    data["features"]["object_bundle_contract"] = 2
    plan = data["object_bundles"][0]["plan"]
    plan.update(vector_output_values=0, vector_output_uses=0, decoded_vector_lanes=0)
    for access in plan["accesses"]: access["elements"] = 1
    plan["lifetime"] = {"contract": "sre-tile-lifetime-v1", "mode": "single-entry",
                        "source_starts": 1, "source_ends": 2, "translated_markers": 3,
                        "proof": "start-dominates-accesses-no-access-or-marker-reachable-after-end"}
    return data


class TileLifetimes(unittest.TestCase):
    def test_complete_single_entry_and_unmarked_contracts(self):
        data = lifetime_report()
        self.assertEqual(tile_violations(data), [])
        self.assertEqual(tile_summary(data)["lifetime_owned_objects"], 1)
        self.assertEqual(tile_summary(data)["translated_lifetime_markers"], 3)
        life = data["object_bundles"][0]["plan"]["lifetime"]
        life.update(mode="whole-function", source_starts=0, source_ends=0, translated_markers=0)
        self.assertEqual(tile_violations(data), [])

    def test_missing_modern_proofs(self):
        for key in ("lifetime", "vector_output_values", "vector_output_uses", "decoded_vector_lanes"):
            data = lifetime_report()
            del data["object_bundles"][0]["plan"][key]
            self.assertTrue(tile_violations(data), key)
        data = lifetime_report()
        del data["object_bundles"][0]["plan"]["accesses"][0]["elements"]
        self.assertTrue(tile_violations(data))
        data["features"]["object_bundle_contract"] = 99
        self.assertTrue(tile_violations(data))

    def test_lifetime_mutations(self):
        for key, value in (("mode", "restarted"), ("proof", "assumed"), ("contract", "unknown"),
                           ("source_starts", 0), ("source_starts", 2), ("source_ends", 9),
                           ("source_ends", -1), ("translated_markers", 0)):
            data = lifetime_report()
            data["object_bundles"][0]["plan"]["lifetime"][key] = value
            self.assertTrue(tile_violations(data), key)

    def test_vector_boundary_is_not_scalar_or_encoded_operation_credit(self):
        data = lifetime_report()
        plan = data["object_bundles"][0]["plan"]
        plan["accesses"][-2]["elements"] = 2
        plan.update(vector_output_values=1, vector_output_uses=1, decoded_vector_lanes=2)
        self.assertEqual(tile_violations(data), [])
        self.assertEqual(tile_summary(data)["decoded_vector_lanes"], 2)
        self.assertEqual(tile_summary(data)["retained_operations"], 6)
        for key in ("vector_output_values", "decoded_vector_lanes"):
            changed = copy.deepcopy(data)
            changed["object_bundles"][0]["plan"][key] = 0
            self.assertTrue(tile_violations(changed), key)

    def test_vector_span_must_be_whole_elements_and_proved_in_bounds(self):
        for index, span in ((0, 0), (0, 3), (1, 2), (None, 2)):
            data = lifetime_report()
            plan = data["object_bundles"][0]["plan"]
            plan["accesses"][-2].update(index=index, elements=span)
            self.assertTrue(tile_violations(data))
        data = lifetime_report()
        data["object_bundles"][0]["plan"]["accesses"][0]["elements"] = 2
        self.assertTrue(tile_violations(data))

    def test_source_fixture_oracle_wraps_at_each_word_width(self):
        from conformance.tile_run import c_oracle
        for width in (32, 64):
            mask = (1 << width) - 1
            for a, b in ((0, 0), (mask, mask), (mask, 16), (1 << (width - 1), mask - 1)):
                out = c_oracle(a, b, width)
                self.assertTrue(all(0 <= x <= mask for x in out))
                self.assertEqual(out[2:], [a ^ b, 0])

    def test_narrow_index_oracle_preserves_all_other_cells(self):
        from conformance.tile_run import fixture, oracle
        for shape in ("narrow-index", "narrow-constant"):
            self.assertIn("i32 0, i1 ", fixture(8, 4, shape))
            self.assertEqual(oracle(7, 3, 8, 4, shape)[1:], [8, 9, 10])


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


class TilePhases(unittest.TestCase):
    def test_exhaustive_small_phase_transfer(self):
        from conformance.tile_model import store
        for family in FAMILIES:
            d = Descriptor(2, family, (1, 3), (1, 1))
            for values in itertools.product(range(4), repeat=2):
                for m, phase, slot, value, key in itertools.product(range(4), range(2), range(2), range(4), range(4)):
                    pair = ((value + key) & 3, key) if d.additive else (value ^ key, key)
                    new, carrier, next_phase = store(d, d.encode(values, m), m, phase, slot, pair)
                    expected = list(values)
                    expected[slot] = value
                    self.assertEqual(d.decode(new, carrier), tuple(expected))
                    self.assertEqual(next_phase, phase ^ 1)

    def test_layouts_and_history_all_production_widths(self):
        from conformance.tile_model import layout, store
        rng = random.Random(314159)
        for width, n, family in itertools.product((8, 16, 32, 64), (2, 3, 4), FAMILIES):
            physical = rng.sample(range(n), n)
            for p in (0, 1): self.assertEqual(sorted(layout(physical, p)), list(range(n)))
            self.assertNotEqual(layout(physical, 0), layout(physical, 1))
            d = Descriptor(width, family, tuple(rng.getrandbits(width) for _ in range(n)),
                           tuple(rng.randrange(1, width) for _ in range(n)))
            values = [rng.getrandbits(width) for _ in range(n)]
            carrier, phase = rng.getrandbits(width), 0
            state = d.encode(values, carrier)
            for _ in range(64):
                slot, value, key = rng.randrange(n), rng.getrandbits(width), rng.getrandbits(width)
                pair = ((value + key) & d.bits, key) if d.additive else (value ^ key, key)
                state, carrier, phase = store(d, state, carrier, phase, slot, pair)
                values[slot] = value
                self.assertEqual(d.decode(state, carrier), tuple(values))
                memory = [0] * n
                for k, physical_slot in enumerate(layout(physical, phase)): memory[physical_slot] = state[k]
                loaded = tuple(memory[j] for j in layout(physical, phase))
                self.assertEqual(d.decode(loaded, carrier), tuple(values))

    def test_phase_report_fails_closed(self):
        data = lifetime_report()
        data["features"].update(object_bundle_contract=3, object_phases=True)
        row = data["object_bundles"][0]
        plan = row["plan"]
        plan.update(phase_mode="store-toggle-v1", physical_loads=20, physical_stores=8,
                    phase_contract={"states": 2, "entry": 0, "transition": "toggle-after-update",
                        "carrier": "history-and-encoded-update-v1", "layout": "rotate-logical-slots-by-phase",
                        "static_update_sites": 1, "bytes_reencoded_per_update": 4})
        row["growth_allocation"] += 64 * 7 * 4
        row["module_growth_limit"] = 20000
        self.assertEqual(tile_violations(data), [])
        self.assertEqual(tile_summary(data)["phase_update_sites"], 1)
        for key, value in (("entry", 1), ("static_update_sites", 2), ("bytes_reencoded_per_update", 2)):
            bad = copy.deepcopy(data)
            bad["object_bundles"][0]["plan"]["phase_contract"][key] = value
            self.assertTrue(tile_violations(bad))
        data["features"]["object_phases"] = False
        self.assertTrue(tile_violations(data))

    def test_phase_option_dependency_and_roundtrip(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        with self.assertRaises(ValueError):
            bundle_options.validate(parser.parse_args(["--bundles", "--object-phases"]), True)
        args = parser.parse_args(["--bundles", "--object-bundles", "--object-phases"])
        bundle_options.validate(args, True)
        self.assertIn("-native-object-phases=1", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))


if __name__ == "__main__":
    unittest.main()
