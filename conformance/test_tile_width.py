"""Explicit larger-tile experiment; four-cell default and budgets stay fixed."""
import argparse
import copy
import itertools
import random
import unittest

from conformance import bundle_options
from conformance.bundle_model import Descriptor, FAMILIES
from conformance.test_tile import lifetime_report
from conformance.tile_check import tile_violations
from conformance.tile_model import layout, store
from conformance.tile_run import fixture, index_mask, oracle


def wide_report(cells=8, phases=False):
    data = lifetime_report()
    data["features"].update(object_bundle_contract=4, object_max_cells=8, object_phases=phases)
    row = data["object_bundles"][0]
    row.update(max_cells=8, module_growth_limit=65536)
    plan = row["plan"]
    def access(kind, index, initial=False):
        return dict(kind=kind, index=index, initializer=initial, elements=1,
                    input_origin="", bounds="constant" if index is not None else
                    "known-bits-nonnegative-in-range")
    accesses = ([access("store", k, True) for k in range(cells)] +
                [access("load", None), access("load", cells - 1), access("store", None)] +
                [access("load", k) for k in range(cells)])
    lanes = cells + 1 + int(phases)
    plan.update(cells=cells, salts_hex=[format(k + 17, "x") for k in range(cells)],
                rotations=[1 + k % 7 for k in range(cells)], physical_slots=list(reversed(range(cells))),
                accesses=accesses, source_loads=cells + 2, source_stores=cells + 1,
                physical_loads=(cells + 3) * lanes, physical_stores=2 * lanes,
                scalar_output_values=cells, scalar_output_uses=cells,
                phase_mode="store-toggle-v1" if phases else "static",
                phase_contract={"states": 2 if phases else 1, "entry": 0,
                    "transition": "toggle-after-update" if phases else "identity",
                    "carrier": "history-and-encoded-update-v1" if phases else "entry-only",
                    "layout": "rotate-logical-slots-by-phase" if phases else "seeded-permutation",
                    "static_update_sites": int(phases), "bytes_reencoded_per_update": lanes if phases else 0})
    row["growth_allocation"] = (512 + 6 * 1200 + len(accesses) * cells * 192 +
                                (64 * len(accesses) * (cells + 2) if phases else 0))
    return data


class WideTiles(unittest.TestCase):
    def test_model_requires_explicit_opt_in(self):
        for n in range(5, 9):
            with self.assertRaises(ValueError): Descriptor(8, FAMILIES[0], (1,) * n, (1,) * n)
            self.assertEqual(len(Descriptor(8, FAMILIES[0], (1,) * n, (1,) * n, max_lanes=8).salts), n)
        for ceiling in (0, 5, 9):
            with self.assertRaises(ValueError): Descriptor(8, FAMILIES[0], (1, 2), (1, 1), max_lanes=ceiling)

    def test_update_history_and_layout_all_wide_shapes(self):
        rng = random.Random(81473)
        for width, n, family in itertools.product((8, 16, 32, 64), range(5, 9), FAMILIES):
            d = Descriptor(width, family, tuple(rng.getrandbits(width) for _ in range(n)),
                           tuple(rng.randrange(1, width) for _ in range(n)), max_lanes=8)
            physical = rng.sample(range(n), n)
            values = [rng.getrandbits(width) for _ in range(n)]
            m, phase = rng.getrandbits(width), 0
            state = d.encode(values, m)
            stale_failed = False
            for i in range(32):
                slot, value, key = i % n, rng.getrandbits(width), rng.getrandbits(width)
                pair = ((value + key) & d.bits, key) if d.additive else (value ^ key, key)
                old_m = m
                state, m, phase = store(d, state, m, phase, slot, pair)
                values[slot] = value
                self.assertEqual(d.decode(state, m), tuple(values))
                stale_failed |= d.decode(state, old_m) != tuple(values)
                slots = layout(physical, phase)
                self.assertEqual(sorted(slots), list(range(n)))
                memory = [0] * n
                for k, p in enumerate(slots): memory[p] = state[k]
                self.assertEqual(d.decode(tuple(memory[p] for p in slots), m), tuple(values))
            self.assertTrue(stale_failed)
            # Known descriptors/relation must still invert; they are not secrets.
            next_slots = tuple(reversed(range(n)))
            rebased = d.rebase(state, m, next_slots, 7)
            self.assertEqual(d.decode(rebased, 7), tuple(reversed(values)))

    def test_versioned_policy_and_unchanged_cost(self):
        for n, phases in itertools.product(range(5, 9), (False, True)):
            data = wide_report(n, phases)
            self.assertEqual(tile_violations(data), [])
            self.assertLessEqual(data["object_bundles"][0]["growth_allocation"], 65536)
            for key, value in (("object_max_cells", 4), ("object_max_cells", 9),
                               ("object_bundle_contract", 3), ("object_bundles", False)):
                bad = copy.deepcopy(data)
                bad["features"][key] = value
                self.assertTrue(tile_violations(bad), (key, value))
            for key, value in (("max_cells", 4), ("max_cells", 8.0), ("growth_allocation", 65537),
                               ("module_growth_limit", 1)):
                bad = copy.deepcopy(data)
                bad["object_bundles"][0][key] = value
                self.assertTrue(tile_violations(bad), (key, value))
            del data["features"]["object_max_cells"]
            self.assertTrue(tile_violations(data))

    def test_default_fixtures_unchanged_and_all_wide_outputs_observed(self):
        for n in (2, 3, 4): self.assertEqual(fixture(32, n), fixture(32, n, max_cells=4))
        for n in range(5, 9):
            with self.assertRaises(ValueError): fixture(32, n)
            ir = fixture(32, n, max_cells=8)
            self.assertEqual(ir.count("store i64 "), n)
            self.assertEqual(len(oracle(19, 37, 32, n)), n)
            for k in range(n): self.assertIn(f"%r{k} = load i32, ptr %p{k}", ir)
        self.assertEqual(index_mask(8), 7)
        self.assertEqual(index_mask(6), 3)
        # For non-power-of-two shapes the unreachable update tail is still observed.
        self.assertEqual(oracle(19, 37, 32, 6)[4:], [23, 24])

    def test_shared_cli_roundtrip_and_dependency(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        default = parser.parse_args(["--bundles", "--object-bundles"])
        self.assertNotIn("-native-object-max-cells=8", bundle_options.flags(default))
        for tokens in (["--object-max-cells", "8"], ["--bundles", "--object-max-cells", "8"]):
            with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(tokens), True)
        args = parser.parse_args(["--bundles", "--object-bundles", "--object-max-cells", "8"])
        bundle_options.validate(args, True)
        self.assertIn("-native-object-max-cells=8", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))
