import argparse
import copy
import itertools
import importlib.util
import random
import unittest

from conformance import bundle_options, state_model
from conformance.bundle_control import bundle_control_summary, bundle_control_violations, keys
from conformance.test_bundle_loops import loop_report


def control_report(phases=False):
    data = loop_report(phases)
    data["features"].update(bundle_control=True, multistate=True)
    roles = ["state0", "state1", "carrier"] + (["phase"] if phases else [])
    words = [{"role": role, "width": 8, "initialized_before_all_reads": True,
              "dispatcher_reads": 3, "transition_reads": 7, "useful_reads": 2,
              "data_store_sites": 3, "unclassified_accesses": 0} for role in roles]
    data["bundle_control"] = [{"function": "f", "contract": "persistent-bundle-control-v1",
        "stage": "final-ir", "requested_regions": 1, "bound_origin": "f/native-bundle/0",
        "status": "coupled", "reason": "", "words": words, "hardness_evaluated": False,
        **{key: sum(w[key] for w in words) for key in ("dispatcher_reads", "transition_reads", "useful_reads")}}]
    return data


class ControlReports(unittest.TestCase):
    def test_both_phases_and_actual_counts(self):
        for phases in (False, True):
            data = control_report(phases)
            self.assertEqual(bundle_control_violations(data), [])
            summary = bundle_control_summary(data)
            self.assertEqual(summary["live_words"], 4 if phases else 3)
            self.assertEqual(summary["coupled_functions"], 1)
            self.assertFalse(summary["hardness_evaluated"])

    def test_missing_zero_or_uninitialized_word_fails(self):
        for field, value in (("width", 16), ("initialized_before_all_reads", False),
                             ("dispatcher_reads", 0), ("transition_reads", 0),
                             ("useful_reads", 0), ("data_store_sites", 0),
                             ("unclassified_accesses", 1), ("role", "mirror")):
            data = control_report(True)
            data["bundle_control"][0]["words"][1][field] = value
            self.assertTrue(bundle_control_violations(data), field)
        for mutation in (lambda words: words.pop(), lambda words: words.reverse()):
            data = control_report(True)
            mutation(data["bundle_control"][0]["words"])
            self.assertTrue(bundle_control_violations(data))

    def test_phase_origin_denominator_and_totals_fail_closed(self):
        for field, value in (("contract", "future"), ("stage", "before-flattening"),
                             ("requested_regions", 0), ("requested_regions", True),
                             ("bound_origin", "f/native-bundle/1"), ("status", "invalid"),
                             ("hardness_evaluated", True), ("dispatcher_reads", 1),
                             ("transition_reads", 1), ("useful_reads", 1), ("reason", "guessed")):
            data = control_report(True)
            data["bundle_control"][0][field] = value
            self.assertTrue(bundle_control_violations(data), field)
        data = control_report(True)
        data["bundles"][0]["regions"][0]["loop"]["phase_mode"] = "static"
        self.assertTrue(bundle_control_violations(data))

    def test_control_reads_must_cover_complete_tuple(self):
        for key in ("dispatcher_reads", "transition_reads"):
            data = control_report(True)
            data["bundle_control"][0]["words"][0][key] += 1
            data["bundle_control"][0][key] += 1
            self.assertTrue(bundle_control_violations(data), key)

    def test_exact_owner_set_and_feature_dependencies(self):
        for name in ("bundles", "bundle_loops", "multistate", "bundle_control"):
            data = control_report()
            data["features"][name] = False
            self.assertTrue(bundle_control_violations(data), name)
        for mode in ("duplicate", "missing", "unknown"):
            data = control_report()
            if mode == "duplicate": data["bundle_control"] *= 2
            elif mode == "missing": data["bundle_control"] = []
            else: data["bundle_control"][0]["function"] = "invented"
            self.assertTrue(bundle_control_violations(data), mode)
        self.assertEqual(bundle_control_violations({}), [])
        self.assertIsNone(bundle_control_summary({}))

    def test_unavailable_and_rollback_never_claim_coupling(self):
        for retained in (False, True):
            data = control_report()
            if not retained: data["bundles"][0]["status"] = "rolled-back"
            row = data["bundle_control"][0]
            row.update(status="unavailable", requested_regions=int(retained), words=[], bound_origin="",
                       dispatcher_reads=0, transition_reads=0, useful_reads=0,
                       reason="no-retained-complete-control-contract" if retained else "no-selected-persistent-loop")
            self.assertEqual(bundle_control_violations(data), [])
            self.assertEqual(bundle_control_summary(data)["coupled_functions"], 0)
            for field, value in (("useful_reads", 1), ("useful_reads", None), ("transition_reads", False),
                                 ("words", None), ("bound_origin", None), ("bound_origin", "f/native-bundle/0"),
                                 ("requested_regions", int(not retained))):
                wrong = copy.deepcopy(data)
                wrong["bundle_control"][0][field] = value
                self.assertTrue(bundle_control_violations(wrong), field)

    def test_option_dependencies_and_roundtrip(self):
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        for bad in (["--bundle-control"], ["--bundles", "--bundle-control"]):
            with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(bad), True)
        args = parser.parse_args(["--bundles", "--bundle-loops", "--bundle-control"])
        bundle_options.validate(args, True)
        self.assertIn("-native-bundle-control=1", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))
        args.no_multistate = True
        with self.assertRaises(ValueError): bundle_options.validate(args, True)


class KnownRelationControls(unittest.TestCase):
    def test_supplied_relation_repairs_every_family(self):
        # Successful repair is expected. Failure of the stale script alone is
        # not resistance, and no binary interface discovery is measured here.
        rng = random.Random(944)
        for width, count, family in itertools.product((8, 16, 32, 64), (3, 4), range(3)):
            stale_failures = 0
            for _ in range(64):
                label, key, salt = [rng.getrandbits(32) for _ in range(3)]
                words = [rng.getrandbits(width) for _ in range(count)]
                live_key, live_salt = keys(key, salt, words, width)
                token = state_model.encode(label, live_key, live_salt, family)
                self.assertEqual(state_model.recover(token, live_key, live_salt, family), label)
                stale_failures += state_model.recover(token, key, salt, family) != label
            self.assertGreater(stale_failures, 0)

    def test_each_word_and_high_half_can_affect_relation(self):
        for width, count in itertools.product((8, 16, 32, 64), (3, 4)):
            words = [0] * count
            baseline = keys(7, 13, words, width)
            for index in range(count):
                for bit in (0, width - 1):
                    changed = words.copy()
                    changed[index] = 1 << bit
                    self.assertNotEqual(keys(7, 13, changed, width), baseline)

    def test_known_folding_collision_is_not_secret_entropy(self):
        # The 64-to-32 fold deliberately has collisions. Do not claim an
        # injective relation or 64 bits of entropy per participating word.
        self.assertEqual(keys(7, 13, [0, 0, 0], 64),
                         keys(7, 13, [(1 << 32) | 1, 0, 0], 64))

    def test_reject_unsupported_model_contracts(self):
        for width, count in ((1, 3), (128, 4), (32, 2), (32, 5)):
            with self.assertRaises(ValueError): keys(0, 0, [0] * count, width)


def proof_fixture():
    """Small supplied-interface positive control, not compiler coverage."""
    report = control_report()
    row = report["bundle_control"][0]
    row.update(dispatcher_reads=3, transition_reads=3)
    for word in row["words"]:
        word.update(width=32, dispatcher_reads=1, transition_reads=1)
    report["bundles"][0]["regions"][0]["width"] = 32
    lines = ["define void @f(i32 %key, i32 %salt) {", "entry:"]
    for i in range(3): lines.append(f"  %p{i} = alloca i32, align 4, !sre.native.bundle.control-bound !{i}")
    for kind, tag in (("d", 3), ("t", 4)):
        key, salt = "%key", "%salt"
        for i in range(3):
            x = f"%{kind}{i}"
            next_key, next_salt = f"%sre.bundle.control.key.{kind}{i}", f"%sre.bundle.control.salt.{kind}{i}"
            lines += [f"  {x} = load volatile i32, ptr %p{i}, align 4, !sre.native.bundle.control-read !{tag}",
                      f"  {x}a = shl i32 {x}, {5 + 7 * i}", f"  {x}b = lshr i32 {x}, {27 - 7 * i}",
                      f"  {x}c = or i32 {x}a, {x}b", f"  {x}e = xor i32 {x}c, {(0x9e3779b9 * (i + 1)) & 0xffffffff}",
                      f"  {next_key} = add i32 {key}, {x}e",
                      f"  {x}g = shl i32 {x}, {3 + 5 * i}", f"  {x}h = lshr i32 {x}, {29 - 5 * i}",
                      f"  {x}j = or i32 {x}g, {x}h", f"  {x}m = mul i32 {x}, {0x85ebca6b + 2 * i}",
                      f"  {x}n = add i32 {x}j, {x}m", f"  {next_salt} = xor i32 {salt}, {x}n"]
            key, salt = next_key, next_salt
    lines += ["  ret void", "}"]
    for i, role in enumerate(("state0", "state1", "carrier")):
        lines.append(f'!{i} = !{{!"f/native-bundle/0", !"{role}", i1 false}}')
    lines += ['!3 = !{!"dispatcher"}', '!4 = !{!"transition"}']
    return "\n".join(lines), report


@unittest.skipUnless(importlib.util.find_spec("z3"), "emitted relation proof requires pinned solver image")
class EmittedRelationProof(unittest.TestCase):
    def test_supplied_positive_and_wrong_constant(self):
        from conformance.bundle_control_proof import validate
        text, report = proof_fixture()
        results = validate(text, report)
        self.assertEqual([r["status"] for r in results], ["proved", "proved"])
        wrong = text.replace(str(0x9e3779b9), str(0x9e3779b8), 1)
        results = validate(wrong, report)
        self.assertEqual([r["status"] for r in results], ["counterexample", "proved"])

    def test_unsupported_or_incomplete_slices_do_not_pass(self):
        from conformance.bundle_control_proof import validate
        text, report = proof_fixture()
        for wrong in (text.replace("shl i32 %d0, 5", "shl i32 %d0, 32"),
                      text.replace("load volatile i32", "load i32", 1),
                      text.replace("ptr %p0,", "ptr %p1,", 1),
                      text.replace("xor i32 %salt, %d0n", "xor i32 %unknown, %missing"),
                      text.replace("%sre.bundle.control.salt.t2", "%not_an_endpoint")):
            with self.assertRaises((ValueError, KeyError)): validate(wrong, report)
        with self.assertRaises(ValueError): validate(text, {})

    def test_independent_integer_and_symbolic_models_agree(self):
        import z3
        from conformance.bundle_control_proof import symbolic_keys
        rng = random.Random(947)
        for width, count in itertools.product((8, 16, 32, 64), (3, 4)):
            for _ in range(16):
                key, salt = rng.getrandbits(32), rng.getrandbits(32)
                words = [rng.getrandbits(width) for _ in range(count)]
                a, b = symbolic_keys(z3.BitVecVal(key, 32), z3.BitVecVal(salt, 32),
                                     [z3.BitVecVal(w, width) for w in words], z3)
                self.assertEqual((z3.simplify(a).as_long(), z3.simplify(b).as_long()), keys(key, salt, words, width))


if __name__ == "__main__":
    unittest.main()
