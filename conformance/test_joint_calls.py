import argparse
import copy
import itertools
import random
import unittest

from conformance import bundle_options
from conformance.bundle_model import Descriptor, FAMILIES
from conformance.joint_call_check import joint_call_summary, joint_call_violations
from conformance.recursive_run import fixture
from conformance.joint_call_controls import fixture as control_fixture, oracle as control_oracle


def report():
    return {"features": {"bundles": True, "encoded_calls": True, "joint_call_arguments": True},
            "encoded_calls": [{"function": "f", "status": "encoded", "parameters": 3,
                "argument_widths": [8, 8, 8], "call_sites_rewritten": 2,
                "representation": "triangular-xor-arguments-v1",
                "joint_arguments": {"contract": "triangular-call-arguments-v1", "status": "joint", "reason": "",
                    "abi_words": 4, "mask_reservation": 72, "mask_instructions": 63,
                    "descriptor": {"width": 8, "family": FAMILIES[0], "salts_hex": ["a7", "39", "e1"],
                                   "rotations": [1, 3, 5]}}}]}


class JointCalls(unittest.TestCase):
    def test_report_and_summary(self):
        self.assertEqual(joint_call_violations(report()), [])
        summary = joint_call_summary(report())
        self.assertEqual(summary["abi_argument_words"], 8)
        self.assertEqual(summary["joint_source_parameters"], 3)
        self.assertFalse(summary["hardness_evaluated"])

    def test_fail_closed_contract_and_costs(self):
        for key, value in (("contract", "unknown"), ("status", "paired-fallback"), ("reason", "secret"),
                           ("abi_words", 6), ("mask_reservation", 73), ("mask_reservation", True),
                           ("mask_instructions", 0), ("mask_instructions", 64), ("mask_instructions", True)):
            data = report(); data["encoded_calls"][0]["joint_arguments"][key] = value
            self.assertTrue(joint_call_violations(data), key)
        for key, value in (("width", 16), ("family", FAMILIES[1]), ("rotations", [1, 3, 8]),
                           ("salts_hex", ["a7", "39"])):
            data = report(); data["encoded_calls"][0]["joint_arguments"]["descriptor"][key] = value
            self.assertTrue(joint_call_violations(data), key)

    def test_missing_disabled_and_skipped(self):
        for key in ("bundles", "encoded_calls", "joint_call_arguments"):
            data = report(); data["features"][key] = False
            self.assertTrue(joint_call_violations(data), key)
        data = report(); del data["encoded_calls"][0]["joint_arguments"]
        self.assertTrue(joint_call_violations(data))
        data = report(); data["encoded_calls"][0]["status"] = "skipped"
        self.assertTrue(joint_call_violations(data))

    def test_pair_fallbacks_keep_denominators(self):
        for widths, sites, reason in (([8], 2, "argument-count"), ([8] * 5, 2, "argument-count"),
                                      ([8, 16], 2, "mixed-argument-widths"), ([8, 8], 9, "call-site-limit")):
            data = report(); row = data["encoded_calls"][0]
            row.update(parameters=len(widths), argument_widths=widths, call_sites_rewritten=sites, representation="xor-pair-v1")
            row["joint_arguments"] = dict(contract="triangular-call-arguments-v1", status="paired-fallback",
                reason=reason, abi_words=2 * len(widths), mask_reservation=0, mask_instructions=0)
            self.assertEqual(joint_call_violations(data), [], reason)
            self.assertEqual(joint_call_summary(data)["joint_interfaces"], 0)
            bad = copy.deepcopy(data); bad["encoded_calls"][0]["joint_arguments"]["mask_instructions"] = 1
            self.assertTrue(joint_call_violations(bad))

    def test_known_descriptor_inverse_and_direct_supplies(self):
        # Independent scalar oracle versus direct pair remasking. Every lane's
        # mask is rebuilt from the already supplied predecessor coordinate.
        rng = random.Random(73821)
        for width, n in itertools.product((8, 16, 32, 64), (2, 3, 4)):
            d = Descriptor(width, FAMILIES[0], tuple(rng.getrandbits(width) for _ in range(n)),
                           tuple(rng.randrange(1, width) for _ in range(n)))
            for _ in range(64):
                values = tuple(rng.getrandbits(width) for _ in range(n))
                carrier = rng.getrandbits(width)
                supplied = []
                for k, value in enumerate(values):
                    key = rng.getrandbits(width)
                    e, r = value ^ key, key
                    supplied.append(e ^ r ^ d.mask(supplied, carrier, k))
                self.assertEqual(tuple(supplied), d.encode(values, carrier))
                self.assertEqual(d.decode(supplied, carrier), values)

    def test_shared_cli_and_typed_recursion_fixture(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--encoded-calls", action="store_true")
        bundle_options.add_options(parser)
        for tokens in (["--joint-call-arguments"], ["--bundles", "--joint-call-arguments"]):
            with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(tokens), True)
        args = parser.parse_args(["--bundles", "--encoded-calls", "--joint-call-arguments"])
        bundle_options.validate(args, True)
        self.assertIn("-native-joint-call-arguments=1", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))
        for w in (8, 16, 32, 64):
            ir = fixture(w, homogeneous=True)
            self.assertIn(f"@recur(i{w} %x, i{w} %y, i{w} %depth)", ir)
            self.assertIn(f"%next = sub i{w} %depth, 1", ir)
            self.assertNotIn("trunc i64 %d0 to i64", ir)
        with self.assertRaises(ValueError): fixture(8, drop_unused_depth=True)
        ir = fixture(8, straight_line=True, drop_unused_depth=True)
        self.assertIn('@recur(i8 %x, i8 %y)', ir)
        self.assertNotIn(', i32 %depth', ir)

    def test_control_oracle_counts_all_arguments_and_sites(self):
        self.assertEqual(control_oracle(10, 20, 8, 4, 2), 136)
        self.assertEqual(control_oracle(255, 255, 8, 2, 2), 256)
        self.assertEqual(control_oracle(10, 20, 32, 0, 9), 63)
        self.assertEqual(control_fixture(32, 4, 9).count('call i32 @subject('), 9)


def emitted_example():
    data = report()
    data['encoded_calls'][0]['encoded_function'] = 'f.sre.encoded'
    lines = ['define i8 @f.sre.encoded(i8 %e0, i8 %e1, i8 %e2, i8 %m) {', 'entry:']
    for k, (salt, rotation) in enumerate(((167, 1), (57, 3), (225, 5))):
        prev = f'%e{k - 1}' if k else '%m'
        lines += [f'  %a{k} = xor i8 {prev}, {salt}', f'  %b{k} = add i8 %a{k}, %m',
                  f'  %c{k} = shl i8 %b{k}, {rotation}', f'  %d{k} = lshr i8 %b{k}, {8 - rotation}',
                  f'  %f{k} = or i8 %c{k}, %d{k}', f'  %g{k} = mul i8 {prev}, {salt | 1}',
                  f'  %r{k} = xor i8 %f{k}, %g{k}', f'  %x{k} = xor i8 %e{k}, %r{k}, !sre.native.call.arg !0']
    return '\n'.join(lines + ['  ret i8 %x2', '}', '!0 = !{}']) + '\n', data


class EmittedJointMasks(unittest.TestCase):
    def test_actual_slice_positive_and_wrong_law(self):
        from conformance.joint_call_proof import validate
        text, data = emitted_example()
        self.assertTrue(all(row['status'] == 'proved' for row in validate(text, data)))
        changed = text.replace('%g1 = mul', '%g1 = add')
        self.assertIn('counterexample', [row['status'] for row in validate(changed, data)])

    def test_unknown_flags_wrong_roots_and_missing_abi_rejected(self):
        from conformance.joint_call_proof import validate
        text, data = emitted_example()
        for changed in (text.replace('add i8 %a0', 'add nuw i8 %a0'),
                        text.replace('%x1 = xor i8 %e1', '%x1 = xor i8 %e0'),
                        text.replace('i8 %m)', 'i16 %m)'),
                        text.replace('%c0 = shl i8 %b0, 1', '%c0 = shl i8 %b0, 8'),
                        text.replace(', !sre.native.call.arg !0', '', 1)):
            with self.assertRaises(ValueError): validate(changed, data)
