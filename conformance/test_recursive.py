import unittest

from conformance.connected_check import call_violations
from conformance.recursive_run import fixture, oracle


def report():
    return {"schema": "sre-native-v6", "features": {"encoded_calls": True, "self_recursion": True},
        "encoded_calls": [{"function": "f", "status": "encoded", "reason": "", "parameters": 3,
            "encoded_parameters": 3, "callers": 2, "call_sites_rewritten": 3, "result_rebuilds": 2,
            "activation_allocas": 2, "absorbed_arguments": 2, "partially_absorbed_arguments": 1,
            "absorbed_results": 3, "encoded_function": "f.sre.encoded", "returns_pair": True,
            "wrapper_retained": False, "representation": "xor-pair-v1",
            "recursion_contract": "direct-self-activation-v1", "self_recursive": True,
            "recursive_calls_rewritten": 1}]}


class RecursiveInterfaces(unittest.TestCase):
    def test_missing_interface_dependency_is_rejected(self):
        self.assertTrue(call_violations({"features": {"self_recursion": True}}))

    def test_coverage_contract(self):
        self.assertEqual(call_violations(report()), [])
        for key, value in (("recursive_calls_rewritten", 0), ("recursive_calls_rewritten", 4),
                           ("self_recursive", False), ("recursion_contract", "unknown")):
            data = report()
            data["encoded_calls"][0][key] = value
            self.assertTrue(call_violations(data), key)

    def test_skipped_self_does_not_claim_a_call(self):
        data = report()
        row = data["encoded_calls"][0]
        row.update(status="skipped", reason="recursive-unsupported-effect", encoded_function="", returns_pair=False,
                   encoded_parameters=0, call_sites_rewritten=0, result_rebuilds=0, activation_allocas=0,
                   absorbed_arguments=0, partially_absorbed_arguments=0, absorbed_results=0, recursive_calls_rewritten=0)
        self.assertEqual(call_violations(data), [])
        row["recursive_calls_rewritten"] = 1
        self.assertTrue(call_violations(data))

    def test_source_retains_real_recursion(self):
        for width in (8, 16, 32, 64):
            self.assertIn(f"%child = notail call i{width} @recur", fixture(width))
            self.assertIn(f"%result = xor i{width} %child, %v6", fixture(width))

    def test_independent_recursive_and_stack_oracles_agree(self):
        for width in (8, 16, 32, 64):
            mask = (1 << width) - 1
            def direct(x, y, depth):
                if not depth: return x ^ y
                p = ((x + y) * 3) & mask
                q = (x ^ 7) | y
                a = ((p + q) * 5) & mask
                b = ((p ^ q) + a) & mask
                return direct(a, b, depth - 1) ^ a
            for a, b in ((0, 0), (1, 1), (mask, mask), (mask >> 1, 15), (1 << (width - 1), 16)):
                result = oracle(a, b, width)
                self.assertEqual(result[0], direct(a, b, b & 15))
                self.assertEqual(result[1], direct(b, a, (a >> 5) & 7))


if __name__ == "__main__":
    unittest.main()
