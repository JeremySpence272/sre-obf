import unittest
from conformance.recovery_reach import check_expression, validate


class ReplayTests(unittest.TestCase):
    def test_closed_expression_language(self):
        check_expression({"op": "arg", "width": 8, "index": 0})
        for bad in ({"op": "eval", "width": 8}, {"op": "arg", "width": 128, "index": 0},
                    {"op": "arg", "width": 8, "index": 7}):
            with self.assertRaises(ValueError):
                check_expression(bad)

    def test_model_caps_and_split_byte_guard(self):
        spec = {"schema": "sre-symbolic-reach-v1", "abi": "buffer-length", "input_bytes": 8,
                "success": [123], "split_selects": []}
        validate(spec)
        with self.assertRaises(ValueError):
            validate({**spec, "input_bytes": 257})
        with self.assertRaises(ValueError):
            validate({**spec, "split_selects": [{"condition": "eq"}]})


if __name__ == "__main__":
    unittest.main()
