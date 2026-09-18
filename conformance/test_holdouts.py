import base64
import bz2
import hashlib
import json
import unittest

from conformance.prepare_holdouts import contracts


class HoldoutContracts(unittest.TestCase):
    def test_byte_stream_contracts_are_deterministic_and_bidirectional(self):
        cases = contracts("bzip2")
        self.assertEqual(cases, contracts("bzip2"))
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({c["name"] for c in cases}), 6)
        for case in cases:
            source = base64.b64decode(case["stdin_base64"], validate=True)
            output = bz2.decompress(source) if "-d" in case["argv"] else bz2.compress(source, compresslevel=9)
            self.assertEqual(hashlib.sha256(output).hexdigest(), case["stdout_sha256"])

    def test_json_contract_covers_nested_values_and_invalid_input(self):
        valid, invalid = contracts("cjson")
        records = base64.b64decode(valid["stdin_base64"], validate=True).decode().splitlines()
        self.assertGreater(len(records), 10)
        output = "".join(json.dumps(json.loads(line), ensure_ascii=False, separators=(",", ":")) + "\n"
                         for line in records)
        self.assertEqual(hashlib.sha256(output.encode()).hexdigest(), valid["stdout_sha256"])
        bad = base64.b64decode(invalid["stdin_base64"], validate=True).decode().splitlines()
        for line in bad:
            with self.assertRaises(json.JSONDecodeError): json.loads(line)
        self.assertEqual(hashlib.sha256(b"invalid\n" * len(bad)).hexdigest(), invalid["stdout_sha256"])

    def test_unknown_program_is_not_silently_assumed_json(self):
        with self.assertRaises(ValueError): contracts("unknown")


if __name__ == "__main__":
    unittest.main()
