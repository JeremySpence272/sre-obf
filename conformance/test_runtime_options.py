import argparse
import unittest

from conformance import runtime_options
from conformance.whole import parser
from integrations.revgame.build import V4_OPTIONS, V5_OPTIONS


class RuntimeOptions(unittest.TestCase):
    def parse(self, argv):
        p = argparse.ArgumentParser()
        runtime_options.add_options(p)
        return p.parse_args(argv)

    def test_v04_has_no_runtime_flags(self):
        args = self.parse([])
        runtime_options.validate(args)
        self.assertEqual(runtime_options.flags(args), [])
        self.assertNotIn("--runtime-state", V4_OPTIONS)

    def test_lifetime_contract_is_explicit(self):
        for argv in (["--runtime-state"], ["--runtime-phases"],
                     ["--runtime-single-thread"], ["--runtime-test-seed", "0"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                runtime_options.validate(self.parse(argv))

    def test_zero_is_a_valid_diagnostic_seed_and_not_a_release_default(self):
        args = self.parse(V5_OPTIONS + ["--runtime-test-seed", "0"])
        runtime_options.validate(args)
        self.assertIn("-native-runtime-test-seed=0", runtime_options.flags(args))
        args = self.parse(V5_OPTIONS)
        self.assertFalse(any("test-seed" in x for x in runtime_options.flags(args)))

    def test_bounds_and_whole_program_parser(self):
        for option, value in (("--runtime-growth", "0"), ("--runtime-growth", "65537"),
                              ("--runtime-test-seed", "-1"), ("--runtime-test-seed", str(2**64))):
            with self.subTest(option=option, value=value), self.assertRaises(ValueError):
                runtime_options.validate(self.parse(V5_OPTIONS + [option, value]))
        args = parser().parse_args(["fixture.c", "--out", "unused", *V5_OPTIONS])
        runtime_options.validate(args)
        self.assertIn("-native-runtime-phases=1", runtime_options.flags(args))


if __name__ == "__main__":
    unittest.main()
