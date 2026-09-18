import argparse
import unittest

from conformance import bundle_options
from conformance.continuity_selection import continuity_summary, continuity_violations


def report():
    return {"features": {"bundles": True, "continuity_priority": True}, "connected_regions": [
        {"function": "f", "status": "encoded", "eligible_nodes": 40, "nodes": 12,
         "continuity_selection": {"contract": "sre-continuity-selection-v1", "root_limit": 256,
            "joined_unit_limit": 8, "eligible_roots": 10, "prioritized_roots": 10, "selected_roots": 5,
            "atomic_joins": 4, "scope": "retained-selection", "hardness_evaluated": False}}]}


class ContinuitySelection(unittest.TestCase):
    def test_bounded_counts(self):
        self.assertEqual(continuity_violations(report()), [])
        for key, value in (("root_limit", 1000), ("selected_roots", 11), ("eligible_roots", 41),
                           ("prioritized_roots", 9), ("atomic_joins", 11), ("hardness_evaluated", True)):
            data = report()
            data["connected_regions"][0]["continuity_selection"][key] = value
            self.assertTrue(continuity_violations(data), key)
        data = report()
        row = data["connected_regions"][0]
        row["eligible_nodes"] = 1000
        row["continuity_selection"].update(eligible_roots=300, prioritized_roots=256)
        self.assertEqual(continuity_violations(data), [])

    def test_scope_and_missing_counts(self):
        data = report()
        row = data["connected_regions"][0]
        row.update(status="skipped", reason="connected-growth-rollback", attempted_nodes=row.pop("nodes"))
        self.assertTrue(continuity_violations(data))
        row["continuity_selection"]["scope"] = "attempted-selection"
        self.assertEqual(continuity_violations(data), [])
        summary = continuity_summary(data)
        self.assertEqual(summary["retained_selected_roots"], 0)
        self.assertEqual(summary["rolled_back_selected_roots"], 5)
        del row["continuity_selection"]
        self.assertTrue(continuity_violations(data))
        row["reason"] = "structure-or-size"
        self.assertEqual(continuity_violations(data), [])

    def test_disabled_and_options(self):
        data = report()
        data["features"]["continuity_priority"] = False
        self.assertTrue(continuity_violations(data))
        parser = argparse.ArgumentParser()
        bundle_options.add_options(parser)
        with self.assertRaises(ValueError):
            bundle_options.validate(parser.parse_args(["--continuity-priority"]), True)
        args = parser.parse_args(["--bundles", "--continuity-priority"])
        bundle_options.validate(args, True)
        self.assertIn("-native-continuity-priority=1", bundle_options.flags(args))
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))


if __name__ == "__main__":
    unittest.main()
