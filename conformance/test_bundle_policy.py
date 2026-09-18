import copy
import unittest

from conformance.bundle_policy import canonical_hash, select, shape_key


def evidence():
    shape = {"width": 32, "lanes": 4, "nodes": 8, "pins": True}
    protocol = {"split": "training", "candidates": ["xor", "additive"],
                "attacks": ["binary", "post-o2"],
                "limits": {"growth": 2, "runtime_ratio": 2, "compile_seconds": 600},
                "cases": [{"id": "training-a-1", "shape": shape}]}
    arm = {"status": "recovered", "summary": {"validated": True, "best": {"verification": "proved"}},
           "cost": {"mechanism_steps": 5, "repair_steps": 0}}
    return {"schema": "sre-bundle-policy-evidence-v1", "protocol": protocol, "complete": True,
            "protocol_sha256": canonical_hash(protocol), "rows": [
                {"case": "training-a-1", "candidate": name, "attack": attack,
                 "control": copy.deepcopy(arm), "native": copy.deepcopy(arm),
                 "growth": 1.5, "runtime_ratio": 1.5, "compile_seconds": 2,
                 "correctness": True, "accounting": True}
                for name in ("xor", "additive") for attack in protocol["attacks"]]}


class PolicyTests(unittest.TestCase):
    def test_ties_keep_diversity(self):
        self.assertEqual(select(evidence())["rules"][0]["candidates"], ["additive", "xor"])

    def test_cheapest_normalizer_wins_not_worst(self):
        e = evidence()
        e["rows"][0]["native"]["cost"]["mechanism_steps"] = 5000
        self.assertEqual(select(e)["decisions"][0]["admitted"][1]["cheapest_steps"], 5)

    def test_pareto_improvement_and_resource_tradeoff(self):
        e = evidence()
        for r in e["rows"][:2]: r["native"]["cost"]["mechanism_steps"] = 10
        self.assertEqual(select(e)["rules"][0]["candidates"], ["xor"])
        e["rows"][0]["growth"] = 1.9
        self.assertEqual(select(e)["rules"][0]["candidates"], ["additive", "xor"])

    def test_inconclusive_is_not_a_win(self):
        e = evidence()
        for r in e["rows"]: r["native"] = {"status": "budget"}
        self.assertEqual(select(e)["rules"], [])

    def test_any_bad_case_excludes_candidate(self):
        for change in ({"correctness": False}, {"accounting": False}, {"growth": 2.01},
                       {"runtime_ratio": None}, {"compile_seconds": float("nan")},
                       {"control": {"status": "error"}}):
            with self.subTest(change=change):
                e = evidence(); e["rows"][0].update(change)
                self.assertEqual(select(e)["rules"][0]["candidates"], ["additive"])

    def test_missing_repair_cost_and_sampled_proof_excluded(self):
        for mutation in ("repair", "proof"):
            e = evidence()
            if mutation == "repair": del e["rows"][0]["native"]["cost"]["repair_steps"]
            else: e["rows"][0]["native"]["summary"]["best"]["verification"] = "sampled"
            self.assertEqual(select(e)["rules"][0]["candidates"], ["additive"])

    def test_matrix_and_holdout_firewall(self):
        for mutation in ("missing", "duplicate", "unknown", "holdout", "protocol", "incomplete"):
            e = evidence()
            if mutation == "missing": e["rows"].pop()
            if mutation == "incomplete": e["complete"] = False
            if mutation == "duplicate": e["rows"].append(e["rows"][0])
            if mutation == "unknown": e["rows"][0]["case"] = "unfrozen"
            if mutation == "holdout":
                e["protocol"]["split"] = "holdout"
                e["protocol_sha256"] = canonical_hash(e["protocol"])
            if mutation == "protocol": e["protocol"]["limits"]["growth"] = 200
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): select(e)

    def test_shape_not_a_function_address_or_name(self):
        for field, value in (("function", "checker"), ("width", True), ("pins", 1), ("nodes", 1000)):
            shape = dict(evidence()["protocol"]["cases"][0]["shape"]); shape[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): shape_key(shape)


if __name__ == "__main__": unittest.main()
