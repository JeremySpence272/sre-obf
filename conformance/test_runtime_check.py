import copy
import unittest

from conformance.runtime_check import runtime_summary, runtime_violations, v05_violations


def report():
    return {"features": {"runtime_state": True}, "runtime_state": {
        "schema": "sre-runtime-state-v1", "status": "encoded",
        "phases": True, "hardness_evaluated": False, "complete_chain_claim": False,
        "closed_scalar_exits": False, "instructions_before": 20, "instructions_after": 150,
        "growth_budget": 200, "retained_operations": 4, "scalar_exit_uses": 1,
        "exact_predicates": 1, "objects": [
            {"object": "counter", "status": "encoded", "reason": "", "width": 32,
             "source_loads": 2, "source_stores": 2, "phase": "per-store"},
            {"object": "array", "status": "excluded", "reason": "unsupported-aggregate-or-width"}]}}


class RuntimeAccounting(unittest.TestCase):
    def test_feature_off_and_valid_partial_coverage(self):
        self.assertEqual(runtime_violations({"features": {}}), [])
        self.assertEqual(runtime_violations(report()), [])
        summary = runtime_summary(report())
        self.assertEqual(summary["retained_objects"], 1)
        self.assertFalse(summary["candidate_ready"])
        self.assertTrue(summary["pending_contracts"])

    def test_invalid_or_overclaimed_accounting(self):
        for key, value in (("schema", "unknown"), ("status", "pass"),
                           ("hardness_evaluated", True), ("complete_chain_claim", True),
                           ("instructions_after", 1000), ("scalar_exit_uses", -1),
                           ("closed_scalar_exits", True)):
            with self.subTest(key=key):
                data = report()
                data["runtime_state"][key] = value
                self.assertTrue(runtime_violations(data))
        data = report()
        data["runtime_state"]["objects"].append(copy.deepcopy(data["runtime_state"]["objects"][0]))
        self.assertTrue(runtime_violations(data))

    def test_rollback_requires_zero_retained_growth_and_coverage(self):
        data = report()
        state = data["runtime_state"]
        state.update(status="rolled-back", instructions_after=20,
                     retained_operations=0, scalar_exit_uses=0, exact_predicates=0)
        state["objects"][0]["status"] = "rolled-back"
        self.assertEqual(runtime_violations(data), [])
        state["instructions_after"] = 21
        self.assertTrue(runtime_violations(data))

    def test_all_exclusions_remain_visible(self):
        data = report()
        state = data["runtime_state"]
        state["status"] = "no-eligible-storage"
        state["objects"] = [{"object": "counter", "status": "excluded", "reason": "growth-reservation"}]
        self.assertEqual(runtime_violations(data), [])
        state["objects"][0]["reason"] = "ignored"
        self.assertTrue(runtime_violations(data))


class V05Accounting(unittest.TestCase):
    def complete(self):
        data = report()
        data["features"].update(runtime_buffers=True, exact_consumers=True)
        data["runtime_state"]["objects"][0].update(cells=32, source_resets=1,
            bounds_contract="defined-inbounds-element-access")
        data["exact_consumers"] = [{"status": "integrated", "exact_consumers": 1,
            "compared_bytes": 32, "hardness_evaluated": False, "complete_chain_claim": False}]
        data["vm"] = True
        data["selective_interpreter"] = {"schema": "sre-selective-interpreter-v1",
            "status": "interpreted", "anti_debug": False, "bytecode_verifier": True,
            "hardness_evaluated": False, "complete_chain_claim": False,
            "original_instructions": 7, "instructions_before": 100,
            "instructions_after": 500, "growth_budget": 1000}
        return data

    def test_retained_contracts_without_hardness_claim(self):
        self.assertEqual(v05_violations(self.complete()), [])
        self.assertEqual(v05_violations({}), [])

    def test_zero_coverage_cannot_pass_enabled_features(self):
        for key in ("runtime_state", "exact_consumers", "selective_interpreter"):
            data = self.complete()
            del data[key]
            self.assertTrue(v05_violations(data), key)

    def test_invalid_bounds_budget_and_unmeasured_claims(self):
        for mutate in (
            lambda r: r["runtime_state"]["objects"][0].update(bounds_contract="unchecked"),
            lambda r: r["runtime_state"]["objects"][0].update(cells=65),
            lambda r: r["exact_consumers"][0].update(complete_chain_claim=True),
            lambda r: r["selective_interpreter"].update(hardness_evaluated=True),
            lambda r: r["selective_interpreter"].update(anti_debug=True),
            lambda r: r["selective_interpreter"].update(bytecode_verifier=False),
            lambda r: r["selective_interpreter"].update(instructions_after=2000)):
            data = self.complete()
            mutate(data)
            self.assertTrue(v05_violations(data))


class RuntimeLaws(unittest.TestCase):
    def test_exhaustive_byte_store_and_phase_preserve_logical_value(self):
        # Independent bit-vector specification. Actual compiler lowering is
        # checked separately by runtime_run's multi-width differential fixture.
        for value in range(256):
            for mask in range(256):
                encoded = value ^ mask
                for multiplier, increment in ((1, 1), (13, 7), (255, 255)):
                    next_mask = (mask * multiplier + increment) & 255
                    transferred = encoded ^ (mask ^ next_mask)
                    self.assertEqual(transferred ^ next_mask, value)


if __name__ == "__main__":
    unittest.main()
