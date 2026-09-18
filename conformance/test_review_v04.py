"""Regressions found while auditing the v04 checkpoint's evidence gates."""
import types
import unittest

from conformance import corpora, extract_phases as ph, recovery, recovery_grammar as grammar
from pathlib import Path
from conformance import transfer_model as tm

try:
    CLARIPY = ph._load_claripy()
except ModuleNotFoundError:
    CLARIPY = None


class RecoveryReviewTests(unittest.TestCase):
    def test_full_range_bounds_do_not_wrap_to_false(self):
        for width in ph.WIDTHS:
            mask = (1 << width) - 1
            models = [ph.Bound(width, n=mask + 1), ph.RecoveryModel(
                {"family": "bounds", "width": width, "arity": 1,
                 "params": {"low": 0, "high": mask}})]
            for model in models:
                for value in (0, 1, mask >> 1, mask):
                    self.assertEqual(model.apply([value]), 1)

    def test_recurrence_must_match_the_entire_sequence(self):
        self.assertIsNone(ph.fit_recurrence([0, 1, 2, 99], 8))

    def test_unsupported_arity_cannot_be_enumerated_as_pairs(self):
        for fn in (ph.domain_points, ph.constructed_points):
            with self.assertRaises(ValueError):
                fn(8, 3)

    def test_partial_table_has_no_total_domain_proof(self):
        self.assertFalse(ph.total_model(ph.LookupTable(8, table=[0, 1])))
        self.assertTrue(ph.total_model(ph.LookupTable(8, table=list(range(256)))))
        model = ph.RecoveryModel({"family": "table", "width": 8, "arity": 1,
                                  "params": {"domain": [0, 1], "values": [3, 4]}})
        # No solver is needed: a partial model cannot enter a total proof query.
        oracle = ph.SymbolicOracle(None, None, [None], 8)
        self.assertEqual(oracle.equivalence(model)["status"], "inconclusive")
        self.assertIsNone(model.apply([2]))

    def test_samples_and_duplicate_points_cannot_claim_exhaustiveness(self):
        sites = [{"name": name, "observations": [[[x], x ^ 9] for x in range(8)]}
                 for name in ("a", "b")]
        args = dict(oracle=lambda xs: xs[0] ^ 9)
        for domain in ([(0,)], [(0,)] * 256):
            self.assertFalse(grammar.summarize(sites, 8, domain=domain, **args)["validated"])
        complete = grammar.summarize(sites, 8, domain=[(x,) for x in range(256)], **args)
        self.assertTrue(complete["validated"])
        self.assertEqual(complete["best"]["verification"], "exhaustive")

    def test_inconsistent_sample_interfaces_are_rejected(self):
        with self.assertRaises(ValueError):
            grammar.fit({"observations": [[[0], 0], [[1, 2], 3]]}, 8)

    def test_clean_control_requires_a_verified_model(self):
        row = {"candidate": "a", "control": {"status": "recovered"},
               "native": {"status": "recovered"}, "growth": 1, "runtime_ratio": 1}
        ranked, blocked = recovery.choose([row], 8)
        self.assertFalse(ranked)
        self.assertEqual(blocked[0]["reasons"], ["clean-control-not-summarized"])

    def test_legacy_constructed_summary_is_not_a_verified_result(self):
        arm = {"status": "recovered", "summary": {"validated": True,
               "best": {"verification": "constructed"}}}
        self.assertEqual(recovery.attack_level(arm), ("blocked", "legacy-or-unverified-summary"))

    def test_deadended_path_invalidates_an_otherwise_successful_lift(self):
        sim = types.SimpleNamespace(stashes={"returned": [object()], "deadended": [object()]},
                                    active=[], errored=[], unconstrained=[])
        self.assertEqual(ph._lift_status(sim, 1, 0)["status"], "inconclusive")

    def test_buffer_return_domain_includes_guards(self):
        covered = types.SimpleNamespace(variables={"input", "undeclared_guard"})
        claripy = types.SimpleNamespace(And=lambda *xs: covered, Or=lambda *xs: covered)
        returned = [types.SimpleNamespace(solver=types.SimpleNamespace(constraints=[covered]))]
        complete, unknown, reason = ph.return_domain(claripy, returned, ["input"], 10)
        self.assertFalse(complete)
        self.assertEqual(unknown, {"undeclared_guard"})
        self.assertEqual(reason, "unresolved-memory")

    def test_buffer_partial_domain_is_not_complete(self):
        covered = types.SimpleNamespace(variables={"input"})
        solver = types.SimpleNamespace(satisfiable=lambda **kw: True)
        claripy = types.SimpleNamespace(And=lambda *xs: covered, Or=lambda *xs: covered,
                                        Not=lambda x: x, Solver=lambda **kw: solver)
        returned = [types.SimpleNamespace(solver=types.SimpleNamespace(constraints=[covered]))]
        self.assertEqual(ph.return_domain(claripy, returned, ["input"], 10),
                         (False, set(), "interface-mismatch"))

    def test_empty_report_does_not_claim_recovery(self):
        self.assertEqual(ph.region_report("r", "supplied-region", [])["status"], "inconclusive")

    def test_locked_manifest_cannot_change_upstream_revision(self):
        lock = corpora.load()
        acquisition = lock["corpora"]["zlib"]["acquisition"]
        spec = {"schema": "sre-scale-v1", "project": "zlib", **acquisition}
        self.assertTrue(corpora.validate_manifest(lock, "zlib", spec, Path(__file__))[
            "archive_identity_checked"])
        spec["revision"] = "unreviewed"
        with self.assertRaises(corpora.CorpusError):
            corpora.validate_manifest(lock, "zlib", spec, Path(__file__))

    def test_holdout_requires_a_frozen_manifest_hash(self):
        lock = corpora.load()
        record = lock["corpora"]["bzip2"]
        record["spec_schema"] = "sre-scale-v1"
        spec = {"schema": "sre-scale-v1", "project": "bzip2", **record["acquisition"]}
        with self.assertRaisesRegex(corpora.CorpusError, "manifest hash"):
            corpora.validate_manifest(lock, "bzip2", spec, Path(__file__))

    def test_gf2_fitting_retains_contradictory_training_evidence(self):
        fit = tm.Gf2System()
        self.assertTrue(fit.add(1, 0))
        self.assertFalse(fit.add(1, 1))
        self.assertFalse(fit.consistent)


@unittest.skipIf(CLARIPY is None, "run in the pinned analysis image for real symbolic checks")
class SymbolicReviewTests(unittest.TestCase):
    def test_unsigned_full_range_bounds_are_proved_at_every_width(self):
        for width in ph.WIDTHS:
            x = CLARIPY.BVS("x", width, explicit_name=True)
            oracle = ph.SymbolicOracle(CLARIPY, CLARIPY.BVV(1, width), [x], width)
            spec = {"family": "bounds", "width": width, "arity": 1,
                    "params": {"low": 0, "high": (1 << width) - 1}}
            self.assertEqual(oracle.equivalence(ph.RecoveryModel(spec))["status"], "proved")

    def test_path_coverage_uses_actual_solver_constraints(self):
        x = CLARIPY.BVS("x", 8, explicit_name=True)
        def state(condition):
            return types.SimpleNamespace(solver=types.SimpleNamespace(constraints=[condition]))
        self.assertFalse(ph.return_domain(CLARIPY, [state(x == 0)], ["x"], 1000)[0])
        self.assertTrue(ph.return_domain(CLARIPY, [state(x == 0), state(x != 0)], ["x"], 1000)[0])

    def test_undeclared_values_cannot_be_concretized_arbitrarily(self):
        x = CLARIPY.BVS("x", 8, explicit_name=True)
        hidden = CLARIPY.BVS("hidden", 8, explicit_name=True)
        oracle = ph.SymbolicOracle(CLARIPY, x ^ hidden, [x], 8)
        with self.assertRaises(ValueError):
            oracle.evaluate([7])

    def test_shared_fitter_and_symbolic_prover_recover_joint_affine_model(self):
        x, y = [CLARIPY.BVS(n, 8, explicit_name=True) for n in ("x", "y")]
        oracle = ph.SymbolicOracle(CLARIPY, 3 * x + 5 * y + 9, [x, y], 8)
        models = ph.fit_models(oracle, 8)
        self.assertTrue(any(ph.test_model(m, oracle, 8)["accepted"] for m in models))


if __name__ == "__main__":
    unittest.main()
