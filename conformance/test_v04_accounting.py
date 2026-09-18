"""M0 accounting and corpus-lock gates.

Two things are under test. First, that every source-owned function and object
reaches a denominator, that selection loss and transformation rollback stay
separable, and that no single weighting can be quoted as the coverage of a
build. Second, that the locked evaluation matrix refuses the uses that would
make a later measurement worthless: tuning on a held-out program, calling a
scale regression held-out, or reporting a result for a corpus whose
input/output contract was never frozen.
"""
from pathlib import Path
import unittest

from conformance import corpora
from conformance.scale import (SOURCE_DISPOSITIONS, accounting_violations, cap_ledger,
                               coverage, coverage_passes, loss_ledger, object_ledger,
                               ratio, source_ledger, support_charge)


def planner_row(function="a", **overrides):
    row = {"function": function, "status": "encoded", "nodes": 4, "eligible_nodes": 6,
           "predicates": 1, "memory_edges": 2, "objects": [{"status": "encoded", "reason": ""}],
           "eligible_memory_edges": 4, "eligible_memory_objects": 2,
           "eligible_aggregate_memory_objects": 0, "eligible_memory_leaves": 2,
           "skipped_components": 1, "oversized_components": 0, "sharded_components": 0,
           "shards": 0, "shard_lost_nodes": 0, "bounded_growth": True, "growth_allocation": 900,
           "eligible_estimated_cost": 1000, "selected_estimated_cost": 700,
           "skipped_estimated_cost": 300, "shard_lost_estimated_cost": 0,
           "component_estimated_cost_limit": 900, "shard_estimated_cost_limit": 0,
           "shard_policy": "whole-component-only", "regions": []}
    row.update(overrides)
    return row


def source_row(function="a", instructions=100, **overrides):
    row = {"function": function, "instructions": instructions, "blocks": 3, "loads": 4,
           "stores": 2, "local_objects": 1, "integer_comparisons": 1, "selects": 0,
           "indirect_calls": 0, "generated_helper": False, "external_linkage": False,
           "selected_attribute": False, "direct_helper_calls": []}
    row.update(overrides)
    return row


def report(sources=("a",), planner=None, selection=None, merged=(), helpers=None,
           final_functions=None, schema="sre-native-v6"):
    rows = [source_row(name) for name in sources]
    value = {"schema": schema,
             "features": {"module_instruction_limit": 250000, "helper_limit": 4096},
             "connected_regions": list(planner if planner is not None else [planner_row("a")]),
             "flattening_state": [],
             "functions": (selection if selection is not None
                           else [{"function": name, "selected": True, "reason": ""} for name in sources]),
             "merged_groups": list(merged),
             "input_inventory": {"definitions": len(rows),
                                 "instructions": sum(r["instructions"] for r in rows),
                                 "functions": rows},
             "final_inventory": {"instructions": 500, "helper_instructions": 40,
                                 "helper_definitions": 2,
                                 "functions": [{"function": name} for name in
                                               (final_functions if final_functions is not None else sources)]}}
    if helpers is not None:
        value["helpers"] = list(helpers)
    return value


class DenominatorTests(unittest.TestCase):
    """Nothing source-owned may be missing from a denominator."""

    def test_every_source_function_lands_in_exactly_one_disposition(self):
        ledger = source_ledger(report(sources=("a", "b"), planner=[planner_row("a")]))
        self.assertEqual(sum(ledger["functions"].values()), ledger["source_functions"])
        self.assertEqual(set(ledger["functions"]), set(SOURCE_DISPOSITIONS))
        self.assertEqual(ledger["functions"]["encoded"], 1)

    def test_a_function_no_pass_touched_is_visible_rather_than_absent(self):
        # `b` reached selection and the planner never produced a row for it.
        ledger = source_ledger(report(sources=("a", "b"), planner=[planner_row("a")]))
        self.assertEqual(ledger["functions"]["not-planned"], 1)
        self.assertEqual(ledger["instructions"]["not-planned"], 100)

    def test_a_function_the_module_lost_before_selection_is_its_own_bucket(self):
        value = report(sources=("a", "gone"), planner=[planner_row("a")],
                       selection=[{"function": "a", "selected": True, "reason": ""}],
                       final_functions=["a"])
        value["fusion_absorbed"] = [{"function": "gone", "absorbed_by": "a",
                                     "reason": "fusion-inlined", "absorbing_callers": 1}]
        ledger = source_ledger(value)
        self.assertEqual(ledger["functions"]["absorbed-before-selection"], 1)
        self.assertEqual(ledger["functions"]["unaccounted"], 0)
        self.assertEqual(accounting_violations(coverage(value)), [])

    def test_a_function_in_no_stage_record_is_an_accounting_violation(self):
        # Still in the final module, but in no selection and no planner row:
        # that is a reporting defect, and it must fail rather than vanish.
        value = report(sources=("a", "ghost"), planner=[planner_row("a")],
                       selection=[{"function": "a", "selected": True, "reason": ""}],
                       final_functions=["a", "ghost"])
        self.assertEqual(source_ledger(value)["functions"]["unaccounted"], 1)
        self.assertTrue(any("no later stage record" in v
                            for v in accounting_violations(coverage(value))))

    def test_disappearance_without_provenance_is_not_absorption(self):
        value = report(sources=("gone",), planner=[], selection=[], final_functions=[])
        self.assertEqual(source_ledger(value)["functions"]["unaccounted"], 1)

    def test_encoded_interface_rename_preserves_source_ownership(self):
        value = report(planner=[planner_row("a.sre.encoded.1")])
        value["encoded_calls"] = [{"function": "a", "encoded_function": "a.sre.encoded.1",
                                    "status": "encoded"}]
        self.assertEqual(source_ledger(value)["functions"]["encoded"], 1)

    def test_old_object_inventory_keeps_unknown_fields_unknown(self):
        value = report()
        del value["input_inventory"]["functions"][0]["local_objects"]
        self.assertIsNone(object_ledger(value)["source_local_objects"])

    def test_a_merged_origin_is_credited_at_the_function_that_owns_its_body(self):
        value = report(sources=("a", "b"), planner=[planner_row("__obf_merged__auto0")],
                       merged=[{"function": "__obf_merged__auto0", "members": "a,b"}])
        ledger = source_ledger(value)
        self.assertEqual(ledger["functions"]["encoded"], 2)
        self.assertEqual(ledger["merged_origins"], 2)
        self.assertEqual(ledger["merge_owners"], 1)

    def test_a_function_touched_by_neither_pass_is_counted_directly(self):
        value = report(sources=("a", "b", "c"), planner=[
            planner_row("a"),
            planner_row("b", status="skipped", reason="no-whole-component-within-budget"),
            planner_row("c", status="skipped", reason="no-whole-component-within-budget")])
        value["flattening_state"] = [{"function": "b"}]
        ledger = source_ledger(value)
        # `b` was skipped by the planner but flattened; `c` was reached by
        # neither, and that is the number the brief asks to be visible.
        self.assertEqual(ledger["also_flattened"]["planner-skipped"], 1)
        self.assertEqual(ledger["untouched_by_either_pass"], 1)
        self.assertEqual(ledger["untouched_by_either_pass_instructions"], 100)

    def test_a_report_without_per_function_rows_has_no_denominator_at_all(self):
        value = report()
        value["input_inventory"]["functions"] = None
        self.assertIsNone(source_ledger(value))

    def test_generated_code_never_enters_the_source_denominator(self):
        value = report(sources=("a",))
        value["input_inventory"]["functions"].append(source_row("helper", generated_helper=True))
        ledger = source_ledger(value)
        self.assertEqual(ledger["source_functions"], 1)
        self.assertEqual(ledger["generated_functions_in_source_inventory"], 1)
        self.assertTrue(any("generated code is inside" in v
                            for v in accounting_violations(coverage(value))))


class ObjectDenominatorTests(unittest.TestCase):
    def test_raw_and_eligible_object_denominators_are_both_reported(self):
        objects = object_ledger(report(sources=("a", "b")))
        self.assertEqual(objects["source_local_objects"], 2)
        self.assertEqual(objects["source_memory_operations"], 12)
        self.assertEqual(objects["eligible_closed_memory_objects"], 2)
        self.assertEqual(objects["encoded_memory_objects"], 1)

    def test_module_globals_are_unknown_and_never_zero(self):
        self.assertIsNone(object_ledger(report())["source_module_globals"])

    def test_an_old_report_leaves_the_eligible_object_denominator_unknown(self):
        value = report(schema="sre-native-v1", planner=[planner_row("a")])
        self.assertIsNone(object_ledger(value)["eligible_closed_memory_objects"])

    def test_a_numerator_above_its_own_raw_denominator_fails(self):
        value = report(sources=("a",))
        value["input_inventory"]["functions"][0]["local_objects"] = 0
        self.assertTrue(any("exceeds its own denominator" in v
                            for v in accounting_violations(coverage(value))))


class WeightingTests(unittest.TestCase):
    """No single weighting may be allowed to hide uncovered code."""

    def test_raw_and_weighted_views_are_reported_side_by_side(self):
        # One small encoded function beside one large untouched one: the
        # function-count view and the raw-operation view must disagree, and
        # both must be present.
        value = report(sources=("a", "b"), planner=[planner_row("a")])
        value["input_inventory"]["functions"][1]["instructions"] = 9900
        value["input_inventory"]["instructions"] = 10000
        views = coverage(value)["coverage_views"]
        self.assertEqual(views["function_count"]["ratio"], 0.5)
        self.assertLess(views["raw_operations"]["ratio"], 0.001)
        self.assertGreater(views["planner_eligible_operations"]["ratio"],
                           views["raw_operations"]["ratio"] * 10)
        for name in ("raw_operations", "source_weighted_functions", "function_count",
                     "planner_cost", "memory_objects_raw", "memory_objects_eligible"):
            self.assertIn(name, views)

    def test_a_missing_denominator_produces_null_rather_than_zero(self):
        self.assertIsNone(ratio(0, None))
        self.assertIsNone(ratio(0, 0))
        self.assertEqual(ratio(0, 4), 0.0)

    def test_coverage_is_never_inferred_from_an_enabled_flag(self):
        # Every experiment on, nothing actually selected: no view may be a pass.
        value = report(planner=[planner_row("a", status="skipped", reason="structure-or-size")])
        value["features"].update({"memory_ssa": True, "connected_aggregates": True,
                                  "connected_shards": True, "predicate_regions": True})
        measured = coverage(value)
        self.assertEqual(measured["coverage_views"]["function_count"]["numerator"], 0)
        self.assertFalse(coverage_passes(measured, require_memory=True))
        self.assertFalse(coverage_passes(measured, require_aggregate_memory=True))


class LossTests(unittest.TestCase):
    """Selection loss and transformation rollback are different failures."""

    def test_rollback_is_reported_apart_from_selection_loss(self):
        value = report(sources=("a", "b"), planner=[
            planner_row("a"),
            {"function": "b", "status": "skipped", "reason": "connected-growth-rollback",
             "eligible_estimated_cost": 900, "attempted_estimated_cost": 400,
             "attempted_nodes": 5, "eligible_nodes": 6}])
        loss = loss_ledger(value)
        self.assertEqual(loss["selection"]["skipped_estimated_cost"], 300)
        self.assertEqual(loss["selection"]["functions"], 0)
        self.assertEqual(loss["rollback"]["rollback_estimated_cost"], 900)
        self.assertEqual(loss["rollback"]["attempted_estimated_cost"], 400)
        self.assertEqual(loss["rollback"]["functions"], 1)
        self.assertEqual(source_ledger(value)["functions"]["rolled-back"], 1)

    def test_the_identity_closes_only_when_rollback_is_counted(self):
        value = report(sources=("a", "b"), planner=[
            planner_row("a"),
            {"function": "b", "status": "skipped", "reason": "connected-growth-rollback",
             "eligible_estimated_cost": 900, "attempted_estimated_cost": 400,
             "eligible_nodes": 6}])
        identity = loss_ledger(value)["identity"]
        self.assertTrue(identity["balanced"])
        self.assertEqual(identity["residual"], 0)
        self.assertEqual(identity["eligible"],
                         identity["selected"] + identity["skipped"]
                         + identity["shard_lost"] + identity["rolled_back"])

    def test_an_identity_that_does_not_close_is_a_failure(self):
        value = report(planner=[planner_row("a", skipped_estimated_cost=1)])
        measured = coverage(value)
        self.assertFalse(measured["loss_ledger"]["identity"]["balanced"])
        self.assertTrue(any("cost identity does not close" in v
                            for v in measured["accounting_violations"]))

    def test_an_old_report_leaves_the_identity_unknown_and_unknown_is_not_a_pass(self):
        value = report(schema="sre-native-v1")
        measured = coverage(value)
        self.assertIsNone(measured["loss_ledger"]["identity"]["balanced"])
        self.assertFalse(coverage_passes(measured, require_accounting=True))
        self.assertTrue(coverage_passes(measured))


class CapTests(unittest.TestCase):
    """Four scopes, four caps, kept apart."""

    def test_each_scope_reports_its_own_cap(self):
        caps = cap_ledger(report())
        self.assertEqual(set(caps), {"module", "function", "region", "shard", "object"})
        self.assertEqual(caps["module"]["limit"], 250000)
        self.assertEqual(caps["function"]["policy"], "bounded-growth-allocation")
        self.assertEqual(caps["function"]["max"], 900)
        self.assertEqual(caps["region"]["max"], 900)
        self.assertEqual(caps["shard"]["policy"], "whole-component-only")

    def test_the_per_object_cap_is_unknown_and_names_the_missing_field(self):
        caps = cap_ledger(report())
        self.assertIsNone(caps["object"]["limit"])
        self.assertIn("object_leaf_limit", caps["object"]["missing_compiler_field"])

    def test_published_object_caps_are_not_reported_as_missing(self):
        value = report(planner=[planner_row(object_leaf_limit=128, object_leaf_depth_limit=4)])
        caps = cap_ledger(value)["object"]
        self.assertEqual(caps["limit"], 128)
        self.assertEqual(caps["depth_limits"]["max"], 4)
        self.assertIsNone(caps["missing_compiler_field"])

    def test_published_module_global_denominator_is_used(self):
        value = report()
        value["input_inventory"]["global_definitions"] = 7
        self.assertEqual(object_ledger(value)["source_module_globals"], 7)

    def test_an_absent_growth_cap_is_distinguished_from_an_unknown_one(self):
        rows = [planner_row("a", bounded_growth=False)]
        rows[0].pop("growth_allocation")
        self.assertEqual(cap_ledger(report(planner=rows))["function"]["policy"],
                         "no-per-function-growth-cap")
        legacy = planner_row("a")
        legacy.pop("bounded_growth")
        legacy.pop("growth_allocation")
        self.assertIsNone(cap_ledger(report(planner=[legacy]))["function"]["policy"])


class SupportChargeTests(unittest.TestCase):
    """Generated support is charged once, at its owner."""

    def test_one_helper_called_by_many_functions_is_charged_once(self):
        value = report(sources=("a", "b", "c"), planner=[planner_row("a")],
                       helpers=[{"function": "h", "origin": "a", "role": "call-forwarder",
                                 "instructions_after": 30}])
        for row in value["input_inventory"]["functions"]:
            row["direct_helper_calls"] = ["h"]
        charge = support_charge(value)
        self.assertEqual(charge["helper_stage_instructions"], 30)
        self.assertEqual(charge["owners"], 1)
        self.assertEqual(charge["owners_by_kind"]["function"], 1)
        self.assertEqual(charge["double_charged"], 0)

    def test_the_same_helper_reported_twice_is_a_violation(self):
        value = report(helpers=[{"function": "h", "origin": "a", "instructions_after": 30},
                                {"function": "h", "origin": "b", "instructions_after": 30}])
        self.assertEqual(support_charge(value)["double_charged"], 1)
        self.assertTrue(any("charged more than once" in v
                            for v in accounting_violations(coverage(value))))

    def test_the_helper_stage_snapshot_is_never_rescaled_to_the_final_total(self):
        value = report(helpers=[{"function": "h", "origin": "a", "instructions_after": 30}])
        charge = support_charge(value)
        self.assertEqual(charge["final_generated_support_instructions"], 40)
        self.assertEqual(charge["helper_stage_instructions"], 30)

    def test_a_report_without_helper_rows_leaves_the_distribution_unknown(self):
        charge = support_charge(report())
        self.assertIsNone(charge["owners"])
        self.assertIsNone(charge["helper_stage_instructions"])
        self.assertEqual(charge["final_generated_support_instructions"], 40)


class CorpusLockTests(unittest.TestCase):
    """The matrix is data, and it refuses the uses that would spoil it."""

    def setUp(self):
        self.lock = corpora.load()

    def test_the_shipped_lock_is_self_consistent(self):
        self.assertEqual(corpora.validate(self.lock), [])

    def test_the_in_repo_corpus_files_still_match_the_lock(self):
        self.assertEqual(corpora.file_drift(self.lock), [])

    def test_seed_sets_are_disjoint(self):
        seeds = self.lock["seeds"]
        self.assertEqual(seeds["regression"], [1, 3, 4])
        for left in ("regression", "promotion", "holdout"):
            for right in ("regression", "promotion", "holdout"):
                if left != right:
                    self.assertFalse(set(seeds[left]) & set(seeds[right]))

    def test_a_held_out_program_cannot_be_tuned_against(self):
        for purpose in ("tuning", "regression", "promotion"):
            with self.assertRaises(corpora.CorpusError):
                corpora.resolve(self.lock, "bzip2", purpose)

    def test_a_scale_regression_cannot_be_relabelled_held_out(self):
        for name in ("zlib", "lua", "sqlite"):
            self.assertEqual(self.lock["corpora"][name]["split"], "scale-regression")
            with self.assertRaises(corpora.CorpusError):
                corpora.resolve(self.lock, name, "holdout")

    def test_a_corpus_without_a_frozen_contract_yields_no_result(self):
        self.lock["corpora"]["bzip2"].update(workload_state="pending", workload_contract=None)
        with self.assertRaises(corpora.CorpusError) as caught:
            corpora.resolve(self.lock, "bzip2", "holdout")
        self.assertIn("frozen input/output contract", str(caught.exception))

    def test_frozen_holdouts_resolve_but_cannot_lose_their_hash(self):
        for name in ("bzip2", "cjson"):
            result = corpora.resolve(self.lock, name, "holdout")
            self.assertFalse(result["tuning_allowed"])
            self.assertEqual(result["seed"], 23)
        self.lock["corpora"]["bzip2"].pop("manifest_sha256")
        self.assertTrue(any("frozen holdout" in error for error in corpora.validate(self.lock)))

    def test_a_seed_outside_its_set_is_refused(self):
        with self.assertRaises(corpora.CorpusError):
            corpora.resolve(self.lock, "zlib", "regression", 11)
        self.assertEqual(corpora.resolve(self.lock, "zlib", "promotion", 11)["seed"], 11)

    def test_two_held_out_families_exist_and_none_is_also_tuned_on(self):
        families = {name: record["family"] for name, record in self.lock["corpora"].items()}
        holdout = {families[name] for name, record in self.lock["corpora"].items()
                   if record["split"] == "holdout"}
        tuned = {families[name] for name, record in self.lock["corpora"].items()
                 if record["split"] != "holdout"}
        self.assertGreaterEqual(len(holdout), 2)
        self.assertFalse(holdout & tuned)

    def test_a_claimed_acquisition_must_carry_an_archive_hash(self):
        broken = corpora.load()
        broken["corpora"]["bzip2"]["acquisition"]["archive_sha256"] = None
        self.assertTrue(any("without an archive hash" in v for v in corpora.validate(broken)))

    def test_the_required_build_flags_travel_with_the_plan(self):
        # Growth allocation is part of the resource envelope: without it an
        # unchanged zlib passes 2.2M instructions where the retained evidence
        # stayed under 1.5M, so the two numbers are not comparable.
        plan = corpora.resolve(self.lock, "zlib", "regression")
        self.assertIn("scale-budget", plan["required_build_flags"])

    def test_the_primary_and_high_cap_limits_are_both_pinned(self):
        plan = corpora.resolve(self.lock, "zlib", "regression")
        self.assertEqual(plan["module_instruction_limit"], 250000)
        self.assertEqual(plan["module_instruction_cap_label"], "primary")
        high = corpora.resolve(self.lock, "zlib", "regression", high_cap=True)
        self.assertEqual(high["module_instruction_limit"], 1500000)
        self.assertEqual(high["module_instruction_cap_label"], "high-cap-experiment")

    def test_the_locked_container_limits_match_what_the_runner_passes(self):
        # Read as text on purpose: the lock claims a resource envelope, and a
        # silent change on either side must fail rather than be discovered in a
        # cost comparison a milestone later.
        source = (Path(corpora.__file__).with_name("process.py")).read_text()
        container = self.lock["resources"]["container"]
        self.assertIn(f'"--memory", "{container["memory"]}"', source)
        self.assertIn(f'"--cpus", "{container["cpus"]}"', source)
        self.assertIn('"--network", "none"', source)

    def test_the_locked_ir_budget_matches_the_build_driver(self):
        from conformance.whole import IR_BUDGET_MAX, IR_BUDGET_MULTIPLIER
        build = self.lock["resources"]["build"]
        self.assertEqual(build["ir_budget_multiplier"], IR_BUDGET_MULTIPLIER)
        self.assertEqual(build["ir_budget_max"], IR_BUDGET_MAX)


if __name__ == "__main__":
    unittest.main()
