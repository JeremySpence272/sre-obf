"""Manifest-pinned whole-application build/correctness/coverage measurement.

This trusted suite executes clean/protected workload binaries, not agent input.
It is a scale/conformance measurement, never an automatic hardness verdict.
Sources must already be present; no network fetching occurs in this runner.
"""
from __future__ import annotations
import argparse
import base64
from collections import Counter
import json
from pathlib import Path
from conformance import bundle_options, corpora
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.whole import build, parser as build_parser
from conformance.run import ROOT
from conformance.connected_check import SHARD_ACCOUNTING, cost_accounting, report_violations
from conformance.bundle_check import bundle_summary
from conformance.tile_check import tile_summary
from conformance.immutable_check import immutable_summary


# Reports that actually emit connected planning denominators. An older report
# leaves them unknown, and unknown is never zero.
MEMORY_DENOMINATORS = ("sre-native-v2", *SHARD_ACCOUNTING)

# Every source-owned function lands in exactly one of these. A function that no
# pass ever touched is a bucket with a name, not an absence from the report.
SOURCE_DISPOSITIONS = ("encoded", "rolled-back", "planner-skipped", "not-planned",
                       "not-selected", "absorbed-before-selection", "unaccounted")

# Quantities that describe emitted shape rather than resistance. Named here so
# no reader of a result file mistakes one for evidence of protection.
DIAGNOSTIC_NOT_PROTECTION = ("connected_nodes", "connected_predicates", "connected_family_conversions",
                             "final_ir_instructions", "generated_support_instructions",
                             "emitted family counts", "AST size", "taint-set size",
                             "decompiler output length")


def ratio(numerator, denominator):
    """A rate, or None. A missing or empty denominator is unknown, never zero."""
    if numerator is None or denominator is None or denominator == 0:
        return None
    return round(numerator / denominator, 6)


def view(numerator, denominator, scope):
    return {"numerator": numerator, "denominator": denominator,
            "ratio": ratio(numerator, denominator), "scope": scope}


def merge_owners(report):
    """Source function -> the merged function that now owns its body, if any.

    Merging happens after the input inventory is taken, so without this map a
    merged origin is credited to nothing at all.
    """
    owners = {}
    for group in report.get("merged_groups", []) or []:
        for member in str(group.get("members", "")).split(","):
            if member:
                owners[member] = group["function"]
    return owners


def source_ledger(report):
    """Every source-owned function, in exactly one disposition.

    The input inventory is taken before fusion, merging and every pass, so it
    is the only denominator that cannot shrink under the transformations it is
    measuring. Functions the module lost before selection are a named bucket,
    and functions that appear nowhere later are `unaccounted`: a reporting
    defect that must be visible rather than silently outside the denominator.
    """
    inventory = report.get("input_inventory", {})
    rows = inventory.get("functions")
    if rows is None:
        return None
    source = [row for row in rows if not row.get("generated_helper")]
    selection = {row["function"]: row for row in report.get("functions", []) or []}
    planner = {row["function"]: row for row in report.get("connected_regions", []) or []}
    bundled = {row["function"] for row in report.get("bundles", []) if row["retained_operations"]}
    tiled = {row["function"] for row in report.get("object_bundles", []) if row["retained_operations"]}
    final = {row["function"] for row in (report.get("final_inventory", {}).get("functions") or [])}
    owners = merge_owners(report)
    encoded = {row["function"]: row["encoded_function"]
               for row in report.get("encoded_calls", []) or []
               if row.get("status") == "encoded" and row.get("encoded_function")}
    absorbed = {row["function"]: row for row in report.get("fusion_absorbed", []) or []}
    flattened = {row["function"] for row in report.get("flattening_state", []) or []}
    counts = dict.fromkeys(SOURCE_DISPOSITIONS, 0)
    weights = dict.fromkeys(SOURCE_DISPOSITIONS, 0)
    also_flattened = dict.fromkeys(SOURCE_DISPOSITIONS, 0)
    untouched, untouched_weight = 0, 0
    skips, skip_weights, unaccounted = {}, {}, []
    for row in source:
        name, cost = row["function"], row.get("instructions", 0)
        owner = owners.get(name, name)
        owner = encoded.get(owner, owner)
        plan = planner.get(owner)
        if name in selection and not selection[name].get("selected", True):
            state = "not-selected"
        elif owner in bundled or owner in tiled:
            state = "encoded"
        elif plan is None:
            if name in selection or name in owners:
                state = "not-planned"
            elif name in absorbed:
                state = "absorbed-before-selection"
            else:
                state = "unaccounted"
        elif plan["status"] == "encoded":
            state = "encoded"
        elif plan.get("reason") == "connected-growth-rollback":
            state = "rolled-back"
        else:
            state = "planner-skipped"
            reason = plan.get("reason") or "unspecified"
            skips[reason] = skips.get(reason, 0) + 1
            skip_weights[reason] = skip_weights.get(reason, 0) + cost
        if state == "unaccounted" and len(unaccounted) < 32:
            unaccounted.append(name)
        counts[state] += 1
        weights[state] += cost
        # "Touched by neither pass" is counted directly rather than inferred
        # from two separate tables that a reader would have to intersect.
        if owner in flattened:
            also_flattened[state] += 1
        elif state not in ("encoded", "absorbed-before-selection", "unaccounted"):
            untouched += 1
            untouched_weight += cost
    return {"source_functions": len(source),
            "source_instructions": sum(row.get("instructions", 0) for row in source),
            "inventory_definitions": inventory.get("definitions"),
            "functions": counts, "instructions": weights,
            "also_flattened": also_flattened,
            "untouched_by_either_pass": untouched,
            "untouched_by_either_pass_instructions": untouched_weight,
            "planner_skip_reasons": skips, "planner_skip_instructions": skip_weights,
            "merged_origins": sum(1 for row in source if row["function"] in owners),
            "merge_owners": len(set(owners.values())),
            "encoded_interface_origins": sum(1 for row in source
                if owners.get(row["function"], row["function"]) in encoded),
            "absorption": list(absorbed.values()),
            "coverage_unknown_functions": counts["absorbed-before-selection"] + counts["unaccounted"],
            "generated_functions_in_source_inventory":
                sum(1 for row in rows if row.get("generated_helper")),
            "unaccounted_examples": unaccounted,
            "selection_rows": len(selection), "planner_rows": len(planner),
            "bundle_owners": len(bundled),
            "object_bundle_owners": len(tiled),
            "scope": "input IR before fusion, merging and every pass; a merged origin is "
                     "credited to its current owner, including encoded-interface renames. "
                     "Selected regions include retained connected regions or bundles. "
                     "Instruction weights are whole-function input weights, not counts of "
                     "protected source instructions. Explicit fusion/dead-code removals "
                     "remain an absorption bucket with unknown body coverage; an absent "
                     "function without removal evidence is unaccounted. Generated code "
                     "is never in this denominator"}


def object_ledger(report):
    """Source-owned objects beside the planner's much narrower eligibility.

    The raw denominator is every alloca and every memory operation in the input
    IR. The planner's denominator is supported closed entry allocas only. Both
    are reported: the narrow one alone would make a build with almost no memory
    coverage look complete.
    """
    rows = (report.get("input_inventory", {}) or {}).get("functions")
    planned = report.get("connected_regions", []) or []
    selected = [row for row in planned if row["status"] == "encoded"]
    accounted = [row for row in planned if "eligible_memory_objects" in row]
    known = report.get("schema") in MEMORY_DENOMINATORS and bool(accounted)
    source = None if rows is None else [row for row in rows if not row.get("generated_helper")]
    return {"source_local_objects": (sum(r["local_objects"] for r in source)
            if source is not None and all("local_objects" in r for r in source) else None),
            "source_memory_operations": (sum(r["loads"] + r["stores"] for r in source)
            if source is not None and all("loads" in r and "stores" in r for r in source) else None),
            "source_module_globals": report.get("input_inventory", {}).get("global_definitions"),
            "eligible_closed_memory_objects": sum(r.get("eligible_memory_objects", 0) for r in accounted) if known else None,
            "eligible_closed_memory_edges": sum(r.get("eligible_memory_edges", 0) for r in accounted) if known else None,
            "encoded_memory_objects": sum(1 for r in selected for o in r.get("objects", []) if o["status"] == "encoded"),
            "encoded_memory_edges": sum(r.get("memory_edges", 0) for r in selected),
            "rows_without_object_denominator": len(planned) - len(accounted),
            "scope": "source_local_objects counts input allocas after clang -O2, so promoted "
                     "locals are already gone; source_module_globals includes all input "
                     "global definitions (including compiler-owned ones), and stays null "
                     "for older inventories that did not enumerate them"}


def support_charge(report):
    """Generated support code, charged exactly once at its owning symbol.

    A helper called from forty functions is one charge, not forty. The
    per-owner distribution is a snapshot taken when helpers were processed;
    later passes keep growing them, so the module total is reported from the
    final inventory and the snapshot is never rescaled to match it.
    """
    helpers = report.get("helpers")
    final = report.get("final_inventory", {}) or {}
    charge = {"final_generated_support_instructions": final.get("helper_instructions"),
              "final_generated_support_definitions": final.get("helper_definitions"),
              "helper_stage_instructions": None, "helper_rows": None,
              "owners": None, "owners_by_kind": None, "double_charged": None,
              "scope": "each generated helper is charged once, to the owner symbol it "
                       "declares; callers of a shared helper are never charged again. The "
                       "per-owner totals are the helper-processing snapshot and are not "
                       "rescaled to the final module total"}
    if helpers is None:
        return charge
    source = {row["function"] for row in ((report.get("input_inventory", {}) or {}).get("functions") or [])}
    owners, seen, duplicates = {}, set(), 0
    for row in helpers:
        name = row.get("function")
        if name in seen:
            duplicates += 1
            continue
        seen.add(name)
        origin = row.get("origin") or "<unknown>"
        owners.setdefault(origin, 0)
        owners[origin] += row.get("instructions_after", 0)
    kinds = {"function": 0, "module": 0, "other-symbol": 0, "unknown": 0}
    for origin in owners:
        # One owner per helper. A merged owner is still a function owner; an
        # emitted table is another symbol; the module itself owns the runtime.
        kinds["unknown" if origin == "<unknown>" else
              "module" if origin == "native-module-preparation" else
              "function" if origin in source or origin.startswith("__obf_merged_")
              else "other-symbol"] += 1
    charge.update(helper_stage_instructions=sum(owners.values()), helper_rows=len(helpers),
                  owners=len(owners), owners_by_kind=kinds, double_charged=duplicates,
                  owners_scope="distinct owning symbols, not helper rows")
    return charge


def cap_ledger(report):
    """Per-function, per-object, per-region and module caps, kept distinct.

    Four different limits bind four different scopes. Collapsing them into one
    number hides which one actually stopped the work, so each is reported with
    its own policy and its own unknowns.
    """
    features = report.get("features", {}) or {}
    rows = report.get("connected_regions", []) or []

    def spread(key, rows):
        values = [row[key] for row in rows if isinstance(row.get(key), int)]
        return {"rows_with_limit": len(values), "rows_without_limit": len(rows) - len(values),
                "min": min(values) if values else None, "max": max(values) if values else None,
                "total": sum(values) if values else None}

    bounded = [row for row in rows if row.get("bounded_growth")]
    function_policy = (None if not rows or all("bounded_growth" not in row for row in rows)
                       else "bounded-growth-allocation" if bounded else "no-per-function-growth-cap")
    shard_rows = [row for row in rows if row.get("shard_policy")
                  and row["shard_policy"] != "whole-component-only"]
    return {"module": {"scope": "module", "policy": "instruction-limit",
                       "limit": features.get("module_instruction_limit"),
                       "helper_limit": features.get("helper_limit")},
            "function": {"scope": "function", "policy": function_policy,
                         **spread("growth_allocation", rows)},
            "region": {"scope": "connected component", "policy": "estimated-cost-limit",
                       "derivation": "min(20000, the per-function growth allocation) under "
                                     "bounded growth, else 20000. It is derived from the "
                                     "function cap, not chosen independently of it",
                       **spread("component_estimated_cost_limit", rows)},
            "shard": {"scope": "shard within a component",
                      "policy": (shard_rows[0]["shard_policy"] if shard_rows else
                                 "whole-component-only" if rows else None),
                      "derivation": "min(component limit, max(2048, component limit / 4))",
                      **spread("shard_estimated_cost_limit", shard_rows)},
            "object": {"scope": "memory object",
                       "policy": "bounded-leaves-and-depth" if any("object_leaf_limit" in r for r in rows) else None,
                       "limit": spread("object_leaf_limit", rows)["max"],
                       "leaf_limits": spread("object_leaf_limit", rows),
                       "depth_limits": spread("object_leaf_depth_limit", rows),
                       "missing_compiler_field": (None if any("object_leaf_limit" in r for r in rows) else
                           "connected_regions[].object_leaf_limit and object_leaf_depth_limit; "
                           "older reports leave these unknown")}}


def loss_ledger(report):
    """Selection loss and transformation rollback, never added together.

    Cost the planner declined to take and cost it took and then undid are
    different failures with different fixes. The aggregate identity
    eligible = selected + skipped + shard-lost holds only away from rollback:
    a rolled-back function keeps publishing its eligible cost while its
    selected cost reappears as `attempted`, and the residual below is exactly
    that gap.
    """
    costs = cost_accounting(report)
    rows = report.get("connected_regions", []) or []
    rolled = [row for row in rows if row.get("reason") == "connected-growth-rollback"]
    skipped = [row for row in rows if row["status"] != "encoded"
               and row.get("reason") != "connected-growth-rollback"]
    known = all(costs[key] is not None for key in costs)
    parts = None if not known else (costs["selected_estimated_cost"] + costs["skipped_estimated_cost"]
                                    + costs["shard_lost_estimated_cost"] + costs["rollback_estimated_cost"])
    residual = None if not known else costs["eligible_estimated_cost"] - parts
    return {"selection": {"skipped_estimated_cost": costs["skipped_estimated_cost"],
                          "shard_lost_estimated_cost": costs["shard_lost_estimated_cost"],
                          "skipped_components": sum(row.get("skipped_components", 0) for row in rows),
                          "shard_lost_nodes": sum(row.get("shard_lost_nodes", 0) for row in rows),
                          "functions": len(skipped)},
            "rollback": {"rollback_estimated_cost": costs["rollback_estimated_cost"],
                         "attempted_estimated_cost": sum(row.get("attempted_estimated_cost", 0) for row in rolled),
                         "attempted_nodes": sum(row.get("attempted_nodes", 0) for row in rolled),
                         "functions": len(rolled)},
            "identity": {"eligible": costs["eligible_estimated_cost"],
                         "selected": costs["selected_estimated_cost"],
                         "skipped": costs["skipped_estimated_cost"],
                         "shard_lost": costs["shard_lost_estimated_cost"],
                         "rolled_back": costs["rollback_estimated_cost"],
                         "residual": residual,
                         "balanced": None if residual is None else residual == 0,
                         "scope": "eligible = selected + skipped + shard-lost + rolled-back, "
                                  "in the planner's own node cost model, not measured "
                                  "instructions; balanced is null when the report predates "
                                  "the accounting, and null is not a pass"}}


def coverage_views(report, ledger, objects):
    """Raw and weighted coverage side by side; neither may be quoted alone.

    The plan forbids letting one weighting hide uncovered code, so the same
    build is reported against source operations, source bodies, function
    counts, planner-eligible operations and planner cost at once. They
    disagree by design: that disagreement is the finding.
    """
    planned = report.get("connected_regions", []) or []
    selected = [row for row in planned if row["status"] == "encoded"]
    nodes = sum(row["nodes"] for row in selected)
    eligible_nodes = sum(row.get("eligible_nodes", 0) for row in planned) or None
    costs = cost_accounting(report)
    encoded_instructions = None if ledger is None else ledger["instructions"]["encoded"]
    encoded_functions = None if ledger is None else ledger["functions"]["encoded"]
    return {
        "raw_operations": view(nodes, None if ledger is None else ledger["source_instructions"],
                               "stage-mixed diagnostic: selected pre-connected-lowering nodes "
                               "over all input IR instructions. Earlier passes can insert or "
                               "duplicate nodes; this is not source-instruction coverage"),
        "planner_eligible_operations": view(nodes, eligible_nodes,
                               "selected nodes over nodes the planner deemed eligible; narrow, "
                               "and never a substitute for the raw view"),
        "source_weighted_functions": view(encoded_instructions,
                               None if ledger is None else ledger["source_instructions"],
                               "input instructions of source bodies whose owner carries a "
                               "selected region, over all input instructions"),
        "function_count": view(encoded_functions,
                               None if ledger is None else ledger["source_functions"],
                               "source functions with a selected region over all source functions"),
        "planner_cost": view(costs["selected_estimated_cost"], costs["eligible_estimated_cost"],
                               "estimated selected cost over estimated eligible cost"),
        "memory_objects_raw": view(objects["encoded_memory_objects"], objects["source_local_objects"],
                               "encoded objects over every input alloca"),
        "memory_objects_eligible": view(objects["encoded_memory_objects"],
                               objects["eligible_closed_memory_objects"],
                               "encoded objects over supported closed entry allocas"),
        "memory_operations_raw": view(objects["encoded_memory_edges"], objects["source_memory_operations"],
                               "encoded memory edges over every input load and store"),
        "weighting_scope": "raw and weighted views are both reported and no single one may be "
                           "quoted as the coverage of this build",
    }


def accounting_violations(measured):
    """Accounting that contradicts itself, as explicit strings.

    These are failures, not diagnostics: a numerator larger than its own
    denominator or a cost identity that does not close means the report cannot
    be used as evidence at all.
    """
    violations = []
    ledger = measured.get("source_ledger")
    identity = measured["loss_ledger"]["identity"]
    if identity["balanced"] is False:
        violations.append(f"cost identity does not close: residual {identity['residual']}")
    if ledger is None:
        violations.append("the input inventory carries no per-function rows, so no source "
                          "denominator exists; unknown, not zero")
    else:
        total = sum(ledger["functions"].values())
        if total != ledger["source_functions"]:
            violations.append(f"disposition buckets hold {total} functions, "
                              f"{ledger['source_functions']} are source-owned")
        if ledger["functions"]["unaccounted"]:
            violations.append(f"{ledger['functions']['unaccounted']} source functions appear in "
                              f"no later stage record: {', '.join(ledger['unaccounted_examples'])}")
        if ledger["generated_functions_in_source_inventory"]:
            violations.append("generated code is inside the source denominator")
        if (ledger["inventory_definitions"] is not None
                and ledger["source_functions"] > ledger["inventory_definitions"]):
            violations.append("more source functions than the inventory counted")
    for name in ("memory_objects_raw", "memory_objects_eligible", "memory_operations_raw"):
        item = measured["coverage_views"][name]
        if item["denominator"] is not None and item["numerator"] > item["denominator"]:
            # Either the numerator counts objects the source never owned, which
            # is generated code inflating source coverage, or the denominator
            # is too narrow. Both are accounting failures, not a high score.
            violations.append(f"{name}: numerator {item['numerator']} exceeds its own "
                              f"denominator {item['denominator']}; the numerator counts "
                              "objects outside the source denominator, or the denominator "
                              "is incomplete")
    if measured["support_charge"]["double_charged"]:
        violations.append(f"{measured['support_charge']['double_charged']} generated helpers "
                          "were charged more than once")
    return violations


def coverage_passes(measured, require_flattening=False, require_memory=False, require_shards=False,
                    require_aggregate_memory=False, require_accounting=False):
    if require_accounting and measured["loss_ledger"]["identity"]["balanced"] is not True:
        return False
    if require_accounting and measured.get("source_ledger") is None:
        return False
    return ((not require_flattening or measured["functions_with_surviving_flattening"] > 0) and
            (not require_memory or measured["memory_edges"] > 0) and
            (not require_shards or (measured.get("connected_shards") or 0) > 0) and
            (not require_aggregate_memory or (measured.get("aggregate_memory_objects") or 0) > 0))


def coverage(report):
    original = report["input_inventory"]
    planned = report.get("connected_regions", [])
    selected = [r for r in planned if r["status"] == "encoded"]
    shards = report["schema"] in SHARD_ACCOUNTING

    def estimate(field):
        return sum(r.get(field, 0) for r in planned) if shards else None

    # The aggregate-leaf denominators were added inside sre-native-v3, so the
    # schema alone cannot say whether a report carries them. A report that
    # does not carry them in every planned row leaves them unknown, not zero.
    accounted = [r for r in planned if "eligible_memory_objects" in r]

    def memory_denominator(field):
        if report["schema"] not in MEMORY_DENOMINATORS or not accounted:
            return None
        return sum(r[field] for r in accounted) if all(field in r for r in accounted) else None

    names = {r["function"] for r in selected}
    flattened = {r["function"] for r in report["flattening_state"]}
    source_rows = original["functions"]
    ledger, objects = source_ledger(report), object_ledger(report)
    measured = {"source_ledger": ledger, "object_ledger": objects,
            "bundles": bundle_summary(report),
            "object_bundles": tile_summary(report),
            "immutable_bundles": immutable_summary(report),
            "support_charge": support_charge(report), "cap_ledger": cap_ledger(report),
            "loss_ledger": loss_ledger(report),
            "coverage_views": coverage_views(report, ledger, objects),
            "diagnostics_are_not_protection": list(DIAGNOSTIC_NOT_PROTECTION),
            "input_definitions": original["definitions"], "input_instructions": original["instructions"],
            "connected_functions": len(selected), "connected_nodes": sum(r["nodes"] for r in selected),
            "connected_eligible_nodes": sum(r.get("eligible_nodes", 0) for r in planned),
            "connected_predicates": sum(r["predicates"] for r in selected),
            "connected_family_conversions": sum(r.get("family_conversions", 0) for r in selected),
            "connected_mixed_family_components": sum(r.get("mixed_family_components", 0) for r in selected),
            "memory_edges": sum(r["memory_edges"] for r in selected),
            # Aggregate-leaf coverage is reported beside, never instead of,
            # the eligible denominator it came from.
            "aggregate_memory_objects": sum(r.get("aggregate_memory_objects", 0) for r in selected),
            "aggregate_memory_edges": sum(r.get("aggregate_memory_edges", 0) for r in selected),
            "eligible_closed_aggregate_memory_objects": memory_denominator("eligible_aggregate_memory_objects"),
            "eligible_closed_memory_leaves": memory_denominator("eligible_memory_leaves"),
            "input_memory_operations": sum(r["loads"] + r["stores"] for r in source_rows),
            "eligible_closed_memory_objects": sum(r.get("eligible_memory_objects", 0) for r in planned) if report["schema"] in MEMORY_DENOMINATORS else None,
            "eligible_closed_memory_edges": sum(r.get("eligible_memory_edges", 0) for r in planned) if report["schema"] in MEMORY_DENOMINATORS else None,
            "connected_oversized_components": estimate("oversized_components"),
            "connected_sharded_components": estimate("sharded_components"),
            "connected_shards": estimate("shards"),
            "connected_shard_lost_nodes": estimate("shard_lost_nodes"),
            **{"connected_" + key: value for key, value in cost_accounting(report).items()},
            "estimated_cost_scope": "the planner's own node cost model, not measured instructions; per function eligible equals selected plus skipped plus shard loss, EXCEPT for a growth-rolled-back function, which publishes its eligible cost while its selected cost is republished as attempted; connected_rollback_estimated_cost is exactly that aggregate gap",
            "memory_eligibility_scope": "supported closed entry allocas in analyzed functions; NOT all program memory operations",
            "memory_object_skips": dict(Counter(o["reason"] for r in planned
                                              for o in r.get("objects", []) if o["status"] == "skipped")),
            "functions_with_surviving_flattening": len(report["flattening_state"]),
            "flattening_matched_source_definitions": sum(r["function"] in flattened for r in source_rows),
            "flattening_matched_source_instructions": sum(r["instructions"] for r in source_rows if r["function"] in flattened),
            "connected_matched_source_definitions": sum(r["function"] in names for r in source_rows),
            "connected_matched_source_instructions": sum(r["instructions"] for r in source_rows if r["function"] in names),
            "source_weight_scope": "input bodies containing a matched selected region; NOT number of protected instructions; merged/unmatched origins are not credited here. source_ledger does credit merged origins, at the function that owns the body",
            "input_indirect_calls": sum(r["indirect_calls"] for r in source_rows),
            "connected_skips": dict(Counter(r.get("reason", "unspecified") for r in planned if r["status"] != "encoded")),
            "final_ir_instructions": report["final_inventory"]["instructions"],
            "generated_support_instructions": report["final_inventory"]["helper_instructions"],
            "selected_attributes_are_not_proof": True}
    measured["accounting_violations"] = accounting_violations(measured)
    return measured


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--spec", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--toolchain-image", required=True)
    p.add_argument("--variant", choices=("control", "v01", "v02"), default="v02")
    p.add_argument("--seed", type=int)
    p.add_argument("--module-insts", type=int)
    p.add_argument("--compile-timeout", type=float)
    p.add_argument("--corpus", help="entry in the locked evaluation matrix; it, not the command "
                                    "line, then supplies the seed set and the resource limits")
    p.add_argument("--purpose", choices=tuple(corpora.PURPOSES), default="regression",
                   help="what this run may be called; a held-out corpus refuses every other purpose")
    p.add_argument("--high-cap", action="store_true",
                   help="the separately labelled high module cap; never rewrites a primary-cap comparison")
    p.add_argument("--corpora-lock", type=Path, default=None)
    p.add_argument("--require-accounting", action="store_true",
                   help="require the cost identity to close and a source denominator to exist; "
                        "an unknown accounting then fails instead of passing by omission")
    p.add_argument("--scale-budget", action="store_true", help="Explicit fair growth-allocation experiment; not a promotion flag")
    p.add_argument("--scale-structure", action="store_true")
    for flag in ("plan", "encoded-calls", "call-policy"):
        p.add_argument("--" + flag, action="store_true")
    p.add_argument("--semantic-budget", type=int, default=0)
    bundle_options.add_options(p)
    p.add_argument("--connected-shards", action="store_true",
                   help="Explicit bounded-shard experiment for oversized connected components; not a promotion flag")
    p.add_argument("--require-flattening", action="store_true")
    p.add_argument("--require-memory", action="store_true")
    p.add_argument("--connected-aggregates", action="store_true",
                   help="Explicit bounded constant-index aggregate-leaf memory experiment; not a promotion flag")
    p.add_argument("--require-shards", action="store_true")
    p.add_argument("--require-aggregate-memory", action="store_true")
    p.add_argument("--post-o2-attack", action="store_true")
    args = p.parse_args()
    try:
        bundle_options.validate(args, args.variant == "v02")
    except ValueError as exc:
        p.error(str(exc))
    if (args.plan or args.encoded_calls or args.call_policy or args.semantic_budget) and args.variant != "v02":
        p.error("v04 experiments require the connected v02 base variant")
    if args.call_policy and not args.encoded_calls:
        p.error("--call-policy requires --encoded-calls")
    if not 0 <= args.semantic_budget <= 50:
        p.error("--semantic-budget must be 0..50")
    if args.scale_budget and args.variant != "v02":
        p.error("--scale-budget requires v02")
    if args.connected_shards and args.variant != "v02":
        p.error("--connected-shards requires v02")
    if args.require_shards and not args.connected_shards:
        p.error("--require-shards requires --connected-shards")
    if args.connected_aggregates and args.variant != "v02":
        p.error("--connected-aggregates requires v02")
    if args.require_aggregate_memory and not args.connected_aggregates:
        p.error("--require-aggregate-memory requires --connected-aggregates")
    if args.scale_structure and not args.scale_budget:
        p.error("--scale-structure requires --scale-budget")
    if args.variant == "control" and (args.require_flattening or args.require_memory or args.require_shards
                                      or args.require_aggregate_memory or args.require_accounting):
        p.error("protection coverage cannot be required of a control-only build")
    if args.variant == "control" and args.post_o2_attack:
        p.error("the post-O2 attack requires a protected build")
    spec = json.loads(args.spec.read_text())
    if spec.get("schema") != "sre-scale-v1" or not spec.get("revision") or not spec.get("sources"):
        p.error("a revision-pinned scale manifest is required")
    # The locked matrix, when named, is the authority for seeds and limits: the
    # point of freezing them is that they stop being command-line opinions.
    plan, lock = None, None
    if args.corpus:
        if args.module_insts is not None or args.compile_timeout is not None:
            p.error("--corpus pins the resource limits; do not override them on the command line")
        try:
            lock = corpora.load(args.corpora_lock)
            plan = corpora.resolve(lock, args.corpus, args.purpose, args.seed, args.high_cap)
            plan["manifest_binding"] = corpora.validate_manifest(lock, args.corpus, spec, args.spec)
        except corpora.CorpusError as exc:
            p.error(str(exc))
        if plan["corpus"] != spec.get("project"):
            p.error(f"manifest project {spec.get('project')!r} is not corpus {plan['corpus']!r}")
        # A build configuration the lock calls required is part of the resource
        # envelope, not an option. It is refused, never switched on silently:
        # a defaults-off flag stays off unless the caller asks for it.
        missing = [flag for flag in plan["required_build_flags"]
                   if not getattr(args, flag.replace("-", "_"), False)]
        if missing and args.variant != "control":
            p.error("the locked matrix requires " + ", ".join("--" + flag for flag in missing)
                    + " for a comparable scale run; pass them or do not name a locked corpus")
    elif args.purpose == "holdout" or args.high_cap:
        p.error("--purpose holdout and --high-cap only mean something against a locked --corpus")
    seed = plan["seed"] if plan else (1 if args.seed is None else args.seed)
    module_insts = plan["module_instruction_limit"] if plan else (args.module_insts or 250000)
    compile_timeout = plan["compile_timeout"] if plan else (args.compile_timeout or 180)
    root = Path(spec["root"]).resolve(strict=True)
    sources = []
    inputs = []
    for item in spec.get("inputs", spec["sources"]):
        path = (root / item["path"]).resolve(strict=True)
        if not path.is_relative_to(root) or digest(path) != item["sha256"]:
            p.error("input/header path or hash mismatch")
        inputs.append((path, item["sha256"]))
    for item in spec["sources"]:
        source = (root / item["path"]).resolve(strict=True)
        if not source.is_relative_to(root) or digest(source) != item["sha256"]:
            p.error("source path/hash mismatch")
        sources.append(source)
    out = args.out.resolve()
    if out.exists():
        p.error("use a fresh output directory")
    out.mkdir(parents=True)
    result = {"schema": "sre-scale-result-v3", "project": spec["project"], "revision": spec["revision"],
              "spec_sha256": digest(args.spec), "variant": args.variant, "seed": seed,
              "status": "incomplete", "hardness_evaluated": False,
              "generality_gate": "not-promoted", "workloads": [],
              "corpus_plan": plan, "corpora": corpora.summary(lock) if lock else None,
              "module_instruction_limit": module_insts, "compile_timeout": compile_timeout,
              "scale_budget": args.scale_budget,
              "scale_structure": args.scale_structure,
              "v04_features": {"plan": args.plan, "encoded_calls": args.encoded_calls,
                               "call_policy": args.call_policy, "semantic_budget": args.semantic_budget,
                               "bundle_flags": bundle_options.flags(args)},
              "connected_shards": args.connected_shards,
              "connected_aggregates": args.connected_aggregates,
              "post_o2_attack": args.post_o2_attack,
              "required_coverage": {"flattening": args.require_flattening, "memory": args.require_memory,
                                    "shards": args.require_shards,
                                    "aggregate_memory": args.require_aggregate_memory,
                                    "accounting": args.require_accounting},
              "input_hash_scope": "sources-and-headers" if "inputs" in spec else "source-files-only"}
    argv = [*map(str, sources), "--out", str(out / "build"), "--toolchain-image", args.toolchain_image,
            "--optimization", "O2", "--seed", str(seed), "--no-disassembly",
            "--module-insts", str(module_insts), "--compile-timeout", str(compile_timeout)]
    argv += ["--cflag=" + flag for flag in spec.get("cflags", [])]
    argv += ["--link-flag=" + flag for flag in spec.get("link_flags", [])]
    if args.post_o2_attack: argv += ["--post-o2-attack"]
    if args.variant == "control":
        argv += ["--control-only"]
    else:
        argv += ["--fusion", "--memory", "--values", "--values-wide", "--coupled-state", "--invariant"]
        if args.variant == "v02":
            argv += ["--region-plan", "connected", "--memory-ssa", "--predicate-regions", "--regional-families", "--support-regions"]
            if args.scale_budget: argv += ["--scale-budget"]
            if args.scale_structure: argv += ["--scale-structure"]
            if args.connected_shards: argv += ["--connected-shards"]
            if args.connected_aggregates: argv += ["--connected-aggregates"]
            for name in ("plan", "encoded_calls", "call_policy"):
                if getattr(args, name): argv += ["--" + name.replace("_", "-")]
            argv += ["--semantic-budget", str(args.semantic_budget)]
            argv += bundle_options.argv(args)
    phase = "build"
    try:
        manifest = build(build_parser().parse_args(argv))
        if args.variant != "control":
            report = json.loads((out / "build/native.json").read_text())
            result["planning_violations"] = report_violations(report)
            result["coverage"] = None if result["planning_violations"] else coverage(report)
            result["accounting_violations"] = (None if result["coverage"] is None
                                               else result["coverage"]["accounting_violations"])
        phase = "workload"
        runner = Runner(ROOT, out / "workload-logs", args.toolchain_image, mounts=(out, root),
                        timeout=lock["resources"]["workload"]["timeout_seconds"] if lock else 60)
        for workload in spec["workloads"]:
            stdin = base64.b64decode(workload["stdin_base64"], validate=True)
            outputs = {}
            for arm in manifest["artifacts"]:
                binary = out / "build" / arm
                if digest(binary) != manifest["artifacts"][arm]["binary_sha256"]:
                    raise ToolFailure("workload binary hash changed")
                outputs[arm] = runner.run([str(binary), *workload.get("argv", [])], stdin=stdin)
            equal = all(value == outputs["clean"] for value in outputs.values())
            # A workload needs an independently declared expected output, not
            # only agreement between two accidentally broken builds.
            import hashlib
            expected = hashlib.sha256(outputs["clean"]).hexdigest() == workload["stdout_sha256"]
            result["workloads"].append({"name": workload["name"], "differential": equal, "expected_output": expected,
                "output_bytes": len(outputs["clean"]), "sha256": hashlib.sha256(outputs["clean"]).hexdigest()})
        result["status"] = "conformance-pass" if result["workloads"] and all(w["differential"] and w["expected_output"] for w in result["workloads"]) else "correctness-failure"
        if result["status"] == "conformance-pass" and args.variant != "control":
            if result["planning_violations"]:
                result["status"] = "report-failure"
            # Accounting that contradicts itself is a failure of the evidence,
            # not a coverage shortfall: it is reported before coverage is read.
            elif result["coverage"]["accounting_violations"]:
                result["status"] = "accounting-failure"
            elif not coverage_passes(result["coverage"], args.require_flattening, args.require_memory,
                                     args.require_shards, args.require_aggregate_memory,
                                     args.require_accounting):
                identity = result["coverage"]["loss_ledger"]["identity"]
                result["status"] = ("accounting-unknown"
                                    if args.require_accounting and identity["balanced"] is None
                                    else "coverage-failure")
        result["commands"] = runner.records
    except (OSError, ValueError, ToolFailure) as exc:
        result.update(status="workload-or-tool-failure" if phase == "workload" else "build-or-tool-failure", reason=str(exc), failure_phase=phase)
        # A module-cap abort is a boundary the run hit, not an unexplained tool
        # crash. The compiler records where and by how much before it fatals;
        # lift that into the result so the cap, not a stderr file, is the
        # visible reason. It stays a failure.
        budget = out / "build/native.json.budget.json"
        if budget.exists():
            try:
                report = json.loads(budget.read_text())
                result["budget_failure"] = {key: report.get(key) for key in
                                            ("status", "stage", "instructions", "limit")}
                result["status"] = "module-budget-failure"
            except ValueError:
                result["budget_failure"] = "unreadable"
    finally:
        result["sources_unchanged"] = all(digest(path) == expected for path, expected in inputs)
        if not result["sources_unchanged"]:
            result["status"] = "source-mutation"
        dump(out / "result.json", result)
    return 0 if result["status"] == "conformance-pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
