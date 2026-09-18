"""Trusted full-output differential and actual connected-region coverage gate."""
import argparse
import json
from pathlib import Path
from conformance.call_policy import policy_violations
from conformance.bundle_check import bundle_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, test_inputs

SHARD_ACCOUNTING = ("sre-native-v3", "sre-native-v4", "sre-native-v5", "sre-native-v6")
# Schemas carrying the v5 interface repairs: the partial-absorption counter,
# the recorded encoded symbol and exact region cost sums.
INTERFACE_ACCOUNTING = ("sre-native-v5", "sre-native-v6")
# The fixed skip vocabulary of the encoded-call interface pass. A row with any
# other reason is a reporting bug, not coverage.
CALL_SKIPS = ("not-original", "exported-or-address-taken", "varargs", "eh-or-personality",
              "recursive", "unsupported-signature", "unsupported-call-site", "function-budget",
              "no-callers", "musttail-body", "returns-twice", "no-return", "call-policy-owner")


def cost_accounting(report):
    """One cost identity shared by the fixture and whole-application gates."""
    fields = ("eligible_estimated_cost", "selected_estimated_cost",
              "skipped_estimated_cost", "shard_lost_estimated_cost")
    if report["schema"] not in SHARD_ACCOUNTING:
        return dict.fromkeys((*fields, "rollback_estimated_cost"))
    rows = report.get("connected_regions", [])
    costs = {field: sum(row.get(field, 0) for row in rows) for field in fields}
    costs["rollback_estimated_cost"] = sum(row.get("eligible_estimated_cost", 0) for row in rows
                                           if row.get("reason") == "connected-growth-rollback")
    return costs


def report_violations(report):
    """Validate before computing coverage; malformed reports fail explicitly."""
    violations = []
    for check in (invariants, call_violations, policy_violations, plan_violations, bundle_violations):
        try:
            violations.extend(check(report))
        except (KeyError, TypeError, ValueError) as exc:
            violations.append(f"{check.__name__}: malformed report: {exc}")
    return violations


BOUNDARY_REASONS = ("external-abi", "address-exposure", "unsupported-operation",
                    "object-escape", "component-limit", "interface-mismatch", "budget-loss")
PLAN_FAMILIES = ("none", "xor-prefix-pair", "additive-pair", "triangular-xor", "triangular-additive")
PLAN_VERIFICATION = ("unverified", "algebraic", "enumerated", "smt")
PLAN_CONSUMERS = ("branch-choice", "address", "return", "call", "store", "phi",
                  "unsupported-consumer")


def plan_violations(report):
    """The private typed plan checked against itself and against its own row.

    A row without a plan is unknown, not a violation: the planner publishes one
    only when it was asked to. A plan that is present must agree with the
    accounting beside it, must carry the compiler's own validation result, and
    must not report an unmeasured inventory as a set of zeroes.
    """
    violations = []
    for row in report.get("connected_regions", []):
        plan = row.get("plan")
        if plan is None:
            if (report.get("features", {}).get("plan") and
                    row.get("reason") != "structure-or-size"):
                violations.append(f"{row['function']}: requested typed plan is missing")
            continue
        where = f"{row['function']} plan"
        if plan.get("plan_version") not in (1, 2):
            violations.append(f"{where}: unsupported plan version {plan.get('plan_version')!r}")
            continue
        if not plan.get("sealed"):
            violations.append(f"{where}: published without sealing the original graph")
        # The compiler validates its own plan; a nonempty list is a planner bug
        # and is never allowed to pass silently.
        for detail in plan.get("violations", []):
            violations.append(f"{where}: {detail}")
        if plan.get("eligible_nodes") != row.get("eligible_nodes"):
            violations.append(f"{where}: eligible nodes disagree with the row")
        costs = plan.get("costs", {})
        rolled_back = row.get("reason") == "connected-growth-rollback"
        if bool(costs.get("rolled_back")) != rolled_back:
            violations.append(f"{where}: rollback status disagrees with the row")
        for field, key in (("eligible_estimated", "eligible_estimated_cost"),
                           ("selected_estimated", "selected_estimated_cost"),
                           ("skipped_estimated", "skipped_estimated_cost"),
                           ("lost_estimated", "shard_lost_estimated_cost")):
            if rolled_back:
                key = {"selected_estimated_cost": "attempted_estimated_cost",
                       "skipped_estimated_cost": "attempted_skipped_estimated_cost",
                       "shard_lost_estimated_cost": "attempted_shard_lost_estimated_cost"}.get(key, key)
            if key in row and costs.get(field) != row[key]:
                violations.append(f"{where}: {field} disagrees with {key}")
        # Generated instructions must never enter a denominator.
        if len(plan.get("operations", [])) > (plan.get("eligible_nodes") or 0):
            violations.append(f"{where}: more planned operations than eligible nodes")
        for op in plan.get("operations", []):
            if op["selected"] and op["reason"] is not None:
                violations.append(f"{where}: {op['origin']} is selected and carries a skip reason")
            if not op["selected"] and op["reason"] not in BOUNDARY_REASONS:
                violations.append(f"{where}: {op['origin']} was dropped without a known reason")
        if plan.get("plan_version") == 2:
            ops, regions = plan.get("operations", []), plan.get("regions", [])
            for op in ops:
                edges = op.get("operands")
                if (not isinstance(edges, list) or op.get("operand_count") != len(edges)
                        or any(type(i) is not int or not 0 <= i < len(ops) for i in edges)):
                    violations.append(f"{where}: invalid operand identities at {op['origin']}")
                if op["selected"] and (type(op.get("region")) is not int
                                       or not 0 <= op["region"] < len(regions)):
                    violations.append(f"{where}: selected operation without a valid region")
            for index, region in enumerate(regions):
                members = [op for op in ops if op["selected"] and op.get("region") == index]
                if (len(members) != region["nodes"] or
                        sum(op["estimated_cost"] for op in members) != region["estimated_cost"]):
                    violations.append(f"{where}: region membership or cost disagrees with operations")
            for bundle in plan.get("bundles", []):
                members = bundle.get("members")
                if (not isinstance(members, list) or bundle.get("member_count") != len(members)
                        or any(type(i) is not int or not 0 <= i < len(ops) for i in members)):
                    violations.append(f"{where}: invalid bundle member identities")
        for rep in plan.get("representations", []):
            if rep["family"] not in PLAN_FAMILIES:
                violations.append(f"{where}: unknown representation family {rep['family']!r}")
            if rep["verification"] not in PLAN_VERIFICATION:
                violations.append(f"{where}: unknown verification {rep['verification']!r}")
            if not rep["lanes"] or not rep["invariant"] or not rep["seed_namespace"]:
                violations.append(f"{where}: representation without lanes, invariant or namespace")
        for site in plan.get("decodes", []):
            if site["consumer"] not in PLAN_CONSUMERS:
                violations.append(f"{where}: unknown decode consumer {site['consumer']!r}")
            if site["reason"] not in BOUNDARY_REASONS:
                violations.append(f"{where}: decode at {site['origin']} without a known reason")
            if site["uses"] < 1:
                violations.append(f"{where}: decode at {site['origin']} serves no use")
        inventory = plan.get("boundary_inventory", {})
        counted = ("total_scalar_use_edges", "absorbed_edges", "constant_entries",
                   "protected_operations", "exposures", "useful_work_total", "useful_work_max")
        if inventory.get("measured"):
            if set(inventory.get("scalar_use_edges", {})) != set(BOUNDARY_REASONS):
                violations.append(f"{where}: inventory vocabulary is not the fixed one")
            if inventory.get("exposures") != len(plan.get("decodes", [])):
                violations.append(f"{where}: exposures disagree with the decode sites")
            if sum(inventory.get("scalar_use_edges", {}).values()) != inventory.get("total_scalar_use_edges"):
                violations.append(f"{where}: scalar-use edges do not sum to the total")
            if inventory.get("useful_work_max", 0) > inventory.get("protected_operations", 0):
                violations.append(f"{where}: useful work exceeds the protected operations")
        else:
            # An unmeasured inventory is unknown. Publishing it as zero would
            # read as "no boundaries", which is the opposite of the truth.
            if any(inventory.get(key) is not None for key in counted):
                violations.append(f"{where}: unmeasured inventory published counts instead of null")
    return violations


def call_violations(report):
    """Encoded-call rows checked against themselves, as explicit strings.

    A row that claims an encoded interface carrying no pair, keeps a plaintext
    wrapper, uses a reason outside the fixed vocabulary, or reports more
    absorbed pairs than its interface has, fails the gate instead of being read
    as protection.
    """
    rows = report.get("encoded_calls")
    if rows is None:
        return (["encoded-call feature has no interface report"]
                if report.get("features", {}).get("encoded_calls") else [])
    violations = []
    for row in rows:
        where = row["function"]
        if row["status"] not in ("encoded", "skipped"):
            violations.append(f"{where}: unknown interface status {row['status']!r}")
            continue
        counters = ("parameters", "encoded_parameters", "callers", "call_sites_rewritten",
                    "result_rebuilds", "activation_allocas", "absorbed_arguments", "absorbed_results")
        if report["schema"] in INTERFACE_ACCOUNTING:
            counters += ("partially_absorbed_arguments",)
            if (row["status"] == "encoded") != bool(row["encoded_function"]):
                violations.append(f"{where}: encoded symbol does not match interface status")
        if any(type(row[key]) is not int or row[key] < 0 for key in counters):
            violations.append(f"{where}: interface counts must be nonnegative integers")
            continue
        if row["status"] == "encoded":
            if row["reason"]:
                violations.append(f"{where}: encoded row carries the skip reason {row['reason']!r}")
            if row["encoded_parameters"] + int(row["returns_pair"]) == 0:
                violations.append(f"{where}: encoded interface carries no pair")
            if row["encoded_parameters"] != row["parameters"]:
                violations.append(f"{where}: {row['parameters']} parameters but "
                                  f"{row['encoded_parameters']} encoded")
            if not row["call_sites_rewritten"]:
                violations.append(f"{where}: encoded interface rewrote no call site")
            if row["wrapper_retained"]:
                violations.append(f"{where}: a duplicate plaintext wrapper was retained")
            if row["representation"] != "xor-pair-v1":
                violations.append(f"{where}: unexpected representation {row['representation']!r}")
            if row["absorbed_arguments"] + row.get("partially_absorbed_arguments", 0) > row["encoded_parameters"]:
                violations.append(f"{where}: more absorbed argument pairs than parameters")
            supplies = row["encoded_parameters"] * row["call_sites_rewritten"] + row["result_rebuilds"]
            if row["absorbed_results"] > supplies:
                violations.append(f"{where}: {row['absorbed_results']} absorbed supplies "
                                  f"but only {supplies} pairs are supplied")
            if row["returns_pair"] != bool(row["result_rebuilds"]):
                violations.append(f"{where}: a pair result must be rebuilt at least once")
        else:
            if row["reason"] not in CALL_SKIPS:
                violations.append(f"{where}: skip reason {row['reason']!r} is outside the vocabulary")
            if any(row[field] for field in ("encoded_parameters", "call_sites_rewritten",
                                            "activation_allocas", "absorbed_arguments",
                                            "absorbed_results", "result_rebuilds")) or row["returns_pair"] or row.get("partially_absorbed_arguments", 0):
                violations.append(f"{where}: a skipped interface reported encoded work")
    return violations


def call_coverage(report):
    """Pairs that actually cross a private call boundary, and what became of them.

    A report without the array has an unknown denominator, never zero. Moved
    pairs are pairs the interface carries; absorbed pairs are the subset a
    later pass consumed without a scalar decode.
    """
    rows = report.get("encoded_calls")
    if rows is None:
        return {key: None for key in
                ("encoded_interfaces", "encoded_widths", "call_sites_rewritten",
                 "argument_pairs_moved", "result_pairs_moved",
                 "parameter_reconstructions", "pair_supplies", "absorbed_arguments", "partially_absorbed_arguments",
                 "absorbed_results", "activation_allocas", "wrappers_retained", "skips")}
    encoded = [row for row in rows if row["status"] == "encoded"]
    skips = {}
    for row in rows:
        if row["status"] != "encoded":
            skips[row["reason"]] = skips.get(row["reason"], 0) + 1
    return {"encoded_interfaces": len(encoded),
            "encoded_widths": sorted({w for row in encoded for w in row["widths"]}),
            "call_sites_rewritten": sum(row["call_sites_rewritten"] for row in encoded),
            "argument_pairs_moved": sum(row["encoded_parameters"] * row["call_sites_rewritten"]
                                        for row in encoded),
            "result_pairs_moved": sum(row["call_sites_rewritten"] for row in encoded
                                      if row["returns_pair"]),
            # The denominator of absorbed_arguments: one parameter reconstruction
            # per parameter of each encoded interface, however many call sites
            # feed it.
            "parameter_reconstructions": sum(row["encoded_parameters"] for row in encoded),
            # The denominator of absorbed_results: one caller split per argument
            # per call site, plus one callee rebuild per return site.
            "pair_supplies": sum(row["encoded_parameters"] * row["call_sites_rewritten"]
                                 + row["result_rebuilds"] for row in encoded),
            "absorbed_arguments": sum(row["absorbed_arguments"] for row in encoded),
            "partially_absorbed_arguments": (sum(row["partially_absorbed_arguments"] for row in encoded)
                                             if report["schema"] in INTERFACE_ACCOUNTING else None),
            "absorbed_results": sum(row["absorbed_results"] for row in encoded),
            "activation_allocas": sum(row["activation_allocas"] for row in encoded),
            "wrappers_retained": sum(int(row["wrapper_retained"]) for row in rows),
            "skips": skips}


def call_coverage_passes(coverage, require_widths=False):
    if not coverage["encoded_interfaces"]:
        return False
    if not coverage["argument_pairs_moved"] and not coverage["result_pairs_moved"]:
        return False
    return not require_widths or {8, 16, 32, 64}.issubset(set(coverage["encoded_widths"]))


def invariants(report):
    """Planner self-consistency violations, as explicit strings.

    These check the report against itself: an accounting bug that inflated
    coverage, or a shard count that no region supports, fails here instead of
    being read as protection.
    """
    if report["schema"] not in SHARD_ACCOUNTING:
        return []
    violations = []
    for row in report["connected_regions"]:
        where = row["function"]
        if row["status"] not in ("encoded", "skipped"):
            violations.append(f"{where}: unknown connected status {row['status']!r}")
            continue
        # A function rejected before planning publishes no accounting at all,
        # and a rolled-back one republishes its counts as attempted_*. Neither
        # ever claimed the identity below. Any OTHER row missing the fields is
        # itself a violation: never crash, and never pass by omission.
        if row["status"] == "skipped" and row.get("reason") in ("structure-or-size", "connected-growth-rollback"):
            continue
        missing = [key for key in ("eligible_estimated_cost", "selected_estimated_cost",
                                   "skipped_estimated_cost", "shard_lost_estimated_cost",
                                   "component_estimated_cost_limit", "shard_policy", "shards",
                                   "sharded_components", "oversized_components", "eligible_nodes",
                                   "eligible_memory_objects", "eligible_memory_edges")
                   if key not in row]
        if missing:
            violations.append(f"{where}: planning accounting missing {', '.join(missing)}")
            continue
        counts = ("eligible_estimated_cost", "selected_estimated_cost", "skipped_estimated_cost",
                  "shard_lost_estimated_cost", "component_estimated_cost_limit", "shards",
                  "sharded_components", "oversized_components", "eligible_nodes",
                  "eligible_memory_objects", "eligible_memory_edges")
        if any(type(row[key]) is not int or row[key] < 0 for key in counts):
            violations.append(f"{where}: planning counts must be nonnegative integers")
            continue
        eligible = row["eligible_estimated_cost"]
        parts = row["selected_estimated_cost"] + row["skipped_estimated_cost"] + row["shard_lost_estimated_cost"]
        if eligible != parts:
            violations.append(f"{where}: eligible cost {eligible} != selected+skipped+lost {parts}")
        if row["selected_estimated_cost"] > row["component_estimated_cost_limit"]:
            violations.append(f"{where}: selected cost exceeds the component limit")
        if row["shard_policy"] == "whole-component-only" and (row["shards"] or row["sharded_components"]):
            violations.append(f"{where}: shards reported without the shard policy")
        regions = row.get("regions", [])
        if row["status"] == "encoded":
            missing = [key for key in ("nodes", "regions", "objects", "memory_edges", "predicates") if key not in row]
            if missing:
                violations.append(f"{where}: encoded accounting missing {', '.join(missing)}")
                continue
        if report["schema"] in INTERFACE_ACCOUNTING:
            # Region estimates now sum actual node costs, including both
            # representation parts of a shard; no proportional rounding loss.
            costs = {}
            for region in regions:
                key = (region["component"], region["shard"])
                if region["sharded"]:
                    costs[key] = costs.get(key, 0) + region["estimated_cost"]
            if sum(region["estimated_cost"] for region in regions) != row["selected_estimated_cost"]:
                violations.append(f"{where}: region costs do not sum to selected cost")
            if any(cost > row["shard_estimated_cost_limit"] for cost in costs.values()):
                violations.append(f"{where}: an atomic shard exceeds the reported shard limit")
        if row["status"] == "encoded" and sum(r["nodes"] for r in regions) != row["nodes"]:
            violations.append(f"{where}: region nodes do not sum to selected nodes")
        if row.get("nodes", 0) > row["eligible_nodes"]:
            violations.append(f"{where}: selected more nodes than were eligible")
        sharded = {(r["component"], r["shard"]) for r in regions if r["sharded"]}
        if len(sharded) != row["shards"]:
            violations.append(f"{where}: {row['shards']} shards reported, {len(sharded)} in regions")
        if len({component for component, _ in sharded}) != row["sharded_components"]:
            violations.append(f"{where}: sharded component count does not match the regions")
        for component in {c for c, _ in sharded}:
            ids = sorted(shard for c, shard in sharded if c == component)
            if ids != list(range(len(ids))):
                violations.append(f"{where}: component {component} shard ids are not contiguous from zero")
        if row["sharded_components"] > row["oversized_components"]:
            violations.append(f"{where}: more components sharded than were oversized")
        # The memory denominator may only ever grow. An encoded object that no
        # eligible object accounts for, or memory edges beyond the eligible
        # ones, would be a coverage ratio inflated by a shrunken denominator.
        objects = row.get("objects", [])
        encoded = [o for o in objects if o["status"] == "encoded"]
        if len(encoded) > row["eligible_memory_objects"]:
            violations.append(f"{where}: {len(encoded)} memory objects encoded, {row['eligible_memory_objects']} eligible")
        if row.get("memory_edges", 0) > row["eligible_memory_edges"]:
            violations.append(f"{where}: memory edges exceed the eligible memory denominator")
        aggregates = [o for o in encoded if o.get("layout") == "aggregate-leaves"]
        if row.get("memory_layout_policy") == "scalar-and-flat-array-only" and aggregates:
            violations.append(f"{where}: aggregate objects encoded without the aggregate layout policy")
        if row["status"] == "encoded" and len(aggregates) != row.get("aggregate_memory_objects", 0):
            violations.append(f"{where}: {row.get('aggregate_memory_objects', 0)} aggregate objects reported, "
                              f"{len(aggregates)} in the object rows")
        if row.get("eligible_aggregate_memory_objects", 0) > row["eligible_memory_objects"]:
            violations.append(f"{where}: more aggregate objects eligible than objects")
        violations += joint_invariants(row, where)
    return violations


def joint_invariants(row, where):
    """Joint-output self-consistency, or nothing when the field set is absent.

    A report written before this experiment existed carries no joint fields at
    all; that is unknown, not a violation and not zero coverage.
    """
    if "joint_policy" not in row:
        return []
    missing = [key for key in ("joint_output_groups", "joint_output_candidates", "joint_lane_uses_rewritten")
               if key not in row]
    if missing:
        return [f"{where}: joint accounting missing {', '.join(missing)}"]
    violations = []
    groups = row["joint_output_groups"]
    if row["joint_policy"] == "disabled" and groups:
        violations.append(f"{where}: joint groups reported with the coupling disabled")
    if 2 * groups > row["joint_output_candidates"]:
        violations.append(f"{where}: {groups} joint groups need more candidates than were eligible")
    # Each group must govern at least one lane use per member, otherwise it
    # mixed and unmixed values nothing downstream reads.
    if row["joint_lane_uses_rewritten"] < 2 * groups:
        violations.append(f"{where}: joint groups rewrote fewer lane uses than members")
    return violations


def joint_coverage(regions):
    """Selected joint groups, or None when any encoded row cannot report them."""
    if not regions or any("joint_output_groups" not in row for row in regions):
        return None, None, None
    return (sum(row["joint_output_groups"] for row in regions),
            sum(row["joint_output_candidates"] for row in regions),
            sum(row["joint_lane_uses_rewritten"] for row in regions))
def lane_coverage(report):
    """P6 coupling coverage, with an explicit denominator.

    A dispatcher can only be keyed on encoded data in a function that keeps both
    a surviving flattening state and a coupled data context. Reports that predate
    the field leave the numerator unknown, never zero.
    """
    state = report.get("flattening_state", [])
    known = [row for row in state if "lane_keyed_dispatcher_reads" in row]
    couplable = [row for row in state if row.get("coupled_data_updates", 0) > 0 and row.get("words", 0) > 0]
    return {"flattened_functions": len(state),
            "couplable_flattened_functions": len(couplable),
            "lane_keyed_functions": (sum(1 for row in known if row["lane_keyed_dispatcher_reads"] > 0)
                                     if len(known) == len(state) else None),
            "lane_keyed_dispatcher_reads": (sum(row["lane_keyed_dispatcher_reads"] for row in known)
                                            if len(known) == len(state) else None),
            "lane_transitions": report.get("features", {}).get("lane_transitions")}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("build", type=Path)
    p.add_argument("--toolchain-image")
    p.add_argument("--require-memory", action="store_true")
    p.add_argument("--require-predicates", action="store_true")
    p.add_argument("--require-family-conversions", action="store_true")
    p.add_argument("--require-shards", action="store_true",
                   help="require at least one oversized component actually partitioned into selected shards")
    p.add_argument("--require-aggregates", action="store_true",
                   help="require at least one closed constant-index aggregate object actually encoded")
    p.add_argument("--require-joint-outputs", action="store_true",
                   help="require at least one emitted joint-output group; an unreported count is unknown, not a pass")
    p.add_argument("--require-lane-coupling", action="store_true",
                   help="require at least one surviving dispatcher to read the encoded-data word")
    p.add_argument("--require-encoded-calls", action="store_true",
                   help="require at least one private interface whose arguments or results genuinely cross as pairs")
    p.add_argument("--require-encoded-widths", action="store_true",
                   help="require encoded private interfaces at all of 8, 16, 32 and 64 bits")
    args = p.parse_args()
    out = args.build.resolve()
    manifest = json.loads((out / "manifest.json").read_text())
    runner = Runner(ROOT, out / "connected-check-logs", args.toolchain_image, mounts=(out,))
    values = {}
    for arm, info in manifest["artifacts"].items():
        binary = out / arm
        if digest(binary) != info["binary_sha256"]:
            raise ToolFailure("binary hash changed")
        values[arm] = runner.run([str(binary)], stdin=test_inputs(512))
    report = json.loads((out / "native.json").read_text())
    violations = report_violations(report)
    correct = (set(values) >= {"clean", "native"} and len(values["clean"].splitlines()) == 593
               and all(value == values["clean"] for value in values.values()))
    if violations:
        dump(out / "connected-correctness.json", {
            "passed": False, "correctness": correct, "vectors": 593, "coverage": None,
            "planning_violations": violations, "report_schema": report.get("schema"),
            "manifest_sha256": digest(out / "manifest.json"), "commands": runner.records})
        return 1
    regions = [row for row in report["connected_regions"] if row["status"] == "encoded"]
    encoded_objects = [obj for row in regions for obj in row["objects"] if obj["status"] == "encoded"]
    planned = report["connected_regions"]
    coverage = {"regions": bool(regions), "memory": bool(encoded_objects),
                "predicates": any(row["predicates"] > 0 for row in regions),
                "family_conversions": sum(row.get("family_conversions", 0) for row in regions),
                "mixed_family_components": sum(row.get("mixed_family_components", 0) for row in regions),
                "shards": sum(row.get("shards", 0) for row in regions),
                # Memory coverage next to its own denominator, so a widened
                # eligibility is visible rather than hidden in a ratio.
                "memory_edges": sum(row["memory_edges"] for row in regions),
                "aggregate_memory_objects": sum(row.get("aggregate_memory_objects", 0) for row in regions),
                "aggregate_memory_edges": sum(row.get("aggregate_memory_edges", 0) for row in regions),
                "encoded_memory_objects": len(encoded_objects),
                "eligible_memory_objects": sum(row.get("eligible_memory_objects", 0) for row in planned),
                "eligible_aggregate_memory_objects": sum(row.get("eligible_aggregate_memory_objects", 0) for row in planned),
                "eligible_memory_edges": sum(row.get("eligible_memory_edges", 0) for row in planned),
                "memory_object_skip_reasons": sorted({o["reason"] for row in planned
                                                      for o in row.get("objects", []) if o["status"] == "skipped"}),
                "sharded_components": sum(row.get("sharded_components", 0) for row in regions),
                "oversized_components": sum(row.get("oversized_components", 0) for row in planned),
                "eligible_nodes": sum(row.get("eligible_nodes", 0) for row in planned),
                "selected_nodes": sum(row["nodes"] for row in regions),
                **cost_accounting(report)}
    groups, candidates, rewritten = joint_coverage(regions)
    # None means the compiler that wrote this report predates the experiment.
    coverage["joint_output_groups"] = groups
    coverage["joint_output_candidates"] = candidates
    coverage["joint_lane_uses_rewritten"] = rewritten
    coverage.update(lane_coverage(report))
    calls = call_coverage(report)
    coverage["encoded_calls"] = calls
    passed = (correct and not violations and coverage["regions"] and (not args.require_memory or coverage["memory"])
              and (not args.require_predicates or coverage["predicates"])
              and (not args.require_family_conversions or coverage["family_conversions"] > 0)
              and (not args.require_shards or coverage["shards"] > 0)
              and (not args.require_aggregates or coverage["aggregate_memory_objects"] > 0)
              and (not args.require_joint_outputs or bool(coverage["joint_output_groups"]))
              # Unknown is not success: an old report cannot satisfy this gate.
              and (not args.require_lane_coupling or bool(coverage["lane_keyed_dispatcher_reads"]))
              and (not (args.require_encoded_calls or args.require_encoded_widths)
                   or call_coverage_passes(calls, args.require_encoded_widths)))
    result = {"passed": passed, "correctness": correct, "vectors": 593, "coverage": coverage,
              "planning_violations": violations, "report_schema": report["schema"],
              "manifest_sha256": digest(out / "manifest.json"), "commands": runner.records}
    dump(out / "connected-correctness.json", result)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
