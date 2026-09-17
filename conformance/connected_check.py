"""Trusted full-output differential and actual connected-region coverage gate."""
import argparse
import json
from pathlib import Path
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, test_inputs

SHARD_ACCOUNTING = ("sre-native-v3", "sre-native-v4")
# The fixed skip vocabulary of the encoded-call interface pass. A row with any
# other reason is a reporting bug, not coverage.
CALL_SKIPS = ("not-original", "exported-or-address-taken", "varargs", "eh-or-personality",
              "recursive", "unsupported-signature", "unsupported-call-site", "function-budget",
              "no-callers")


def call_violations(report):
    """Encoded-call rows checked against themselves, as explicit strings.

    A row that claims an encoded interface carrying no pair, keeps a plaintext
    wrapper, uses a reason outside the fixed vocabulary, or reports more
    absorbed pairs than its interface has, fails the gate instead of being read
    as protection.
    """
    rows = report.get("encoded_calls")
    if rows is None:
        return []
    violations = []
    for row in rows:
        where = row["function"]
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
            if row["absorbed_arguments"] > row["encoded_parameters"]:
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
                                            "absorbed_results", "result_rebuilds")) or row["returns_pair"]:
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
                 "parameter_reconstructions", "pair_supplies", "absorbed_arguments",
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
        # A function rejected before planning publishes no accounting at all,
        # and a rolled-back one republishes its counts as attempted_*. Neither
        # ever claimed the identity below. Any OTHER row missing the fields is
        # itself a violation: never crash, and never pass by omission.
        if row.get("reason") in ("structure-or-size", "connected-growth-rollback"):
            continue
        missing = [key for key in ("eligible_estimated_cost", "selected_estimated_cost",
                                   "skipped_estimated_cost", "shard_lost_estimated_cost",
                                   "component_estimated_cost_limit", "shard_policy", "shards",
                                   "sharded_components", "oversized_components", "eligible_nodes")
                   if key not in row]
        if missing:
            violations.append(f"{where}: planning accounting missing {', '.join(missing)}")
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
    if "joint_policy" not in row or "joint_output_groups" not in row:
        return []
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
                # Planner estimates, not measured instructions. Eligible cost
                # equals selected plus skipped plus shard loss, exactly.
                "eligible_estimated_cost": sum(row.get("eligible_estimated_cost", 0) for row in planned),
                "selected_estimated_cost": sum(row.get("selected_estimated_cost", 0) for row in planned),
                "skipped_estimated_cost": sum(row.get("skipped_estimated_cost", 0) for row in planned),
                "shard_lost_estimated_cost": sum(row.get("shard_lost_estimated_cost", 0) for row in planned)}
    groups, candidates, rewritten = joint_coverage(regions)
    # None means the compiler that wrote this report predates the experiment.
    coverage["joint_output_groups"] = groups
    coverage["joint_output_candidates"] = candidates
    coverage["joint_lane_uses_rewritten"] = rewritten
    coverage.update(lane_coverage(report))
    calls = call_coverage(report)
    coverage["encoded_calls"] = calls
    violations = invariants(report) + call_violations(report)
    correct = len(values["clean"].splitlines()) == 593 and all(value == values["clean"] for value in values.values())
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
