"""Trusted full-output differential and actual connected-region coverage gate."""
import argparse
import json
from pathlib import Path
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, test_inputs

SHARD_ACCOUNTING = ("sre-native-v3",)


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
        if row["status"] != "encoded" and row.get("reason") == "connected-growth-rollback":
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
    violations = invariants(report)
    correct = len(values["clean"].splitlines()) == 593 and all(value == values["clean"] for value in values.values())
    passed = (correct and not violations and coverage["regions"] and (not args.require_memory or coverage["memory"])
              and (not args.require_predicates or coverage["predicates"])
              and (not args.require_family_conversions or coverage["family_conversions"] > 0)
              and (not args.require_shards or coverage["shards"] > 0)
              and (not args.require_aggregates or coverage["aggregate_memory_objects"] > 0)
              and (not args.require_joint_outputs or bool(coverage["joint_output_groups"])))
    result = {"passed": passed, "correctness": correct, "vectors": 593, "coverage": coverage,
              "planning_violations": violations, "report_schema": report["schema"],
              "manifest_sha256": digest(out / "manifest.json"), "commands": runner.records}
    dump(out / "connected-correctness.json", result)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
