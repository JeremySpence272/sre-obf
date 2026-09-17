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
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.whole import build, parser as build_parser
from conformance.run import ROOT


# Reports that actually emit connected planning denominators. An older report
# leaves them unknown, and unknown is never zero.
MEMORY_DENOMINATORS = ("sre-native-v2", "sre-native-v3")
SHARD_ACCOUNTING = ("sre-native-v3",)


def coverage_passes(measured, require_flattening=False, require_memory=False, require_shards=False,
                    require_aggregate_memory=False):
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
    return {"input_definitions": original["definitions"], "input_instructions": original["instructions"],
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
            "connected_eligible_estimated_cost": estimate("eligible_estimated_cost"),
            "connected_selected_estimated_cost": estimate("selected_estimated_cost"),
            "connected_skipped_estimated_cost": estimate("skipped_estimated_cost"),
            "connected_shard_lost_estimated_cost": estimate("shard_lost_estimated_cost"),
            "estimated_cost_scope": "the planner's own node cost model, not measured instructions; eligible equals selected plus skipped plus shard loss",
            "memory_eligibility_scope": "supported closed entry allocas in analyzed functions; NOT all program memory operations",
            "memory_object_skips": dict(Counter(o["reason"] for r in planned
                                              for o in r.get("objects", []) if o["status"] == "skipped")),
            "functions_with_surviving_flattening": len(report["flattening_state"]),
            "flattening_matched_source_definitions": sum(r["function"] in flattened for r in source_rows),
            "flattening_matched_source_instructions": sum(r["instructions"] for r in source_rows if r["function"] in flattened),
            "connected_matched_source_definitions": sum(r["function"] in names for r in source_rows),
            "connected_matched_source_instructions": sum(r["instructions"] for r in source_rows if r["function"] in names),
            "source_weight_scope": "input bodies containing a matched selected region; NOT number of protected instructions; merged/unmatched origins are not credited",
            "input_indirect_calls": sum(r["indirect_calls"] for r in source_rows),
            "connected_skips": dict(Counter(r.get("reason", "unspecified") for r in planned if r["status"] != "encoded")),
            "final_ir_instructions": report["final_inventory"]["instructions"],
            "generated_support_instructions": report["final_inventory"]["helper_instructions"],
            "selected_attributes_are_not_proof": True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--spec", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--toolchain-image", required=True)
    p.add_argument("--variant", choices=("control", "v01", "v02"), default="v02")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--module-insts", type=int, default=250000)
    p.add_argument("--compile-timeout", type=float, default=180)
    p.add_argument("--scale-budget", action="store_true", help="Explicit fair growth-allocation experiment; not a promotion flag")
    p.add_argument("--scale-structure", action="store_true")
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
                                      or args.require_aggregate_memory):
        p.error("protection coverage cannot be required of a control-only build")
    if args.variant == "control" and args.post_o2_attack:
        p.error("the post-O2 attack requires a protected build")
    spec = json.loads(args.spec.read_text())
    if spec.get("schema") != "sre-scale-v1" or not spec.get("revision") or not spec.get("sources"):
        p.error("a revision-pinned scale manifest is required")
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
    result = {"schema": "sre-scale-result-v2", "project": spec["project"], "revision": spec["revision"],
              "spec_sha256": digest(args.spec), "variant": args.variant, "seed": args.seed,
              "status": "incomplete", "hardness_evaluated": False,
              "generality_gate": "not-promoted", "workloads": [],
              "module_instruction_limit": args.module_insts, "compile_timeout": args.compile_timeout,
              "scale_budget": args.scale_budget,
              "scale_structure": args.scale_structure,
              "connected_shards": args.connected_shards,
              "connected_aggregates": args.connected_aggregates,
              "post_o2_attack": args.post_o2_attack,
              "required_coverage": {"flattening": args.require_flattening, "memory": args.require_memory,
                                    "shards": args.require_shards,
                                    "aggregate_memory": args.require_aggregate_memory},
              "input_hash_scope": "sources-and-headers" if "inputs" in spec else "source-files-only"}
    argv = [*map(str, sources), "--out", str(out / "build"), "--toolchain-image", args.toolchain_image,
            "--optimization", "O2", "--seed", str(args.seed), "--no-disassembly",
            "--module-insts", str(args.module_insts), "--compile-timeout", str(args.compile_timeout)]
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
    phase = "build"
    try:
        manifest = build(build_parser().parse_args(argv))
        if args.variant != "control":
            result["coverage"] = coverage(json.loads((out / "build/native.json").read_text()))
        phase = "workload"
        runner = Runner(ROOT, out / "workload-logs", args.toolchain_image, mounts=(out, root), timeout=60)
        for workload in spec["workloads"]:
            stdin = base64.b64decode(workload["stdin_base64"], validate=True)
            outputs = {}
            for arm in manifest["artifacts"]:
                binary = out / "build" / arm
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
            if not coverage_passes(result["coverage"], args.require_flattening, args.require_memory, args.require_shards,
                                   args.require_aggregate_memory):
                result["status"] = "coverage-failure"
        result["commands"] = runner.records
    except (OSError, ValueError, ToolFailure) as exc:
        result.update(status="workload-or-tool-failure" if phase == "workload" else "build-or-tool-failure", reason=str(exc), failure_phase=phase)
    finally:
        result["sources_unchanged"] = all(digest(path) == expected for path, expected in inputs)
        if not result["sources_unchanged"]:
            result["status"] = "source-mutation"
        dump(out / "result.json", result)
    return 0 if result["status"] == "conformance-pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
