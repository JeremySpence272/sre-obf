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


def coverage(report):
    original = report["input_inventory"]
    selected = [r for r in report.get("connected_regions", []) if r["status"] == "encoded"]
    names = {r["function"] for r in selected}
    source_rows = original["functions"]
    return {"input_definitions": original["definitions"], "input_instructions": original["instructions"],
            "connected_functions": len(selected), "connected_nodes": sum(r["nodes"] for r in selected),
            "connected_eligible_nodes": sum(r.get("eligible_nodes", 0) for r in report.get("connected_regions", [])),
            "connected_predicates": sum(r["predicates"] for r in selected),
            "memory_edges": sum(r["memory_edges"] for r in selected),
            "functions_with_surviving_flattening": len(report["flattening_state"]),
            "connected_matched_source_definitions": sum(r["function"] in names for r in source_rows),
            "connected_matched_source_instructions": sum(r["instructions"] for r in source_rows if r["function"] in names),
            "source_weight_scope": "input bodies containing a matched selected region; NOT number of protected instructions; merged/unmatched origins are not credited",
            "input_indirect_calls": sum(r["indirect_calls"] for r in source_rows),
            "connected_skips": dict(Counter(r.get("reason", "unspecified") for r in report.get("connected_regions", []) if r["status"] != "encoded")),
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
    args = p.parse_args()
    if args.scale_budget and args.variant != "v02":
        p.error("--scale-budget requires v02")
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
    result = {"schema": "sre-scale-result-v1", "project": spec["project"], "revision": spec["revision"],
              "spec_sha256": digest(args.spec), "variant": args.variant, "seed": args.seed,
              "status": "incomplete", "hardness_evaluated": False,
              "generality_gate": "not-promoted", "workloads": [],
              "module_instruction_limit": args.module_insts, "compile_timeout": args.compile_timeout,
              "scale_budget": args.scale_budget,
              "input_hash_scope": "sources-and-headers" if "inputs" in spec else "source-files-only"}
    argv = [*map(str, sources), "--out", str(out / "build"), "--toolchain-image", args.toolchain_image,
            "--optimization", "O2", "--seed", str(args.seed), "--no-disassembly",
            "--module-insts", str(args.module_insts), "--compile-timeout", str(args.compile_timeout)]
    argv += ["--cflag=" + flag for flag in spec.get("cflags", [])]
    argv += ["--link-flag=" + flag for flag in spec.get("link_flags", [])]
    if args.variant == "control":
        argv += ["--control-only"]
    else:
        argv += ["--fusion", "--memory", "--values", "--values-wide", "--coupled-state", "--invariant"]
        if args.variant == "v02":
            argv += ["--region-plan", "connected", "--memory-ssa", "--predicate-regions", "--regional-families", "--support-regions"]
            if args.scale_budget: argv += ["--scale-budget"]
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
