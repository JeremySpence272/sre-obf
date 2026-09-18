"""Matched stripped-binary decompiler stages for one informed bundle control.

Successful decompilation is not successful semantic recovery; syntax metrics
are retained only as diagnostics. No source/origin map enters a binary-only run.
"""
import argparse
import json
from pathlib import Path
import shutil

from conformance.bundle_run import inputs
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, compile_variant, decompile, target_offset


def private_offset(symbols, name):
    # This resolver is only for the explicitly informed arm. The compiler's
    # private symbol table never accompanies the stripped attacker artifact.
    matches = [int(parts[0], 16) for line in symbols.splitlines()
               if len(parts := line.split()) == 3 and parts[1] in ("t", "T") and parts[2] == name]
    if len(matches) != 1: raise ToolFailure(f"expected one private callable symbol {name}")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True, help="width directory from bundle_run")
    parser.add_argument("--stem", default="xor-1-pins-1")
    parser.add_argument("--width", type=int, choices=(8, 16, 32, 64), required=True)
    workload = parser.add_mutually_exclusive_group()
    workload.add_argument("--loop", action="store_true", help="use a supported bundle_loop_run case and full two-output workload")
    workload.add_argument("--tile", action="store_true", help="use a supported tile_run case and all four output cells")
    workload.add_argument("--immutable", action="store_true", help="four-output immutable_run case with matched off arms")
    workload.add_argument("--private-calls", action="store_true", help="recursive_run bundle-input case and matched off arms")
    parser.add_argument("--call-output-ablation", action="store_true", help="private-calls disabled arms turn off outputs, leaving inputs on")
    parser.add_argument("--control-ablation", action="store_true", help="loop disabled arms retain flattening without bundle control")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--ghidra-image", required=True)
    parser.add_argument("--ghidra", default="/opt/ghidra/support/analyzeHeadless")
    parser.add_argument("--decompile-timeout", type=float, default=240)
    args = parser.parse_args()
    if args.call_output_ablation and not args.private_calls:
        parser.error("--call-output-ablation requires --private-calls")
    if args.control_ablation and not args.loop:
        parser.error("--control-ablation requires --loop")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out, args.case), timeout=180)
    result = {"schema": "sre-bundle-decompiler-v1", "passed": False, "scope": "informed-entry",
              "workload": "private-calls" if args.private_calls else "immutable" if args.immutable else "tile" if args.tile else "loop" if args.loop else "straight-line",
              "hardness_evaluated": False, "semantic_recovery": "not_measured", "arms": {}}
    if args.private_calls: result["private_ablation"] = "outputs" if args.call_output_ablation else "inputs"
    try:
        driver = out / "driver.o"
        driver_source = "tile_driver.c" if args.tile or args.immutable or args.private_calls else "bundle_loop_driver.c" if args.loop else "bundle_driver.c"
        threaded = args.loop or args.tile or args.immutable or args.private_calls
        runner.run(["clang", "-O2", *(["-pthread"] if threaded else []), "-c",
                    str(FIXTURES / driver_source), "-o", str(driver)])
        selected = {"clean": args.case / "clean.ll", "native": args.case / (args.stem + ".ll"),
                    "post-o2": args.case / (args.stem + "-post-o2.ll")}
        if args.tile or args.immutable or args.private_calls or args.control_ablation:
            if args.control_ablation: name = "control"
            elif args.private_calls: name = "call-outputs" if args.call_output_ablation else "call-inputs"
            else: name = "immutable" if args.immutable else "tiles"
            selected[name + "-off"] = args.case / (args.stem + "-disabled.ll")
            selected[name + "-off-post-o2"] = args.case / (args.stem + "-disabled-post-o2.ll")
        expected = None
        vectors = inputs(args.width, 1024)
        if args.private_calls:
            y = (1 << (args.width - 2)) - 13
            vectors += f"16 {y}\n{y} 16\n".encode()
        if args.loop:
            from conformance.bundle_loop_run import vectors as loop_vectors
            vectors = "".join(f"{a} {b} {n}\n" for a, b, n in loop_vectors(args.width, True)).encode()
        for name, source in selected.items():
            archived = out / (name + ".ll")
            shutil.copy2(source, archived)
            artifact = compile_variant(runner, archived, driver, out / name, threaded=threaded)
            output = runner.run([str(artifact["binary"])], stdin=vectors)
            if expected is None: expected = output
            if output != expected: raise ToolFailure("stripped binary differential failed")
            target = ("recur" if name == "clean" else "recur.sre.encoded") if args.private_calls else "kernel"
            offset = private_offset((out / name / "symbols.txt").read_text(), target) if args.private_calls else target_offset(artifact["link_map"], target)
            recovered = decompile(runner, artifact["binary"], artifact["link_map"],
                out / (name + "-decompiled.json"), args, offset)
            if recovered.get("status") != "ok": raise ToolFailure("decompiler control did not export the callable root")
            result["arms"][name] = {"binary_sha256": artifact["binary_sha256"],
                "binary_bytes": artifact["binary_bytes"], "input_ir_sha256": digest(archived),
                "assembly_sha256": digest(artifact["assembly"]), "vectors": len(output.splitlines()),
                "decompiler_status": recovered["status"], "diagnostics": recovered.get("metrics")}
            dump(out / "summary.json", result)
        result["passed"] = True
    except (ToolFailure, OSError, ValueError) as exc:
        result["error"] = str(exc)
    finally:
        result["commands"] = runner.records
        dump(out / "summary.json", result)
    print(json.dumps({k: result.get(k) for k in ("passed", "scope", "error")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
