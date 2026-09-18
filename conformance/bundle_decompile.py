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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True, help="width directory from bundle_run")
    parser.add_argument("--stem", default="xor-1-pins-1")
    parser.add_argument("--width", type=int, choices=(8, 16, 32, 64), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--ghidra-image", required=True)
    parser.add_argument("--ghidra", default="/opt/ghidra/support/analyzeHeadless")
    parser.add_argument("--decompile-timeout", type=float, default=240)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out, args.case), timeout=180)
    result = {"schema": "sre-bundle-decompiler-v1", "passed": False, "scope": "informed-entry",
              "hardness_evaluated": False, "semantic_recovery": "not_measured", "arms": {}}
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-c", str(FIXTURES / "bundle_driver.c"), "-o", str(driver)])
        selected = {"clean": args.case / "clean.ll", "native": args.case / (args.stem + ".ll"),
                    "post-o2": args.case / (args.stem + "-post-o2.ll")}
        expected = None
        vectors = inputs(args.width, 1024)
        for name, source in selected.items():
            archived = out / (name + ".ll")
            shutil.copy2(source, archived)
            artifact = compile_variant(runner, archived, driver, out / name)
            output = runner.run([str(artifact["binary"])], stdin=vectors)
            if expected is None: expected = output
            if output != expected: raise ToolFailure("stripped binary differential failed")
            recovered = decompile(runner, artifact["binary"], artifact["link_map"],
                out / (name + "-decompiled.json"), args, target_offset(artifact["link_map"], "kernel"))
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
