"""All-cell local-tile differentials and strict negative ownership controls.

No paid agent, protected holdout, promotion or hardness measurement.
"""
import argparse
import json
from pathlib import Path
import shutil

from conformance.bundle_run import inputs
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command
from conformance.tile_check import tile_summary

FALLBACKS = {
    "partial-init": "requires-complete-entry-initialization",
    "early-read": "requires-complete-entry-initialization",
    "unbounded": "unproved-index",
    "volatile": "partial-volatile-or-atomic-access",
    "atomic": "partial-volatile-or-atomic-access",
    "byte-read": "partial-volatile-or-atomic-access",
    "escape": "pointer-escape-or-observation",
    "derived": "derived-pointer",
    "lifetime": "lifetime-not-supported",
}


def fixture(width, cells, shape="supported"):
    if width not in (8, 16, 32, 64) or cells not in (2, 3, 4):
        raise ValueError("unsupported tile shape")
    ty, array = f"i{width}", f"[{cells} x i{width}]"
    lines = ['target triple = "x86_64-unknown-linux-gnu"',
             'target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"',
             f"define void @kernel({ty} %a, {ty} %b, ptr %out) {{", "entry:",
             f"  %tile = alloca {array}"]
    for k in range(cells):
        lines += [f"  %p{k} = getelementptr inbounds {array}, ptr %tile, i32 0, i32 {k}",
                  f"  %init{k} = add {ty} %a, {k}", f"  store {ty} %init{k}, ptr %p{k}"]
    lines += ["  br label %loop", "loop:", "  %i = phi i32 [ 0, %entry ], [ %next, %loop ]",
              f"  %idx = and {ty} %b, {3 if cells == 4 else 1}",
              f"  %p = getelementptr inbounds {array}, ptr %tile, i32 0, {ty} %idx",
              f"  %left = load {ty}, ptr %p", f"  %right = load {ty}, ptr %p{cells - 1}",
              f"  %v0 = add {ty} %left, %b", f"  %v1 = xor {ty} %v0, %right",
              f"  %v2 = mul {ty} %v1, 3", f"  %v3 = ashr {ty} %v2, 1",
              f"  %v4 = sub {ty} %v3, %a", f"  %v5 = or {ty} %v4, 1",
              f"  store {ty} %v5, ptr %p", "  %next = add i32 %i, 1",
              "  %again = icmp ult i32 %next, 4", "  br i1 %again, label %loop, label %exit", "exit:"]
    for k in range(4):
        value = "0"
        if k < cells:
            lines.append(f"  %r{k} = load {ty}, ptr %p{k}")
            value = f"%r{k}"
            if width != 64:
                lines.append(f"  %z{k} = zext {ty} %r{k} to i64")
                value = f"%z{k}"
        lines += [f"  %out{k} = getelementptr inbounds i64, ptr %out, i32 {k}", f"  store i64 {value}, ptr %out{k}"]
    lines += ["  ret void", "}", "define void @invoke(i64 %a, i64 %b, ptr %out) {", "entry:"]
    a, b = "%a", "%b"
    if width != 64:
        lines += [f"  %x = trunc i64 %a to {ty}", f"  %y = trunc i64 %b to {ty}"]
        a, b = "%x", "%y"
    lines += [f"  call void @kernel({ty} {a}, {ty} {b}, ptr %out)", "  ret void", "}"]
    source = "\n".join(lines) + "\n"
    if shape == "partial-init": source = source.replace(f"  store {ty} %init1, ptr %p1\n", "")
    elif shape == "early-read": source = source.replace(f"  %init1 =", f"  %early = load {ty}, ptr %p0\n  %init1 =")
    elif shape == "unbounded": source = source.replace(f"%idx = and {ty} %b, {3 if cells == 4 else 1}", f"%idx = add {ty} %b, 0")
    elif shape == "volatile": source = source.replace(f"%left = load {ty}", f"%left = load volatile {ty}")
    elif shape == "atomic": source = source.replace(f"%left = load {ty}, ptr %p", f"%left = load atomic {ty}, ptr %p monotonic, align {width // 8}")
    elif shape == "byte-read": source = source.replace("  %left =", "  %byte = load i1, ptr %p\n  %left =")
    elif shape == "escape": source = source.replace("  br label %loop", "  %observed = ptrtoint ptr %tile to i64\n  br label %loop", 1)
    elif shape == "derived": source = source.replace("  %left =", f"  %alias = getelementptr inbounds {ty}, ptr %p, i32 0\n  %left =")
    elif shape == "lifetime":
        source = source.replace(f"  %p0 =", "  call void @llvm.lifetime.start.p0(ptr %tile)\n  %p0 =", 1)
        source += "declare void @llvm.lifetime.start.p0(ptr captures(none))\n"
    elif shape == "address":
        source = source.replace(f"  store {ty} %v5, ptr %p", f"  %nextidx = and {ty} %v5, 1\n"
                                f"  %q = getelementptr inbounds {array}, ptr %tile, i32 0, {ty} %nextidx\n"
                                f"  %v6 = xor {ty} %nextidx, %v5\n  store {ty} %v6, ptr %q")
    elif shape == "many-loads":
        # Stress membership spilling beyond SmallPtrSet's inline storage. The
        # later final-output stores overwrite these intentionally redundant
        # writes: this is a determinism stressor, not useful-coverage evidence.
        extra = "".join(f"  %many{k} = load {ty}, ptr %p0\n  store {ty} %many{k}, ptr %out\n" for k in range(33))
        source = source.replace("exit:\n", "exit:\n" + extra)
    elif shape != "supported": raise ValueError("unknown fixture shape")
    return source


def oracle(a, b, width, cells, shape="supported"):
    mask = (1 << width) - 1
    a, b = a & mask, b & mask
    tile = [(a + k) & mask for k in range(cells)]
    for _ in range(4):
        idx = b & (3 if cells == 4 else 1)
        x = (((tile[idx] + b) & mask) ^ tile[-1]) * 3 & mask
        signed = x - (1 << width) if x >> (width - 1) else x
        x = (((signed >> 1) - a) & mask) | 1
        if shape == "address": idx, x = x & 1, (x & 1) ^ x
        tile[idx] = x
    return tile + [0] * (4 - cells)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--widths", type=int, nargs="+", choices=(8, 16, 32, 64), default=[8, 16, 32, 64])
    parser.add_argument("--cells", type=int, nargs="+", choices=(2, 3, 4), default=[2, 3, 4])
    parser.add_argument("--shapes", nargs="+", choices=("supported", "address", "many-loads", *FALLBACKS), default=["supported", "address"])
    parser.add_argument("--families", nargs="+", choices=("xor", "additive", "seeded"), default=["xor", "additive"])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1])
    parser.add_argument("--random-inputs", type=int, default=512)
    parser.add_argument("--ablation", action="store_true", help="also emit/test matched tile-disabled and normalized controls")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    summary = {"schema": "sre-tile-conformance-v1", "passed": False, "complete": False,
               "plugin_sha256": digest(plugin), "cases": [], "hardness_evaluated": False}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0",
             "-native-late-constants=0", "-native-merge=0", "-native-values=1", "-native-values-wide=1",
             "-native-region-plan=connected", "-native-connected-nodes=2", "-native-functions=kernel",
             "-native-plan=1", "-native-scale-budget=1", "-native-bundles=1", "-native-object-bundles=1",
             "-obf-deterministic", "-obf-verify"]
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-pthread", "-c", str(FIXTURES / "tile_driver.c"), "-o", str(driver)])
        for width in args.widths:
            vectors = inputs(width, args.random_inputs)
            pairs = [tuple(map(int, line.split())) for line in vectors.splitlines()]
            for cells in args.cells:
                for shape in args.shapes:
                    case = out / f"i{width}-n{cells}-{shape}"
                    case.mkdir()
                    clean = case / "clean.ll"
                    clean.write_text(fixture(width, cells, shape))
                    expected = None
                    if shape not in FALLBACKS:
                        expected = "".join(" ".join(f"{v:016x}" for v in oracle(a, b, width, cells, shape)) + "\n"
                                           for a, b in pairs).encode()
                        binary = case / "clean"
                        runner.run(["clang", str(clean), str(driver), "-pthread", "-o", str(binary)])
                        if runner.run([str(binary)], stdin=vectors) != expected: raise ToolFailure("clean/oracle mismatch")
                    for family in args.families:
                        for seed in args.seeds:
                            for pins in (False, True):
                                name = f"{family}-{seed}-pins-{int(pins)}"
                                protected, report = case / (name + ".ll"), case / (name + ".json")
                                stage = case / (name + "-stages")
                                command = opt_command(plugin) + flags + [f"-obf-seed={seed}",
                                    f"-native-transfer-family={family}", f"-native-bundle-pins={int(pins)}",
                                    f"-native-report-json={report}", f"-native-stage-dir={stage}",
                                    "-S", str(clean), "-o", str(protected)]
                                runner.run(command)
                                data = json.loads(report.read_text())
                                errors = report_violations(data)
                                if errors: raise ToolFailure("; ".join(errors))
                                rows = [r for r in data["object_bundles"] if r["function"] == "kernel"]
                                if len(rows) != 1: raise ToolFailure("unexpected object denominator")
                                row = rows[0]
                                if shape in FALLBACKS:
                                    if row["status"] != "skipped" or row["reason"] != FALLBACKS[shape]:
                                        raise ToolFailure(f"unexpected fallback: {row}")
                                else:
                                    if row["status"] != "encoded": raise ToolFailure(f"no tile retained: {row}")
                                    if shape == "address" and row["plan"]["scalar_address_uses"] == 0:
                                        raise ToolFailure("address projection not accounted")
                                    prior, prior_report = digest(protected), digest(report)
                                    runner.run(command)
                                    if digest(protected) != prior or digest(report) != prior_report:
                                        raise ToolFailure("nondeterministic IR/report")
                                    if args.ablation:
                                        disabled = case / (name + "-disabled.ll")
                                        disabled_report = case / (name + "-disabled.json")
                                        substitutions = {"-native-object-bundles=1": "-native-object-bundles=0",
                                            str(protected): str(disabled),
                                            f"-native-report-json={report}": f"-native-report-json={disabled_report}",
                                            f"-native-stage-dir={stage}": f"-native-stage-dir={stage}-disabled"}
                                        runner.run([substitutions.get(arg, arg) for arg in command])
                                        off_data = json.loads(disabled_report.read_text())
                                        if report_violations(off_data) or off_data["features"]["object_bundles"]:
                                            raise ToolFailure("disabled control reporting failed")
                                        disabled_o2 = case / (name + "-disabled-post-o2.ll")
                                        runner.run(["opt", "-passes=default<O2>,verify", "-S", str(disabled), "-o", str(disabled_o2)])
                                        for ir in (disabled, disabled_o2):
                                            binary = ir.with_suffix(".bin")
                                            runner.run(["clang", str(ir), str(driver), "-pthread", "-o", str(binary)])
                                            if runner.run([str(binary)], stdin=vectors) != expected:
                                                raise ToolFailure("disabled control differential failed")
                                    # Stage-local, final-pipeline, and optimizer-normalized controls.
                                    normalized = case / (name + "-post-o2.ll")
                                    runner.run(["opt", "-passes=default<O2>,verify", "-S", str(protected), "-o", str(normalized)])
                                    for arm, ir in (("tile", stage / "object-bundles.ll"), ("final", protected), ("o2", normalized)):
                                        binary = case / (name + "-" + arm)
                                        runner.run(["clang", str(ir), str(driver), "-pthread", "-o", str(binary)])
                                        if runner.run([str(binary)], stdin=vectors) != expected:
                                            raise ToolFailure(f"all-cell output mismatch: {name}/{arm}")
                                        runner.run([str(binary), "--threads"])
                                summary["cases"].append({"width": width, "cells": cells, "shape": shape,
                                    "family": family, "seed": seed, "pins": pins, "passed": True,
                                    "matched_disabled_control": args.ablation and shape not in FALLBACKS,
                                    "vectors": len(pairs) if expected else 0,
                                    "coverage": tile_summary(data), "reason": row["reason"]})
                                dump(out / "summary.json", summary)
                                print(f"{case.name} {name}: passed", flush=True)
        summary.update(passed=True, complete=True)
    except (ToolFailure, OSError, ValueError, AssertionError) as exc:
        summary["error"] = str(exc)
    finally:
        summary["commands"] = runner.records
        dump(out / "summary.json", summary)
    print(json.dumps({k: summary.get(k) for k in ("passed", "complete", "error")}))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
