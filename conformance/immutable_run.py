"""Immutable numeric tiles: all outputs, exact tail model and scalar-use edges."""
import argparse
import json
from pathlib import Path
import re
import shutil

from conformance.bundle_model import Descriptor
from conformance.bundle_run import inputs
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


def table(width, cells):
    return [((i * 17) ^ 55) & ((1 << width) - 1) for i in range(cells)]


def fixture(width, cells, partial=False, unaligned=False):
    ty = f"i{width}"
    lines = ['target triple = "x86_64-unknown-linux-gnu"',
             'target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"',
             f'@table = private constant [{cells} x {ty}] [' + ", ".join(f"{ty} {v}" for v in table(width, cells)) +
             ("] , align 1" if unaligned else "]"),
             f"define void @kernel({ty} %a, {ty} %b, ptr %out) {{", "entry:",
             f"  %ai = urem {ty} %a, {cells}", f"  %bi = urem {ty} %b, {cells}"]
    for name in ("a", "b"):
        # Narrow GEP indices are signed. Extend the proven unsigned index to
        # pointer width before indexing, so i8 values >=128 remain legal.
        index = f"%{name}i"
        if width != 64:
            lines.append(f"  %{name}idx = zext {ty} {index} to i64")
            index = f"%{name}idx"
        lines += [f"  %{name}ptr = getelementptr inbounds [{cells} x {ty}], ptr @table, i32 0, i64 {index}",
                  f"  %{name}val = load {ty}, ptr %{name}ptr" + (", align 1" if unaligned else "")]
    lines += [f"  %v0 = add {ty} %aval, %bval", f"  %v1 = xor {ty} %aval, 7",
              f"  %v2 = mul {ty} %v0, 3", f"  %v3 = or {ty} %v1, %bval",
              f"  %v4 = add {ty} %v2, %v3", f"  %v5 = xor {ty} %v3, %v2",
              f"  %v6 = mul {ty} %v4, 5", f"  %v7 = add {ty} %v5, %v6"]
    for k, value in enumerate(("%v6", "%v7", "%aval" if partial else "0", "0")):
        if width != 64 and value != "0":
            lines.append(f"  %wide{k} = zext {ty} {value} to i64")
            value = f"%wide{k}"
        lines += [f"  %out{k} = getelementptr inbounds i64, ptr %out, i32 {k}", f"  store i64 {value}, ptr %out{k}"]
    lines += ["  ret void", "}", "define void @invoke(i64 %a, i64 %b, ptr %out) {", "entry:"]
    a, b = "%a", "%b"
    if width != 64:
        lines += [f"  %a0 = trunc i64 %a to {ty}", f"  %b0 = trunc i64 %b to {ty}"]
        a, b = "%a0", "%b0"
    lines += [f"  call void @kernel({ty} {a}, {ty} {b}, ptr %out)", "  ret void", "}"]
    return "\n".join(lines) + "\n"


def oracle(a, b, width, cells, partial):
    mask = (1 << width) - 1
    data = table(width, cells)
    left, right = data[(a & mask) % cells], data[(b & mask) % cells]
    v2, v3 = (((left + right) & mask) * 3) & mask, (left ^ 7) | right
    v6 = (((v2 + v3) & mask) * 5) & mask
    return [v6, ((v3 ^ v2) + v6) & mask, left if partial else 0, 0]


def backing_values(line, width, cells):
    if "zeroinitializer" in line: return [0] * cells
    literal = re.search(r'c"((?:[^"\\]|\\[0-9a-fA-F]{2})*)"', line)
    if literal:
        if width != 8: raise ToolFailure("byte string for a non-byte array")
        return [int(escaped, 16) if escaped else ord(char)
                for escaped, char in re.findall(r'\\([0-9a-fA-F]{2})|([^\\])', literal[1])]
    return [int(v) & ((1 << width) - 1) for v in re.findall(rf"i{width} (-?\d+)", line)]


def check_backing(ir, record):
    desc = Descriptor.from_plan(record)
    line = next(line for line in ir.splitlines() if line.startswith("@table ="))
    encoded = backing_values(line, desc.width, record["cells"])
    if len(encoded) != record["cells"]: raise ToolFailure("encoded backing extent mismatch")
    recovered = []
    for base in range(0, len(encoded), 4):
        z = tuple(encoded[min(base + k, len(encoded) - 1)] for k in range(4))
        m = (int(record["carrier_base_hex"], 16) + base * int(record["carrier_step_hex"], 16)) & desc.bits
        recovered.extend(desc.decode(z, m)[:min(4, len(encoded) - base)])
    if recovered != table(desc.width, record["cells"]): raise ToolFailure("independent backing decode mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--widths", type=int, nargs="+", choices=(8, 16, 32, 64), default=[8, 32])
    parser.add_argument("--cells", type=int, nargs="+", default=[3, 4, 5])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1])
    parser.add_argument("--families", nargs="+", choices=("xor", "additive"), default=["xor", "additive"])
    parser.add_argument("--partial", action="store_true")
    parser.add_argument("--unaligned", action="store_true")
    parser.add_argument("--connected-only", action="store_true", help="exclude the three-live-value bundle via its two-slot cap")
    parser.add_argument("--ablation", action="store_true")
    parser.add_argument("--random-inputs", type=int, default=512)
    args = parser.parse_args()
    if any(n < 1 or n >= (1 << min(args.widths)) for n in args.cells): parser.error("invalid element count")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    result = {"schema": "sre-immutable-conformance-v1", "passed": False, "complete": False,
              "plugin_sha256": digest(plugin), "cases": [], "hardness_evaluated": False}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=1", "-native-helper-hardening=0",
             "-native-late-constants=0", "-native-merge=0", "-native-values=1", "-native-values-wide=1",
             "-native-region-plan=connected", "-native-connected-nodes=2", "-native-functions=kernel",
             "-native-plan=1", "-native-scale-budget=1", "-native-bundles=1", "-native-immutable-bundles=1",
             "-obf-deterministic", "-obf-verify"]
    if args.connected_only:
        flags = ["-native-connected-nodes=32" if x == "-native-connected-nodes=2" else x for x in flags]
        flags.append("-native-bundle-values=2")
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-pthread", "-c", str(FIXTURES / "tile_driver.c"), "-o", str(driver)])
        for width in args.widths:
            vectors = inputs(width, args.random_inputs)
            pairs = [tuple(map(int, line.split())) for line in vectors.splitlines()]
            for n in args.cells:
                case = out / f"i{width}-n{n}"
                case.mkdir()
                clean = case / "clean.ll"
                clean.write_text(fixture(width, n, args.partial, args.unaligned))
                expected = "".join(" ".join(f"{v:016x}" for v in oracle(a, b, width, n, args.partial)) + "\n"
                                   for a, b in pairs).encode()
                binary = case / "clean"
                runner.run(["clang", str(clean), str(driver), "-pthread", "-o", str(binary)])
                if runner.run([str(binary)], stdin=vectors) != expected: raise ToolFailure("clean/oracle mismatch")
                for family in args.families:
                    for seed in args.seeds:
                        for pins in (False, True):
                            name = f"{family}-{seed}-pins-{int(pins)}"
                            native, report, stage = case / (name + ".ll"), case / (name + ".json"), case / (name + "-stages")
                            command = opt_command(plugin) + flags + [f"-obf-seed={seed}", f"-native-transfer-family={family}",
                                f"-native-bundle-pins={int(pins)}", f"-native-stage-dir={stage}",
                                f"-native-report-json={report}", "-S", str(clean), "-o", str(native)]
                            runner.run(command)
                            data = json.loads(report.read_text())
                            errors = report_violations(data)
                            if errors: raise ToolFailure("; ".join(errors))
                            row = next(r for r in data["data"] if r["object"] == "table")
                            if row["status"] != "encoded": raise ToolFailure("immutable tile not retained")
                            edges = data["immutable_continuity"]
                            if args.connected_only:
                                if any(r["retained_operations"] for r in data["bundles"]):
                                    raise ToolFailure("connected-only control retained a pure bundle")
                                if sum(e["eliminated_scalar_uses"] for e in edges):
                                    raise ToolFailure("connected-only control credited early absorption")
                                edges = data["immutable_connected_continuity"]
                            if sum(e["remaining_scalar_uses"] for e in edges) != int(args.partial):
                                raise ToolFailure("unaccounted/unabsorbed scalar crossings")
                            if not sum(e["eliminated_scalar_uses"] for e in edges): raise ToolFailure("no direct data-to-use path")
                            check_backing((stage / "bundles.ll").read_text(), row)
                            if args.unaligned:
                                source_ir = (stage / "bundles.ll").read_text()
                                # Bundle pin loads use other allocas; the eight
                                # backing reads precede bundle entry in kernel.
                                loads = re.findall(rf" = load (?:volatile )?i{width}, ptr [^\n]+", source_ir)
                                if sum(", align 1" in line for line in loads) < 8:
                                    raise ToolFailure("extra immutable reads overstate alignment")
                            hashes = digest(native), digest(report)
                            runner.run(command)
                            if hashes != (digest(native), digest(report)): raise ToolFailure("nondeterministic immutable output")
                            if args.ablation:
                                off, off_report = case / (name + "-disabled.ll"), case / (name + "-disabled.json")
                                replacements = {"-native-immutable-bundles=1": "-native-immutable-bundles=0",
                                    str(native): str(off), f"-native-report-json={report}": f"-native-report-json={off_report}",
                                    f"-native-stage-dir={stage}": f"-native-stage-dir={stage}-disabled"}
                                runner.run([replacements.get(arg, arg) for arg in command])
                                if report_violations(json.loads(off_report.read_text())): raise ToolFailure("invalid off control")
                                off_o2 = case / (name + "-disabled-post-o2.ll")
                                runner.run(["opt", "-passes=default<O2>,verify", "-S", str(off), "-o", str(off_o2)])
                                for ir in (off, off_o2):
                                    binary = ir.with_suffix(".bin")
                                    runner.run(["clang", str(ir), str(driver), "-pthread", "-o", str(binary)])
                                    if runner.run([str(binary)], stdin=vectors) != expected: raise ToolFailure("off control mismatch")
                            o2 = case / (name + "-post-o2.ll")
                            runner.run(["opt", "-passes=default<O2>,verify", "-S", str(native), "-o", str(o2)])
                            for arm, ir in (("bundle", stage / "bundles.ll"), ("final", native), ("post-o2", o2)):
                                binary = case / (name + "-" + arm)
                                runner.run(["clang", str(ir), str(driver), "-pthread", "-o", str(binary)])
                                if runner.run([str(binary)], stdin=vectors) != expected: raise ToolFailure(f"mismatch: {arm}")
                                runner.run([str(binary), "--threads"])
                            result["cases"].append({"width": width, "cells": n, "family": family, "seed": seed,
                                "pins": pins, "vectors": len(pairs), "backing_inverse_control": True,
                                "consumer": "connected" if args.connected_only else "bundle",
                                "matched_disabled_control": args.ablation,
                                "continuity": edges, "passed": True})
                            dump(out / "summary.json", result)
                            print(f"{case.name} {name}: passed", flush=True)
        result.update(passed=True, complete=True)
    except (ToolFailure, OSError, ValueError, AssertionError) as exc:
        result["error"] = str(exc)
    finally:
        result["commands"] = runner.records
        dump(out / "summary.json", result)
    print(json.dumps({k: result.get(k) for k in ("passed", "complete", "error")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
