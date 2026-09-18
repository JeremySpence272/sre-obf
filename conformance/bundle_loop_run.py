"""Bounded loop continuity differentials, explicit fallback and phase controls.

No protected holdout, recovery resistance or promotion measurement is performed.
"""
import argparse
import json
from pathlib import Path
import random
import shutil

from conformance.bundle_model import replay_loop
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


FALLBACKS = {
    "external-user": "recurrence-has-external-users",
    "guarded-preheader": "requires-unconditional-preheader",
    "multi-exit": "not-single-block-self-loop",
    "constant-backedge": "backedge-is-not-region-output",
}


def fixture(width, shape="supported"):
    source = (FIXTURES / "bundle_loop.ll.in").read_text()
    if shape == "external-user":
        source = source.replace("  %a0 =", "  %old = icmp eq iWIDTH %x, 0\n  %a0 =")
        source = source.replace("freeze iWIDTH %a5", "select i1 %old, iWIDTH %a5, iWIDTH %b5")
    elif shape == "guarded-preheader":
        source = source.replace("pre:\n  br label %loop", "pre:\n  %guard = icmp ult i32 %count, 4096\n  br i1 %guard, label %loop, label %exit")
        source = source.replace("[ %a, %entry ], [ %result0", "[ %a, %entry ], [ %a, %pre ], [ %result0")
        source = source.replace("[ %b, %entry ], [ %b5", "[ %b, %entry ], [ %b, %pre ], [ %b5")
    elif shape == "multi-exit":
        source = source.replace("[ %b5, %loop ]", "[ %b5, %latch ]", 1)
        source = source.replace("[ %a5, %loop ]", "[ %a5, %latch ]", 1)
        source = source.replace("[ %next, %loop ]", "[ %next, %latch ]", 1)
        source = source.replace("  br i1 %again, label %loop, label %exit", "  %early = icmp eq iWIDTH %b5, 0\n  br i1 %early, label %exit, label %latch\nlatch:\n  br i1 %again, label %loop, label %exit")
        source = source.replace("[ %result0, %loop ]", "[ %result0, %loop ], [ %result0, %latch ]")
        source = source.replace("[ %b5, %loop ]", "[ %b5, %loop ], [ %b5, %latch ]")
    elif shape == "constant-backedge":
        source = source.replace("[ %b5, %loop ]", "[ 7, %loop ]", 1)
    elif shape != "supported":
        raise ValueError("unknown shape")
    source = source.replace("WIDTH", str(width))
    ty = f"i{width}"
    cast = f"  %x = trunc i64 %a to {ty}\n  %y = trunc i64 %b to {ty}\n" if width != 64 else ""
    args = "%x, " + ty + " %y" if width != 64 else "%a, i64 %b"
    extend = f"  %o0 = zext {ty} %r0 to i64\n  %o1 = zext {ty} %r1 to i64\n" if width != 64 else ""
    a, b = ("%o0", "%o1") if width != 64 else ("%r0", "%r1")
    return (source + "\ndefine void @invoke(i64 %a, i64 %b, i32 %count, ptr %out0, ptr %out1) {\nentry:\n" + cast +
            f"  %r = call {{{ty}, {ty}}} @kernel({ty} {args}, i32 %count)\n" +
            f"  %r0 = extractvalue {{{ty}, {ty}}} %r, 0\n  %r1 = extractvalue {{{ty}, {ty}}} %r, 1\n" + extend +
            f"  store i64 {a}, ptr %out0\n  store i64 {b}, ptr %out1\n  ret void\n}}\n")


def scalar_loop(a, b, count, width):
    """Independent source oracle, including signed shift and swapped backedge."""
    mask = (1 << width) - 1
    a, b = a & mask, b & mask
    out = a, b
    for _ in range(count):
        a0 = (a + b) & mask
        b0 = b ^ 91
        a1 = (a0 * 13) & mask
        b1 = (b0 - a0) & mask
        a2, b2 = a1 >> 3, (b1 << 2) & mask
        a3, b3 = a1 ^ a2, b1 | b2
        a4, b4 = (a3 + b3) & mask, b3 & 127
        signed = a4 - ((1 << width) if a4 >> (width - 1) else 0)
        a5, b5 = (signed >> 1) & mask, b4 ^ a4
        out = a5, b5
        a, b = b5, a5
    return out


def vectors(width, exhaustive=False):
    mask = (1 << width) - 1
    edges = (0, 1, 2, 7, mask >> 1, 1 << (width - 1), mask)
    values = [(a, b, count) for a in edges for b in edges for count in (0, 1, 2, 3, 7, 32, 64)]
    rng = random.Random(925 + width)
    values += [(rng.getrandbits(width), rng.getrandbits(width), rng.randrange(33)) for _ in range(256)]
    if width == 8 and exhaustive:
        values += [(a, b, 2) for a in range(256) for b in range(256)]
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--widths", type=int, nargs="+", choices=(8, 16, 32, 64), default=[8, 16, 32, 64])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 3, 4])
    parser.add_argument("--families", nargs="+", choices=("xor", "additive", "seeded"), default=["xor", "additive"])
    parser.add_argument("--pins", type=int, nargs="+", choices=(0, 1), default=[0, 1])
    parser.add_argument("--shapes", nargs="+", choices=("supported", *FALLBACKS), default=["supported", *FALLBACKS])
    parser.add_argument("--exhaustive-byte-pairs", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    summary = {"schema": "sre-bundle-loop-conformance-v1", "passed": False, "complete": False,
               "plugin_sha256": digest(plugin), "cases": [], "hardness_evaluated": False,
               "exhaustive_byte_pairs_trip_count": 2 if args.exhaustive_byte_pairs else None}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0",
             "-native-late-constants=0", "-native-merge=0", "-native-values=1", "-native-values-wide=1",
             "-native-region-plan=connected", "-native-connected-nodes=2", "-native-functions=kernel",
             "-native-plan=1", "-native-scale-budget=1", "-native-bundles=1", "-native-transfer-nodes=12",
             "-native-bundle-loops=1", "-obf-deterministic", "-obf-verify"]
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-pthread", "-c", str(FIXTURES / "bundle_loop_driver.c"), "-o", str(driver)])
        for width in args.widths:
            values = vectors(width, args.exhaustive_byte_pairs)
            stdin = "".join(f"{a} {b} {n}\n" for a, b, n in values).encode()
            for shape in args.shapes:
                case = out / f"i{width}-{shape}"
                case.mkdir()
                clean = case / "clean.ll"
                clean.write_text(fixture(width, shape))
                binary = case / "clean.bin"
                runner.run(["clang", "-pthread", str(clean), str(driver), "-o", str(binary)])
                expected = runner.run([str(binary)], stdin=stdin)
                if shape == "supported":
                    oracle = "".join("%d %d\n" % scalar_loop(a, b, n, width) for a, b, n in values).encode()
                    if expected != oracle: raise ToolFailure("clean compiler differs from independent source oracle")
                for family in args.families:
                    for seed in args.seeds:
                        for pins in args.pins:
                            for phases in (False, True):
                                name = f"{family}-{seed}-pins-{pins}-phases-{int(phases)}"
                                protected, report, stage = case / (name + ".ll"), case / (name + ".json"), case / (name + "-stages")
                                command = opt_command(plugin) + flags + [f"-obf-seed={seed}",
                                    f"-native-transfer-family={family}", f"-native-bundle-pins={pins}",
                                    f"-native-bundle-phases={int(phases)}", f"-native-report-json={report}",
                                    f"-native-stage-dir={stage}", "-S", str(clean), "-o", str(protected)]
                                runner.run(command)
                                data = json.loads(report.read_text())
                                errors = report_violations(data)
                                if errors: raise ToolFailure("; ".join(errors))
                                row = next(r for r in data["bundles"] if r["function"] == "kernel")
                                if row["retained_operations"] != 12: raise ToolFailure("expected twelve retained recurrence operations")
                                region = row["regions"][0]
                                loop = region["loop"]
                                if shape == "supported":
                                    if loop["status"] != "encoded": raise ToolFailure("recurrence fell back: " + loop["reason"])
                                    for a, b, n in values[:28]:
                                        if replay_loop(region, [a, b], n) != scalar_loop(a, b, n, width):
                                            raise ToolFailure("plan replay differs from independent loop oracle")
                                elif loop["status"] != "straight-line" or loop["reason"] != FALLBACKS[shape]:
                                    raise ToolFailure("unsupported shape lacks exact fallback reason")
                                before = digest(protected)
                                runner.run(command)
                                if digest(protected) != before: raise ToolFailure("nondeterministic emission")
                                for normalized in (False, True):
                                    selected = protected
                                    if normalized:
                                        selected = case / (name + "-post-o2.ll")
                                        runner.run(["opt", "-passes=default<O2>,verify", "-S", str(protected), "-o", str(selected)])
                                    binary = selected.with_suffix(".bin")
                                    runner.run(["clang", "-pthread", str(selected), str(driver), "-o", str(binary)])
                                    if runner.run([str(binary)], stdin=stdin) != expected:
                                        raise ToolFailure(f"{name}: full-output mismatch, post-O2={normalized}")
                                summary["cases"].append({"width": width, "shape": shape, "seed": seed,
                                    "family": family, "pins": bool(pins), "phases": phases, "vectors": len(values),
                                    "loop": loop, "passed": True, "post_o2_correct": True,
                                    "deterministic": True, "reentry_and_threads": True})
                                dump(out / "summary.json", summary)
                                print(f"i{width} {shape} {name}: passed", flush=True)
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
