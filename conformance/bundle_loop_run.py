"""Bounded loop continuity differentials, explicit fallback and phase controls.

No protected holdout, recovery resistance or promotion measurement is performed.
"""
import argparse
import json
from pathlib import Path
import random
import re
import shutil

from conformance.bundle_model import replay_loop
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


FALLBACKS = {
    "external-user": "recurrence-has-external-users",
    "guarded-preheader": "requires-unconditional-preheader",
    "constant-backedge": "backedge-is-not-region-output",
    "phi-user": "recurrence-has-external-users",
    "earlier-region": "recurrence-has-external-users",
    "duplicate-edges": "duplicate-header-edges",
    "switch-backedge": "unsupported-backedge-terminator",
    "five-backedges": "backedge-count-limit",
    "unreachable-edge": "unreachable-header-predecessor",
}
SHAPES = ("supported", "multi-exit", "multi-latch", *FALLBACKS)
EXPOSED = ("external-user", "phi-user", "earlier-region")


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
        source = source.replace("  br i1 %again, label %loop, label %exit", "  %early_bits = and iWIDTH %b5, 7\n  %early = icmp eq iWIDTH %early_bits, 0\n  br i1 %early, label %exit, label %latch\nlatch:\n  br i1 %again, label %loop, label %exit")
        source = source.replace("[ %result0, %loop ]", "[ %result0, %loop ], [ %result0, %latch ]")
        source = source.replace("[ %b5, %loop ]", "[ %b5, %loop ], [ %b5, %latch ]")
    elif shape == "constant-backedge":
        source = source.replace("[ %b5, %loop ]", "[ 7, %loop ]", 1)
    elif shape == "phi-user":
        source = source.replace("[ %result0, %loop ]", "[ %x, %loop ]")
    elif shape == "earlier-region":
        body = "  %a0 =" + source.split("  %a0 =", 1)[1].split("  %result0 =", 1)[0]
        earlier = re.sub(r"%([ab][0-5])", r"%p_\1", body).replace(", 91", ", 37")
        source = source.replace("  %a0 =", earlier + "  %a0 =", 1)
        source = source.replace("  br i1 %again", "  %mixed0 = xor iWIDTH %result0, %p_a5\n  %mixed1 = xor iWIDTH %b5, %p_b5\n  br i1 %again")
        source = source.replace("[ %result0, %loop ]", "[ %mixed0, %loop ]")
        source = source.replace("  %out1 = phi iWIDTH [ %b, %entry ], [ %b5, %loop ]", "  %out1 = phi iWIDTH [ %b, %entry ], [ %mixed1, %loop ]")
    elif shape in ("multi-latch", "five-backedges"):
        count = 2 if shape == "multi-latch" else 5
        for value in ("b5", "a5", "next"):
            incoming = []
            for k in range(count):
                mapped = ({"b5": "a5", "a5": "b5"}.get(value, value)
                          if shape == "multi-latch" and k == 1 else value)
                incoming.append(f"[ %{mapped}, %latch{k} ]")
            source = source.replace(f"[ %{value}, %loop ]", ", ".join(incoming), 1)
        if count == 2:
            choice = "  %bit = and iWIDTH %b5, 1\n  %pick = icmp ne iWIDTH %bit, 0\n  br i1 %pick, label %latch0, label %latch1\n"
        else:
            cases = " ".join(f"i32 {k}, label %latch{k}" for k in range(1, count))
            choice = f"  %choice = urem i32 %next, 5\n  switch i32 %choice, label %latch0 [ {cases} ]\n"
        latches = "".join(f"latch{k}:\n  br label %loop\n" for k in range(count))
        source = source.replace("  br i1 %again, label %loop, label %exit", "  br i1 %again, label %fork, label %exit\nfork:\n" + choice + latches.rstrip())
    elif shape == "duplicate-edges":
        for value in ("b5", "a5", "next"):
            source = source.replace(f"[ %{value}, %loop ]", f"[ %{value}, %loop ], [ %{value}, %loop ]", 1)
        source = source.replace("  br i1 %again, label %loop, label %exit", "  switch i32 %next, label %exit [ i32 1, label %loop i32 2, label %loop ]")
    elif shape == "switch-backedge":
        source = source.replace("  br i1 %again, label %loop, label %exit", "  switch i1 %again, label %exit [ i1 true, label %loop ]")
    elif shape == "unreachable-edge":
        for value in ("b5", "a5", "next"):
            source = source.replace(f"[ %{value}, %loop ]", f"[ %{value}, %loop ], [ %{value}, %dead ]", 1)
        source = source.replace("exit:\n", "dead:\n  br label %loop\nexit:\n")
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


def scalar_trace(a, b, count, width, shape="supported"):
    """Independent source and edge oracle, not derived from the compiler plan."""
    mask = (1 << width) - 1
    a, b = a & mask, b & mask
    out = a, b
    raw, edges = out, []
    if shape == "guarded-preheader" and count >= 4096: count = 0
    if shape == "duplicate-edges" and count: count = 3
    def step(a, b, salt=91):
        a0 = (a + b) & mask
        b0 = b ^ salt
        a1 = (a0 * 13) & mask
        b1 = (b0 - a0) & mask
        a2, b2 = a1 >> 3, (b1 << 2) & mask
        a3, b3 = a1 ^ a2, b1 | b2
        a4, b4 = (a3 + b3) & mask, b3 & 127
        signed = a4 - ((1 << width) if a4 >> (width - 1) else 0)
        a5, b5 = (signed >> 1) & mask, b4 ^ a4
        return a5, b5
    for _ in range(count):
        a5, b5 = raw = step(a, b)
        out = raw
        if shape == "external-user": out = (a5 if a == 0 else b5), b5
        elif shape == "phi-user": out = a, b5
        elif shape == "earlier-region":
            p, q = step(a, b, 37)
            out = a5 ^ p, b5 ^ q
        edge = int(not (b5 & 1)) if shape == "multi-latch" else 0
        edges.append(edge)
        if shape == "multi-exit" and (b5 & 7) == 0: break
        a, b = (a5, b5) if edge else (b5, a5)
        if shape == "constant-backedge": a = 7
    return out, raw, edges


def scalar_loop(a, b, count, width):
    return scalar_trace(a, b, count, width)[0]


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
    parser.add_argument("--shapes", nargs="+", choices=SHAPES, default=list(SHAPES))
    parser.add_argument("--bundle-loop-boundaries", action="store_true")
    parser.add_argument("--bundle-control", action="store_true")
    parser.add_argument("--control-ablation", action="store_true", help="matched control-off arm, retaining flattening")
    parser.add_argument("--control-profile", choices=("smoke", "max"), default="smoke")
    parser.add_argument("--control-passes", default="flattening", help="application pass filter; all uses the full profile")
    parser.add_argument("--exhaustive-byte-pairs", action="store_true")
    args = parser.parse_args()
    if not args.bundle_control and (args.control_ablation or args.control_profile != "smoke" or args.control_passes != "flattening"):
        parser.error("control experiment options require --bundle-control")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    summary = {"schema": "sre-bundle-loop-conformance-v1", "passed": False, "complete": False,
               "plugin_sha256": digest(plugin), "cases": [], "hardness_evaluated": False,
               "scalar_input_boundaries": args.bundle_loop_boundaries,
               "control_ablation": args.control_ablation,
               "control_profile": args.control_profile if args.bundle_control else None,
               "control_passes": args.control_passes if args.bundle_control else None,
               "exhaustive_byte_pairs_requested_trip_count": 2 if args.exhaustive_byte_pairs else None}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0",
             "-native-late-constants=0", "-native-merge=0", "-native-values=1", "-native-values-wide=1",
             "-native-region-plan=connected", "-native-connected-nodes=2", "-native-functions=kernel",
             "-native-plan=1", "-native-scale-budget=1", "-native-bundles=1", "-native-transfer-nodes=12",
             "-native-bundle-loops=1", f"-native-bundle-loop-boundaries={int(args.bundle_loop_boundaries)}",
             "-obf-deterministic", "-obf-verify"]
    if args.bundle_control:
        flags = [f for f in flags if f not in ("-native-passes=constenc", "-native-level=smoke")]
        flags += [f"-native-level={args.control_profile}", "-native-bundle-control=1"]
        if args.control_passes != "all": flags.append(f"-native-passes={args.control_passes}")
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
                oracle = "".join("%d %d\n" % scalar_trace(a, b, n, width, shape)[0] for a, b, n in values).encode()
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
                                if row["retained_operations"] != (24 if shape == "earlier-region" else 12):
                                    raise ToolFailure("unexpected retained recurrence operations")
                                region = row["regions"][-1]
                                loop = region["loop"]
                                encoded = shape not in FALLBACKS or (shape in EXPOSED and args.bundle_loop_boundaries)
                                if encoded:
                                    if args.bundle_control:
                                        control = next(r for r in data["bundle_control"] if r["function"] == "kernel")
                                        if control["status"] != "coupled": raise ToolFailure("persistent data/control relation was not emitted")
                                    if loop["status"] != "encoded": raise ToolFailure("recurrence fell back: " + loop["reason"])
                                    if len(loop["backedges"]) != (2 if shape == "multi-latch" else 1):
                                        raise ToolFailure("missing edge-specific tuple join")
                                    if bool(loop["scalar_input_uses"]) != (shape in EXPOSED):
                                        raise ToolFailure("scalar projection exposure was not reported")
                                    for a, b, n in values[:28]:
                                        _, raw, edges = scalar_trace(a, b, n, width, shape)
                                        if replay_loop(region, [a, b], len(edges), edges) != raw:
                                            raise ToolFailure("plan replay differs from independent loop oracle")
                                elif loop["status"] != "straight-line" or loop["reason"] != FALLBACKS[shape]:
                                    raise ToolFailure("unsupported shape lacks exact fallback reason")
                                before = digest(protected)
                                runner.run(command)
                                if digest(protected) != before: raise ToolFailure("nondeterministic emission")
                                arms = {name: protected}
                                if args.control_ablation:
                                    disabled = case / (name + "-disabled.ll")
                                    off_report = case / (name + "-disabled.json")
                                    off_command = [f for f in command if not f.startswith(("-native-report-json=", "-native-stage-dir="))]
                                    off_command = ["-native-bundle-control=0" if f == "-native-bundle-control=1" else
                                                   str(disabled) if f == str(protected) else f for f in off_command]
                                    off_command += [f"-native-report-json={off_report}"]
                                    runner.run(off_command)
                                    off = json.loads(off_report.read_text())
                                    errors = report_violations(off)
                                    if errors: raise ToolFailure("control-off: " + "; ".join(errors))
                                    if not any(r["function"] == "kernel" and r["words"] == 3 for r in off["flattening_state"]):
                                        raise ToolFailure("matched control-off arm lost multi-state flattening")
                                    arms[name + "-disabled"] = disabled
                                for arm, source in arms.items():
                                    for normalized in (False, True):
                                        selected = source
                                        if normalized:
                                            selected = case / (arm + "-post-o2.ll")
                                            runner.run(["opt", "-passes=default<O2>,verify", "-S", str(source), "-o", str(selected)])
                                        binary = selected.with_suffix(".bin")
                                        runner.run(["clang", "-pthread", str(selected), str(driver), "-o", str(binary)])
                                        if runner.run([str(binary)], stdin=stdin) != expected:
                                            raise ToolFailure(f"{arm}: full-output mismatch, post-O2={normalized}")
                                summary["cases"].append({"width": width, "shape": shape, "seed": seed,
                                    "family": family, "pins": bool(pins), "phases": phases, "vectors": len(values),
                                    "loop": loop, "passed": True, "post_o2_correct": True,
                                    "deterministic": True, "reentry_and_threads": True,
                                    "control_disabled_correct": True if args.control_ablation else None})
                                if args.bundle_control: summary["cases"][-1]["control"] = data["bundle_control"]
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
