"""Native bundle integration: all outputs, emitted plans, determinism, O2 controls.

This is a correctness/coverage gate, not a promotion or hardness result.
"""
import argparse
import json
from pathlib import Path
import random
import shutil

from conformance.bundle_model import replay
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


def inputs(width, random_count):
    mask = (1 << width) - 1
    if width == 8:
        return "".join(f"{x} {y}\n" for x in range(256) for y in range(256)).encode()
    edges = (0, 1, 2, 7, width - 1, width, mask >> 1, 1 << (width - 1), mask)
    rng = random.Random(912 + width)
    values = [(x, y) for x in edges for y in edges]
    values += [(rng.getrandbits(width), rng.getrandbits(width)) for _ in range(random_count)]
    return "".join(f"{x} {y}\n" for x, y in values).encode()


def fixture(width):
    source = (FIXTURES / "bundle_kernel.ll.in").read_text().replace("WIDTH", str(width))
    cast_in = (f"  %x = trunc i64 %a to i{width}\n  %y = trunc i64 %b to i{width}\n"
               if width != 64 else "")
    args = f"%x, i{width} %y" if width != 64 else "%a, i64 %b"
    cast_out = f"  %out = zext i{width} %r to i64\n" if width != 64 else ""
    return (source + "\ndefine i64 @invoke(i64 %a, i64 %b) {\nentry:\n" + cast_in +
            f"  %r = call i{width} @kernel(i{width} {args})\n" + cast_out +
            f"  ret i64 {'%out' if width != 64 else '%r'}\n}}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--widths", type=int, nargs="+", default=[8, 16, 32, 64])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 3, 4])
    parser.add_argument("--families", nargs="+", choices=["xor", "additive", "seeded"], default=["xor", "additive"])
    parser.add_argument("--random-inputs", type=int, default=1024)
    args = parser.parse_args()
    if not args.widths or any(w not in (8, 16, 32, 64) for w in args.widths):
        parser.error("unsupported width")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    summary = {"schema": "sre-bundle-conformance-v1", "passed": False, "complete": False,
               "plugin_sha256": digest(plugin), "cases": [], "hardness_evaluated": False}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0",
             "-native-late-constants=0", "-native-merge=0", "-native-values=1", "-native-values-wide=1",
             "-native-region-plan=connected", "-native-connected-nodes=2", "-native-functions=kernel",
             "-native-plan=1", "-native-scale-budget=1", "-native-bundles=1", "-native-transfer-nodes=16",
             "-obf-deterministic", "-obf-verify"]
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-c", str(FIXTURES / "bundle_driver.c"), "-o", str(driver)])
        for width in args.widths:
            case = out / f"i{width}"
            case.mkdir()
            clean_ir = case / "clean.ll"
            clean_ir.write_text(fixture(width))
            clean = case / "clean"
            runner.run(["clang", str(clean_ir), str(driver), "-o", str(clean)])
            vectors = inputs(width, args.random_inputs)
            expected = runner.run([str(clean)], stdin=vectors)
            for family in args.families:
                for seed in args.seeds:
                    for pins in (False, True):
                        name = f"{family}-{seed}-pins-{int(pins)}"
                        stage = case / (name + "-stages")
                        protected = case / (name + ".ll")
                        report = case / (name + ".json")
                        command = opt_command(plugin) + flags + [f"-obf-seed={seed}",
                            f"-native-transfer-family={family}", f"-native-bundle-pins={int(pins)}",
                            f"-native-report-json={report}", f"-native-stage-dir={stage}",
                            "-S", str(clean_ir), "-o", str(protected)]
                        runner.run(command)
                        data = json.loads(report.read_text())
                        errors = report_violations(data)
                        if errors: raise ToolFailure("; ".join(errors))
                        row = next(r for r in data["bundles"] if r["function"] == "kernel")
                        if row["retained_operations"] < 8:
                            raise ToolFailure(f"{name}: no useful bundle retained")
                        rng = random.Random(seed)
                        for region in row["regions"]:
                            for _ in range(64):
                                replay(region, [rng.getrandbits(width) for _ in range(region["inputs"])])
                        before_hash = digest(protected)
                        runner.run(command)
                        if digest(protected) != before_hash:
                            raise ToolFailure("nondeterministic emission")
                        for normalized in (False, True):
                            selected = protected
                            if normalized:
                                selected = case / (name + "-post-o2.ll")
                                runner.run(["opt", "-passes=default<O2>,verify", "-S", str(protected), "-o", str(selected)])
                            binary = selected.with_suffix(".bin")
                            runner.run(["clang", str(selected), str(driver), "-o", str(binary)])
                            if runner.run([str(binary)], stdin=vectors) != expected:
                                raise ToolFailure(f"{name}: full-output mismatch, post-O2={normalized}")
                        summary["cases"].append({"width": width, "seed": seed, "family": family,
                            "pins": pins, "retained_operations": row["retained_operations"],
                            "vectors": len(expected.splitlines()), "post_o2_correct": True,
                            "deterministic": True, "plan_replayed": True, "passed": True})
                        dump(out / "summary.json", summary)
                        print(f"i{width} {name}: passed", flush=True)
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
