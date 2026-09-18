"""Targeted exact compound-predicate integration, without a large-corpus gate."""
import argparse
import json
from pathlib import Path
import shutil

from conformance.bundle_predicates import predicate_summary
from conformance.bundle_run import inputs
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command

SHAPES = ("all", "any", "partial", "three", "four", "wrong-left", "wrong-right",
          "shared", "mixed", "reused-output", "cross-block")
NEGATIVE = ("shared", "mixed", "reused-output", "cross-block")


def values(a, b, width):
    m = (1 << width) - 1
    a, b = a & m, b & m
    a0, b0 = (a + b) & m, b ^ 91
    a1, b1 = (a0 * 13) & m, (b0 - a0) & m
    a3, b3 = a1 ^ (a1 >> 3), b1 | ((b1 << 2) & m)
    a4, b4 = (a3 + b3) & m, b3 & 127
    signed = a4 - ((1 << width) if a4 >> (width - 1) else 0)
    return a4, b4, (signed >> 1) & m, b4 ^ a4


def target_spec(width, shape):
    names = ["a4", "b4", "a5", "b5"]
    selected = [0, 1, 2, 3] if shape == "four" else [0, 2, 3] if shape == "three" else [2, 3]
    target = values(19, 37, width)
    targets = [(names[k], target[k]) for k in selected]
    if shape == "wrong-left": targets[0] = targets[0][0], targets[0][1] ^ 1
    if shape == "wrong-right": targets[1] = targets[1][0], targets[1][1] ^ 1
    if shape == "reused-output": targets[1] = targets[0][0], targets[0][1] ^ 1
    return targets


def oracle(a, b, width, shape):
    actual = dict(zip(("a4", "b4", "a5", "b5"), values(a, b, width)))
    equal = [actual[name] == constant for name, constant in target_spec(width, shape)]
    answer = not all(equal) if shape == "any" else equal[0] and not equal[1] if shape == "mixed" else all(equal)
    extra = actual["a5"] if shape == "partial" else actual["b5"] if shape == "reused-output" else int(equal[0]) if shape == "shared" else 0
    return (int(answer) + extra) & ((1 << width) - 1)


def fixture(width, shape):
    source = (FIXTURES / "bundle_kernel.ll.in").read_text().replace("WIDTH", str(width))
    source = source.split("  %answer =", 1)[0]
    targets = target_spec(width, shape)
    ty = f"i{width}"
    comparisons = []
    for index, (name, constant) in enumerate(targets):
        op = "ne" if shape == "any" or (shape == "mixed" and index == 1) else "eq"
        comparisons.append(f"  %cmp{index} = icmp {op} {ty} %{name}, {constant}\n")
    if shape == "cross-block":
        source += comparisons[0] + "  br i1 %cmp0, label %second, label %done\nsecond:\n"
        source += comparisons[1] + "  br label %done\ndone:\n  %decision = phi i1 [ false, %entry ], [ %cmp1, %second ]\n"
        root = "%decision"
    else:
        source += "".join(comparisons)
        root = "%cmp0"
        for index in range(1, len(targets)):
            source += f"  %reduce{index} = {'or' if shape == 'any' else 'and'} i1 {root}, %cmp{index}\n"
            root = f"%reduce{index}"
    source += f"  %wide = zext i1 {root} to {ty}\n"
    if shape == "shared": source += f"  %shared = zext i1 %cmp0 to {ty}\n"
    extra = "%a5" if shape == "partial" else "%b5" if shape == "reused-output" else "%shared" if shape == "shared" else None
    if extra: source += f"  %answer = add {ty} %wide, {extra}\n"
    source += f"  ret {ty} {'%answer' if extra else '%wide'}\n}}\n"
    cast = f"  %x = trunc i64 %a to {ty}\n  %y = trunc i64 %b to {ty}\n" if width < 64 else ""
    args = f"%x, {ty} %y" if width < 64 else "%a, i64 %b"
    extend = f"  %out = zext {ty} %r to i64\n" if width < 64 else ""
    return source + "\ndefine i64 @invoke(i64 %a, i64 %b) {\nentry:\n" + cast + f"  %r = call {ty} @kernel({ty} {args})\n" + extend + f"  ret i64 {'%out' if extend else '%r'}\n}}\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--widths", type=int, nargs="+", choices=(8, 16, 32, 64), default=[8, 32])
    parser.add_argument("--shapes", nargs="+", choices=SHAPES, default=list(SHAPES))
    parser.add_argument("--family", choices=("xor", "additive", "seeded"), default="xor")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--pins", type=int, choices=(0, 1), default=0)
    parser.add_argument("--profile", choices=("smoke", "max"), default="smoke")
    parser.add_argument("--passes", default="constenc", help="all runs the full application profile")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    result = {"schema": "sre-joint-predicate-conformance-v1", "passed": False, "complete": False,
              "plugin_sha256": digest(plugin), "cases": [], "hardness_evaluated": False}
    flags = ["-passes=native-obfuscation", f"-native-level={args.profile}", "-native-strings=0", "-native-data=0",
             "-native-helper-hardening=0", "-native-late-constants=0", "-native-merge=0", "-native-values=1",
             "-native-values-wide=1", "-native-region-plan=connected", "-native-connected-nodes=2", "-native-functions=kernel",
             "-native-plan=1", "-native-scale-budget=1", "-native-bundles=1", "-native-transfer-nodes=12",
             f"-native-transfer-family={args.family}", f"-native-bundle-pins={args.pins}",
             f"-obf-seed={args.seed}", "-obf-deterministic", "-obf-verify"]
    if args.passes != "all": flags.append("-native-passes=" + args.passes)
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-c", str(FIXTURES / "bundle_driver.c"), "-o", str(driver)])
        for width in args.widths:
            stdin = inputs(width, 512) + b"19 37\n19 38\n20 37\n20 38\n"
            vectors = [tuple(map(int, line.split())) for line in stdin.splitlines()]
            for shape in args.shapes:
                case = out / f"i{width}-{shape}"
                case.mkdir()
                clean = case / "clean.ll"
                clean.write_text(fixture(width, shape))
                expected = "".join(f"{oracle(a, b, width, shape):016x}\n" for a, b in vectors).encode()
                runner.run(["clang", str(clean), str(driver), "-o", str(case / "clean.bin")])
                if runner.run([str(case / "clean.bin")], stdin=stdin) != expected:
                    raise ToolFailure("clean compiler differs from independent predicate oracle")
                coverage = None
                for enabled in (True, False):
                    arm = "native" if enabled else "disabled"
                    ir, report = case / (arm + ".ll"), case / (arm + ".json")
                    command = opt_command(plugin) + flags + [f"-native-bundle-predicates={int(enabled)}",
                        f"-native-report-json={report}", f"-native-stage-dir={case / (arm + '-stages')}", "-S", str(clean), "-o", str(ir)]
                    runner.run(command)
                    data = json.loads(report.read_text())
                    errors = report_violations(data)
                    if errors: raise ToolFailure("; ".join(errors))
                    if enabled:
                        coverage = predicate_summary(data)
                        if coverage["roots"] != int(shape not in NEGATIVE):
                            raise ToolFailure("requested predicate coverage or explicit exclusion differs")
                        before = digest(ir)
                        runner.run(command)
                        if digest(ir) != before: raise ToolFailure("nondeterministic predicate emission")
                    for normalized in (False, True):
                        source = ir
                        if normalized:
                            source = case / (arm + "-post-o2.ll")
                            runner.run(["opt", "-passes=default<O2>,verify", "-S", str(ir), "-o", str(source)])
                        binary = source.with_suffix(".bin")
                        runner.run(["clang", str(source), str(driver), "-o", str(binary)])
                        if runner.run([str(binary)], stdin=stdin) != expected:
                            raise ToolFailure(f"{shape}: predicate outputs differ, arm={arm}, normalized={normalized}")
                result["cases"].append({"width": width, "shape": shape, "vectors": len(vectors), "coverage": coverage,
                    "passed": True, "post_o2_correct": True, "ablation_correct": True, "deterministic": True})
                dump(out / "summary.json", result)
                print(f"i{width} {shape}: passed", flush=True)
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
