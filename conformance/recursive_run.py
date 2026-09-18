"""Actual recursive private activations, merge arbitration and all-output gates."""
import argparse
import json
from pathlib import Path
import shutil

from conformance.bundle_run import inputs
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


def fixture(width, straight_line=False, direct_return=False, homogeneous=False, drop_unused_depth=False):
    if drop_unused_depth and not straight_line:
        raise ValueError("cannot drop a live recursion depth")
    ty = f"i{width}"
    lines = ['target triple = "x86_64-unknown-linux-gnu"',
             'target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"',
             f"define internal {ty} @recur({ty} %x, {ty} %y, i32 %depth) noinline {{", "entry:",
             "  %stop = icmp eq i32 %depth, 0", "  br i1 %stop, label %base, label %step", "base:",
             f"  %initial = xor {ty} %x, %y", f"  ret {ty} %initial", "step:",
             f"  %v0 = add {ty} %x, %y", f"  %v1 = xor {ty} %x, 7", f"  %v2 = mul {ty} %v0, 3",
             f"  %v3 = or {ty} %v1, %y", f"  %v4 = add {ty} %v2, %v3", f"  %v5 = xor {ty} %v2, %v3",
             f"  %v6 = mul {ty} %v4, 5", f"  %v7 = add {ty} %v5, %v6", "  %next = sub i32 %depth, 1",
             f"  %child = notail call {ty} @recur({ty} %v6, {ty} %v7, i32 %next)",
             f"  %result = xor {ty} %child, %v6", f"  ret {ty} %result", "}",
             "define internal i64 @ptr_a(ptr %p) noinline {", "entry:", "  %x = load i64, ptr %p",
             "  %a = mul i64 %x, 3", "  %b = add i64 %a, 17", "  ret i64 %b", "}",
             "define internal i64 @ptr_b(ptr %p) noinline {", "entry:", "  %x = load i64, ptr %p",
             "  %a = lshr i64 %x, 11", "  %b = xor i64 %a, %x", "  ret i64 %b", "}",
             "define void @invoke(i64 %a, i64 %b, ptr %out) {", "entry:"]
    a, b = "%a", "%b"
    if width != 64:
        lines += [f"  %a0 = trunc i64 %a to {ty}", f"  %b0 = trunc i64 %b to {ty}"]
        a, b = "%a0", "%b0"
    lines += ["  %d0 = and i64 %b, 15", "  %depth0 = trunc i64 %d0 to i32",
              "  %shift = lshr i64 %a, 5", "  %d1 = and i64 %shift, 7", "  %depth1 = trunc i64 %d1 to i32",
              f"  %r0 = call {ty} @recur({ty} {a}, {ty} {b}, i32 %depth0)",
              f"  %r1 = call {ty} @recur({ty} {b}, {ty} {a}, i32 %depth1)"]
    for k in range(2):
        value = f"%r{k}"
        if width != 64:
            lines.append(f"  %wide{k} = zext {ty} {value} to i64")
            value = f"%wide{k}"
        lines += [f"  %out{k} = getelementptr inbounds i64, ptr %out, i32 {k}", f"  store i64 {value}, ptr %out{k}"]
    for k, helper in ((2, "ptr_a"), (3, "ptr_b")):
        lines += [f"  %r{k} = call i64 @{helper}(ptr %out{k - 2})",
                  f"  %out{k} = getelementptr inbounds i64, ptr %out, i32 {k}", f"  store i64 %r{k}, ptr %out{k}"]
    source = "\n".join(lines + ["  ret void", "}"]) + "\n"
    if straight_line:
        source = source.replace("  %stop = icmp eq i32 %depth, 0\n  br i1 %stop, label %base, label %step\nbase:\n" +
            f"  %initial = xor {ty} %x, %y\n  ret {ty} %initial\nstep:", "  br label %step\nstep:", 1)
        source = source.replace("  %next = sub i32 %depth, 1\n" +
            f"  %child = notail call {ty} @recur({ty} %v6, {ty} %v7, i32 %next)\n" +
            f"  %result = xor {ty} %child, %v6\n  ret {ty} %result",
            f"  %zero = icmp eq {ty} %v6, 0\n  %fallback = xor {ty} %v7, 11\n" +
            f"  %mixed = xor {ty} %v6, %v7\n  %result = select i1 %zero, {ty} %fallback, {ty} %mixed\n  ret {ty} %result", 1)
    if direct_return:
        source = source.replace(f"  %fallback = xor {ty} %v7, 11\n" +
            f"  %mixed = xor {ty} %v6, %v7\n  %result = select i1 %zero, {ty} %fallback, {ty} %mixed\n  ret {ty} %result",
            f"  br i1 %zero, label %rare, label %done\nrare:\n  ret {ty} 11\ndone:\n  ret {ty} %v7", 1)
    if drop_unused_depth:
        source = source.replace(', i32 %depth)', ')').replace(', i32 %depth0)', ')').replace(', i32 %depth1)', ')')
    if homogeneous and width != 32:
        source = source.replace("i32 %depth", f"{ty} %depth").replace("i32 %next", f"{ty} %next")
        for k in (0, 1):
            source = source.replace(f"%depth{k} = trunc i64 %d{k} to i32",
                f"%depth{k} = trunc i64 %d{k} to {ty}" if width != 64 else f"%depth{k} = or i64 %d{k}, 0")
    return source


def oracle(a, b, width, straight_line=False, direct_return=False):
    mask = (1 << width) - 1
    def recurse(x, y, depth):
        if straight_line: depth = 1
        parents = []
        for _ in range(depth):
            v2 = (((x + y) & mask) * 3) & mask
            v3 = (x ^ 7) | y
            v6 = (((v2 + v3) & mask) * 5) & mask
            v7 = ((v2 ^ v3) + v6) & mask
            parents.append(v6)
            x, y = v6, v7
        if direct_return: return 11 if x == 0 else y
        if straight_line: return (y ^ 11) if x == 0 else (x ^ y)
        out = x ^ y
        for value in reversed(parents): out ^= value
        return out
    left = recurse(a & mask, b & mask, b & 15)
    right = recurse(b & mask, a & mask, (a >> 5) & 7)
    return [left, right, (left * 3 + 17) & ((1 << 64) - 1), right ^ (right >> 11)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--widths", type=int, nargs="+", choices=(8, 16, 32, 64), default=[8, 32])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1])
    parser.add_argument("--random-inputs", type=int, default=256)
    parser.add_argument("--merge", action="store_true", help="require actual coexistence with a separately merged pointer group")
    parser.add_argument("--ablation-plugin", type=Path, help="require feature-off IR equality with this prior plugin")
    parser.add_argument("--bundle-call-inputs", action="store_true")
    parser.add_argument("--bundle-call-outputs", action="store_true")
    parser.add_argument("--joint-call-arguments", action="store_true")
    parser.add_argument("--homogeneous-arguments", action="store_true", help="use the word type for bounded recursion depth too")
    parser.add_argument("--drop-unused-depth", action="store_true", help="two-argument straight-line control without an unused depth formal")
    parser.add_argument("--straight-line", action="store_true", help="nonrecursive all-input-absorption control")
    parser.add_argument("--direct-return", action="store_true", help="straight-line control with a direct bundle result")
    parser.add_argument("--transfer-family", choices=("xor", "additive", "seeded"), default="seeded")
    parser.add_argument("--no-bundle-pins", action="store_true")
    parser.add_argument("--connected-nodes", type=int, default=128)
    parser.add_argument("--profile", choices=("smoke", "max"), default="smoke")
    parser.add_argument("--passes", help="explicit native application pass selection")
    args = parser.parse_args()
    if args.direct_return and not args.straight_line: parser.error("--direct-return requires --straight-line")
    if args.drop_unused_depth and not args.straight_line: parser.error("--drop-unused-depth requires --straight-line")
    if args.ablation_plugin and (args.straight_line or args.bundle_call_inputs or args.bundle_call_outputs or args.joint_call_arguments):
        parser.error("recursion prior-plugin ablation is separate from bundle-input controls")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=240)
    result = {"schema": "sre-recursive-call-conformance-v1", "passed": False,
              "plugin_sha256": digest(plugin), "cases": [], "hardness_evaluated": False,
              "profile": args.profile, "passes": args.passes or ("constenc,fmerge" if args.merge else "constenc")}
    flags = ["-passes=native-obfuscation", f"-native-level={args.profile}",
             *([] if result['passes'] == 'all' else [f"-native-passes={result['passes']}"]),
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0", "-native-late-constants=0",
             f"-native-merge={int(args.merge)}", "-native-values=1", "-native-values-wide=1",
             "-native-region-plan=connected", f"-native-connected-nodes={args.connected_nodes}", "-native-predicate-regions=1",
             "-native-encoded-calls=1", "-native-self-recursion=1", "-native-call-policy=1", "-native-plan=1",
             "-native-regional-families=1", "-obf-deterministic", "-obf-verify"]
    if args.bundle_call_inputs or args.bundle_call_outputs or args.joint_call_arguments:
        flags += ["-native-bundles=1",
                  f"-native-transfer-family={args.transfer_family}",
                  f"-native-bundle-pins={int(not args.no_bundle_pins)}"]
    if args.bundle_call_inputs: flags += ["-native-bundle-call-inputs=1"]
    if args.bundle_call_outputs: flags += ["-native-bundle-call-outputs=1"]
    if args.joint_call_arguments: flags += ["-native-joint-call-arguments=1"]
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-pthread", "-c", str(FIXTURES / "tile_driver.c"), "-o", str(driver)])
        for width in args.widths:
            case = out / f"i{width}"
            case.mkdir()
            source = case / "clean.ll"
            source.write_text(fixture(width, args.straight_line, args.direct_return, args.homogeneous_arguments, args.drop_unused_depth))
            vectors = inputs(width, args.random_inputs)
            if args.direct_return:
                # v6 == 0 exactly: 3*(16+y) + (23|y) == 2**width.
                # Random wide inputs almost never exercise this return arm.
                y = (1 << (width - 2)) - 13
                vectors += f"16 {y}\n{y} 16\n".encode()
            pairs = [tuple(map(int, line.split())) for line in vectors.splitlines()]
            expected = "".join(" ".join(f"{v:016x}" for v in oracle(a, b, width, args.straight_line, args.direct_return)) + "\n" for a, b in pairs).encode()
            clean = case / "clean"
            runner.run(["clang", str(source), str(driver), "-pthread", "-o", str(clean)])
            if runner.run([str(clean)], stdin=vectors) != expected: raise ToolFailure("clean recursion oracle mismatch")
            for seed in args.seeds:
                native, report = case / f"seed-{seed}.ll", case / f"seed-{seed}.json"
                command = opt_command(plugin) + flags + [f"-obf-seed={seed}", f"-native-report-json={report}",
                                                        f"-native-stage-dir={case / f'seed-{seed}-stages'}",
                                                        "-S", str(source), "-o", str(native)]
                runner.run(command)
                data = json.loads(report.read_text())
                errors = report_violations(data)
                if errors: raise ToolFailure("; ".join(errors))
                row = next(r for r in data["encoded_calls"] if r["function"] == "recur")
                if args.joint_call_arguments:
                    expected_joint = width == 32 or args.homogeneous_arguments or args.drop_unused_depth
                    if (row["joint_arguments"]["status"] == "joint") != expected_joint:
                        raise ToolFailure("joint argument ABI did not match source width contract")
                policy = next(r for r in data["call_policy"] if r["function"] == "recur")
                recursive = not args.straight_line
                if row["status"] != "encoded" or row["recursive_calls_rewritten"] != int(recursive) or row["call_sites_rewritten"] != 2 + int(recursive):
                    raise ToolFailure(f"recursive interface not actually emitted: {row}")
                if args.bundle_call_inputs:
                    imported = next((r for r in data["bundle_call_inputs"] if r["function"] == row["encoded_function"]), None)
                    if not imported or imported["imported_arguments"] < 2:
                        raise ToolFailure("bundle did not import multiple private arguments")
                    if args.straight_line and imported["fully_absorbed_arguments"] < 2:
                        raise ToolFailure("straight-line control retained avoidable scalar inputs")
                if args.bundle_call_outputs:
                    supplied = [r for r in data["bundle_call_outputs"] if r["interface"] == row["encoded_function"]]
                    key = "result_pairs" if args.direct_return else "argument_pairs"
                    if not sum(r[key] for r in supplied): raise ToolFailure("no direct bundle-call supplies emitted")
                if policy["policy"] != "encoded-interface" or policy["outcome"] != "encoded":
                    raise ToolFailure("recursive arbitration did not retain its interface")
                if args.merge and not data["merged_groups"]: raise ToolFailure("merge flag did not emit a merged group")
                hashes = digest(native), digest(report)
                runner.run(command)
                if hashes != (digest(native), digest(report)): raise ToolFailure("nondeterministic recursive interface")
                normalized = case / f"seed-{seed}-post-o2.ll"
                runner.run(["opt", "-passes=default<O2>,verify", "-S", str(native), "-o", str(normalized)])
                for arm, ir in (("native", native), ("post-o2", normalized)):
                    binary = case / f"seed-{seed}-{arm}"
                    runner.run(["clang", str(ir), str(driver), "-pthread", "-o", str(binary)])
                    if runner.run([str(binary)], stdin=vectors) != expected: raise ToolFailure(f"recursive mismatch: {arm}")
                    runner.run([str(binary), "--threads"])
                if args.joint_call_arguments:
                    off = case / f"seed-{seed}-joint-off.ll"
                    off_report = off.with_suffix(".json")
                    runner.run(opt_command(plugin) + [f for f in flags if f != "-native-joint-call-arguments=1"] +
                        [f"-obf-seed={seed}", f"-native-report-json={off_report}", "-S", str(source), "-o", str(off)])
                    off_data = json.loads(off_report.read_text())
                    if report_violations(off_data) or off_data["features"]["joint_call_arguments"]:
                        raise ToolFailure("invalid joint-off interface report")
                    off_o2 = case / f"seed-{seed}-joint-off-post-o2.ll"
                    runner.run(["opt", "-passes=default<O2>,verify", "-S", str(off), "-o", str(off_o2)])
                    for ir in (off, off_o2):
                        binary = ir.with_suffix(".bin")
                        runner.run(["clang", str(ir), str(driver), "-pthread", "-o", str(binary)])
                        if runner.run([str(binary)], stdin=vectors) != expected:
                            raise ToolFailure("joint-off full-output mismatch")
                        runner.run([str(binary), "--threads"])
                if args.bundle_call_inputs or args.bundle_call_outputs:
                    disabled = case / f"seed-{seed}-disabled.ll"
                    disabled_report = case / f"seed-{seed}-disabled.json"
                    ablation = "-native-bundle-call-outputs=1" if args.bundle_call_outputs else "-native-bundle-call-inputs=1"
                    off_flags = [f for f in flags if f != ablation]
                    runner.run(opt_command(plugin) + off_flags + [f"-obf-seed={seed}",
                        f"-native-report-json={disabled_report}", "-S", str(source), "-o", str(disabled)])
                    if report_violations(json.loads(disabled_report.read_text())):
                        raise ToolFailure("invalid bundle-input ablation report")
                    off_o2 = case / f"seed-{seed}-disabled-post-o2.ll"
                    runner.run(["opt", "-passes=default<O2>,verify", "-S", str(disabled), "-o", str(off_o2)])
                    for label, ir in (("disabled", disabled), ("disabled-post-o2", off_o2)):
                        binary = case / f"seed-{seed}-{label}"
                        runner.run(["clang", str(ir), str(driver), "-pthread", "-o", str(binary)])
                        if runner.run([str(binary)], stdin=vectors) != expected:
                            raise ToolFailure(f"bundle-input ablation mismatch: {label}")
                if args.ablation_plugin:
                    control = case / f"seed-{seed}-off.ll"
                    control_report = case / f"seed-{seed}-off.json"
                    off_flags = [f for f in flags if f != "-native-self-recursion=1"]
                    runner.run(opt_command(plugin) + off_flags + [f"-obf-seed={seed}",
                        f"-native-report-json={control_report}", "-S", str(source), "-o", str(control)])
                    off = json.loads(control_report.read_text())
                    if report_violations(off): raise ToolFailure("invalid feature-off report")
                    off_policy = next((r for r in off["call_policy"] if r["function"] == "recur"), None)
                    if not off_policy or off_policy["interface_blocker"] != "recursive":
                        raise ToolFailure("feature-off policy did not exclude the recursive interface")
                    # With the interface excluded, fusion may own and erase
                    # the original function. Its policy row is the denominator.
                    off_row = next((r for r in off["encoded_calls"] if r["function"] == "recur"), None)
                    if off_row and (off_row["status"] != "skipped" or off_row["reason"] != "recursive"):
                        raise ToolFailure("feature-off emitter did not exclude the recursive interface")
                    previous = case / f"seed-{seed}-previous.ll"
                    runner.run(opt_command(args.ablation_plugin.resolve()) + off_flags + [f"-obf-seed={seed}",
                        "-S", str(source), "-o", str(previous)])
                    if control.read_bytes() != previous.read_bytes():
                        raise ToolFailure("feature-off IR differs from the prior plugin")
                    binary = case / f"seed-{seed}-off"
                    runner.run(["clang", str(control), str(driver), "-pthread", "-o", str(binary)])
                    if runner.run([str(binary)], stdin=vectors) != expected:
                        raise ToolFailure("feature-off oracle mismatch")
                    result["ablation_plugin_sha256"] = digest(args.ablation_plugin.resolve())
                result["cases"].append({"width": width, "seed": seed, "vectors": len(pairs),
                    "merge_requested": args.merge, "merged_groups": len(data["merged_groups"]),
                    "interface": row, "policy": policy, "passed": True,
                    "straight_line": args.straight_line, "family": args.transfer_family,
                    "pins": not args.no_bundle_pins, "direct_return": args.direct_return,
                    "bundle_call_inputs": data.get("bundle_call_inputs", []), "bundle_call_outputs": data.get("bundle_call_outputs", [])})
                dump(out / "summary.json", result)
                print(f"i{width} seed-{seed}: passed", flush=True)
        result["passed"] = True
    except (ToolFailure, OSError, ValueError) as exc:
        result["error"] = str(exc)
    finally:
        result["commands"] = runner.records
        dump(out / "summary.json", result)
    print(json.dumps({k: result.get(k) for k in ("passed", "error")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
