"""Regression for unusable per-function shares and module-order independence."""
import argparse
import json
from pathlib import Path
import shutil

from conformance.bundle_run import inputs
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


def module(reverse=False):
    source = (FIXTURES / "bundle_kernel.ll.in").read_text().replace("WIDTH", "32")
    body = source[source.index("define i32"):]
    names = [f"unit{n:02d}" for n in range(32)]
    definitions = [body.replace("@kernel", "@" + name) for name in (reversed(names) if reverse else names)]
    wrapper = ["define i64 @invoke(i64 %a, i64 %b) {", "entry:",
               "  %x = trunc i64 %a to i32", "  %y = trunc i64 %b to i32"]
    for n, name in enumerate(names):
        value = "%x" if not n else f"%r{n - 1}"
        wrapper.append(f"  %r{n} = call i32 @{name}(i32 {value}, i32 %y)")
    wrapper += ["  %out = zext i32 %r31 to i64", "  ret i64 %out", "}"]
    return ('source_filename = "bundle-allocation-control"\ntarget triple = "x86_64-unknown-linux-gnu"\n' +
            "\n".join(definitions + wrapper) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,))
    result = {"schema": "sre-bundle-allocation-control-v1", "passed": False,
              "plugin_sha256": digest(plugin), "arms": []}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0",
             "-native-late-constants=0", "-native-merge=0", "-native-values=1", "-native-values-wide=1",
             "-native-region-plan=connected", "-native-connected-nodes=2", "-native-bundles=1",
             "-native-scale-budget=1", "-obf-seed=3", "-obf-deterministic", "-obf-verify"]
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-c", str(FIXTURES / "bundle_driver.c"), "-o", str(driver)])
        plans, expected = [], None
        vectors = inputs(32, 128)
        for reverse in (False, True):
            case = out / ("reverse" if reverse else "forward")
            case.mkdir()
            clean = case / "clean.ll"
            clean.write_text(module(reverse))
            native, report = case / "native.ll", case / "native.json"
            runner.run(opt_command(plugin) + flags + [f"-native-report-json={report}",
                "-S", str(clean), "-o", str(native)])
            data = json.loads(report.read_text())
            errors = report_violations(data)
            if errors: raise ToolFailure("; ".join(errors))
            selected = {r["function"]: r["regions"] for r in data["bundles"] if r["retained_operations"]}
            if not selected: raise ToolFailure("small nominal shares starved every complete region")
            plans.append(selected)
            for name, path in (("clean", clean), ("native", native)):
                binary = case / name
                runner.run(["clang", str(path), str(driver), "-o", str(binary)])
                output = runner.run([str(binary)], stdin=vectors)
                if expected is None: expected = output
                if output != expected: raise ToolFailure("module-order differential mismatch")
            result["arms"].append({"reverse": reverse, "owners": sorted(selected),
                "allocated": sum(r["growth_allocation"] for r in data["bundles"]),
                "vectors": len(expected.splitlines())})
        if plans[0] != plans[1]: raise ToolFailure("module order changed selection or site descriptors")
        result.update(passed=True, module_order_independent=True)
    except (ToolFailure, ValueError, OSError) as exc:
        result["error"] = str(exc)
    finally:
        result["commands"] = runner.records
        dump(out / "summary.json", result)
    print(json.dumps({k: result.get(k) for k in ("passed", "arms", "error")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
