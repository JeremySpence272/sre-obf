"""Compile-only recursive ownership exclusions; invalid IR is never a pass."""
import argparse
import json
from pathlib import Path
import shutil

from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.recursive_run import fixture
from conformance.run import ROOT, opt_command


def controls():
    base = fixture(32)
    selfcall = "%child = notail call i32 @recur(i32 %v6, i32 %v7, i32 %next)"
    def entry(instruction):
        return base.replace("entry:\n", "entry:\n  " + instruction + "\n", 1)
    yield "unknown-callee", entry("call void @unknown()") + "declare void @unknown()\n", "recursive-unsupported-effect"
    yield "stack-observation", entry("%frame = call ptr @llvm.frameaddress.p0(i32 0)") + "declare ptr @llvm.frameaddress.p0(i32 immarg)\n", "recursive-unsupported-effect"
    yield "callback", entry("%cb = load ptr, ptr @callback\n  call void %cb()") + "@callback = external global ptr\n", "recursive-unsupported-effect"
    yield "operand-bundle", base.replace(selfcall, selfcall + ' [ "unknown"(i32 %x) ]'), "unsupported-call-site"
    yield "musttail", base.replace(selfcall, selfcall.replace("notail", "musttail")).replace("  %result = xor i32 %child, %v6\n  ret i32 %result", "  ret i32 %child"), "musttail-body"
    yield "returns-twice", base.replace("noinline {", "noinline returns_twice {", 1), "returns-twice"
    yield "address-taken", base + "@address = global ptr @recur\n", "exported-or-address-taken"
    mutual = base.replace(selfcall, selfcall.replace("@recur", "@other"))
    mutual += "define internal i32 @other(i32 %x, i32 %y, i32 %depth) noinline {\nentry:\n  %r = call i32 @recur(i32 %x, i32 %y, i32 %depth)\n  ret i32 %r\n}\n"
    yield "mutual-recursion", mutual, "recursive"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    result = {"schema": "sre-recursive-controls-v1", "passed": False, "plugin_sha256": digest(plugin),
              "cases": [], "executed_test_programs": False, "hardness_evaluated": False}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0", "-native-late-constants=0",
             "-native-merge=0", "-native-values=1", "-native-values-wide=1", "-native-region-plan=connected",
             "-native-encoded-calls=1", "-native-self-recursion=1", "-native-call-policy=1", "-native-plan=1",
             "-obf-seed=3", "-obf-deterministic", "-obf-verify"]
    try:
        for name, source, reason in controls():
            ir = out / (name + ".ll")
            ir.write_text(source)
            report = out / (name + ".json")
            runner.run(["opt", "-passes=verify", "-disable-output", str(ir)])
            runner.run(opt_command(plugin) + flags + [f"-native-report-json={report}", "-S", str(ir),
                                                     "-o", str(out / (name + "-native.ll"))])
            data = json.loads(report.read_text())
            errors = report_violations(data)
            if errors: raise ToolFailure("; ".join(errors))
            row = next(r for r in data["encoded_calls"] if r["function"] == "recur")
            policy = next(r for r in data["call_policy"] if r["function"] == "recur")
            if row["status"] != "skipped" or row["reason"] != reason or policy["interface_blocker"] != reason:
                raise ToolFailure(f"{name}: unexpected disposition {row} / {policy}")
            result["cases"].append({"case": name, "source_sha256": digest(ir), "reason": reason, "passed": True})
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
