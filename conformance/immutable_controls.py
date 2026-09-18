"""Compile-only rejection controls for immutable storage ownership.

Some controls intentionally contain undefined data or unresolved external
calls. Never execute them and never classify a compiler error as rejection.
"""
import argparse
import json
from pathlib import Path
import shutil

from conformance.connected_check import report_violations
from conformance.immutable_run import fixture
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, opt_command


def controls():
    base = fixture(32, 5)
    yield "exported", base.replace("private constant", "constant", 1), "linkage-mutability-or-storage"
    yield "mutable", base.replace("private constant", "private global", 1), "linkage-mutability-or-storage"
    yield "external-init", base.replace("private constant", "private externally_initialized constant", 1), "linkage-mutability-or-storage"
    yield "tls", base.replace("private constant", "private thread_local constant", 1), "linkage-mutability-or-storage"
    yield "partial-init", base.replace("i32 55", "i32 undef", 1), "non-integer-initializer"
    yield "volatile", base.replace("%aval = load i32", "%aval = load volatile i32", 1), "non-scalar-or-volatile-access"
    yield "atomic", base.replace("%aval = load i32, ptr %aptr", "%aval = load atomic i32, ptr %aptr monotonic, align 4", 1), "non-scalar-or-volatile-access"
    yield "partial-read", base.replace("entry:\n", "entry:\n  %byte = load i8, ptr @table\n", 1), "non-scalar-or-volatile-access"
    yield "identity", base.replace("entry:\n", "entry:\n  %identity = icmp eq ptr @table, %out\n", 1), "address-escape-or-unsupported-use"
    yield "escape", base.replace("entry:\n", "entry:\n  call void @observe(ptr @table)\n", 1) + "declare void @observe(ptr)\n", "address-escape-or-unsupported-use"


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
    result = {"schema": "sre-immutable-controls-v1", "passed": False, "plugin_sha256": digest(plugin),
              "cases": [], "executed_test_programs": False, "hardness_evaluated": False}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=1", "-native-helper-hardening=0", "-native-late-constants=0",
             "-native-merge=0", "-native-values=1", "-native-values-wide=1", "-native-region-plan=connected",
             "-native-connected-nodes=2", "-native-functions=kernel", "-native-bundles=1", "-native-immutable-bundles=1",
             "-obf-seed=4", "-obf-deterministic", "-obf-verify"]
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
            row = next(r for r in data["data"] if r["object"] == "table")
            if row["status"] != "skipped" or row["reason"] != reason:
                raise ToolFailure(f"{name}: unexpected disposition {row}")
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
