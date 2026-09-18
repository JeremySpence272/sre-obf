"""Bounded v04 compiler regressions: plan neutrality, policy ownership and outputs."""
import argparse
import json
from pathlib import Path
import shutil

from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command, test_inputs


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
    result = {"schema": "sre-v04-review-v1", "passed": False,
              "plugin_sha256": digest(plugin), "cases": [], "hardness_evaluated": False}
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0",
             "-native-late-constants=0", "-native-values=1", "-native-values-wide=1",
             "-native-region-plan=connected", "-native-connected-nodes=256",
             "-obf-deterministic", "-obf-verify"]
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-c", str(FIXTURES / "driver.c"), "-o", str(driver)])
        inputs = test_inputs(128)
        for name in ("encoded_calls", "connected_aggregate", "call_policy_owner"):
            case = out / name
            case.mkdir()
            source = FIXTURES / (name + (".ll" if name == "call_policy_owner" else ".c"))
            archived = case / ("input" + source.suffix)
            shutil.copy2(source, archived)
            ir = case / "input.ll"
            objects = [str(driver)]
            if name == "connected_aggregate":
                sink = case / "sink.c"
                shutil.copy2(FIXTURES / "connected_aggregate_sink.c", sink)
                sink_object = case / "sink.o"
                runner.run(["clang", "-O2", "-c", str(sink), "-o", str(sink_object)])
                objects.append(str(sink_object))
            if source.suffix == ".c":
                frontend = (["-O0", "-Xclang", "-disable-O0-optnone", "-Dproducer=obf_target"]
                            if name == "connected_aggregate" else ["-O2"])
                runner.run(["clang", *frontend, "-S", "-emit-llvm", str(archived), "-o", str(ir)])
            clean = case / "clean"
            runner.run(["clang", str(ir), *objects, "-o", str(clean)])
            expected = runner.run([str(clean)], stdin=inputs)
            features = (["-native-memory=1", "-native-memory-ssa=1",
                         "-native-connected-aggregates=1", "-native-semantic-budget=25"]
                        if name == "connected_aggregate" else
                        ["-native-encoded-calls=1", "-native-merge=1",
                         f"-native-call-policy={int(name == 'encoded_calls')}"])
            for seed in (1, 3):
                outputs = []
                for planned in (False, True):
                    stem = case / f"seed-{seed}-plan-{int(planned)}"
                    report, native_ir = stem.with_suffix(".json"), stem.with_suffix(".ll")
                    runner.run(opt_command(plugin) + flags + features + [f"-obf-seed={seed}",
                        f"-native-plan={int(planned)}", f"-native-report-json={report}",
                        "-S", str(ir), "-o", str(native_ir)])
                    data = json.loads(report.read_text())
                    errors = report_violations(data)
                    if errors:
                        raise ToolFailure("; ".join(errors))
                    if name == "call_policy_owner":
                        row = next(r for r in data["encoded_calls"] if r["function"] == "helper")
                        if row["reason"] != "call-policy-owner":
                            raise ToolFailure("encoded calls ignored the recorded non-interface owner")
                    if name == "encoded_calls" and not any(
                            r["status"] == "encoded" for r in data["encoded_calls"]):
                        raise ToolFailure("arbitration produced no encoded interface")
                    outputs.append(native_ir.read_bytes())
                    if not planned:
                        continue
                    for normalized in (False, True):
                        selected = native_ir
                        if normalized:
                            selected = case / f"seed-{seed}-post-o2.ll"
                            runner.run(["opt", "-passes=default<O2>,verify", "-S",
                                        str(native_ir), "-o", str(selected)])
                        binary = selected.with_suffix(".bin")
                        runner.run(["clang", str(selected), *objects, "-o", str(binary)])
                        if runner.run([str(binary)], stdin=inputs) != expected:
                            raise ToolFailure(f"{name}: full-output differential mismatch")
                if outputs[0] != outputs[1]:
                    raise ToolFailure(f"{name}: observing the typed plan changed emitted IR")
                result["cases"].append({"fixture": name, "fixture_sha256": digest(archived),
                    "seed": seed, "vectors": len(expected.splitlines()),
                    "plan_observation_neutral": True, "post_o2_correct": True,
                    "encoded_interfaces": sum(r["status"] == "encoded"
                                              for r in data.get("encoded_calls", [])),
                    "passed": True})
        result["passed"] = True
    except (ToolFailure, OSError, ValueError) as exc:
        result["error"] = str(exc)
    finally:
        result["commands"] = runner.records
        dump(out / "summary.json", result)
    print(json.dumps({key: result.get(key) for key in ("passed", "cases", "error")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
