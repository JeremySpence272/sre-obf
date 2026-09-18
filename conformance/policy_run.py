"""Small frozen training matrix for the native-bundle family cache.

Not a holdout, large-program gate or agent benchmark. Attack entry is supplied.
Two normalization routes share the same symbolic grammar; they are not two
independent solvers. Failed/timed-out attacks cannot populate the cache.
"""
import argparse
import json
from pathlib import Path
import shutil
import statistics

from conformance.bundle_check import bundle_violations
from conformance.bundle_policy import CANDIDATES, canonical_hash, select
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.recovery import probe_summary
from conformance.run import ROOT, FIXTURES, image_identity, test_inputs, opt_command, target_offset


def fixture(kind):
    if kind == "affine":
        operations = [("add", "%a", "7"), ("add", "%b", "11"),
                      ("add", "%v0", "%b"), ("sub", "%v1", "%a"),
                      ("mul", "%v2", "3"), ("mul", "%v3", "5"),
                      ("sub", "%v4", "19"), ("add", "%v5", "23")]
        reduction = "add"
    elif kind == "xor":
        operations = [("xor", "%a", "7"), ("xor", "%b", "11"),
                      ("xor", "%v0", "%b"), ("xor", "%v1", "%a"),
                      ("xor", "%v2", "%a"), ("xor", "%v3", "%b"),
                      ("xor", "%v4", "19"), ("xor", "%v5", "23")]
        reduction = "xor"
    else: raise ValueError("unknown training fixture")
    return ('target triple = "x86_64-unknown-linux-gnu"\n'
            'define i32 @obf_target(i32 %a, i32 %b) noinline {\nentry:\n' +
            "".join(f"  %v{i} = {op} i32 {a}, {b}\n" for i, (op, a, b) in enumerate(operations)) +
            f"  %x = freeze i32 %v6\n  %y = freeze i32 %v7\n  %z = {reduction} i32 %x, %y\n  ret i32 %z\n}}\n")


def text_bytes(runner, binary):
    rows = runner.run(["llvm-size", "-A", str(binary)]).decode().splitlines()
    return next(int(row.split()[1]) for row in rows if row.split() and row.split()[0] == ".text")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--analysis-image", required=True)
    parser.add_argument("--seeds", nargs="+", type=int, default=[1])
    parser.add_argument("--seconds", type=int, default=20)
    args = parser.parse_args()
    if args.seconds <= 0 or len(set(args.seeds)) != len(args.seeds): parser.error("invalid bounds/seeds")
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"; shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    shape = {"width": 32, "lanes": 4, "nodes": 8, "pins": True}
    protocol = {"split": "training", "candidates": list(CANDIDATES),
                "attacks": ["binary-grammar", "llvm-o2-binary-grammar"],
                "limits": {"growth": 2, "runtime_ratio": 2, "compile_seconds": 600},
                "cases": [{"id": f"{kind}-{seed}", "seed": seed, "workload": kind, "shape": shape,
                           "source_sha256": canonical_hash(fixture(kind))}
                          for kind in ("affine", "xor") for seed in args.seeds],
                "probe_seconds": args.seconds, "plugin_sha256": digest(plugin),
                "toolchain": image_identity(args.toolchain_image), "analysis": image_identity(args.analysis_image),
                "timing_scope": "median of three trusted I/O batches including container startup",
                "size_scope": "whole executable .text including fixed driver",
                "attack_scope": "supplied entry; no native execution; two routes share a grammar"}
    # Freeze before any candidate compile or attack. No holdouts are consumed.
    dump(out / "protocol.json", protocol)
    evidence = {"schema": "sre-bundle-policy-evidence-v1", "protocol": protocol,
                "protocol_sha256": canonical_hash(protocol), "complete": False, "rows": []}
    dump(out / "evidence.json", evidence)
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0", "-native-late-constants=0",
             "-native-merge=0", "-native-values=1", "-native-values-wide=1", "-native-region-plan=connected",
             "-native-connected-nodes=2", "-native-functions=obf_target", "-native-plan=1",
             "-native-scale-budget=1", "-native-bundles=1", "-native-transfer-nodes=8",
             "-obf-deterministic", "-obf-verify"]
    driver = out / "driver.o"
    runner.run(["clang", "-O2", "-c", str(FIXTURES / "driver.c"), "-o", str(driver)])
    vectors = test_inputs(256)

    def build(ir, dest):
        link_map = dest.with_suffix(".map")
        runner.run(["clang", str(ir), str(driver), "-Wl,-Map=" + str(link_map), "-o", str(dest)])
        return link_map

    def measure(binary, expected):
        samples = []
        for _ in range(3):
            if runner.run([str(binary)], stdin=vectors) != expected: raise ToolFailure("policy output mismatch")
            samples.append(runner.records[-1]["seconds"])
        return statistics.median(samples)

    def attack(binary, link_map, dest):
        worker = Runner(ROOT, dest / "logs", args.analysis_image, mounts=(out,), timeout=args.seconds + 30)
        try:
            worker.run(["python3", str(ROOT / "conformance/recovery_probe.py"), "--binary", str(binary),
                        "--entry", hex(target_offset(link_map)), "--out", str(dest), "--seconds", str(args.seconds)])
            result = json.loads((dest / "result.json").read_text())
            if result.get("status") in ("recovered", "lifted_large"): result["summary"] = probe_summary(result)
        except ToolFailure as exc:
            result = {"status": "inconclusive", "reason": str(exc)}
        result["cost"] = {"mechanism_steps": result.get("steps"), "repair_steps": 0,
                          "repair_scope": "no pseudocode repairs; symbolic binary lift"}
        result["binary_sha256"] = digest(binary)
        return result

    try:
        for case in protocol["cases"]:
            dest = out / case["id"]; dest.mkdir()
            source = dest / "clean.ll"; source.write_text(fixture(case["workload"]))
            clean = dest / "clean"; build(source, clean)
            expected = runner.run([str(clean)], stdin=vectors)
            for route in protocol["attacks"]:
                normalized = route.startswith("llvm")
                control_ir = source
                if normalized:
                    control_ir = dest / "clean-o2.ll"
                    runner.run(["opt", "-passes=default<O2>,verify", "-S", str(source), "-o", str(control_ir)])
                control = dest / (route + "-control"); control_map = build(control_ir, control)
                control_time = measure(control, expected); control_size = text_bytes(runner, control)
                control_attack = attack(control, control_map, dest / (route + "-control-attack"))
                for name in CANDIDATES:
                    stem = dest / (route + "-" + name)
                    ir = stem.with_suffix(".ll"); report = stem.with_suffix(".json")
                    runner.run(opt_command(plugin) + flags + [f"-native-transfer-family={name}",
                        f"-obf-seed={case['seed']}", f"-native-report-json={report}", "-S", str(source), "-o", str(ir)])
                    compile_seconds = runner.records[-1]["seconds"]
                    data = json.loads(report.read_text()); errors = bundle_violations(data)
                    regions = [r for row in data["bundles"] for r in row.get("regions", [])]
                    if errors or len(regions) != 1 or regions[0]["useful_operations"] != 8 or regions[0]["lanes"] != 4:
                        raise ToolFailure("training shape/accounting mismatch: " + str(errors))
                    if normalized:
                        normalized_ir = stem.with_suffix(".o2.ll")
                        runner.run(["opt", "-passes=default<O2>,verify", "-S", str(ir), "-o", str(normalized_ir)])
                        compile_seconds += runner.records[-1]["seconds"]; ir = normalized_ir
                    binary = stem.with_suffix(".bin"); link_map = build(ir, binary)
                    compile_seconds += runner.records[-1]["seconds"]
                    runtime = measure(binary, expected)
                    row = {"case": case["id"], "candidate": name, "attack": route,
                           "correctness": True, "accounting": True, "control": control_attack,
                           "native": attack(binary, link_map, dest / (route + "-" + name + "-attack")),
                           "growth": text_bytes(runner, binary) / control_size,
                           "runtime_ratio": runtime / control_time, "compile_seconds": compile_seconds,
                           "report_sha256": digest(report), "output_sha256": canonical_hash(expected.decode())}
                    evidence["rows"].append(row); dump(out / "evidence.json", evidence)
                    print(case["id"], route, name, row["native"]["status"], flush=True)
        evidence["complete"] = True; dump(out / "evidence.json", evidence)
        selection = select(evidence); dump(out / "selection.json", selection)
        dump(out / "policy.json", {"schema": "sre-bundle-policy-v1", "evidence_sha256": digest(out / "evidence.json"),
                                   "rules": selection["rules"]})
    finally:
        dump(out / "commands.json", runner.records)


if __name__ == "__main__": main()
