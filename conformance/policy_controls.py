"""Compiler cache plumbing tests. Synthetic policies are NOT attack evidence."""
import argparse
import copy
import json
from pathlib import Path
import shutil

from conformance.connected_check import report_violations
from conformance.policy_run import fixture
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command, test_inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    args = parser.parse_args()
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    plugin = out / "Obfuscator.so"; shutil.copy2(ROOT / "build/Obfuscator.so", plugin)
    source = out / "source.ll"; source.write_text(fixture("affine"))
    driver = out / "driver.o"
    runner.run(["clang", "-O2", "-c", str(FIXTURES / "driver.c"), "-o", str(driver)])
    flags = ["-passes=native-obfuscation", "-native-level=smoke", "-native-passes=constenc",
             "-native-strings=0", "-native-data=0", "-native-helper-hardening=0", "-native-late-constants=0",
             "-native-merge=0", "-native-values=1", "-native-values-wide=1", "-native-region-plan=connected",
             "-native-connected-nodes=2", "-native-functions=obf_target", "-native-plan=1",
             "-native-scale-budget=1", "-native-bundles=1", "-native-transfer-nodes=8",
             "-obf-deterministic", "-obf-seed=4", "-obf-verify"]
    shape = {"width": 32, "lanes": 4, "nodes": 8, "pins": True}
    base = {"schema": "sre-bundle-policy-v1", "evidence_sha256": "0" * 64,
            "rules": [{"shape": shape, "candidates": ["additive"]}]}
    policies = {"off": None, "matched": base, "empty": {**base, "rules": []},
                "unmeasured": {**base, "rules": [{"shape": {**shape, "width": 64}, "candidates": ["xor"]}]},
                "ties": {**base, "rules": [{"shape": shape, "candidates": ["xor", "additive"]}]},
                "ties-reordered": {**base, "rules": [{"shape": shape, "candidates": ["additive", "xor"]}]}}
    summary = {"schema": "sre-bundle-policy-controls-v1", "plugin_sha256": digest(plugin),
               "passed": False, "cases": [], "hardness_evaluated": False}
    inputs = test_inputs(256)
    runner.run(["clang", str(source), str(driver), "-o", str(out / "clean")])
    expected = runner.run([str(out / "clean")], stdin=inputs)
    try:
        for name, policy in policies.items():
            extra = []
            if policy is not None:
                path = out / (name + "-policy.json"); dump(path, policy)
                extra = [f"-native-bundle-policy={path}"]
            ir, report = out / (name + ".ll"), out / (name + ".json")
            cmd = opt_command(plugin) + flags + extra + [f"-native-report-json={report}", "-S", str(source), "-o", str(ir)]
            runner.run(cmd)
            hashes = digest(ir), digest(report)
            runner.run(cmd)
            if hashes != (digest(ir), digest(report)): raise ToolFailure("nondeterministic policy")
            data = json.loads(report.read_text())
            if report_violations(data): raise ToolFailure("invalid bundle accounting")
            region = next(r for row in data["bundles"] for r in row["regions"])
            if policy is not None:
                matched = name in ("matched", "ties", "ties-reordered")
                if (region["selection"]["status"] == "matched") != matched: raise ToolFailure("incorrect policy match")
                if data["bundle_policy"]["sha256"] != digest(path): raise ToolFailure("policy digest mismatch")
            if name == "matched" and "additive" not in region["family"]: raise ToolFailure("candidate not selected")
            for normalized in (False, True):
                selected = ir
                if normalized:
                    selected = out / (name + "-o2.ll")
                    runner.run(["opt", "-passes=default<O2>,verify", "-S", str(ir), "-o", str(selected)])
                binary = selected.with_suffix(".bin")
                runner.run(["clang", str(selected), str(driver), "-o", str(binary)])
                if runner.run([str(binary)], stdin=inputs) != expected: raise ToolFailure("policy differential mismatch")
            summary["cases"].append({"case": name, "passed": True, "post_o2": True, "deterministic": True})
        for name in ("empty", "unmeasured"):
            if (out / (name + ".ll")).read_bytes() != (out / "off.ll").read_bytes():
                raise ToolFailure("fallback changed IR")
        if (out / "ties.ll").read_bytes() != (out / "ties-reordered.ll").read_bytes():
            raise ToolFailure("JSON order changed tied selection")
        invalid = []
        for field, value in (("width", 7), ("nodes", 33), ("pins", 1), ("function", "target")):
            p = copy.deepcopy(base); p["rules"][0]["shape"][field] = value; invalid.append(p)
        for field, value in (("schema", "future"), ("evidence_sha256", "bad")):
            invalid.append({**base, field: value})
        for candidates in ([], ["unknown"], ["xor", "xor"]):
            p = copy.deepcopy(base); p["rules"][0]["candidates"] = candidates; invalid.append(p)
        invalid += [{**base, "rules": base["rules"] * 2}, {**base, "rules": base["rules"] * 129}]
        for i, policy in enumerate(invalid):
            path = out / f"invalid-{i}.json"; dump(path, policy)
            try:
                runner.run(opt_command(plugin) + flags + [f"-native-bundle-policy={path}", "-disable-output", str(source)])
            except ToolFailure:
                err = Path(runner.records[-1]["stderr"]).read_text()
                if "native bundle policy:" not in err: raise
            else: raise ToolFailure("invalid policy accepted")
        summary.update(passed=True, malformed_rejections=len(invalid), fallback_ir_identical=True,
                       tie_order_independent=True)
    finally:
        dump(out / "summary.json", summary); dump(out / "commands.json", runner.records)


if __name__ == "__main__": main()
