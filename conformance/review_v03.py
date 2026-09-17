"""IR-level v03 compiler regressions with archived plugins and full outputs."""
import argparse
import json
from pathlib import Path
import shutil

from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command, test_inputs
from conformance.connected_check import report_violations


def check_report(name, report):
    violations = report_violations(report)
    if violations:
        raise ToolFailure("; ".join(violations))
    if name == "encoded_call_musttail":
        for function, reason in (("tail_helper", "musttail-body"), ("never_returns", "no-return"),
                                 ("returns_again", "returns-twice"), ("calls_twice", "returns-twice")):
            row = next(row for row in report["encoded_calls"] if row["function"] == function)
            if row["status"] != "skipped" or row["reason"] != reason:
                raise ToolFailure(f"encoded-call pass failed to exclude {function}: {reason}")
    elif name == "encoded_call_accounting":
        row = next(row for row in report["encoded_calls"] if row["function"] == "mixed")
        if row.get("encoded_function") == "mixed.sre.encoded" or not row.get("encoded_function"):
            raise ToolFailure("interface report lost the uniquified callee name")
        if (row["absorbed_arguments"], row["partially_absorbed_arguments"], row["absorbed_results"]) != (1, 1, 1):
            raise ToolFailure("partial or renamed interface absorption was misreported")
    else:
        row = next(row for row in report["connected_regions"] if row["function"] == "obf_target")
        if row["status"] != "encoded" or not row["shards"] or row["shard_lost_nodes"] < 64:
            raise ToolFailure("regression did not exercise an oversized atomic memory unit")
        if row["memory_edges"] or row["eligible_memory_edges"] != 65:
            raise ToolFailure("oversized memory object was partly encoded or its eligibility was lost")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--toolchain-image")
    p.add_argument("--plugin", type=Path, default=ROOT / "build/Obfuscator.so")
    p.add_argument("--case", choices=("encoded_call_musttail", "encoded_call_accounting", "shard_atomic"),
                   action="append")
    args = p.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    shutil.copyfile(args.plugin.resolve(strict=True), plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,))
    result = {"schema": "sre-v03-review-v1", "plugin_sha256": digest(plugin),
              "passed": False, "cases": []}
    try:
        driver = out / "driver.o"
        runner.run(["clang", "-O2", "-c", str(FIXTURES / "driver.c"), "-o", str(driver)])
        inputs = test_inputs(512)
        flags = ["-passes=native-obfuscation", "-native-level=smoke",
            "-native-passes=constenc", "-native-merge=0", "-native-strings=0",
            "-native-data=0", "-native-helper-hardening=0", "-native-late-constants=0",
            "-native-values=1", "-native-values-wide=1", "-native-region-plan=connected",
            "-native-connected-nodes=512", "-obf-deterministic", "-obf-verify"]
        for name in args.case or ("encoded_call_musttail", "encoded_call_accounting", "shard_atomic"):
            fixture = FIXTURES / (name + ".ll")
            case = out / name
            case.mkdir()
            archived_fixture = case / "input.ll"
            shutil.copyfile(fixture, archived_fixture)
            fixture = archived_fixture
            clean = case / "clean"
            runner.run(["clang", str(fixture), str(driver), "-o", str(clean)])
            expected = runner.run([str(clean)], stdin=inputs)
            if len(expected.splitlines()) != 593:
                raise ToolFailure("clean control did not produce 593 outputs")
            for seed in (1, 3):
                ir, report = case / f"seed-{seed}.ll", case / f"seed-{seed}.json"
                features = (["-native-memory=1", "-native-memory-ssa=1", "-native-connected-shards=1"]
                            if name == "shard_atomic" else ["-native-encoded-calls=1"])
                runner.run(opt_command(plugin) + flags + features + [f"-obf-seed={seed}",
                    f"-native-report-json={report}", "-S", str(fixture), "-o", str(ir)])
                check_report(name, json.loads(report.read_text()))
                for normalized in (False, True):
                    source = ir
                    if normalized:
                        source = case / f"seed-{seed}-post-o2.ll"
                        runner.run(["opt", "-passes=default<O2>,verify", "-S", str(ir), "-o", str(source)])
                    native = source.with_suffix(".bin")
                    runner.run(["clang", str(source), str(driver), "-o", str(native)])
                    if runner.run([str(native)], stdin=inputs) != expected:
                        raise ToolFailure(f"{name}: full-output differential mismatch")
                result["cases"].append({"fixture": name, "fixture_sha256": digest(fixture), "seed": seed,
                                        "vectors": 593, "passed": True})
        result["passed"] = True
    except ToolFailure as exc:
        result["error"] = str(exc)
    finally:
        result["commands"] = runner.records
        dump(out / "summary.json", result)
    print(json.dumps({key: result[key] for key in ("passed", "cases")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
