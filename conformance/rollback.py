"""Force body-budget rollback with global block addresses and recursive calls."""
import argparse
import json
from pathlib import Path

from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command, test_inputs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--toolchain-image")
    p.add_argument("--plugin", type=Path, default=ROOT / "build/Obfuscator.so")
    args = p.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = args.plugin.resolve(strict=True)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out, plugin.parent))
    plugin_hash = digest(plugin)
    fixture = FIXTURES / "computed_goto.ll"
    driver, clean = out / "driver.o", out / "clean"
    runner.run(["clang", "-O2", "-c", str(FIXTURES / "driver.c"), "-o", str(driver)])
    runner.run(["clang", str(fixture), str(driver), "-o", str(clean)])
    inputs = test_inputs(512)
    expected = runner.run([str(clean)], stdin=inputs)
    rows = []
    for seed in (1, 2, 3):
        source, rollbacks = fixture, 0
        for repeat in (0, 1):
            ir = out / f"seed-{seed}-{repeat}.ll"
            report = ir.with_suffix(".json")
            runner.run(opt_command(plugin) + ["-passes=obfuscation", f"-obf-seed={seed}",
                "-obf-deterministic", "-obf-verify", "-obf-ir-budget-multiplier=100",
                "-obf-ir-budget-max=32", f"-obf-report-json={report}",
                "-S", str(source), "-o", str(ir)])
            data = json.loads(report.read_text())
            count = sum(p.get("skip_reason") == "budget_rollback"
                        for f in data["functions"] for p in f["passes"])
            if not count:
                raise ToolFailure("regression did not exercise repeated rollback")
            source, rollbacks = ir, rollbacks + count
        table = next(line for line in ir.read_text().splitlines() if line.startswith("@targets ="))
        if table.count("blockaddress(@dispatch,") != 2 or "inttoptr" in table:
            raise ToolFailure("rollback corrupted global block addresses")
        for normalized in (False, True):
            source = ir
            if normalized:
                source = out / f"seed-{seed}-post-o2.ll"
                runner.run(["opt", "-passes=default<O2>,verify", "-S", str(ir), "-o", str(source)])
            binary = out / f"seed-{seed}-normalized-{int(normalized)}"
            runner.run(["clang", str(source), str(driver), "-o", str(binary)])
            if runner.run([str(binary)], stdin=inputs) != expected:
                raise ToolFailure("rollback full-output differential mismatch")
        rows.append({"seed": seed, "rollbacks": rollbacks, "correctness": True})
    if digest(plugin) != plugin_hash:
        raise ToolFailure("plugin changed during regression")
    dump(out / "summary.json", {"schema": "sre-rollback-v1", "cases": rows,
                               "plugin_sha256": plugin_hash})
    print("computed-goto rollback: pass", flush=True)


if __name__ == "__main__":
    main()
