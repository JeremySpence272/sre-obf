"""Focused annotated-pass checks: no other obfuscation can hide a broken flag.

Run inside the pinned toolchain image. Trusted execution is for correctness.
This is a structural regression, not an agent or solver-resistance benchmark.
"""
import argparse
import re
from pathlib import Path

from .process import Runner, digest, dump
from .run import ROOT, FIXTURES, opt_command, test_inputs


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    runner = Runner(ROOT, out / "logs")
    plugin = ROOT / "build/Obfuscator.so"
    plugin_hash = digest(plugin)
    inputs = test_inputs(512)
    driver = out / "driver.o"
    runner.run(["clang", "-O2", "-c", str(FIXTURES / "driver.c"), "-o", str(driver)])
    expected = None
    rows = []
    for multi, family in ((0, 3), (1, 0), (1, 1), (1, 2)):
        for hybrid in (0, 1):
            case = out / f"multi-{multi}-family-{family}-hybrid-{hybrid}"
            case.mkdir()
            spec = (f"flattening(minBlocks=2,maxBlocks=500,multiState={multi},"
                    f"stateFamily={family},hybrid={hybrid},opaqueState=0,"
                    "fakeTransitions=0,perDispatcherDomain=0,"
                    "obfuscateStatePtr=0,opaqueAliasStatePtr=0)")
            optimized, protected = case / "optimized.ll", case / "protected.ll"
            runner.run(["clang", "-O2", "-fPIE", "-fno-discard-value-names",
                        f'-DFLA_SPEC="{spec}"', "-S", "-emit-llvm",
                        str(FIXTURES / "cff_flags.c"), "-o", str(optimized)])
            if expected is None:
                clean = out / "control"
                runner.run(["clang", str(optimized), str(driver), "-o", str(clean)])
                expected = runner.run([str(clean)], stdin=inputs)
                require(len(expected.splitlines()) == 593, "control output count")
            require(digest(plugin) == plugin_hash, "plugin changed during run")
            runner.run(opt_command(plugin) + ["-passes=obfuscation", "-obf-seed=11",
                        "-obf-deterministic", "-obf-verify", "-S", str(optimized),
                        "-o", str(protected)])
            ir = protected.read_text()
            dispatchers = len(re.findall(r"^fla\.dispatch\.\d+:", ir, re.M))
            require(dispatchers == 1 if not hybrid else dispatchers > 1,
                    "hybrid dispatcher count did not change")
            require(("fla.multi.key = alloca i32" in ir) == bool(multi),
                    "multi-state storage does not match configuration")
            if multi:
                require("fla.multi.match" in ir, "encoded comparisons missing")
            binary = case / "binary"
            runner.run(["clang", str(protected), str(driver), "-o", str(binary)])
            require(runner.run([str(binary)], stdin=inputs) == expected,
                    "full-output differential mismatch")
            require(digest(plugin) == plugin_hash, "plugin changed during run")
            rows.append({"multi": multi, "family": family, "hybrid": hybrid,
                         "dispatchers": dispatchers, "correctness": True,
                         "protected_ir_sha256": digest(protected)})
            dump(out / "summary.json", {"cases": rows, "plugin_sha256": plugin_hash})
            print(case.name + ": pass", flush=True)


if __name__ == "__main__":
    main()
