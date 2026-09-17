"""Trusted duplicate-edge PHI regression; run inside the pinned toolchain."""
import argparse
from pathlib import Path

from .process import Runner, ToolFailure, digest, dump
from .run import ROOT, FIXTURES, opt_command, test_inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--wide", action="store_true")
    parser.add_argument("--invariant", action="store_true")
    parser.add_argument("--connected", action="store_true")
    parser.add_argument("--fixture", choices=("duplicate_edges", "nonentry_alloca"), default="duplicate_edges")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    runner = Runner(ROOT, out / "logs")
    plugin = ROOT / "build/Obfuscator.so"
    plugin_hash = digest(plugin)
    driver, control = out / "driver.o", out / "control"
    source = FIXTURES / (args.fixture + ".ll")
    runner.run(["clang", "-O2", "-c", str(FIXTURES / "driver.c"), "-o", str(driver)])
    runner.run(["clang", str(source), str(driver), "-o", str(control)])
    inputs = test_inputs(512)
    expected = runner.run([str(control)], stdin=inputs)
    rows = []
    for limit, flattening in ((2, False), (64, False), (64, True)):
        name = f"nodes-{limit}-flattening-{int(flattening)}"
        ir, binary = out / (name + ".ll"), out / name
        # Selecting a disabled fmerge leaves the ordinary function-pass list
        # empty, so the first two configurations isolate the value pass.
        command = opt_command(plugin) + ["-passes=native-obfuscation", "-obf-seed=11",
            "-obf-verify", "-obf-deterministic", "-native-level=smoke", "-native-values=1",
            f"-native-value-nodes={limit}", "-native-outline=0", "-native-merge=0",
            f"-native-values-wide={int(args.wide)}",
            f"-native-region-plan={'connected' if args.connected else 'legacy'}",
            f"-native-connected-nodes={limit}",
            f"-native-predicate-regions={int(args.connected)}",
            f"-native-regional-families={int(args.connected)}",
            f"-native-coupled-state={int(args.invariant and flattening)}",
            f"-native-invariant={int(args.invariant and flattening)}",
            "-native-strings=0", "-native-data=0", "-native-diversity=0",
            "-native-helper-hardening=0", "-native-late-constants=0",
            "-native-passes=" + ("flattening" if flattening else "fmerge"),
            "-obf-ir-budget-multiplier=50", "-obf-ir-budget-max=30000",
            "-S", str(source), "-o", str(ir)]
        runner.run(command)
        runner.run(["clang", str(ir), str(driver), "-o", str(binary)])
        if runner.run([str(binary)], stdin=inputs) != expected:
            raise ToolFailure("duplicate-edge differential mismatch")
        if digest(plugin) != plugin_hash:
            raise ToolFailure("plugin changed during run")
        rows.append({"case": name, "correctness": True, "binary_sha256": digest(binary)})
        dump(out / "summary.json", {"cases": rows, "plugin_sha256": plugin_hash})
        print(name + ": pass", flush=True)


if __name__ == "__main__":
    main()
