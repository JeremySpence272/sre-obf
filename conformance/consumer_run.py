"""Trusted exact-consumer differential tests, with ordering and escape controls."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from conformance.process import Runner, digest, dump
from conformance.run import ROOT, opt_command


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--toolchain-image", default="sre-obf-dev:llvm22")
    p.add_argument("--plugin", type=Path, default=ROOT / "build/Obfuscator.so")
    args = p.parse_args(argv)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / "Obfuscator.so"
    before = digest(args.plugin)
    shutil.copyfile(args.plugin, plugin)
    if digest(plugin) != before:
        raise AssertionError("plugin changed while copying")
    run = Runner(ROOT, out / "logs", args.toolchain_image, timeout=180, mounts=(out,))
    source = ROOT / "conformance/fixtures/exact_consumer.c"
    ir, clean = out / "input.ll", out / "clean"
    run.run(["clang", "-O0", "-Xclang", "-disable-O0-optnone", "-emit-llvm", "-S", str(source), "-o", str(ir)])
    run.run(["clang", str(ir), "-o", str(clean)])
    expected = run.run([str(clean)])
    cases = []
    for seed in (1, 2, 3):
        protected, report, binary = (out / f"seed-{seed}{suffix}" for suffix in (".ll", ".json", ""))
        run.run(opt_command(plugin) + [
            "-passes=native-obfuscation", "-native-exact-consumers=1", "-native-level=smoke",
            "-native-passes=constenc", "-native-data=0", "-native-strings=0", "-native-merge=0",
            "-native-helper-hardening=0", "-native-late-constants=0", f"-obf-seed={seed}",
            f"-native-report-json={report}", "-S", str(ir), "-o", str(protected)])
        data = json.loads(report.read_text())["exact_consumers"]
        row = next((r for r in data if r["function"] == "exact"), None)
        if row is None or row["status"] != "integrated":
            raise AssertionError(f"missing exact consumer coverage: {data}")
        if row["byte_arrays_after"] != 0:
            raise AssertionError(f"fixture scratch arrays not eliminated: {row}")
        if any(r["function"] in ("ordering", "volatile_boundary") and r["status"] == "integrated" for r in data):
            raise AssertionError("unsupported comparison contract integrated")
        run.run(["clang", str(protected), "-o", str(binary)])
        if run.run([str(binary)]) != expected:
            raise AssertionError("exact equality or negative control changed")
        cases.append({"seed": seed, "status": "pass", "exact_consumers": data})
        dump(out / "summary.json", {"status": "running", "cases": cases})
    dump(out / "summary.json", {"status": "pass", "cases": cases, "plugin_sha256": before,
                                "source_sha256": digest(source),
                                "expected_output_sha256": hashlib.sha256(expected).hexdigest()})
    print("3 exact-consumer compiler seeds passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
