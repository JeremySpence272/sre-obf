"""Compile and execute trusted runtime-state fixtures; no analyst automation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import hashlib

from conformance.process import Runner, ToolFailure, digest, dump
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
    plugin_hash = digest(args.plugin)
    shutil.copyfile(args.plugin, plugin)
    if digest(plugin) != plugin_hash:
        raise AssertionError("compiler plugin changed during snapshot")
    runner = Runner(ROOT, out / "logs", args.toolchain_image, timeout=180, mounts=(out,))
    source = ROOT / "conformance/fixtures/runtime_state.c"
    ir = out / "input.ll"
    runner.run(["clang", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
                str(source), "-o", str(ir)])
    clean = out / "clean"
    runner.run(["clang", str(ir), "-o", str(clean)])
    expected = runner.run([str(clean)])
    results = []
    for seed in (1, 2, 3):
        for phase in (False, True):
            for context in (None, 0, 0xffffffffffffffff):
                label = f"s{seed}-p{int(phase)}-c{context}"
                protected = out / (label + ".ll")
                report = out / (label + ".json")
                flags = ["-native-runtime-state=1", "-native-runtime-single-thread=1",
                         "-native-runtime-getters=1", "-native-runtime-buffers=1",
                         f"-native-runtime-phases={int(phase)}", "-native-runtime-growth=65536",
                         "-native-level=smoke", "-native-passes=constenc", "-native-data=0",
                         "-native-strings=0", "-native-merge=0", "-native-helper-hardening=0",
                         "-native-late-constants=0", f"-obf-seed={seed}",
                         f"-native-report-json={report}"]
                if context is not None:
                    flags.append(f"-native-runtime-test-seed={context}")
                runner.run(opt_command(plugin) + ["-passes=native-obfuscation",
                            *flags, "-S", str(ir), "-o", str(protected)])
                data = json.loads(report.read_text())["runtime_state"]
                if data["status"] != "encoded":
                    raise AssertionError(f"{label}: zero runtime coverage: {data}")
                owned = {r["object"]: r for r in data["objects"] if r["status"] == "encoded"}
                if owned.get("buffer", {}).get("cells") != 32 or owned.get("words", {}).get("cells") != 8:
                    raise AssertionError(f"{label}: persistent buffer coverage missing: {owned}")
                if "escaped_buffer" in owned:
                    raise AssertionError("escaped buffer incorrectly admitted")
                binary = out / label
                runner.run(["clang", str(protected), "-o", str(binary)])
                for repeat in range(3 if context is None else 1):
                    if runner.run([str(binary)]) != expected:
                        raise AssertionError(f"{label}: differential mismatch on process {repeat}")
                if data["scalar_exit_uses"] < 1:
                    raise AssertionError("fixture division boundary disappeared from the report")
                if data["complete_chain_claim"]:
                    raise AssertionError("partial fixture incorrectly claims full continuity")
                results.append({"case": label, "status": "pass", "runtime_state": data})
                dump(out / "summary.json", {"status": "running", "cases": results})
    controls = []
    for name, flag, wanted in (
            ("rollback", "-native-runtime-test-rollback=1", "rolled-back"),
            ("reservation", "-native-runtime-growth=1", "no-eligible-storage")):
        protected, report, binary = (out / (name + suffix) for suffix in (".ll", ".json", ""))
        control_flags = [v for v in flags if not v.startswith(("-native-runtime-growth=", "-native-report-json="))]
        control_flags += [flag, f"-native-report-json={report}"]
        runner.run(opt_command(plugin) + ["-passes=native-obfuscation",
                    *control_flags, "-S", str(ir), "-o", str(protected)])
        data = json.loads(report.read_text())["runtime_state"]
        if data["status"] != wanted:
            raise AssertionError(f"{name}: unexpected state {data}")
        code = protected.read_text()
        if "__sre_runtime_init" in code or ".runtime.mask" in code:
            raise AssertionError(f"{name}: orphaned runtime support after rejection")
        runner.run(["clang", str(protected), "-o", str(binary)])
        if runner.run([str(binary)]) != expected:
            raise AssertionError(f"{name}: rejected transaction changed semantics")
        controls.append({"case": name, "status": "pass"})
    wrapper = out / "entropy_failure.c"
    wrapper.write_text("#include <stddef.h>\nint __wrap_getentropy(void *p, size_t n) { (void)p; (void)n; return -1; }\n")
    binary = out / "entropy-failure"
    runner.run(["clang", str(out / "s1-p0-cNone.ll"), str(wrapper),
                "-Wl,--wrap=getentropy", "-o", str(binary)])
    try:
        runner.run(["sh", "-c", 'ulimit -c 0; exec "$1"', "sre-test", str(binary)])
    except ToolFailure:
        if runner.records[-1].get("returncode") != 78:
            raise AssertionError("entropy failure did not terminate explicitly")
    else:
        raise AssertionError("entropy failure silently continued")
    controls.append({"case": "entropy-failure", "status": "pass"})
    dump(out / "summary.json", {"status": "pass", "cases": results, "controls": controls,
                                "plugin_sha256": plugin_hash, "source_sha256": digest(source),
                                "expected_output_sha256": hashlib.sha256(expected).hexdigest()})
    print(f"{len(results)} compiler/runtime-context combinations passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
