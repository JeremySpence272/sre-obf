"""Matched optimized-IR builds, full-output differential tests, and Ghidra probes."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys

from .metrics import CANARY, FOLDABLE, c_metrics, contains_integer, flattening_ran
from .process import Runner, ToolFailure, digest, dump

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "conformance" / "fixtures"
CASES = ("arithmetic", "data", "constructors", "literal", "foldable")


def test_inputs(count: int = 128) -> bytes:
    edges = (0, 1, 2, 7, 31, 32, 0x7fffffff, 0x80000000, 0xffffffff)
    values = [(x, y) for x in edges for y in edges]
    rng = random.Random(0x535245)
    values += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(count)]
    return "".join(f"{x} {y}\n" for x, y in values).encode()


def target_offset(link_map: Path, name: str = "obf_target") -> int:
    pattern = rf"^\s*(0x[0-9a-fA-F]+)\s+{re.escape(name)}\s*$"
    matches = re.findall(pattern, link_map.read_text(), re.M)
    if len(matches) != 1:
        raise ToolFailure(f"expected one {name} address in {link_map}")
    return int(matches[0], 16)


def image_identity(image: str | None) -> str | None:
    if image is None:
        return None
    return subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        text=True, timeout=15).strip()


def opt_command(plugin: Path) -> list[str]:
    # -load registers custom cl::opts before argument parsing; the new-PM
    # entrypoint is selected by -load-pass-plugin. dlopen reuses the same DSO.
    return ["opt", f"-load={plugin}", f"-load-pass-plugin={plugin}"]


def decompile(runner: Runner, binary: Path, link_map: Path, out: Path,
              args: argparse.Namespace) -> dict:
    if not args.ghidra_image and not args.ghidra:
        return {"status": "not_run", "reason": "Ghidra was not configured"}
    project = out.parent / ("project-" + out.stem)
    project.mkdir()
    headless = args.ghidra or "/opt/ghidra/support/analyzeHeadless"
    runner.run([headless, str(project), "conformance", "-import", str(binary),
                "-scriptPath", str(ROOT / "conformance" / "ghidra"),
                "-postScript", "ExportConformance.java", str(out),
                f"{target_offset(link_map):x}", "-deleteProject",
                "-analysisTimeoutPerFile", "120", "-max-cpu", "2"],
               image=args.ghidra_image, timeout=args.decompile_timeout)
    if not out.is_file():
        raise ToolFailure("Ghidra did not produce its export; inspect tool logs")
    result = json.loads(out.read_text())
    if result.get("status") == "ok":
        result["metrics"] = c_metrics(result["c"])
    return result


def compile_variant(runner: Runner, ir: Path, driver: Path, directory: Path) -> dict:
    directory.mkdir()
    obj, assembly = directory / "target.o", directory / "target.s"
    binary, link_map = directory / "binary", directory / "link.map"
    # Deliberately no second -O2. Both arms receive identical backend settings.
    runner.run(["clang", "-Wno-override-module", "-fPIE", "-S", str(ir),
                "-o", str(assembly)])
    runner.run(["clang", "-Wno-override-module", "-fPIE", "-c", str(ir),
                "-o", str(obj)])
    runner.run(["clang", "-pie", "-Wl,-s", f"-Wl,-Map={link_map}",
                str(obj), str(driver), "-o", str(binary)])
    relocations = runner.run(["llvm-readobj", "--relocations", str(obj)])
    (directory / "relocations.txt").write_bytes(relocations)
    disassembly = runner.run(["llvm-objdump", "-d", str(binary)])
    (directory / "disassembly.txt").write_bytes(disassembly)
    return {"binary": binary, "link_map": link_map, "assembly": assembly,
            "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
            "canary_in_binary": CANARY.to_bytes(4, "little") in binary.read_bytes(),
            "canary_in_assembly": contains_integer(assembly.read_text(), CANARY)}


def run_case(args: argparse.Namespace, name: str, seed: int, out: Path) -> dict:
    case = out / f"{name}-seed-{seed}"
    case.mkdir()
    runner = Runner(ROOT, case / "logs", args.toolchain_image, args.timeout)
    result = {"case": name, "seed": seed, "status": "incomplete",
              "profile": args.profile}
    try:
        source = FIXTURES / f"{name}.c"
        optimized, protected = case / "optimized.ll", case / "protected.ll"
        driver = case / "driver.o"
        runner.run(["clang", "-std=c11", "-O2", "-fPIE", "-ffp-contract=off",
                    "-fno-discard-value-names", "-S", "-emit-llvm", str(source),
                    "-o", str(optimized)])
        runner.run(["clang", "-std=c11", "-O2", "-fPIE", "-c",
                    str(FIXTURES / "driver.c"), "-o", str(driver)])
        report = case / "passes.json"
        ablation = [f"-native-passes={args.passes}"] if args.passes else []
        runner.run(opt_command(args.plugin) + ablation + [
            "-passes=native-obfuscation", f"-native-level={args.profile}",
            f"-obf-seed={seed}", "-obf-deterministic", "-obf-verify",
            "-obf-ir-budget-multiplier=50", "-obf-ir-budget-max=30000",
            f"-obf-report-json={report}", f"-native-report-json={case / 'native.json'}",
            "-S", str(optimized), "-o", str(protected)])
        result["source_sha256"] = digest(source)
        result["optimized_ir_sha256"] = digest(optimized)
        result["protected_ir_sha256"] = digest(protected)
        result["flattening_ran"] = flattening_ran(json.loads(report.read_text()))
        inputs = test_inputs(args.random_inputs)
        (case / "inputs.txt").write_bytes(inputs)
        outputs = {}
        arms = {}
        for arm, ir in (("control", optimized), ("native", protected)):
            variant = compile_variant(runner, ir, driver, case / arm)
            outputs[arm] = runner.run([str(variant["binary"])], stdin=inputs,
                                       timeout=args.run_timeout)
            (case / arm / "outputs.txt").write_bytes(outputs[arm])
            variant["decompiler"] = decompile(
                runner, variant["binary"], variant["link_map"],
                case / arm / "ghidra.json", args)
            arms[arm] = {key: str(value) if isinstance(value, Path) else value
                         for key, value in variant.items()}
        result["arms"] = arms
        result["vectors"] = len(inputs.splitlines())
        result["correctness"] = (
            outputs["control"] == outputs["native"] and
            len(outputs["control"].splitlines()) == result["vectors"])
        if not result["correctness"]:
            raise ToolFailure("full-output differential mismatch")
        result["flattening_required"] = name == "arithmetic" and (
            not args.passes or "flattening" in args.passes.split(","))
        if result["flattening_required"] and not result["flattening_ran"]:
            raise ToolFailure("required native flattening did not run")

        clean_dec, obf_dec = arms["control"]["decompiler"], arms["native"]["decompiler"]
        result["decompiler_status"] = (
            "ok" if clean_dec["status"] == obf_dec["status"] == "ok"
            else "not_run" if clean_dec["status"] == obf_dec["status"] == "not_run"
            else "decompiler_error")
        if name == "literal" and clean_dec["status"] == "ok":
            if not clean_dec["metrics"]["canary_recovered"]:
                raise ToolFailure("Ghidra positive recovery control failed")
        if name == "foldable":
            result["negative_control"] = not contains_integer(
                optimized.read_text(), FOLDABLE)
            if clean_dec["status"] == "ok":
                result["negative_control"] &= not contains_integer(
                    clean_dec["c"], FOLDABLE)
            if not result["negative_control"]:
                raise ToolFailure("foldable negative control did not simplify")

        # Narrow, declared contract: visible canary recovery. This does NOT
        # establish resistance to constructor evaluation, slicing, or SMT.
        if name in ("literal", "data"):
            result["literal_hiding"] = {
                "compiler": not arms["native"]["canary_in_assembly"],
                "decompiler": (not obf_dec["metrics"]["canary_recovered"]
                               if obf_dec["status"] == "ok" else None)}
        result["status"] = "pass" if result["decompiler_status"] == "ok" else "partial"
        if result["decompiler_status"] == "decompiler_error":
            result["status"] = "inconclusive"
    except (ToolFailure, OSError, ValueError, KeyError) as exc:
        result["status"] = "fail"
        result["error"] = str(exc)
    finally:
        dump(case / "result.json", result)
    return result


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--plugin", type=Path, default=ROOT / "build" / "Obfuscator.so")
    p.add_argument("--toolchain-image")
    p.add_argument("--ghidra-image")
    p.add_argument("--ghidra", help="Headless executable path (inside image if configured)")
    p.add_argument("--profile", choices=("max", "smoke"), default="max")
    p.add_argument("--passes", help="Explicit comma-separated native pass ablation")
    p.add_argument("--case", choices=CASES, action="append")
    p.add_argument("--seed", type=int, action="append")
    p.add_argument("--random-inputs", type=int, default=128)
    p.add_argument("--timeout", type=float, default=180)
    p.add_argument("--run-timeout", type=float, default=15)
    p.add_argument("--decompile-timeout", type=float, default=240)
    p.add_argument("--require-ghidra", action="store_true")
    p.add_argument("--require-literal-hiding", action="store_true")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    args.out, args.plugin = args.out.resolve(), args.plugin.resolve()
    if not args.plugin.is_file():
        raise SystemExit(f"build this fork first; plugin missing: {args.plugin}")
    if args.random_inputs < 0 or any(x <= 0 for x in (
            args.timeout, args.run_timeout, args.decompile_timeout)):
        raise SystemExit("counts/timeouts must be valid positive limits")
    if any(seed < 0 or seed >= 2**64 for seed in args.seed or [1]):
        raise SystemExit("seeds must fit unsigned 64-bit integers")
    if args.toolchain_image or args.ghidra_image:
        if not args.out.is_relative_to(ROOT) or not args.plugin.is_relative_to(ROOT):
            raise SystemExit("container runs require output/plugin inside this checkout")
    args.out.mkdir(parents=True, exist_ok=False)
    os.chmod(args.out, 0o700)
    tools = Runner(ROOT, args.out / "tool-identity", args.toolchain_image)
    metadata = {"schema": "sre-conformance-v1", "plugin_sha256": digest(args.plugin),
                "toolchain_image": image_identity(args.toolchain_image),
                "ghidra_image": image_identity(args.ghidra_image),
                "clang": tools.run(["clang", "--version"]).decode(),
                "opt": tools.run(["opt", "--version"]).decode(),
                "analysis_mode": "informed-entry", "cases": []}
    for name in args.case or CASES:
        for seed in args.seed or [1]:
            result = run_case(args, name, seed, args.out)
            metadata["cases"].append(result)
            print(f"{name} seed={seed}: {result['status']}", flush=True)
            dump(args.out / "summary.json", metadata)
    failed = any(case["status"] == "fail" for case in metadata["cases"])
    incomplete = any(case["status"] != "pass" for case in metadata["cases"])
    if args.require_literal_hiding:
        failed |= any(not all(case["literal_hiding"].values())
                      for case in metadata["cases"] if "literal_hiding" in case)
    metadata["status"] = "fail" if failed else "partial" if incomplete else "pass"
    dump(args.out / "summary.json", metadata)
    print(f"Report: {args.out / 'summary.json'}")
    return 1 if failed else 2 if incomplete and args.require_ghidra else 0


if __name__ == "__main__":
    sys.exit(main())
