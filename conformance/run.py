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
from . import bundle_options

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "conformance" / "fixtures"
# encoded_calls is deliberately not a case here: its fixture keeps ten private
# definitions alive, and this driver always disassembles every arm, which
# exceeds the 16 MiB tool-output limit. conformance/whole.py drives it instead.
CASES = ("arithmetic", "data", "widths", "constructors", "merging", "strings",
         "literal", "foldable", "state", "values", "wide")

# P6 useful data/control relation experiment; see conformance/whole.py.
LANE_TRANSITIONS = {"off": 0, "on": 1, "stale-relation": 2}


# Required persistent-value widths. Both planners must cover all four.
VALUE_WIDTHS = frozenset({8, 16, 32, 64})
# Each planner publishes its own evidence rows: the legacy planner writes
# "values", the connected planner writes "connected_regions". Only one of them
# runs, so the gate must read the one the compiler recorded as active.
VALUE_EVIDENCE = {"legacy": "values", "connected": "connected_regions"}


def check_value_coverage(native_report: dict) -> None:
    """Require the four persistent-value widths from whichever planner ran.

    Raises ToolFailure naming what is missing. Extra widths are extra coverage,
    not a violation: the connected planner also encodes i1 branch predicates,
    while the legacy planner only ever selects the four required widths.
    """
    plan = native_report["features"]["region_plan"]
    if plan not in VALUE_EVIDENCE:
        raise ToolFailure(f"region plan {plan!r} publishes no persistent-value evidence")
    encoded = [row for row in native_report[VALUE_EVIDENCE[plan]]
               if row["status"] == "encoded"]
    if not encoded:
        raise ToolFailure(f"the {plan} planner encoded no persistent values")
    if any("widths" not in row or "phi_pairs" not in row for row in encoded):
        raise ToolFailure(f"the {plan} planner did not report encoded widths")
    missing = VALUE_WIDTHS - {w for row in encoded for w in row["widths"]}
    if missing:
        raise ToolFailure("persistent-value width coverage is incomplete: missing "
                          + ", ".join(str(w) for w in sorted(missing)))
    if not any(row["phi_pairs"] and row["persistent_edges"] for row in encoded):
        raise ToolFailure("persistent-value loop/join coverage is missing")


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


def feature_flags(args: argparse.Namespace) -> list[str]:
    return bundle_options.flags(args) + [f"-native-diversity={int(not args.no_diversity)}",
            f"-native-data={int(not args.no_data)}",
            f"-native-helper-hardening={int(not args.no_helpers)}",
            f"-native-late-constants={int(not args.no_late)}",
            f"-native-strings={int(not args.no_strings)}",
            f"-native-merge={int(not args.no_merge)}",
            f"-native-multistate={int(not args.no_multistate)}",
            f"-native-state-family={args.state_family}",
            f"-native-values={int(args.values)}",
            f"-native-outline={int(args.outline)}",
            f"-native-value-nodes={args.value_nodes}",
            f"-native-coupled-state={int(args.coupled_state)}",
            f"-native-fusion={int(getattr(args, 'fusion', False))}",
            f"-native-memory={int(getattr(args, 'memory', False))}",
            f"-native-values-wide={int(getattr(args, 'values_wide', False))}",
            f"-native-invariant={int(getattr(args, 'invariant', False))}",
            f"-native-region-plan={getattr(args, 'region_plan', 'legacy')}",
            f"-native-connected-nodes={getattr(args, 'connected_nodes', 128)}",
            *(f"-native-{name.replace('_', '-')}={int(getattr(args, name, False))}"
              for name in ("memory_ssa", "predicate_regions", "regional_families", "support_regions", "scale_budget",
                           "scale_structure", "connected_shards", "connected_aggregates",
                           "joint_outputs", "encoded_calls", "call_policy", "plan")),
            f"-native-semantic-budget={getattr(args, 'semantic_budget', 0)}",
            f"-native-lane-transitions={LANE_TRANSITIONS[getattr(args, 'lane_transitions', 'off')]}",
            f"-native-family={args.family}"]


def decompile(runner: Runner, binary: Path, link_map: Path, out: Path,
              args: argparse.Namespace, offset: int | None = None) -> dict:
    if not args.ghidra_image and not args.ghidra:
        return {"status": "not_run", "reason": "Ghidra was not configured"}
    project = out.parent / ("project-" + out.stem)
    project.mkdir()
    headless = args.ghidra or "/opt/ghidra/support/analyzeHeadless"
    runner.run([headless, str(project), "conformance", "-import", str(binary),
                "-scriptPath", str(ROOT / "conformance" / "ghidra"),
                "-postScript", "ExportConformance.java", str(out),
                f"{target_offset(link_map) if offset is None else offset:x}", "-deleteProject",
                "-analysisTimeoutPerFile", "120", "-max-cpu", "2"],
               image=args.ghidra_image, timeout=args.decompile_timeout)
    if not out.is_file():
        raise ToolFailure("Ghidra did not produce its export; inspect tool logs")
    result = json.loads(out.read_text())
    if result.get("status") == "ok":
        result["metrics"] = c_metrics(result["c"])
    return result


def compile_variant(runner: Runner, ir: Path, driver: Path, directory: Path,
                    threaded: bool = False) -> dict:
    directory.mkdir()
    obj, assembly = directory / "target.o", directory / "target.s"
    binary, link_map = directory / "binary", directory / "link.map"
    # Deliberately no second -O2. Both arms receive identical backend settings.
    # The release arm is an ordinary source -O2 compile, not another IR arm.
    optimization = ["-std=c11", "-O2", "-ffp-contract=off"] if ir.suffix == ".c" else []
    runner.run(["clang", *optimization, "-Wno-override-module", "-fPIE", "-S", str(ir),
                "-o", str(assembly)])
    # Preserve assembler-local function labels in the PRIVATE intermediate so
    # informed probes can locate private LLVM helpers. Final --strip-all still
    # removes them from the attacker binary.
    runner.run(["clang", *optimization, "-Wno-override-module", "-fPIE", "-Wa,-L", "-c", str(ir),
                "-o", str(obj)])
    unstripped = directory / "binary.unstripped"
    runner.run(["clang", *(["-pthread"] if threaded else []), "-pie", "-Wl,--discard-none",
                f"-Wl,-Map={link_map}",
                str(obj), str(driver), "-o", str(unstripped)])
    symbols = runner.run(["llvm-nm", "--defined-only", "-n", str(unstripped)])
    (directory / "symbols.txt").write_bytes(symbols)
    runner.run(["llvm-strip", "--strip-all", "-o", str(binary), str(unstripped)])
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
              "threads": 4 if args.threads else 1,
              "profile": args.profile, "passes": args.passes,
              "feature_flags": feature_flags(args)}
    try:
        if digest(args.plugin) != args.plugin_sha256:
            raise ToolFailure("plugin changed during this run; start a new artifact set")
        source = FIXTURES / f"{name}.c"
        optimized, protected = case / "optimized.ll", case / "protected.ll"
        driver = case / "driver.o"
        runner.run(["clang", "-std=c11", "-O2", "-fPIE", "-ffp-contract=off",
                    "-fno-discard-value-names", "-S", "-emit-llvm", str(source),
                    "-o", str(optimized)])
        driver_source = FIXTURES / ("driver_threads.c" if args.threads else "driver.c")
        runner.run(["clang", *(["-pthread"] if args.threads else []),
                    "-std=c11", "-O2", "-fPIE", "-c",
                    str(driver_source), "-o", str(driver)])
        result["driver_sha256"] = digest(driver_source)
        report = case / "passes.json"
        ablation = [f"-native-passes={args.passes}"] if args.passes else []
        runner.run(opt_command(args.plugin) + ablation + feature_flags(args) + [
            "-passes=native-obfuscation", f"-native-level={args.profile}",
            f"-obf-seed={seed}", "-obf-deterministic", "-obf-verify",
            "-obf-ir-budget-multiplier=50", "-obf-ir-budget-max=30000",
            f"-obf-report-json={report}", f"-native-report-json={case / 'native.json'}",
            "-S", str(optimized), "-o", str(protected)])
        if digest(args.plugin) != args.plugin_sha256:
            raise ToolFailure("plugin changed during transformation")
        result["source_sha256"] = digest(source)
        result["optimized_ir_sha256"] = digest(optimized)
        result["protected_ir_sha256"] = digest(protected)
        result["flattening_ran"] = flattening_ran(json.loads(report.read_text()), "obf_target")
        native_report = json.loads((case / "native.json").read_text())
        result["feature_coverage"] = native_report
        if result["flattening_ran"] and not args.no_multistate:
            state = next((item for item in native_report["flattening_state"]
                          if item["function"] == "obf_target"), None)
            if not state or state["words"] != 3:
                raise ToolFailure("target flattening lost required multi-state storage")
            if args.coupled_state and name == "values" and not (
                    state["coupled_data_updates"] and state["coupled_control_updates"]):
                raise ToolFailure("required data/control coupling did not survive")
        enabled_pass = lambda name: not args.passes or name in args.passes.split(",")
        if name == "values" and args.values:
            check_value_coverage(native_report)
        if name == "values" and args.outline:
            outlined = [v for v in native_report["outlined_regions"] if v["status"] == "outlined"]
            if not outlined:
                raise ToolFailure("required pure-region outlining did not run")
            if not any(v["outputs"] >= 2 for v in outlined):
                raise ToolFailure("required multi-output outlined region is missing")
        if name == "merging" and not args.no_merge and enabled_pass("fmerge"):
            groups = native_report["merged_groups"]
            if not groups:
                raise ToolFailure("required function merging did not run")
            if enabled_pass("flattening") and not all(
                    flattening_ran(json.loads(report.read_text()), group["function"])
                    for group in groups):
                raise ToolFailure("a merged application group was not flattened")
        if name in ("data", "widths") and not args.no_data:
            encoded = [entry for entry in native_report["data"]
                       if entry["status"] == "encoded"]
            if not encoded:
                raise ToolFailure("required array encoding did not run")
            if name == "widths" and {entry["width"] for entry in encoded} != {8, 16, 32, 64}:
                raise ToolFailure("required array widths were not all encoded")
            if not args.no_helpers and any(entry["status"] != "processed"
                                           for entry in native_report["helpers"]):
                raise ToolFailure("required generated helper was not processed")
        inputs = test_inputs(args.random_inputs)
        (case / "inputs.txt").write_bytes(inputs)
        outputs = {}
        arms = {}
        variants = [("release", source), ("control", optimized), ("native", protected)]
        if args.post_o2_attack:
            # Deliberate normalization attack, not a change to the production
            # after-O2 pipeline. Stock LLVM gets the entire protected module.
            reoptimized = case / "post-o2.ll"
            runner.run(["opt", "-passes=default<O2>", "-S", str(protected),
                        "-o", str(reoptimized)])
            variants.append(("post_o2", reoptimized))
            result["post_o2_ir_sha256"] = digest(reoptimized)
        for arm, ir in variants:
            variant = compile_variant(runner, ir, driver, case / arm, args.threads)
            outputs[arm] = runner.run([str(variant["binary"])], stdin=inputs,
                                       timeout=args.run_timeout)
            variant["execution_seconds"] = runner.records[-1]["seconds"]
            variant["execution_timing_scope"] = "trusted batch, includes container/process startup"
            (case / arm / "outputs.txt").write_bytes(outputs[arm])
            variant["decompiler"] = {"status": "not_run",
                                      "reason": "execution gates run before analysis"}
            arms[arm] = {key: str(value) if isinstance(value, Path) else value
                         for key, value in variant.items()}
        result["arms"] = arms
        result["vectors"] = len(inputs.splitlines())
        result["correctness"] = (all(value == outputs["release"] for value in outputs.values())
                                 and len(outputs["release"].splitlines()) == result["vectors"])
        if not result["correctness"]:
            raise ToolFailure("full-output differential mismatch")
        if name == "strings" and not args.no_strings and enabled_pass("strenc"):
            canary = b"cobalt-kinetic-conformance"
            if canary in Path(arms["native"]["binary"]).read_bytes():
                raise ToolFailure("required string encoding left the plaintext probe")
            if not native_report["helpers"]:
                raise ToolFailure("string runtime is missing from helper inventory")
        result["flattening_required"] = name in ("arithmetic", "state") and (
            not args.passes or "flattening" in args.passes.split(","))
        if result["flattening_required"] and not result["flattening_ran"]:
            raise ToolFailure("required native flattening did not run")
        for arm in (["control", "native", "post_o2"] if args.post_o2_attack
                    else ["control", "native"]):
            arms[arm]["decompiler"] = decompile(
                runner, Path(arms[arm]["binary"]), Path(arms[arm]["link_map"]),
                case / arm / "ghidra.json", args)
        if args.probe_helpers:
            symbols = {}
            for line in (case / "native/symbols.txt").read_text().splitlines():
                fields = line.split()
                if len(fields) == 3 and fields[1].lower() == "t":
                    symbols[fields[2]] = int(fields[0], 16)
                    if fields[2].startswith(".L"):
                        symbols.setdefault(fields[2][2:], int(fields[0], 16))
            probes, seen_roles = [], set()
            for helper in native_report["helpers"]:
                if len(probes) >= args.probe_helpers:
                    break
                helper_name, role = helper["function"], helper["role"]
                if role in seen_roles or helper_name not in symbols:
                    continue
                seen_roles.add(role)
                exported = decompile(runner, Path(arms["native"]["binary"]),
                    Path(arms["native"]["link_map"]),
                    case / "native" / f"helper-{len(probes)}.json", args, symbols[helper_name])
                probes.append({"function": helper_name, "role": role, "decompiler": exported})
            if native_report["helpers"] and not probes:
                raise ToolFailure("requested helper probes found no helper entry symbols")
            result["helper_probes"] = probes

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
        if args.post_o2_attack and arms["post_o2"]["decompiler"]["status"] not in ("ok", "not_run"):
            result["status"] = "inconclusive"
        if any(probe["decompiler"]["status"] != "ok"
               for probe in result.get("helper_probes", [])):
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
    p.add_argument("--no-diversity", action="store_true")
    p.add_argument("--no-data", action="store_true")
    p.add_argument("--no-helpers", action="store_true")
    p.add_argument("--no-late", action="store_true")
    p.add_argument("--no-strings", action="store_true")
    p.add_argument("--no-merge", action="store_true")
    p.add_argument("--no-multistate", action="store_true")
    p.add_argument("--state-family", type=int, choices=(0, 1, 2, 3), default=3)
    p.add_argument("--values", action="store_true")
    p.add_argument("--outline", action="store_true")
    p.add_argument("--value-nodes", type=int, default=24)
    p.add_argument("--coupled-state", action="store_true")
    p.add_argument("--fusion", action="store_true")
    p.add_argument("--memory", action="store_true")
    p.add_argument("--values-wide", action="store_true")
    p.add_argument("--invariant", action="store_true")
    p.add_argument("--region-plan", choices=("legacy", "connected"), default="legacy")
    p.add_argument("--connected-nodes", type=int, default=128)
    for name in ("memory-ssa", "predicate-regions", "regional-families", "support-regions", "scale-budget",
                 "scale-structure", "connected-shards", "connected-aggregates",
                 "joint-outputs", "encoded-calls", "call-policy", "plan"):
        p.add_argument("--" + name, action="store_true")
    p.add_argument("--semantic-budget", type=int, default=0)
    bundle_options.add_options(p)
    p.add_argument("--lane-transitions", choices=tuple(LANE_TRANSITIONS), default="off",
                   help="P6: key dispatcher transitions on the live encoded-data word")
    p.add_argument("--family", type=int, choices=(-1, 0, 1, 2, 3), default=-1)
    p.add_argument("--probe-helpers", type=int, default=0,
                   help="Informed-entry probes for up to N distinct helper roles")
    p.add_argument("--case", choices=CASES, action="append")
    p.add_argument("--seed", type=int, action="append")
    p.add_argument("--random-inputs", type=int, default=128)
    p.add_argument("--threads", action="store_true",
                   help="Run each binary with four concurrent callers (max 4096 vectors)")
    p.add_argument("--post-o2-attack", action="store_true",
                   help="Also normalize protected IR with stock O2, compile, compare and decompile")
    p.add_argument("--timeout", type=float, default=180)
    p.add_argument("--run-timeout", type=float, default=15)
    p.add_argument("--decompile-timeout", type=float, default=240)
    p.add_argument("--require-ghidra", action="store_true")
    p.add_argument("--require-literal-hiding", action="store_true")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        bundle_options.validate(args, args.region_plan == "connected")
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    args.out, args.plugin = args.out.resolve(), args.plugin.resolve()
    if not args.plugin.is_file():
        raise SystemExit(f"build this fork first; plugin missing: {args.plugin}")
    if args.random_inputs < 0 or any(x <= 0 for x in (
            args.timeout, args.run_timeout, args.decompile_timeout)):
        raise SystemExit("counts/timeouts must be valid positive limits")
    if args.threads and args.random_inputs + 81 > 4096:
        raise SystemExit("--threads supports at most 4096 total vectors")
    if not 2 <= args.value_nodes <= 64:
        raise SystemExit("--value-nodes must be 2..64")
    if not 2 <= args.connected_nodes <= 512:
        raise SystemExit("--connected-nodes must be 2..512")
    if args.region_plan == "connected" and not (args.values and args.values_wide):
        raise SystemExit("connected regions require --values --values-wide")
    if (any((args.memory_ssa, args.predicate_regions, args.regional_families, args.support_regions,
             args.scale_budget, args.connected_shards, args.connected_aggregates, args.joint_outputs,
             args.encoded_calls, args.call_policy, args.plan, args.semantic_budget))
            or args.lane_transitions != "off") and args.region_plan != "connected":
        raise SystemExit("connected subfeatures require --region-plan connected")
    if args.call_policy and not args.encoded_calls:
        raise SystemExit("--call-policy requires --encoded-calls")
    if not 0 <= args.semantic_budget <= 50:
        raise SystemExit("--semantic-budget must be 0..50")
    if args.memory_ssa and not args.memory:
        raise SystemExit("--memory-ssa requires --memory")
    if args.connected_aggregates and not args.memory_ssa:
        raise SystemExit("--connected-aggregates requires --memory-ssa")
    if args.scale_structure and not args.scale_budget:
        raise SystemExit("--scale-structure requires --scale-budget")
    if args.coupled_state and (not args.values or args.no_multistate):
        raise SystemExit("--coupled-state requires --values and multi-state flattening")
    if args.lane_transitions != "off" and not args.coupled_state:
        raise SystemExit("--lane-transitions requires --coupled-state; the lane word is the value pass's context")
    if not 0 <= args.probe_helpers <= 8:
        raise SystemExit("--probe-helpers must be between 0 and 8")
    if any(seed < 0 or seed >= 2**64 for seed in args.seed or [1]):
        raise SystemExit("seeds must fit unsigned 64-bit integers")
    if args.require_literal_hiding and not set(args.case or CASES) & {"literal", "data"}:
        raise SystemExit("--require-literal-hiding requires a literal or data probe")
    if args.toolchain_image or args.ghidra_image:
        if not args.out.is_relative_to(ROOT) or not args.plugin.is_relative_to(ROOT):
            raise SystemExit("container runs require output/plugin inside this checkout")
    args.out.mkdir(parents=True, exist_ok=False)
    os.chmod(args.out, 0o700)
    tools = Runner(ROOT, args.out / "tool-identity", args.toolchain_image)
    args.plugin_sha256 = digest(args.plugin)
    metadata = {"schema": "sre-conformance-v1", "plugin_sha256": args.plugin_sha256,
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
