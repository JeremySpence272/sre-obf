"""Build matched clean/native binaries from linked application IR, without LTO."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

from conformance.cc import backend_flags
from conformance import bundle_options
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, image_identity, opt_command

# Per-function IR growth budget for the generic passes. Named here, and echoed
# into every manifest, so that a later measurement can tell whether it was
# taken under the same budget rather than having to reconstruct it from a
# command line. The locked evaluation matrix pins the same two numbers.
IR_BUDGET_MULTIPLIER, IR_BUDGET_MAX = 50, 30000

EXPERIMENTS = ("fusion", "memory", "values", "values-wide", "coupled-state", "invariant", "outline",
               "memory-ssa", "predicate-regions", "regional-families", "support-regions", "scale-budget", "scale-structure",
               "connected-shards", "connected-aggregates", "joint-outputs", "encoded-calls",
               "call-policy", "plan")

# P6 useful data/control relation experiment. "stale-relation" is the
# canonical-repair arm: transitions are keyed on the live encoded-data word
# while the dispatcher keeps the previous three-word relation. It is an attack
# replay and is expected to break the program, not a protection mode.
LANE_TRANSITIONS = {"off": 0, "on": 1, "stale-relation": 2}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    bundle_options.add_options(p)
    p.add_argument("sources", type=Path, nargs="+")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--toolchain-image")
    p.add_argument("--plugin", type=Path, default=ROOT / "build/Obfuscator.so")
    p.add_argument("--profile", choices=("max", "smoke"), default="max")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--optimization", choices=("O0", "O2"), default="O2")
    p.add_argument("--closed-world", action="store_true",
                   help="explicit permission to internalize all definitions except exports and LLVM-preserved roots")
    p.add_argument("--export", action="append", default=[])
    p.add_argument("--cflag", action="append", default=[])
    p.add_argument("--link-flag", action="append", default=[])
    for name in EXPERIMENTS:
        p.add_argument("--" + name, action="store_true")
    p.add_argument("--lane-transitions", choices=tuple(LANE_TRANSITIONS), default="off",
                   help="P6: key dispatcher transitions on the live encoded-data word")
    p.add_argument("--no-merge", action="store_true",
                   help="disable bounded internal function merging; it runs first and absorbs the private "
                        "helpers a private-interface experiment targets")
    p.add_argument("--value-nodes", type=int, default=24)
    p.add_argument("--region-plan", choices=("legacy", "connected"), default="legacy")
    p.add_argument("--connected-nodes", type=int, default=128)
    p.add_argument("--semantic-budget", type=int, default=0,
                   help="percent of the component limit reserved for components owning encoded storage (0..50); 0 is the previous selection exactly")
    p.add_argument("--post-o2-attack", action="store_true")
    p.add_argument("--control-only", action="store_true", help="Build only the matched clean arm, including when a protected build cannot compile")
    p.add_argument("--no-disassembly", action="store_true", help="Skip full ELF disassembly for large scale-only runs; not a survival test")
    p.add_argument("--module-insts", type=int, default=250000)
    p.add_argument("--compile-timeout", type=float, default=180)
    return p


def build(args):
    bundle_options.validate(args, args.region_plan == "connected")
    out, plugin = args.out.resolve(), args.plugin.resolve()
    if out.exists():
        raise ValueError("output directory already exists; use a fresh path to preserve provenance")
    if not 0 <= args.seed < 2**64:
        raise ValueError("seed must be an unsigned 64-bit integer")
    if any(s.suffix != ".c" for s in args.sources):
        raise ValueError("whole-program driver currently accepts C sources only")
    if args.values_wide and not args.values:
        raise ValueError("--values-wide requires --values")
    if args.coupled_state and not args.values:
        raise ValueError("--coupled-state requires --values")
    if args.invariant and not args.coupled_state:
        raise ValueError("--invariant requires --coupled-state")
    if args.lane_transitions != "off" and not args.coupled_state:
        raise ValueError("--lane-transitions requires --coupled-state; the lane word is the value pass's context")
    if args.region_plan == "connected" and not (args.values and args.values_wide):
        raise ValueError("connected regions require --values --values-wide")
    if any((args.memory_ssa, args.predicate_regions, args.regional_families, args.support_regions,
            args.scale_budget, args.connected_shards, args.connected_aggregates,
            args.joint_outputs, args.encoded_calls, args.call_policy, args.plan)
           ) and args.region_plan != "connected":
        raise ValueError("connected subfeatures require --region-plan connected")
    if not 0 <= args.semantic_budget <= 50:
        raise ValueError("--semantic-budget must be 0..50")
    if args.semantic_budget and args.region_plan != "connected":
        raise ValueError("--semantic-budget requires --region-plan connected")
    if args.call_policy and not args.encoded_calls:
        raise ValueError("--call-policy requires --encoded-calls")
    if args.memory_ssa and not args.memory:
        raise ValueError("--memory-ssa requires --memory")
    if args.connected_aggregates and not args.memory_ssa:
        raise ValueError("--connected-aggregates requires --memory-ssa")
    if args.scale_structure and not args.scale_budget:
        raise ValueError("--scale-structure requires --scale-budget")
    if not 2 <= args.connected_nodes <= 512 or not 2 <= args.value_nodes <= 64:
        raise ValueError("connected-nodes must be 2..512; value-nodes must be 2..64")
    if args.control_only and args.post_o2_attack:
        raise ValueError("the post-O2 attack requires a protected arm")
    if not 10000 <= args.module_insts <= 5000000 or args.compile_timeout <= 0:
        raise ValueError("invalid explicit module/time budget")
    if any(f.startswith(("-O", "-flto", "-fpass-plugin", "-Xclang")) or f in ("-o", "-c", "-S", "-emit-llvm")
           for f in args.cflag):
        raise ValueError("use --optimization; custom pipeline/output flags are forbidden")
    if any(f.startswith(("-O", "-flto", "-fpass-plugin", "-Xclang")) or f in ("-o", "-c", "-S", "-emit-llvm")
           for f in args.link_flag):
        raise ValueError("link flags must not inject optimization or change the pipeline")
    sources = [s.resolve(strict=True) for s in args.sources]
    plugin_hash = digest(plugin)
    driver_hash = digest(Path(__file__))
    source_hashes = [{"path": str(s), "sha256": digest(s)} for s in sources]
    out.mkdir(parents=True)
    # Seal the actual compiler plugin for each build. A concurrent rebuild in
    # the development tree cannot change a running experiment's compiler.
    archived_plugin = out / "toolchain" / "Obfuscator.so"
    archived_plugin.parent.mkdir()
    shutil.copyfile(plugin, archived_plugin)
    if digest(archived_plugin) != plugin_hash:
        raise ToolFailure("plugin changed while snapshotting")
    plugin = archived_plugin
    runner = Runner(ROOT, out / "logs", args.toolchain_image, timeout=args.compile_timeout,
                    mounts=tuple({out, plugin.parent, *(s.parent for s in sources)}))
    flags = ["-std=c11", "-" + args.optimization, *args.cflag]
    if args.optimization == "O0":
        flags += ["-Xclang", "-disable-O0-optnone"]
    modules = []
    for index, source in enumerate(sources):
        module = out / f"tu-{index}.ll"
        runner.run(["clang", *flags, "-S", "-emit-llvm", str(source), "-o", str(module)])
        modules.append(module)
    linked = out / "linked.ll"
    runner.run(["llvm-link", "-S", *map(str, modules), "-o", str(linked)])
    prepared = linked
    if args.closed_world:
        prepared = out / "closed.ll"
        exports = sorted(set(["main", *args.export]))
        runner.run(["opt", "-passes=internalize", "-internalize-public-api-list=" + ",".join(exports),
                    "-S", str(linked), "-o", str(prepared)])
    protected = out / "protected.ll"
    feature_flags = bundle_options.flags(args) + [f"-native-{name}={int(getattr(args, name.replace('-', '_')))}" for name in EXPERIMENTS]
    feature_flags += [f"-native-region-plan={args.region_plan}", f"-native-connected-nodes={args.connected_nodes}",
                      f"-native-lane-transitions={LANE_TRANSITIONS[args.lane_transitions]}",
                      f"-native-merge={int(not args.no_merge)}",
                      f"-native-semantic-budget={args.semantic_budget}"]
    if not args.control_only:
        runner.run(opt_command(plugin) + ["-passes=native-obfuscation", f"-native-level={args.profile}",
                *feature_flags, f"-native-value-nodes={args.value_nodes}",
                f"-native-stage-dir={out / 'stages'}",
                f"-native-module-insts={args.module_insts}",
                f"-obf-seed={args.seed}", "-obf-deterministic", "-obf-verify",
                f"-obf-ir-budget-multiplier={IR_BUDGET_MULTIPLIER}",
                f"-obf-ir-budget-max={IR_BUDGET_MAX}",
                f"-native-report-json={out / 'native.json'}", f"-obf-report-json={out / 'passes.json'}",
                "-S", str(prepared), "-o", str(protected)])
    arms = {"clean": prepared}
    if not args.control_only:
        arms["native"] = protected
    if args.post_o2_attack:
        attack = out / "post-o2.ll"
        runner.run(["opt", "-passes=default<O2>", "-S", str(protected), "-o", str(attack)])
        arms["post-o2"] = attack
    hashes = {}
    for name, module in arms.items():
        obj, binary = out / f"{name}.o", out / name
        runner.run(["clang", *backend_flags(flags), "-Wno-override-module", "-c", str(module), "-o", str(obj)])
        runner.run(["clang", str(obj), *args.link_flag, "-o", str(binary)])
        if not args.no_disassembly:
            runner.run(["llvm-objdump", "-d", str(binary)])
        hashes[name] = {"binary_sha256": digest(binary), "ir_sha256": digest(module), "bytes": binary.stat().st_size}
    if digest(plugin) != plugin_hash:
        raise ToolFailure("plugin changed during build")
    result = {"schema": "sre-whole-ir-v1", "seed": args.seed, "profile": args.profile,
              "closed_world": args.closed_world, "exports": sorted(set(["main", *args.export])),
              "frontend_optimization": args.optimization, "backend_optimization": "O0",
              "preparation": "llvm-link; optional explicit internalization; fusion optionally promotes private scalars",
              "second_production_optimization": False, "features": [] if args.control_only else feature_flags,
              "control_only": args.control_only, "full_disassembly": not args.no_disassembly,
              "budgets": {"module_instruction_limit": args.module_insts,
                          "compile_timeout_seconds": args.compile_timeout,
                          "ir_budget_multiplier": IR_BUDGET_MULTIPLIER,
                          "ir_budget_max": IR_BUDGET_MAX,
                          "connected_nodes": args.connected_nodes, "value_nodes": args.value_nodes,
                          "scope": "every limit this build ran under, recorded as data; a "
                                   "measurement taken under different numbers is not comparable"},
              "module_instruction_limit": args.module_insts, "compile_timeout": args.compile_timeout,
              "sources": source_hashes,
              "plugin_sha256": plugin_hash, "plugin_archive": str(archived_plugin), "driver_sha256": driver_hash,
              "toolchain_image": image_identity(args.toolchain_image), "artifacts": hashes,
              "commands": runner.records}
    dump(out / "manifest.json", result)
    return result


def main(argv=None):
    try:
        build(parser().parse_args(argv))
        return 0
    except (OSError, ValueError, ToolFailure) as exc:
        print(f"sre-whole-ir: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
