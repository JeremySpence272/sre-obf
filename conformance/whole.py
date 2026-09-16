"""Build matched clean/native binaries from linked application IR, without LTO."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from conformance.cc import backend_flags
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, image_identity, opt_command

EXPERIMENTS = ("fusion", "memory", "values", "values-wide", "coupled-state", "invariant", "outline")


def parser():
    p = argparse.ArgumentParser(description=__doc__)
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
    p.add_argument("--value-nodes", type=int, default=24)
    p.add_argument("--post-o2-attack", action="store_true")
    return p


def build(args):
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
    if any(f.startswith(("-O", "-flto", "-fpass-plugin", "-Xclang")) or f in ("-o", "-c", "-S", "-emit-llvm")
           for f in args.cflag):
        raise ValueError("use --optimization; custom pipeline/output flags are forbidden")
    if any(f.startswith(("-O", "-flto", "-fpass-plugin", "-Xclang")) or f in ("-o", "-c", "-S", "-emit-llvm")
           for f in args.link_flag):
        raise ValueError("link flags must not inject optimization or change the pipeline")
    sources = [s.resolve(strict=True) for s in args.sources]
    plugin_hash = digest(plugin)
    out.mkdir(parents=True)
    runner = Runner(ROOT, out / "logs", args.toolchain_image,
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
    feature_flags = [f"-native-{name}={int(getattr(args, name.replace('-', '_')))}" for name in EXPERIMENTS]
    runner.run(opt_command(plugin) + ["-passes=native-obfuscation", f"-native-level={args.profile}",
                *feature_flags, f"-native-value-nodes={args.value_nodes}",
                f"-obf-seed={args.seed}", "-obf-deterministic", "-obf-verify",
                "-obf-ir-budget-multiplier=50", "-obf-ir-budget-max=30000",
                f"-native-report-json={out / 'native.json'}", f"-obf-report-json={out / 'passes.json'}",
                "-S", str(prepared), "-o", str(protected)])
    arms = {"clean": prepared, "native": protected}
    if args.post_o2_attack:
        attack = out / "post-o2.ll"
        runner.run(["opt", "-passes=default<O2>", "-S", str(protected), "-o", str(attack)])
        arms["post-o2"] = attack
    hashes = {}
    for name, module in arms.items():
        obj, binary = out / f"{name}.o", out / name
        runner.run(["clang", *backend_flags(flags), "-Wno-override-module", "-c", str(module), "-o", str(obj)])
        runner.run(["clang", str(obj), *args.link_flag, "-o", str(binary)])
        runner.run(["llvm-objdump", "-d", str(binary)])
        hashes[name] = {"binary_sha256": digest(binary), "ir_sha256": digest(module), "bytes": binary.stat().st_size}
    if digest(plugin) != plugin_hash:
        raise ToolFailure("plugin changed during build")
    result = {"schema": "sre-whole-ir-v1", "seed": args.seed, "profile": args.profile,
              "closed_world": args.closed_world, "exports": sorted(set(["main", *args.export])),
              "frontend_optimization": args.optimization, "backend_optimization": "O0",
              "preparation": "llvm-link; optional explicit internalization; fusion optionally promotes private scalars",
              "second_production_optimization": False, "features": feature_flags,
              "sources": [{"path": str(s), "sha256": digest(s)} for s in sources],
              "plugin_sha256": plugin_hash, "driver_sha256": digest(Path(__file__)),
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
