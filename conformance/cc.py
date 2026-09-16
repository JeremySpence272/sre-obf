#!/usr/bin/env python3
"""C-only compiler adapter for the standalone crackme harness; fail closed."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, opt_command, image_identity

PAIRED = {"-I", "-isystem", "-iquote", "-include", "-imacros", "-D", "-U",
          "-target", "--target", "-MF", "-MT", "-MQ", "-isysroot", "--sysroot"}


def compile_args(args: list[str]) -> tuple[Path, Path, list[str]]:
    flags, sources = [], []
    output = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in PAIRED or arg == "-o":
            if i + 1 == len(args):
                raise ValueError(f"{arg} requires an argument")
            if arg == "-o":
                output = Path(args[i + 1]).resolve()
            else:
                flags.extend(args[i:i + 2])
            i += 2
            continue
        if arg == "-c":
            i += 1
            continue
        if not arg.startswith("-") and Path(arg).suffix in (".c", ".cc", ".cpp", ".cxx"):
            sources.append(Path(arg).resolve())
        else:
            flags.append(arg)
        i += 1
    if len(sources) != 1 or sources[0].suffix != ".c" or output is None:
        raise ValueError("adapter requires one C source, -c, and an explicit -o")
    if any(flag.startswith(("-flto", "-fpass-plugin")) or flag == "-Xclang"
           for flag in flags):
        raise ValueError("LTO and injected frontend passes are outside this pipeline")
    levels = [flag for flag in flags if flag.startswith("-O")]
    if levels and levels[-1] not in ("-O0", "-O2"):
        raise ValueError("native adapter supports explicit -O0 or -O2 input")
    if not levels:
        flags.append("-O2")
    if levels and levels[-1] == "-O0":
        # Suppress only the attribute that blocks explicit transformation passes.
        # This does not run an optimization pipeline. Apply to BOTH paired arms.
        flags.extend(["-Xclang", "-disable-O0-optnone"])
    return sources[0], output, flags


def backend_flags(flags: list[str]) -> list[str]:
    out, i = [], 0
    while i < len(flags):
        flag = flags[i]
        if flag in ("-target", "--target", "-isysroot", "--sysroot"):
            out.extend(flags[i:i + 2])
            i += 2
            continue
        if flag.startswith(("-m", "--target=", "--sysroot=")) or flag in (
                "-fPIE", "-fpie", "-fPIC", "-fpic", "-pthread"):
            out.append(flag)
        i += 1
    return out


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    image = os.environ.get("SRE_OBF_TOOLCHAIN_IMAGE") or None
    plugin = Path(os.environ.get("SRE_OBF_PLUGIN", ROOT / "build/Obfuscator.so")).resolve()
    profile = os.environ.get("SRE_OBF_PROFILE", "max")
    seed = int(os.environ.get("SRE_OBF_SEED", "1"))
    multistate = os.environ.get("SRE_OBF_MULTISTATE", "1")
    if multistate not in ("0", "1"):
        raise ValueError("SRE_OBF_MULTISTATE must be 0 or 1")
    values = os.environ.get("SRE_OBF_VALUES", "0")
    outline = os.environ.get("SRE_OBF_OUTLINE", "0")
    coupled = os.environ.get("SRE_OBF_COUPLED_STATE", "0")
    if values not in ("0", "1") or outline not in ("0", "1"):
        raise ValueError("SRE_OBF_VALUES and SRE_OBF_OUTLINE must be 0 or 1")
    if coupled not in ("0", "1") or (coupled == "1" and (values != "1" or multistate != "1")):
        raise ValueError("SRE_OBF_COUPLED_STATE requires enabled values and multistate")
    if profile not in ("max", "smoke", "none") or not 0 <= seed < 2**64:
        raise ValueError("invalid SRE_OBF_PROFILE or SRE_OBF_SEED")
    if args == ["--version"]:
        command = ["clang", "--version"]
        if image:
            command = ["docker", "run", "--rm", "--network", "none",
                       "--entrypoint", "clang", image, "--version"]
        return subprocess.call(command)
    if not plugin.is_file() and profile != "none":
        raise ValueError(f"modified plugin is missing: {plugin}")

    if "-c" not in args:
        if any(not arg.startswith("-") and Path(arg).suffix in
               (".c", ".cc", ".cpp", ".cxx") for arg in args):
            raise ValueError("combined compile/link is unsupported; use separate -c commands")
        if "-o" not in args:
            raise ValueError("link requires an explicit -o")
        output = Path(args[args.index("-o") + 1]).resolve()
        work = Path(tempfile.mkdtemp(prefix=".sre-link-", dir=output.parent))
        mounts = tuple({Path(arg).resolve().parent for arg in args
                        if not arg.startswith("-") and Path(arg).is_file()} |
                       {output.parent})
        runner = Runner(Path.cwd(), work / "logs", image, mounts=mounts)
        runner.run(["clang", *args])
        dump(Path(str(output) + ".sre.json"), {
            "schema": "sre-native-link-v1", "output_sha256": digest(output),
            "toolchain_image": image_identity(image),
            "commands": runner.records})
        return 0

    source, output, flags = compile_args(args)
    work = Path(tempfile.mkdtemp(prefix=f".{output.name}.sre-", dir=output.parent))
    runner = Runner(Path.cwd(), work / "logs", image,
                    mounts=(source.parent, output.parent, plugin.parent))
    optimized, protected = work / "optimized.ll", work / "protected.ll"
    runner.run(["clang", *flags, "-S", "-emit-llvm", str(source), "-o", str(optimized)])
    if profile == "none":
        protected = optimized
    else:
        runner.run(opt_command(plugin) + [
            "-passes=native-obfuscation", f"-native-level={profile}",
            f"-native-multistate={multistate}",
            f"-native-values={values}", f"-native-outline={outline}",
            f"-native-coupled-state={coupled}",
            f"-obf-seed={seed}", "-obf-deterministic", "-obf-verify",
            "-obf-ir-budget-multiplier=50", "-obf-ir-budget-max=30000",
            f"-obf-report-json={work / 'passes.json'}",
            f"-native-report-json={work / 'native.json'}",
            "-S", str(optimized), "-o", str(protected)])
    runner.run(["clang", *backend_flags(flags), "-Wno-override-module",
                "-c", str(protected), "-o", str(output)])
    dump(Path(str(output) + ".sre.json"), {
        "schema": "sre-native-object-v1", "profile": profile, "seed": seed,
        "frontend_optimization": [f for f in flags if f.startswith("-O")][-1],
        "backend_optimization": "-O0 (clang default)",
        "disable_o0_optnone": "-disable-O0-optnone" in flags,
        "multistate": multistate == "1" if profile != "none" else False,
        "values": values == "1" if profile != "none" else False,
        "outline": outline == "1" if profile != "none" else False,
        "coupled_state": coupled == "1" if profile != "none" else False,
        "toolchain_image": image_identity(image),
        "adapter_sha256": digest(Path(__file__)),
        "plugin_sha256": digest(plugin) if profile != "none" else None,
        "source_sha256": digest(source), "optimized_ir_sha256": digest(optimized),
        "protected_ir_sha256": digest(protected), "output_sha256": digest(output),
        "work": str(work), "commands": runner.records})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, ToolFailure) as exc:
        print(f"sre-native-cc: {exc}", file=sys.stderr)
        sys.exit(2)
