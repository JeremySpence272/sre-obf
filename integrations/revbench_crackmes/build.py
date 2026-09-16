#!/usr/bin/env python3
"""Build and install a fresh matched O0/static/stripped crackme pair into Revbench.

Uses the existing standalone C crackme generator; private data is never printed.
Both destination cells must be absent. All builds and checks precede publication.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import secrets
import shlex
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FORK = HERE.parents[1]
CELLS = {"none": "c-noopt-nosym-static", "max": "c-noopt-nosym-static-sre-obf-max"}
CFLAGS = "-std=c11 -O0 -g0 -Wall -Wextra -Werror -fno-pie"
LDFLAGS = "-static -no-pie -s -Wl,--build-id=none"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def elf_properties(binary):
    headers = subprocess.check_output(["readelf", "-hW", str(binary)], text=True)
    program = subprocess.check_output(["readelf", "-lW", str(binary)], text=True)
    sections = subprocess.check_output(["readelf", "-SW", str(binary)], text=True)
    dynamic = subprocess.check_output(["readelf", "-dW", str(binary)], text=True)
    if not ("ELF64" in headers and "EXEC" in headers and "X86-64" in headers):
        raise RuntimeError("expected a non-PIE Linux x86-64 ELF64 executable")
    if "INTERP" in program or "(NEEDED)" in dynamic:
        raise RuntimeError("target is not fully statically linked")
    if any(name in sections for name in (".symtab", ".debug_", ".zdebug_")):
        raise RuntimeError("target is not stripped")
    return {"elf64_x86_64": True, "static": True, "pie": False,
            "stripped": True, "debug_sections": False}


def inspect_build(case, profile):
    metadata = json.loads((case / "private/build.json").read_text())
    reports = []
    for name in ("main.o.sre.json", "check.o.sre.json"):
        unit = metadata["compiler_sidecars"][name]
        if unit["frontend_optimization"] != "-O0" or not unit["disable_o0_optnone"]:
            raise RuntimeError("no-opt frontend contract was not honored")
        if unit["profile"] != profile:
            raise RuntimeError("wrong obfuscation profile")
        # Input and object compilation may NOT silently invoke another -O level.
        for record in unit["commands"]:
            if any(arg.startswith("-O") and arg != "-O0" for arg in record["command"]):
                raise RuntimeError("unexpected compiler optimization level")
        if profile != "none":
            reports.append(json.loads((Path(unit["work"]) / "native.json").read_text()))
    if profile != "none":
        states = [s for r in reports for s in r["flattening_state"]]
        # Fail if no real three-word CFF survives; flag selection is not coverage.
        if not any(s.get("words", 0) >= 3 for s in states):
            raise RuntimeError("no final multi-state flattening found in protected target")
        if any(r["vm"] or r["injected_assembly"] for r in reports):
            raise RuntimeError("unexpected VM or injected assembly")
    return metadata, reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revbench", required=True, type=Path)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--toolchain-image", default="sre-obf-dev:llvm22")
    parser.add_argument("--obf-seed", type=int, default=1)
    parser.add_argument("--instance-file", type=Path,
                        help="private instance.json from a prior build; otherwise fresh random seed")
    args = parser.parse_args()
    root, source, out = args.revbench.resolve(), args.harness.resolve(), args.out.resolve()
    family = root / "binaries/crackmes"
    if not (root / "harness/crackmes.py").is_file():
        raise SystemExit("install the Revbench integration first")
    for cell in CELLS.values():
        if (family / cell).exists():
            raise SystemExit(f"refusing to replace existing cell: {cell}")
    if not 0 <= args.obf_seed < 2**64:
        raise SystemExit("obf seed must be uint64")
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    spec = importlib.util.spec_from_file_location("standalone_crackme_builder", source / "harness.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    seed = (json.loads(args.instance_file.read_text())["seed"] if args.instance_file
            else secrets.token_hex(32))
    instance = builder.make_instance(seed)
    if args.instance_file and json.loads(args.instance_file.read_text()) != instance:
        raise RuntimeError("inconsistent private instance file")
    plugin = FORK / "build/Obfuscator.so"
    plugin_hash = digest(plugin)
    environ = {
        "SRE_OBF_TOOLCHAIN_IMAGE": args.toolchain_image, "SRE_OBF_PLUGIN": str(plugin),
        "SRE_OBF_SEED": str(args.obf_seed), "SRE_OBF_MULTISTATE": "1",
        "SRE_OBF_VALUES": "1", "SRE_OBF_OUTLINE": "1", "SRE_OBF_COUPLED_STATE": "1",
    }
    previous_env = os.environ.copy()
    builds, native_reports = {}, {}
    try:
        os.environ.update(environ)
        for profile, cell in CELLS.items():
            os.environ["SRE_OBF_PROFILE"] = profile
            print(f"Building {cell} ...", flush=True)
            builder.build(argparse.Namespace(
                out=out / profile, seed=seed, variant=cell,
                cc=shlex.join([sys.executable, str(FORK / "conformance/cc.py")]),
                cflags=CFLAGS, ldflags=LDFLAGS, build_timeout=600, check_timeout=10))
            builds[profile], native_reports[profile] = inspect_build(out / profile, profile)
    finally:
        os.environ.clear()
        os.environ.update(previous_env)
    if digest(plugin) != plugin_hash:
        raise RuntimeError("plugin changed during the paired build")
    # Both source/header and untransformed IR must match (ignore source-path lines).
    left, right = builds["none"], builds["max"]
    if left["source_sha256"] != right["source_sha256"] or \
            left["instance_header_sha256"] != right["instance_header_sha256"]:
        raise RuntimeError("paired source or instance mismatch")
    for name in ("main.o.sre.json", "check.o.sre.json"):
        units = [b["compiler_sidecars"][name] for b in (left, right)]
        def ir(unit):
            return "\n".join(line for line in
                (Path(unit["work"]) / "optimized.ll").read_text().splitlines()
                if not line.startswith(("; ModuleID =", "source_filename =")))
        if ir(units[0]) != ir(units[1]):
            raise RuntimeError("paired frontend IR differs beyond source path")
        if units[0]["toolchain_image"] != units[1]["toolchain_image"]:
            raise RuntimeError("paired toolchains differ")
    targets = [out / profile / "public/binary" for profile in CELLS]
    properties = [elf_properties(target) for target in targets]
    if digest(targets[0]) == digest(targets[1]):
        raise RuntimeError("obfuscated binary is identical to control")
    # Trusted differential testing, independent from the static-only agent task.
    password = instance["password"].encode("ascii")
    candidates = [password] + [b"A" * n for n in (0, 1, 7, 9, 64)]
    for i in range(8):
        for bit in range(7):
            changed = bytearray(password)
            changed[i] ^= 1 << bit
            if 0 not in changed:
                candidates.append(bytes(changed))
    rng = random.Random(91827)
    candidates += [bytes(rng.randrange(1, 128) for _ in range(8)) for _ in range(256)]
    for candidate in candidates:
        expected = ((0, b"Access granted!\n", b"") if candidate == password
                    else (1, b"Access denied.\n", b""))
        for target in targets:
            run = subprocess.run([os.fsencode(target), candidate], capture_output=True, timeout=10)
            if (run.returncode, run.stdout, run.stderr) != expected:
                raise RuntimeError("paired differential correctness failure")
    stage = out / "family"
    stage.mkdir()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=FORK, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=FORK, text=True).splitlines()
    for index, (profile, cell) in enumerate(CELLS.items()):
        destination = stage / cell
        destination.mkdir()
        private = destination / "eval"
        private.mkdir(mode=0o700)
        shutil.copytree(out / profile / "private", private / "build")
        (private / "flag.txt").write_bytes(password)
        (private / "submission").mkdir()
        (private / "submission/flag.txt").write_bytes(password)
        shutil.copy2(targets[index], destination / "binary")
        shutil.copyfile(HERE / "prompt.md", destination / "prompt.md")
        manifest = {
            "schema": "revbench-crackmes-build-v1", "cell": cell, "profile": profile,
            "binary_sha256": digest(targets[index]), "binary_bytes": targets[index].stat().st_size,
            "prompt_sha256": digest(destination / "prompt.md"), "elf": properties[index],
            "frontend_optimization": "-O0", "backend_optimization": "-O0 (clang default)",
            "disable_o0_optnone": True, "cflags": CFLAGS, "ldflags": LDFLAGS,
            "libc": "prebuilt toolchain static libc; identical in both arms; not obfuscated",
            "fork_commit": commit, "fork_status": dirty, "plugin_sha256": plugin_hash,
            "adapter_sha256": digest(FORK / "conformance/cc.py"),
            "generator_sha256": digest(source / "harness.py"),
            "builder_sha256": digest(Path(__file__)),
            "obfuscation_environment": {**environ, "SRE_OBF_PROFILE": profile},
            "source_sha256": builds[profile]["source_sha256"],
            "semantic_checks_per_binary": builds[profile]["semantic_checks"],
            "differential_cases_per_binary": len(candidates),
            "matched_frontend_ir": True, "native_reports": native_reports[profile],
        }
        dump(private / "build-manifest.json", manifest)
        shutil.copyfile(source / "harness.py", private / "generator.py")
        # JSON is a YAML subset; no additional builder dependency is required.
        config = {
            "name": "crackmes-" + cell, "type": "crackmes",
            "description": "Authorized synthetic static-only password recovery; exact-match 0/1 scoring.",
            "source": "Owner-authored standalone C crackme / sre-obf development control",
            "language": "c", "variant": cell.removeprefix("c-"),
            "binary": {"file": "binary", "format": "elf64", "arch": "x86_64"},
            "evaluation": "crackmes_exact", "analysis_protocol": "static-recovery-v2",
            "submission": {"file": "flag.txt", "format": "eight ASCII bytes; optional single LF",
                           "max_score": 1},
            "tools": {name: "tools/" + name for name in
                      ("pyghidra", "radare2", "angr", "binutils", "z3")},
            "build": {"binary_sha256": manifest["binary_sha256"], "optimization": "-O0",
                      "static": True, "stripped": True, "obfuscation": profile,
                      "native_values": profile != "none", "native_outline": profile != "none",
                      "native_multistate": profile != "none", "native_coupled_state": profile != "none",
                      "private_manifest": "eval/build-manifest.json"},
        }
        dump(destination / "config.yaml", config)
        if password in (destination / "binary").read_bytes() or \
                password in (destination / "prompt.md").read_bytes():
            raise RuntimeError("plaintext answer leaked into public assets")
    family.mkdir(parents=True, exist_ok=True)
    # Single rename per complete cell, on the destination filesystem. Refuse any
    # raced-in destination; an operator can retain an older family untouched.
    import tempfile
    with tempfile.TemporaryDirectory(prefix=".crackmes-stage-", dir=family.parent) as temporary:
        for cell in CELLS.values():
            shutil.copytree(stage / cell, Path(temporary) / cell)
        for cell in CELLS.values():
            if (family / cell).exists():
                raise RuntimeError("destination appeared during build; refusing overwrite")
        for cell in CELLS.values():
            (Path(temporary) / cell).rename(family / cell)
    shutil.copyfile(HERE / "README.md", family / "README.md")
    print(json.dumps({"installed": list(CELLS.values()), "differential_cases": len(candidates),
                      "binary_sha256": [digest(t) for t in targets]}, indent=2))


if __name__ == "__main__":
    main()
