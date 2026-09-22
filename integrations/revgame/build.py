"""Build matched O0, stripped, static-PIE RevGame C binaries with v04 or experimental v05."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from conformance.process import ToolFailure, digest, dump
from conformance.whole import build as whole_build, parser as whole_parser

V4_OPTIONS = [
    "--fusion", "--memory", "--values", "--values-wide", "--coupled-state",
    "--invariant", "--region-plan", "connected", "--connected-nodes", "256",
    "--memory-ssa", "--predicate-regions", "--regional-families",
    "--support-regions", "--connected-shards", "--connected-aggregates",
    "--joint-outputs", "--encoded-calls", "--lane-transitions", "on",
    "--bundles", "--bundle-loops", "--bundle-phases", "--bundle-loop-boundaries",
    "--object-bundles", "--object-phases", "--object-max-cells", "8",
    "--object-calls", "--immutable-bundles", "--continuity-priority",
    "--bundle-call-inputs", "--bundle-call-outputs", "--joint-call-arguments",
    "--bundle-control", "--bundle-predicates", "--call-policy",
    "--self-recursion", "--plan", "--scale-budget", "--scale-structure",
    "--semantic-budget", "25",
]
V5_OPTIONS = ["--runtime-state", "--runtime-single-thread", "--runtime-phases", "--runtime-getters",
              "--exact-consumers", "--runtime-buffers", "--selective-interpreter"]


def prepare(source: Path, out: Path) -> tuple[Path, list[Path]]:
    """Copy source inputs, then run the game's own deterministic generators."""
    snapshot = out / "source"
    shutil.copytree(source / "c", snapshot / "c",
                    ignore=shutil.ignore_patterns("build", "__pycache__"))
    manual = Path("go/cmd/crypts/game-manual.md")
    (snapshot / manual).parent.mkdir(parents=True)
    shutil.copy2(source / manual, snapshot / manual)
    for name in ("testdata", "docs/reference"):
        if (source / name).is_dir():
            shutil.copytree(source / name, snapshot / name)
    inputs = [{"path": str(p.relative_to(snapshot)), "sha256": digest(p)}
              for p in sorted(snapshot.rglob("*")) if p.is_file()]
    dump(out / "source-manifest.json", {"source": str(source), "files": inputs})
    croot = snapshot / "c"
    subprocess.run(["make", "-s", "build/generated/game_manual_embed.c",
                    "build/generated/messages.c", "build/generated/obfconst.c"],
                   cwd=croot, check=True)
    # Ask Make for the production source list so save/verifier exclusions and
    # future source additions remain owned by the game.
    rule = ("sre-print-sources:\n\t@printf '%s\\n' "
            "$(PROD_LIB_SRCS) $(PROD_ONLY_SRCS) $(VENDOR_SRCS) "
            "$(PROD_ONLY_GEN_SRCS) $(CRYPTS_MAIN)\n")
    names = subprocess.check_output(
        ["make", "-s", "--no-print-directory", "--eval=" + rule, "sre-print-sources"],
        cwd=croot, text=True).splitlines()
    sources = [(croot / name).resolve(strict=True) for name in names]
    if not sources or len(sources) != len(set(sources)):
        raise ValueError("empty or duplicate production source list")
    if any(not path.is_relative_to(croot) for path in sources):
        raise ValueError("production source escapes the copied C tree")
    return croot, sources


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True, help="RevGame root (read only)")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--toolchain-image", default="sre-obf-dev:llvm22")
    p.add_argument("--plugin", type=Path, default=Path("build/Obfuscator.so"))
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--module-insts", type=int, default=250000)
    p.add_argument("--compile-timeout", type=float, default=600)
    p.add_argument("--control-only", action="store_true")
    p.add_argument("--revision", choices=("v04", "v05"), default="v04")
    p.add_argument("--v05-features-off", action="store_true",
                   help="v05 ablation using the unchanged v04 compiler feature set")
    p.add_argument("--runtime-growth", type=int, default=20000)
    args = p.parse_args(argv)
    if args.v05_features_off and args.revision != "v05":
        p.error("--v05-features-off requires --revision v05")
    if not 1 <= args.runtime_growth <= 65536:
        p.error("--runtime-growth must be 1..65536")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    status = {"status": "preparing", "revision": args.revision,
              "v05_features_off": args.v05_features_off, "candidate_ready": False}
    dump(out / "status.json", status)
    try:
        croot, sources = prepare(args.source.resolve(strict=True), out)
        options = [*map(str, sources), "--out", str(out / "build"),
                   "--toolchain-image", args.toolchain_image,
                   "--plugin", str(args.plugin.resolve()), "--optimization", "O0",
                   "--profile", "max", "--seed", str(args.seed), "--closed-world",
                   "--no-disassembly", "--module-insts", str(args.module_insts),
                   "--compile-timeout", str(args.compile_timeout), *V4_OPTIONS]
        if args.revision == "v05" and not args.v05_features_off:
            options += [*V5_OPTIONS, "--runtime-growth", str(args.runtime_growth)]
        # Match the shipped C Makefile's production semantics, including its
        # existing HARDENED catalogs and noncontracted floating-point math.
        options += ["--cflag=" + flag for flag in (
            "-std=c11", "-g0", "-DHARDENED", "-ffp-contract=off", "-fPIE",
            "-I" + str(croot / "include"), "-I" + str(croot / "vendor"))]
        options += ["--link-flag=" + flag for flag in (
            "-static-pie", "-s", "-Wl,--build-id=none", "-lncursesw", "-ltinfo", "-lm")]
        if args.control_only:
            options.append("--control-only")
        status.update(status="building", source_files=len(sources), options=options)
        dump(out / "status.json", status)
        manifest = whole_build(whole_parser().parse_args(options))
        status.update(status="built", artifacts=manifest["artifacts"])
        print(json.dumps(status["artifacts"], indent=2))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, ToolFailure) as exc:
        status.update(status="failed", error=str(exc))
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        dump(out / "status.json", status)


if __name__ == "__main__":
    sys.exit(main())
