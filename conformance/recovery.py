"""Replay one static recovery adapter unchanged across correctness-gated candidates.

Only the binary path and informed entry address change per artifact. Tuning is
separate from held-out seeds/programs. Budgets/errors never count as protection.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, image_identity, target_offset


def choose(rows, max_growth, max_runtime=16):
    groups = {}
    for row in rows:
        groups.setdefault(row["candidate"], []).append(row)
    ranked = []
    for key, cases in groups.items():
        # A broken clean control invalidates this adapter/fixture pairing.
        if any(r["control"]["status"] != "recovered" or
               r["native"]["status"] not in ("recovered", "lifted_large") or
               r.get("runtime_ratio") is None or r["runtime_ratio"] > max_runtime or
               r["growth"] > max_growth for r in cases):
            continue
        score = sum(r["native"].get("ast_nodes", 0) + r["native"].get("steps", 0) for r in cases) / len(cases)
        ranked.append({"candidate": key, "score": score, "cases": len(cases)})
    return sorted(ranked, key=lambda r: (-r["score"], r["candidate"]))


def collect(paths):
    result = []
    for path in paths:
        summary = json.loads(path.read_text())
        for case in summary["cases"]:
            if not case.get("correctness"):
                raise ValueError(f"correctness gate missing/failed in {path}: {case['case']}")
            case = dict(case)
            case["candidate"] = json.dumps([case["profile"], case["passes"], case["feature_flags"]], sort_keys=True)
            case["summary_sha256"] = digest(path)
            result.append(case)
    return result


def replay(case, out, image, seconds):
    row = {k: case[k] for k in ("case", "seed", "candidate", "source_sha256", "summary_sha256")}
    row["growth"] = case["arms"]["native"]["binary_bytes"] / case["arms"]["control"]["binary_bytes"]
    timing = [case["arms"][arm].get("execution_seconds") for arm in ("control", "native")]
    row["runtime_ratio"] = timing[1] / timing[0] if all(t is not None and t > 0 for t in timing) else None
    row["timing_scope"] = "trusted batch including startup; not a microbenchmark"
    for arm in ("control", "native"):
        metadata = case["arms"][arm]
        binary = Path(metadata["binary"]).resolve()
        if digest(binary) != metadata["binary_sha256"]:
            raise ValueError("binary no longer matches correctness provenance")
        dest = out / arm
        dest.mkdir(parents=True)
        runner = Runner(ROOT, dest / "logs", image, timeout=seconds + 15, mounts=(out, binary.parent))
        try:
            entry = target_offset(Path(metadata["link_map"]))
            runner.run(["python3", str(ROOT / "conformance/recovery_probe.py"),
                        "--binary", str(binary), "--entry", hex(entry), "--out", str(dest),
                        "--seconds", str(seconds)])
            row[arm] = json.loads((dest / "result.json").read_text())
        except ToolFailure as exc:
            row[arm] = {"status": "inconclusive", "reason": str(exc)}
        if digest(binary) != metadata["binary_sha256"]:
            raise ValueError("binary changed during recovery")
    dump(out / "replay.json", row)
    return row


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tune", type=Path, action="append", required=True, help="conformance summary.json")
    p.add_argument("--holdout", type=Path, action="append", default=[])
    p.add_argument("--analysis-image", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seconds", type=float, default=20)
    p.add_argument("--max-growth", type=float, default=8)
    p.add_argument("--max-runtime", type=float, default=16)
    args = p.parse_args(argv)
    try:
        if args.seconds <= 0 or args.max_growth < 1 or args.max_runtime < 1:
            raise ValueError("invalid budgets")
        tune, holdout = collect(args.tune), collect(args.holdout)
        identities = {(c["source_sha256"], c["seed"]) for c in tune}
        if identities & {(c["source_sha256"], c["seed"]) for c in holdout}:
            raise ValueError("held-out source/seed pairs overlap tuning data")
        # All candidates must be judged on the same tuning source/seed grid.
        grids = {}
        for c in tune:
            grids.setdefault(c["candidate"], set()).add((c["source_sha256"], c["seed"]))
        if any(grid != identities for grid in grids.values()):
            raise ValueError("candidate tuning grids differ")
        out = args.out.resolve()
        out.mkdir(parents=True, exist_ok=False)
        rows = [replay(c, out / f"tune-{i}", args.analysis_image, args.seconds) for i, c in enumerate(tune)]
        ranking = choose(rows, args.max_growth, args.max_runtime)
        winner = ranking[0]["candidate"] if ranking else None
        held = [replay(c, out / f"holdout-{i}", args.analysis_image, args.seconds)
                for i, c in enumerate(holdout) if c["candidate"] == winner]
        dump(out / "summary.json", {"schema": "sre-recovery-transfer-v1", "ranking": ranking,
            "selected": winner, "tune": rows, "holdout": held,
            "max_growth": args.max_growth, "max_runtime": args.max_runtime,
            "holdout_status": "evaluated" if held else "not_evaluated",
            "analysis_image": image_identity(args.analysis_image),
            "interpretation": "relative symbolic recovery cost, not a security proof; timeout/errors are inconclusive",
            "adapter_edits_between_artifacts": 0, "probe_sha256": digest(ROOT / "conformance/recovery_probe.py")})
        return 0
    except (OSError, ValueError, ToolFailure) as exc:
        print(f"sre-recovery: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
