"""Shared recovery machinery and candidate selection for the static attack adapters.

`conformance/extract_supplied.py` is handed
a region interface from private provenance; `conformance/extract_discovery.py`
receives only the binary and the public protocol and has to find one. Both then
share a fitting grammar and symbolic model builder, but support different ABIs
and phase coverage. Compare mechanism costs only on matched interfaces. They report cost split
into the classes in `COST_CLASSES`: discovery, repair and mechanism. Mixing those
would make the two adapters indistinguishable, which is the whole reason there
are two.

Selection used to score a candidate by the size of the symbolic expression the
prober produced -- `ast_nodes + steps`. That is a syntactic proxy, and it selects
for candidates that look complicated rather than candidates that resist recovery:
a larger AST is at least as often a sign that the attack stalled in an
uninteresting place. `choose` now ranks by what the attack actually achieved and
what it cost. The old scoring is kept verbatim in `choose_ast_ablation` as a
historical ablation so the two can be compared; it must not drive selection.

Nothing here converts an inconclusive result into a win. A candidate whose attack
returned `budget`, an error, or an unmodelled state is not ranked at all: it is
reported blocked with a reason. Unknown is not success.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, image_identity, target_offset

# Adapter phases, in the order the plan lists them. The first five are reachable
# only from the discovery adapter; the supplied control starts at `slice`.
PHASES = ("lift", "unwind", "startup", "strings", "xrefs", "select", "slice",
          "immutable_data", "local_memory", "normalize", "fit", "test_model",
          "compose", "probe")
COST_CLASSES = ("discovery", "repair", "mechanism")
PHASE_STATUS = ("ok", "boundary", "invalid_test")

# What the attack actually achieved on one case. Ordered: a higher level is a
# better result *for the attacker*. Level 0 is never ranked.
ATTACK_LEVELS = {"blocked": 0, "lifted": 1, "summarized": 2}


def phase(name: str, cost_class: str, seconds: float, status: str,
          reason: str | None = None, **detail) -> dict:
    if name not in PHASES:
        raise ValueError(f"unknown adapter phase: {name}")
    if cost_class not in COST_CLASSES:
        raise ValueError(f"unknown cost class: {cost_class}")
    if status not in PHASE_STATUS:
        raise ValueError(f"unknown phase status: {status}")
    if status != "ok" and not reason:
        raise ValueError(f"phase {name} reported {status} without a reason")
    record = {"phase": name, "cost_class": cost_class, "status": status,
              "reason": reason, "seconds": round(float(seconds), 4),
              "steps": int(detail.pop("steps", 0))}
    record.update(detail)
    return record


def costs(phases) -> dict:
    """Per-class cost. Classes are kept apart; there is no combined total.

    A class with no phases reports null, not zero. Zero repair seconds would say
    the decompiled code needed no repair; null says nothing tried to repair it.
    """
    result = {}
    for cost_class in COST_CLASSES:
        rows = [p for p in phases if p["cost_class"] == cost_class]
        result[f"{cost_class}_seconds"] = round(sum(p["seconds"] for p in rows), 4) if rows else None
        result[f"{cost_class}_steps"] = sum(p["steps"] for p in rows) if rows else None
        result[f"{cost_class}_phases"] = len(rows)
    result["boundaries"] = [f"{p['phase']}:{p['reason']}" for p in phases if p["status"] != "ok"]
    return result


from conformance.recovery_grammar import (FAMILIES, fit, parameters, predict,
                                          summarize, validate)


# ---------------------------------------------------------------------------
# Normalization and decompiler hygiene.
# ---------------------------------------------------------------------------

def normalization(before: str, after: str, function: str) -> dict:
    """Judge one normalize/recompile round.

    The v03 transcript contains the trap this encodes: a `-fwhole-program`
    attempt deleted the recovered function because nothing referenced it, and the
    resulting empty output looks like total simplification. An output that lost
    the function, or has no function bodies at all, is an invalid test. It is
    never evidence that anything was simplified.
    """
    body = after.strip()
    kept = f"{function}(" in after
    braces = after.count("{")
    if not body or not kept or not braces:
        return {"status": "invalid_test",
                "reason": "optimizer-discarded-function" if body else "empty-optimizer-output",
                "kept_function": kept, "before_bytes": len(before), "after_bytes": len(after)}
    ratio = len(after) / len(before) if before else None
    return {"status": "simplified" if ratio is not None and ratio < 1 else "unchanged",
            "reason": None, "kept_function": True, "ratio": None if ratio is None else round(ratio, 4),
            "before_bytes": len(before), "after_bytes": len(after)}


EQUIVALENCE = ("unchecked", "differential", "proved")


def pseudocode(repairs, equivalence: str = "unchecked") -> dict:
    """Account for decompiler repairs without assuming the result is equivalent.

    Ghidra's types and its upper-bit reconstruction needed hand repair during the
    v03 solve. Each repair is real analyst work and is charged to the repair cost
    class; none of it licenses the claim that recompiled pseudocode matches the
    binary. `equivalent` stays null until something actually checks it.
    """
    if equivalence not in EQUIVALENCE:
        raise ValueError(f"unknown equivalence status: {equivalence}")
    repairs = list(repairs)
    return {"repairs": repairs, "repair_count": len(repairs), "equivalence": equivalence,
            "equivalent": None if equivalence == "unchecked" else True,
            "note": "recompiled pseudocode is not assumed equivalent to the binary"}


# ---------------------------------------------------------------------------
# Candidate selection.
# ---------------------------------------------------------------------------

def attack_level(arm: dict) -> tuple[str, str | None]:
    """What one arm's recovery achieved, and why it stopped if it did."""
    status = arm.get("status")
    if status not in ("recovered", "lifted_large"):
        return "blocked", arm.get("reason") or status or "missing-result"
    outcome = arm.get("summary") or {}
    if outcome.get("validated"):
        if outcome.get("best", {}).get("verification") not in ("proved", "exhaustive"):
            return "blocked", "legacy-or-unverified-summary"
        return "summarized", None
    if not outcome or arm.get("evaluation", {}).get("truncated"):
        return "blocked", "model-verification-incomplete"
    if outcome.get("verification_incomplete"):
        return "blocked", "model-verification-inconclusive"
    if any(o.get("proof", {}).get("status") == "inconclusive"
           for o in outcome.get("outcomes", []) if o.get("proof")):
        return "blocked", "model-verification-inconclusive"
    if outcome.get("reason") in ("complete-domain-verification-required", "sampled-equality-only"):
        return "blocked", "model-verification-incomplete"
    return "lifted", outcome.get("reason", "no-validated-model")


def _eligible(row, max_growth, max_runtime):
    if row["control"]["status"] != "recovered":
        # A broken clean control invalidates this adapter/fixture pairing.
        return "clean-control-not-recovered"
    if attack_level(row["control"])[0] != "summarized":
        return "clean-control-not-summarized"
    if row.get("runtime_ratio") is None:
        return "runtime-ratio-unavailable"
    if row["runtime_ratio"] > max_runtime:
        return "runtime-budget-exceeded"
    if row["growth"] > max_growth:
        return "growth-budget-exceeded"
    return None


def case_cost(row) -> int:
    """Deterministic attack work, excluding discovery.

    Discovery cost is deliberately *not* scored. Making an entry point hard to
    find would otherwise be the cheapest way to win this metric, and the plan is
    explicit that discovery hygiene does not close the semantic weakness. It is
    reported beside the score instead.
    """
    cost = row.get("native", {}).get("cost") or {}
    mechanism = cost.get("mechanism_steps")
    if mechanism is None:
        mechanism = row["native"].get("steps", 0)
    return int(mechanism) + int(cost.get("repair_steps") or 0)


def choose(rows, max_growth, max_runtime=16):
    """Rank candidates by validated recovery outcome, then by measured cost.

    Ordering is `(attack level reached, -cost)`. A candidate whose regions
    the attack only lifted outranks one it fully summarized, and among equals the
    one that cost the attack more work wins. Candidates with any blocked case are
    not ranked: an attack that timed out or hit an unmodelled state measured
    nothing, and nothing is not resistance.
    """
    groups, ranked, blocked = {}, [], []
    for row in rows:
        groups.setdefault(row["candidate"], []).append(row)
    for key, cases in sorted(groups.items()):
        stops = []
        for row in cases:
            gate = _eligible(row, max_growth, max_runtime)
            if gate:
                stops.append(gate)
                continue
            level, reason = attack_level(row["native"])
            if level == "blocked":
                stops.append(f"attack-blocked:{reason}")
        if stops:
            blocked.append({"candidate": key, "cases": len(cases),
                            "reasons": sorted(set(stops))})
            continue
        levels = [attack_level(row["native"])[0] for row in cases]
        # The best result the attack got on *any* case. If one case was
        # summarized the candidate is summarizable, whatever the others did.
        reached = max(levels, key=lambda name: ATTACK_LEVELS[name])
        cost = sum(case_cost(row) for row in cases) / len(cases)
        discovery = sum(int((row["native"].get("cost") or {}).get("discovery_steps") or 0)
                        for row in cases) / len(cases)
        ranked.append({"candidate": key, "attack_level": reached, "cost": round(cost, 4),
                       "discovery_cost": round(discovery, 4), "cases": len(cases),
                       "summarized_cases": levels.count("summarized"),
                       "metric": "validated-outcome-and-measured-cost"})
    ranked.sort(key=lambda r: (ATTACK_LEVELS[r["attack_level"]], -r["cost"], r["candidate"]))
    return ranked, blocked


def choose_ast_ablation(rows, max_growth, max_runtime=16):
    """HISTORICAL ABLATION -- the v01..v03 metric. Not for selection.

    Scored `ast_nodes + steps` on the protected arm, which rewards a candidate
    for producing a large symbolic expression whether or not the expression was
    ever validated, and treats a stalled solver and a genuinely joint
    representation as the same observation. Retained so the two rankings can be
    compared on the same rows; `main` records the comparison.
    """
    groups = {}
    for row in rows:
        groups.setdefault(row["candidate"], []).append(row)
    ranked = []
    for key, cases in groups.items():
        if any(r["control"]["status"] != "recovered" or
               r["native"]["status"] not in ("recovered", "lifted_large") or
               r.get("runtime_ratio") is None or r["runtime_ratio"] > max_runtime or
               r["growth"] > max_growth for r in cases):
            continue
        score = sum(r["native"].get("ast_nodes", 0) + r["native"].get("steps", 0) for r in cases) / len(cases)
        ranked.append({"candidate": key, "score": score, "cases": len(cases),
                       "metric": "ast-size-and-step-count (historical ablation)"})
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


class Boundaryless(RuntimeError):
    """Raised by an entry provider that cannot locate a region to attack."""


def supplied_entry(metadata, _arm):
    """Entry provider for the supplied-region control: private provenance, no cost."""
    return target_offset(Path(metadata["link_map"])), []


def constructed_negatives(positives):
    """Degeneracy check only: the true output of each positive, altered by one bit.

    Rejecting these shows the model is a function of its inputs rather than
    something that accepts anything. It is the weakest of the checks here; the
    load-bearing evidence is complete-domain equivalence, not these samples.
    """
    return [(tuple(inputs), int(out) ^ 1) for inputs, out in positives]


def probe_summary(result, width=32):
    """Use the worker's proof, or report unverified candidates from legacy samples."""
    if "verified_summary" in result:
        return result["verified_summary"]
    sites = result.get("sites") or []
    if len(sites) < 2:
        return {"status": "not_summarized", "validated": False,
                "reason": "probe-emitted-fewer-than-two-sites"}
    positives = [(tuple(inputs), int(out)) for inputs, out in result.get("positives") or []]
    return summarize(sites, width, positives=positives,
                     negatives=constructed_negatives(positives))


def replay(case, out, image, seconds, entry_source=supplied_entry):
    """Run both arms of one case through the shared probe.

    `entry_source` is the one thing the two adapters do not share: it returns the
    region to attack plus the phase records for finding it, which is how the
    discovery adapter's cost stays separable from this control's.
    """
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
        phases = []
        try:
            entry, phases = entry_source(metadata, arm)
            runner.run(["python3", str(ROOT / "conformance/recovery_probe.py"),
                        "--binary", str(binary), "--entry", hex(entry), "--out", str(dest),
                        "--seconds", str(seconds)])
            row[arm] = json.loads((dest / "result.json").read_text())
        except (ToolFailure, Boundaryless) as exc:
            row[arm] = {"status": "inconclusive", "reason": str(exc)}
        if row[arm].get("status") in ("recovered", "lifted_large"):
            row[arm]["summary"] = probe_summary(row[arm])
        phases = list(phases) + [phase("probe", "mechanism", row[arm].get("seconds", 0.0),
                                       "ok" if row[arm].get("status") == "recovered" else "boundary",
                                       row[arm].get("reason") or (None if row[arm].get("status") == "recovered" else "not-recovered"),
                                       steps=int(row[arm].get("steps", 0)))]
        row[arm]["cost"] = costs(phases)
        row[arm]["phases"] = phases
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
        ranking, blocked = choose(rows, args.max_growth, args.max_runtime)
        ablation = choose_ast_ablation(rows, args.max_growth, args.max_runtime)
        winner = ranking[0]["candidate"] if ranking else None
        held = [replay(c, out / f"holdout-{i}", args.analysis_image, args.seconds)
                for i, c in enumerate(holdout) if c["candidate"] == winner]
        dump(out / "summary.json", {"schema": "sre-recovery-transfer-v1", "ranking": ranking,
            "blocked": blocked, "selected": winner, "tune": rows, "holdout": held,
            "ablation_ranking": ablation,
            "ablation_selected": ablation[0]["candidate"] if ablation else None,
            "ablation_agrees": bool(ablation) and bool(ranking) and ablation[0]["candidate"] == winner,
            "selection_metric": "validated-outcome-and-measured-cost",
            "max_growth": args.max_growth, "max_runtime": args.max_runtime,
            "holdout_status": "evaluated" if held else "not_evaluated",
            "analysis_image": image_identity(args.analysis_image),
            "interpretation": "relative measured recovery cost among candidates the attack actually "
                              "recovered; not a security proof. Timeouts, solver errors and unmodelled "
                              "state are blocked rows, never protection. Discovery cost is reported "
                              "separately and is never scored.",
            "adapter_edits_between_artifacts": 0, "probe_sha256": digest(ROOT / "conformance/recovery_probe.py")})
        return 0
    except (OSError, ValueError, ToolFailure) as exc:
        print(f"sre-recovery: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
