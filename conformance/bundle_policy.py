"""Offline Pareto cache for bounded native families; unknown never means hard.

Evidence is private, supplied-interface training data. This module does not
promote v04 or consume holdout results. The compiler only consumes the cache.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from conformance.process import dump
from conformance.recovery import ATTACK_LEVELS, attack_level, case_cost

CANDIDATES = ("additive", "xor")
SHAPE_KEYS = ("width", "lanes", "nodes", "pins")


def shape_key(shape):
    if set(shape) != set(SHAPE_KEYS): raise ValueError("unknown shape fields")
    if (type(shape["width"]) is not int or shape["width"] not in (8, 16, 32, 64) or
        type(shape["lanes"]) is not int or not 2 <= shape["lanes"] <= 4 or
        type(shape["nodes"]) is not int or not 8 <= shape["nodes"] <= 32 or
        type(shape["pins"]) is not bool):
        raise ValueError("unsupported shape")
    return tuple(shape[k] for k in SHAPE_KEYS)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def dominates(a, b):
    # Smaller success and costs for the program, larger cheapest attack work.
    left = (a["attack_level"], -a["cheapest_steps"], a["growth"], a["runtime_ratio"], a["compile_seconds"])
    right = (b["attack_level"], -b["cheapest_steps"], b["growth"], b["runtime_ratio"], b["compile_seconds"])
    return all(x <= y for x, y in zip(left, right)) and any(x < y for x, y in zip(left, right))


def select(evidence):
    if evidence.get("schema") != "sre-bundle-policy-evidence-v1": raise ValueError("unknown evidence schema")
    if evidence.get("complete") is not True: raise ValueError("evidence collection is incomplete")
    protocol = evidence["protocol"]
    if evidence["protocol_sha256"] != canonical_hash(protocol): raise ValueError("protocol changed")
    if protocol.get("split") != "training": raise ValueError("holdouts cannot select policy")
    if tuple(sorted(protocol["candidates"])) != CANDIDATES: raise ValueError("incomplete candidate library")
    attacks = protocol["attacks"]
    if len(set(attacks)) != len(attacks) or len(attacks) < 2: raise ValueError("two distinct adapters required")
    limits = protocol["limits"]
    if set(limits) != {"growth", "runtime_ratio", "compile_seconds"}: raise ValueError("unknown resource dimensions")
    for k in ("growth", "runtime_ratio", "compile_seconds"):
        if type(limits[k]) not in (int, float) or not math.isfinite(limits[k]) or limits[k] <= 0:
            raise ValueError("invalid frozen limits")
    cases = protocol["cases"]
    if not cases or len(cases) > 128: raise ValueError("invalid case count")
    case_map = {c["id"]: c for c in cases}
    if len(case_map) != len(cases): raise ValueError("duplicate case")
    for c in cases: shape_key(c["shape"])
    rows = {}
    for row in evidence["rows"]:
        key = row["case"], row["candidate"], row["attack"]
        if key in rows: raise ValueError("duplicate observation")
        if key[0] not in case_map or key[1] not in CANDIDATES or key[2] not in attacks:
            raise ValueError("unfrozen observation")
        rows[key] = row
    expected = {(c["id"], name, attack) for c in cases for name in CANDIDATES for attack in attacks}
    if set(rows) != expected: raise ValueError("incomplete frozen matrix")
    shapes = sorted({shape_key(c["shape"]) for c in cases})
    rules, decisions = [], []
    for key in shapes:
        group = [c for c in cases if shape_key(c["shape"]) == key]
        admitted, rejected = [], []
        for name in CANDIDATES:
            observations = [rows[c["id"], name, attack] for c in group for attack in attacks]
            reasons, levels = [], []
            for row in observations:
                if row.get("correctness") is not True or row.get("accounting") is not True:
                    reasons.append("correctness-or-accounting")
                if attack_level(row.get("control", {}))[0] != "summarized":
                    reasons.append("clean-control-not-proved")
                level, reason = attack_level(row.get("native", {}))
                if level == "blocked": reasons.append("inconclusive:" + str(reason))
                else: levels.append(ATTACK_LEVELS[level])
                cost = row.get("native", {}).get("cost", {})
                # Repair may be zero for machine-code lifting; missing is unknown.
                if any(type(cost.get(k)) is not int or cost[k] < 0 for k in ("mechanism_steps", "repair_steps")):
                    reasons.append("unmeasured-attack-cost")
                for metric in limits:
                    value = row.get(metric)
                    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                        reasons.append("missing-resource:" + metric)
                    elif value > limits[metric]: reasons.append("resource-cap:" + metric)
            if reasons:
                rejected.append({"candidate": name, "reasons": sorted(set(reasons))})
                continue
            best_level = max(levels)
            cheapest = min(case_cost(r) for r in observations
                           if ATTACK_LEVELS[attack_level(r["native"])[0]] == best_level)
            admitted.append({"candidate": name, "attack_level": best_level, "cheapest_steps": cheapest,
                             **{metric: max(r[metric] for r in observations) for metric in limits}})
        frontier = [a for a in admitted if not any(dominates(b, a) for b in admitted)]
        shape = dict(zip(SHAPE_KEYS, key))
        if frontier: rules.append({"shape": shape, "candidates": sorted(a["candidate"] for a in frontier)})
        decisions.append({"shape": shape, "admitted": admitted, "rejected": rejected,
                          "pareto": sorted(a["candidate"] for a in frontier)})
    return {"schema": "sre-bundle-policy-selection-v1", "protocol_sha256": evidence["protocol_sha256"],
            "rules": rules, "decisions": decisions, "promotion": "not-evaluated",
            "scope": "training only; supplied interfaces; no held-out improvement claim"}


def policy_violations(report):
    """Validate decision identity and scope, not the truth of offline measurements."""
    policy = report.get("bundle_policy")
    errors = []
    for row in report.get("bundles", []):
        for region in row.get("regions", []):
            selection = region.get("selection")
            if policy is None:
                if selection is not None: errors.append("bundle selection without policy identity")
                continue
            if selection is None:
                errors.append("missing bundle policy decision"); continue
            if any(selection.get(k) != v for k, v in policy.items()):
                errors.append("bundle policy identity mismatch")
            if selection.get("hardness_evaluated") is not False:
                errors.append("cache cannot evaluate current-program hardness")
            status, choices = selection.get("status"), selection.get("candidates", [])
            if status == "matched":
                if (not choices or len(set(choices)) != len(choices) or
                    not set(choices) <= set(CANDIDATES)):
                    errors.append("invalid policy candidates")
                family = "additive" if "additive" in region["family"] else "xor"
                if family not in choices: errors.append("selected family absent from cache")
                if (region.get("loop", {}).get("status") == "encoded" or region.get("predicates") or
                    region.get("call_supply_uses") or report.get("features", {}).get("bundle_call_inputs")):
                    errors.append("policy applied outside straight pure context")
            elif status == "seeded-fallback":
                if choices or selection.get("reason") not in ("unmeasured-shape", "unsupported-context"):
                    errors.append("invalid policy fallback")
            else: errors.append("unknown policy decision")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw = args.evidence.read_bytes()
    result = select(json.loads(raw))
    args.out.mkdir(parents=True, exist_ok=False)
    dump(args.out / "selection.json", result)
    dump(args.out / "policy.json", {"schema": "sre-bundle-policy-v1",
         "evidence_sha256": hashlib.sha256(raw).hexdigest(), "rules": result["rules"]})


if __name__ == "__main__": main()
