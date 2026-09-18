"""Shared recovery machinery and candidate selection for the static attack adapters.

Two adapters share everything below. `conformance/extract_supplied.py` is handed
a region interface from private provenance; `conformance/extract_discovery.py`
receives only the binary and the public protocol and has to find one. Both then
run the same phases, so their costs are comparable, and both report cost split
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


# ---------------------------------------------------------------------------
# A small grammar of expressions and relations, and its validation rules.
# ---------------------------------------------------------------------------

# Free parameters per family. Used for the capacity check: a family with as many
# parameters as it has observations explains nothing, which is precisely how a
# memorized lookup table passes a naive fit.
FAMILIES = {"identity": 0, "xor_const": 1, "add_const": 1, "sub_const": 1,
            "mask_const": 1, "rotl": 1, "affine": 2, "gf2_linear": None,
            "table": None, "bounds": 2, "xor_join": 1, "sum_join": 1,
            "difference": 1, "affine_join": 3, "recurrence": 3}


def _mask(width: int) -> int:
    return (1 << width) - 1


def _inverse(a: int, width: int):
    """Inverse of an odd residue modulo 2**width; None when `a` is even."""
    if not a & 1:
        return None
    x = 1
    for _ in range(width.bit_length() + 2):
        x = x * (2 - a * x) & _mask(width)
    return x


def predict(model: dict, inputs):
    """Evaluate a fitted model. Returns None where the model does not apply."""
    width, family, p = model["width"], model["family"], model["params"]
    mask = _mask(width)
    values = [int(v) & mask for v in inputs]
    if len(values) < model["arity"]:
        return None
    x = values[0]
    if family == "identity":
        return x
    if family == "xor_const":
        return x ^ p["k"]
    if family == "add_const":
        return (x + p["k"]) & mask
    if family == "sub_const":
        return (p["k"] - x) & mask
    if family == "mask_const":
        return x & p["k"]
    if family == "rotl":
        r = p["r"] % width
        return x if not r else ((x << r) | (x >> (width - r))) & mask
    if family == "affine":
        return (p["a"] * x + p["b"]) & mask
    if family == "gf2_linear":
        out = 0
        for i, column in enumerate(p["columns"]):
            if x >> i & 1:
                out ^= column
        return out & mask
    if family == "table":
        index = p["domain"].index(x) if x in p["domain"] else None
        return None if index is None else p["values"][index]
    if family == "bounds":
        return int(p["low"] <= x <= p["high"])
    y = values[1] if len(values) > 1 else 0
    if family == "xor_join":
        return x ^ y ^ p["k"]
    if family == "sum_join":
        return (x + y + p["k"]) & mask
    if family == "difference":
        return (x - y + p["k"]) & mask
    if family == "affine_join":
        return (p["a"] * x + p["b"] * y + p["k"]) & mask
    if family == "recurrence":
        if x > 1 << 12:
            return None
        state = p["seed"]
        for _ in range(x):
            state = (p["a"] * state + p["b"]) & mask
        return state
    raise ValueError(f"unknown family: {family}")


def _observations(site):
    return [(tuple(int(v) for v in inputs), int(out)) for inputs, out in site["observations"]]


def _candidates(pairs, width):
    """Every family instantiation worth checking against `pairs`."""
    mask = _mask(width)
    first_in, first_out = pairs[0]
    x0 = first_in[0] & mask
    out = [("identity", {}),
           ("xor_const", {"k": x0 ^ first_out}),
           ("add_const", {"k": (first_out - x0) & mask}),
           ("sub_const", {"k": (first_out + x0) & mask})]
    keep = 0
    for _, value in pairs:
        keep |= value
    out.append(("mask_const", {"k": keep}))
    out.extend(("rotl", {"r": r}) for r in range(width))
    for inputs, value in pairs[1:]:
        inverse = _inverse((x0 - (inputs[0] & mask)) & mask, width)
        if inverse is not None:
            a = ((first_out - value) * inverse) & mask
            out.append(("affine", {"a": a, "b": (first_out - a * x0) & mask}))
            break
    basis = {inputs[0] & mask: value for inputs, value in pairs}
    if all(1 << i in basis for i in range(width)) and basis.get(0, 0) == 0:
        out.append(("gf2_linear", {"columns": [basis[1 << i] for i in range(width)]}))
    domain = sorted({inputs[0] & mask for inputs, _ in pairs})
    if len(domain) <= 16:
        table = {}
        for inputs, value in pairs:
            table.setdefault(inputs[0] & mask, value)
        out.append(("table", {"domain": domain, "values": [table[d] for d in domain]}))
    if {value for _, value in pairs} <= {0, 1}:
        inside = [inputs[0] & mask for inputs, value in pairs if value]
        if inside:
            out.append(("bounds", {"low": min(inside), "high": max(inside)}))
    if len(first_in) > 1:
        y0 = first_in[1] & mask
        out.append(("xor_join", {"k": first_out ^ x0 ^ y0}))
        out.append(("sum_join", {"k": first_out - x0 - y0 & mask}))
        out.append(("difference", {"k": first_out - x0 + y0 & mask}))
        out.extend(_affine_join(pairs, width))
    out.extend(_recurrence(pairs, width))
    return out


def _affine_join(pairs, width):
    """Fit a*x + b*y + k by solving two difference equations modulo 2**width.

    Cramer's rule applies whenever the determinant is odd, which covers the
    common case of two observations sharing one input as well as a general grid.
    """
    mask = _mask(width)
    x0, y0, out0 = pairs[0][0][0] & mask, pairs[0][0][1] & mask, pairs[0][1]
    for i in range(1, len(pairs)):
        for j in range(i + 1, len(pairs)):
            dx1, dy1 = (pairs[i][0][0] - x0) & mask, (pairs[i][0][1] - y0) & mask
            dx2, dy2 = (pairs[j][0][0] - x0) & mask, (pairs[j][0][1] - y0) & mask
            do1, do2 = (pairs[i][1] - out0) & mask, (pairs[j][1] - out0) & mask
            inverse = _inverse((dx1 * dy2 - dy1 * dx2) & mask, width)
            if inverse is None:
                continue
            a = (do1 * dy2 - dy1 * do2) * inverse & mask
            b = (dx1 * do2 - do1 * dx2) * inverse & mask
            return [("affine_join", {"a": a, "b": b,
                                     "k": (out0 - a * x0 - b * y0) & mask})]
    return []


def _recurrence(pairs, width):
    """Fit s(i+1) = a*s(i) + b from indices 0, 1 and 2 when they are present."""
    mask = _mask(width)
    known = {inputs[0] & mask: value for inputs, value in pairs}
    if not {0, 1, 2} <= set(known):
        return []
    inverse = _inverse(known[1] - known[0] & mask, width)
    if inverse is None:
        return []
    a = (known[2] - known[1]) * inverse & mask
    return [("recurrence", {"a": a, "b": known[1] - a * known[0] & mask, "seed": known[0]})]


def fit(site, width):
    """Every model in the grammar that reproduces *all* of one site's observations."""
    pairs = _observations(site)
    if len(pairs) < 2:
        raise ValueError("a site needs at least two observations")
    arity = min(len(inputs) for inputs, _ in pairs)
    models = []
    for family, params in _candidates(pairs, width):
        needs = 2 if family in ("xor_join", "sum_join", "difference", "affine_join") else 1
        if needs > arity:
            continue
        model = {"family": family, "params": params, "width": width, "arity": needs}
        if all(predict(model, inputs) == value for inputs, value in pairs):
            models.append(model)
    return models


def parameters(model) -> int:
    declared = FAMILIES[model["family"]]
    if declared is not None:
        return declared
    if model["family"] == "gf2_linear":
        return model["width"]
    return len(model["params"]["domain"])


def validate(model, sites, *, negatives=(), positives=(), oracle=None, domain=None,
             sampled=False) -> dict:
    """Decide whether one fitted model is a summary or just a memory of one example.

    A model is accepted only when it predicts at least two sites, survives
    constructed positives and negatives, is falsifiable on the evidence at hand,
    and has fewer free parameters than the observations it explains. Sampled
    agreement alone is never enough: almost every random pair is a false one, so
    a family that happens to match a handful of samples has been tested by
    nothing. `oracle` plus a small `domain` upgrades the check to exhaustive.
    """
    per_site, predicted, observations = [], 0, 0
    for site in sites:
        pairs = _observations(site)
        misses = [inputs for inputs, value in pairs if predict(model, inputs) != value]
        per_site.append({"site": site.get("name", "?"), "observations": len(pairs),
                         "predicted": not misses,
                         "first_miss": list(misses[0]) if misses else None})
        if not misses:
            predicted += 1
            observations += len(pairs)
    positive_fail = [list(inputs) for inputs, out in positives if predict(model, inputs) != out]
    negative_hit = [list(inputs) for inputs, out in negatives if predict(model, inputs) == out]
    observations += len(positives)
    free = parameters(model)
    counterexample, checked = None, 0
    if oracle is not None and domain is not None:
        for inputs in domain:
            checked += 1
            if predict(model, tuple(inputs)) != oracle(tuple(inputs)):
                counterexample = list(inputs)
                break
    # Falsifiability: perturb one output and require the family to stop fitting.
    # A family that still fits corrupted data has not been tested by the good data.
    falsified = _falsifiable(model, sites)
    if checked:
        level = "exhaustive"
    elif positives and negatives:
        level = "constructed"
    else:
        level = "sampled_only"
    if sampled and level != "exhaustive":
        level = "sampled_only"
    reasons = []
    if predicted < 2:
        reasons.append("predicts-fewer-than-two-sites")
    if positive_fail:
        reasons.append("constructed-positive-mispredicted")
    if negative_hit:
        reasons.append("negative-case-accepted")
    if counterexample is not None:
        reasons.append("counterexample-found")
    if not falsified:
        reasons.append("family-not-falsifiable-on-this-evidence")
    if free >= observations:
        reasons.append("free-parameters-exceed-observations")
    if level == "sampled_only":
        reasons.append("sampled-equality-only")
    return {"model": model, "sites_predicted": predicted, "sites_total": len(sites),
            "observations_explained": observations, "free_parameters": free,
            "constructed_positives": len(positives), "constructed_negatives": len(negatives),
            "positive_failures": positive_fail, "negatives_accepted": negative_hit,
            "counterexample": counterexample, "domain_checked": checked,
            "falsifiable": falsified, "verification": level,
            "validated": not reasons, "reasons": reasons, "per_site": per_site}


def _falsifiable(model, sites) -> bool:
    """Can the evidence at hand reject this family at all?

    Perturb one output in the *pooled* multi-site observations and refit. A
    family that still fits the corrupted pool was never tested by the clean pool:
    a lookup table refits any single site, which is the exact shape of a model
    that has only memorized its one example. The same table checked against
    several sites is falsifiable, because a perturbation then contradicts the
    other sites, and that distinction is the point of the check.
    """
    pool = [pair for site in sites for pair in _observations(site)]
    if len(pool) < 2:
        return False
    for index in range(min(len(pool), 4)):
        corrupted = list(pool)
        inputs, value = corrupted[index]
        corrupted[index] = (inputs, value ^ 1)
        refit = fit({"observations": [[list(i), o] for i, o in corrupted]}, model["width"])
        if not any(other["family"] == model["family"] for other in refit):
            return True
    return False


def summarize(sites, width, *, negatives=(), positives=(), oracle=None, domain=None,
              sampled=False) -> dict:
    """Fit at the first site, then test every candidate against the others."""
    if len(sites) < 2:
        return {"status": "not_summarized", "reason": "fewer-than-two-sites",
                "outcomes": [], "validated": False}
    outcomes = [validate(model, sites, negatives=negatives, positives=positives,
                         oracle=oracle, domain=domain, sampled=sampled)
                for model in fit(sites[0], width)]
    accepted = [o for o in outcomes if o["validated"]]
    accepted.sort(key=lambda o: (o["free_parameters"], o["model"]["family"]))
    if accepted:
        return {"status": "summarized", "validated": True, "best": accepted[0],
                "candidates": len(outcomes), "accepted": len(accepted)}
    # Report why the *closest* candidate failed. Merging every family's
    # complaints would hide which obstacle actually stopped the attack.
    ranked = sorted(outcomes, key=lambda o: (len(o["reasons"]), -o["sites_predicted"],
                                             o["model"]["family"]))
    return {"status": "not_summarized", "validated": False,
            "reason": ranked[0]["reasons"][0] if ranked else "no-family-fits",
            "candidates": len(outcomes), "accepted": 0, "outcomes": ranked[:8]}


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
        return "summarized", None
    return "lifted", outcome.get("reason", "no-validated-model")


def _eligible(row, max_growth, max_runtime):
    if row["control"]["status"] != "recovered":
        # A broken clean control invalidates this adapter/fixture pairing.
        return "clean-control-not-recovered"
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
    load-bearing evidence is prediction at unseen points and across sites.
    """
    return [(tuple(inputs), int(out) ^ 1) for inputs, out in positives]


def probe_summary(result, width=32):
    """Fit and validate a model from the sites the probe measured, if it emitted any."""
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
