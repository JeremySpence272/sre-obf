"""Dependency-free recovery grammar shared by both static-analysis adapters.

Fitting proposes models; only complete-domain verification can validate them.
"""
from __future__ import annotations

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
    if width not in (8, 16, 32, 64):
        raise ValueError("unsupported model width")
    if len(pairs) < 2:
        raise ValueError("a site needs at least two observations")
    arities = {len(inputs) for inputs, _ in pairs}
    if len(arities) != 1 or not arities <= {1, 2}:
        raise ValueError("observations must have a consistent one- or two-word interface")
    arity = next(iter(arities))
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
             domain_size=None, equivalence=None, sampled=False) -> dict:
    """Decide whether one fitted model is a summary or just a memory of one example.

    A model is accepted only when it predicts at least two sites, survives
    constructed positives and negatives, is falsifiable on the evidence at hand,
    and has fewer free parameters than the observations it explains. Sampled
    agreement alone is never enough. Constructed examples are also only samples.
    Verification requires a symbolic equivalence callback, or every point of a
    declared Cartesian domain. `domain_size` defaults to the full word range;
    callers using a smaller domain must declare it explicitly in the report.
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
    counterexample, checked, seen = None, 0, set()
    size = (1 << model["width"]) if domain_size is None else domain_size
    if not isinstance(size, int) or not 0 < size <= 1 << model["width"]:
        raise ValueError("invalid declared domain size")
    arity = len(_observations(sites[0])[0][0]) if sites else model["arity"]
    if oracle is not None and domain is not None:
        for inputs in domain:
            inputs = tuple(inputs)
            if len(inputs) != arity or any(not 0 <= v < size for v in inputs):
                raise ValueError("point outside declared domain")
            if checked >= 1 << 16:
                break
            checked += 1
            seen.add(inputs)
            if predict(model, tuple(inputs)) != oracle(tuple(inputs)):
                counterexample = list(inputs)
                break
    # Falsifiability: perturb one output and require the family to stop fitting.
    # A family that still fits corrupted data has not been tested by the good data.
    falsified = _falsifiable(model, sites)
    proof = equivalence(model) if equivalence is not None else None
    if proof and proof.get("status") == "proved":
        level = "proved"
    elif len(seen) == size ** arity and counterexample is None:
        level = "exhaustive"
    elif positives and negatives:
        level = "constructed"
    else:
        level = "sampled_only"
    if sampled and level not in ("exhaustive", "proved"):
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
    if proof and proof.get("status") == "refuted":
        reasons.append("counterexample-found")
    if not falsified:
        reasons.append("family-not-falsifiable-on-this-evidence")
    if free >= observations:
        reasons.append("free-parameters-exceed-observations")
    if level not in ("exhaustive", "proved"):
        reasons.append("sampled-equality-only" if level == "sampled_only"
                       else "complete-domain-verification-required")
    return {"model": model, "sites_predicted": predicted, "sites_total": len(sites),
            "observations_explained": observations, "free_parameters": free,
            "constructed_positives": len(positives), "constructed_negatives": len(negatives),
            "positive_failures": positive_fail, "negatives_accepted": negative_hit,
            "counterexample": counterexample, "domain_checked": checked,
            "domain_size": size, "domain_arity": arity, "proof": proof,
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
              domain_size=None, equivalence=None, sampled=False) -> dict:
    """Fit pooled observations, then verify candidates on the declared domain."""
    if len(sites) < 2:
        return {"status": "not_summarized", "reason": "fewer-than-two-sites",
                "outcomes": [], "validated": False}
    outcomes = [validate(model, sites, negatives=negatives, positives=positives,
                         oracle=oracle, domain=domain, sampled=sampled,
                         domain_size=domain_size, equivalence=equivalence)
                for model in fit({"observations": [p for s in sites
                                                   for p in s["observations"]]}, width)]
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
            "verification_incomplete": any(o.get("proof") and
                o["proof"].get("status") == "inconclusive" for o in outcomes),
            "reason": ranked[0]["reasons"][0] if ranked else "no-family-fits",
            "candidates": len(outcomes), "accepted": 0, "outcomes": ranked[:8]}
