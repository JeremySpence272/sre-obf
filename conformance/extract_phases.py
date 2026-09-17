"""Shared recovery phases for the v04 semantic-extraction adapters (plan W0).

Two adapters use this module: the supplied-region control
(`conformance/extract_supplied.py`, which is handed a region interface from
private provenance) and the binary-discovery adapter, which must find the same
interface itself. Everything here is deliberately discovery-free so the two
adapters differ only in where the interface comes from, and the mechanism cost
they measure is therefore comparable.

Phases, in the order plan W0 names them:

  lift        obtain a region expression from machine or decompiled code
  slice       identify a slice and *validate* that it is closed
  immutable   recover immutable backing data and safe summaries
  memory      forward local memory that the lift proved resolvable
  normalize   re-optimize with LLVM/GCC and measure simplification
  fit         fit a small grammar of expressions and relations
  test        test the inferred model
  compose     compose it with adjacent regions

Two rules from the plan are enforced here rather than left to callers.

*A model that predicts only one example is not a successful summary.* A fitted
model is reported `single-site` unless it is re-probed against at least two
distinct sites.

*Sampled identities are weak evidence, because almost every random sample is
false.* Random agreement is recorded as a diagnostic and can never promote a
model. Acceptance requires constructed positives, constructed negatives that
the probe set actually discriminates, and a counterexample check that is either
an exhaustive enumeration of a declared finite domain or a solver query. A
solver `unknown` is inconclusive, never a win.

Stdlib only, and runnable as a standalone script so the same file can be
executed inside an analysis image that has angr/z3 but not this package.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys
import time

SCHEMA = "sre-extract-v1"
WIDTHS = (8, 16, 32, 64)

# Fixed reason vocabulary. A phase that is not `ok` always carries one of these;
# a missing denominator is reported as null, never as zero.
REASONS = (
    "not-attempted",
    "tool-unavailable",
    "tool-error",
    "timeout",
    "budget-exhausted",
    "unsupported-operation",
    "unresolved-memory",
    "address-exposure",
    "interface-mismatch",
    "domain-too-large",
    "no-candidate-model",
    "discriminator-vacuous",
    "counterexample-found",
    "solver-unknown",
    "single-site",
    "empty-normalizer-output",
    "no-adjacent-region",
)


def phase(name, status, reason=None, **fields):
  """One phase record. `status` is ok | skipped | inconclusive | failed."""
  if status not in ("ok", "skipped", "inconclusive", "failed"):
    raise ValueError(f"bad phase status {status!r}")
  if status != "ok" and reason not in REASONS:
    raise ValueError(f"reason {reason!r} is outside the fixed vocabulary")
  if status == "ok" and reason is not None:
    raise ValueError("an ok phase carries no reason")
  return {"phase": name, "status": status, "reason": reason, **fields}


def mask_of(width):
  return (1 << width) - 1


def _check_width(width):
  if width not in WIDTHS:
    raise ValueError(f"unsupported width {width}")
  return width


# --------------------------------------------------------------------------
# Backends. A model is built once and evaluated either concretely (tests and
# the reconstruction arm) or symbolically (the counterexample check).
# --------------------------------------------------------------------------


class IntBackend:
  """Concrete evaluation on Python ints, truncated to the model width."""

  symbolic = False

  def __init__(self, width):
    self.width, self.mask = _check_width(width), mask_of(width)

  def const(self, value):
    return value & self.mask

  def add(self, a, b):
    return (a + b) & self.mask

  def sub(self, a, b):
    return (a - b) & self.mask

  def mul(self, a, b):
    return (a * b) & self.mask

  def xor(self, a, b):
    return (a ^ b) & self.mask

  def and_(self, a, b):
    return a & b & self.mask

  def or_(self, a, b):
    return (a | b) & self.mask

  def shl(self, a, n):
    return (a << n) & self.mask

  def lshr(self, a, n):
    return (a & self.mask) >> n

  def ult(self, a, b):
    return (a & self.mask) < (b & self.mask)

  def eq(self, a, b):
    return (a & self.mask) == (b & self.mask)

  def ite(self, cond, a, b):
    return a if cond else b


class ClaripyBackend:
  """Symbolic evaluation, for the counterexample check inside the image."""

  symbolic = True

  def __init__(self, width, claripy):
    self.width, self.mask = _check_width(width), mask_of(width)
    self.cl = claripy

  def const(self, value):
    return self.cl.BVV(value & self.mask, self.width)

  def add(self, a, b):
    return a + b

  def sub(self, a, b):
    return a - b

  def mul(self, a, b):
    return a * b

  def xor(self, a, b):
    return a ^ b

  def and_(self, a, b):
    return a & b

  def or_(self, a, b):
    return a | b

  def shl(self, a, n):
    return a << self.const(n)

  def lshr(self, a, n):
    return self.cl.LShR(a, self.const(n))

  def ult(self, a, b):
    return self.cl.ULT(a, b)

  def eq(self, a, b):
    return a == b

  def ite(self, cond, a, b):
    return self.cl.If(cond, a, b)


# --------------------------------------------------------------------------
# The grammar. Small, closed, and each member is fitted in closed form so that
# fitting itself introduces no search bias.
# --------------------------------------------------------------------------


class Model:
  """A candidate summary over `arity` words of `width` bits."""

  kind = "model"
  arity = 1

  def __init__(self, width, **params):
    self.width = _check_width(width)
    self.mask = mask_of(width)
    self.params = params

  def build(self, backend, args):
    raise NotImplementedError

  def apply(self, args):
    return self.build(IntBackend(self.width), [a & self.mask for a in args])

  def perturbations(self):
    """Neighbouring models used as constructed negatives."""
    return []

  def witnesses(self):
    """Extra probe points constructed from this model's own parameters.

    Boundary points near a fitted parameter are what separate a model from its
    neighbours; without them a probe set can pass every positive and still be
    unable to tell two candidates apart.
    """
    return []

  def cost(self):
    """Description length, in words of parameter. Smaller models win ties."""
    total = 0
    for value in self.params.values():
      total += len(value) if isinstance(value, (list, tuple)) else 1
    return total

  def describe(self):
    return {"kind": self.kind, "width": self.width, "arity": self.arity,
            "params": self.params, "cost": self.cost()}


class Identity(Model):
  kind = "identity-index"

  def build(self, b, args):
    return args[0]

  def perturbations(self):
    return [XorConst(self.width, k=1), Affine(self.width, a=1, b=1)]


class XorConst(Model):
  kind = "xor-constant"

  def build(self, b, args):
    return b.xor(args[0], b.const(self.params["k"]))

  def perturbations(self):
    k = self.params["k"]
    return [XorConst(self.width, k=k ^ 1),
            XorConst(self.width, k=(k + 1) & self.mask),
            XorConst(self.width, k=k ^ (1 << (self.width - 1)))]


class Mask(Model):
  kind = "mask"

  def build(self, b, args):
    return b.and_(args[0], b.const(self.params["m"]))

  def perturbations(self):
    m = self.params["m"]
    return [Mask(self.width, m=m ^ 1), Mask(self.width, m=(m >> 1) & self.mask)]


class Affine(Model):
  kind = "affine"

  def build(self, b, args):
    return b.add(b.mul(args[0], b.const(self.params["a"])), b.const(self.params["b"]))

  def perturbations(self):
    a, c = self.params["a"], self.params["b"]
    return [Affine(self.width, a=(a + 1) & self.mask, b=c),
            Affine(self.width, a=a, b=(c + 1) & self.mask),
            Affine(self.width, a=(a ^ 1) & self.mask, b=c)]


class Rotate(Model):
  kind = "rotate-left"

  def build(self, b, args):
    r = self.params["r"] % self.width
    if r == 0:
      return args[0]
    return b.or_(b.shl(args[0], r), b.lshr(args[0], self.width - r))

  def perturbations(self):
    r = self.params["r"]
    return [Rotate(self.width, r=(r + 1) % self.width),
            Rotate(self.width, r=(r - 1) % self.width)]


class BitPermutation(Model):
  kind = "bit-permutation"

  def build(self, b, args):
    perm, out = self.params["perm"], b.const(0)
    for source, target in enumerate(perm):
      bit = b.and_(b.lshr(args[0], source), b.const(1))
      out = b.or_(out, b.shl(bit, target))
    return out

  def perturbations(self):
    perm = list(self.params["perm"])
    if len(perm) < 2:
      return []
    swapped = list(perm)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    return [BitPermutation(self.width, perm=swapped)]


class Difference(Model):
  kind = "difference"
  arity = 2

  def build(self, b, args):
    return b.sub(args[0], args[1])

  def perturbations(self):
    return [Sum(self.width)]


class Sum(Model):
  kind = "sum"
  arity = 2

  def build(self, b, args):
    return b.add(args[0], args[1])

  def perturbations(self):
    return [Difference(self.width)]


class Xor2(Model):
  kind = "xor-pair"
  arity = 2

  def build(self, b, args):
    return b.xor(args[0], args[1])

  def perturbations(self):
    return [Difference(self.width), Sum(self.width)]


class LookupTable(Model):
  """Exact over its declared finite domain, and only over that domain."""

  kind = "lookup-table"

  def build(self, b, args):
    table = self.params["table"]
    if not table:
      raise ValueError("a lookup table needs at least one entry")
    out = b.const(table[-1])
    for index in range(len(table) - 2, -1, -1):
      out = b.ite(b.eq(args[0], b.const(index)), b.const(table[index]), out)
    return out

  def perturbations(self):
    table = list(self.params["table"])
    if not table:
      return []
    bumped = list(table)
    bumped[0] = (bumped[0] + 1) & self.mask
    rotated = table[1:] + table[:1]
    out = [LookupTable(self.width, table=bumped)]
    if rotated != table:
      out.append(LookupTable(self.width, table=rotated))
    return out

  def witnesses(self):
    return [(i,) for i in range(len(self.params["table"]))]


class Bound(Model):
  """A predicate: 1 while the index is below the bound, else 0."""

  kind = "bound"

  def build(self, b, args):
    return b.ite(b.ult(args[0], b.const(self.params["n"])), b.const(1), b.const(0))

  def perturbations(self):
    n = self.params["n"]
    return [Bound(self.width, n=(n + 1) & self.mask),
            Bound(self.width, n=(n - 1) & self.mask)]

  def witnesses(self):
    n = self.params["n"]
    return [((n - 1) & self.mask,), (n & self.mask,), ((n + 1) & self.mask,)]


class Recurrence(Model):
  """A state relation: the step is itself a grammar member, applied k times.

  Fitted from a state sequence rather than from input/output pairs, so it
  carries its own probe rule; `apply` advances exactly one step.
  """

  kind = "recurrence"

  def __init__(self, width, step):
    super().__init__(width, step=step.describe())
    self.step = step

  def build(self, b, args):
    return self.step.build(b, args)

  def perturbations(self):
    return [Recurrence(self.width, p) for p in self.step.perturbations()]

  def cost(self):
    return 1 + self.step.cost()

  def iterate(self, start, count):
    state, out = start & self.mask, []
    for _ in range(count):
      state = self.step.apply([state])
      out.append(state)
    return out


# --------------------------------------------------------------------------
# Oracles. Never the supplied target machine code: either a reference callable
# (tests), a symbolic expression recovered by lifting, or a *reconstruction*
# compiled from recovered C. The last is labelled and never conflated.
# --------------------------------------------------------------------------


class CallableOracle:
  """Wraps a Python callable. `evidence` says what the answers are about."""

  def __init__(self, fn, width, arity=1, evidence="reference", domain=None):
    self.fn, self.width, self.arity = fn, _check_width(width), arity
    self.mask, self.evidence, self.domain = mask_of(width), evidence, domain
    self.calls = 0

  def evaluate(self, args):
    self.calls += 1
    return self.fn(*[a & self.mask for a in args]) & self.mask

  def equivalence(self, model):
    """No symbolic backend: the caller must enumerate a finite domain."""
    return {"method": "none", "status": "inconclusive", "reason": "solver-unknown"}

  def equivalence_sliced(self, model, fixed, position):
    return self.equivalence(model)


class SlicedOracle:
  """A 1-ary view of a 2-ary oracle with one operand pinned.

  A decoder that is not a single two-operand relation is often a family of
  one-operand relations indexed by its other operand. Slicing exposes that
  family without widening the grammar, and every slice is still judged by the
  same constructed-positive, constructed-negative and counterexample rules.
  """

  def __init__(self, inner, fixed, position=1):
    self.inner, self.fixed, self.position = inner, fixed, position
    self.width, self.arity = inner.width, 1
    self.evidence = getattr(inner, "evidence", "unknown")
    self.domain = getattr(inner, "domain", None)

  @property
  def calls(self):
    return self.inner.calls

  def evaluate(self, args):
    pair = [args[0], self.fixed] if self.position == 1 else [self.fixed, args[0]]
    return self.inner.evaluate(pair)

  def equivalence(self, model):
    return self.inner.equivalence_sliced(model, self.fixed, self.position)


class SymbolicOracle:
  """A claripy expression over named input variables, recovered by lifting."""

  evidence = "symbolic-lift"

  def __init__(self, claripy, expression, variables, width, timeout_ms=5000):
    self.cl, self.expression = claripy, expression
    self.variables = list(variables)
    self.width, self.mask = _check_width(width), mask_of(width)
    self.arity = len(self.variables)
    self.timeout_ms, self.calls, self.domain = timeout_ms, 0, None

  def _solver(self):
    solver = self.cl.Solver()
    try:
      solver.timeout = self.timeout_ms
    except Exception:
      pass
    return solver

  def evaluate(self, args):
    self.calls += 1
    solver = self._solver()
    for variable, value in zip(self.variables, args):
      solver.add(variable == (value & self.mask))
    values = solver.eval(self.expression, 1)
    return values[0] & self.mask

  def equivalence_sliced(self, model, fixed, position):
    """Prove or refute equality with one operand pinned to a constant."""
    if len(self.variables) != 2:
      return {"method": "solver", "status": "inconclusive", "reason": "interface-mismatch"}
    free = self.variables[0] if position == 1 else self.variables[1]
    pinned = self.variables[1] if position == 1 else self.variables[0]
    backend = ClaripyBackend(self.width, self.cl)
    try:
      candidate = model.build(backend, [free])
      solver = self._solver()
      solver.add(pinned == (fixed & self.mask))
      solver.add(self.expression != candidate)
      if solver.satisfiable():
        return {"method": "solver", "status": "refuted",
                "reason": "counterexample-found",
                "counterexample": [solver.eval(free, 1)[0], fixed]}
      return {"method": "solver", "status": "proved", "reason": None}
    except Exception as exc:
      return {"method": "solver", "status": "inconclusive",
              "reason": "solver-unknown", "detail": type(exc).__name__}

  def equivalence(self, model):
    """Prove or refute equality against the lifted expression."""
    backend = ClaripyBackend(self.width, self.cl)
    try:
      candidate = model.build(backend, list(self.variables))
      solver = self._solver()
      solver.add(self.expression != candidate)
      if solver.satisfiable():
        point = [solver.eval(v, 1)[0] for v in self.variables]
        return {"method": "solver", "status": "refuted",
                "reason": "counterexample-found", "counterexample": point}
      return {"method": "solver", "status": "proved", "reason": None}
    except Exception as exc:  # solver unknown, unsupported op, resource cap
      return {"method": "solver", "status": "inconclusive",
              "reason": "solver-unknown", "detail": type(exc).__name__}


# --------------------------------------------------------------------------
# Probe points. Fixed and constructed, never drawn at random.
# --------------------------------------------------------------------------


def constructed_points(width, arity=1):
  """A deterministic probe set that exercises every bit position."""
  m = mask_of(width)
  base = [0, 1, 2, 3, m, m - 1, m >> 1, (m >> 1) + 1]
  base += [(1 << i) & m for i in range(width)]
  for pattern in (0x55, 0xAA, 0x0F, 0xF0):
    value = 0
    for byte in range(width // 8):
      value |= pattern << (8 * byte)
    base.append(value & m)
  ordered = sorted(set(v & m for v in base))
  if arity == 1:
    return [(v,) for v in ordered]
  # Pair each point with a small deterministic set of partners, so difference
  # and sum relations are exercised without a combinatorial blow-up.
  partners = [0, 1, m, m >> 1]
  return [(v, p) for v in ordered for p in partners]


def domain_points(domain, arity=1):
  """Every point of a declared finite domain, or None when it is too large."""
  if domain is None:
    return None
  size = int(domain)
  if size <= 0 or size ** arity > 1 << 16:
    return None
  if arity == 1:
    return [(i,) for i in range(size)]
  return [(i, j) for i in range(size) for j in range(size)]


def probe_set(width, arity, domain=None, model=None):
  """The points a model is fitted and judged on.

  A declared finite domain is enumerated, because outside its own domain a
  table or a bounded index predicts nothing and must not be judged as if it
  did. Otherwise the fixed constructed set is used, widened by points built
  from the candidate's own parameters so that neighbouring models can be told
  apart. Nothing here is drawn at random.
  """
  enumerated = domain_points(domain, arity)
  if enumerated is not None:
    return enumerated
  points = list(constructed_points(width, arity))
  if model is not None:
    points += [tuple(p) for p in model.witnesses() if len(p) == arity]
  return sorted(set(points))


# --------------------------------------------------------------------------
# Phase: fit. Closed-form fitters, ranked by description length.
# --------------------------------------------------------------------------


def _agrees(model, oracle, points):
  for args in points:
    if model.apply(list(args)) != oracle.evaluate(list(args)):
      return False
  return True


def fit_models(oracle, width, domain=None):
  """Every grammar member that matches the oracle on the constructed points."""
  arity = getattr(oracle, "arity", 1)
  points = probe_set(width, arity, domain)
  m = mask_of(width)
  candidates = []

  if arity == 2:
    for model in (Xor2(width), Difference(width), Sum(width)):
      if _agrees(model, oracle, points):
        candidates.append(model)
    return sorted(candidates, key=lambda mo: (mo.cost(), mo.kind))

  f0 = oracle.evaluate([0])
  f1 = oracle.evaluate([1])
  fall = oracle.evaluate([m])

  candidates.append(Identity(width))
  candidates.append(XorConst(width, k=f0))
  candidates.append(Mask(width, m=fall))
  candidates.append(Affine(width, a=(f1 - f0) & m, b=f0))
  for r in range(width):
    candidates.append(Rotate(width, r=r))

  # A bit permutation only exists if every single-bit input maps to a single bit.
  images = [oracle.evaluate([(1 << i) & m]) for i in range(width)]
  if all(image and (image & (image - 1)) == 0 for image in images):
    perm = [image.bit_length() - 1 for image in images]
    if sorted(perm) == list(range(width)):
      candidates.append(BitPermutation(width, perm=perm))

  # A bound predicate, located by binary search on a monotone predicate.
  if {f0, fall} <= {0, 1}:
    low, high = 0, m + 1
    while low < high:
      middle = (low + high) // 2
      if oracle.evaluate([middle]) == 1:
        low = middle + 1
      else:
        high = middle
    candidates.append(Bound(width, n=low))

  # Each candidate is judged on its own probe set, so a bound is separated at
  # its own boundary rather than only where the generic points happen to fall.
  kept = [model for model in candidates
          if _agrees(model, oracle, probe_set(width, arity, domain, model))]

  # A table is exact over an enumerated finite domain, and is offered last so
  # it never displaces a closed-form relation that also fits.
  enumerated = domain_points(domain, 1)
  if enumerated is not None:
    table = [oracle.evaluate(list(args)) for args in enumerated]
    kept.append(LookupTable(width, table=table))

  return sorted(kept, key=lambda mo: (mo.cost(), mo.kind, json.dumps(mo.params, sort_keys=True)))


def fit_recurrence(states, width):
  """Fit a one-step relation to an observed state sequence."""
  m = mask_of(width)
  if len(states) < 4:
    return None
  s0, s1, s2 = (s & m for s in states[:3])
  steps = [(s & m, t & m) for s, t in zip(states, states[1:])]
  constant = (s1 ^ s0)
  if all(((t ^ s) & m) == constant for s, t in steps):
    return Recurrence(width, XorConst(width, k=constant))
  delta0, delta1 = (s1 - s0) & m, (s2 - s1) & m
  if delta0 == delta1:
    return Recurrence(width, Affine(width, a=1, b=delta0))
  # a*(s1-s0) == (s2-s1) determines a when the first difference is invertible.
  if delta0 % 2 == 1:
    a = (delta1 * pow(delta0, -1, 1 << width)) & m
    b = (s1 - a * s0) & m
    model = Recurrence(width, Affine(width, a=a, b=b))
    if all(model.step.apply([s]) == t for s, t in steps):
      return model
  return None


# --------------------------------------------------------------------------
# Phase: test. Constructed positives, discriminating negatives, counterexamples.
# --------------------------------------------------------------------------


def test_model(model, oracle, width, domain=None, random_samples=0, seed=1):
  """Decide whether a fitted model may be reported as a summary.

  Acceptance needs all three constructed checks to pass. Random agreement is
  recorded only as a diagnostic: the plan is explicit that random equality
  tests are weak because almost every random sample is false, so they can
  never promote a model here.
  """
  arity = getattr(oracle, "arity", 1)
  points = probe_set(width, arity, domain, model)
  positives, first_bad = 0, None
  for args in points:
    if model.apply(list(args)) == oracle.evaluate(list(args)):
      positives += 1
    elif first_bad is None:
      first_bad = list(args)

  # Constructed negatives: each perturbation must be *rejected* by this probe
  # set. If a perturbation survives, the probe set cannot tell the models
  # apart and the fit is not identified, whatever the positives say.
  negatives, undiscriminated = [], []
  for other in model.perturbations():
    separating = None
    for args in points:
      if other.apply(list(args)) != oracle.evaluate(list(args)):
        separating = list(args)
        break
    negatives.append({"kind": other.kind, "params": other.params,
                      "separated": separating is not None, "witness": separating})
    if separating is None:
      undiscriminated.append(other.kind)

  # Counterexample check: exhaustive over a declared finite domain, otherwise a
  # solver query. Neither available means inconclusive, never accepted.
  enumerated = domain_points(domain, arity)
  if enumerated is not None:
    counterexample = None
    for args in enumerated:
      if model.apply(list(args)) != oracle.evaluate(list(args)):
        counterexample = list(args)
        break
    check = {"method": "exhaustive", "points": len(enumerated),
             "status": "refuted" if counterexample else "proved",
             "reason": "counterexample-found" if counterexample else None,
             "counterexample": counterexample}
  else:
    check = dict(oracle.equivalence(model))
    check.setdefault("points", None)

  diagnostic = None
  if random_samples > 0:
    import random as _random
    rng = _random.Random(seed)
    agree = 0
    for _ in range(random_samples):
      args = [rng.getrandbits(width) for _ in range(arity)]
      if model.apply(args) == oracle.evaluate(args):
        agree += 1
    diagnostic = {"samples": random_samples, "agreeing": agree,
                  "note": "diagnostic only; random equality tests are weak "
                          "evidence and never promote a model"}

  accepted = (first_bad is None and not undiscriminated
              and check["status"] == "proved")
  if accepted:
    status, reason = "ok", None
  elif check["status"] == "refuted" or first_bad is not None:
    status, reason = "failed", "counterexample-found"
  elif undiscriminated:
    status, reason = "inconclusive", "discriminator-vacuous"
  else:
    status, reason = "inconclusive", check.get("reason") or "solver-unknown"

  return {"model": model.describe(), "accepted": accepted,
          "status": status, "reason": reason,
          "constructed_positives": {"points": len(points), "agreeing": positives,
                                    "first_disagreement": first_bad},
          "constructed_negatives": {"perturbations": len(negatives),
                                    "all_separated": not undiscriminated,
                                    "undiscriminated": sorted(undiscriminated),
                                    "cases": negatives},
          "counterexample_check": check,
          "random_diagnostic": diagnostic,
          "oracle_evidence": getattr(oracle, "evidence", "unknown")}


def probe_sites(model, oracles, width, domain=None):
  """Re-probe one fitted model at several sites.

  A model that predicts only the site it was fitted on is not a summary, so a
  single predicted site is reported as `single-site`, never as a success.
  """
  rows = []
  for name, oracle in sorted(oracles.items()):
    result = test_model(model, oracle, width, domain=domain)
    rows.append({"site": name, "accepted": result["accepted"],
                 "status": result["status"], "reason": result["reason"],
                 "oracle_evidence": result["oracle_evidence"]})
  predicted = [row["site"] for row in rows if row["accepted"]]
  if len(predicted) >= 2:
    return phase("compose", "ok", sites=rows, sites_probed=len(rows),
                 sites_predicted=len(predicted), predicted=predicted)
  return phase("compose", "inconclusive", "single-site", sites=rows,
               sites_probed=len(rows), sites_predicted=len(predicted),
               predicted=predicted,
               note="a model that predicts fewer than two sites is not a summary")


def probe_model_reuse(fitted, oracles, width, domain=None):
  """Re-probe every distinct fitted model against every site.

  Fitting a fresh model per site proves nothing on its own: a per-site model
  always fits its own site. What counts is whether one inferred model carries
  to sites it was not fitted on, so each distinct model is replayed against all
  sites and a model that still explains only one is reported `single-site`.
  """
  distinct = {}
  for site, model in sorted(fitted.items()):
    if model is None:
      continue
    distinct.setdefault(json.dumps(model.describe(), sort_keys=True), model)
  rows = []
  for key, model in sorted(distinct.items()):
    probe = probe_sites(model, oracles, width, domain)
    rows.append({"model": model.describe(), "fitted_at": sorted(
                     s for s, m in fitted.items()
                     if m is not None and json.dumps(m.describe(), sort_keys=True) == key),
                 "sites_predicted": probe["sites_predicted"],
                 "predicted": probe["predicted"], "status": probe["status"]})
  reusable = [row for row in rows if row["sites_predicted"] >= 2]
  if not rows:
    return phase("compose", "inconclusive", "no-candidate-model", models=rows)
  if not reusable:
    return phase("compose", "inconclusive", "single-site", models=rows,
                 distinct_models=len(rows), reusable_models=0,
                 note="every inferred model explains only the site it was fitted on")
  return phase("compose", "ok", models=rows, distinct_models=len(rows),
               reusable_models=len(reusable))


def fit_source_map(sources, count):
  """Fit the index relation carrying each output lane back to an input lane.

  Recovers the plan's `identity indices` and byte-granularity `rotations`: a
  lane map that is the identity, a constant rotation, or neither.
  """
  if any(s is None for s in sources) or len(sources) != count:
    return {"kind": None, "status": "inconclusive", "reason": "unresolved-memory",
            "sources": sources}
  if sources == list(range(count)):
    return {"kind": "identity-index", "status": "ok", "reason": None, "sources": sources}
  for rotation in range(1, count):
    if sources == [(j + rotation) % count for j in range(count)]:
      return {"kind": "byte-rotation", "status": "ok", "reason": None,
              "rotation": rotation, "sources": sources}
  if sorted(sources) == list(range(count)):
    return {"kind": "byte-permutation", "status": "ok", "reason": None, "sources": sources}
  return {"kind": None, "status": "inconclusive", "reason": "no-candidate-model",
          "sources": sources}


# --------------------------------------------------------------------------
# Phase: immutable data. A minimal ELF64 reader; immutability is decided by the
# section flags of the supplied binary, not by assumption.
# --------------------------------------------------------------------------

SHF_WRITE = 0x1
SHT_NOBITS = 8


class Elf64:
  def __init__(self, path):
    self.path = Path(path)
    self.data = self.path.read_bytes()
    if self.data[:4] != b"\x7fELF" or self.data[4] != 2:
      raise ValueError("not an ELF64 image")
    shoff, = struct.unpack_from("<Q", self.data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", self.data, 0x3A)
    self.sections = []
    for index in range(shnum):
      base = shoff + index * shentsize
      name, kind, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", self.data, base)
      self.sections.append({"name_offset": name, "type": kind, "flags": flags,
                            "addr": addr, "offset": offset, "size": size})
    strtab = self.sections[shstrndx]
    for section in self.sections:
      start = strtab["offset"] + section["name_offset"]
      end = self.data.index(b"\x00", start)
      section["name"] = self.data[start:end].decode("ascii", "replace")

  def containing(self, address):
    for section in self.sections:
      if section["addr"] and section["addr"] <= address < section["addr"] + section["size"]:
        return section
    return None

  def read(self, address, count):
    section = self.containing(address)
    if section is None:
      return None, None
    if section["type"] == SHT_NOBITS:
      return bytes(count), section
    start = section["offset"] + (address - section["addr"])
    return self.data[start:start + count], section


def recover_immutable_data(binary, items):
  """Read declared backing data and report whether it is genuinely immutable.

  The v03 solve turned on exactly this: the visible eight-byte table was
  *encoded backing*, not the expected vector, and recovering its
  index-dependent decoder was part of the win. So reading bytes out of a
  read-only section is recorded as recovering backing, never as recovering a
  plaintext answer.
  """
  try:
    elf = Elf64(binary)
  except (OSError, ValueError, IndexError, struct.error):
    return phase("immutable", "inconclusive", "tool-error", items=[])
  rows, unresolved = [], 0
  for item in items:
    address = int(item["address"], 0) if isinstance(item["address"], str) else int(item["address"])
    count = int(item["bytes"])
    raw, section = elf.read(address, count)
    if raw is None or len(raw) != count:
      unresolved += 1
      rows.append({"name": item["name"], "address": hex(address), "bytes": count,
                   "status": "unresolved", "reason": "address-exposure"})
      continue
    writable = bool(section["flags"] & SHF_WRITE)
    rows.append({"name": item["name"], "address": hex(address), "bytes": count,
                 "section": section["name"], "immutable": not writable,
                 "status": "ok" if not writable else "mutable",
                 "values": list(raw),
                 "interpretation": "backing bytes as stored; an encoded table is "
                                   "not the value its consumer sees"})
  if unresolved:
    return phase("immutable", "inconclusive", "address-exposure", items=rows,
                 resolved=len(rows) - unresolved, unresolved=unresolved)
  return phase("immutable", "ok", items=rows, resolved=len(rows), unresolved=0)


# --------------------------------------------------------------------------
# Phase: slice and memory forwarding, over a completed lift.
# --------------------------------------------------------------------------


def declared_inputs(interface):
  """The input variable names a supplied interface promises, by ABI."""
  abi = interface.get("abi", "int-words")
  if abi == "buffer-in-out":
    return [f"in_{i}" for i in range(int(interface["input_bytes"]))]
  if abi == "int-words":
    return [p["name"] for p in interface["params"]]
  raise ValueError(f"unsupported ABI {abi!r}")


def validate_slice(lift, interface):
  """A slice is valid only if it is closed over the declared interface.

  Closure means every free variable of the recovered expression is a declared
  input, and the recovered paths cover the declared input domain. Anything
  else is an unresolved read, which is a boundary, not a summary.
  """
  declared = sorted(declared_inputs(interface))
  free = sorted(lift.get("variables", []))
  extra = [name for name in free if name not in declared]
  if extra:
    return phase("slice", "inconclusive", "unresolved-memory",
                 declared_inputs=declared, free_variables=free,
                 undeclared_reads=extra)
  if not lift.get("domain_complete", False):
    return phase("slice", "inconclusive", "budget-exhausted",
                 declared_inputs=declared, free_variables=free,
                 note="recovered paths do not cover the declared input domain")
  return phase("slice", "ok", declared_inputs=declared, free_variables=free,
               undeclared_reads=[], instructions=lift.get("steps"))


def forward_local_memory(lift, slice_result):
  """Report local memory the lift *proved* resolvable, not memory assumed away.

  Forwarding is claimed only when the recovered expression has no free memory
  variable left; residual reads are reported as unresolved with their names.
  """
  if slice_result["status"] != "ok":
    return phase("memory", "skipped", "unresolved-memory",
                 forwarded=None, residual_reads=slice_result.get("undeclared_reads", []))
  residual = sorted(lift.get("unresolved_reads", []))
  if residual:
    return phase("memory", "inconclusive", "unresolved-memory",
                 forwarded=False, residual_reads=residual)
  return phase("memory", "ok", forwarded=True, residual_reads=[],
               basis="every load in the slice was resolved to a declared input "
                     "or to immutable backing; nothing was assumed away")


# --------------------------------------------------------------------------
# Phase: normalize. Simplification is measured, and an empty output is refused.
# --------------------------------------------------------------------------


def normalize_result(before, after, tool, flags, produced_body):
  """Score one normalizer run.

  A v03 attempt lost its recovered function to `-fwhole-program` because
  nothing referenced it. An empty optimizer output is an invalid test, never
  evidence of simplification, so it is refused here rather than scored as a
  perfect reduction.
  """
  if not produced_body or after <= 0:
    return phase("normalize", "failed", "empty-normalizer-output",
                 tool=tool, flags=flags, instructions_before=before,
                 instructions_after=after if after > 0 else None,
                 note="the normalizer emitted no body for the region; the run "
                      "measures nothing and is not a simplification result")
  if before <= 0:
    return phase("normalize", "inconclusive", "tool-error", tool=tool, flags=flags,
                 instructions_before=None, instructions_after=after)
  return phase("normalize", "ok", tool=tool, flags=flags,
               instructions_before=before, instructions_after=after,
               reduction=round(1.0 - after / before, 4))


# --------------------------------------------------------------------------
# Report assembly.
# --------------------------------------------------------------------------


def region_report(name, adapter, phases, interface=None, **extra):
  order = [p["phase"] for p in phases]
  failed = [p["phase"] for p in phases if p["status"] == "failed"]
  inconclusive = [p["phase"] for p in phases if p["status"] == "inconclusive"]
  if failed:
    status = "failed"
  elif inconclusive:
    status = "inconclusive"
  else:
    status = "recovered"
  return {"region": name, "adapter": adapter, "status": status,
          "phase_order": order, "failed_phases": failed,
          "inconclusive_phases": inconclusive,
          "interface": interface, "phases": phases, **extra}


def adapter_report(adapter, regions, **extra):
  recovered = [r for r in regions if r["status"] == "recovered"]
  return {"schema": SCHEMA, "adapter": adapter,
          "regions_total": len(regions), "regions_recovered": len(recovered),
          "regions_inconclusive": sum(1 for r in regions if r["status"] == "inconclusive"),
          "regions_failed": sum(1 for r in regions if r["status"] == "failed"),
          "interpretation": "relative semantic-recovery cost under a fixed adapter; "
                            "not a hardness claim and not a security proof. "
                            "Budgets, tool errors and solver unknowns are "
                            "inconclusive, never protection and never a win.",
          "regions": regions, **extra}


# --------------------------------------------------------------------------
# Standalone worker. Runs inside an analysis image that has angr/claripy; the
# host driver never imports angr. Kept here so both W0 adapters share it.
# --------------------------------------------------------------------------


def _load_claripy():
  try:
    import claripy
    return claripy
  except ModuleNotFoundError:
    from angr import claripy  # angr 10 vendors the solver
    return claripy




def _ast_size(expression, cap=100000):
  """Distinct AST nodes, by a bounded walk over `.args`.

  Written against `.args` rather than a helper method because the solver
  vendored by the analysis image does not expose one.
  """
  seen, work = set(), [expression]
  while work and len(seen) < cap:
    node = work.pop()
    key = getattr(node, "hash", None)
    try:
      key = node.hash() if callable(key) else id(node)
    except Exception:
      key = id(node)
    if key in seen:
      continue
    seen.add(key)
    for child in getattr(node, "args", ()) or ():
      if hasattr(child, "args"):
        work.append(child)
  return len(seen)


# Pinned operands used when fitting a two-operand site one slice at a time.
SLICE_POINTS = (0, 1, 2, 0x0F, 0x55, 0xAA, 0xF0, 0xFF)

STOP = 0x7FFF00000000
IN_BASE, OUT_BASE = 0x50000000, 0x50001000


def _run(project, state, limits, started):
  """Step one call state to return, under the supplied budget."""
  import angr  # noqa: F401  (the caller already imported it)
  sim = project.factory.simgr(state, save_unconstrained=True)
  steps = 0
  while sim.active and steps < limits["steps"] and time.monotonic() - started < limits["seconds"]:
    sim.move(from_stash="active", to_stash="returned", filter_func=lambda s: s.addr == STOP)
    if not sim.active:
      break
    if len(sim.active) + len(sim.stashes.get("returned", [])) > limits["paths"]:
      break
    sim.step()
    steps += 1
  return sim, steps


def _lift_status(sim, steps, started):
  out = {"steps": steps, "returned_paths": len(sim.stashes.get("returned", [])),
         "active_paths": len(sim.active), "errors": len(sim.errored),
         "unconstrained": len(sim.unconstrained),
         "seconds": round(time.monotonic() - started, 4),
         "mode": "oracle-entry-symbolic-no-native-execution",
         "variables": [], "unresolved_reads": [], "domain_complete": False}
  if sim.errored or sim.unconstrained:
    out.update(status="inconclusive", reason="unsupported-operation")
  elif sim.active:
    out.update(status="inconclusive", reason="budget-exhausted")
  elif not sim.stashes.get("returned"):
    out.update(status="inconclusive", reason="unsupported-operation")
  else:
    out.update(status="ok", reason=None)
  return out


def lift_region(spec, limits):
  """Lift one region to symbolic expressions over its declared interface.

  The entry and the ABI are supplied from private provenance, so this measures
  recovery *after* discovery, never discovery itself. The supplied target is
  not executed: Unicorn is disabled, no initializer is emulated, and every
  answer comes from a solver over the lifted expression.

  Returns `(lift, oracles)`, where `oracles` maps a site name to an oracle over
  the recovered expression. `int-words` yields one site, `result`;
  `buffer-in-out` yields one site per output lane.
  """
  import angr
  from angr.calling_conventions import SimCCSystemVAMD64
  from angr.sim_type import (SimTypeFunction, SimTypeInt, SimTypeLongLong,
                             SimTypePointer, SimTypeChar)

  claripy = _load_claripy()
  interface = spec["interface"]
  abi = interface.get("abi", "int-words")
  started = time.monotonic()
  project = angr.Project(spec["binary"], auto_load_libs=False)
  main = project.loader.main_object
  entry = int(spec["entry"], 0) + (main.mapped_base if main.pic else 0)
  options = {"add_options": {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                             angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
             "remove_options": {angr.options.UNICORN}}

  if abi == "int-words":
    width = int(interface.get("width", 32))
    names = [p["name"] for p in interface["params"]]
    args = [claripy.BVS(n, width, explicit_name=True) for n in names]
    # The declared width drives the prototype, so a narrow interface is passed
    # and read at its own width instead of being widened into register noise.
    scalar = {8: SimTypeChar, 32: SimTypeInt, 64: SimTypeLongLong}.get(width)
    if scalar is None:
      raise ValueError(f"unsupported int-words width {width}")
    proto = SimTypeFunction([scalar()] * len(args), scalar())
    state = project.factory.call_state(entry, *args, ret_addr=STOP,
                                       cc=SimCCSystemVAMD64(project.arch),
                                       prototype=proto, **options)
  elif abi == "buffer-in-out":
    width = int(interface.get("width", 8))
    count = int(interface["input_bytes"])
    proto = SimTypeFunction([SimTypePointer(SimTypeChar()),
                             SimTypePointer(SimTypeChar())], SimTypeInt(False))
    state = project.factory.call_state(entry, IN_BASE, OUT_BASE, ret_addr=STOP,
                                       cc=SimCCSystemVAMD64(project.arch),
                                       prototype=proto, **options)
    args = [claripy.BVS(f"in_{i}", 8, explicit_name=True) for i in range(count)]
    for index, symbol in enumerate(args):
      state.memory.store(IN_BASE + index, symbol)
  else:
    raise ValueError(f"unsupported ABI {abi!r}")

  state.solver._solver.timeout = limits["solver_ms"]
  sim, steps = _run(project, state, limits, started)
  lift = _lift_status(sim, steps, started)
  lift["abi"] = abi
  if lift["status"] != "ok":
    return lift, {}

  declared = declared_inputs(interface)
  returned = sim.stashes["returned"]
  oracles, free = {}, set()

  if abi == "int-words":
    expression, covered = claripy.BVV(0, width), claripy.false()
    for finished in returned:
      condition = claripy.And(*finished.solver.constraints)
      covered = claripy.Or(covered, condition)
      # Read the result at the declared width, not the full register.
      expression = claripy.If(condition, finished.regs.rax[width - 1:0], expression)
    expression = claripy.simplify(expression)
    free |= expression.variables | covered.variables
    solver = claripy.Solver()
    lift["domain_complete"] = not solver.satisfiable(extra_constraints=[claripy.Not(covered)])
    lift["ast_nodes"] = _ast_size(expression)
    lift["ast_depth"] = expression.depth
    oracles["result"] = SymbolicOracle(claripy, expression, args, width, limits["solver_ms"])
  else:
    # One returned path is required: a buffer region that branches on its own
    # input leaves several, and merging them here would hide the branch.
    if len(returned) != 1:
      lift.update(status="inconclusive", reason="unsupported-operation",
                  note="more than one returned path; lane expressions would hide a branch")
      return lift, {}
    finished = returned[0]
    lift["domain_complete"] = True
    lanes, nodes = [], 0
    for index in range(int(interface["output_bytes"])):
      expression = claripy.simplify(finished.memory.load(OUT_BASE + index, 1))
      variables = sorted(expression.variables)
      free |= expression.variables
      nodes += _ast_size(expression)
      sources = [declared.index(v) for v in variables if v in declared]
      lanes.append({"lane": index, "variables": variables,
                    "source": sources[0] if len(sources) == 1 else None,
                    "ast_depth": expression.depth})
      if len(variables) == 1 and variables[0] in declared:
        oracles[f"lane_{index}"] = SymbolicOracle(
            claripy, expression, [claripy.BVS(variables[0], width, explicit_name=True)],
            width, limits["solver_ms"])
    lift["lanes"] = lanes
    lift["ast_nodes"] = nodes

  lift["variables"] = sorted(name for name in free if name in declared)
  lift["unresolved_reads"] = sorted(name for name in free if name not in declared)
  if lift["unresolved_reads"]:
    lift.update(status="inconclusive", reason="unresolved-memory")
  return lift, oracles


def analyze(spec, lift, oracles):
  """Run every phase after the lift. Shared by both W0 adapters.

  Kept separate from lifting so the supplied-region control and the binary
  discovery adapter differ only in how the interface and entry were obtained,
  and their mechanism costs stay comparable.
  """
  interface = spec["interface"]
  width = int(interface.get("width", 32))
  domain = spec.get("domain")
  phases = [phase("lift", "ok" if lift["status"] == "ok" else "inconclusive",
                  None if lift["status"] == "ok" else lift.get("reason", "tool-error"),
                  **{k: v for k, v in lift.items() if k not in ("status", "reason")})]
  if lift["status"] != "ok" or not oracles:
    if lift["status"] == "ok" and not oracles:
      phases[0] = phase("lift", "inconclusive", "unresolved-memory",
                        **{k: v for k, v in lift.items() if k not in ("status", "reason")})
    return phases, {}

  slice_result = validate_slice(lift, interface)
  phases.append(slice_result)
  phases.append(forward_local_memory(lift, slice_result))

  fitted, fits, tests = {}, [], []
  for site, oracle in sorted(oracles.items()):
    models = fit_models(oracle, width, domain)
    fitted[site] = models[0] if models else None
    fits.append({"site": site, "candidates": [m.describe() for m in models]})
    if models:
      result = test_model(models[0], oracle, width, domain)
      result["site"] = site
      tests.append(result)
  if not any(fitted.values()):
    phases.append(phase("fit", "inconclusive", "no-candidate-model", sites=fits))
    sliced = slice_family(oracles, width, domain)
    if sliced is not None:
      phases.append(sliced)
    return phases, fitted
  phases.append(phase("fit", "ok", sites=fits,
                      sites_fitted=sum(1 for m in fitted.values() if m is not None),
                      sites_total=len(oracles)))
  accepted = [t for t in tests if t["accepted"]]
  if not accepted:
    phases.append(phase("test", "inconclusive",
                        tests[0]["reason"] if tests else "no-candidate-model",
                        sites=tests, sites_accepted=0, sites_total=len(tests)))
  else:
    phases.append(phase("test", "ok", sites=tests, sites_accepted=len(accepted),
                        sites_total=len(tests)))
  phases.append(probe_model_reuse(fitted, oracles, width, domain))
  if lift.get("abi") == "buffer-in-out":
    sources = [lane["source"] for lane in lift["lanes"]]
    mapping = fit_source_map(sources, len(sources))
    phases.append(phase("index-map", "ok" if mapping["status"] == "ok" else "inconclusive",
                        mapping["reason"], **{k: v for k, v in mapping.items()
                                              if k not in ("status", "reason")}))
  return phases, fitted


def slice_family(oracles, width, domain=None):
  """Fit a one-operand family to any two-operand site that fit nothing whole.

  Reported only when the same grammar kind explains at least two slices: a
  relation that holds at a single pinned operand explains one example and is
  not a summary.
  """
  rows = []
  for site, oracle in sorted(oracles.items()):
    if getattr(oracle, "arity", 1) != 2:
      continue
    for fixed in SLICE_POINTS:
      view = SlicedOracle(oracle, fixed & mask_of(width))
      models = fit_models(view, width, domain)
      if not models:
        rows.append({"site": site, "pinned": fixed, "model": None,
                     "accepted": False, "reason": "no-candidate-model"})
        continue
      result = test_model(models[0], view, width, domain)
      rows.append({"site": site, "pinned": fixed, "model": models[0].describe(),
                   "accepted": result["accepted"], "reason": result["reason"]})
  if not rows:
    return None
  accepted = [r for r in rows if r["accepted"]]
  kinds = sorted({r["model"]["kind"] for r in accepted})
  if len(accepted) < 2:
    return phase("slice-family", "inconclusive", "single-site", slices=rows,
                 slices_accepted=len(accepted), slices_probed=len(rows),
                 note="fewer than two pinned slices are explained; this is not a summary")
  return phase("slice-family", "ok", slices=rows, slices_accepted=len(accepted),
               slices_probed=len(rows), kinds=kinds)


def worker(argv):
  """`extract_phases.py worker --spec S --out O`, run inside an analysis image."""
  p = argparse.ArgumentParser(prog="extract_phases worker")
  p.add_argument("--spec", type=Path, required=True)
  p.add_argument("--out", type=Path, required=True)
  args = p.parse_args(argv)
  spec = json.loads(args.spec.read_text())
  limits = dict({"seconds": 120, "steps": 4000, "paths": 32, "solver_ms": 5000},
                **spec.get("limits", {}))
  try:
    lift, oracles = lift_region(spec, limits)
    phases, _ = analyze(spec, lift, oracles)
    calls = sum(getattr(o, "calls", 0) for o in oracles.values())
    report = region_report(spec["region"], spec.get("adapter", "unknown"), phases,
                           interface=spec["interface"], limits=limits,
                           solver_queries=calls)
  except Exception as exc:
    report = region_report(spec["region"], spec.get("adapter", "unknown"),
                           [phase("lift", "inconclusive", "tool-error",
                                  detail=type(exc).__name__, message=str(exc)[:200])],
                           interface=spec["interface"], limits=limits)
  args.out.parent.mkdir(parents=True, exist_ok=True)
  args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
  return 0


def main(argv=None):
  argv = list(sys.argv[1:] if argv is None else argv)
  if argv and argv[0] == "worker":
    return worker(argv[1:])
  print(__doc__)
  return 0


if __name__ == "__main__":
  sys.exit(main())
