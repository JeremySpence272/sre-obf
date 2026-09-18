"""Bounded QF_BV proofs of reference transfer laws, NOT the entire LLVM pass.

All lanes are universally quantified by searching for a counterexample. A
timeout/unknown is inconclusive, never a successful proof or protection result.
Run in the pinned analysis image; no native target execution occurs here.

Two groups run by default.

  v03  the existing connected reference laws, unchanged.
  v04  the candidate transfer families in `conformance/transfer_model.py`:
       the encode/decode round trip, the rebase lemma, each transfer law, and
       the rejection criterion that forbids a recognizable decode inside a
       transfer. Every family law is stated over free state words, which is
       exactly the reachable state set because `encode_is_bijective` is checked
       on a complete domain in `conformance/test_transfer.py`.

`--group` narrows the run for iteration; the selection is recorded in the report
and `passed` then means only "for the groups that were run". A law that times
out is `inconclusive` and fails the run, at any width, in either group.

Every verdict is printed as it is decided, and a partial report is written
beside `--out` after each width, because the report is only useful if it
survives: an outer timeout that kills the run would otherwise discard every
completed width along with the unfinished one. A partial report carries
`complete: false`, lists the widths it reached, and can never say `passed`.
"""
import argparse
import json
import time
from pathlib import Path
from conformance.connected_model import (operations, add, compare,
                                         xor_to_additive, additive_to_xor,
                                         joint_mix, joint_unmix)
from conformance import transfer_model as tm

# Which family laws are attempted at which widths. The share networks are the
# expensive ones; they are attempted everywhere and recorded as inconclusive
# where the solver gives up, rather than quietly dropped.
CHEAP = ("xor", "and", "or", "shl", "lshr")
NEGATIVE = ("xor_sandwich", "add_sandwich", "mul_v03_refresh", "repair_sandwich",
            "add_wrapper")


def judge(z3, solver, answer, expect, seconds, record):
  status = ("proved" if answer == z3.unsat else
            "counterexample" if answer == z3.sat else "inconclusive")
  record.update(status=status, expect=expect, seconds=seconds,
                ok=status == expect)
  if answer == z3.unknown: record["reason"] = solver.reason_unknown()
  if answer == z3.sat and expect != "counterexample":
    record["model"] = str(solver.model())[:2000]
  return record


def run_claim(z3, milliseconds, claim, expect="proved", **fields):
  """Assert `claim` and report. `expect` says which answer the law needs."""
  solver = z3.SolverFor("QF_BV")
  solver.set(timeout=milliseconds)
  solver.add(claim)
  start = time.monotonic()
  answer = solver.check()
  record = judge(z3, solver, answer, expect, time.monotonic() - start, dict(fields))
  print(record.get("width"), record.get("law"), record["status"],
        "" if record["ok"] else f"(wanted {record['expect']})", flush=True)
  return record


def v03_cases(z3, width):
  """The existing connected reference laws, unchanged."""
  x, y, r, s = z3.BitVecs("x y r s", width)
  a, b = (x ^ r, r), (y ^ s, s)
  xor, inv, land, lor, shl, lshr = operations(width, z3.LShR)
  cases = [("and", land(a, b), x & y, "xor"),
           ("or", lor(a, b), x | y, "xor"),
           ("add", add(a, b, width, logical_shift=z3.LShR), x + y, "xor"),
           ("sub", add(a, inv(b), width, True, z3.LShR), x - y, "xor")]
  for name, signed, equality in (("eq", False, True), ("ult", False, False), ("slt", True, False)):
    expected = x == y if equality else x < y if signed else z3.ULT(x, y)
    cases.append((name, compare(a, b, width, signed, equality, z3.LShR),
                  z3.If(expected, z3.BitVecVal(1, width), z3.BitVecVal(0, width)), "xor"))
  # Additive multiplication used by arithmetic-only components.
  ae, be, mask = x + r, y + s, r ^ s
  affine = xor_to_additive(a, s, width)
  cases.append(("xor-to-additive", affine, x, "additive"))
  cases.append(("additive-to-xor", additive_to_xor(affine, r, s, width, z3.LShR), x, "xor"))
  cases.append(("affine-mul", (ae * be - (ae * s + be * r) + r * s + mask, mask), x * y, "additive"))
  # Bounded joint outputs U = X + Y and V = X + 2Y on encoded lanes, with
  # the exact inverse X = 2U - V, Y = V - U, in both families.
  for is_affine in (True, False):
    family = "additive" if is_affine else "xor"
    px = (ae, r) if is_affine else a
    py = (be, s) if is_affine else b
    u, v = joint_mix(px, py, width, is_affine, z3.LShR)
    rx, ry = joint_unmix(u, v, width, is_affine, z3.LShR)
    cases.append((f"joint-mix-u-{family}", u, x + y, family))
    cases.append((f"joint-mix-v-{family}", v, x + y + y, family))
    cases.append((f"joint-unmix-x-{family}", rx, x, family))
    cases.append((f"joint-unmix-y-{family}", ry, y, family))
  return cases


def family_sites(width):
  """The v04 candidates, their controls and their declared ablations."""
  return [("nlcarry-abstract", tm.NlCarryAbstract(width, 11, lanes=3, kernel="and")),
          ("nlcarry-and", tm.NlCarry(width, 11, lanes=3, kernel="and")),
          ("nlcarry-arx", tm.NlCarry(width, 11, lanes=3, kernel="arx")),
          ("tricouple", tm.TriCouple(width, 7)),
          ("arx-value", tm.ArxValue(width, 3, lanes=2))]


class SymbolicComparisons:
  """The comparison operations a specification needs, over bit-vector terms.

  The solver's `<` is signed and its `ULT` is unsigned; a specification written
  with Python's `<` would silently mean the wrong one here, which is how the
  first version of this runner produced a spurious counterexample.
  """

  def __init__(self, width, z3):
    self.width, self.z3 = width, z3

  def _bit(self, condition):
    return self.z3.If(condition, self.z3.BitVecVal(1, self.width),
                      self.z3.BitVecVal(0, self.width))

  def eq(self, a, b): return self._bit(a == b)
  def ult(self, a, b): return self._bit(self.z3.ULT(a, b))
  def slt(self, a, b): return self._bit(a < b)
  def umin(self, a, b): return self.z3.If(self.z3.ULT(a, b), a, b)


def symbolic_state(z3, site, suffix=""):
  return {word: z3.BitVec(f"{word}{suffix}", site.width) for word in site.state_words()}


def primitive_laws(z3, width, milliseconds, results):
  """Small lemmas that hold at every width and carry the wide-width argument.

  When a whole transfer law times out at 32 or 64 bits the composition of these
  with the v03 share-network law is what remains; that is a reviewed derivation
  resting on mechanized parts, and it is recorded as such rather than as a
  proof of the whole.
  """
  value = z3.BitVec("v", width)
  for amount in sorted({0, 1, width // 2, width - 1}):
    program = tm.Program("rot", width, ("v",))
    node = tm.rotl(program.input("v"), amount, width)
    name = node.name if isinstance(node, tm.Node) else "v"
    got = tm.evaluate(program, {"v": value}, tm.Symbolic(width, z3))[name]
    results.append(run_claim(z3, milliseconds, got != tm.ref_rotl(value, amount, width),
                             law=f"rotation-{amount}", width=width, group="v04",
                             kind="lemma"))
  e, m, q = z3.BitVecs("e m q", width)
  results.append(run_claim(z3, milliseconds, ((e ^ q) ^ m) ^ q != e ^ m,
                           law="rebase", width=width, group="v04", kind="lemma"))
  results.append(run_claim(z3, milliseconds, (e + e) != 2 * e,
                           law="doubling-is-an-addition", width=width, group="v04",
                           kind="lemma"))


# The rejection criterion asks whether an intermediate is a bijection of a
# logical value. Below this width that question cannot discriminate: at width 1
# the only bijections of a lane are identity and negation, so every
# mask-independent bit looks like a decode. The laws are still proved at the
# small widths, where complete enumeration is affordable; only the criterion is
# withheld, and the withholding is recorded.
EXPOSURE_MIN_WIDTH = 4


def family_laws(z3, width, milliseconds, results, quick):
  """Encode/decode, every transfer law, and the rejection criterion."""
  backend = tm.Symbolic(width, z3)
  comparisons = SymbolicComparisons(width, z3)
  if width < EXPOSURE_MIN_WIDTH:
    results.append({"law": "exposure-criterion", "width": width, "group": "v04",
                    "kind": "exposure", "status": "not-applicable",
                    "expect": "not-applicable", "ok": True,
                    "reason": f"a bijection of a {width}-bit logical value is not a "
                              "discriminating test; the criterion needs width "
                              f"{EXPOSURE_MIN_WIDTH} or more"})
  for label, site in family_sites(width):
    # A family outside its own declared domain is not instantiated. At width 1
    # every rotation is zero and every odd multiplier is one, so all the
    # carriers of `nlcarry` collapse to one function and its lanes share a
    # carrier; the transfers then genuinely do expose logical values, which says
    # nothing about the family and everything about running it where its
    # preconditions do not hold. The failure is recorded, never skipped, and i1
    # values belong to the separately typed predicate representation anyway.
    precondition = getattr(site, "distinct_carriers", None)
    if precondition is not None:
      report = precondition(trials=128)
      if not report["passed"]:
        results.append({"law": f"{label}:preconditions", "width": width,
                        "group": "v04", "kind": "precondition",
                        "status": "precondition-failed", "expect": "precondition-failed",
                        "ok": True, "clashes": report["clashes"],
                        "reason": "carriers are not distinct at this width, so the "
                                  "family is not instantiable here"})
        print(width, f"{label}:preconditions", "precondition-failed", flush=True)
        continue
    lanes = [z3.BitVec(f"x{i}", width) for i in range(site.n)]
    masks = [z3.BitVec(f"m{j}", width) for j in range(len(site.mask_words()))]
    encoded = site.reference_encode(lanes, masks)
    decoded = site.reference_decode(encoded)
    claim = z3.Or([decoded[i] != lanes[i] for i in range(site.n)])
    results.append(run_claim(z3, milliseconds, claim, law=f"{label}:round-trip",
                             width=width, group="v04", kind="law"))
    for name in site.transfer_names():
      try:
        transfer = site.build(name)
      except ValueError as error:
        results.append({"law": f"{label}:{name}", "width": width, "group": "v04",
                        "kind": "law", "status": "unavailable", "expect": "unavailable",
                        "ok": True, "reason": str(error)})
        continue
      if quick and name not in CHEAP and name not in NEGATIVE: continue
      state = symbolic_state(z3, site)
      before = site.reference_decode(state)
      _, produced = transfer.run(state, backend)
      if transfer.kind == "predicate":
        claim = produced != transfer.spec(before, comparisons)
      else:
        after = dict(enumerate(before))
        after.update(transfer.spec(before, comparisons))
        expected = site.reference_encode([after[i] for i in range(site.n)],
                                         [state[w] for w in site.mask_words()])
        claim = z3.Or([produced[w] != expected[w] for w in site.state_words()])
      # A concrete nlcarry law is an instance of the abstract one: the share
      # pair is (e_i, Q_i) whatever the kernel computes. It is still attempted,
      # because an instance failing would mean the abstraction is wrong, but an
      # inconclusive instance is covered by the abstract proof and says so.
      implied = (f"nlcarry-abstract:{name}"
                 if label.startswith("nlcarry") and label != "nlcarry-abstract" else None)
      results.append(run_claim(z3, milliseconds, claim, law=f"{label}:{name}",
                               width=width, group="v04", kind="law",
                               implied_by=implied))
      if width < EXPOSURE_MIN_WIDTH: continue
      if isinstance(site, tm.NlCarryAbstract):
        # Free carriers would assume away exactly the collapse the rejection
        # criterion is looking for, so exposure is only settled on concrete
        # kernels. The law above still covers every kernel.
        continue
      settle_exposure(z3, width, milliseconds, site, transfer, label, results)


def settle_exposure(z3, width, milliseconds, site, transfer, label, results):
  """Decide, universally, whether a suspect intermediate is lane determined.

  The concrete classifier proposes: an intermediate whose value never moved when
  the masks moved is a suspect. The solver disposes, with two copies of the
  program over the same logical values and different mask words. `unsat` means
  the intermediate is a function of the logical values alone -- a plaintext in a
  register. For a transfer that declares itself a negative control that is the
  expected answer; anywhere else it is a finding.
  """
  verdict = tm.classify(transfer, repeats=3, extra=4, mask_points=10)
  suspects = [n for n, v in verdict["verdicts"].items()
              if v in ("decode", "partial-plain")]
  if not suspects: return
  lanes = [z3.BitVec(f"lx{i}", width) for i in range(site.n)]
  count = len(site.mask_words())
  left = [z3.BitVec(f"lm{j}", width) for j in range(count)]
  right = [z3.BitVec(f"rm{j}", width) for j in range(count)]
  backend = tm.Symbolic(width, z3)
  a = tm.evaluate(transfer.program, site.reference_encode(lanes, left), backend)
  b = tm.evaluate(transfer.program, site.reference_encode(lanes, right), backend)
  for name in suspects[:8]:
    # The concrete evidence already says this intermediate did not move when the
    # masks moved. `unsat` upgrades that sample to the universal statement, so
    # "proved" is the expected answer for every suspect; what differs is how bad
    # it is. A bijection of a logical value is a recognizable decode and rejects
    # the candidate; a lossy function of the logical values is a partial
    # plaintext, which is recorded rather than used to reject.
    classified = verdict["verdicts"][name]
    severity = ("recognizable-decode" if classified == "decode" else "partial-plaintext")
    record = run_claim(z3, milliseconds, a[name] != b[name], expect="proved",
                       law=f"{label}:{transfer.name}:exposure:{name}", width=width,
                       group="v04", kind="exposure", classified=classified,
                       severity=severity, declared=transfer.expect)
    if record["status"] == "proved" and severity == "recognizable-decode" \
        and transfer.expect != "reject":
      record["finding"] = "recognizable decode inside a transfer declared acceptable"
      record["ok"] = False
    results.append(record)


def main():
  import z3
  p = argparse.ArgumentParser(description=__doc__)
  p.add_argument("--out", type=Path, required=True)
  p.add_argument("--milliseconds", type=int, default=10000)
  p.add_argument("--group", choices=("all", "v03", "v04"), default="all")
  p.add_argument("--widths", default="1,8,16,32,64")
  p.add_argument("--quick", action="store_true",
                 help="attempt only the bit-parallel transfers and the negative "
                      "controls, for iteration; the default attempts every law")
  args = p.parse_args()
  if args.out.exists() or not 1 <= args.milliseconds <= 60000:
    p.error("use a fresh output file and a 1..60000 millisecond per-law cap")
  widths = tuple(int(w) for w in args.widths.split(","))
  results = []
  if args.group in ("all", "v03"):
    for width in widths:
      for name, pair, expected, representation in v03_cases(z3, width):
        decoded = pair[0] - pair[1] if representation == "additive" else pair[0] ^ pair[1]
        results.append(run_claim(z3, args.milliseconds, decoded != expected,
                                 law=name, width=width, group="v03", kind="law"))
  if args.group in ("all", "v04"):
    for width in widths:
      primitive_laws(z3, width, args.milliseconds, results)
      family_laws(z3, width, args.milliseconds, results, args.quick)
      reached = [w for w in widths if w <= width]
      partial = args.out.with_suffix(".partial.json")
      partial.parent.mkdir(parents=True, exist_ok=True)
      partial.write_text(json.dumps(
          assemble(results, args, widths, z3, complete=False, reached=reached),
          indent=2) + "\n")
  report = assemble(results, args, widths, z3, complete=True)
  args.out.parent.mkdir(parents=True, exist_ok=True)
  args.out.write_text(json.dumps(report, indent=2) + "\n")
  return 0 if report["passed"] else 1


def assemble(results, args, widths, z3, complete, reached=None):
  """Build the report from whatever has been decided so far.

  Called after every width as well as at the end, because the report file is
  only meaningful if it survives: an outer timeout that kills the container
  otherwise discards every completed width along with the unfinished one.
  """
  groups, per_width = {}, {}
  for record in results:
    bucket = groups.setdefault(record.get("group", "v03"), {})
    bucket[record["status"]] = bucket.get(record["status"], 0) + 1
    # Raising the per-law cap is a legitimate choice only if its cost is
    # reported, so the wall time and the outcome mix are recorded per width.
    slot = per_width.setdefault(record["width"], {"seconds": 0.0})
    slot["seconds"] = round(slot["seconds"] + record.get("seconds", 0.0), 2)
    slot[record["status"]] = slot.get(record["status"], 0) + 1
  return {"schema": "sre-connected-reference-proofs-v2", "z3": z3.get_version_string(),
          "scope": "reference laws only; not LLVM lowering, memory safety, ABI, or hardness",
          "per_law_timeout_ms": args.milliseconds, "groups_run": args.group,
          "widths": list(widths), "quick": bool(args.quick),
          "summary": groups, "per_width": per_width,
          "solver_seconds": round(sum(r.get("seconds", 0.0) for r in results), 1),
          "results": results,
          "recognizable_decodes": [r["law"] for r in results
                                   if r.get("severity") == "recognizable-decode" and
                                   r["status"] == "proved"],
          "partial_plaintext_intermediates": [r["law"] for r in results
                                             if r.get("severity") == "partial-plaintext" and
                                             r["status"] == "proved"],
          "inconclusive_but_implied": [r["law"] for r in results
                                       if r["status"] == "inconclusive" and r.get("implied_by")],
          "complete": complete, "widths_reached": reached or list(widths),
          "passed": complete and all(r["ok"] for r in results)}


if __name__ == "__main__":
  raise SystemExit(main())
