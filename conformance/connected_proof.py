"""Bounded QF_BV proofs of reference transfer laws, NOT the entire LLVM pass.

All lanes are universally quantified by searching for a counterexample. A
timeout/unknown is inconclusive, never a successful proof or protection result.
Run in the pinned analysis image; no native target execution occurs here.
"""
import argparse
import json
import time
from pathlib import Path
from conformance.connected_model import operations, add, compare


def main():
    import z3
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--milliseconds", type=int, default=10000)
    args = p.parse_args()
    if args.out.exists() or not 1 <= args.milliseconds <= 60000:
        p.error("use a fresh output file and a 1..60000 millisecond per-law cap")
    results = []
    for width in (1, 8, 16, 32, 64):
        x, y, r, s = z3.BitVecs("x y r s", width)
        a, b = (x ^ r, r), (y ^ s, s)
        xor, inv, land, lor, shl, lshr = operations(width, z3.LShR)
        cases = [("and", land(a, b), x & y),
                 ("or", lor(a, b), x | y),
                 ("add", add(a, b, width, logical_shift=z3.LShR), x + y),
                 ("sub", add(a, inv(b), width, True, z3.LShR), x - y)]
        for name, signed, equality in (("eq", False, True), ("ult", False, False), ("slt", True, False)):
            expected = x == y if equality else x < y if signed else z3.ULT(x, y)
            cases.append((name, compare(a, b, width, signed, equality, z3.LShR),
                          z3.If(expected, z3.BitVecVal(1, width), z3.BitVecVal(0, width))))
        # Additive multiplication used by arithmetic-only components.
        ae, be, mask = x + r, y + s, r ^ s
        cases.append(("affine-mul", (ae * be - (ae * s + be * r) + r * s + mask, mask), x * y))
        for name, pair, expected in cases:
            solver = z3.SolverFor("QF_BV")
            solver.set(timeout=args.milliseconds)
            decoded = pair[0] - pair[1] if name == "affine-mul" else pair[0] ^ pair[1]
            solver.add(decoded != expected)
            start = time.monotonic()
            answer = solver.check()
            result = {"law": name, "width": width, "seconds": time.monotonic() - start,
                      "status": "proved" if answer == z3.unsat else "counterexample" if answer == z3.sat else "inconclusive"}
            if answer == z3.unknown: result["reason"] = solver.reason_unknown()
            if answer == z3.sat: result["model"] = str(solver.model())
            results.append(result)
            print(width, name, result["status"], flush=True)
    report = {"schema": "sre-connected-reference-proofs-v1", "z3": z3.get_version_string(),
              "scope": "reference laws only; not LLVM lowering, memory safety, ABI, or hardness",
              "per_law_timeout_ms": args.milliseconds, "results": results,
              "passed": all(r["status"] == "proved" for r in results)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
