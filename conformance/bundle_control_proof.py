"""Informed translation validation of emitted persistent-control mixers.

Uses private final-IR names/metadata and a supplied report. Each participating
storage read is an unconstrained word, not a simulated application execution.
Proves the emitted key/salt slice, not storage initialization, whole-function
equivalence, binary discovery or attack cost. Unknown syntax fails closed.
"""
import argparse
import json
from pathlib import Path
import re
import time

from conformance.bundle_control import bundle_control_violations
from conformance.process import digest, dump
from conformance.relation_recovery import functions

VALUE = r"(?:%[\w.$-]+|-?\d+)"
ASSIGN = re.compile(r"\s*(%[\w.$-]+) = (.*)")


def symbolic_keys(key, salt, words, z3):
    for i, word in enumerate(words):
        w = (z3.Extract(31, 0, word) ^ z3.Extract(63, 32, word) if word.size() == 64 else
             z3.ZeroExt(32 - word.size(), word))
        key = key + (z3.RotateLeft(w, 5 + 7 * i) ^ (0x9e3779b9 * (i + 1)))
        salt = salt ^ (z3.RotateLeft(w, 3 + 5 * i) + w * (0x85ebca6b + 2 * i))
    return key, salt


def validate(text, report, milliseconds=3000):
    import z3
    errors = bundle_control_violations(report)
    if errors: raise ValueError("; ".join(errors))
    rows = [r for r in report.get("bundle_control", []) if r["status"] == "coupled"]
    if not rows: raise ValueError("no coupled roots to validate")
    metadata = dict(re.findall(r'^!(\d+) = !\{(.*)\}$', text, re.M))
    bodies, results = dict(functions(text)), []
    for row in rows:
        name, body = row["function"], bodies[row["function"]]
        roles = [w["role"] for w in row["words"]]
        width, pointers = row["words"][0]["width"], {}
        for line in body:
            if "!sre.native.bundle.control-bound " not in line: continue
            m = re.match(r"\s*(%[\w.$-]+) = alloca i(\d+),.*!sre.native.bundle.control-bound !(\d+)", line)
            if not m or int(m[2]) != width: raise ValueError("unknown bound storage")
            md = re.fullmatch(r'!"([^"]+)", !"([^"]+)", i1 (true|false)', metadata[m[3]])
            if not md or md[1] != row["bound_origin"] or md[2] not in roles:
                raise ValueError("unknown control storage identity")
            if md[2] in pointers.values(): raise ValueError("duplicate control storage")
            pointers[m[1]] = md[2]
        if set(pointers.values()) != set(roles): raise ValueError("missing bound storage")
        active, found = None, {"dispatcher": 0, "transition": 0}
        for line in body:
            is_read = "!sre.native.bundle.control-read " in line
            if not active and not is_read: continue
            assignment = ASSIGN.fullmatch(line)
            if not assignment: raise ValueError("non-straight-line mixer slice")
            result, rhs = assignment[1], re.sub(r", !.*$", "", assignment[2])
            if is_read:
                m = re.fullmatch(r"load volatile i(\d+), ptr (%[\w.$-]+), align \d+", rhs)
                if not m or int(m[1]) != width or m[2] not in pointers: raise ValueError("unproved mixer read")
                tag = re.search(r"!sre.native.bundle.control-read !(\d+)", line)[1]
                kind = { '!"dispatcher"': "dispatcher", '!"transition"': "transition" }.get(metadata[tag])
                if not kind: raise ValueError("unknown control-read kind")
                if active is None:
                    active = {"values": {}, "words": [], "inputs": {}, "kind": kind}
                index = len(active["words"])
                if index >= len(roles) or pointers[m[2]] != roles[index] or active["kind"] != kind:
                    raise ValueError("incomplete, reordered or mixed control tuple")
                value = z3.BitVec(f"word{index}", width)
                active["values"][result] = value
                active["words"].append(value)
                continue

            def word(token, bits):
                value = active["values"][token] if token.startswith("%") else z3.BitVecVal(int(token), bits)
                if value.size() != bits: raise ValueError("mixer operand-width mismatch")
                return value

            m = re.fullmatch(r"(add|mul|or|xor|shl|lshr) i(\d+) (" + VALUE + r"), (" + VALUE + r")", rhs)
            if m:
                op, bits, a, b = m[1], int(m[2]), m[3], m[4]
                slot = "key" if result.startswith("%sre.bundle.control.key") else "salt" if result.startswith("%sre.bundle.control.salt") else None
                if slot and slot not in active["inputs"]:
                    if bits != 32 or not a.startswith("%") or a in active["values"]:
                        raise ValueError("unexpected mixer input boundary")
                    active["inputs"][slot] = active["values"][a] = z3.BitVec("input_" + slot, 32)
                x, y = word(a, bits), word(b, bits)
                if op in ("shl", "lshr") and (b.startswith("%") or not 0 <= int(b) < bits):
                    raise ValueError("unproved mixer shift range")
                if op == "add": value = x + y
                elif op == "mul": value = x * y
                elif op == "or": value = x | y
                elif op == "xor": value = x ^ y
                elif op == "shl": value = x << y
                else: value = z3.LShR(x, y)
                active["values"][result] = value
                if slot: active[slot] = value
                if slot == "salt" and len(active["words"]) == len(roles):
                    expected = symbolic_keys(active["inputs"]["key"], active["inputs"]["salt"], active["words"], z3)
                    solver = z3.SolverFor("QF_BV")
                    solver.set(timeout=milliseconds)
                    solver.add(z3.Or(active["key"] != expected[0], value != expected[1]))
                    start = time.monotonic()
                    answer = solver.check()
                    item = {"function": name, "kind": active["kind"], "width": width, "words": len(roles),
                            "seconds": time.monotonic() - start,
                            "status": "proved" if answer == z3.unsat else "counterexample" if answer == z3.sat else "inconclusive"}
                    if answer == z3.sat: item["counterexample"] = str(solver.model())
                    elif answer == z3.unknown: item["reason"] = solver.reason_unknown()
                    results.append(item)
                    found[active["kind"]] += 1
                    active = None
            elif m := re.fullmatch(r"(zext|trunc) i(\d+) (" + VALUE + r") to i(\d+)", rhs):
                op, before, a, after = m[1], int(m[2]), m[3], int(m[4])
                x = word(a, before)
                if op == "zext" and after > before: value = z3.ZeroExt(after - before, x)
                elif op == "trunc" and after < before: value = z3.Extract(after - 1, 0, x)
                else: raise ValueError("invalid mixer conversion")
                active["values"][result] = value
            else:
                raise ValueError("unsupported mixer instruction: " + rhs[:160])
        if active or any(found[k] * len(roles) != row[k + "_reads"] for k in found):
            raise ValueError("incomplete emitted mixer inventory")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--milliseconds", type=int, default=3000)
    args = parser.parse_args()
    result = {"schema": "sre-bundle-control-proof-v1", "passed": False, "scope": "informed-emitted-key-salt-slices",
              "hardness_evaluated": False, "whole_function_equivalence": False}
    try:
        result.update(ir_sha256=digest(args.ir), report_sha256=digest(args.report))
        result["slices"] = validate(args.ir.read_text(), json.loads(args.report.read_text()), args.milliseconds)
        result["passed"] = all(r["status"] == "proved" for r in result["slices"])
    except (ValueError, KeyError, OSError, ImportError, TypeError) as exc:
        result.update(status="unsupported", reason=str(exc))
    dump(args.out, result)
    print(json.dumps({k: result.get(k) for k in ("passed", "status", "reason")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
