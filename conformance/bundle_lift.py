"""Informed translation validation of the emitted straight-line bundle subset.

Fail closed on unknown instructions, branches, escaping/unknown memory, poison
shift amounts, or non-bundle storage. This is not a general LLVM interpreter or
a binary discovery attack. It does not ignore arbitrary volatile application IO.
"""
import argparse
import json
from pathlib import Path
import re
import time

from conformance.process import dump

VALUE = r"(?:%[\w.$-]+|-?\d+)"


def lift(text, function, arguments, z3):
    match = re.search(r"^define [^\n]*@" + re.escape(function) + r"\(([^\n]*)\)[^\n]*\{\n(.*?)^}", text, re.M | re.S)
    if not match:
        raise ValueError("missing callable root")
    parameters = re.findall(r"i(\d+)\s+(%[\w.$-]+)", match[1])
    if len(parameters) != len(arguments) or len(parameters) != 2:
        raise ValueError("unsupported argument interface")
    values, pointers, sizes, memory = {}, {}, {}, {}
    for (width, name), argument in zip(parameters, arguments):
        if argument.size() != int(width): raise ValueError("argument width mismatch")
        values[name] = argument
    def word(token, width):
        if token.startswith("%"):
            result = values[token]
            if result.size() != width: raise ValueError("operand width mismatch")
            return result
        return z3.BitVecVal(int(token), width)
    returned = None
    blocks = 0
    for source in match[2].splitlines():
        line = source.split(";", 1)[0].strip()
        if not line: continue
        if line.endswith(":"):
            blocks += 1
            if blocks != 1: raise ValueError("control flow unsupported by straight-line validator")
            continue
        owned = "!sre.native.bundle " in line
        line = re.sub(r", !.*$", "", line)
        result, rhs = (line.split(" = ", 1) if " = " in line else (None, line))
        if returned is not None: raise ValueError("instruction after return")
        if m := re.fullmatch(r"(add|sub|mul|and|or|xor|shl|lshr|ashr) i(\d+) (" + VALUE + r"), (" + VALUE + r")", rhs):
            op, width, a, b = m[1], int(m[2]), m[3], m[4]
            x, y = word(a, width), word(b, width)
            if op in ("shl", "lshr", "ashr") and (b.startswith("%") or not 0 <= int(b) < width):
                raise ValueError("unproved shift range")
            if op == "add": value = x + y
            elif op == "sub": value = x - y
            elif op == "mul": value = x * y
            elif op == "and": value = x & y
            elif op == "or": value = x | y
            elif op == "xor": value = x ^ y
            elif op == "shl": value = x << y
            elif op == "lshr": value = z3.LShR(x, y)
            else: value = x >> y
            values[result] = value
        elif m := re.fullmatch(r"freeze i(\d+) (" + VALUE + r")", rhs):
            # Only already-defined integer arguments/operations are admitted;
            # no undef/poison input is accepted by word().
            values[result] = word(m[2], int(m[1]))
        elif m := re.fullmatch(r"alloca \[(\d+) x i(\d+)\](?:, align \d+)?", rhs):
            if not owned: raise ValueError("unowned allocation")
            sizes[result] = (int(m[1]), int(m[2]))
            pointers[result] = (result, 0)
        elif m := re.fullmatch(r"getelementptr inbounds \[(\d+) x i(\d+)\], ptr (%[\w.$-]+), i32 0, i32 (\d+)", rhs):
            if not owned: raise ValueError("unowned address")
            base, old = pointers[m[3]]
            if old or sizes[base] != (int(m[1]), int(m[2])) or not 0 <= int(m[4]) < sizes[base][0]:
                raise ValueError("unknown/out-of-bounds object mapping")
            pointers[result] = (base, int(m[4]))
        elif m := re.fullmatch(r"store volatile i(\d+) (" + VALUE + r"), ptr (%[\w.$-]+)(?:, align \d+)?", rhs):
            if not owned: raise ValueError("unowned volatile store")
            ptr = pointers[m[3]]
            if sizes[ptr[0]][1] != int(m[1]): raise ValueError("partial store")
            memory[ptr] = word(m[2], int(m[1]))
        elif m := re.fullmatch(r"load volatile i(\d+), ptr (%[\w.$-]+)(?:, align \d+)?", rhs):
            if not owned: raise ValueError("unowned volatile load")
            ptr = pointers[m[2]]
            if sizes[ptr[0]][1] != int(m[1]): raise ValueError("partial load")
            if ptr not in memory: raise ValueError("uninitialized tuple read")
            values[result] = memory[ptr]
        elif m := re.fullmatch(r"ret i(\d+) (" + VALUE + r")", rhs):
            returned = word(m[2], int(m[1]))
        else:
            raise ValueError("unsupported emitted instruction: " + rhs[:160])
    if returned is None: raise ValueError("missing return")
    return returned


def validate(clean, emitted, function, width, milliseconds):
    import z3
    inputs = z3.BitVecs("input0 input1", width)
    a = lift(clean, function, inputs, z3)
    b = lift(emitted, function, inputs, z3)
    solver = z3.SolverFor("QF_BV")
    solver.set(timeout=milliseconds)
    solver.add(a != b)
    started = time.monotonic()
    answer = solver.check()
    result = {"status": "proved" if answer == z3.unsat else "counterexample" if answer == z3.sat else "inconclusive",
              "seconds": time.monotonic() - started, "width": width,
              "scope": "emitted-straight-line-defined-integer-domain",
              "private_memory_forwarded": True}
    if answer == z3.sat: result["counterexample"] = str(solver.model())
    if answer == z3.unknown: result["reason"] = solver.reason_unknown()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", type=Path, required=True)
    parser.add_argument("--emitted", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--function", default="kernel")
    parser.add_argument("--width", type=int, required=True, choices=(8, 16, 32, 64))
    parser.add_argument("--milliseconds", type=int, default=3000)
    args = parser.parse_args()
    result = {"schema": "sre-bundle-emitter-proof-v1", "passed": False}
    try:
        result.update(validate(args.clean.read_text(), args.emitted.read_text(),
                               args.function, args.width, args.milliseconds))
        result["passed"] = result["status"] == "proved"
    except (ValueError, KeyError, ImportError) as exc:
        result.update(status="unsupported", reason=str(exc))
    dump(args.out, result)
    print(json.dumps(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
