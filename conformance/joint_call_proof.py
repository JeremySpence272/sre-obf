"""Validate actual entry-mask slices against the supplied joint descriptor.

This uses private interface-stage IR, not binary-only discovery. Arguments are
unconstrained bit vectors. It proves only entry reconstruction laws: ownership,
caller lowering, useful consumer absorption and runtime semantics have separate
checks. Unknown syntax in a participating slice is rejected, not ignored.
"""
import argparse
import json
from pathlib import Path
import re
import time

from conformance.joint_call_check import joint_call_violations
from conformance.process import digest, dump

VALUE = r"(?:%[\w.$-]+|-?\d+)"


def validate(text, report, milliseconds=3000):
    import z3
    errors = joint_call_violations(report)
    if errors: raise ValueError("; ".join(errors))
    rows = [r for r in report.get("encoded_calls", [])
            if r.get("joint_arguments", {}).get("status") == "joint"]
    if not rows: raise ValueError("no joint interface to validate")
    results = []
    for row in rows:
        name, desc = row["encoded_function"], row["joint_arguments"]["descriptor"]
        match = re.search(r'^define [^\n]*@' + re.escape(name) + r'\(([^\n]*)\)[^\n]*\{\n(.*?)^}', text, re.M | re.S)
        if not match: raise ValueError("missing interface-stage definition")
        params = re.findall(r'i(\d+)\s+(%[\w.$-]+)', match[1])
        width, count = desc["width"], row["parameters"]
        if len(params) != count + 1 or any(int(w) != width for w, _ in params):
            raise ValueError("emitted ABI does not match joint argument descriptor")
        symbols = {arg: z3.BitVec(f"{name}/arg/{k}", width) for k, (_, arg) in enumerate(params)}
        expressions, roots = {}, []
        for line in match[2].splitlines():
            m = re.fullmatch(r'\s*(%[\w.$-]+) = (.*)', line)
            if not m: continue
            if m[1] in expressions: raise ValueError("duplicate SSA definition")
            expressions[m[1]] = re.sub(r', !.*$', '', m[2])
            if '!sre.native.call.arg ' in line: roots.append(m[1])
        if len(roots) != count: raise ValueError("missing or repeated argument reconstruction")
        active, cache = set(), dict(symbols)
        def word(token):
            if not token.startswith('%'): return z3.BitVecVal(int(token), width)
            if token in cache: return cache[token]
            if token in active: raise ValueError("cyclic argument slice")
            active.add(token)
            rhs = expressions.get(token, '')
            m = re.fullmatch(r'(add|sub|mul|xor|or|and|shl|lshr) i(\d+) (' + VALUE + r'), (' + VALUE + r')', rhs)
            if not m or int(m[2]) != width: raise ValueError("unsupported argument-mask slice")
            a, b = word(m[3]), word(m[4])
            op = m[1]
            if op in ('shl', 'lshr') and (m[4].startswith('%') or not 0 <= int(m[4]) < width):
                raise ValueError("unproved mask shift")
            value = {'add': lambda: a + b, 'sub': lambda: a - b, 'mul': lambda: a * b,
                     'xor': lambda: a ^ b, 'or': lambda: a | b, 'and': lambda: a & b,
                     'shl': lambda: a << b, 'lshr': lambda: z3.LShR(a, b)}[op]()
            active.remove(token); cache[token] = value
            return value
        coordinates = [symbols[arg] for _, arg in params[:-1]]
        carrier = symbols[params[-1][1]]
        for k, root in enumerate(roots):
            # Tie root order to actual formal operands; names are not proof.
            if not expressions[root].startswith(f'xor i{width} {params[k][1]}, '):
                raise ValueError("argument root mapped to wrong coordinate")
            previous = coordinates[k - 1] if k else carrier
            salt, rotation = int(desc['salts_hex'][k], 16), desc['rotations'][k]
            expected = coordinates[k] ^ (z3.RotateLeft((previous ^ salt) + carrier, rotation) ^ (previous * (salt | 1)))
            solver = z3.SolverFor('QF_BV'); solver.set(timeout=milliseconds)
            solver.add(word(root) != expected)
            started = time.monotonic(); answer = solver.check()
            result = {'function': name, 'argument': k, 'width': width,
                      'status': 'proved' if answer == z3.unsat else 'counterexample' if answer == z3.sat else 'inconclusive',
                      'seconds': time.monotonic() - started}
            if answer == z3.sat: result['counterexample'] = str(solver.model())
            if answer == z3.unknown: result['reason'] = solver.reason_unknown()
            results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--milliseconds', type=int, default=3000)
    args = parser.parse_args()
    result = {'scope': 'informed-emitted-joint-entry-slices', 'hardness_evaluated': False,
              'ir_sha256': digest(args.ir), 'report_sha256': digest(args.report), 'passed': False}
    try:
        result['cases'] = validate(args.ir.read_text(), json.loads(args.report.read_text()), args.milliseconds)
        result['passed'] = all(c['status'] == 'proved' for c in result['cases'])
    except (KeyError, TypeError, ValueError) as error:
        result['error'] = str(error)
    dump(args.out, result)
    print(json.dumps({'passed': result['passed'], 'error': result.get('error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
