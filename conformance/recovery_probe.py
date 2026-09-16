"""Bounded, informed-entry *symbolic* lifting probe. Run in the analysis image.

Never executes the target natively; Unicorn is disabled. The entry and ABI are
oracle-supplied, so this measures recovery after discovery, not discovery itself.
No initializers are emulated: unsupported runtime initialization is inconclusive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time


def probe(args):
    import angr
    import claripy
    from angr.calling_conventions import SimCCSystemVAMD64
    from angr.sim_type import SimTypeFunction, SimTypeInt

    start = time.monotonic()
    project = angr.Project(str(args.binary), auto_load_libs=False)
    main = project.loader.main_object
    entry = args.entry + (main.mapped_base if main.pic else 0)
    x, y = claripy.BVS("x", 32, explicit_name=True), claripy.BVS("y", 32, explicit_name=True)
    stop = 0x7fff00000000
    state = project.factory.call_state(entry, x, y, ret_addr=stop,
        cc=SimCCSystemVAMD64(project.arch),
        prototype=SimTypeFunction([SimTypeInt(False), SimTypeInt(False)], SimTypeInt(False)),
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        remove_options={angr.options.UNICORN})
    state.solver._solver.timeout = 2000
    sim = project.factory.simgr(state, save_unconstrained=True)
    steps = 0
    while sim.active and steps < args.steps and time.monotonic() - start < args.seconds:
        sim.move(from_stash="active", to_stash="returned", filter_func=lambda s: s.addr == stop)
        if not sim.active:
            break
        if len(sim.active) + len(sim.stashes.get("returned", [])) > args.paths:
            break
        sim.step()
        steps += 1
    returned = sim.stashes.get("returned", [])
    result = {"mode": "oracle-entry-symbolic-no-native-execution", "steps": steps,
              "returned_paths": len(returned), "active_paths": len(sim.active),
              "errors": len(sim.errored), "unconstrained": len(sim.unconstrained),
              "status": "inconclusive"}
    if sim.errored or sim.unconstrained or sim.deadended:
        result["reason"] = "unsupported-state-or-control-flow"
    elif sim.active:
        result.update(status="budget", reason="time-step-or-path-cap")
    elif returned:
        expression = claripy.BVV(0, 32)
        covered = claripy.false()
        for s in returned:
            condition = claripy.And(*s.solver.constraints)
            covered = claripy.Or(covered, condition)
            expression = claripy.If(condition, s.regs.eax, expression)
        expression = claripy.simplify(expression)
        if (expression.variables | covered.variables) - {"x", "y"}:
            result["reason"] = "unmodeled-memory-registers-or-initializers"
        else:
            coverage_solver = claripy.Solver(timeout=2000)
            if coverage_solver.satisfiable(extra_constraints=[claripy.Not(covered)]):
                result["reason"] = "input-domain-incomplete"
            else:
                seen, work = set(), [expression]
                while work and len(seen) <= args.nodes:
                    node = work.pop()
                    if not isinstance(node, claripy.ast.Base) or node.hash() in seen:
                        continue
                    seen.add(node.hash())
                    work.extend(node.args)
                result.update(status="recovered" if not work else "lifted_large",
                              ast_nodes=len(seen), ast_depth=expression.depth)
                if not work:
                    text = claripy.backends.z3.convert(expression).sexpr()
                    if len(text) <= 1024 * 1024:
                        (args.out / "expression.smt2").write_text(text + "\n")
                    else:
                        result.update(status="lifted_large", reason="serialization-cap")
    else:
        result["reason"] = "no-return"
    result["seconds"] = round(time.monotonic() - start, 4)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--entry", required=True, type=lambda s: int(s, 0))
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--seconds", type=float, default=20)
    p.add_argument("--steps", type=int, default=512)
    p.add_argument("--paths", type=int, default=32)
    p.add_argument("--nodes", type=int, default=1000)
    args = p.parse_args()
    if min(args.seconds, args.steps, args.paths, args.nodes) <= 0:
        p.error("budgets must be positive")
    args.out.mkdir(parents=True, exist_ok=True)
    try:
        result = probe(args)
    except Exception as exc:
        result = {"status": "inconclusive", "reason": type(exc).__name__}
    result.update(binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  entry=args.entry, limits={k: getattr(args, k) for k in ("seconds", "steps", "paths", "nodes")})
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
