"""Bounded *symbolic* lifting probe. Run in the analysis image.

Never executes the target natively; Unicorn is disabled. The ABI is supplied.
The entry comes either from private provenance (the supplied-region control) or
from `conformance/extract_discovery.py`, which found it from the binary alone;
this file is identical in both cases, which is what makes their costs comparable.
No initializers are emulated: unsupported runtime initialization is inconclusive.

On a successful lift it also evaluates the recovered expression at constructed
points, grouped into sites, and emits them for `conformance/recovery.py` to fit
and validate a model against. Those points are fixed and structural: no random
sampling, no known answers, and the points used as constructed positives are
disjoint from the points any model is fitted on.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time


# Constructed evaluation grid. Edges, small values and a few structured words.
# `SITES` are the second-argument values each site holds fixed; `POINTS` vary the
# first argument. `EXTRA` is disjoint from POINTS and supplies constructed
# positives at an unseen site, so a model is always asked about inputs it was
# never fitted on.
SITES = (0, 1, 0x9E3779B9)
POINTS = (0, 1, 2, 3, 7, 8, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x1234, 0x55555555, 0xDEADBEEF)
EXTRA_SITE = 0x0BADC0DE
EXTRA = (4, 5, 6, 9, 0x10001, 0x7FFFFFFE)


def evaluate(claripy, expression, x, y, start, args):
    """Concretize the recovered expression on the constructed grid.

    Evaluation goes through the solver rather than `replace`: angr 10 rebuilds
    the AST during execution, so substituting the wrapper objects this file
    created silently matches nothing and yields an empty grid. Asking for two
    solutions and keeping only unique ones is also the check that the expression
    is a function of the declared inputs; an input with two answers is dropped
    rather than resolved by taking the first.
    """
    def at(a, b):
        solver = claripy.Solver(timeout=2000)
        solver.add(x == claripy.BVV(a, 32))
        solver.add(y == claripy.BVV(b, 32))
        try:
            values = solver.eval(expression, 2)
        except Exception:
            return None
        return int(values[0]) if len(values) == 1 else None

    sites, positives, truncated = [], [], False
    for b in SITES:
        observations = []
        for a in POINTS:
            if time.monotonic() - start > args.seconds:
                truncated = True
                break
            value = at(a, b)
            if value is not None:
                observations.append([[a, b], value])
        if len(observations) >= 2:
            sites.append({"name": f"y=0x{b:x}", "observations": observations})
        if truncated:
            break
    for a in EXTRA:
        if truncated or time.monotonic() - start > args.seconds:
            truncated = True
            break
        value = at(a, EXTRA_SITE)
        if value is not None:
            positives.append([[a, EXTRA_SITE], value])
    detail = {"grid": "constructed-edges-and-structured-words", "truncated": truncated,
              "sites": len(sites), "points": sum(len(s["observations"]) for s in sites),
              "note": "constructed positives are disjoint from the fitted points"}
    if len(sites) < 2:
        # An empty or single-site grid is a failed evaluation, not a simple
        # answer. It must not reach the model fitter looking like evidence.
        detail["status"] = "insufficient"
        detail["reason"] = "grid-truncated" if truncated else "expression-not-a-function-of-declared-inputs"
    else:
        detail["status"] = "ok"
    return {"sites": sites, "positives": positives, "evaluation": detail}


def serialize(claripy, expression, out):
    """Write the recovered expression out, without letting that step lose a result.

    angr 10 does not expose `claripy.backends`, so the previous SMT-LIB dump
    raised `AttributeError` on exactly the successful path and the probe reported
    the recovery as `inconclusive`. A failure to pretty-print an expression we
    already hold is a reporting boundary, never a failed recovery, so the status
    is left alone and the serializer used is recorded.
    """
    for name, render in (("smt2", lambda: claripy.backends.z3.convert(expression).sexpr()),
                         ("claripy-repr", lambda: str(expression))):
        try:
            text = render()
        except Exception:
            continue
        if len(text) > 1024 * 1024:
            return {"status": "capped", "format": name, "bytes": len(text)}
        (out / ("expression." + ("smt2" if name == "smt2" else "txt"))).write_text(text + "\n")
        return {"status": "written", "format": name, "bytes": len(text)}
    return {"status": "unavailable", "reason": "no-serializer-in-this-image"}


def probe(args):
    import angr
    try:
        import claripy
    except ModuleNotFoundError:
        # angr 10 vendors the solver as angr.claripy. This is an import shim for
        # the available analysis image; it does not change what is measured.
        from angr import claripy
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
        # Name the obstacle. "Inconclusive" with no detail is indistinguishable
        # from protection when someone reads the table later, and it is not.
        try:
            result["error_classes"] = sorted({type(record.error).__name__
                                              for record in sim.errored})[:4]
            result["error_messages"] = sorted({str(record.error)[:160]
                                               for record in sim.errored})[:4]
        except Exception:
            result["error_classes"] = ["unavailable"]
        result["deadended"] = len(sim.deadended)
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
                result.update(evaluate(claripy, expression, x, y, start, args))
                if not work:
                    result["serialization"] = serialize(claripy, expression, args.out)
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
