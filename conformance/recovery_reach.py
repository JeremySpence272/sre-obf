"""Bounded symbolic reachability with explicit, private oracle/model assumptions.

No native execution, Unicorn, pickle, arbitrary Python expressions, or automatic
constructor execution. Run in the analysis container with an outer process cap.
An answer from this model is a candidate, not an independent correctness proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def validate(spec):
    if spec.get("schema") != "sre-symbolic-reach-v1":
        raise ValueError("unsupported replay schema")
    if spec.get("abi") not in ("main-argv", "buffer-length"):
        raise ValueError("unsupported ABI")
    if not 1 <= spec["input_bytes"] <= 256:
        raise ValueError("input size must be 1..256")
    if not 0 <= spec.get("byte_min", 0) <= spec.get("byte_max", 255) <= 255:
        raise ValueError("invalid byte domain")
    if len(spec.get("initial_stores", [])) > 4096 or len(spec.get("summaries", [])) > 128:
        raise ValueError("model size cap")
    if not spec.get("success") or len(spec["success"]) > 64 or len(spec.get("avoid", [])) > 128:
        raise ValueError("goal address cap")
    if len(spec.get("split_selects", [])) > 128:
        raise ValueError("split site cap")
    for store in spec.get("initial_stores", []):
        if store["bytes"] not in (1, 2, 4, 8):
            raise ValueError("invalid initialization width")
    for summary in spec.get("summaries", []):
        if summary["kind"] not in ("strlen-input", "memcpy", "scalar", "irrelevant-output"):
            raise ValueError("unsupported summary kind")
        if summary["kind"] == "scalar":
            check_expression(summary["expression"])
    for split in spec.get("split_selects", []):
        if split.get("condition") not in ("eq", "ne"):
            raise ValueError("only equality select splitting is supported")
        if not split.get("bytes_hex"):
            raise ValueError("select hook requires a binary-byte guard")
        for key in ("left", "right", "destination", "source"):
            if split[key] not in REGISTERS:
                raise ValueError("unsupported scalar register")
    return spec


REGISTERS = {prefix + reg for prefix in ("e", "r") for reg in ("ax", "bx", "cx", "dx", "si", "di")}


def check_expression(node, depth=0):
    if depth > 16 or not isinstance(node, dict) or node.get("width") not in (8, 16, 32, 64):
        raise ValueError("invalid expression width/depth")
    op = node.get("op")
    if op == "const":
        number(node["value"])
    elif op == "arg":
        if node["index"] not in (0, 1, 2, 3, 4, 5):
            raise ValueError("invalid scalar argument")
    elif op in ("xor", "and", "or", "add", "sub", "mul", "lshr", "shl"):
        if len(node.get("args", [])) != 2:
            raise ValueError("binary expression arity")
        for child in node["args"]:
            check_expression(child, depth + 1)
            if child["width"] != node["width"]:
                raise ValueError("expression widths must agree")
    elif op == "if-zero":
        if len(node.get("args", [])) != 3:
            raise ValueError("select expression arity")
        for child in node["args"]:
            check_expression(child, depth + 1)
        if any(child["width"] != node["width"] for child in node["args"][1:]):
            raise ValueError("select widths must agree")
    else:
        raise ValueError("unsupported scalar expression")


def expression(node, values, c):
    w, op = node["width"], node["op"]
    if op == "const":
        return c.BVV(number(node["value"]) % (1 << w), w)
    if op == "arg":
        value = values[node["index"]]
        return value[w - 1:0] if value.size() >= w else value.zero_extend(w - value.size())
    args = [expression(child, values, c) for child in node["args"]]
    if op == "if-zero":
        return c.If(args[0] == 0, args[1], args[2])
    x, y = args
    return {"xor": lambda: x ^ y, "and": lambda: x & y, "or": lambda: x | y,
            "add": lambda: x + y, "sub": lambda: x - y, "mul": lambda: x * y,
            "lshr": lambda: c.LShR(x, y), "shl": lambda: x << y}[op]()


def probe(binary, spec, seconds, steps, paths, summaries=True, split=True):
    import angr
    import claripy as c
    from angr.calling_conventions import SimCCSystemVAMD64
    from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeChar, SimTypeLongLong

    start = time.monotonic()
    p = angr.Project(str(binary), auto_load_libs=False)
    if p.arch.name != "AMD64":
        raise ValueError("only AMD64 SysV is supported")
    main = p.loader.main_object
    address = lambda x: number(x) + (main.mapped_base if spec.get("addresses") == "rva" else 0)
    stop, argv, buf = 0x7fff00000000, 0x7fff00100000, 0x7fff00200000
    n = spec["input_bytes"]
    secret = c.BVS("input", n * 8, explicit_name=True)
    pointer = SimTypePointer(SimTypeChar())
    if spec["abi"] == "main-argv":
        args = (2, argv)
        prototype = SimTypeFunction([SimTypeInt(), SimTypePointer(pointer)], SimTypeInt())
    else:
        args = (buf, n)
        prototype = SimTypeFunction([pointer, SimTypeLongLong(False)], SimTypeInt())
    state = p.factory.call_state(address(spec["entry"]), *args, ret_addr=stop,
        cc=SimCCSystemVAMD64(p.arch), prototype=prototype,
        remove_options={angr.options.UNICORN},
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
    state.solver._solver.timeout = 2000
    state.memory.store(buf, secret)
    state.memory.store(buf + n, c.BVV(0, 8))
    state.memory.store(argv, c.BVV(argv + 32, 64), endness="Iend_LE")
    state.memory.store(argv + 8, c.BVV(buf, 64), endness="Iend_LE")
    state.memory.store(argv + 16, c.BVV(0, 64), endness="Iend_LE")
    state.memory.store(argv + 32, b"binary\0")
    for byte in secret.chop(8):
        state.solver.add(byte >= spec.get("byte_min", 0), byte <= spec.get("byte_max", 255))
    for store in spec.get("initial_stores", []):
        state.memory.store(address(store["address"]), c.BVV(number(store["value"]), store["bytes"] * 8), endness="Iend_LE")

    def scalar_hook(tree):
        class Scalar(angr.SimProcedure):
            def run(self, a0, a1, a2, a3, a4, a5):
                value = expression(tree, [a0, a1, a2, a3, a4, a5], c)
                return value.zero_extend(64 - value.size())
        return Scalar()

    class InputLength(angr.SimProcedure):
        def run(self, pointer):
            if self.state.solver.satisfiable(extra_constraints=[pointer != buf]):
                raise ValueError("strlen summary applied to an unproven input pointer")
            if spec.get("byte_min", 0) == 0:
                raise ValueError("strlen summary needs a non-NUL domain")
            return n

    class Output(angr.SimProcedure):
        def run(self, destination, length, nonce):
            sizes = self.state.solver.eval_upto(length, 2)
            if len(sizes) != 1 or not 0 < sizes[0] <= 4096:
                raise ValueError("unsupported output-summary length")
            self.state.memory.store(destination, c.BVS("unmodeled_output", sizes[0] * 8))
            return 0

    if summaries:
        for hook in spec.get("summaries", []):
            kind = hook["kind"]
            model = scalar_hook(hook["expression"]) if kind == "scalar" else (
                InputLength() if kind == "strlen-input" else Output() if kind == "irrelevant-output"
                else angr.SIM_PROCEDURES["libc"]["memcpy"]())
            p.hook(address(hook["address"]), model)

    def split_hook(site):
        class Split(angr.SimProcedure):
            NO_RET = True
            def run(self):
                condition = getattr(self.state.regs, site["left"]) == getattr(self.state.regs, site["right"])
                if site["condition"] == "ne":
                    condition = ~condition
                taken, other = self.state.copy(), self.state.copy()
                setattr(taken.regs, site["destination"], getattr(taken.regs, site["source"]))
                target = address(site["next"])
                self.successors.add_successor(taken, target, condition, "Ijk_Boring")
                self.successors.add_successor(other, target, ~condition, "Ijk_Boring")
        return Split()

    if split:
        for site in spec.get("split_selects", []):
            at = address(site["address"])
            guard = bytes.fromhex(site["bytes_hex"])
            if p.loader.memory.load(at, len(guard)) != guard or address(site["next"]) != at + len(guard):
                raise ValueError("split-select byte/continuation guard failed")
            p.hook(at, split_hook(site))
    goals = {address(x) for x in spec["success"]}
    avoid = {address(x) for x in spec.get("avoid", [])} | {stop}
    sim = p.factory.simgr(state, save_unconstrained=True)
    count = 0
    result = {"status": "inconclusive", "reason": "no-modeled-goal", "mode": "oracle-symbolic-reach"}
    while sim.active and count <= steps and time.monotonic() - start < seconds:
        for active in sim.active:
            if active.addr in goals:
                variables = set().union(*(condition.variables for condition in active.solver.constraints))
                if variables - {"input"}:
                    result.update(reason="goal-depends-on-unmodeled-state", variables=sorted(variables))
                else:
                    value = active.solver.eval(secret, cast_to=bytes)
                    result.update(status="candidate", reason="model-goal-reached", input_hex=value.hex(),
                                  unique_in_model=not active.solver.satisfiable(extra_constraints=[secret != c.BVV(value)]))
                result.update(steps=count, seconds=round(time.monotonic() - start, 4))
                return result
        sim.move(from_stash="active", to_stash="avoided", filter_func=lambda s: s.addr in avoid)
        if not sim.active:
            break
        if count == steps or len(sim.active) > paths:
            break
        sim.step()
        count += 1
        if count % 128 == 0:
            # Keep current constraints and machine state, not an unbounded
            # printable history chain. No checkpoints or native execution.
            for active in sim.active:
                active.history.parent = None
    if sim.errored or sim.unconstrained or sim.deadended:
        result.update(reason="unmodeled-state-or-control", errors=len(sim.errored),
                      error_types=sorted({type(e.error).__name__ for e in sim.errored}))
    elif sim.active:
        result.update(status="budget", reason="time-step-or-path-cap")
    result.update(steps=count, seconds=round(time.monotonic() - start, 4), active_paths=len(sim.active))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--spec", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seconds", type=float, default=60)
    p.add_argument("--steps", type=int, default=10000)
    p.add_argument("--paths", type=int, default=64)
    p.add_argument("--no-summaries", action="store_true")
    p.add_argument("--no-split", action="store_true")
    args = p.parse_args()
    if min(args.seconds, args.steps, args.paths) <= 0 or args.out.exists():
        p.error("positive budgets and a fresh output directory are required")
    spec = validate(json.loads(args.spec.read_text()))
    sha = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    if sha != spec["binary_sha256"]:
        p.error("binary hash mismatch; port locations explicitly and retain the old spec")
    args.out.mkdir(parents=True)
    try:
        result = probe(args.binary, spec, args.seconds, args.steps, args.paths,
                       not args.no_summaries, not args.no_split)
    except Exception as exc:
        result = {"status": "inconclusive", "reason": type(exc).__name__, "detail": str(exc)[:512]}
    result.update(binary_sha256=sha, adapter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  spec_sha256=hashlib.sha256(args.spec.read_bytes()).hexdigest(),
                  summaries=not args.no_summaries, split_selects=not args.no_split,
                  assumptions="oracle locations and supplied initialization/summary semantics; not independently proved",
                  limits={key: getattr(args, key) for key in ("seconds", "steps", "paths")})
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
