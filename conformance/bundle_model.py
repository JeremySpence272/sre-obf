"""Bit-vector specification and independent oracle for triangular native bundles.

The specification knows the descriptor. Successful decoding is an inverse control,
not a binary-only extraction result. Correctness and protection are separate.
"""
from dataclasses import dataclass
from conformance import connected_model as cm

FAMILIES = ("triangular-xor-v1", "triangular-additive-v1")
OPCODES = ("add", "sub", "mul", "xor", "and", "or", "shl", "lshr", "ashr")


@dataclass(frozen=True)
class Descriptor:
    width: int
    family: str
    salts: tuple[int, ...]
    rotations: tuple[int, ...]

    def __post_init__(self):
        if self.width not in (2, 4, 8, 16, 32, 64) or self.family not in FAMILIES:
            raise ValueError("unsupported descriptor")
        if not 2 <= len(self.salts) <= 4 or len(self.rotations) != len(self.salts):
            raise ValueError("invalid lane count")
        if any(not 0 < r < self.width for r in self.rotations):
            raise ValueError("poison rotation")

    @classmethod
    def from_plan(cls, region):
        return cls(region["width"], region["family"],
                   tuple(int(s, 16) for s in region["salts_hex"]),
                   tuple(region["rotations"]))

    @property
    def bits(self):
        return (1 << self.width) - 1

    @property
    def additive(self):
        return self.family == FAMILIES[1]

    def mask(self, state, carrier, slot):
        a = state[slot - 1] if slot else carrier
        t = ((a ^ self.salts[slot]) + carrier) & self.bits
        r = self.rotations[slot]
        return (((t << r) | (t >> (self.width - r))) ^
                (a * (self.salts[slot] | 1))) & self.bits

    def encode(self, values, carrier):
        if len(values) != len(self.salts):
            raise ValueError("wrong logical tuple width")
        state = []
        for slot, value in enumerate(values):
            mask = self.mask(state, carrier, slot)
            state.append(((value + mask) if self.additive else (value ^ mask)) & self.bits)
        return tuple(state)

    def decode(self, state, carrier):
        if len(state) != len(self.salts):
            raise ValueError("wrong encoded tuple width")
        return tuple(((word - self.mask(state, carrier, k)) if self.additive else
                      (word ^ self.mask(state, carrier, k))) & self.bits
                     for k, word in enumerate(state))

    def update(self, state, carrier, destination, opcode, x, y):
        """Masked transfer followed by triangular downstream repair."""
        def read(operand):
            if "constant_hex" in operand:
                return int(operand["constant_hex"], 16) & self.bits, 0
            slot = operand["slot"]
            return state[slot], self.mask(state, carrier, slot)
        fresh = carrier ^ state[-1]
        result = pair_operation(opcode, read(x), read(y), self.width, self.additive, fresh)
        new = list(state)
        for k in range(destination, len(state)):
            old = result if k == destination else (state[k], self.mask(state, carrier, k))
            m = self.mask(new, carrier, k)
            new[k] = ((old[0] + m - old[1]) if self.additive else (old[0] ^ (old[1] ^ m))) & self.bits
        return tuple(new)

    def rebase(self, state, carrier, next_slots, new_carrier):
        """Move/rekey output coordinates into canonical recurrence input slots."""
        if not 2 <= len(next_slots) <= len(state) or any(not 0 <= k < len(state) for k in next_slots):
            raise ValueError("invalid recurrence mapping")
        old = [(state[k], self.mask(state, carrier, k)) for k in next_slots]
        new = []
        for k in range(len(state)):
            e, r = old[k] if k < len(old) else (0, 0)
            m = self.mask(new, new_carrier, k)
            new.append(((e + m - r) if self.additive else (e ^ (r ^ m))) & self.bits)
        return tuple(new)

    def next_carrier(self, state, carrier, phase):
        if phase not in (0, 1):
            raise ValueError("phase outside the finite graph")
        x, r = carrier ^ state[-1], self.rotations[-1]
        rotated = ((x << r) | (x >> (self.width - r))) & self.bits
        history = (rotated + (state[0] ^ self.salts[-1])) & self.bits
        return (history ^ ((phase ^ 1) * (self.salts[0] | 1))) & self.bits


def scalar(opcode, x, y, width):
    """Independent source semantics, including defined arithmetic right shift."""
    bits = (1 << width) - 1
    if opcode in ("shl", "lshr", "ashr") and not 0 <= y < width:
        raise ValueError("poison shift")
    if opcode == "add": out = x + y
    elif opcode == "sub": out = x - y
    elif opcode == "mul": out = x * y
    elif opcode == "xor": out = x ^ y
    elif opcode == "and": out = x & y
    elif opcode == "or": out = x | y
    elif opcode == "shl": out = x << y
    elif opcode == "lshr": out = (x & bits) >> y
    elif opcode == "ashr": out = ((x & bits) - ((1 << width) if x & (1 << (width - 1)) else 0)) >> y
    else: raise ValueError("unsupported operation")
    return out & bits


def pair_operation(opcode, x, y, width, additive, fresh):
    bits = (1 << width) - 1
    fresh &= bits
    xor, inv, land, lor, *_ = cm.operations(width)
    to_add = lambda z: cm.xor_to_additive_grouped(z, fresh, width)
    to_xor = lambda z: cm.additive_to_xor(z, fresh, fresh ^ bits, width)
    def product(a, b):
        return ((a[0] * b[0] + fresh - (a[0] * b[1] + b[0] * a[1]) +
                 a[1] * b[1]) & bits, fresh)
    if opcode in ("shl", "lshr", "ashr"):
        if y[1]:
            raise ValueError("shift amount must be unshared constant")
        a = to_xor(x) if additive else x
        out = tuple(scalar(opcode, p, y[0], width) for p in a)
        return to_add(out) if additive else out
    if additive:
        if opcode in ("add", "sub"):
            return tuple(scalar(opcode, a, b, width) for a, b in zip(x, y))
        if opcode == "mul": return product(x, y)
        # The emitter uses the complemented refresh for the second conversion;
        # that affects coordinates but not decoded semantics.
        other = cm.additive_to_xor(y, fresh ^ bits, fresh, width)
        return to_add(pair_operation(opcode, to_xor(x), other, width, False, fresh))
    if opcode == "xor": out = xor(x, y)
    elif opcode == "and": out = land(x, y)
    elif opcode == "or": out = lor(x, y)
    elif opcode == "add": out = cm.add(x, y, width)
    elif opcode == "sub": out = cm.add(x, inv(y), width, True)
    elif opcode == "mul":
        other = cm.xor_to_additive_grouped(y, fresh ^ bits, width)
        out = to_xor(product(to_add(x), other))
    else: raise ValueError("unsupported operation")
    return tuple(p & bits for p in out)


def replay(region, inputs):
    """Compare every emitted-plan step with scalar semantics; retain all outputs."""
    d = Descriptor.from_plan(region)
    if len(inputs) != region["inputs"]:
        raise ValueError("wrong input count")
    values = list(inputs) + [0] * (region["lanes"] - len(inputs))
    r = d.rotations[0]
    rotated = ((inputs[0] << r) | (inputs[0] >> (d.width - r))) & d.bits
    carrier = (rotated + (inputs[1] ^ d.salts[0])) & d.bits
    state = d.encode(values, carrier)
    def read(op):
        return int(op["constant_hex"], 16) & d.bits if "constant_hex" in op else values[op["slot"]]
    for step in region["steps"]:
        state = d.update(state, carrier, step["destination"], step["opcode"], step["x"], step["y"])
        values[step["destination"]] = scalar(step["opcode"], read(step["x"]), read(step["y"]), d.width)
        if d.decode(state, carrier) != tuple(values):
            raise AssertionError("bundle transfer differs from independent source semantics")
    return tuple(values[k] for k in region["output_slots"])


def replay_loop(region, inputs, iterations):
    """Informed recurrence control: every transfer/rebase vs scalar semantics.

    Iteration count is supplied, not inferred from a branch. Zero returns entry
    inputs; positive counts return all scheduled outputs of the last iteration.
    """
    if region["loop"]["status"] != "encoded" or iterations < 0:
        raise ValueError("requires encoded recurrence and nonnegative trip count")
    if len(inputs) != region["inputs"]:
        raise ValueError("wrong input count")
    d = Descriptor.from_plan(region)
    values = list(inputs) + [0] * (region["lanes"] - len(inputs))
    r = d.rotations[0]
    carrier = ((((inputs[0] << r) | (inputs[0] >> (d.width - r))) & d.bits) +
               (inputs[1] ^ d.salts[0])) & d.bits
    state, phase = d.encode(values, carrier), 0
    result = tuple(inputs)
    for _ in range(iterations):
        for step in region["steps"]:
            def read(op):
                return int(op["constant_hex"], 16) & d.bits if "constant_hex" in op else values[op["slot"]]
            state = d.update(state, carrier, step["destination"], step["opcode"], step["x"], step["y"])
            values[step["destination"]] = scalar(step["opcode"], read(step["x"]), read(step["y"]), d.width)
            if d.decode(state, carrier) != tuple(values):
                raise AssertionError("recurrence transfer differs from scalar semantics")
        result = tuple(values[k] for k in region["output_slots"])
        mapping = region["loop"]["next_input_slots"]
        new_carrier = carrier
        if region["loop"]["phase_mode"] == "two-phase":
            new_carrier = d.next_carrier(state, carrier, phase)
            phase ^= 1
        state = d.rebase(state, carrier, mapping, new_carrier)
        values = [values[k] for k in mapping] + [0] * (region["lanes"] - len(mapping))
        carrier = new_carrier
        if d.decode(state, carrier) != tuple(values):
            raise AssertionError("backedge rebase differs from scalar recurrence")
    return result
