"""Candidate v04 transfer families as offline reference models, never a compiler.

This file is research support for plan workstream W1. Nothing here is lowered,
nothing here is emitted, and nothing here measures hardness. Each family is a
*candidate*: a forward law, its preconditions, an exact inverse, and an
independent reference model. A candidate is believed only when three separate
things agree, and it is rejected outright when the fourth test fires.

  1. `reference_*`  plain algebraic Python written from the specification;
  2. `Program`      the straight-line operation list a planner would lower,
                    obtained by tracing ordinary Python through `Node`;
  3. the law        decode(transfer(Z)) == F(decode(Z)), checked by complete
                    enumeration at small widths here and by bounded QF_BV proof
                    in `conformance/connected_proof.py` at 8/16/32/64;
  4. `classify`     every non-constant intermediate of a transfer program must
                    depend on the runtime mask words. An intermediate that is
                    determined by the logical lane values alone is a plaintext
                    in a register: that is exactly the "one original instruction
                    between two recognizable inverses" the plan rejects, so a
                    candidate containing one is rejected here.

No number here is a difficulty measurement. `constant_readback_attack` decodes
every family in this file exactly, because a carrier's rotation amounts,
multipliers and constants are operands of emitted instructions and an analyst
reads them rather than searching for them. The algebraic fits below measure
whether a *generic* attack that ignores the emitted constants succeeds, which is
a much weaker question and the only one they answer.

Rule 4 is a rejection criterion only. The masks are ordinary program values that
the analyst can read, so mask dependence is necessary for a candidate to be
interesting and is nowhere near sufficient for it to be hard. No score is
derived from it.

Bit-vector discipline. Every value is masked to the declared width. Shift
amounts are compile-time constants in 0..width-1, because an out-of-range shift
is poison rather than defined wrapping; `Concrete.shl`/`lshr` raise instead of
silently modelling poison. Rotation by zero emits nothing. Doubling is emitted
as an addition, never a one-bit shift, so that width 1 stays legal. Unsigned
overflow is defined and is used deliberately.
"""
from __future__ import annotations

import itertools
import random

def seeded(parts):
  """Deterministic RNG from a structured label. Stdlib seeds must be scalars."""
  return random.Random("|".join(repr(part) for part in parts))


WIDTHS = (1, 2, 4, 8, 16, 32, 64)
IR_WIDTHS = (8, 16, 32, 64)  # the homogeneous vector widths W1 starts from
SHIFTS = ("shl", "lshr")


# --------------------------------------------------------------------------
# Straight-line program: what a planner would lower.
# --------------------------------------------------------------------------

class Program:
  """An SSA operation list over one homogeneous width, built by tracing."""

  def __init__(self, name, width, free):
    if width not in WIDTHS: raise ValueError(f"unsupported width {width}")
    self.name, self.width, self.free = name, width, tuple(free)
    self.mask = (1 << width) - 1
    self.steps, self.counter = [], 0
    self.nodes = {n: Node(self, n) for n in self.free}

  def input(self, name):
    if name not in self.nodes: raise KeyError(name)
    return self.nodes[name]

  def emit(self, op, *args):
    name = f"t{self.counter}"
    self.counter += 1
    self.steps.append((name, op, args))
    node = Node(self, name)
    self.nodes[name] = node
    return node

  def constant(self, value):
    return Const(self, value & self.mask)

  def shift(self, amount):
    """Shift amounts are constants and must be in range; poison is not modelled."""
    if not isinstance(amount, int) or not 0 <= amount < self.width:
      raise ValueError(f"out-of-range shift {amount} at width {self.width}")
    return amount

  @property
  def size(self): return len(self.steps)

  def text(self):
    out = [f"; {self.name} width={self.width} free={','.join(self.free)}"]
    for name, op, args in self.steps:
      out.append(f"  {name} = {op} " + ", ".join(str(a) for a in args))
    return "\n".join(out)


class Const:
  """A compile-time constant operand. Constants are not mask words."""

  def __init__(self, program, value):
    self.program, self.value = program, value

  def __repr__(self): return f"#{self.value}"


def _operand(program, value):
  if isinstance(value, Node): return value.name
  if isinstance(value, Const): return value.value
  if isinstance(value, int): return value & program.mask
  raise TypeError(type(value))


class Node:
  """A traced SSA value. Python operators on it emit instructions."""

  __slots__ = ("program", "name")

  def __init__(self, program, name):
    self.program, self.name = program, name

  def __repr__(self): return self.name

  def _binary(self, op, other, reflected=False):
    p = self.program
    if isinstance(other, int) and not isinstance(other, bool):
      if op == "and" and (other & p.mask) == p.mask: return self  # width mask: no-op
      if op in ("xor", "or", "add", "sub") and (other & p.mask) == 0 and not reflected:
        return self
      if op == "mul" and (other & p.mask) == 1 and not reflected: return self
      if op == "xor" and (other & p.mask) == p.mask: return p.emit("inv", self.name)
    a, b = (other, self) if reflected else (self, other)
    return p.emit(op, _operand(p, a), _operand(p, b))

  def __xor__(self, other): return self._binary("xor", other)
  def __rxor__(self, other): return self._binary("xor", other, True)
  def __and__(self, other): return self._binary("and", other)
  def __rand__(self, other): return self._binary("and", other, True)
  def __or__(self, other): return self._binary("or", other)
  def __ror__(self, other): return self._binary("or", other, True)
  def __add__(self, other): return self._binary("add", other)
  def __radd__(self, other): return self._binary("add", other, True)
  def __sub__(self, other): return self._binary("sub", other)
  def __rsub__(self, other): return self._binary("sub", other, True)
  def __mul__(self, other): return self._binary("mul", other)
  def __rmul__(self, other): return self._binary("mul", other, True)

  def __lshift__(self, amount):
    p = self.program
    return self if p.shift(amount) == 0 else p.emit("shl", self.name, amount)

  def lshr(self, amount):
    p = self.program
    return self if p.shift(amount) == 0 else p.emit("lshr", self.name, amount)

  def __rshift__(self, amount): return self.lshr(amount)


def logical_shift(value, amount):
  """The `logical_shift` hook `connected_model` takes, for traced values."""
  return value.lshr(amount)


def rotl(value, amount, width):
  """Rotation as two in-range shifts; amount 0 emits nothing at any width."""
  amount %= width
  if amount == 0: return value
  return (value << amount) | value.lshr(width - amount)


def double(value):
  """A doubling is an addition. A one-bit shift would be poison at width 1."""
  return value + value


# --------------------------------------------------------------------------
# Backends that evaluate a Program.
# --------------------------------------------------------------------------

class Concrete:
  """Concrete bit-vector semantics. Poison is rejected, never modelled."""

  kind = "concrete"

  def __init__(self, width):
    self.width, self.mask = width, (1 << width) - 1

  def const(self, value): return value & self.mask
  def add(self, a, b): return (a + b) & self.mask
  def sub(self, a, b): return (a - b) & self.mask
  def mul(self, a, b): return (a * b) & self.mask
  def xor(self, a, b): return (a ^ b) & self.mask
  def and_(self, a, b): return a & b & self.mask
  def or_(self, a, b): return (a | b) & self.mask
  def inv(self, a): return a ^ self.mask

  def shl(self, a, k):
    if not 0 <= k < self.width: raise ValueError("out-of-range shift")
    return (a << k) & self.mask

  def lshr(self, a, k):
    if not 0 <= k < self.width: raise ValueError("out-of-range shift")
    return (a & self.mask) >> k


class Symbolic:
  """QF_BV semantics over z3, used only by the bounded proof runner."""

  kind = "symbolic"

  def __init__(self, width, z3):
    self.width, self.z3 = width, z3

  def const(self, value): return self.z3.BitVecVal(value, self.width)
  def add(self, a, b): return a + b
  def sub(self, a, b): return a - b
  def mul(self, a, b): return a * b
  def xor(self, a, b): return a ^ b
  def and_(self, a, b): return a & b
  def or_(self, a, b): return a | b
  def inv(self, a): return ~a

  def shl(self, a, k):
    if not 0 <= k < self.width: raise ValueError("out-of-range shift")
    return a << k

  def lshr(self, a, k):
    if not 0 <= k < self.width: raise ValueError("out-of-range shift")
    return self.z3.LShR(a, k)


METHOD = {"add": "add", "sub": "sub", "mul": "mul", "xor": "xor", "and": "and_",
          "or": "or_", "inv": "inv", "shl": "shl", "lshr": "lshr"}


def evaluate(program, env, backend):
  """Run a program. Returns every intermediate, keyed by SSA name."""
  if backend.width != program.width: raise ValueError("width mismatch")
  values = dict(env)
  missing = [n for n in program.free if n not in values]
  if missing: raise KeyError(f"unbound inputs {missing}")
  for name, op, args in program.steps:
    call = getattr(backend, METHOD[op])
    if op in SHIFTS:
      values[name] = call(values[args[0]], args[1])
    else:
      operands = [values[a] if isinstance(a, str) else backend.const(a) for a in args]
      values[name] = call(*operands)
  return values


# --------------------------------------------------------------------------
# Reference primitives: written separately from the traced path on purpose.
# --------------------------------------------------------------------------

def ref_lshr(value, amount, width):
  """Logical right shift, correct for a concrete int and for a bit-vector term.

  A symbolic `>>` is an arithmetic shift, so the high bits are masked off
  explicitly. Writing it this way rather than reusing the emitted `lshr` opcode
  keeps the reference independent of the traced program.
  """
  if not 0 <= amount < width: raise ValueError("out-of-range shift")
  return (value >> amount) & ((1 << (width - amount)) - 1)


def ref_shl(value, amount, width):
  if not 0 <= amount < width: raise ValueError("out-of-range shift")
  return (value << amount) & ((1 << width) - 1)


def ref_rotl(value, amount, width):
  """Rotation, independent of the traced `rotl`.

  For a concrete value this is the bit-index definition, kept deliberately
  unlike the emitted form. A symbolic bit-vector takes a compact equivalent
  instead, because the bit-index form explodes inside a multi-round network and
  every query over one then times out; the `rotation-*` lemmas in
  `connected_proof.py` prove the two forms equal at every width and amount, so
  the substitution rests on a mechanized fact rather than on inspection.
  """
  amount %= width
  if isinstance(value, int):
    bits = [(value >> i) & 1 for i in range(width)]
    return sum(bits[(i - amount) % width] << i for i in range(width))
  if amount == 0: return value
  return ref_shl(value, amount, width) | ref_lshr(value, width - amount, width)


def ref_double(value, width): return (value + value) & ((1 << width) - 1)


def odd_constant(rng, width): return (rng.getrandbits(width) | 1) & ((1 << width) - 1)


def rot_amount(rng, width): return rng.randrange(1, width) if width > 1 else 0


def inverse_odd(value, width):
  if value % 2 == 0: raise ValueError("multiplier must be odd to be invertible")
  return pow(value, -1, 1 << width)


# --------------------------------------------------------------------------
# Seeded reversible network (family ingredient 2 of W1).
# --------------------------------------------------------------------------

class ArxNetwork:
  """A seeded reversible network over `words` lanes at one width.

  Steps are drawn from modular addition, XOR, odd multiplication, rotation and
  triangular/Feistel coupling. Every step is a bijection of the whole word
  tuple, so the composition is a bijection and `invert` is exact by
  construction: it is the reversed list of per-step inverses.

  Preconditions: `words >= 1`; a `couple` step needs `words >= 2` and distinct
  lanes; multipliers are odd; rotation amounts lie in 0..width-1 and a zero
  rotation emits nothing. Nothing here is a claim about diffusion quality.
  """

  KINDS = ("mul", "addc", "xorc", "rot", "couple_add", "couple_xor", "swap")

  def __init__(self, width, seed, words=2, rounds=3, allow=KINDS, pattern="random"):
    if width not in WIDTHS: raise ValueError(f"unsupported width {width}")
    if words < 1: raise ValueError("need at least one lane")
    self.width, self.seed, self.words, self.rounds = width, seed, words, rounds
    self.mask = (1 << width) - 1
    self.pattern = pattern
    rng = seeded(("arx", width, seed, words, rounds, pattern))
    if pattern == "mixer":
      if words != 2: raise ValueError("the mixer pattern is defined for two words")
      self.steps = []
      for _ in range(rounds):
        self.steps += [
            ("couple_xor", 0, 1, rot_amount(rng, width), odd_constant(rng, width)),
            ("mul", 0, odd_constant(rng, width)),
            ("rot", 0, rot_amount(rng, width)),
            ("couple_add", 1, 0, rot_amount(rng, width), odd_constant(rng, width)),
            ("couple_add", 0, 1, rot_amount(rng, width), odd_constant(rng, width)),
            ("xorc", 0, rng.getrandbits(width))]
      return
    kinds = [k for k in allow if words >= 2 or not k.startswith(("couple", "swap"))]
    self.steps = []
    for _ in range(rounds):
      for lane in range(words):
        kind = kinds[rng.randrange(len(kinds))]
        if kind == "mul":
          self.steps.append(("mul", lane, odd_constant(rng, width)))
        elif kind == "addc":
          self.steps.append(("addc", lane, rng.getrandbits(width)))
        elif kind == "xorc":
          self.steps.append(("xorc", lane, rng.getrandbits(width)))
        elif kind == "rot":
          self.steps.append(("rot", lane, rot_amount(rng, width)))
        elif kind == "swap":
          other = (lane + 1 + rng.randrange(words - 1)) % words
          self.steps.append(("swap", lane, other))
        else:
          other = (lane + 1 + rng.randrange(words - 1)) % words
          self.steps.append((kind, lane, other, rot_amount(rng, width),
                             odd_constant(rng, width)))

  # -- traced forward/inverse -------------------------------------------

  def _kernel(self, value, rot, mul):
    """The nonlinear round kernel of a coupling step, on traced values."""
    return rotl(value, rot, self.width) ^ (value * mul)

  def apply(self, words):
    z = list(words)
    for step in self.steps:
      kind, lane = step[0], step[1]
      if kind == "mul": z[lane] = z[lane] * step[2]
      elif kind == "addc": z[lane] = z[lane] + step[2]
      elif kind == "xorc": z[lane] = z[lane] ^ step[2]
      elif kind == "rot": z[lane] = rotl(z[lane], step[2], self.width)
      elif kind == "swap": z[lane], z[step[2]] = z[step[2]], z[lane]
      elif kind == "couple_add": z[lane] = z[lane] + self._kernel(z[step[2]], step[3], step[4])
      else: z[lane] = z[lane] ^ self._kernel(z[step[2]], step[3], step[4])
    return z

  def invert(self, words):
    z = list(words)
    for step in reversed(self.steps):
      kind, lane = step[0], step[1]
      if kind == "mul": z[lane] = z[lane] * inverse_odd(step[2], self.width)
      elif kind == "addc": z[lane] = z[lane] - step[2]
      elif kind == "xorc": z[lane] = z[lane] ^ step[2]
      elif kind == "rot": z[lane] = rotl(z[lane], self.width - (step[2] % self.width), self.width)
      elif kind == "swap": z[lane], z[step[2]] = z[step[2]], z[lane]
      elif kind == "couple_add": z[lane] = z[lane] - self._kernel(z[step[2]], step[3], step[4])
      else: z[lane] = z[lane] ^ self._kernel(z[step[2]], step[3], step[4])
    return z

  # -- independent integer reference ------------------------------------

  def ref_kernel(self, value, rot, mul):
    return ref_rotl(value, rot, self.width) ^ ((value * mul) & self.mask)

  def ref_apply(self, words):
    z = [w & self.mask for w in words]
    for step in self.steps:
      kind, lane = step[0], step[1]
      if kind == "mul": z[lane] = (z[lane] * step[2]) & self.mask
      elif kind == "addc": z[lane] = (z[lane] + step[2]) & self.mask
      elif kind == "xorc": z[lane] = z[lane] ^ step[2]
      elif kind == "rot": z[lane] = ref_rotl(z[lane], step[2], self.width)
      elif kind == "swap": z[lane], z[step[2]] = z[step[2]], z[lane]
      elif kind == "couple_add":
        z[lane] = (z[lane] + self.ref_kernel(z[step[2]], step[3], step[4])) & self.mask
      else: z[lane] = z[lane] ^ self.ref_kernel(z[step[2]], step[3], step[4])
    return z

  def ref_invert(self, words):
    z = [w & self.mask for w in words]
    for step in reversed(self.steps):
      kind, lane = step[0], step[1]
      if kind == "mul": z[lane] = (z[lane] * inverse_odd(step[2], self.width)) & self.mask
      elif kind == "addc": z[lane] = (z[lane] - step[2]) & self.mask
      elif kind == "xorc": z[lane] = z[lane] ^ step[2]
      elif kind == "rot":
        z[lane] = ref_rotl(z[lane], self.width - (step[2] % self.width), self.width)
      elif kind == "swap": z[lane], z[step[2]] = z[step[2]], z[lane]
      elif kind == "couple_add":
        z[lane] = (z[lane] - self.ref_kernel(z[step[2]], step[3], step[4])) & self.mask
      else: z[lane] = z[lane] ^ self.ref_kernel(z[step[2]], step[3], step[4])
    return z

  def preconditions(self):
    return {"width": self.width, "words": self.words, "rounds": self.rounds,
            "multipliers_odd": True, "rotations_in_range": True,
            "shift_amounts_constant": True,
            "inverse": "reversed list of per-step inverses, exact by construction"}


# --------------------------------------------------------------------------
# Sites: a family instantiated at one width with one seed.
# --------------------------------------------------------------------------

from conformance.connected_model import (add as share_add, compare as share_compare,
                                         operations as share_ops, pair_add, pair_sub,
                                         additive_to_xor, xor_to_additive,
                                         xor_to_additive_grouped, affine_mul_grouped)


def store(pair, carrier):
  """Rebase a share pair onto a destination carrier without forming the value."""
  e, m = pair
  return (e ^ carrier) ^ m


def store_decoded(pair, carrier):
  """The rejected grouping: `e ^ m` is the plain value, in a register."""
  e, m = pair
  return (e ^ m) ^ carrier


class Comparisons:
  """Comparisons and unsigned minimum over concrete bit-vectors.

  A specification that says `a < b` cannot be shared between a concrete and a
  symbolic backend: Python `<` on ints is unsigned for masked values while a
  solver's `<` on bit-vectors is signed. The operations a specification needs
  are named here instead, and the proof runner supplies the solver's versions.
  """

  def __init__(self, width):
    self.width, self.mask = width, (1 << width) - 1

  def _signed(self, value):
    sign = 1 << (self.width - 1)
    return ((value & self.mask) ^ sign) - sign

  def eq(self, a, b): return int((a & self.mask) == (b & self.mask))
  def ult(self, a, b): return int((a & self.mask) < (b & self.mask))
  def slt(self, a, b): return int(self._signed(a) < self._signed(b))
  def umin(self, a, b): return min(a & self.mask, b & self.mask)


class Transfer:
  """One candidate transfer: the program a planner would lower, plus its law.

  `reference` is deliberately the specification-level implementation -- decode,
  apply F, re-encode. That is the very shape the plan forbids emitting, so the
  law `program == reference` says the program computes the right thing while
  `classify` says it does not compute it the forbidden way.
  """

  def __init__(self, name, site, program, outputs=None, spec=None,
               predicate=None, note="", expect="accept", source_ops=1):
    self.name, self.site, self.program = name, site, program
    self.outputs, self.spec, self.predicate = outputs or {}, spec, predicate
    self.note, self.expect = note, expect
    # How many operations of the original program this transfer stands for.
    # A candidate that stands for one operation is the shape the plan warns
    # about; the ratio of emitted instructions to this number is the cost a
    # planner is paying for that coverage.
    self.source_ops = source_ops
    self.kind = "predicate" if predicate else "state"

  @property
  def identifier(self): return f"{self.site.identifier}:{self.name}"

  def reference(self, state):
    """decode, apply the source operation, re-encode with the same masks."""
    lanes = self.site.reference_decode(state)
    updated = dict(enumerate(lanes))
    updated.update(self.spec(lanes))
    masks = [state[w] for w in self.site.mask_words()]
    return self.site.reference_encode([updated[i] for i in range(len(lanes))], masks)

  def run(self, state, backend):
    values = evaluate(self.program, state, backend)
    if self.kind == "predicate":
      names = self.predicate
      return values, backend.xor(values[names[0]], values[names[1]])
    produced = dict(state)
    for word, ssa in self.outputs.items(): produced[word] = values[ssa]
    return values, produced


class Site:
  """One family at one width with one seed. Subclasses supply the laws."""

  family, version = "", ""
  ablation = False

  def __init__(self, width, seed, lanes=2):
    if width not in WIDTHS: raise ValueError(f"unsupported width {width}")
    self.width, self.seed, self.n = width, seed, lanes
    self.mask = (1 << width) - 1

  @property
  def identifier(self): return f"{self.family}-{self.version}"

  def state_words(self): raise NotImplementedError
  def mask_words(self): raise NotImplementedError
  def reference_encode(self, lanes, masks): raise NotImplementedError
  def reference_decode(self, state): raise NotImplementedError
  def preconditions(self): raise NotImplementedError
  def transfer_names(self): return ()
  def build(self, kind, **kw): raise ValueError(f"{self.identifier} has no transfer {kind}")

  def program(self, name):
    return Program(f"{self.identifier}:{name}", self.width, self.state_words())

  def sample(self, rng):
    return ([rng.getrandbits(self.width) for _ in range(self.n)],
            [rng.getrandbits(self.width) for _ in range(len(self.mask_words()))])

  def sample_state(self, rng):
    lanes, masks = self.sample(rng)
    return self.reference_encode(lanes, masks), lanes, masks

  def domain_size(self):
    return 1 << (self.width * (self.n + len(self.mask_words())))

  def enumerate_domain(self):
    """Every (lanes, masks) pair. Only call where the domain is small."""
    count = self.n + len(self.mask_words())
    for index in range(1 << (self.width * count)):
      values = [(index >> (self.width * k)) & self.mask for k in range(count)]
      yield values[:self.n], values[self.n:]

  def encode_is_bijective(self):
    """Complete check that (lanes, masks) <-> state is a bijection.

    Surjectivity matters: the proofs below quantify over every state tuple, so
    they are only about reachable states if every tuple is reachable.
    """
    seen, total = set(), 0
    for lanes, masks in self.enumerate_domain():
      state = self.reference_encode(lanes, masks)
      seen.add(tuple(state[w] for w in self.state_words()))
      total += 1
    return total == len(seen) and total == self.domain_size()


class XorPair(Site):
  """Baseline control: X = e ^ m, the v03 XOR family."""

  family, version = "xor-pair", "v1"

  def state_words(self): return tuple(f"e{i}" for i in range(self.n)) + ("m",)
  def mask_words(self): return ("m",)

  def reference_encode(self, lanes, masks):
    state = {"m": masks[0] & self.mask}
    for i, x in enumerate(lanes): state[f"e{i}"] = (x ^ masks[0]) & self.mask
    return state

  def reference_decode(self, state):
    return [state[f"e{i}"] ^ state["m"] for i in range(self.n)]

  def preconditions(self):
    return {"decode": "X_i = e_i ^ m", "linear_over_gf2": True,
            "role": "baseline control", "mask_is_runtime_value": True}


class AdditivePair(Site):
  """Baseline control: X = e - m, the v03 additive family."""

  family, version = "additive-pair", "v1"

  def state_words(self): return tuple(f"e{i}" for i in range(self.n)) + ("m",)
  def mask_words(self): return ("m",)

  def reference_encode(self, lanes, masks):
    state = {"m": masks[0] & self.mask}
    for i, x in enumerate(lanes): state[f"e{i}"] = (x + masks[0]) & self.mask
    return state

  def reference_decode(self, state):
    return [(state[f"e{i}"] - state["m"]) & self.mask for i in range(self.n)]

  def preconditions(self):
    return {"decode": "X_i = e_i - m mod 2^w", "affine_over_ring": True,
            "role": "baseline control", "mask_is_runtime_value": True}


class UnimodularPair(Site):
  """Baseline control: the v03 joint outputs U = X0 + X1, V = X0 + 2*X1.

  The mixing matrix has determinant one, so the exact inverse is
  X0 = 2U - V, X1 = V - U. Both the mixing and the masking are affine.
  """

  family, version = "unimodular-uv", "v1"

  def __init__(self, width, seed, lanes=2):
    if lanes != 2: raise ValueError("the unimodular control mixes exactly two lanes")
    super().__init__(width, seed, lanes)

  def state_words(self): return ("u", "v", "m")
  def mask_words(self): return ("m",)

  def reference_encode(self, lanes, masks):
    x, y = lanes[0] & self.mask, lanes[1] & self.mask
    return {"u": (x + y + masks[0]) & self.mask,
            "v": (x + 2 * y + masks[0]) & self.mask, "m": masks[0] & self.mask}

  def reference_decode(self, state):
    u = (state["u"] - state["m"]) & self.mask
    v = (state["v"] - state["m"]) & self.mask
    return [(2 * u - v) & self.mask, (v - u) & self.mask]

  def preconditions(self):
    return {"decode": "X0 = 2(u-m) - (v-m), X1 = (v-m) - (u-m)",
            "determinant": 1, "affine_over_ring": True, "role": "baseline control"}


class BitslicePermutation(Site):
  """Declared ablation, not a family: a seeded linear bit permutation.

  The plan is explicit that plain bitslicing or a bit permutation alone is an
  ablation, because linear algebra may undo it cheaply. It is kept here so the
  fitting attacks have something they are expected to break immediately, and so
  that "a new family name" cannot be claimed for it.
  """

  family, version = "bitslice-permutation", "v1-ablation"
  ablation = True

  def __init__(self, width, seed, lanes=2):
    super().__init__(width, seed, lanes)
    rng = seeded(("bitperm", width, seed, lanes))
    self.perm = list(range(self.width))
    rng.shuffle(self.perm)
    self.keys = [rng.getrandbits(self.width) for _ in range(lanes)]

  def _permute(self, value):
    return sum(((value >> i) & 1) << self.perm[i] for i in range(self.width))

  def _unpermute(self, value):
    return sum(((value >> self.perm[i]) & 1) << i for i in range(self.width))

  def state_words(self): return tuple(f"e{i}" for i in range(self.n)) + ("m",)
  def mask_words(self): return ("m",)

  def reference_encode(self, lanes, masks):
    state = {"m": masks[0] & self.mask}
    for i, x in enumerate(lanes):
      state[f"e{i}"] = self._permute(x & self.mask) ^ masks[0] ^ self.keys[i]
    return state

  def reference_decode(self, state):
    return [self._unpermute(state[f"e{i}"] ^ state["m"] ^ self.keys[i])
            for i in range(self.n)]

  def preconditions(self):
    return {"decode": "X_i = P^-1(e_i ^ m ^ k_i)", "linear_over_gf2": True,
            "role": "ablation, expected to fall to a GF(2) fit"}


class ArxValue(Site):
  """A seeded reversible network applied to the logical values themselves.

  Verified bijection with an exact inverse. It is recorded as a *negative*
  candidate for W1: the only lowering of a useful operation available here is
  the decode/F/encode wrapper the plan rejects, because the network does not
  commute with the operation.
  """

  family, version = "arx-value", "v1"

  def __init__(self, width, seed, lanes=2, rounds=3):
    super().__init__(width, seed, lanes)
    self.net = ArxNetwork(self.width, ("arx-value", seed), words=lanes, rounds=rounds)

  def state_words(self): return tuple(f"z{i}" for i in range(self.n)) + ("m",)
  def mask_words(self): return ("m",)

  def reference_encode(self, lanes, masks):
    mixed = self.net.ref_apply([(x ^ masks[0]) & self.mask for x in lanes])
    state = {f"z{i}": mixed[i] for i in range(self.n)}
    state["m"] = masks[0] & self.mask
    return state

  def reference_decode(self, state):
    plain = self.net.ref_invert([state[f"z{i}"] for i in range(self.n)])
    return [(p ^ state["m"]) & self.mask for p in plain]

  def preconditions(self):
    return dict(self.net.preconditions(),
                decode="X_i = invert(Z)_i ^ m",
                role="negative candidate: no closed-form transfer found")

  def transfer_names(self): return ("add_wrapper",)

  def build(self, kind, **kw):
    if kind != "add_wrapper": return super().build(kind, **kw)
    prog = self.program(kind)
    z = {n: prog.input(n) for n in self.state_words()}
    plain = self.net.invert([z[f"z{i}"] for i in range(self.n)])
    lanes = [p ^ z["m"] for p in plain]
    lanes[0] = lanes[0] + lanes[1]
    mixed = self.net.apply([x ^ z["m"] for x in lanes])
    outputs = {f"z{i}": mixed[i].name for i in range(self.n)}
    def spec(values, ops=None): return {0: (values[0] + values[1]) & self.mask}
    return Transfer("add_wrapper", self, prog, outputs=outputs, spec=spec,
                    expect="reject",
                    note="the only lowering found: decode, add, re-encode")


# --------------------------------------------------------------------------
# Candidate family 1: a nonlinear carrier over shared runtime mask words.
# --------------------------------------------------------------------------

class NlCarry(Site):
  """`nlcarry`: X_i = e_i ^ Q_i, with Q_i a seeded nonlinear kernel of two
  shared runtime mask words m0, m1.

  Forward law   e_i = X_i ^ Q_i(m0, m1)
  Inverse       X_i = e_i ^ Q_i(m0, m1), exact, because XOR is an involution
                and Q_i does not read any e.
  Preconditions the two mask words are ordinary live program values, not
                constants; rotation amounts are constants in 0..w-1;
                multipliers are odd; no shift is ever emitted with an amount
                outside 0..w-1, so width 1 is legal.

  Every lane shares the same two mask words, so the lanes stay jointly
  dependent: a consumer that wants one lane must still evaluate the kernel over
  the words that every other lane also uses. The share pair (e_i, Q_i) is a v03
  XOR pair, so the v03 transfer networks apply unchanged and their existing
  bounded proofs are inherited rather than reproved from scratch.

  Kernels. `linear` is an ablation: Q is GF(2)-affine, so the whole decode is
  affine and a linear fit recovers it. `and` is quadratic, `mul` uses modular
  multiplication so the algebraic degree of bit k grows with k, and `arx` is a
  seeded reversible mixing network. The attacks below report which fall.
  """

  family, version = "nlcarry", "v1"
  KERNELS = ("linear", "and", "mul", "arx")

  def __init__(self, width, seed, lanes=2, kernel="arx"):
    super().__init__(width, seed, lanes)
    if kernel not in self.KERNELS: raise ValueError(f"unknown kernel {kernel}")
    self.kernel = kernel
    self.ablation = kernel == "linear"
    rng = seeded(("nlcarry", width, seed, lanes, kernel))
    # Two extra carriers beyond the lanes. Constants and refreshes are carried
    # on those, never on an operand's own carrier: two share pairs that meet in
    # one operation must not share a carrier, or the mask cancels and the
    # propagate share is the plain value. `distinct_carriers` checks it.
    self.carriers = lanes + 2
    # Rotation pairs are drawn without replacement: two carriers built from the
    # same pair are the same function, and then the lanes using them cancel.
    # Below width 4 there are not enough pairs, and `distinct_carriers` says so
    # rather than the family pretending otherwise.
    self.rot, taken = [], set()
    for _ in range(self.carriers):
      pair = (rot_amount(rng, self.width), rot_amount(rng, self.width))
      attempts = 0
      while pair in taken and attempts < 256:
        pair = (rot_amount(rng, self.width), rot_amount(rng, self.width))
        attempts += 1
      taken.add(pair)
      self.rot.append(pair)
    self.nets = ([ArxNetwork(self.width, ("nlcarry", seed, i), words=2, rounds=2,
                             pattern="mixer") for i in range(self.carriers)]
                 if kernel == "arx" else [])

  @property
  def identifier(self): return f"{self.family}-{self.kernel}-{self.version}"

  def state_words(self): return tuple(f"e{i}" for i in range(self.n)) + ("m0", "m1")
  def mask_words(self): return ("m0", "m1")

  def carrier(self, m0, m1, index, reference=False):
    """Q_index. `reference` selects the independent integer implementation."""
    p, q = self.rot[index]
    if reference:
      rot, mask = ref_rotl, self.mask
      if self.kernel == "linear": return rot(m0, p, self.width) ^ rot(m1, q, self.width)
      if self.kernel == "and": return rot(m0, p, self.width) & rot(m1, q, self.width)
      if self.kernel == "mul":
        return rot((m0 * m1) & mask, p, self.width) ^ rot(m0, q, self.width)
      return self.nets[index].ref_apply([m0, m1])[0]
    if self.kernel == "linear":
      return rotl(m0, p, self.width) ^ rotl(m1, q, self.width)
    if self.kernel == "and":
      return rotl(m0, p, self.width) & rotl(m1, q, self.width)
    if self.kernel == "mul":
      return rotl(m0 * m1, p, self.width) ^ rotl(m0, q, self.width)
    return self.nets[index].apply([m0, m1])[0]

  def reference_encode(self, lanes, masks):
    m0, m1 = masks[0] & self.mask, masks[1] & self.mask
    state = {"m0": m0, "m1": m1}
    for i, x in enumerate(lanes):
      state[f"e{i}"] = (x & self.mask) ^ self.carrier(m0, m1, i, reference=True)
    return state

  def reference_decode(self, state):
    return [state[f"e{i}"] ^ self.carrier(state["m0"], state["m1"], i, reference=True)
            for i in range(self.n)]

  def distinct_carriers(self, trials=256, seed=0, complete=False):
    """No two carriers may be the same function of the mask words.

    A collision makes two lanes share a carrier, and then any transfer that
    combines those lanes cancels the mask and computes on plain values. Seeded
    parameters do collide: at width 4 the `mul` kernel collides for two lanes
    under some seeds, which is why this is a precondition and not a comment.
    """
    rng = seeded(("distinct", seed, self.identifier))
    points = list(enumerate_masks(self)) if complete else \
        [self.sample(rng)[1] for _ in range(trials)]
    clashes = []
    for a in range(self.carriers):
      for b in range(a + 1, self.carriers):
        if all(self.carrier(m0, m1, a, reference=True) ==
               self.carrier(m0, m1, b, reference=True) for m0, m1 in points):
          clashes.append((a, b))
    return {"site": self.identifier, "width": self.width, "complete": bool(complete),
            "points": len(points), "clashes": clashes, "passed": not clashes}

  def preconditions(self):
    return {"decode": "X_i = e_i ^ Q_i(m0, m1)", "kernel": self.kernel,
            "carriers": self.carriers, "auxiliary_carriers": 2,
            "distinct_carriers_required": True,
            "mask_words_are_runtime_values": True,
            "rotations": self.rot, "shift_amounts_constant_in_range": True,
            "lanes": self.n, "width": self.width,
            "linear_over_gf2": self.kernel == "linear",
            "role": "ablation" if self.ablation else "candidate"}

  # -- transfer construction -------------------------------------------

  def transfer_names(self):
    return ("xor", "and", "or", "add", "sub", "addc", "shl", "lshr", "mul",
            "mul_v03_refresh", "cmp_ult", "cmp_eq", "cmp_slt", "select",
            "combined", "xor_sandwich", "add_sandwich")

  def carriers_from(self, z):
    return [self.carrier(z["m0"], z["m1"], i) for i in range(self.carriers)]

  def _open(self, name):
    prog = self.program(name)
    z = {n: prog.input(n) for n in self.state_words()}
    carriers = self.carriers_from(z)
    pairs = [(z[f"e{i}"], carriers[i]) for i in range(self.n)]
    return prog, z, carriers, pairs

  def _const_pair(self, carrier, value):
    """A constant carried in the same representation; never a bare literal."""
    return ((carrier ^ (value & self.mask)), carrier)

  def build(self, kind, i=0, j=1, k=0, amount=None, constant=3):
    ops = share_ops(self.width, logical_shift)
    pxor, inv, land, lor, pshl, plshr = ops
    prog, z, carriers, pairs = self._open(kind)
    aux0, aux1 = carriers[self.n], carriers[self.n + 1]
    word = f"e{k}"

    def finish(pair, spec, note="", expect="accept", grouping=store, source_ops=1):
      out = grouping(pair, carriers[k])
      return Transfer(kind, self, prog, outputs={word: out.name}, spec=spec,
                      note=note, expect=expect, source_ops=source_ops)

    if kind in ("xor", "and", "or", "add", "sub"):
      table = {"xor": (pxor, lambda a, b: a ^ b),
               "and": (land, lambda a, b: a & b),
               "or": (lor, lambda a, b: a | b),
               "add": (lambda x, y: share_add(x, y, self.width, False, logical_shift),
                       lambda a, b: (a + b) & self.mask),
               "sub": (lambda x, y: share_add(x, inv(y), self.width, True, logical_shift),
                       lambda a, b: (a - b) & self.mask)}
      share_op, plain_op = table[kind]
      pair = share_op(pairs[i], pairs[j])
      return finish(pair, lambda v, ops=None: {k: plain_op(v[i], v[j])},
                    note=f"X{k} = X{i} {kind} X{j} on share pairs, no decode")

    if kind == "addc":
      pair = share_add(pairs[i], self._const_pair(aux0, constant),
                       self.width, False, logical_shift)
      return finish(pair, lambda v, ops=None: {k: (v[i] + constant) & self.mask},
                    note="the constant is carried encoded, never as a bare literal")

    if kind in ("shl", "lshr"):
      if self.width == 1:
        raise ValueError("no nonzero shift amount is in range at width 1; "
                         "a doubling is emitted as an addition instead")
      amount = self.width // 2 if amount is None else amount
      if not 0 <= amount < self.width: raise ValueError("out-of-range shift")
      pair = (pshl if kind == "shl" else plshr)(pairs[i], amount)
      plain = (lambda a: ref_shl(a, amount, self.width)) if kind == "shl" else \
              (lambda a: ref_lshr(a, amount, self.width))
      return finish(pair, lambda v, ops=None: {k: plain(v[i])},
                    note=f"{kind} by the constant {amount}, in range at this width")

    if kind in ("mul", "mul_v03_refresh"):
      # Multiply needs the additive view: convert, multiply, convert back.
      convert = xor_to_additive_grouped if kind == "mul" else xor_to_additive
      ax = convert(pairs[i], aux0, self.width)
      ay = convert(pairs[j], aux1, self.width)
      r, s = ax[1], ay[1]
      product = (affine_mul_grouped(ax, ay, self.width) if kind == "mul" else
                 (ax[0] * ay[0] - (ax[0] * s + ay[0] * r) + r * s + (r ^ s), r ^ s))
      pair = additive_to_xor(product, carriers[i], carriers[j], self.width, logical_shift)
      return finish(pair, lambda v, ops=None: {k: (v[i] * v[j]) & self.mask},
                    expect="accept" if kind == "mul" else "reject",
                    note="v03 xor_to_additive materializes the plain value"
                         if kind != "mul" else "grouped conversion, additive multiply")

    if kind.startswith("cmp_"):
      signed, equality = {"cmp_ult": (False, False), "cmp_eq": (False, True),
                          "cmp_slt": (True, False)}[kind]
      pair = share_compare(pairs[i], pairs[j], self.width, signed, equality, logical_shift)
      def spec(v, ops=None):
        ops = ops or Comparisons(self.width)
        return (ops.eq if equality else ops.slt if signed else ops.ult)(v[i], v[j])
      return Transfer(kind, self, prog, predicate=(pair[0].name, pair[1].name),
                      spec=spec,
                      note="i1 predicate: separately typed, lowered as trunc to i1")

    if kind == "select":
      cond = share_compare(pairs[i], pairs[j], self.width, False, False, logical_shift)
      widened = share_add(inv(cond), (aux0, aux0), self.width, True, logical_shift)
      pair = pxor(land(widened, pairs[i]), land(inv(widened), pairs[j]))
      return finish(pair, lambda v, ops=None:
                    {k: (ops or Comparisons(self.width)).umin(v[i], v[j])},
                    source_ops=2,
                    note="predicate widened to a full-width mask inside the shares")

    if kind == "combined":
      if self.n < 3: raise ValueError("the combined transfer needs three lanes")
      total = share_add(pairs[0], pairs[1], self.width, False, logical_shift)
      u = pxor(total, pairs[2])
      v = share_add(land(pairs[0], pairs[1]), u, self.width, False, logical_shift)
      out0, out1 = store(u, carriers[0]), store(v, carriers[1])
      def spec(values, ops=None):
        u_value = ((values[0] + values[1]) & self.mask) ^ values[2]
        return {0: u_value, 1: ((values[0] & values[1]) + u_value) & self.mask}
      return Transfer(kind, self, prog, outputs={"e0": out0.name, "e1": out1.name},
                      spec=spec, source_ops=4,
                      note="four source operations, three inputs, two real outputs")

    if kind == "xor_sandwich":
      pair = pxor(pairs[i], pairs[j])
      return finish(pair, lambda v, ops=None: {k: v[i] ^ v[j]}, expect="reject",
                    grouping=store_decoded,
                    note="rejected grouping: forms the plain result in a register")

    if kind == "add_sandwich":
      prog2 = self.program(kind)
      z2 = {n: prog2.input(n) for n in self.state_words()}
      carriers2 = self.carriers_from(z2)
      x = z2[f"e{i}"] ^ carriers2[i]
      y = z2[f"e{j}"] ^ carriers2[j]
      out = (x + y) ^ carriers2[k]
      return Transfer(kind, self, prog2, outputs={word: out.name},
                      spec=lambda v, ops=None: {k: (v[i] + v[j]) & self.mask}, expect="reject",
                      note="adjacent decode/F/encode wrapper, the shape the plan forbids")

    return super().build(kind)


# --------------------------------------------------------------------------
# Candidate family 2: a triangular chain, where one lane carries the next.
# --------------------------------------------------------------------------

class NlCarryAbstract(NlCarry):
  """`nlcarry` with the carriers left uninterpreted.

  No transfer law here depends on what a kernel computes: the share pair is
  (e_i, Q_i) whatever Q_i is, and the v03 networks are correct for any pair.
  Proving the laws with the carriers as free words therefore proves them for
  every kernel at once, and keeps the query small enough to decide at 32 and 64
  bits -- which the concrete network kernel is not, because its modular
  multiplications put the bounded QF_BV queries out of reach.

  It says nothing about the rejection criterion. There the correlations between
  concrete carriers are exactly what matters, and free carriers would assume
  away the collapse that a repeated or colliding carrier causes. Exposure stays
  measured per kernel on the concrete family.
  """

  family, version = "nlcarry-abstract", "v1"

  def state_words(self):
    return tuple(f"e{i}" for i in range(self.n)) + \
        tuple(f"q{i}" for i in range(self.carriers))

  def mask_words(self): return tuple(f"q{i}" for i in range(self.carriers))

  def carriers_from(self, z): return [z[f"q{i}"] for i in range(self.carriers)]

  def reference_encode(self, lanes, masks):
    state = {f"q{i}": masks[i] & self.mask for i in range(self.carriers)}
    for i, x in enumerate(lanes):
      state[f"e{i}"] = (x & self.mask) ^ state[f"q{i}"]
    return state

  def reference_decode(self, state):
    return [state[f"e{i}"] ^ state[f"q{i}"] for i in range(self.n)]

  def distinct_carriers(self, trials=256, seed=0, complete=False):
    return {"site": self.identifier, "width": self.width, "clashes": [],
            "not_applicable": "carriers are free words in the abstract variant",
            "points": 0, "complete": False, "passed": True}

  def preconditions(self):
    return {"decode": "X_i = e_i ^ q_i", "carriers": "uninterpreted free words",
            "implies": "the same law for every concrete kernel",
            "excludes": "the rejection criterion, which needs concrete carriers",
            "lanes": self.n, "width": self.width, "role": "proof abstraction"}


class TriCouple(Site):
  """`tricouple`: a two-lane chain whose second carrier reads the first state word.

  Forward law   z0 = X0 ^ H(m)            H a seeded nonlinear kernel of m
                z1 = X1 ^ G(z0, m)        G a seeded nonlinear kernel of both
  Inverse       X0 = z0 ^ H(m), then X1 = z1 ^ G(z0, m). Exact, and triangular:
                z1 is never needed to recover z0.
  Preconditions m is a live runtime word, not a constant; rotations constant and
                in range; the evaluation order is fixed (z0 before z1), which is
                what keeps the pair of laws acyclic.

  The point of the family is the dependency shape rather than the kernels. Any
  transfer that rewrites lane 0 changes lane 1's carrier as well, so a single
  logical update must rewrite two state words and a consumer of lane 1 must
  read lane 0's word. That joint dependency is the property W1 asks to survive
  to consumers; it is not by itself a difficulty claim.
  """

  family, version = "tricouple", "v1"

  def __init__(self, width, seed, lanes=2):
    if lanes != 2: raise ValueError("tricouple is defined for exactly two lanes")
    super().__init__(width, seed, lanes)
    rng = seeded(("tricouple", width, seed))
    self.spread = rot_amount(rng, self.width)
    self.head = ArxNetwork(self.width, ("tricouple-h", seed), words=2, rounds=2,
                           pattern="mixer")
    self.link = ArxNetwork(self.width, ("tricouple-g", seed), words=2, rounds=2,
                           pattern="mixer")
    self.spare = ArxNetwork(self.width, ("tricouple-a", seed), words=2, rounds=2,
                            pattern="mixer")

  def state_words(self): return ("z0", "z1", "m")
  def mask_words(self): return ("m",)

  def head_carrier(self, m, reference=False):
    if reference:
      return self.head.ref_apply([m, ref_rotl(m, self.spread, self.width)])[0]
    return self.head.apply([m, rotl(m, self.spread, self.width)])[0]

  def link_carrier(self, z0, m, reference=False):
    if reference: return self.link.ref_apply([z0, m])[0]
    return self.link.apply([z0, m])[0]

  def aux_carrier(self, m, reference=False):
    """A carrier for constants, distinct from both lane carriers."""
    if reference:
      return self.spare.ref_apply([m, ref_rotl(m, self.spread, self.width)])[0]
    return self.spare.apply([m, rotl(m, self.spread, self.width)])[0]

  def reference_encode(self, lanes, masks):
    m = masks[0] & self.mask
    z0 = (lanes[0] & self.mask) ^ self.head_carrier(m, reference=True)
    z1 = (lanes[1] & self.mask) ^ self.link_carrier(z0, m, reference=True)
    return {"z0": z0, "z1": z1, "m": m}

  def reference_decode(self, state):
    m, z0, z1 = state["m"], state["z0"], state["z1"]
    return [z0 ^ self.head_carrier(m, reference=True),
            z1 ^ self.link_carrier(z0, m, reference=True)]

  def preconditions(self):
    return {"decode": "X0 = z0 ^ H(m); X1 = z1 ^ G(z0, m)",
            "evaluation_order": "z0 before z1, acyclic by construction",
            "mask_word_is_runtime_value": True, "width": self.width,
            "shift_amounts_constant_in_range": True, "role": "candidate"}

  def transfer_names(self): return ("addc0", "cross_add", "combined", "repair_sandwich")

  def _open(self, name):
    prog = self.program(name)
    z = {n: prog.input(n) for n in self.state_words()}
    head = self.head_carrier(z["m"])
    link = self.link_carrier(z["z0"], z["m"])
    aux = self.aux_carrier(z["m"])
    return prog, z, head, link, aux, [(z["z0"], head), (z["z1"], link)]

  def build(self, kind, constant=5, **kw):
    ops = share_ops(self.width, logical_shift)
    pxor, inv, land, lor, pshl, plshr = ops
    prog, z, head, link, aux, pairs = self._open(kind)

    def rewrite(pair0, pair1=None, repair_grouping=True):
      """Store a new lane 0, then repair lane 1 for its changed carrier."""
      new0 = store(pair0, head)
      link2 = self.link_carrier(new0, z["m"])
      if pair1 is not None:
        return new0, store(pair1, link2)
      if repair_grouping:
        return new0, z["z1"] ^ (link ^ link2)      # correction is state-only
      return new0, (z["z1"] ^ link) ^ link2        # forms X1 in a register

    if kind == "addc0":
      pair = share_add(pairs[0], (aux ^ (constant & self.mask), aux),
                       self.width, False, logical_shift)
      new0, new1 = rewrite(pair)
      return Transfer(kind, self, prog, outputs={"z0": new0.name, "z1": new1.name},
                      spec=lambda v, ops=None: {0: (v[0] + constant) & self.mask},
                      note="one logical update rewrites two state words")

    if kind == "cross_add":
      pair = share_add(pairs[0], pairs[1], self.width, False, logical_shift)
      new0, new1 = rewrite(pair)
      return Transfer(kind, self, prog, outputs={"z0": new0.name, "z1": new1.name},
                      spec=lambda v, ops=None: {0: (v[0] + v[1]) & self.mask},
                      note="cross-lane add; lane 1 is repaired, not decoded")

    if kind == "combined":
      total = share_add(pairs[0], pairs[1], self.width, False, logical_shift)
      mixed = pxor(pairs[0], pairs[1])
      new0, new1 = rewrite(total, mixed)
      def spec(v, ops=None): return {0: (v[0] + v[1]) & self.mask, 1: v[0] ^ v[1]}
      return Transfer(kind, self, prog, outputs={"z0": new0.name, "z1": new1.name},
                      spec=spec, source_ops=2,
                      note="two real outputs; lane 1's carrier reads lane 0's new word")

    if kind == "repair_sandwich":
      pair = share_add(pairs[0], (aux ^ (constant & self.mask), aux),
                       self.width, False, logical_shift)
      new0, new1 = rewrite(pair, repair_grouping=False)
      return Transfer(kind, self, prog, outputs={"z0": new0.name, "z1": new1.name},
                      spec=lambda v, ops=None: {0: (v[0] + constant) & self.mask},
                      expect="reject",
                      note="rejected grouping: the repair decodes lane 1 first")

    return super().build(kind)


# --------------------------------------------------------------------------
# Law checking: the candidate program against the independent reference.
# --------------------------------------------------------------------------

def live_steps(transfer):
  """The steps that actually reach an output.

  The builders compute every carrier eagerly, so a transfer that touches two
  lanes still traces the kernels of the others. Those are dead and a planner
  would not emit them, so cost counts and the rejection criterion both use this
  slice rather than the whole trace.
  """
  defs = {step[0]: step for step in transfer.program.steps}
  roots = list(transfer.predicate) if transfer.kind == "predicate" else \
      list(transfer.outputs.values())
  live, work = set(), list(roots)
  while work:
    name = work.pop()
    if name in live or name not in defs: continue
    live.add(name)
    for arg in defs[name][2]:
      if isinstance(arg, str): work.append(arg)
  return [step for step in transfer.program.steps if step[0] in live]


def edge_values(width):
  """Constructed cases the plan asks for: carries, borrows, high-bit changes."""
  mask, sign = (1 << width) - 1, 1 << (width - 1)
  return sorted({0, 1, mask, mask - 1, sign, (sign - 1) & mask, (sign + 1) & mask})


def constructed_points(site, limit=64):
  """All-equal, all-different and boundary lane values with boundary masks."""
  values = edge_values(site.width)
  points, masks = [], len(site.mask_words())
  for a in values:
    for b in values:
      lanes = [a if i % 2 == 0 else b for i in range(site.n)]
      for m in (0, (1 << site.width) - 1, 1):
        points.append((lanes, [m] * masks))
      points.append((lanes, [values[(i + 1) % len(values)] for i in range(masks)]))
    points.append(([a] * site.n, [a] * masks))
  return points[:limit] if limit else points


def check_laws(transfer, trials=512, seed=0, complete=False, extra_points=True):
  """Program == reference, and decode(transfer(Z)) == F(decode(Z)).

  `complete` enumerates the whole (lanes, masks) domain, which is the strongest
  form available here and is only affordable at small widths.
  """
  site = transfer.site
  backend = Concrete(site.width)
  rng = seeded(("laws", seed, transfer.identifier))
  if complete:
    points = list(site.enumerate_domain())
  else:
    points = [site.sample(rng) for _ in range(trials)]
    if extra_points: points += constructed_points(site)
  report = {"transfer": transfer.identifier, "width": site.width,
            "points": len(points), "complete": bool(complete),
            "program_mismatch": None, "spec_mismatch": None, "checked": 0}
  for lanes, masks in points:
    state = site.reference_encode(lanes, masks)
    values, produced = transfer.run(state, backend)
    if transfer.kind == "predicate":
      expected = transfer.spec(site.reference_decode(state))
      if produced != expected and report["spec_mismatch"] is None:
        report["spec_mismatch"] = {"lanes": lanes, "masks": masks,
                                  "got": produced, "want": expected}
    else:
      expected_state = transfer.reference(state)
      if produced != expected_state and report["program_mismatch"] is None:
        report["program_mismatch"] = {"lanes": lanes, "masks": masks,
                                      "got": produced, "want": expected_state}
      decoded = site.reference_decode(produced)
      wanted = dict(enumerate(site.reference_decode(state)))
      wanted.update(transfer.spec(site.reference_decode(state)))
      if decoded != [wanted[i] for i in range(site.n)] and report["spec_mismatch"] is None:
        report["spec_mismatch"] = {"lanes": lanes, "masks": masks,
                                  "got": decoded, "want": wanted}
    report["checked"] += 1
  report["passed"] = report["program_mismatch"] is None and report["spec_mismatch"] is None
  return report


def check_inverse(site, complete=False, trials=512, seed=0):
  """Positive control for the inverse: decode(encode(X, M)) == X everywhere."""
  rng = seeded(("inverse", seed, site.identifier))
  points = list(site.enumerate_domain()) if complete else \
      [site.sample(rng) for _ in range(trials)] + constructed_points(site)
  failures = []
  for lanes, masks in points:
    decoded = site.reference_decode(site.reference_encode(lanes, masks))
    if decoded != [x & site.mask for x in lanes]:
      failures.append({"lanes": lanes, "masks": masks, "got": decoded})
      if len(failures) > 3: break
  return {"site": site.identifier, "width": site.width, "points": len(points),
          "complete": bool(complete), "failures": failures, "passed": not failures}


def mutate_counterexample(transfer, attempts=8, points=64, seed=0):
  """Negative control: corrupt a live constant and confirm the law then fails.

  A law test that cannot fail proves nothing, so every accepted law is paired
  with mutants that must be caught. A mutant whose output never differs from the
  original on any sampled input is an *equivalent* mutant and is excluded rather
  than counted as an escape: the destination carrier of a transfer that writes
  back to one of its own operands cancels algebraically, so corrupting that
  carrier really does leave the transfer unchanged. Anything that does change an
  output word must be caught.
  """
  site = transfer.site
  backend = Concrete(site.width)
  rng = seeded(("mutate", seed, transfer.identifier))
  steps = transfer.program.steps
  reachable = {step[0] for step in live_steps(transfer)}
  candidates = [k for k, (name, op, args) in enumerate(steps)
                if name in reachable and
                (op in SHIFTS or any(isinstance(a, int) for a in args))]
  rng.shuffle(candidates)
  sample = [site.sample(rng) for _ in range(points)]
  states = [site.reference_encode(lanes, masks) for lanes, masks in sample]
  baseline = [transfer.run(state, backend)[1] for state in states]
  report = {"transfer": transfer.identifier, "attempted": 0, "equivalent": 0,
            "effective": 0, "escaped": [], "missed_by_sampling": []}
  for index in candidates[:attempts]:
    name, op, args = steps[index]
    if op in SHIFTS:
      if site.width == 1: continue
      changed = (args[0], (args[1] + 1) % site.width)
    else:
      changed = tuple(((a ^ 1) & site.mask) if isinstance(a, int) else a for a in args)
    steps[index] = (name, op, changed)
    try:
      report["attempted"] += 1
      moved = any(transfer.run(state, backend)[1] != want
                  for state, want in zip(states, baseline))
      if not moved:
        report["equivalent"] += 1
        continue
      report["effective"] += 1
      # The law must fail at the points that distinguish the mutant. If it does
      # but an independent random sample of the same size did not find them, the
      # mutant was missed by sampling rather than escaping the law: that is a
      # statement about the sample size, and it is why the complete small-domain
      # enumerations and the bounded proofs exist.
      distinguishing = [state for state, want in zip(states, baseline)
                        if transfer.run(state, backend)[1] != want]
      broken = any(not _law_holds_at(transfer, state, backend)
                   for state in distinguishing)
      if not broken:
        report["escaped"].append({"step": index, "operation": op})
      elif check_laws(transfer, trials=128, seed=seed)["passed"]:
        report["missed_by_sampling"].append({"step": index, "operation": op})
    finally:
      steps[index] = (name, op, args)
  report["caught"] = None if not report["effective"] else not report["escaped"]
  return report


def _law_holds_at(transfer, state, backend):
  """The transfer law at a single state, used by the mutation control."""
  site = transfer.site
  _, produced = transfer.run(state, backend)
  if transfer.kind == "predicate":
    return produced == transfer.spec(site.reference_decode(state))
  return produced == transfer.reference(state)


# --------------------------------------------------------------------------
# Rejection criterion: no intermediate may be determined by the lanes alone.
# --------------------------------------------------------------------------

def enumerate_masks(site):
  count = len(site.mask_words())
  for index in range(1 << (site.width * count)):
    yield [(index >> (site.width * j)) & site.mask for j in range(count)]


def plain_values(transfer, lanes):
  """The values a transfer must never materialize: its inputs and its results."""
  values = {f"in{i}": x & transfer.site.mask for i, x in enumerate(lanes)}
  if transfer.kind == "predicate":
    values["out"] = transfer.spec(lanes)
  else:
    for i, x in transfer.spec(lanes).items(): values[f"out{i}"] = x & transfer.site.mask
  return values


def lane_grid(site, rng, repeats=6, extra=8):
  """Lane tuples that vary one logical value at a time, then all of them.

  The one-at-a-time structure is what makes the bijection test below
  discriminating: without it a sample almost never repeats a logical value, so
  "v is a function of X_i" could not be distinguished from "v is a function of
  the whole tuple".
  """
  base = site.sample(rng)[0]
  points = [list(base)]
  for i in range(site.n):
    for _ in range(repeats):
      moved = list(base)
      moved[i] = rng.getrandbits(site.width)
      points.append(moved)
    for _ in range(repeats):
      other = site.sample(rng)[0]
      other[i] = base[i]
      points.append(other)
  points += [site.sample(rng)[0] for _ in range(extra)]
  unique, seen = [], set()
  for p in points:
    if tuple(p) in seen: continue
    seen.add(tuple(p))
    unique.append(p)
  return unique


def classify(transfer, repeats=6, extra=8, mask_points=24, seed=0, exhaustive_masks=False):
  """Classify every intermediate of a transfer program by where its entropy is.

  For each intermediate v and each sampled lane tuple L, collect the set S(L) of
  values v takes as the runtime mask words range over the mask sample. Then

    masked           |S(L)| > 1 at every L: the mask entropy always reaches v;
    mask-only        v never changes when the lanes change: a carrier;
    constant         v never changes at all;
    decode           |S(L)| == 1 at every L and, for one of the transfer's plain
                     values p, the sampled relation p -> v is a bijection. v is
                     then that logical value behind a recognizable inverse, so
                     the candidate is rejected;
    partial-plain    |S(L)| == 1 at every L but no such bijection: a lossy
                     function of the logical values;
    partial-collapse |S(L)| == 1 at some L and > 1 at others: the masking
                     degrades on part of the domain.

  Only `decode` rejects, and it is exactly the plan's "one original instruction
  between two recognizable inverses". The two lossy verdicts are reported with
  counts because they are real observations, not because a count of them means
  anything on its own. Nothing here measures hardness: the mask words are
  ordinary program values an analyst can read, so mask dependence is necessary
  for a candidate to be worth lowering and nowhere near sufficient for it to be
  hard.

  `exhaustive_masks` replaces the mask sample with the complete mask domain,
  which turns "|S(L)| == 1" from evidence into a fact at that lane tuple. It is
  only affordable at small widths; the bounded QF_BV runner states the universal
  form at 8/16/32/64.
  """
  site = transfer.site
  backend = Concrete(site.width)
  rng = seeded(("classify", seed, transfer.identifier))
  names = [step[0] for step in live_steps(transfer)]
  lane_tuples = lane_grid(site, rng, repeats, extra)
  masks_list = list(enumerate_masks(site)) if exhaustive_masks else \
      [site.sample(rng)[1] for _ in range(mask_points)]
  collapsed = {n: 0 for n in names}
  per_lane = {n: [] for n in names}
  plains = []
  for lanes in lane_tuples:
    spread = {n: set() for n in names}
    for masks in masks_list:
      values = evaluate(transfer.program, site.reference_encode(lanes, masks), backend)
      for n in names: spread[n].add(values[n])
    for n in names:
      if len(spread[n]) == 1: collapsed[n] += 1
      per_lane[n].append(min(spread[n]))
    plains.append(plain_values(transfer, lanes))
  keys = sorted(plains[0])
  verdicts, detail = {}, {}
  for n in names:
    images = len(set(per_lane[n]))
    full = collapsed[n] == len(lane_tuples)
    matched = None
    if full and images > 1:
      for key in keys:
        forward, backward, ok = {}, {}, True
        for row, value in zip(plains, per_lane[n]):
          p = row[key]
          if forward.setdefault(p, value) != value: ok = False; break
          if backward.setdefault(value, p) != p: ok = False; break
        if ok and len(forward) > 1:
          matched = key
          break
    detail[n] = {"collapsed_lane_points": collapsed[n], "lane_points": len(lane_tuples),
                 "distinct_images": images, "bijection_of": matched}
    if images == 1 and full: verdicts[n] = "constant"
    elif images == 1: verdicts[n] = "mask-only"
    elif matched: verdicts[n] = "decode"
    elif full: verdicts[n] = "partial-plain"
    elif collapsed[n]: verdicts[n] = "partial-collapse"
    else: verdicts[n] = "masked"
  order = ("masked", "mask-only", "constant", "partial-collapse", "partial-plain", "decode")
  exposed = [n for n, v in verdicts.items() if v == "decode"]
  return {"transfer": transfer.identifier, "width": site.width,
          "instructions": len(names), "traced": transfer.program.size,
          "exhaustive_masks": bool(exhaustive_masks),
          "lane_points": len(lane_tuples), "mask_points": len(masks_list),
          "counts": {v: sum(1 for x in verdicts.values() if x == v) for v in order},
          "exposed": exposed, "exposes": sorted({detail[n]["bijection_of"] for n in exposed}),
          "verdicts": verdicts,
          "detail": {n: detail[n] for n in names if verdicts[n] in
                     ("decode", "partial-plain", "partial-collapse")},
          "accepted": not exposed}


def review(transfer, **kw):
  """Accept or reject one candidate transfer against its declared expectation."""
  verdict = classify(transfer, **kw)
  outcome = "accept" if verdict["accepted"] else "reject"
  verdict["expected"] = transfer.expect
  verdict["as_expected"] = outcome == transfer.expect
  verdict["outcome"] = outcome
  return verdict


# --------------------------------------------------------------------------
# Attacks. A family that a fit recovers immediately is a negative result.
# --------------------------------------------------------------------------

def state_bits(site, state):
  bits, shift = 0, 0
  for word in site.state_words():
    bits |= (state[word] & site.mask) << shift
    shift += site.width
  return bits, shift


def monomials(count, degree):
  """Every monomial of degree 1..`degree` over `count` GF(2) variables."""
  out = []
  for d in range(1, degree + 1):
    out.extend(itertools.combinations(range(count), d))
  return out


def features(bits, monos):
  """The feature row for one sample: one bit per monomial, plus the constant."""
  row = 0
  for index, mono in enumerate(monos):
    value = 1
    for b in mono: value &= (bits >> b) & 1
    row |= value << index
  return row | (1 << len(monos))


class Gf2System:
  """Row-echelon GF(2) system over feature bitmasks with several right sides."""

  def __init__(self): self.basis = {}

  def add(self, row, rhs):
    while row:
      pivot = row.bit_length() - 1
      if pivot not in self.basis:
        self.basis[pivot] = (row, rhs)
        return True
      other, orhs = self.basis[pivot]
      row ^= other
      rhs ^= orhs
    return rhs == 0  # a zero row with a nonzero side is inconsistent

  def predict(self, row):
    rhs = 0
    while row:
      pivot = row.bit_length() - 1
      if pivot not in self.basis: return None  # outside the trained span
      other, orhs = self.basis[pivot]
      row ^= other
      rhs ^= orhs
    return rhs


def gf2_attack(site, lane=0, degree=1, train=None, test=200, seed=0):
  """Fit lane bits as a degree-`degree` GF(2) function of the state bits."""
  rng = seeded(("gf2", seed, site.identifier, degree, lane))
  count = site.width * len(site.state_words())
  monos = monomials(count, degree)
  size = len(monos) + 1
  train = train if train is not None else size + 32
  system = Gf2System()
  consistent = True
  for _ in range(train):
    lanes, masks = site.sample(rng)
    bits, _ = state_bits(site, site.reference_encode(lanes, masks))
    consistent &= system.add(features(bits, monos), lanes[lane] & site.mask)
  hits = [0] * site.width
  scored, undetermined = 0, 0
  for _ in range(test):
    lanes, masks = site.sample(rng)
    bits, _ = state_bits(site, site.reference_encode(lanes, masks))
    prediction = system.predict(features(bits, monos))
    if prediction is None:
      undetermined += 1
      continue
    scored += 1
    for b in range(site.width):
      hits[b] += int(((prediction >> b) & 1) == ((lanes[lane] >> b) & 1))
  recovered = [b for b in range(site.width) if scored and hits[b] == scored]
  return {"site": site.identifier, "kernel": getattr(site, "kernel", None),
          "width": site.width, "degree": degree, "lane": lane,
          "train": train, "features": size, "consistent": consistent,
          "scored": scored, "undetermined": undetermined,
          "bits_recovered": len(recovered), "bits": site.width,
          "recovered_bits": recovered,
          "broken": scored > 0 and len(recovered) == site.width}


def solve_mod(rows, rhs, width):
  """Solve A x = b over Z/2^w, pivoting only on units. None if it cannot."""
  mod = 1 << width
  work = [[a % mod for a in row] + [b % mod] for row, b in zip(rows, rhs)]
  columns = len(rows[0])
  pivots, r = [], 0
  for c in range(columns):
    choice = next((i for i in range(r, len(work)) if work[i][c] % 2), None)
    if choice is None: continue
    work[r], work[choice] = work[choice], work[r]
    scale = pow(work[r][c], -1, mod)
    work[r] = [(x * scale) % mod for x in work[r]]
    for i in range(len(work)):
      if i != r and work[i][c]:
        factor = work[i][c]
        work[i] = [(a - factor * b) % mod for a, b in zip(work[i], work[r])]
    pivots.append(c)
    r += 1
    if r == len(work): break
  for row in work[r:]:
    if all(a == 0 for a in row[:columns]) and row[columns]: return None
  solution = [0] * columns
  for i, c in enumerate(pivots): solution[c] = work[i][columns]
  return solution if len(pivots) == columns else None


def modular_affine_attack(site, lane=0, test=200, seed=0):
  """Fit lane = sum a_j * Z_j + c over Z/2^w: the ring-affine projection."""
  rng = seeded(("affine", seed, site.identifier, lane))
  words = site.state_words()
  rows, rhs = [], []
  for _ in range(len(words) + 12):
    lanes, masks = site.sample(rng)
    state = site.reference_encode(lanes, masks)
    rows.append([state[w] for w in words] + [1])
    rhs.append(lanes[lane] & site.mask)
  solution = solve_mod(rows, rhs, site.width)
  if solution is None:
    return {"site": site.identifier, "kernel": getattr(site, "kernel", None),
            "width": site.width, "lane": lane, "fitted": False, "broken": False}
  hits = 0
  for _ in range(test):
    lanes, masks = site.sample(rng)
    state = site.reference_encode(lanes, masks)
    guess = sum(c * v for c, v in zip(solution,
                [state[w] for w in words] + [1])) & site.mask
    hits += int(guess == (lanes[lane] & site.mask))
  return {"site": site.identifier, "kernel": getattr(site, "kernel", None),
          "width": site.width, "lane": lane, "fitted": True,
          "coefficients": solution, "agreement": hits / test,
          "broken": hits == test}


def kernel_shape_attack(site, lane=0, samples=16, seed=0):
  """Guess the kernel shape and search its rotation amounts.

  The shape is in the binary, so this is the realistic attack: the seeds are
  not a secret, only a search space. Reported as a trial count, never as a
  score. Only defined for the closed-form kernels; the network kernel has too
  many parameters for this enumeration and is reported as not attempted.
  """
  if not isinstance(site, NlCarry) or isinstance(site, NlCarryAbstract) \
      or site.kernel == "arx":
    return {"site": site.identifier, "kernel": getattr(site, "kernel", None),
            "attempted": False, "reason": "search space not enumerated here"}
  rng = seeded(("shape", seed, site.identifier, lane))
  points = []
  for _ in range(samples):
    lanes, masks = site.sample(rng)
    points.append((site.reference_encode(lanes, masks), lanes[lane] & site.mask))
  width, trials = site.width, 0
  for p in range(width):
    for q in range(width):
      trials += 1
      def carrier(m0, m1):
        if site.kernel == "linear":
          return ref_rotl(m0, p, width) ^ ref_rotl(m1, q, width)
        if site.kernel == "and":
          return ref_rotl(m0, p, width) & ref_rotl(m1, q, width)
        return ref_rotl((m0 * m1) & site.mask, p, width) ^ ref_rotl(m0, q, width)
      if all(state[f"e{lane}"] ^ carrier(state["m0"], state["m1"]) == value
             for state, value in points):
        return {"site": site.identifier, "kernel": site.kernel, "attempted": True,
                "trials": trials, "search_space": width * width,
                "recovered": True, "rotations": (p, q)}
  return {"site": site.identifier, "kernel": site.kernel, "attempted": True,
          "trials": trials, "search_space": width * width, "recovered": False}


def projection_transfer_attack(site, other, lane=0, degree=2, train=None,
                               test=100, seed=0):
  """Does a projection fitted for one lane still decode elsewhere?

  W1 asks whether an inferred model transfers across lanes, sites and seeds. A
  model that transfers means one recovery pays for many uses; a model that does
  not means the analyst repeats the work. Three arms: the same lane of the same
  site on fresh inputs, another lane of the same site, and the same lane of a
  differently seeded site.
  """
  rng = seeded(("transfer", seed, site.identifier))
  count = site.width * len(site.state_words())
  monos = monomials(count, degree)
  train = train if train is not None else len(monos) + 33
  system = Gf2System()
  for _ in range(train):
    lanes, masks = site.sample(rng)
    bits, _ = state_bits(site, site.reference_encode(lanes, masks))
    system.add(features(bits, monos), lanes[lane] & site.mask)
  results = {}
  arms = [("same-site", site, lane), ("other-seed", other, lane)]
  if site.n > 1: arms.append(("other-lane", site, (lane + 1) % site.n))
  for label, target, which in arms:
    hits = scored = 0
    for _ in range(test):
      lanes, masks = target.sample(rng)
      bits, _ = state_bits(target, target.reference_encode(lanes, masks))
      prediction = system.predict(features(bits, monos))
      if prediction is None: continue
      scored += 1
      hits += int(prediction == (lanes[which] & target.mask))
    results[label] = {"scored": scored, "exact": hits, "lane": which,
                      "transfers": scored > 0 and hits == scored}
  return {"fitted_on": site.identifier, "degree": degree, "results": results}



def carrier_fit_attack(site, lane=0, degree=2, train=None, test=200, seed=0):
  """Fit the carrier itself from the mask words, per bit.

  Strictly stronger than fitting the decode from the whole state, and it is
  what an analyst who can choose inputs would do: knowing one logical value
  makes the carrier observable as `e_i ^ X_i`, which removes the lane variable
  from the fit entirely. The per-bit result is the useful one, because the
  algebraic degree of a carrier bit usually grows with the bit index: a
  modular product's bit k has degree about k+1, so a low-degree fit peels the
  low bits and stalls. Reported as a bit count, never as a score.
  """
  if not hasattr(site, "carrier"): raise ValueError("no carrier in this family")
  rng = seeded(("carrier", seed, site.identifier, degree, lane))
  count = site.width * len(site.mask_words())
  monos = monomials(count, degree)
  train = train if train is not None else len(monos) + 33
  system = Gf2System()
  def observe():
    masks = site.sample(rng)[1]
    bits = 0
    for index, value in enumerate(masks): bits |= (value & site.mask) << (site.width * index)
    return bits, site.carrier(masks[0], masks[1], lane, reference=True)
  for _ in range(train):
    bits, target = observe()
    system.add(features(bits, monos), target)
  hits, scored = [0] * site.width, 0
  for _ in range(test):
    bits, target = observe()
    prediction = system.predict(features(bits, monos))
    if prediction is None: continue
    scored += 1
    for b in range(site.width):
      hits[b] += int(((prediction >> b) & 1) == ((target >> b) & 1))
  recovered = [b for b in range(site.width) if scored and hits[b] == scored]
  return {"site": site.identifier, "kernel": getattr(site, "kernel", None),
          "width": site.width, "degree": degree, "lane": lane, "train": train,
          "monomials": len(monos), "scored": scored,
          "bits_recovered": len(recovered), "recovered_bits": recovered,
          "broken": scored > 0 and len(recovered) == site.width}




def constant_readback_attack(site, lane=0, trials=200, seed=0):
  """Decode using the constants the lowering would have emitted.

  This is the attack that matters and the one the other numbers must be read
  against. A carrier's rotation amounts, multipliers and constants are operands
  of emitted instructions: a static analyst reads them out of the instruction
  stream rather than searching for them. So the trial counts reported by
  `kernel_shape_attack` are an upper bound on a search nobody has to perform,
  and the network kernel resisting every algebraic fit here means only that
  those particular fits are the wrong tool.

  It succeeds for every family by construction. It is kept as an executable
  statement of the threat model, so that "no fit recovered it" can never be read
  as "it was not recovered".
  """
  rng = seeded(("readback", seed, site.identifier, lane))
  exact = 0
  for _ in range(trials):
    lanes, masks = site.sample(rng)
    state = site.reference_encode(lanes, masks)
    # Exactly what the emitted code computes, from the emitted constants.
    recovered = site.reference_decode(state)[lane]
    exact += int(recovered == (lanes[lane] & site.mask))
  return {"site": site.identifier, "kernel": getattr(site, "kernel", None),
          "lane": lane, "trials": trials, "exact": exact,
          "recovered": exact == trials,
          "cost": "reading the emitted constants; no search"}


def seed_collision_probe(width, kernel, lanes=2, sites=64, seed=0):
  """How often do two independently seeded sites share a lane's carrier?

  Distinct carriers within a site are a precondition (`distinct_carriers`).
  Across sites nothing enforces it, and a collision is worth a number rather
  than an anecdote: a projection recovered at one site decodes a colliding site
  for free, so one recovery pays twice. For the closed-form kernels the
  parameter space is just the (w-1)^2 rotation pairs, so collisions are common
  at small widths. The network kernel draws multipliers and constants as well,
  so its space is far larger; it is reported as not enumerated rather than as
  safe.
  """
  built = [NlCarry(width, seed * 1000 + index, lanes=lanes, kernel=kernel)
           for index in range(sites)]
  # The mask sample must cover the whole width. Drawing only small values makes
  # a rotated AND kernel read zero for most parameters, which looks like a
  # collision and is not one.
  rng = seeded(("collision", width, kernel, lanes, seed))
  masks = ([(a, b) for a in range(1 << width) for b in range(1 << width)]
           if width <= 4 else
           [(rng.getrandbits(width), rng.getrandbits(width)) for _ in range(96)])
  signatures = {}
  collisions = 0
  for site in built:
    key = tuple(site.carrier(a, b, 0, reference=True) for a, b in masks)
    if key in signatures: collisions += 1
    signatures.setdefault(key, site.seed)
  space = None if kernel == "arx" else max(1, width - 1) ** 2
  return {"width": width, "kernel": kernel, "sites": sites,
          "distinct_lane0_carriers": len(signatures), "collisions": collisions,
          "parameter_space": space,
          "note": ("rotation pairs only" if space else
                   "network parameters not enumerated here")}


def describe(site):
  """The record W1 asks for: law, preconditions, inverse, model, program size."""
  record = {"family": site.identifier, "width": site.width, "lanes": site.n,
            "state_words": list(site.state_words()),
            "mask_words": list(site.mask_words()),
            "ablation": bool(getattr(site, "ablation", False)),
            "preconditions": site.preconditions(), "transfers": {}}
  for name in site.transfer_names():
    try:
      transfer = site.build(name)
    except ValueError as error:
      record["transfers"][name] = {"unavailable": str(error)}
      continue
    live = live_steps(transfer)
    histogram = {}
    for _, op, _ in live:
      histogram[op] = histogram.get(op, 0) + 1
    record["transfers"][name] = {"instructions": len(live),
                                 "traced": transfer.program.size,
                                 "source_operations": transfer.source_ops,
                                 "instructions_per_source_operation":
                                     round(len(live) / transfer.source_ops, 1),
                                 "operations": histogram, "expect": transfer.expect,
                                 "kind": transfer.kind, "note": transfer.note}
  return record


# --------------------------------------------------------------------------
# Offline driver: the record a planner reads before lowering anything.
# --------------------------------------------------------------------------

def catalogue(width=8, seed=11, degrees=(1, 2), attack_lanes=2):
  """Build the family library record: laws, rejection verdicts and attacks.

  This is a research artifact, not a gate on the compiler. `ready_to_lower` means
  only that a family has at least one transfer whose law holds against an
  independent reference and which contains no recognizable decode. It says
  nothing about how hard the family is, and a family that one of the fitting
  attacks below recovers is reported as recovered even when it is ready.
  """
  report = {"schema": "sre-transfer-families-v1", "width": width, "seed": seed,
            "scope": "offline reference models; no compiler lowering, no hardness claim",
            "families": [], "attacks": [], "failures": [], "ablation_findings": []}
  sites = [XorPair(width, seed, lanes=2), AdditivePair(width, seed, lanes=2),
           UnimodularPair(width, seed), BitslicePermutation(width, seed, lanes=2),
           ArxValue(width, seed, lanes=2), TriCouple(width, seed)]
  sites += [NlCarry(width, seed, lanes=3, kernel=k) for k in NlCarry.KERNELS]
  sites.append(NlCarryAbstract(width, seed, lanes=3, kernel="and"))
  for site in sites:
    record = describe(site)
    inverse = check_inverse(site, trials=400)
    record["inverse_control"] = {"passed": inverse["passed"], "points": inverse["points"]}
    if not inverse["passed"]: report["failures"].append(f"{site.identifier}:inverse")
    if isinstance(site, NlCarry):
      record["distinct_carriers"] = site.distinct_carriers(trials=256)
      if not record["distinct_carriers"]["passed"]:
        report["failures"].append(f"{site.identifier}:carriers")
    accepted = []
    for name, entry in record["transfers"].items():
      if "unavailable" in entry: continue
      transfer = site.build(name)
      laws = check_laws(transfer, trials=300)
      verdict = review(transfer, repeats=4, extra=6, mask_points=12)
      mutant = mutate_counterexample(transfer)
      entry["law_holds"] = laws["passed"]
      entry["law_points"] = laws["points"]
      entry["rejection"] = {"outcome": verdict["outcome"], "counts": verdict["counts"],
                            "exposes": verdict["exposes"]}
      entry["counterexample_control"] = {k: mutant[k] for k in
                                        ("attempted", "equivalent", "effective", "caught")}
      entry["counterexample_control"]["missed_by_sampling"] = \
          len(mutant["missed_by_sampling"])
      if not laws["passed"]: report["failures"].append(f"{transfer.identifier}:law")
      if not verdict["as_expected"]:
        # A declared ablation failing the rejection criterion is a result about
        # the ablation, not a regression, so it is reported separately.
        bucket = "ablation_findings" if site.ablation else "failures"
        report.setdefault(bucket, []).append(
            {"transfer": transfer.identifier, "expected": transfer.expect,
             "outcome": verdict["outcome"], "exposes": verdict["exposes"]}
            if site.ablation else f"{transfer.identifier}:rejection")
      if mutant["escaped"]:
        report["failures"].append(f"{transfer.identifier}:mutant-escaped")
      if mutant["missed_by_sampling"]:
        report.setdefault("law_sample_sensitivity", []).append(
            {"transfer": transfer.identifier,
             "mutants_missed_by_a_random_sample": len(mutant["missed_by_sampling"]),
             "note": "the law holds at the distinguishing inputs; a sample of "
                     "this size did not reach them"})
      if verdict["accepted"] and transfer.expect == "accept": accepted.append(name)
    record["useful_transfers_between_conversions"] = accepted
    proof_only = isinstance(site, NlCarryAbstract)
    record["role"] = ("ablation" if site.ablation else
                      "proof abstraction" if proof_only else
                      "baseline control" if isinstance(
                          site, (XorPair, AdditivePair, UnimodularPair)) else "candidate")
    # The abstract variant exists to make the laws provable at 32 and 64 bits.
    # Its decode is linear in its own free carriers by construction, so the
    # fitting attacks recover it trivially and that number means nothing about
    # any concrete kernel. It is never a lowering candidate.
    record["ready_to_lower"] = bool(accepted) and not site.ablation and not proof_only
    report["families"].append(record)
  for site in sites:
    row = {"site": site.identifier, "ablation": site.ablation,
           "gf2_fit": {str(d): gf2_attack(site, degree=d, seed=seed)["bits_recovered"]
                       for d in degrees},
           "ring_affine_fit": modular_affine_attack(site, seed=seed)["broken"],
           "shape_search": kernel_shape_attack(site, seed=seed)}
    if isinstance(site, NlCarry) and not isinstance(site, NlCarryAbstract):
      row["carrier_fit"] = {str(d): carrier_fit_attack(site, degree=d, seed=seed)["bits_recovered"]
                            for d in degrees}
      other = NlCarry(width, seed + 88, lanes=site.n, kernel=site.kernel)
      row["projection_transfer"] = projection_transfer_attack(site, other, seed=seed)["results"]
    row["constant_readback"] = constant_readback_attack(site, seed=seed)
    row["recovered_by"] = [f"gf2-degree-{d}" for d in degrees
                           if row["gf2_fit"][str(d)] == width]
    if row["constant_readback"]["recovered"]:
      row["recovered_by"].append("constant-readback")
    if row["ring_affine_fit"]: row["recovered_by"].append("ring-affine")
    if row["shape_search"].get("recovered"): row["recovered_by"].append("kernel-shape-search")
    report["attacks"].append(row)
  for row in report["attacks"]:
    for record in report["families"]:
      if record["family"] == row["site"]: record["recovered_by"] = row["recovered_by"]
  report["seed_collisions"] = [seed_collision_probe(width, k, sites=64)
                              for k in NlCarry.KERNELS]
  report["ready"] = sorted(r["family"] for r in report["families"] if r["ready_to_lower"])
  report["ready_and_not_yet_recovered"] = sorted(
      r["family"] for r in report["families"]
      if r["ready_to_lower"] and not r.get("recovered_by"))
  report["passed"] = not report["failures"]
  return report


def main():
  import argparse
  import json
  from pathlib import Path
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--out", type=Path, required=True)
  parser.add_argument("--width", type=int, default=8, choices=IR_WIDTHS)
  parser.add_argument("--seed", type=int, default=11)
  parser.add_argument("--degrees", default="1,2")
  args = parser.parse_args()
  if args.out.exists(): parser.error("use a fresh output file")
  report = catalogue(args.width, args.seed,
                     tuple(int(d) for d in args.degrees.split(",")))
  args.out.parent.mkdir(parents=True, exist_ok=True)
  args.out.write_text(json.dumps(report, indent=2) + "\n")
  for record in report["families"]:
    print(f"{record['family']:28s} ready={record['ready_to_lower']!s:5s} "
          f"transfers={len(record['useful_transfers_between_conversions'])} "
          f"recovered_by={record.get('recovered_by') or 'none of the attacks run here'}")
  print("failures:", report["failures"] or "none")
  return 0 if report["passed"] else 1


if __name__ == "__main__":
  raise SystemExit(main())
