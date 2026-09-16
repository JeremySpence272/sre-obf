# Experimental persistent values and native regions

See [v01](NATIVE_V01.md) for subsequent wide values, cross-call fusion, local
memory representations and invariant-dependent coupling. This document retains
the original affine-pair/outlining/context design and its limitations.

These IR-only experiments are implemented, independently selectable and
conformance-tested. They are **not blocked on an agent benchmark**, but improved
agent resistance is still a research claim to measure before default promotion.
The existing native preset remains unchanged when the flags are off.

```
-native-values=1
-native-outline=1
-native-coupled-state=1
```

`native-coupled-state` requires values and multi-state flattening. None of these
flags enables a VM, MC/post-link rewriting, injected assembly, environment
checks, anti-debugging or executable-code modification.

## Persistent integer representations: initial R1

For width W in {8, 16, 32, 64}, each selected SSA value has two lanes `(E, r)`:

```
E = A*x + B*r                 modulo 2^W
x = inverse(A) * (E - B*r)    modulo 2^W
```

`A` and `B` are seeded odd coefficients, specific to function and width. They
are recoverable software constants, not secrets. Masks are computed from data
and prior encoded operands. Addition, subtraction, multiplication and constant
left shifts operate directly in encoded coordinates. For example:

```
E(x+y) = Ex + Ey + B*(rout-rx-ry)
E(x*y) = inverse(A) * (Ex*Ey - B*(Ex*ry+Ey*rx) + B*B*rx*ry) + B*rout
```

Expanding the second formula gives `A*x*y + B*rout` for every pair of inputs and
masks. Neither operand is individually decoded before the multiply. Selection
chooses both lanes with the same frozen condition; PHIs carry both lanes across
joins and back edges. Duplicate switch edges reuse identical incoming SSA
values, as required by LLVM. Decoder results at duplicate external PHI edges
are reused too.

This differs from wrapping every ordinary operation with an encoder and decoder:
supported edges remain in the representation. Decoding occurs at unsupported
consumers, return/call interfaces, comparisons, and partial-coverage boundaries.
Private per-activation volatile pair storage keeps codegen from immediately
canceling adjacent computations. Memory-aware forwarding and decompiler
normalization remain legitimate attacks against it.

Scope and budgets:

- At most 24 selected nodes per function by default; `native-value-nodes=2..64`
  controls the experiment. Functions over 4,000 input instructions are skipped.
- Skip a function with no connected supported nodes; report the reason.
- Scalars only; no variable shifts, division, FP, vectors, pointer arithmetic,
  arbitrary memory representations or whole-program value encoding.
- No new `nsw`/`nuw` assumptions; transfer arithmetic uses defined modular
  semantics. Removing source overflow flags and freezing boundary values are
  refinements on defined source executions, not exact preservation of poison.
- Reports include transformed nodes, widths, persistent edges, paired PHIs,
  conversion boundaries and whether a coupled context was created. These are
  implementation-coverage counts, not post-decompiler strength scores.
- The algebraic inverse in `conformance/value_model.py` is expected to recover
  values when the representation is known. This is not LOKI or a claim that an
  affine representation defeats a representation-aware solver.

## Bounded pure-region outlining: #10 / initial R3 infrastructure

Extract contiguous regions of 3–8 pure integer instructions within a basic
block into native internal helpers. Each helper has at most six integer inputs
and four real outputs, returned as a typed aggregate. Dependent instructions
move together; multi-output regions expose more than a single expression.
There are at most two regions per source function and sixteen per module.
Report unsupported structures, empty candidate sets and the module cap.

No loads, stores, calls, divisions, variable shifts, casts or vector operations
move into the region. The caller/callee interface is generated together using
the ordinary ABI; external signatures are untouched. Boundaries freeze inputs,
and cloned arithmetic drops poison-generating flags. No interpreter or bytecode
is generated. This is bounded outlining, **not** unrestricted function-boundary
dissolution or joint-output synthesis through an e-graph.

Run outlining before value encoding. Both original functions and outlined
helpers can receive the persistent representation. Original callers then enter
the normal native driver, including indirect calls where applicable. Helpers
are explicitly tagged `outlined-region`, retain origin provenance, and join the
existing bounded one-generation helper-hardening worklist. They are not
recursively outlined. Budget skips in later passes are still possible and
remain visible in the normal pass reports.

## Data/control coupling: initial R2 mechanism

An eligible value-encoded function that also requests flattening can allocate
an initialized private `i32` context. Data operations mix context into their
new representation mask and update it from their resulting encoded lanes.
Flattening transitions mix the same context into their new key and salt, then
write back a value derived from the new token/salt. The next data computation
can consequently depend on the preceding transition's representation.

The context belongs to the activation, not a global variable. Recursive and
concurrent calls have separate contexts. Initialization precedes all accesses;
flattening reads context at transitions, not in a prologue inserted before the
value pass's initialization. Final IR reports count surviving data-side and
control-side updates separately, so allocation alone cannot satisfy the gate.

Correctness does not depend on predicting context: the value transfer identities
hold for every mask, and each state encoding remains a bijection in the block
ID for every key/salt. This is initial coupling of local mechanisms, not
arbitrary cross-function state distribution, phase-changing source objects,
or a synthesized invariant-dependent instruction set. Context propagation
across internal call boundaries remains future work.

## Conformance and interpretation

The `values` fixture requires all four widths, paired loop/join state and
multi-output outlining. With coupling enabled it requires actual data and
control updates. Tests compare complete outputs against source-O2 and matched
IR controls. `--threads` runs four concurrent callers; `--post-o2-attack` adds a
stock-O2 normalization arm. `conformance.value_edges` isolates duplicate PHIs
under partial coverage, full coverage and combined flattening.

Ghidra receives stripped binaries and privately supplied entry addresses. It
also probes outlined helpers and normalized targets. Completed decompilation,
more multiplications, larger binaries and distinct pseudocode are not agent
resistance scores. In particular, helper interfaces remain recovery boundaries,
and identifying the representation can unlock a reusable algebraic repair.

The implementation can be enabled now. Remaining engineering/research work is
coverage expansion, simplification-resistant representations, interprocedural
contexts, object phases, verified predicate/candidate generators and held-out
agent/script-transfer measurement—not a missing permission or MC dependency.
