# v04: persistent joint representations and resistance to semantic extraction

Status: active implementation with bounded experimental increments; not complete
or a claim of measured protection.
Written 2026-09-17 against compiler `8054e9d`. This is the next implementation
plan after [v03](NATIVE_V03_STATUS.md), expanding R1–R5 in the
[native roadmap](STATIC_NATIVE_PLAN.md#8-follow-on-ir-roadmap-the-newer-ideas).

Scheduling override, 2026-09-18: per user direction, large-program conformance
and scale-coverage issues are deferred engineering, not blockers for remaining
v04 feature development or crackme iterations. Keep targeted correctness and
recovery checks, and retain the original gates for later evaluation. See the
[deferred scale ledger](V04_DEFERRED_SCALE.md); no deferred result is a pass.

## 1. Objective and scope

Make recovering one region's semantics substantially less useful for recovering
the rest of the program. Require an analyst to recover representations and
their transitions across useful computation, memory, loops and internal calls.
Judge success by verified recovery and repair cost on held-out programs, with
explicit resource limits and working attack controls.

The ambitious change is a shared planning and lowering architecture for
**persistent bundles of live values**. A bundle keeps a joint representation
through several useful operations and selected boundaries. Independent scalar
shares, immediate mix/unmix, and a single activation word remain baseline
ablations; they do not satisfy the new design by themselves.

Scope remains generic, native, IR-only, with flattening and no VM. No application
names, flag lengths, magic tables, diagnostic strings, known answers or benchmark
addresses enter production selection or lowering. Keep the existing crackme
source and answer semantics fixed. Do not replace its checker with a hash, a
different cipher or a harder source algorithm.

Keep MC and post-link work in [the existing backlog](FUTURE_MACHINE_BINARY_IDEAS.md).
No environment, hardware, timing or debugger checks; no code decryption,
self-modification, undefined-behavior tricks, prompt manipulation or dependence
on context exhaustion. Preserve supported external ABI and observable behavior.

The normal pipeline stays `clang -O2 -> obfuscation -> backend -O0 -> link`.
The historical crackme comparison stays frontend/backend O0, static and stripped.
An attacker-applied O2/O3 is a separate normalization experiment.

## 2. Evidence from the v03 solve

Baseline compiler: `8054e9daf8cccb6bed30cdb1223a1aa0081ee2b3`.
Binary SHA-256:
`5b71fa9c7adb6b1b5cc6ea76d075d20c9b3b4559a28098552067b588b8607ffc`.
Private build: `obfuscation-harness/versions/v03/artifacts/checkpoint-8054e9d-r2/`.
Run prefix, relative to `revbench-revX/results/`:
`crackmes-c-noopt-nosym-static-sre-obf-max-v03_tier2_codex_20260917_215426_r1`.
The `.json` result and `_reasoning.jsonl` transcript are the primary evidence.

GPT-5.6 Sol obtained an exact match in 149 tool steps and 3,602.6 seconds. This
single observation does not establish a statistical v02/v03 ranking. The grader
records static-only compliance as `unverified`; retain that field accurately.

| Observed action | Evidence in transcript | Design consequence |
|---|---|---|
| Found application code through startup, strings, references and unwind information. | Items 2–12. | Evaluate both discovered and supplied entries. Discovery hygiene alone cannot close the semantic weakness. |
| Generic symbolic exploration repeatedly stalled; later used finite domains and QF_BV to prune some branches. | Items 19–121; summaries 69, 106, 117. | Keep CFF, but test domain enumeration and symbolic summaries explicitly. |
| Decompiled the fused function, repaired C declarations, specialized known inputs and used GCC O3/tree dumps. | Items 123–138. | Add decompile–normalize–recompile tests, including constant recovery and local-memory forwarding. |
| Recognized XOR/additive share projections and reconstructed small operation networks. | Items 143, 148, 150, 160, 173. | Test representation recovery and reuse of semantic summaries, not only emitted instruction diversity. |
| Recovered index identity, byte-shift selection and loop bounds. | Items 186, 189, 199–202. | Carry index/phase representations through memory and loop transfers; measure unavoidable address exposures. |
| Inverted an encoded table after recovering the actual rounds and parity-dependent decoder. | Items 197, 203–206. | Protect data-to-consumer continuity; numeric data encoding already existed and was defeated. |

Important qualifications for the regression adapter:

- GCC did not automatically recover the entire source algorithm. The successful
  workflow combined specialization, recompilation, manual slicing, expression
  evaluation and loop reconstruction.
- The visible eight-byte table was **encoded backing**, not the original
  expected vector. Recovering its index-dependent decoder was part of the win.
- The agent compiled reconstructed C expression fragments into shared libraries
  and sampled them. Model this capability explicitly in the expression-recovery
  tests. Do not equate that with executing the supplied target machine code.
- Some claimed identities were sampled, not exhaustively proved. Random tests
  of equality are particularly weak because almost every sample is false.
  New controls require constructed positive cases, negatives and counterexample
  checks before accepting a synthesized summary.
- One `-fwhole-program` attempt discarded the unreferenced recovered function.
  An empty optimizer output is an invalid test, never evidence of simplification.
- Ghidra types and upper-bit reconstruction required repairs. Do not assume
  recompiled pseudocode is automatically equivalent to the original binary.
- Verify whether the retained workspace still exists before archiving scripts.
  File-change events name scripts but do not necessarily contain their contents.
  Mark any reconstruction from the transcript as reconstructed evidence.

The shipped native report measured 52 selected nodes out of 56 eligible,
47 persistent edges, 42 boundary inputs, 29 boundary outputs, 21 family
conversions, 17 memory edges and 8 predicates. These boundary counts are
diagnostics, not a percentage of unprotected source instructions.

There were only two joint-output groups rewriting eight lane uses. In
`NativeConnected.cpp::coupleJointOutputs`, U/V are mixed and pinned, then inverse
arithmetic immediately reconstructs the separate encoded pairs. The code avoids
a plaintext scalar there, but still offers a small recoverable representation.
There were no aggregate-memory objects, shards or encoded private interfaces
on this target. `main` also skipped late constant processing due to its budget.

## 3. Design principles and limits

1. **Preserve representations through useful work.** Count the operations,
   loops, memory uses and calls governed by a representation. A wrapper around
   an ordinary operation is only a candidate until normalization tests it.
2. **Increase the useful interface an extractor must understand.** Join live
   dependencies where legal. Do not inflate arity with constant, dead or
   mechanically cancellable inputs and call it stronger coupling.
3. **Vary recoverable semantics across regions and phases.** Constant changes,
   register names and instruction permutations do not establish distinct
   semantic families. An inverse supplied for one site is a transfer test.
4. **Treat every small scalar exposure as an opportunity to summarize.** Cover
   table reads, indices, predicates, call parameters and storage transitions.
   Report unavoidable machine addresses and external ABI values honestly.
5. **Spend bounded resources on coherent protection.** Preserve memory/control
   continuity before spending remaining capacity on MBA, fake flow or helper
   noise. Report selection loss and transformation rollback separately.
6. **Choose candidates using verified attacks.** AST size, taint-set size,
   nominal family count and decompiler output length are diagnostics only.

The original checker is a small reversible computation with separable byte
semantics. A correct obfuscator cannot remove the existence of that simple
description. Extra shares or a 64-bit container do not create more independent
input entropy. The goal is to make discovering the description and composing
it from local summaries cost more. No purely software representation has a
secret key unavailable to a sufficiently capable static analyst.

## 4. Shared architecture

Introduce a private, typed plan before destructive expansion. Refactor the
current connected encoder incrementally rather than putting another set of
ad-hoc conditions inside its monolithic `Encoder` class.

The plan records:

- origin IDs, original operation/effect graph and object/call ownership;
- logical widths, lane widths, bundle membership and valid-state invariants;
- representation family/version and seed namespace;
- phase transitions, loop joins, storage mapping and private-call contracts;
- supported transfers, exact decode sites and reasons for every fallback;
- estimated and actual costs, reserved structural budget and rollback scope.

Original graph analysis must precede expression expansion. Generated instructions
must not inflate source coverage or masquerade as new independent dependencies.
Use stable IR order and hierarchical RNG streams, never pointer/hash iteration
order. Heavy external solvers and decompilers belong in offline selection and
conformance; ordinary compilation uses a bounded, versioned candidate library.

For logical vector X, activation context C and phase p, describe storage by
`Z = E[p,C](X)`. A source transfer F and its new context/phase must satisfy:

    decode[p', C'](transfer[p,C -> p',C'](Z)) = F(decode[p,C](Z))

This equation is the specification, not a recipe to emit adjacent decode/F/encode
wrappers. The production emitter must lower a verified combined transfer and
test its binary for precisely that easy decomposition. If it cannot do so at
reasonable cost, report a boundary or reject that candidate.

Finite phase sets and backedge conversions must converge. Context updates and
data transfers are designed together with a defined evaluation order; avoid a
circular dependency in which each requires the other's not-yet-produced value.

## 5. Implementation workstreams

### W0 — preserve the winning attack and measure semantic boundaries

Extend existing recovery/conformance infrastructure first. Archive the v03
result, transcript, submission, binary, prompt, compiler and available workspace
privately with hashes. Keep v02 replay as a second attack family.

Build two adapters for v03's successful method:

- **Supplied-region control:** receive a region or typed expression interface
  from private provenance, recover its semantics from machine/decompiled code,
  and measure simplification plus model fitting. This isolates mechanism cost.
- **Binary discovery:** receive only the binary and public protocol; find
  relevant regions and data, infer interfaces, then use the same machinery.
  Account for discovery and repair separately.

Adapter phases: lift/decompile; identify and validate a slice; recover immutable
data and safe summaries; forward proven local memory; normalize with LLVM/GCC;
fit a small grammar of expressions/relations; test the inferred model; compose
it with adjacent regions. Include XOR, difference, affine maps, rotations,
bit permutations, small lookup tables, masks, identity indices, bounds and
simple recurrences. Probe multiple sites using the same inferred model.

Replace selection based mainly on AST size/step count in `conformance/recovery.py`
with validated recovery outcomes and cost. Keep old scoring as a historical
ablation. A model that predicts only one example is not a successful summary.

Add a boundary inventory by origin and reason: external ABI, address exposure,
unsupported operation, object escape, component limit, interface mismatch and
budget loss. Track actual scalar-use edges and useful work between exposures.
Do not treat removing boundary metadata as removing a boundary.

Deliverable: working controls on clean/v03 and stable recovery/report schemas
before selecting stronger candidates.

### W1 — persistent bundles and fused native transfers

Replace post-hoc two-output wrapping with planning of multi-operation regions.
Start with 2–4 logical values and 8–32 original pure integer operations per
region; permit an explicit research mode up to 8 values/96 operations. These
are cost controls, not minimum claims of difficulty.

Select values by producer/consumer reuse, compatible lifetime, operation support
and distinct live dependencies. Multiple offsets in one proven closed object
may be separate values; a reload of the same unchanged location may not.
Include selected induction values and loop-carried data instead of excluding
every PHI from the design. Carry the joint representation through successive
transfers; reconstruct individual scalars only at recorded boundaries.

Implement a small verified family library:

1. Existing XOR/additive pairs and unimodular mixing as baseline controls.
2. Seeded reversible networks using combinations of modular addition, XOR,
   odd multiplication, rotations and triangular/Feistel-style coupling.
3. Restricted Boolean networks with cross-value nonlinear terms, when direct
   operation lowering is affordable. Plain bitslicing or a linear bit permutation
   alone is an ablation, because linear algebra may undo it cheaply.

Start with homogeneous 8/16/32/64-bit vectors. Add mixed logical widths only
with exact truncation/extension invariants; wider carriers do not count as new
semantic dependencies. Leave i1 predicates in a separately typed representation.

Synthesize bounded **combined native transfers** over short operation sequences,
including multiple real outputs. Combine algebraic rewrite rules with optional
offline enumerative/e-graph search. Search needs a verified equality checker;
distance from familiar-looking code is not the fitness function. No runtime
opcodes or interpreter are introduced.

Exercise operations beyond XOR/add: multiply-accumulate, shifts, compares,
packing/extraction, select and mixed Boolean/arithmetic kernels. Reject a
candidate that merely hides one original instruction between two recognizable
inverses. Fit inverse networks and propagate inferred projections as attacks.

Deliverable: at least two distinct candidate families with useful operations
between conversions and surviving joint dependencies at consumers. Promotion
requires measured resistance to the W0 summaries, not just new family names.

### W2 — phase transitions and useful activation relations

Give a bundle different representation descriptors at selected loop iterations,
control joins, object updates and call edges. Prefer a small finite phase graph
initially, with seeded transition families. Later experiment with parameters
derived from multiple already-live program values and per-activation history.

Require a verified entry state, update law, PHI/join conversions and loop
backedge law. Choose a consistent representation at a join or represent the
finite alternatives explicitly; do not let phase-specialized block cloning grow
without a hard bound. Zero-iteration loops and multiple exits are first-class
cases. Retain a static-phase ablation using the same bundle family.

The existing witness residual may remain a baseline ingredient, but new work
must affect useful representations. Adding `f(C)-f(C)` to the old operation is
not a new relation. A phase word is ordinary program state and should be given
to one attack control. Measure whether supplying one relation unlocks other
phases and sites, and how much repair is needed when it does not.

Use several bounded templates for context updates rather than one shared
key schedule everywhere. No randomness, environment read or global mutable
secret is needed at runtime. Initialize context from defined existing values
and build constants; never read an extra pointer argument just for entropy.

Deliverable: useful operations remain encoded across real loop/join transitions;
phase-reset and supplied-relation controls exercise the exact emitted transfers.

### W3 — object-wide memory and immutable-data continuity

Integrate `NativeEncoding` and connected storage so immutable array reads feed
the consumer's representation directly. The existing array encoder must not
automatically create one scalar decoder that becomes a reusable accessor.
Prioritize numeric arrays and useful state alongside strings.

Implementation status: the default-off [closed local tile prototype](NATIVE_OBJECT_BUNDLES_V1.md)
is a bounded increment only. It now has opt-in finite store phases and a separate
[immutable numeric continuity path](NATIVE_IMMUTABLE_BUNDLES_V1.md), but does not
yet handle direct-call ownership propagation or the wider layout/lifetime
contracts below. W3 remains incomplete and is not promoted.
It now preserves proved single-entry root lifetimes and supports exact constant
byte offsets and decoded packed-read boundaries, including ordinary O2 C
fixtures. This is not an interprocedural ownership or general-layout solution.
The explicit [five-to-eight-cell experiment](NATIVE_WIDE_TILES_V1.md) is also
implemented, with full-output tests and unchanged budgets; the default stays
four. An eight-cell phased fixture remains over its shared allocation.

Existing flat-array encoding already accepts some runtime indices and carries
two lanes through loads/stores; the aggregate leaf extension accepts constant
offsets. v04 must preserve that support and add joint tiles, phase transitions
and broader proved layouts. Runtime-index support by itself is not a new v04
feature or sufficient coverage for this workstream.

For proven closed objects:

- Couple bounded groups of elements using W1 storage representations. Start
  with tiles of 2–4 elements, with a separate measured larger-tile experiment.
- Permute physical element locations per object/phase, using a verified
  bijection over the exact object bounds. Simple permutations are support
  mechanisms and must face index-recovery controls.
- Support bounded dynamic indices through the new joint/phase object layouts.
  Prove bounds, preserve the original access guard and compute the tile/slot legally.
  Report actual address exposures; a CPU eventually requires an address.
- Load/store encoded tile state directly and perform combined updates. Any
  read-modify-write of extra tile elements requires proof they are initialized,
  accessible, nonvolatile, nonatomic and unobservable through aliases.
- Keep immutable backing encoded, with no persistent plaintext shadow. Emit
  a transfer to the consumer representation at the read; don't claim stronger
  data protection solely because its section layout changed.
- Change object phase at bounded ownership-safe points. Whole-object re-encoding
  costs O(size); either budget it explicitly or use bounded tiles with tracked
  phase state. Do not retag an object while leaving its stored bytes in the old
  representation. Lazy per-tile state needs its own joins and correctness tests.

Extend the use walk deliberately: constant-offset aggregates, simple aliases,
provably bounded variable GEPs, and specified memcpy/memset patterns. Reject or
explicitly cross a boundary for escapes, unknown aliasing, bytewise observation,
atomics, volatile storage and unsupported partial accesses. Preserve effective
object lifetimes and alignment. Do not manufacture cross-allocation pointers.

C globals with observable linkage, pointer identity or unknown accesses are not
closed objects. Reuse explicit closed-world permission and whole-module effect
analysis. Heap ownership and arbitrary escaping pointers remain separate
follow-on research; the first v04 memory deliverable is closed storage plus
proved direct-call propagation of that ownership.

Deliverable: real variable-index memory fixtures, encoded numeric data-to-use
paths, and new measured coverage in unchanged applications where eligible.
If scale coverage remains zero, record it; don't count a scalar-only fixture
as an improvement in array/object protection.

### W4 — coupled predicates and distributed native control

Bounded increments now include [actual recurrence/control binding](NATIVE_BUNDLE_CONTROL_V1.md)
and [exact compound predicates](NATIVE_BUNDLE_PREDICATES_V1.md). The latter consumes
selected same-block multi-output equality trees without intervening scalar
projections; it does not implement arbitrary short-circuit loop conversion or
complete the broader workstream below.

Keep predicates within persistent bundles through their useful consumers.
Generate combined relation tests over selected pure computations so the
recoverer cannot always isolate a one-byte equality independently of adjacent
state. Reuse W1 transfer verification; emitting a Boolean circuit around one
ordinary comparison is insufficient by itself.

Recognize general side-effect-free comparison/reduction regions, including
bounded loops where equivalence is provable. A candidate can use a full-width
invertible representation of a residual vector: testing that representation
against the encoded all-zero vector preserves the exact conjunction. A short
hash/checksum is not a replacement for exact equality because collisions would
change behavior. Keep mismatch state encoded until the legitimate output.

Preserve short-circuit semantics. Do not speculate loads, division, calls,
volatile/atomic accesses or exceptions from paths that previously did not
execute. An early-exit comparison loop may be converted only when added reads
and termination behavior are proved safe for every originally defined input.
Otherwise protect its original predicates and paths without executing more work.

Generalize flattening to bounded regional dispatch relations coordinated with
bundle and object phases. Several dispatch groups can use different relations
and transition templates. Useful data state should determine representation
updates, while dispatch identifies the next valid transfer. The semantics
still contain a recoverable control location; multiple stored words do not
create independent secret control machines.

Change the current one-word coupling into supported multi-value contracts with
W2. Require the caller/dispatcher and selected data consumers to agree on
phase, without a freely resettable mirror that immediately restores everything.
Avoid expanding every candidate comparison into a large nonlinear network.
Partition dispatch regions and measure selection cost; v03's linear scan of
candidates already has significant runtime cost.

Attack controls must cover:

- recovering useful computation without reconstructing the full CFG;
- canonical control-state resets with unchanged data, then repaired data;
- supplied phase/invariant recovery and inferred phase recovery;
- one-variable enumeration and two-/few-variable truth tables;
- symbolic summaries of loops, feasible-edge pruning and exact predicate fits.

Deliverable: a recoverer needs additional verified information to repair the
combined representation beyond v03's key/salt/token plus one lane word. A broken
canonical reset alone is not evidence; successful repair time is the metric.

### W5 — coherent fusion, private calls and activation ownership

Implementation increment: [direct self-recursive activations](NATIVE_SELF_RECURSION_V1.md)
are available behind an explicit flag, with shared policy/emitter eligibility,
actual merge coexistence, independent-output and rejection tests. This does not
complete the joint bundle or closed-object pointer contracts below.
An additional default-off [private-input continuity path](NATIVE_BUNDLE_CALL_INPUTS_V1.md)
lets selected bundles consume encoded integer arguments without an intervening
scalar reconstruction, with distinct partial/full accounting. A separately
ablated [bundle-to-interface supply path](NATIVE_BUNDLE_CALL_OUTPUTS_V1.md)
supports encoded argument/result supplies from pure bundles and local tiles.
A default-off [joint argument-tuple path](NATIVE_JOINT_CALL_ARGUMENTS_V1.md)
now handles two-to-four same-width private parameters with direct bundle
consumption/supply and matched paired controls. Mixed-width joint groups,
joint/aggregate returns and closed-object pointer interfaces remain work.

Resolve merge/fusion/call-encoding competition during planning. For each
eligible internal group choose exactly one policy: fuse into a useful region,
keep an encoded interface, or preserve a recorded scalar boundary. Do not let
merging consume the group first and then silently credit encoded calls as on.

Private interfaces must exchange bundle descriptors and encoded values that
the callee consumes directly. Return the next representation and permitted
context effects without a generic decode/encode wrapper. Include defined
argument/result attributes, truncation and alias/effect summaries in the
contract. Preserve external linkage, function identity and address-taken uses.

Start with the existing safe integer signatures, then support pointers to
proved closed objects using the W3 ownership model. This is important for C
codebases: integer-only call coverage excludes many real interfaces. Keep
unproved escaping pointers at explicit boundaries. Use separate specializations
for a bounded set of proven call contexts, with a code-growth cap.

Add direct self-recursion after nonrecursive contracts pass: every invocation
gets its own frame/representation, preserving caller state and return phase.
Mutually recursive SCCs are an explicit second stage with bounded descriptors;
do not claim recursion support from testing ordinary nonrecursive calls on
several threads. Unknown callback/reentry edges, varargs, EH, returns-twice and
musttail retain exclusions until separately supported.

Register generated support code before planning, attach effect summaries and
bound helper generation. Absorb or protect useful helpers according to their
role; message formatting and unrelated initialization cannot consume the main
semantic budget merely because they are large.

Deliverable: compatible fusion and encoded-call coverage in one module, tests
for supported recursion/reentry/threads, and reduced avoidable scalar crossings
on held-out multi-function programs. No requirement to force private calls into
the fully fused crackme.

### W6 — attack-guided candidate selection and scale policy

Search a bounded library of verified W1–W5 candidates at useful-region
granularity. The development loop can be expensive; shipped compilation uses
cached, versioned rules plus a bounded candidate count. Candidate identity
includes representation, phase policy, storage mapping and transfer sequence.
Keep deterministic random selection and the current v03 policy as ablations.

Apply acceptance filters in order:

1. semantic validity and supported effects;
2. complete, internally consistent cost/coverage accounting;
3. explicit compile/runtime/size limits;
4. validated normalization and summary-transfer measurements;
5. holdout results, which are never used to tune the same candidate.

Prefer a Pareto comparison of repair cost, recovery success and resource cost
over one opaque score. A candidate that defeats one fixed syntactic extractor
but collapses under another normalizer should be visible in the result. Add
linear/affine/bit-vector fitting and inverse-representation synthesis alongside
Ghidra/GCC; do not train only against v03's literal script or addresses.

Select groups using original graph structure, effect/ownership proofs, useful
consumer reach and estimated benefit per cost. All source-owned functions and
objects must appear in denominators. Report both raw operation coverage and
cost/source-weighted coverage; no one weighting may hide uncovered code.

Reserve cost for coherent bundles, memory transfers, call contracts and control
before optional expansion. Maintain per-function, per-object, per-region and
module caps. Charge generated support once at its owner. If the plan does not
fit, drop a whole coherent unit or select a cheaper verified implementation;
avoid scattering decode boundaries merely to retain an advertised node count.
Report the resulting loss and preserve transactionality for all affected globals,
functions, block-address users and attributes.

Deliverable: deterministic selection that improves held-out recovery measures
within recorded costs, with the exact rejected/accepted candidates retained.

## 6. Pass order and code organization

Proposed order, with each semantic step verifier-checked:

    frontend IR and explicit closed-world preparation
      -> origin/effect/ownership analysis and boundary inventory
      -> shared region, object, phase and call planning
      -> reserve costs; choose fusion or encoded interfaces
      -> verified bundle/operation, memory and private-call lowering
      -> phase-aware predicates and native flattening
      -> bounded existing indirect-call and expression diversity
      -> helper closure, late-data coverage, final verification/report
      -> backend O0 and ordinary link

Fusion decisions may change the graph: either plan a virtual fused view or
recompute affected analysis before final selection. A stale pre-fusion plan
must not be applied to changed IR. Later passes must preserve transfer contracts
or force final-inventory revalidation. Keep the existing pipeline as a versioned
ablation instead of changing its behavior underneath the v03 artifacts.

Use existing entry points, seeds, reports and conformance drivers. Suggested
implementation split; exact names may be adjusted to existing conventions:

| Area | Existing base | Proposed responsibility |
|---|---|---|
| Planning | `NativeConnected.cpp`, `NativeBudget.cpp`, `NativeRegions.cpp` | `NativePlan`: origin graph, effects, boundaries, selection and owned budgets. |
| Representation | `NativeConnected.cpp`, `NativeEncoding.cpp` | `NativeRepresentation` / `NativeTransfer`: descriptors, verified laws and combined native emission. |
| Object state | Connected object walk and data encoder | `NativeObject`: layouts, phase state and direct encoded storage transfers. |
| Calls | `NativeCall.cpp` | Group policy, bundle ABI, activation contracts and absorption. |
| Control | `Flattening.cpp`, `NativeInvariant.h` | Shared phase/dispatch contracts; no duplicated update formulas. |
| Driver | `NativeObfuscation.cpp` | Validation, stage orchestration, rollback and effective configuration. |
| Evidence | `conformance/connected_*`, `relation_recovery.py`, `recovery*.py`, `whole.py`, `scale.py` | Extend common reports and add focused transfer/normalization adapters. |

Do not build a second general compiler IR or runtime interpreter. The private
plan should be small enough to inspect, serialize and validate; actual execution
is still ordinary LLVM IR lowered to native instructions.

Proposed independent flags, defaults off during development:

- `native-bundles`, `native-transfer-family`, `native-bundle-values`,
  `native-transfer-nodes`;
- `native-phase-transfers`, `native-phase-limit`;
- `native-object-bundles`, `native-object-indexing`;
- `native-predicate-fusion`, `native-dispatch-relations`;
- `native-call-policy`, `native-call-contexts`, `native-recursive-calls`;
- `native-selection-policy`, `native-semantic-budget`.

Names are proposals, not currently usable command-line options. Expose matching
driver flags and one recorded effective configuration; validate dependencies
before compilation. Keep per-feature off/on and leave-one-out ablations. Every
new report meaning gets an appropriate schema revision, with unknown older fields
remaining unknown. Never infer coverage from a flag being enabled.

## 7. Conformance and recovery gates

Treat correctness, emitted coverage, normalization survival, practical cost and
agent recovery as separate outcomes. A correct experimental build can be
benchmarked before every research workstream is complete, provided its coverage
and limits are disclosed. That is not promotion of an unfinished preset.

### A. Exact semantics and compiler integration

For each representation/transfer, retain its specification, preconditions,
inverse where applicable, and an independent reference model. Check entry,
transfer, conversion, predicate, object update and join laws. Use explicit
bit-vector semantics for every supported width; integer overflow in unsigned
IR arithmetic is defined, while out-of-range shifts and poison are not.

- Prove bounded primitive laws with SMT or a reviewed algebraic derivation.
  Enumerate complete small domains where feasible. Wider SMT unknown is recorded
  as unknown; it cannot establish a law or be converted to a protection score.
- Compare emitted IR for instantiated transfers against the independent source
  semantics. Model proof alone does not validate the emitter. Restrict automated
  translation validation to supported subsets; state coverage for memory/loops.
- Run full-output clean/native/post-O2 differentials at both O0 and O2 frontends,
  across fixed seeds and input corpora. Keep existing regressions for musttail,
  returns-twice, symbol collisions, shard limits and block-address rollback.
- Test carries, borrows, high-bit changes, shifts at 0/width-1, signed compares,
  truncations, overflow, mask changes, all-equal/all-different inputs and
  constructed equality cases. Include adjacent invalid summary predictions.
- Exercise zero/one/many loop iterations, PHI cycles, early exits, alias joins,
  object tails, initialization, partial writes and supported memcpy patterns.
  Never read uninitialized tile members to introduce coupling.
- Test ABI attributes, multiple callers, actual recursion, permitted reentry,
  threads and activation cleanup. Do not move trapping/effectful work across
  guards. Run suitable sanitizer lanes separately from static release artifacts.
- Check staged and final hashes, source immutability, deterministic output,
  private artifact isolation and expected exact grader behavior.

Counterexamples fail the candidate and get a minimized regression. Correctness
timeouts or unsupported validation remain incomplete, not successful protection.
Do not claim whole-program equivalence from a finite differential corpus.

### B. Normalization and semantic extraction

Retain matched representations of the same candidate at each stage:

    selected original region
      -> protected IR -> backend assembly/binary
      -> decompiler/lifter output
      -> validated recovered slice
      -> local-memory/constant/helper normalization
      -> GCC O3 or LLVM O2/O3 plus model fitting
      -> independently checked semantic summary

Make the branch of this pipeline using private origin maps explicitly informed.
The binary discovery branch cannot receive those maps, annotations or answers.
Allow decompiler repair scripts but hash them and charge their repair effort.

The aggressive local-memory normalizer may remove volatile/pinning artifacts
only after establishing that the particular compiler-owned storage has no
relevant observable behavior in the recovered semantics. Do not blanket-delete
volatile operations from arbitrary application code and declare equivalence.

Retain callable roots and all relevant outputs while recompiling; assert they
remain present. Reconstruct exact widths, defined shifts, signedness and object
bounds. Ghidra pseudocode with incorrect array extents or unspecified behavior
cannot serve as a valid optimizer benchmark until repaired and checked.

Include these independent attacks:

1. Constant-table and decoder extraction, including phase/index recovery.
2. Local memory forwarding, context specialization and proven helper summaries.
3. XOR/difference/affine projection, linear-algebra recovery and bit permutations.
4. Small-domain exhaustive evaluation and multi-input QF_BV fitting.
5. Inverse-network inference and low-degree/Boolean summaries where applicable.
6. Loop induction/bound recovery, path slicing and semantic recurrence summaries.
7. Native dispatcher inversion and canonical-state repair, with live data.
8. Same inferred model transferred across sites, seeds and different programs.

Do not reject a candidate simply because the original operation was XOR; correct
semantics necessarily admit it. Measure how the attacker discovered the valid
interface/projection and whether that work transferred. Supplied-encoding tests
are deliberately strong controls, not the primary binary-only threat model.

A timed-out attack with validated controls may give a censored cost observation.
Unknown equivalence, unsupported lifting, malformed slices, missing outputs or
tool crashes are inconclusive. Keep a known-solvable control for every attack
and fixture combination; failure of that control invalidates the comparison.

### C. Coverage and cost accounting

Extend the common report gate, used by both fixture and scale drivers, with:

- all eligible source operations/objects/call edges and selection/skip reasons;
- selected logical values, bundle membership, useful transfers per lifetime,
  loop/phase edges and live outputs actually consumed in joint form;
- scalar boundary uses by reason and original consumer; partial coverage must
  not become full coverage merely because one use was rewritten;
- encoded numeric reads, storage-to-consumer edges, dynamic-index coverage,
  tile updates, re-encoding bytes and unavoidable address materialization;
- fully/partially absorbed interfaces, scalar wrappers and activation effects;
- effective recovered family classes and summary-transfer outcomes after
  normalization, alongside nominal emitted family counts;
- estimated versus actual IR growth, function/object/module costs, reserves,
  attempted/retained/rolled-back work and source-weighted coverage;
- full ELF size AND application text/data size, so linked libc cannot dilute
  the apparent expansion ratio;
- trusted runtime distributions, compile time and peak memory under pinned
  toolchain/container resource limits. Include repeated useful computation for
  tiny targets so process startup does not dominate, as well as end-to-end cost.

Report dependency breadth as evidence about an interface, not a hardness proof.
Syntactic taint can overestimate dependence, while semantically independent
outputs can have a jointly difficult-to-infer representation. Validate actual
summary behavior and avoid universal rank-based acceptance rules.

### D. Evaluation matrix and overfitting controls

Freeze tuning and holdout manifests before choosing candidates. Use:

- the unchanged crackme, clean/v03/v04, O0 static stripped;
- small programs with bytewise and wordwise arithmetic, mixed-width transfers,
  parsing/state machines, table-driven kernels and bounded memory loops;
- separate multi-function, recursive and aliased-object fixtures;
- unchanged zlib, Lua and SQLite for scale continuity;
- at least two additional program families not used to design or tune the
  candidates, with their input/output contracts frozen in M0.

Zlib/Lua/SQLite have already influenced this work, so they are scale regressions,
not fresh evidence of generalization. Source hashes, dependency versions, seeds
and workload hashes enter each manifest. Keep held-out seeds separate too;
another seed of the same program is not a held-out program family.

Start each new emitter with seeds 1, 3 and 4 for regression and a disjoint seed
set for promotion. Rotate a previously untouched holdout into future tuning
only after reporting the original holdout result; replenish it for the next
development cycle. No known flag, expected table or transcript-derived address
may enter generic compilation or a binary-only recovery adapter.

Run individual feature ablations, the combined candidate and leave-one-out
variants. Test a second normalizer/tool version when feasible. Compare both
equal-resource builds and each configuration's chosen operating point.

### E. Ambition and promotion targets

Lock these provisional targets in M0 after reproducing baseline costs. Any
change is a recorded configuration revision, not a silent gate relaxation.

| Dimension | Initial target |
|---|---|
| Known attacks | At least 5x median verified recovery cost on a predefined held-out region grid relative to v03, or a valid censored lower bound; report per-attack and cheapest successful attack, not just the worst case. |
| Transfer | The inferred v03 projection/operation summaries must require substantive representation repair across held-out sites/programs, with time, queries and script changes recorded. Address edits alone do not satisfy this. |
| Useful coverage | Mandatory nonzero persistent bundle, loop-phase, joint/phase storage with dynamic indices, predicate and call coverage on designated eligible fixtures; disclose which are absent on each real program. |
| Boundary reduction | Target at least a 50% reduction in avoidable scalar-use crossings on designated fixtures at matched useful coverage. Keep external/address boundaries and skipped source code in the report. |
| Fast development | Bounded primitive/slice checks suitable for every milestone; no paid agent call required to test one transfer. |
| Crackme cost | First combined comparison at the same 250k module cap and 6 GiB/4 CPU tool limits, with compile timeout explicitly up to 600 seconds; target no more than 2x v03 application text and median trusted runtime. |
| Scale cost | Retain 250k-cap runs and separately labeled 1.5M-cap runs; compare to v03 at each same cap. Track runtime/text coverage tradeoffs and do not silently raise limits to pass. |
| Fresh agents | At least three independent matched runs per selected artifact with fixed model/tool/prompt policy and a declared 600-step, two-hour wall budget; include another held-out target, not only the crackme. |

Recovery-cost targets are empirical goals, not assumed consequences of a
feature. Use robust timing where baseline work is tiny, and report query counts
and effect sizes too. A tool error cannot provide a censored lower bound.
Agent timeouts are censored observations, not infinite hardness. Three runs are
an initial variability check, not a broad statistical proof; expand sampling
if observed results do not distinguish the candidates.

An expensive research preset may be recorded separately even if it misses the
practical cost target. It must not be called a cost-matched win. A higher build
cap is allowed as a distinct experiment, never as a way to rewrite the earlier
comparison. Large static libc must not hide application-level cost regressions.

## 8. Delivery order and difficulty

Implementation checkpoint: [experimental native bundles](NATIVE_BUNDLE_V1.md)
documents the first descriptor-driven, bounded M2 emitter and its controls.
The continuation adds dominated-header recurrences with one to four encoded
backedges, edge-specific tuple joins, static/two-phase carrier controls and an
opt-in, explicitly accounted scalar projection mode. This is not completion of M0–M6;
arbitrary cross-region joins, memory, predicate and private-call bundle integration and
cost-matched recovery evaluation remain outstanding.

Implement medium milestones with independently reviewable code and evidence.
Maintain the current two-space C++ style, stdlib Python tests, schema conventions
and owner Git identity. Refactoring must preserve the existing v03-off path.

| Milestone | Deliverable | Dependencies / difficulty |
|---|---|---|
| M0 | Freeze v03 attack/evidence; validate normalization controls; fix boundary denominators and lock budgets/corpora. | First; medium engineering. |
| M1 | Typed planner/descriptors, origin/effect ownership, budget reservation and old-family compatibility. | M0; high engineering. |
| M2 | Two persistent bundle candidate families and verified combined native transfers, with inverse controls. | M1; highest research risk. |
| M3 | Finite phases, PHI/backedge transfers, bounded dynamic-index objects and immutable-data continuity. | M2; high correctness/engineering risk. |
| M4 | Persistent predicate/reduction transfers and regional dispatch with useful data phases. | M2–M3; high research risk. |
| M5 | Fusion/call policy, encoded bundle interfaces, closed-object pointer contracts; then supported recursion. | M1–M3; high ABI/ownership risk. |
| M6 | Attack-guided library selection, integrated budget policy and full unchanged-program differentials. | Initial selection starts at M0; complete after M2–M5. |
| M7 | Frozen combined candidate, complete ablations, binary-only agent runs and honest promotion decision. | M6 plus correctness and required coverage. |

M2 is the main research bet. If generic nonlinear wrappers collapse quickly,
retain their negative results and continue with longer combined transfers and
representation continuity. Do not compensate by adding more rounds until a
timeout is manufactured. If a branch of the design cannot beat existing
representations under the declared cost, leave it experimental or drop it from
the promoted preset.

M3 and M5 are necessary for real-program applicability; finishing scalar
examples is not completion of v04. Support narrow well-defined ownership first,
then expand it with explicit tests. Unsupported language/ABI features remain
visible limitations rather than blocking unrelated experimental work.

Run a correctly packaged intermediate crackme when it can test a substantive
milestone; label it by exact checkpoint and effective features. A single failed
agent run does not complete M7. Avoid expensive polling loops; retain artifacts
and examine completed runs or user-requested status.

## 9. Evidence layout and completion criteria

Keep compiler code, models, generic test fixtures and public design docs in this
fork. Store private instance data, recovery transcripts, answers and benchmark
artifacts under `obfuscation-harness/versions/v04/artifacts/`, excluded from Git
and agent workspaces. Each artifact records parent baseline, compiler/plugin,
toolchain, source/workload, seed, effective options and input/output hashes.

Version READMEs distinguish implementation, correctness, coverage, cost,
normalization and agent outcomes. Preserve the original failed build and attack
attempts. Do not overwrite v03 cells or use a new binary with an old manifest.
This planning change does not commit the local review or handoff documents.

Implementation completion means M0–M6 have usable implementations and explicit
supported-scope tests. Empirical promotion additionally requires M7 evidence:

- correct combined builds with coherent useful coverage, including designated
  memory/call/loop fixtures and measured unchanged-program behavior;
- verified failure or increased cost of previously successful summaries after
  fair interface discovery/repair, across multiple seeds and program families;
- fresh agent results on the fixed crackme and another held-out program;
- matched resource accounting and all inconclusive/unsupported results retained.

If those measurements show little improvement, the implementation can be complete
while the stronger-preset hypothesis fails. Publish that outcome and use the
working attack as the next regression. Feature count is not the acceptance test.

## 10. Roadmap mapping and remaining backlog

| Existing direction | v04 commitment |
|---|---|
| R1 persistent values / P1–P4 | W1 joint lifetimes and combined transfers, W2 phase changes. |
| R2 invariant-dependent semantics / P6 | W2 useful representation relations and W4 data/control contracts. |
| R3 multi-output fusion | W1 multi-operation synthesis and W4 exact predicate reductions. |
| R4 memory representation | W3 encoded object tiles, bounded indices, phase updates and numeric-data continuity. |
| R5 attack-guided selection | W0 normalization/summary controls and W6 held-out cost-aware selection. |
| P5 generated support / private calls | W5 early role/effect analysis, compatible group policy and encoded activations. |
| Scale coverage and budgets | Shared planner, W6 reservation and unchanged-program gates. |

R6 proof-erased predicates, semantic mimicry, algorithm-transplant corpora and
arbitrary function fragmentation remain later experiments. This solve does not
justify making them prerequisites. R1–R5 directly address its working method.

MC instruction selection, flags/carry work, internal calling conventions and
post-link pointer handling stay in the separate backlog until stage evidence
identifies a leak they can economically address. Source-independent properties
like correct bit-vector lifting must remain available to the analyst; v04 aims
to increase the work needed to compose the resulting semantics.
