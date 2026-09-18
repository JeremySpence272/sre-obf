# Experimental native bundle lowering

This implements a bounded first M2 emitter, not the complete v04 plan or a
promoted preset. It is IR-only and off by default. It adds no interpreter,
environment checks, dynamic secrets, source-specific checks or post-link work.

## Supported scope

`-native-bundles` runs before the existing connected encoder. It schedules
8–32 contiguous, homogeneous integer operations into 2–4 logical slots, with
at least two external input values and two genuinely consumed output values.
Every selected operation must reach an output. Input multiplicity is syntactic;
it is not an independent-entropy or hardness claim.

Widths: i8, i16, i32, i64. Operations: add, subtract, multiply, Boolean operations
and constant in-range shifts, including arithmetic right shift. Effects, calls,
width changes and block boundaries end a candidate window. No memory operation
is moved, no previously guarded work is speculated, and no unknown shift is
introduced. Unsupported instructions remain at explicit scalar boundaries.

The private plan owns opcode/operand/slot choices before lowering. It uses the
shared `NativePlan::Representation` descriptor to dispatch the family, with
logical slots separate from physical coordinates (slots plus one carrier). A separate
binding maps the plan to LLVM instructions. It is not the old connected pass's
observation-only plan. Original input-IR IDs are stamped before fusion; cloned
instructions retain their ancestry, while generated instructions without an
ancestor remain unknown. This does not reconstruct operations frontend O2
already eliminated, or prove all later passes preserve that lineage.

Options, all requiring `-native-bundles`:

- `-native-transfer-family=xor|additive|seeded` (default seeded).
- `-native-bundle-values=2..4` (default 4).
- `-native-transfer-nodes=8..32` (default 16).
- `-native-bundle-pins=0|1` (default 1).
- `-native-bundle-loops=0|1` (default 0).
- `-native-bundle-phases=0|1` (default 0; requires loops).
- `-native-bundle-loop-boundaries=0|1` (default 0; requires loops).

Whole-tuple pinning occurs only at entry/exit, not around every source operation.
The unpinned arm and the informed private-storage forwarder are mandatory
controls. Compiler survival due to volatile storage is not protection evidence.

## Representation and transfer laws

For word width w, all arithmetic is in Z/(2^w). Let `H_k` be the recorded seeded
ARX mask function and M a defined carrier derived at entry. The XOR family is:

    Z_0 = X_0 xor H_0(M)
    Z_k = X_k xor H_k(Z_(k-1), M), k > 0

The additive family replaces XOR with addition. Inversion uses the *encoded*
predecessor, not its decoded value: subtraction or XOR with the same mask.
For each fixed M, these triangular maps are bijections, by induction on k.
The salts and carrier are recoverable software state, not a secret key.

An operation reads pairs `(E, R)` with semantics `E xor R` or `E - R`. Shared
`NativeTransfer` primitives produce another such pair without an explicit
scalar decode. The output is placed in the destination coordinate with the new
mask; every downstream coordinate is repaired using its old and new mask.
For XOR, the repair is `E xor (R xor R')`. For addition it is `(E + R') - R`.
Both preserve the logical value. Induction across coordinates and then across
scheduled operations establishes the combined transfer from the primitive laws.

Primitive algebra:

- XOR distributes over the two XOR coordinates. AND expands its four products;
  three are retained in E and one in R. OR is XOR of both inputs and their AND.
- The prefix adder uses bitwise propagate/generate and defined shifts below w.
  Subtraction is addition of the complemented operand with carry-in one.
- Addition/subtraction are coordinate-wise in the additive representation.
- Additive multiplication expands `(E-R)(F-S)`; the output mask is added to
  the first partial product, not after a decoded product has been assembled.
- XOR-to-additive uses `E xor R = E + R - 2(E & R)`, adding the destination
  mask to the first sum. The reverse conversion shares the two coordinates
  separately and subtracts with the prefix network.
- Constant shifts distribute over XOR shares, including sign-bit replication
  for arithmetic shift. Additive inputs use the verified conversions.

These are semantic arguments, not resistance arguments. Reassociation alone
does not establish the absence of recognizable projections after normalization.
The Python reference, small complete domains, native differentials and informed
emitted-IR validator check different parts of the implementation. Solver unknown
remains inconclusive even when finite differential checks pass.

## Bounded recurrence continuation

The optional loop path carries joint coordinates through a **dominated-header
recurrence** with one unconditional preheader and one to four distinct backedge
predecessors. A dominator tree verifies that the header dominates every backedge
block. The selected pure region still lives entirely in the header and retains
the same width/window/liveness requirements. Every input must be a header PHI;
each incoming backedge value must be a scheduled output. Each edge may select
a different output-to-input mapping. Multiple blocks, exits and backedges are
supported without moving the original operations, effects or control decisions.

Non-PHI inputs, conditional/multiple entry predecessors, unreachable predecessors, duplicate header edges,
non-branch backedge terminators, more than four backedges, and recurrences not
produced by the selected region keep explicit straight-line fallback reasons.
A zero-trip guard outside the preheader remains supported; entry encoding is
not speculated across that guard. No CFG cloning or global mutable state is used.

The preheader freezes/encodes entry inputs once. The header carries all tuple
coordinates and the activation carrier in PHIs. Completed output pairs are
reordered into the next iteration's input slots and remasked directly, without
first reconstructing the recurrence scalars. Old scalar recurrence PHIs are
removed. Scalar outputs are decoded only when there are actual consumers beyond
the selected operations and recurrence edges. Unused logical slots reset to zero.
All pin buffers are entry-frame allocas, not allocations per iteration; when
enabled, pinning happens at entry and the completed backedge tuple.

By default, scalar uses of a recurrence PHI outside the selected region still
prevent loop lowering. The opt-in `-native-bundle-loop-boundaries` mode inserts
one named scalar projection per externally used input slot, after all header
PHIs and before the original instructions. This placement also dominates PHI
incoming-edge uses elsewhere. These are real plaintext exposures, not protected
input lifetimes. The report records both exposed slots and pre-lowering use
counts; summary coverage separates loops with such projections. This mode is
not enabled in a promoted preset. LLVM bindings track replacement values so an
earlier scheduled region cannot retain a dangling pointer to a deleted PHI.

The static-phase control keeps carrier M unchanged. The two-phase arm carries
an ordinary word P in {0,1}, starts at zero, and emits the following update using
the **completed encoded tuple** Z (all arithmetic modulo the word width):

    P' = P xor 1
    H  = rotl(M xor Z_last, rotation_last) + (Z_0 xor salt_last)
    M' = H xor (P' * (salt_0 | 1))

Every backedge starts from the same completed header tuple, not the tuple emitted
for another mutually exclusive predecessor. All old source masks are captured
before M or predecessor coordinates change. The rebase builds each edge's new
tuple in its specified input order. Header PHIs select the entire tuple, carrier
and phase from the same predecessor. XOR repair uses
`E xor (R xor R')`; additive repair uses `(E + R') - R`. These identities preserve
the logical value for arbitrary old/new masks, so the carrier update does not
need an inversion assumption. The representation family and seeded parameters
stay fixed; this is a bounded phase-dependent carrier/rekey law, not a catalogue
of unrelated representation transitions. The carrier and phase are recoverable
program state, not secret entropy. A supplied-descriptor inverse deliberately
succeeds across both phases; no resistance claim follows from this implementation.

The outer `sre-bundle-plan-v1` now records the nested `sre-bundle-loop-v2` contract:
stable predecessor block IDs, edge-specific next-input mappings, phase graph,
encoded recurrence uses, scalar projections and fallback reason. The old single
mapping is retained as a checked alias only for one-backedge loops. Old v1 loop
reports remain readable. Reservations add 2,048 estimated instructions per edge
and 64 per scalar projection, all inside existing caps. Summary counts distinguish
loop regions, backedges, multi-backedge joins and scalar input exposure. Counts
exclude rolled-back loops and remain lowering-stage measurements.
They do not imply survival of equivalent joint dependencies after normalization.

Run `python3 -m conformance.bundle_loop_run --out out/FRESH --toolchain-image
sre-obf-dev:llvm22` for both families, seeds 1/3/4, all widths, pins on/off,
static/two-phase controls, multi-exit/multi-backedge joins and explicit unsupported
CFG fallbacks. Run again with `--bundle-loop-boundaries` to exercise early scalar
users, outside PHI users and tracked binding replacement in an earlier region. Add
`--exhaustive-byte-pairs` to enumerate every byte input pair at exactly two
requested iterations; the multi-exit fixture can exit earlier and the duplicate
edge negative fixture has a fixed three-iteration path. Other counts use finite
edge/random vectors. Full two-word outputs,
zero/one/many iterations, signed shifts, swapped recurrence slots, serial reentry,
concurrent calls, deterministic emission and post-O2 outputs are checked.
All clean fixture outputs match an independent scalar oracle. The reference
model replays the reported recurrence with supplied edge choices and checks every
transfer/rebase. A path's last modeled rebase is unused after its final output;
the model does not prove branch recovery or a whole-program CFG equivalence.

`python3 -m unittest conformance.test_bundle_loops` checks complete tiny-domain
rekeys, all-width randomized mappings, stale-mask/wrong-mapping counterexamples,
rollback accounting and option/report mutations. In the solver image it proves
the arbitrary-mask rebase identities. That is **not** a proof of the whole emitted
loop: `bundle_lift` still refuses loop IR. `bundle_decompile --loop` reuses the
matched stripped clean/native/post-O2 controls with the two-output loop workload.
Decompiler success and syntax metrics remain diagnostics, not recovery resistance.

`conformance.test_bundle_joins` adds all short supplied-edge paths for both
families/phase modes, wrong-path/mapping controls, edge-ID and projection-count
mutations, and actual source-workload coverage of both backedges and early exits
at every width. None of these informed controls is a binary-only recovery test.

## Ownership, costs and reports

One third of remaining module headroom is reserved. Actual region candidates
are planned first. Whole regions fitting nominal function-weighted shares are
funded, then unusable shares are pooled and assigned to additional whole regions
by weight over cumulative cost (function name breaks ties). No share is spent
on a function with no candidate, and no partial region is emitted just to spend
an allocation. The per-function ceiling is 65,536 instructions. Subsequent
connected/CFF allocations see the remaining headroom. At most eight regions
per function are admitted. A conservative estimate rejects whole schedules;
actual growth is checked inside a body-only transaction. The pass creates no
module globals or callees, so body restoration covers its complete mutation.

The `bundles` report uses `sre-bundle-plan-v1`; the outer report remains v6.
Attempted, retained, unselected and rolled-back operations reconcile separately.
Plans publish all operand slots, output slots and mask parameters. All generated
instructions are tagged with their bundle owner and excluded from later
connected candidate enumeration. Region counts describe this lowering stage,
not survival through a decompiler or semantic recovery resistance.

## Gates and remaining work

Run `python3 -m unittest conformance.test_bundle` for reference laws and gate
counterexamples. `python3 -m conformance.bundle_run --out out/FRESH
--toolchain-image sre-obf-dev:llvm22` tests seeds 1/3/4, both families, all widths,
pins on/off, deterministic emission, plan replay and clean/native/post-O2
outputs. The i8 input domain is complete. Wider differential vectors are finite.
`conformance.bundle_lift` translates only a checked straight-line subset of the
actual emitted IR and asks a bounded equivalence query against the clean root.
Unsupported IR and timeouts do not pass. Run its solver tests in the pinned
analysis image.

`conformance.bundle_allocation` checks a 32-function module whose nominal shares
cannot fund individual regions, and reverses function order to check selection
and descriptor stability. `conformance.bundle_decompile` compiles and checks
matched clean/native/post-O2 stripped artifacts and exports their informed-entry
Ghidra output. Successful decompilation and syntax size are not semantic-recovery
or hardness results. The fixture, whole-program and scale drivers all expose
the corresponding `--bundles`, `--transfer-family`, `--bundle-values`,
`--transfer-nodes`, `--no-bundle-pins`, `--bundle-loops`, `--bundle-phases` and
`--bundle-loop-boundaries` options.

Beyond the narrow recurrence contract above, this emitter does **not** carry
bundles across arbitrary joins whose values originate in different protected
regions, memory tiles, predicates, dispatch regions
or private-call ABIs. Existing v03 paths
still cover their previous supported cases; their coverage must not be credited
to the new bundle implementation. M3–M6 integration and M7 empirical promotion
remain separate work. Do not label v04 complete from this emitter alone.

### Checkpoint evidence (2026-09-18)

Private outputs stay under ignored `out/` directories, not in agent workspaces.

- `bundle-regression-20260918`: 48 width/family/seed/pin cells passed on the
  initial emitter. `bundle-coherent-20260918`: 16 all-width cells passed after
  allocation/refactoring. `bundle-descriptor-final-20260918`: eight i8/i32
  cells passed on the final descriptor-driven emitter; all i8 cells exhaust
  both byte inputs, wider cases use 1,105 vectors. Native and post-O2 outputs
  match, plans replay and emission is deterministic.
- `bundle-allocation-20260918`: forward/reverse order of 32 functions retains
  the same five owners and descriptors; 73,280 instructions reserved, 209
  full-output comparisons per arm passed.
- `bundle-compat-v03-20260918` and `bundle-compat-v04-20260918`: six compiler
  cases each pass existing correctness/ownership gates. Old-path IR matches
  the reviewed checkpoint except for its archived `source_filename` line.
- `bundle-decompiler-20260918`: clean/native/post-O2 stripped-byte controls
  preserve all 65,536 outputs and Ghidra exports all three roots. This is
  decompiler operability, not a recovered-model or resistance result.
- `bundle-first-20260918b/emitter-proof.json`: the informed emitted-slice
  equivalence query timed out at three seconds. It remains **inconclusive**;
  exhaustive byte execution is independent evidence, not a solver proof.
- The first zlib run retained no bundles because nominal shares could not
  afford an atomic unit. Its evidence is preserved in `bundle-scale-zlib-20260918`.
  The corrected allocation retains 32 operations in three functions in
  `bundle-scale-zlib-coherent-20260918`, and the unchanged workload passes.
  Lua retains 50 operations in five functions in `bundle-scale-lua-20260918`;
  its unchanged workload also passes. Both use the primary 250k cap.
- SQLite fails the primary cap **after fusion, before bundle lowering**:
  282,760 instructions exceed 250,000. That result remains in
  `bundle-scale-sqlite-20260918`. The separately labelled 1.5M-cap lane in
  `bundle-scale-sqlite-highcap-20260918` passes and retains 28 operations in
  three functions. It is not a primary-cap success.

Each directory records its own plugin hash; the scale runs preceded the final
descriptor-only refactor. The final descriptor checkpoint plugin hash is
`107f6666ec2bba92ab52c5a7150aa8aa04678bdaaf96d629254b86e56d9c889a`.
At the subsequent frozen-holdout checkpoint, all 409 tests passed in the pinned
solver image without skips.
No fresh paid agent run, holdout protection evaluation or promotion was done.

### Recurrence checkpoint evidence (2026-09-18)

Plugin SHA-256:
`f8c7ad2fc9562257157d5e01a4c24b4a377f0ec34bea4e99ae4d54d4443ce7ab`.
The pinned solver-image suite passes all 420 tests without skips.

- `out/bundle-loop-matrix-20260918`: 32 width/family/pin/phase cells, seed 1.
  Each i8 cell checks 66,135 vectors (including all byte pairs at two iterations);
  wider cells check 599 vectors. Clean/native/post-O2 full outputs agree.
- `out/bundle-loop-fallback-20260918`: 16 additive/seed-3 i8/i64 cells cover
  external PHI users, conditional preheaders, multi-exit loops and constant
  backedges, with both requested phase modes. Exact fallback reasons and all
  599 outputs agree in every cell.
- `out/bundle-loop-seeded-20260918`: eight i8/i64 seeded-family cells, seeds
  3/4, pins off and both phase modes, pass all 599 vectors per cell.
- `out/bundle-loop-straight-compat-20260918`: eight existing i8/i32 straight-line
  cells still pass with the new loop features disabled. Emitted IR matches the
  previous descriptor checkpoint exactly after excluding path headers
  (`source_filename` and `ModuleID`).
- `out/bundle-loop-decompile-20260918`: stripped clean/native/post-O2 i8
  two-phase controls agree on 66,135 full outputs and all export through Ghidra.
  Private assembly, disassembly and decompiled output are retained. This does
  not show that a recovered model is unavailable or that joint dependencies
  survive every decompiler normalization.
- `out/bundle-loop-scale-zlib-20260918`: unchanged zlib passes primary-cap
  workload/accounting/post-O2 gates at 248,698 final IR instructions (<250,000).
  It retains 32 useful bundle operations in three owners; one 14-operation
  region in `__obf_merged__auto3` carries two recurrence uses through a two-phase
  backedge. Other bundle owners remain straight-line. This is one observed
  real-program loop, not broad real-code coverage or a hardness result.

`bundle-loop-first-20260918` retains the earlier four-case smoke result. No
protected holdout, paid agent run, promoted preset or crackme repackaging was
performed. General joins, memory, predicates and bundle-call integration remain
unfinished; the earlier SQLite primary-cap failure is not relabelled a success.

### Multi-backedge checkpoint evidence (2026-09-18)

The broad matrix, scale and Ghidra runs used plugin
`0a3bb1d9122f21238d1ed2e66e0c2b58cc62f29178808f6cc1596aa93058cc33`.
Review then added an explicit unreachable-predecessor rejection to prevent dead
CFG edges inflating join coverage. Final plugin:
`d8dd56f8a8dec7bcfe641f1698a85977d669fdd0a64e4e98773a89897a02b953`.
Each artifact directory records the plugin it actually used; earlier evidence
has not been rewritten. The full solver-image suite passes 430 tests.

- `out/bundle-join-matrix-20260918`: 32 all-width/family/pin/phase join cells,
  seed 1; i8 checks all byte pairs at two iterations plus 599 finite vectors,
  wider cells check 599. Both distinct backedge mappings execute in the workload.
- `out/bundle-join-boundary-20260918`: 32 i16/i64 additive seed-4 cells covering
  early scalar users, outside PHI users, earlier-region binding replacement and
  multi-exit loops, pins on/off and both phases. The early-exit predicate was
  revised to inspect low bits so every width actually exercises that exit.
- `out/bundle-join-negative-20260918`: 16 i8 additive seed-3 cells validate
  duplicate edges, non-branch backedges, five backedges, guarded preheaders,
  constant backedges and the strict no-scalar-projection policy.
- `out/bundle-join-loop-compat-20260918`: 16 i8/i32 one-backedge cells pass.
  Their emitted IR matches the previous frozen loop checkpoint after excluding
  only `source_filename` and `ModuleID` path headers.
- `out/bundle-join-final-20260918`: 12 cells on the final reviewed plugin cover
  i8/i64 joins, earlier-region replacement and unreachable-predecessor rejection,
  both phase modes, XOR seed 1 and pins off. Every cell passes all 599 vectors.
- `out/bundle-join-first-20260918`: the earlier eight-cell smoke remains intact.
  Across compiler runs, full clean/native/post-O2 outputs and deterministic
  emission pass. Reference replay checks supplied edge paths, not recovered ones.
  Forty-eight archived v1-loop reports also pass the backward-compatible gate.
- `out/bundle-join-dead-edge-control-20260918`: the archived pre-review plugin
  counts two backedges on the deliberately unreachable-edge fixture; the final
  plugin rejects that recurrence with `unreachable-header-predecessor`. This is
  a reproduced coverage-accounting defect, not an output-correctness failure.
- `out/bundle-join-decompile-20260918`: all three stripped informed-entry arms
  agree on 66,135 complete two-word outputs and export through Ghidra. This is
  diagnostic operability, not a semantic-recovery or resistance result.
- `out/bundle-join-scale-zlib-20260918` and `out/bundle-join-scale-lua-20260918`:
  unchanged source/workload/accounting/post-O2 gates pass under 250k caps, at
  248,698 and 238,820 final IR instructions respectively. Zlib retains the same
  32 bundle operations and one one-backedge recurrence; Lua retains 50 bundle
  operations and no recurrence. Neither retains a multi-backedge join or header
  scalar projection. These runs establish compatibility, **not increased
  real-program coverage** for this extension.

No protected holdout evaluation, paid agent run, promoted preset, crackme
repackaging or push was performed. Arbitrary cross-region value joins and the
planned memory/predicate/call continuity remain open; increased reversing cost
has not been demonstrated.
