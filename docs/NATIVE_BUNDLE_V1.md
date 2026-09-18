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
`--transfer-nodes` and `--no-bundle-pins` options.

This first emitter does **not** carry bundles across PHIs/backedges, memory
tiles, predicates, dispatch regions or private-call ABIs. Existing v03 paths
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
The final host suite has 405 tests, with seven explicit solver-dependent skips.
No fresh paid agent run, holdout protection evaluation or promotion was done.
