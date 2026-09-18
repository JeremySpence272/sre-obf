# Experimental closed local object bundles

This is a bounded first W3/M3 increment, **not completion of W3 or v04** and not
a promoted preset. `-native-object-bundles=1` requires `-native-bundles`; the
shared harness spelling is `--bundles --object-bundles`. It is off by default.
There is no VM, MC/post-link transform, source-specific recognition, hardware
check, dynamic secret, or anti-debug behavior.

## Ownership and admission

The pass inspects entry-block allocas in original selected owners, after fusion
and encoded-call preparation but before the pure bundle and connected passes.
It selects at most one closed `[N x iW]` alloca per function, N=2..4 by default and
W=8/16/32/64, with count one and address space zero. Function structure must be
ordinary nonvariadic IR without personality, EH, indirect terminators, inline
assembly, returns-twice/musttail calls or stack save/restore. The function cap
is 12,000 incoming instructions.

The explicit [larger-tile experiment](NATIVE_WIDE_TILES_V1.md) permits N=5..8
under the same ownership and growth limits. It is not the default policy.

The complete object-use walk accepts exact-width, nonvolatile, nonatomic scalar
loads/stores and root-relative inbounds GEPs. It also accepts bounded fixed-vector
reads of whole elements as explicitly decoded output boundaries (not encoded
vector computation). Their start must be constant and the entire span must fit.
Root-relative constant byte offsets must be nonnegative, element-aligned and
inside the object. Byte-addressed pointers do not permit bytewise observation.
Every scalar element index must be proved
nonnegative and below N by LLVM known-bits analysis; an `inbounds` annotation
alone is insufficient. GEP sign extension is respected. No pointer escapes,
identity observations, derived aliases, partial/byte accesses, vector stores,
memory intrinsics, pointer PHIs/selects or unreachable accesses are admitted.
Those cases remain unchanged with an explicit fallback reason.

Whole-object lifetime markers are supported under `sre-tile-lifetime-v1`:
either none, or one root start in the entry block dominating all accesses,
plus up to eight reachable ends. After an end, no object access or further
lifetime marker may be reachable, including through a backedge or shared
epilogue. Mutually exclusive ends and a start without explicit ends are valid.
Restarts, late starts, unreachable markers, derived-pointer markers and operand
bundles are rejected. The LLVM 22 whole-alloca marker calls are retargeted in
place to the new allocation, never discarded or moved. The original alloca
alignment is preserved, including alignment promised by lifetime arguments.

The first N memory accesses must initialize each distinct constant slot exactly
once in the entry block. The last initializer must dominate every remaining
access. No object read or update may precede full initialization. This proves
the extra read-modify-write accesses stay inside completely initialized,
private storage. Guards and original memory access positions are retained;
the transform does not hoist an object access out of its original control path.

There must be at least four supported operations on a load-to-store path.
Operations have the same fixed-width arithmetic/Boolean/constant-shift contract
as pure bundles. The operation limit is `-native-transfer-nodes` (default 16,
maximum 32); the memory-access limit is 64. Unknown shifts, casts and PHIs are
explicit scalar boundaries, not silently encoded edges. Dead arithmetic that
does not reach a store is not credited as useful encoded update work.

The report denominator is **inspected entry allocas**, including unsupported
layouts and existing owners. It is not all program memory, all heap objects,
or a claim that every instruction in a selected owner is protected.

## Representation and lowering

`NativeBundleMath.h` shares the existing triangular mask and encoded arithmetic
with pure bundles. The descriptor selects XOR or additive coordinates, salts,
rotation counts, and a seeded bijection from N logical to N physical cells.
`-native-transfer-family` and `-native-bundle-pins` apply to both paths;
`-native-bundle-values` applies only to pure-register bundles. Object width is
the actual admitted array size.

The private allocation contains N coordinates plus a carrier. Initialization
uses the original initializer SSA values at the last initialization point;
it never reads uninitialized source memory. Original stores, GEPs and allocation
are removed. There is no persistent plaintext shadow. Scalar values entering
from outside the selected graph remain an explicitly counted input exposure.

A source load reads the encoded tuple and produces a pair `(E,R)` directly.
Its logical index selects the appropriate encoded pair; it is not encrypted
addressing. Supported consumer operations use `NativeTransfer` without first
creating the decoded scalar. A store reads the old tuple, selects the new pair
for its logical destination, then repairs every coordinate using old/new masks.
For unchanged cells this is `E xor (R xor R')` or `(E + R') - R`. The old masks
are always computed from the old tuple. All other cell values are preserved.
Slot comparisons preserve narrow LLVM index semantics: impossible slot numbers
are not truncated into an i1/i2 index type. A regression reproduced the earlier
i1 bug, where slot 2 compared equal to slot 0 after constant truncation.

External uses reconstruct a scalar at the original definition point. This
includes encoded results used as an index. Reports count original scalar
boundary values/use edges, including the subset of GEP-index uses. Dynamic
access counts also include indices that entered as ordinary scalar inputs;
`scalar_address_uses` is not a count of every physical machine address.
Tracked index bindings follow RAUW before source instructions are erased.
Packed output reads load the tuple once and reconstruct the requested vector
lanes. `vector_output_values`, `vector_output_uses` and `decoded_vector_lanes`
record that exposure separately; those decodes are not credited as useful
encoded arithmetic. This permits ordinary O2-coalesced output reads without
pretending the vector stays protected at the interface.

Without `-native-object-phases=1`, the layout and carrier are **static for the
activation**. The pure loop-phase option does not imply object rekeying.
The shared harness exposes the separate `--object-phases` switch.
Each call owns an independent stack
allocation, so no process-global state or recursion/thread state stack is needed.
Pinning makes only the private tile accesses volatile. The unpinned arm is a
mandatory control for experiments, not an alternate correctness contract.

The pointer-free descriptor/access inventory is decided before mutation, while
LLVM bindings retain the existing CFG and scalar operand edges. This is not yet
a replayable whole-CFG memory schedule or a formal proof of the LLVM emitter.

## Budgets and accounting

Tiles reserve at most half of the existing one-third bundle headroom. Pure
bundles receive the original share minus actual retained tile growth; the
module cap is not raised. Complete object units are selected by useful-operation
density, with lexical function/object ties, at most one per owner. Cost is:

    512 + 1200 * useful_operations + 192 * memory_accesses * cells

Object phases add `64 * memory_accesses * (cells + 2)` to that reservation;
the per-object and module limits do not change.

The per-object cap is 65,536. Every selected owner has a body-only transaction;
invalid IR is fatal, and actual growth above its reservation restores the body.
No new global or callee escapes that transaction. New code/storage is tagged
bundle-owned so the later bundle, connected and legacy memory paths do not
count or re-encode it as new source work.

The native-v6 report adds `object_bundles` rows using `sre-object-bundle-v1`.
Feature `object_bundle_contract=3` additionally requires a finite phase/layout
contract and complete phase traffic accounting. Contract 2 introduced lifetime,
access-span and vector boundary accounting. Both older contracts remain readable.
The shared accounting gate checks dispositions, ownership/initialization and
bounds declarations, layout bijection, useful operations, original ancestry,
growth, extra physical reads/writes and scalar exposures. Counts are static
instruction instances, not dynamic traffic. Ancestry is input-IR reach, not
final semantic coverage. Old two-lane memory coverage is not credited here.

## Reproducible conformance

Run from the repository root with a fresh output directory:

```sh
python3 -m conformance.tile_run --out out/NEW-tile-matrix \
  --toolchain-image sre-obf-dev:llvm22 --shapes supported
python3 -m conformance.tile_run --out out/NEW-tile-address \
  --toolchain-image sre-obf-dev:llvm22 --widths 8 64 --cells 4 \
  --shapes address --seeds 4
python3 -m conformance.tile_run --out out/NEW-tile-ablation \
  --toolchain-image sre-obf-dev:llvm22 --widths 8 --cells 2 \
  --families xor --seeds 3 --shapes supported --ablation
python3 -m conformance.bundle_decompile --tile --width 8 \
  --case out/NEW-tile-ablation/i8-n2-supported --stem xor-3-pins-1 \
  --out out/NEW-tile-decompile --toolchain-image sre-obf-dev:llvm22 \
  --ghidra-image revbench-codex-3b320b602312:latest
```

The runner compares **all cells** against an independent scalar oracle, at the
tile stage, end of the native pipeline, and after `default<O2>`. Byte-width
inputs exhaust all 65,536 input pairs; wider inputs include edges and seeded
random cases. Native output and report determinism, repeated calls and threaded
calls are checked. Negative ownership fixtures are compiled/verified but never
executed when their source could be undefined.
These are deliberately shaped IR fixtures, not evidence of broad optimized
C/C++ coverage. The additional `--c-o2` mode compiles an archived ordinary C
fixture with plain Clang `-O2` (32-/64-bit word variants), without disabling SROA,
vectorization, lifetime insertion or unrolling. `noinline` retains the named
test entry; there is no `optnone`, volatile or inline assembly in the C source.
The native transfer-node bound is 32 to admit frontend-unrolled updates. It has
an independent unsigned-word oracle and uses the same all-output/disabled/O2/
threaded checks. Use `--widths 32 64 --cells 2 --shapes supported --c-o2 --ablation`.
This establishes optimized-C fixture support, not broad corpus coverage.
`--shapes many-loads` additionally stresses deterministic
boundary emission beyond the inline pointer-set capacity; its redundant loads
are a stress control, not evidence of useful new protection.

`--ablation` adds matched feature-off and post-O2 feature-off artifacts. The tile
decompiler control requires these and exports five matched stripped arms, using
the trusted link map only to locate the root. This is informed-entry analysis,
not binary-only discovery. Full-output agreement, assembly hashes and decompiler
shape are diagnostics; none establishes resistance to recovery scripts, SMT,
storage forwarding, or agents. Extra decompiled lines are not a hardness score.

## Lifetime and optimized-C continuation evidence, 2026-09-18

Final plugin SHA-256:
`eef278941d55e9ca9ba2551078dde9c0afe30cbd8ff360260be4ed4749a9f335`.
The full pinned-solver suite passes 449 tests, no skips (78.061 seconds).

- `out/tile-lifetime-first-20260918`: ten i16 controls for closed/open lifetimes,
  mutually exclusive ends with a shared epilogue, constant byte offsets and
  vector exits, both pin modes.
- `out/tile-lifetime-negative-20260918`: 22 compiler-only controls rejecting
  early/backedge/conditional ends followed by accesses, restarts, missing/late
  starts, repeated/unreachable ends, unaligned offsets and invalid vector spans.
- `out/tile-lifetime-matrix-20260918`: 16 i8/i64 three-cell lifetime-join/vector
  controls, both families and pin modes, seed 3. Byte input pairs exhaustive.
- `out/tile-narrow-prefix-control-20260918` reproduces an actual pre-fix output
  mismatch for a proved-zero i1 index. `out/tile-narrow-fixed-20260918` passes
  eight exhaustive i8 four-cell constant/dynamic-index controls with both
  families and pin modes. The failure artifact is retained, not overwritten.
- `out/tile-lifetime-alignment-20260918`: two positive 64-byte-aligned marker
  controls and two pointer-bearing operand-bundle rejection controls.
- `out/tile-lifetime-final-reemit-20260918`: final plugin emits byte-identical
  IR for all 56 preceding first/negative/matrix/narrow controls and all 48
  original scalar tile matrix cells (104 total); final accounting checks pass.
- `out/tile-c-o2-release-20260918`: final plugin, eight ordinary Clang-O2 C
  cases, 32-/64-bit words, both families and pin modes, seed 4. The C source
  is archived/hashed. Each retains **18 encoded operations**, translates two
  lifetime markers, and records two decoded vector lanes. All 593 outputs
  agree with the independent oracle at clean, tile-stage, final and post-O2
  stages; matched disabled/O2 and threaded controls pass. This is nonzero
  optimized-C fixture coverage, not nonzero large-corpus coverage.
- `out/tile-c-lifetime-cff-20260918`: both families with applied multi-state
  flattening under the max constenc/flattening ablation; 593 C-oracle vectors
  pass natively and after O2. Not the full max preset.
- `out/tile-c-o2-decompile-20260918`: five stripped informed-entry arms, each
  with 1,105 agreeing outputs. Clean/native/post-O2/off/off-O2 C sizes are
  985/19,851/12,425/2,660/2,588 bytes. Shape diagnostics only, not hardness.
- `out/tile-lifetime-final-scale-zlib-20260918` and
  `out/tile-lifetime-final-scale-lua-20260918`: exact final plugin passes the
  original primary 250k caps, workloads, accounting and post-O2 gates. IR remains
  248,698/238,820; **zero tiles retained in either corpus**. The formerly
  lifetime-blocked candidates now fail the subsequent pointer-escape check.

Earlier continuation runs are preserved: first/lifetime-negative artifacts
used `3eb5b3bb57e5281ff77253e11fcb43d0cbb9b6d6b130a1717bb2b2bb9b6185c1`;
the initial narrow fix and `tile-c-o2-final` used
`53856febe9bb8577e64dc6431137c635c99217eed5a10b88d9ac213482dbbc44` before
alignment preservation. The final replay and release directories above qualify
the current results. No agent run, protected holdout evaluation, cap increase,
or crackme repackaging was performed. W3 and v04 remain incomplete.

## Initial tile increment evidence (413b2b6), 2026-09-18

That increment's plugin SHA-256:
`96c6a8c748646a529780b2fcd1698f739232665306d82c4243b38b61d08e9beb`.
Pinned LLVM 22.1.8 build passes. The full pinned-solver Python suite passes
442 tests with no skips (84.389 seconds).

- `out/tile-matrix-20260918`: 48 cells across all four widths, three sizes,
  both families and pin modes; clean/oracle, tile-stage, final and post-O2 agree.
- `out/tile-negative-20260918`: 18 compiler-only ownership/initialization
  rejection controls, each with the expected explicit reason.
- `out/tile-address-20260918`: eight i8/i64 four-cell address-boundary controls
  with seed 4; all cells agree and scalar index projections are counted.
- `out/tile-ablation-20260918`: two exhaustive i8 seed-3 cells with matched
  tile-disabled controls, before and after O2.
- `out/tile-final-20260918`: eight final-plugin i16 two-cell controls, both
  families/pin modes, covering many-load determinism and address projections;
  also includes matched disabled and O2 arms.
- `out/tile-final-reemit-20260918`: final plugin re-emits **byte-identical IR**
  for all 76 preceding matrix/negative/address/ablation cells. Those broader
  differentials originally used plugin
  `fbb3e113e037e0e0ffd8790a7339616dfa3b39272562e0ebeb48536a236f9544`;
  the final fix makes large-member boundary emission independent of pointer-set
  iteration. All reports were rechecked with the final accounting rules.
- `out/tile-cff-final-20260918`: both families retain joint tiles and applied
  multi-state flattening under the max-level constenc/flattening **ablation**;
  593 complete-output vectors pass natively and after O2. This is not a test
  or promotion of every max-preset combination.
- `out/tile-off-compat-20260918`: six historical-plugin comparisons (loops,
  projections, memory; both families) preserve identical IR with tiles disabled.
- `out/tile-matched-decompile-20260918`: five stripped Ghidra arms, each with
  65,536 full-output vectors. Clean/native/post-O2/tiles-off/tiles-off-post-O2
  exports are 559/8,586/8,082/4,156/3,990 bytes. These are shape diagnostics only;
  successful decompilation is not semantic recovery and larger C is not hardness.
- `out/tile-final-scale-zlib-20260918` and
  `out/tile-final-scale-lua-20260918`: exact final plugin, original primary
  250,000-instruction cap, full workload and post-O2 accounting gates pass.
  Final IR is 248,698 and 238,820 respectively, unchanged from the earlier
  loop-bundle regression. **Both retain zero new joint memory tiles.**
  Zlib inspects 206 entry allocas; Lua 1,262. Actual skip distributions are in
  the reports, including unsupported layouts, escapes and lifetime markers.

No paid agent run, protected holdout evaluation or crackme repackaging was
performed. Generality and resistance remain unestablished for this increment.

## Finite object phases (September 18 continuation)

`native-object-phases` requires object bundles. Entry stores phase zero; every
non-initializing source store toggles it. The tuple contains N coordinates, a
carrier and the phase word. Phase zero uses the seeded physical permutation;
phase one rotates its logical-slot mapping by one. Both mappings are bijections
over exactly N cells, including N=3. Loads use the stored phase, not a compile-time
guess about which predecessor executed.

For an update pair `(E,R)`, the next carrier combines a rotation of the old
carrier XOR the final coordinate, `(E XOR first_coordinate) + R`, and a seeded
odd multiple of the next phase. The emitter first loads the complete old tuple,
computes every next coordinate in SSA, then writes the complete new tuple.
Every old mask uses the old carrier/prefix; every new mask uses the new
carrier/prefix. Selected and untouched cells use the same remasking law, without
a decoded shadow. This establishes the store law for any new carrier; the
specific carrier recurrence is not assumed cryptographically difficult.

No accesses are hoisted across source guards. Memory owns the current phase at
joins, so a zero-iteration path and predecessors with different store counts
remain valid without cloning CFG blocks or resetting the representation.
The private allocation still belongs to one activation and the same lifetime
proof applies. Static reports count update sites and bytes rewritten per update,
not an invented dynamic traffic estimate.

Evidence before the immutable continuation:

- `out/tile-phases-joins-20260918`: 24 cases, i8/i32, N=2/3/4, both families
  and pin modes; all-output native/post-O2/disabled controls, determinism and
  threads pass. Byte inputs are exhaustive. Includes skipped loops and
  conditional extra stores which give joins different phases.
- `out/tile-phases-c-o2-20260918`: eight unchanged optimized-C cases, i32/i64,
  seed 3, both families/pin modes; lifetime and packed-read boundaries plus
  all matched controls pass.
- These two matrices used plugin
  `9763167e82e7b24627c85fae5e6ee158ed33ee352caeb7e2127704a042e8ee5c`.
- `conformance/tile_model.py` independently checks remasking and physical
  layouts, exhaustively at reduced width and across production widths/history.
  This is a model check plus emitted differentials, not whole-program proof.
- `out/v04-phase-final-reemit-20260918`: all 32 matrix cases re-emitted with
  final integrated plugin `15b643dd74dab7c8233be3e0731743a4129a0366851d7bfab8e39912e0c7b45b`
  have byte-identical protected IR and pass current report gates.

[Immutable numeric tiles](NATIVE_IMMUTABLE_BUNDLES_V1.md) now provide a separate
closed-global backing-to-consumer path. Neither feature establishes resistance
to phase/layout recovery; both remain default-off experiments.

## Remaining W3 work

Still deferred: mutable global ownership, aggregates and derived aliases,
restarted/nested lifetimes, initialized-subobject and memory-intrinsic support,
ownership propagation through direct calls, multiple tiles/owners, larger or
lazy per-tile phase graphs, richer operation scheduling,
and informed index/storage-recovery baselines. Escaping/heap ownership remains
separate research. Generality and promotion gates remain unchanged; protected
holdouts must not be used to tune this prototype.
