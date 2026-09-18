# Experimental closed local object bundles

This is a bounded first W3/M3 increment, **not completion of W3 or v04** and not
a promoted preset. `-native-object-bundles=1` requires `-native-bundles`; the
shared harness spelling is `--bundles --object-bundles`. It is off by default.
There is no VM, MC/post-link transform, source-specific recognition, hardware
check, dynamic secret, or anti-debug behavior.

## Ownership and admission

The pass inspects entry-block allocas in original selected owners, after fusion
and encoded-call preparation but before the pure bundle and connected passes.
It selects at most one closed `[N x iW]` alloca per function, N=2..4 and
W=8/16/32/64, with count one and address space zero. Function structure must be
ordinary nonvariadic IR without personality, EH, indirect terminators, inline
assembly, returns-twice/musttail calls or stack save/restore. The function cap
is 12,000 incoming instructions.

The complete object-use walk accepts only exact-width, nonvolatile, nonatomic
loads/stores and root-relative inbounds GEPs. Every index must be proved
nonnegative and below N by LLVM known-bits analysis; an `inbounds` annotation
alone is insufficient. GEP sign extension is respected. No pointer escapes,
identity observations, derived aliases, partial/byte accesses, lifetime markers,
memory intrinsics, pointer PHIs/selects or unreachable accesses are admitted.
Those cases remain unchanged with an explicit fallback reason.

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

External uses reconstruct a scalar at the original definition point. This
includes encoded results used as an index. Reports count original scalar
boundary values/use edges, including the subset of GEP-index uses. Dynamic
access counts also include indices that entered as ordinary scalar inputs;
`scalar_address_uses` is not a count of every physical machine address.
Tracked index bindings follow RAUW before source instructions are erased.

The layout and carrier are **static for the activation** in v1. The loop-phase
option does not imply object rekeying. Each call owns an independent stack
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

The per-object cap is 65,536. Every selected owner has a body-only transaction;
invalid IR is fatal, and actual growth above its reservation restores the body.
No new global or callee escapes that transaction. New code/storage is tagged
bundle-owned so the later bundle, connected and legacy memory paths do not
count or re-encode it as new source work.

The native-v6 report adds `object_bundles` rows using `sre-object-bundle-v1`.
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
C/C++ coverage. `--shapes many-loads` additionally stresses deterministic
boundary emission beyond the inline pointer-set capacity; its redundant loads
are a stress control, not evidence of useful new protection.

`--ablation` adds matched feature-off and post-O2 feature-off artifacts. The tile
decompiler control requires these and exports five matched stripped arms, using
the trusted link map only to locate the root. This is informed-entry analysis,
not binary-only discovery. Full-output agreement, assembly hashes and decompiler
shape are diagnostics; none establishes resistance to recovery scripts, SMT,
storage forwarding, or agents. Extra decompiled lines are not a hardness score.

## Recorded evidence, 2026-09-18

Final plugin SHA-256:
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

## Remaining W3 work

Still deferred: immutable/global backing, aggregates and derived aliases,
proved lifetime handling, initialized-subobject and memory-intrinsic support,
ownership propagation through direct calls, multiple tiles/owners, object-phase
joins/rekeying and phase-dependent permutations, richer operation scheduling,
and informed index/storage-recovery baselines. Escaping/heap ownership remains
separate research. Generality and promotion gates remain unchanged; protected
holdouts must not be used to tune this prototype.
