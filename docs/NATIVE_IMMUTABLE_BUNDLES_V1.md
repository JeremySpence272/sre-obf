# Experimental immutable numeric continuity

`-native-immutable-bundles=1` requires native data, native bundles and the
connected planner. The common harness spelling is `--bundles --immutable-bundles`.
It is default-off and **not completion or promotion of v04**.

## Storage and transfer contract

The existing closed-use proof admits local, initialized, non-TLS constant
arrays of i8/i16/i32/i64. Address escape/identity, external initialization,
observable linkage/section storage, unknown uses, partial reads and volatile or
atomic reads are rejected. Every initializer must be a defined integer. No
program names, magic contents, answers or known algorithms influence selection.

Groups of four elements use triangular XOR or additive coordinates with a
seeded carrier law per tile. Constants are encoded at build time into the same
array. No plaintext shadow or constructor exists. The global becomes writable
in IR but is never written at runtime; pinning its reads has an explicit off
control and is not treated as a secret or hardness mechanism.

A source read remains at its original guarded location. Its index selects a
tile; four coordinate reads supply the needed encoded value and mask. For a
short final tile, unused candidate lanes duplicate the last legal coordinate.
Only originally defined source indices are required to preserve behavior, and
none can select a nonexistent tail element. All extra reads stay within fully
initialized immutable storage. New read alignment is proved from the global's
base alignment and element stride, not inherited from the selected element.

The scalar fallback is an explicitly tagged XOR/subtraction of the coordinates.
Pure bundles, local-tile arithmetic and connected regions can import those
coordinates directly, including family conversion, without reading the scalar
fallback or invoking a universal scalar accessor. Pure bundle entry carrier
generation also uses coordinates rather than first decoding its input.
Unsupported or unselected consumers retain the fallback. Zero surviving uses
allows its removal; metadata removal alone is not credited as absorption.

This does not eliminate unavoidable output/address boundaries, protect every
consumer, or make the storage descriptor secret. The supplied-descriptor inverse
is deliberately an easy positive attack control.

## Transaction and accounting

At most one twelfth of the remaining module IR allowance is available before
bundle/connected allocation. A whole immutable object reserves 192 instructions
per read site. Actual retained growth reduces that allowance; no cap is raised.
The emitter snapshots every affected reader, restores the initializer and
constantness along with reader bodies/attributes on growth rollback, and creates
no new global or helper. The existing 64 KiB module data limit remains in force.

`data` rows with `sre-immutable-tile-v1` describe extent, coordinates, tail law,
extra reads, pinning and estimated/attempted/retained growth. These descriptors
are private provenance, not binary-only attack inputs.

`immutable_continuity` captures scalar-use edges after pure/object bundles.
Contract 2 also requires `immutable_connected_continuity` after connected
regions, before the function driver. Both retain original read-site identity
and original use denominators; decreases and increases are separately counted.
Thus later region absorption cannot be misattributed to a persistent bundle.
Final source protection and decompiler survival remain unmeasured by these
stage-local counters. All source globals remain in the wider scale inventory.

## Conformance

`conformance.immutable_run` checks an independent source oracle, exact encoded
backing recovery, all four native outputs, post-O2 outputs, deterministic builds
and concurrent calls. `--partial` keeps an explicit scalar consumer;
`--connected-only` forces the pure bundle to miss its slot cap and tests the
connected importer separately. `--unaligned` checks extra-read alignment.
`--ablation` retains matched legacy-data builds and their normalized outputs.

```sh
python3 -m conformance.immutable_run --out out/NEW-immutable \
  --toolchain-image sre-obf-dev:llvm22 --widths 8 32 --cells 3 5 --seeds 1
python3 -m conformance.immutable_run --out out/NEW-immutable-partial \
  --toolchain-image sre-obf-dev:llvm22 --widths 32 64 --cells 5 \
  --seeds 4 --partial --unaligned --ablation
python3 -m conformance.immutable_controls --out out/NEW-immutable-negative \
  --toolchain-image sre-obf-dev:llvm22
```

The ten rejection controls are compile-only: exported/mutable/TLS/externally
initialized arrays, undefined initialization, volatile/atomic/partial reads,
pointer identity and escape. Some intentionally contain undefined data or
unresolved calls; they must never be executed as correctness samples.

Completed evidence, retaining earlier attempts:

- `out/immutable-tiles-first-20260918` exposed a harness parser limitation for
  LLVM's byte-string array spelling. It was not a compiler correctness failure.
- `out/immutable-tiles-tail-20260918`: 16 cases, i8/i32, N=3/5, seed 1; both
  consumer families and pin modes pass. Byte inputs are exhaustive.
- `out/immutable-tiles-partial-20260918`: 16 cases, i16/i64, N=1/7, seed 3;
  partial-consumer counts and matched legacy/off-O2 controls pass. Seeds 1 and
  3 exercise different backing families, independently of consumer family.
- Those two matrices used plugin
  `772123619e5c6a3b0a83c32214b3f0a7d16fda6e1b287b9b26cf58fc72461eb8`.
- `out/immutable-tiles-alignment-20260918`: eight i32/i64, N=5, seed 4 cases;
  under-aligned reads, partial consumers and matched controls pass on plugin
  `15b643dd74dab7c8233be3e0731743a4129a0366851d7bfab8e39912e0c7b45b`.
- `out/immutable-ownership-controls-20260918`: all ten expected rejections pass
  on that same plugin. No test program was executed.
- `out/immutable-connected-control-20260918`: eight i8/i32, N=5, seed 4 cases
  deliberately exclude pure bundles. The connected importer removes the four
  arithmetic scalar-use edges and preserves the remaining partial use;
  complete outputs, threads, post-O2 and matched legacy controls pass.
- `out/immutable-matched-decompile-20260918`: five stripped informed-entry
  Ghidra arms, each with 1,105 matching four-output vectors. Exported C sizes
  clean/native/post-O2/off/off-post-O2 are 505/24,688/13,571/17,956/10,041 bytes.
  This is decompiler shape evidence, **not semantic recovery or hardness**.
- Final integrated solver-enabled unit suite: 461 tests, no skips, PASS
  (86.198 seconds).
- `out/v04-immutable-connected-zlib-20260918` and
  `out/v04-immutable-connected-lua-20260918`: unchanged workloads, post-O2 and
  accounting pass at the primary 250k cap, with final IR 239,337/236,694.
  Seven/ten arrays (43/47 read sites) are encoded, but **zero scalar crossings
  are eliminated in either program at this selection policy**. No local joint
  tiles are retained either. Backing encoding is not consumer continuity.

The compile/selection gap is visible evidence for subsequent ownership/selection
work, not grounds for changing the cap or calling the preset complete. No paid
agent run, protected holdout evaluation or hardness promotion occurred here.

The later [bounded continuity-first selector](NATIVE_CONTINUITY_SELECTION_V1.md)
closes two/four of those scale crossings at the same cap. Those results are
separate artifact cells, not replacements for the zero-coverage baselines above.
