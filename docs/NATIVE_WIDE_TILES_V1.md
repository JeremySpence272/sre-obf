# Opt-in larger local tiles

This is the bounded larger-tile experiment requested by W3, not a general
object-layout or interprocedural ownership solution. It does not finish v04.

`-native-object-max-cells=8` (shared CLI `--object-max-cells 8`) permits closed
local integer arrays of five through eight cells. It requires object bundles.
The default remains four; register bundles, immutable tables, memory-access
limits, the 65,536-instruction function allowance and shared module budgets are
unchanged. No additional source-specific rules or runtime environment checks
are introduced. The existing lifetime, initialization, complete-use ownership,
index-range, alignment and scalar-boundary contracts remain mandatory.

The existing triangular lowering is parameterized by the actual object size.
Its descriptor and every update include all admitted cells, the carrier and,
when selected, phase. This is not a new algebraic family or a secrecy claim.
The independent specification requires explicit `max_lanes=8`; callers outside
this experiment still reject more than four lanes.

Object report contract 4 records the selected ceiling both in the feature policy
and every inspected-object row, including skips. Older report contracts retain
the four-cell meaning. The report gate rejects inconsistent ceilings and costs;
an over-budget candidate is skipped, never credited as encoded coverage.

## Focused validation

`tile_run` now returns and compares every cell of wider fixtures. The C driver
uses a checked output-size definition for stdout, reentry and thread buffers.
The case sidecar records that interface; `bundle_decompile --tile` reads it and
records the observed width. Old four-output cases remain compatible.

The eight-cell source fixture exercises every possible dynamic index using a
proved `index & 7`. Non-power-of-two shapes use a bounded power-of-two prefix;
their tails are still read and included in the full output, but are not claimed
as dynamic-write coverage. Phase-join fixtures include zero-trip and conditional
update paths. `--ablation` for wider shapes additionally compiles the identical
source under the default four-cell policy, requires the explicit size rejection,
and compares its complete output. This is distinct from turning object bundles
off entirely.

Commands use `--toolchain-image sre-obf-dev:llvm22` and private ignored `out/`:

```sh
python3 -m conformance.tile_run --out out/wide-static \
  --toolchain-image sre-obf-dev:llvm22 --widths 8 32 64 --cells 8 \
  --object-max-cells 8 --shapes supported --families xor --seeds 1 --ablation
python3 -m conformance.tile_run --out out/wide-phases \
  --toolchain-image sre-obf-dev:llvm22 --widths 16 64 --cells 6 \
  --object-max-cells 8 --shapes supported phase-joins --families additive \
  --seeds 3 --object-phases --ablation
```

2026-09-18 evidence:

- `native-wide-tiles-static-20260918`: all six static eight-cell cases pass,
  including exhaustive byte input pairs, wider boundary/random vectors, both
  pin modes, stage/final/O2 output comparisons and matched off arms.
- `native-wide-tiles-phased-20260918`: all eight six-cell cases pass, including
  phase joins, both pin modes and matched off/O2 arms.
- `native-wide-tiles-cap-control-20260918`: two additional eight-cell additive
  cases pass with the newly added default-four-cell rejection/output control.
- Pinned unit/model suite: 515 tests pass; additional model checks cover all
  five-to-eight-cell sizes, word widths and families, full-state preservation,
  changing phases, supplied-descriptor inversion and stale-carrier failures.
- `native-wide-tiles-first-20260918` is retained as an expected engineering
  limit: the eight-cell phased fixture requests more than its 41,653 shared
  allocation. It is skipped as `module-unit-budget`. Neither the cap nor the
  fixture was padded to make that result pass.

- `native-wide-tiles-default-compat-fixed-20260918`: default four-cell phased
  IR is byte-identical to the preceding predicate compiler. The first command
  used two invalid CLI spellings; its failed logs are retained separately.
- `native-wide-tiles-decompile-20260918`: all five stripped informed-entry arms
  pass the eight-output workload and Ghidra export. Semantic recovery is
  explicitly `not_measured`.

Retained plugin SHA-256:
`b73b12e122c7a54e324e8ffd6114cc9a285f439c533da8b0fb858a8a9dafbd05`.
Decompiler output size and successful decompilation are diagnostics,
not measured recovery resistance. No large-program or protected-holdout gate,
fresh-agent run, or promotion is implied by these focused checks.
