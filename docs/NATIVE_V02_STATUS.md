# v02 implementation ledger

Work in progress against [the v02 plan](NATIVE_V02_PLAN.md). No v02 preset has
been promoted and no paid v02 agent run has been launched. Large-program gates
remain required; the crackme alone cannot satisfy them.

## P0 foundation

- Added input-before-fusion and final whole-module inventories, including every
  defined function, instruction-weighted selection, helpers, memory operations,
  predicates and indirect calls. Selection attributes and surviving boundary
  names/tags are explicitly diagnostics, not proofs of surviving protection.
- Added `conformance/recovery_reach.py`: bounded AMD64 symbolic reachability for
  main/argv and buffer/length ABIs, private initialized-state specifications,
  restricted scalar summaries and byte-guarded equality-select splitting.
  No Unicorn/native execution, pickle loading or arbitrary expression evaluation.
- Models require exact binary hashes. Oracle addresses and supplied summaries
  are explicit assumptions; model candidates need independent grading. Errors,
  unknown state and budget exhaustion cannot be counted as protection.
- v01 replay addresses/formulas remain private in the local v02 artifact folder,
  not in the compiler or public fixtures. The first 180-second replay hit its cap.
  The confirmation replay recovered the exact answer in 186.3 seconds / 5,475
  steps, with summaries and constrained select splitting. A separate private
  exact-match check passed without native execution. This is informed replay,
  not fresh agent discovery or a v02 hardness result.
- 24 unit tests pass; the plugin builds. `out/v02-p0-compat` reproduces both
  exact v01 binary hashes: P0 reporting does not change code generation.

Remaining P0 work includes additional recovery arms, summary-equivalence checks
and generalized discovery/repair measurements.

## Connected-region core (P1–P5 bounded subset)

New options are defaults-off, and the legacy value/memory implementations remain
available. Use `--values --values-wide --region-plan connected` in `whole.py` or
`run.py`; add `--memory --memory-ssa --predicate-regions --regional-families
--support-regions` independently. `--connected-nodes` is a separate 2..512 cap,
default 128; it does not reinterpret legacy `--value-nodes`. The per-TU wrapper
exposes corresponding `SRE_OBF_*` variables, including `SRE_OBF_REGION_PLAN`.

- A bounded connected-component planner joins supported SSA through closed
  local memory, ranks connectivity/useful consumers, and selects whole components.
  Input/eligible/selected coverage and skipped components are reported. This is
  not general whole-program points-to analysis or universal region coverage.
- Scalar/fixed-array lanes pass directly through stores and loads into supported
  SSA. Bounded byte copies are normalized before planning. Pointer/index uses,
  escaped objects and unsupported operations remain explicit boundaries.
- Equality and signed/unsigned ordered comparisons, Boolean operations, selects
  and PHIs use XOR-coordinate transfers. Tagged Boolean lanes can feed native
  successor construction directly without recreating the decoded condition.
  An eventual observable choice and path-splitting attacks remain possible.
- Eligible arithmetic-only components can select additive representations;
  mixed bitwise/comparison components currently use XOR shares. Selection is
  reported, not assumed to imply effective post-normalization diversity. There
  are no general cross-family conversion circuits yet.
- Small generated data decoders can be absorbed before region selection. This
  is bounded helper absorption, not complete encoded-call ABI coverage. Late
  call-table helpers still expose statically recoverable initialization clues.
- The v01 XOR-wide context update reconstructed a plaintext value as E xor R.
  Connected regions instead update context from the old context and separately
  mixed lanes. The existing witness remains transparent software redundancy;
  no new invariant family or cryptographic claim is introduced.
- Pre-driver/post-driver IR snapshots are retained by the whole-IR driver.
  Final handoff/boundary inventories remain diagnostics when later rewrites
  discard tags. Branch/ABI exits and multiplication bridges are still counted.

### Initial evidence (not candidate promotion)

- 26 unit tests pass, including predicate reference edge/random models for
  widths 1/4/8/16/32/64. These are not proofs of the complete LLVM pass.
- `v02-connected-o0-s1`: 593 full-output vectors agree across clean/native/
  post-O2. Three eight-element i8/i32 arrays and seven predicates are covered;
  native multi-state flattening survives.
- `v02-handoff-o0-s3`: the same full-output differential and required memory/
  predicate gates pass after direct successor handoff integration.
- `v02-whole-o2-s2`: correctness passes, but required memory and predicate
  coverage fails. Keep this failure visible; successful compilation alone is
  not sufficient coverage. Optimized input requires independent inventories.
- `v02-ghidra`: generic wide fixture passes its configured Ghidra differential,
  including the stock-O2 attack arm. This establishes survival, not resistance.
- `out/v02-crackme-candidate`: unchanged source, both static stripped O0 arms
  pass 318 checks each. Main has 52 selected nodes, 47 persistent SSA edges,
  17 memory edges, eight predicates/handoffs and four reported multiply bridges.
  Its expected-table decoder is absorbed; subkey/intermediate arrays have direct
  lane transfers. This remains an unpromoted candidate with no agent benchmark.

P4 joint outputs, P5 private encoded-call interfaces, P6 alternative activation
relations, comprehensive summary proof/repair ablations and large-program
promotion gates are still outstanding. Do not call the full plan completed.

## Scale/conformance expansion (still unpromoted)

- Added pinned official SQLite 3.49.2, Lua 5.4.8 and zlib 1.3.1 source acquisition
  and unchanged-source whole-application workload manifests. The runner verifies
  source hashes and independently expected output, not merely two-build agreement.
  Lua is a test application, not an obfuscation VM. No target sources are patched.
- Clean full-program workload controls pass on all three. Initial protected Lua
  and zlib builds exceeded the old 250,000-instruction module cap. Explicit
  1.5-million calibration also failed: SQLite reached 4,201,450 instructions
  before function passes; zlib reached 2,365,335 after them; Lua timed out at
  600 seconds. These are compiler failures, never resistance evidence.
- Module caps and compiler timeouts are now explicit and logged; defaults stay
  unchanged. Failure reports retain stage and whole-module inventories. The
  `--scale-budget` / `native-scale-budget` experiment allocates remaining growth
  headroom across functions up front, with bounded source-size weights. Connected
  body-only changes have exact transactional ceilings; unused shares are not
  consumed in module order. Applications/support/late stages get separate shares.
  The generated-helper cap is explicitly 4096 in this mode versus legacy 256.
  This policy can sacrifice coverage; successful compilation is not promotion.
- Removed a transient plaintext intermediate from XOR-pair AND and redundant
  prefix work. Subtraction now uses one carry-in network. These are software
  coordinates, not cryptographic secrecy. Generic predicates/PHIs and three
  closed objects retain full-output correctness, including stock-O2 normalization.
- `v02-affine-s1` actually selects the additive family and passes 593 outputs
  per arm. `v02-compact-s4` passes memory/predicate requirements and 593 outputs.
  `v02-compact-ghidra` passes its configured decompiler differential, including
  the stock-O2 arm. None of these results measure recovery hardness.
- Bounded reference-model SMT checks: 33 of 40 laws proved; seven timed out
  with a three-second per-law cap; no counterexamples. The seven remain
  inconclusive. These are not proofs of the complete LLVM implementation.
- Whole-IR builds now archive the exact plugin before compiling and record
  driver/source hashes at entry. Earlier unsealed candidates must be rebuilt
  before treating them as frozen v02 artifacts.
- Fair-budget zlib exposed a previously masked CFF bug: the shared CFG demoter
  excluded every alloca, including non-entry allocation pointers whose uses
  lose dominance after router edges are added. A minimal variable-array fixture
  reproduces the old failure. The fix demotes cross-block pointer uses without
  hoisting the allocation or changing how often it executes. LLVM lifetime
  markers on those objects must be dropped before spilling addresses: reloads
  are not legal lifetime operands. The extended regression passes all three
  configurations (593 vectors each). The unit suite now has 29 passing tests.
- Large gates still fail. The fair Lua build completes at 1,371,895 final IR
  instructions, 190 selected connected functions and 2,728 generated helpers,
  but its protected workload crashes (exit 139). Fair SQLite still reaches the
  600-second compile cap. Preserve these failures; no hardness claim follows.
- `scale-v02-zlib-lifetime-fixed` passes the unchanged full-byte-domain gzip
  workload and independent expected-output check. It selects 1,912 of 7,943
  eligible nodes in 77 functions, with 446 predicates and 46 surviving flattened
  functions, but **zero connected memory edges**. Final IR is 1,266,392
  instructions versus 18,290 input instructions. This passes one correctness
  workload, not broad-coverage or overhead promotion.
- `out/v02-core-sealed` passes 318 checks per crackme arm and retains its exact
  plugin. The clean hash still matches v01. `v02-legacy-compat-final` is a
  correctness/compatibility check, not an exact protected-binary reproduction:
  the protected hash differs after intervening compiler changes. Only the
  earlier report-only P0 build is claimed to reproduce the historical hashes.

Scale coverage remains conservative and incomplete: reports include every input
definition and instruction, skips by reason, region nodes and matched-origin
body weights. A body containing a selected region is **not** fully protected.
Merged/unmatched origins receive no invented coverage credit. Comparable
in-process timing, peak memory, full-size useful-path coverage, independent
held-out recovery and any default promotion remain outstanding.
