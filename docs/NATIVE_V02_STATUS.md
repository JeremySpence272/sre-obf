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
