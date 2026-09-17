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
  not in the compiler or public fixtures. The first 180-second replay reached
  5,395 steps and hit its cap; this is not a reproduced success or a v02 result.
- 24 unit tests pass; the plugin builds. `out/v02-p0-compat` reproduces both
  exact v01 binary hashes: P0 reporting does not change code generation.

Remaining P0 work includes additional recovery arms, complete positive controls,
summary-equivalence checks and generalized discovery/repair measurements. P1–P6
are not implemented by this foundation commit. See subsequent entries for deltas.
