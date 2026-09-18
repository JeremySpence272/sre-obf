# v04 implementation and candidate status — 2026-09-18

Compiler checkpoint `6ac30aa` has a runnable experimental crackme candidate.
It is not a claim that the complete research plan has met its acceptance targets.
Large-scale engineering is deferred by explicit user direction; see
[the unchanged deferred gate ledger](V04_DEFERRED_SCALE.md).

## Implemented bounded contracts

| Area | Contract and evidence |
|---|---|
| Joint pure computation, recurrence tuples and phases | [Native bundles](NATIVE_BUNDLE_V1.md) |
| Mutable/immutable joint backing and indexed updates | [Objects](NATIVE_OBJECT_BUNDLES_V1.md), [immutable data](NATIVE_IMMUTABLE_BUNDLES_V1.md) |
| Actual recurrence state in dispatch | [Bundle control](NATIVE_BUNDLE_CONTROL_V1.md) |
| Joint equality reductions | [Bundle predicates](NATIVE_BUNDLE_PREDICATES_V1.md) |
| Bounded larger objects | [Explicit eight-cell experiment](NATIVE_WIDE_TILES_V1.md) |
| Private bundle entry/exit continuity | [Inputs](NATIVE_BUNDLE_CALL_INPUTS_V1.md), [outputs](NATIVE_BUNDLE_CALL_OUTPUTS_V1.md) |
| Joint private integer arguments and direct recursion | [Joint arguments](NATIVE_JOINT_CALL_ARGUMENTS_V1.md), [self-recursion](NATIVE_SELF_RECURSION_V1.md) |
| Encoded objects shared with a proved private leaf | [Closed-object borrowing](NATIVE_OBJECT_CALLS_V1.md) |
| Budgeted useful-consumer priority | [Continuity policy](NATIVE_CONTINUITY_SELECTION_V1.md) |
| Cached compiler family selection from measured attacks | [Offline policy](NATIVE_BUNDLE_POLICY_V1.md) |

Each contract states supported shapes, exclusions, ablations, correctness,
rollback and normalization evidence. Known-descriptor proofs are positive
controls, not static-analysis resistance. The latest pinned unit/model run
passes 538 tests. Borrowed-object forced rollback restores both bodies and their
attributes exactly; this also fixed a shared snapshot bug leaking `dso_local`.

## Attack-guided selection result

The frozen eight-observation training matrix has fully recovered clean controls.
Two obfuscated arms are recovered; six remain inconclusive at their bounds.
Every arm exceeds the 2x small-training text cap. Therefore zero rules qualify
for the cached policy. Keep seeded selection; do not treat incomplete attacks
or extra generated code as wins. Cross-site summary-transfer/repair costs,
independent additional normalizers, phase/storage policy choices and held-out
improvement are not yet established. W6 has a usable bounded implementation,
but its empirical deliverable and M7 promotion remain unmet.

## Fixed crackme candidate

Cell: `crackmes/c-noopt-nosym-static-sre-obf-max-v04`.
Binary SHA-256:
`7ed3acc5d892db5f3fe1a803e54b87eaf4f1c110996013fe5377ee02f0270650`.
The unchanged C source and answer use O0 frontend/backend, static linking,
stripping, max IR profile, seed 1 and the original 250k module cap. Private
versioned provenance is under `obfuscation-harness/versions/v04/artifacts/`.

All 318 behavior checks per arm, exact grader positive/negative controls and
Revbench verification pass. A separate stock-O2 normalization passes the same
behavior checks. No fresh agent evaluation or combined decompiler/recovery-cost
result has occurred.

New coverage on this unchanged small program is principally joint immutable
storage: two objects, 264 bytes, one scalar-use edge removed out of 69.
Pure SSA bundles, persistent recurrence/control bundles, mutable tiles, joint
private interfaces and bundle predicates have zero retained sites here. Those
mechanisms are tested by designated fixtures, not by this crackme. Do not alter
the source to manufacture coverage or count generated decoder work as protected
source operations. This exposes the proxy's limited representativeness.

The candidate's LLVM application-object text total is 709,137 bytes versus
v03's 197,353 (3.593x), above the planned 2x practical target. Full binary size
is 1,427,432 bytes. This is a higher-cost research candidate, not a cost-matched
promotion. Additional run budgets, seed/corpus locks and scale targets have not
been raised. No large-program or protected-holdout runs were performed during
this continuation.

## Remaining work, without blocking the development loop

- Deferred scale correctness/coverage and growth engineering remain recorded.
- Broader ownership/loop/mixed-width shapes and fewer scalar boundaries need
  generic proofs and fixture coverage, not checker-specific exceptions.
- Establish recovery/repair/transfer improvements using multiple attack routes
  and fixed cost limits; a working cache alone is not such evidence.
- Run the frozen combined artifact and another held-out program with the planned
  matched agent protocol before deciding whether to promote the hypothesis.

MC and post-link work remains outside v04's IR-only implementation scope.
