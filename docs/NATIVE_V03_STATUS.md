# v03 implementation and evidence ledger

Continuation of [v02](NATIVE_V02_PLAN.md), starting at `6d213a4`.
IR only; unchanged application sources; no VM, MC, post-link, environment,
anti-debugging, prompt or tokenizer work. This is an implementation ledger,
not a declaration of agent resistance or preset promotion.

## Scale correctness and compiler cost

The unchanged Lua failure was a compiler bug, not a hard analysis problem.
`luaV_execute` uses a global array of 83 block addresses. Transactional budget
rollback called `Function::deleteBody()` before rescuing those references;
LLVM replaced every table entry with `inttoptr(1)`. Cloning instructions back
did not restore the module-level table. The shared body transaction now moves
surviving block-address uses to its saved body, restores the function, and maps
those references back before destroying the snapshot. Both the ordinary driver
and connected-region budget enforcement use it. Newly generated module objects
still require separate ownership; this is not a general module transaction.

Compiler cost fixes avoid predecessor searches in functions without an EH
personality and replace repeated whole-module helper accounting with local
deltas plus a full stage-boundary recount. The helper profile cannot create
additional function bodies. Source-weight report iteration now follows module
order, not pointer-hash order. Limits were not increased.

Evidence, LLVM 22.1.8, seed 1, existing fair-budget v02 settings and 1,500,000 IR
instruction / 600-second per-command caps:

- `out/v03-rollback-r3`: repeated rollback, global jump table and recursion;
  three seeds, 593 complete outputs per native/post-O2 arm, all pass.
- `out/v03-rollback-old-control`: the retained failing Lua compiler triggers
  the regression's block-address corruption check, as expected.
- `out/scale-v03-lua-rollback`: unchanged workload and independent expected
  output pass. Obfuscation takes 126.99 seconds versus the prior 519.7 seconds;
  1,371,895 final instructions, 1,829 selected nodes, 492 predicates, 71
  flattened functions, **zero connected-memory edges**.
- `out/scale-v03-sqlite-helper-linear`: unchanged workload and independent
  expected output pass. Obfuscation takes 160.03 seconds versus the prior
  600-second timeout; 1,425,954 final instructions, 1,645 selected nodes,
  479 predicates, six memory edges, **zero surviving flattened functions**.
- `out/v03-stage-lua-control`: retained pre-application IR passes its workload
  through the diagnostic stage replayer. It is a dynamic-link diagnostic,
  separate from the static production lane, and is not sanitizer coverage.
- Existing Python unit suite: 29 tests pass.

These measurements close the two known build/correctness failures, not the
large-program coverage or overhead gates. All 513 SQLite flattening attempts
rolled back: proportional growth shares are too small to buy the transformation.
The next scale milestone must allocate usable structural budgets and report
actual coverage, rather than declaring the zero-coverage build protected.

## Usable structural budgets and coverage gates

`--scale-structure` / `-native-scale-structure` is an independent defaults-off
experiment requiring fair scale budgets. It reserves 60% of remaining module
headroom for actual CFF transactions before ordinary expression allocation.
Candidates rank by bounded source weight per current control block, with a
stable symbol-order tie break. A function receives at most one eighth of the
pool (with a 2,048-instruction minimum grant ceiling); its exact emitted growth
is charged. Unspent space returns to the ordinary allocator. Failed attempts
remain recorded and are not retried in the application stage. No instruction
limit is increased, and uniform allocation remains an ablation.

The native report is now `sre-native-v2`, including structural allocations and
eligible closed-memory counts. Scale result v2 records required coverage and
supports `--require-flattening`, `--require-memory` and `--post-o2-attack`.
Missing old-schema denominators are unknown, not zero. Eligibility refers only
to supported closed entry allocations in analyzed functions, not arbitrary heap,
escaped, aggregate or aliased memory. Coverage failure is separate from a
correctness failure and does not erase successful workload evidence.

- `out/scale-v03-sqlite-structural`: 156.42-second obfuscation; unchanged
  workload plus both required coverage checks pass under the same caps.
  117 functions retain CFF (100 matched original definitions containing 5,712
  original instructions; merged/unmatched origins are not credited). Final IR
  is 1,435,019 instructions. Six of 54 eligible closed-memory edges survive;
  input has 69,036 memory operations. **This is narrow coverage, not promotion.**
- `out/v03-structure-small-r2`: cross-TU O0 fixture, clean/native/post-O2
  outputs agree on 593 vectors; required memory and predicate coverage pass.
- `out/scale-v03-zlib-rollback`: unchanged gzip workload still passes after
  the compiler repairs; existing coverage/growth limitations remain.
- 32 Python unit tests pass. Additional seed/post-O2 large runs are pending.

Seed 2 SQLite and zlib runs with the structural allocator and a stock post-O2
attack also preserve their unchanged workloads. SQLite retains 109 flattened
functions and six memory edges. Zlib retains 81 flattened functions, but none
of its six eligible closed-memory edges; that requested memory gate therefore
fails honestly. These results do not broaden the supported memory denominator.

## Cross-family connected regions

Operation-compatible nodes within one selected component now use distinct
additive and XOR-pair subregions. Edges crossing the representation boundary
are converted directly: the lowering never materializes the decoded scalar as
an SSA value. Mixed arithmetic/Boolean components use both families, and a
component containing multiplication selects the additive path, removing the
old plaintext XOR multiplication bridge. Pure arithmetic components retain
seeded family selection. Reports expose components, mixed-family counts and
conversion counts; scale reports aggregate both counters.

`out/v03-family-transfer-o0-s3` seals the exact tested plugin. Across 593
vectors, clean, native and stock-post-O2 outputs agree; required memory,
predicate and cross-family gates pass. It contains 30 direct conversions in
two mixed components and zero plaintext multiplication bridges. The 33-test
Python suite includes 3,000 randomized round trips at each of six widths.
Bounded SMT reference checks prove 38 laws and report 12 timeouts as
inconclusive, with no counterexample. XOR-to-additive proves at all widths;
additive-to-XOR proves at 1/8 bits and times out at wider widths under the
three-second per-law cap. This is correctness evidence, not hardness evidence.

The O2 transfer fixture in `out/v03-family-transfer-o2-s4` is correct in all
three arms but fails coverage: frontend optimization produces one 212-node
component whose estimated cost exceeds the fixed 20,000 connected-region
limit, so no component is selected. Do not count it as a feature pass. Bounded
partitioning of oversized components is required before using this fixture as
an optimized coverage gate.

## Next implementation batch

The private Sol control now reproduces exact recovery in 79.511 seconds with
angr 10 on the retained compatible image. Solver and binary hashes are checked;
only those two files enter its read-only container. The answer comes from the
independently graded historical submission outside that container. An earlier
API-mismatched image failed and remains recorded as inconclusive. This is an
informed positive control, not new-version discovery or original-run compliance.

1. Scale policy: preserve measured structural work within the existing module
   cap; retain uniform allocation as an ablation. Add eligible/selected memory
   and structural denominators, cost and source-weighted coverage, with explicit
   failure when a requested gate has no surviving transformation.
2. Sol recovery regressions: freeze the successful v02 scripts privately;
   separate informed entry/state assumptions from binary-only discovery. Test
   dispatcher inversion, canonical-state rebasing and XOR/additive projection;
   distinguish unchanged transfer, repair, and unsupported/inconclusive tools.
3. P4 direct cross-family transfer is implemented as described above. Bounded
   genuine joint-output coupling remains a separate ablation with an inverse
   control, not an assumed hardness benefit.
4. P5: bounded private encoded-call interfaces integrated with representations;
   preserve exported ABI, recursion/reentry, threads, and effect exclusions.
   Ordinary scalar helper wrappers are not encoded-ABI coverage.
5. Dispatch/activation experiments: regional dispatch relations and useful
   data/control representation dependencies. Canonical control resets must be
   tested with real live lanes, not only a known-zero witness. Keep inference
   and supplied-relation recovery arms.
6. Re-run full-output O0/O2 and post-O2 differentials, bounded reference proofs,
   compiler/decompiler normalization, seeds and unchanged large applications.
   Counterexamples fail; SMT unknown and decompiler errors are inconclusive.

No challenge name, address, flag, expected table, password length or diagnostic
string belongs in the production transformations. Algebraic recovery remains
possible; the target metric is reusable recovery cost, not binary size.
