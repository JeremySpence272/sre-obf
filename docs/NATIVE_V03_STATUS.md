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

## Bounded shards for oversized connected components

Whole-component selection remains the default. `--connected-shards` /
`-native-connected-shards` is an independent defaults-off experiment: when one
connected component does not fit the existing per-function limit, the planner
partitions it into bounded shards **under that same limit** instead of skipping
it. No instruction or cost limit was raised.

The policy is named in every report as
`instruction-order-units-with-atomic-memory-objects`, because that is what it
is. A unit is a single node, except that every load of one encoded closed
object forms a single atomic unit: `prepareMemory()` redirects all of an
object's stores, so a load left in a different budget decision would read an
abandoned allocation. Units are consumed in stable instruction order. This is a
bounded instruction-order slice, **not** a graph partition, and it is not
claimed as one.

A shard boundary inside a component costs no scalar decode. `input()` already
consumes any selected node as a representation pair and converts families
directly, so cross-shard and cross-family edges stay encoded. Only units that
do not fit the remaining budget at all fall back to plaintext boundaries, and
their exact estimated cost is reported as loss.

Each shard's extent is drawn from a seeded stream within
`[limit/2, limit]`, keyed by the component's stable planning index, so two
seeded builds of one program cut the same component at different points. Total
selected cost is unchanged by that draw. Selection order, unit order and the
whole-component family stream are unchanged, so a build without shards is
byte-identical to the previous compiler.

Reports are now `sre-native-v3`. Per function the planner publishes eligible,
selected, skipped and shard-lost node counts and estimated costs, the component
and shard cost limits, the oversized/sharded component counts and the policy
name. The accounting is exact: eligible equals selected plus skipped plus shard
loss. Region rows carry the original component's planning index plus a shard
id. Older schemas report the new denominators as null, never zero; the memory
denominators stay known in v2 and v3. Estimated cost is the planner's own node
cost model, not measured instructions.

`connected_check.py` gains `--require-shards` and a planner self-consistency
check: a report whose cost accounting, shard counts, shard ids or selected-node
totals contradict its own region rows fails the gate as
`planning_violations`, rather than being read as coverage. `scale.py` gains
`--connected-shards` and `--require-shards` for large-program runs.

### Evidence

All runs use LLVM 22.1.8 in `sre-obf-dev:llvm22`, plugin
`5cd545b64ccb9f700ebc60cc70fe818091bb8c52852c9caa5d0d23b2b3c29d39`, 593 vectors
per arm, and clean/native/stock-post-O2 arms that must agree. Each directory
retains its own manifest with the exact command, seed and hashes.

- `out/v03-shard-final-o0-s3-control`: the previous O0 command with shards off,
  built with the new compiler. Its protected module is byte-identical to the
  sealed `out/v03-family-transfer-o0-s3` module
  (`0e378f373e7e506737e1d1372b9c39ef361e3c7d1a4d3039e5f3b61232fdd055`), from a
  different plugin hash, so the planner refactor is a no-op when the experiment
  is off.
- `out/v03-shard-extent-o2-s4`, `-s5`, `-s6`: **the optimized coverage gate now
  passes.** At frontend O2 `producer` is one 212-node component costing an
  estimated 36,256 against a 20,000 limit. Six shards select 124 nodes at an
  estimated 19,968, report 16,288 of exact cost loss, and produce 66 direct
  cross-family conversions with no plaintext multiplication bridge. Required
  predicate, family-conversion and shard gates pass at all three seeds, with
  different shard boundaries per seed and no planning violations.
- `out/v03-shard-extent-o0-s3-memory`: the same fixture at O0 with a 40-node
  cap, so an oversized component is sharded **while closed memory objects
  exist**. Six objects stay encoded across 40 memory edges, and the two objects
  whose loads were not selected are skipped whole as `component-budget`. The
  required memory, predicate, family-conversion and shard gates all pass.
- `out/v03-shard-final-o0-s8-budget`: shards under `--scale-budget`, where the
  fair per-function allocation shrinks the component limit to 5,191. Three
  shards select 39 nodes inside it, memory stays encoded across 40 edges, and
  the required memory, predicate and shard gates pass.
- `out/v03-shard-fixtures-r2`: the fixture differential suite with shards and a
  deliberately small eight-node cap, so the oversized path runs on ordinary
  fixtures. Ten cases at two seeds, all correct across control, native,
  stock-post-O2 and release arms.
- `out/v03-shard-fixtures-multi`: the same suite at a 48-node cap on the loop
  fixtures, so components split into **two** shards each with live PHI cycles
  crossing the boundary. `wide` and `widths` select 48 of 70 and 48 of 68 nodes
  with 33, 12 and 7 direct cross-family conversions; all eight case/seed
  combinations are correct.
- `out/v03-shard-rollback`: the computed-goto block-address rollback regression
  still passes; that path is untouched by this work.

Ghidra was not configured for the fixture runs, so their per-case status is
`partial`, never `pass`. Missing decompiler coverage is not evidence that
anything survived a decompiler.

### A pre-existing harness gap this work uncovered

`conformance/run.py --case values` cannot pass under `--region-plan connected`,
at any node cap, with or without shards. Its gate reads
`native_report["values"]`, which only the legacy planner writes; the connected
planner replaces that pass, so the required 8/16/32/64 width set is always
empty. The check dates from `7718e7e`, long before shards, and reproduces on a
build with the experiment off (`out/v03-shard-values-cap128-noshards` fails,
`out/v03-shard-values-legacy` passes). It is recorded here rather than worked
around: the fix is to give the connected report a real per-function encoded
width set and gate on that, which is its own milestone. Do not weaken the
existing width requirement to make the case green.

The O2 transfer fixture has **zero** eligible closed-memory objects, because
frontend O2 promotes its local arrays to SSA. Its gate therefore cannot and
does not require memory coverage; the O0 run above is the memory evidence. Do
not read an O2 pass as memory coverage.

Known remaining limits are unchanged by this work: boundary decodes at region
exits, the narrow closed-object eligibility of `findObjects()`, the absent
encoded call ABI, and software-invertible dispatch. Coverage is not hardness.

## Bounded genuine joint outputs

`--joint-outputs` / `-native-joint-outputs` is an independent defaults-off
ablation, the P4 remainder. It couples two selected nodes so that the lanes
crossing a pinned slot carry joint quantities instead of either value:

    U = X + Y        V = X + 2Y        X = 2U - V        Y = V - U

The coupling matrix has determinant one, so the inverse is exact at every
supported width, width 1 included, with no division and no wrap correction.
Every step is pair arithmetic on encoded lanes. The additive family is linear
coordinate-wise; the XOR family reuses the already verified carry network.
Neither path ever forms `E xor R` or `E - R`, so no decoded scalar X or Y
exists as an SSA value at any point. Doubling is emitted as a pair addition,
never `shl 1`, because a one-bit shift by one bit is poison at width 1 — the
same hazard `convertFamily` documents.

Both members must be genuinely distinct. The named test, reported per function
as `joint_dependency_test`, is
`distinct-normalized-root-dependencies-both-ways-plus-no-dataflow-dependence`:

- neither node may appear in the other's bounded transitive dependency
  closure, in either direction, so a value is never coupled with something it
  already feeds or is fed by;
- each node must depend on at least one normalized root the other does not.
  Roots are normalized through loads to their underlying object and through
  casts to their source, so two reloads of one alloca, or a cast of one value,
  cannot present themselves as two live dependencies;
- both nodes must be genuinely used, and the first must have at least one use
  the unmix dominates, so no group mixes and unmixes something nothing reads.

PHI nodes are never members: their lane pairs are pre-created and filled after
emission, and rewriting them would break that fill. Members must share a
representation family and an integer type, and the first must strictly dominate
the second. Pairing is first fit over selected nodes in stable instruction
order; it consumes no random stream, and the joint pins draw after every other
site, so an existing site's stream is unchanged. Groups are capped at four per
function with a bounded pair-test budget.

The coupling is applied after every other lane use exists. A use is redirected
to the recovered lanes only if the unmix dominates it; any other use keeps the
original lanes and is reported as ungoverned rather than counted. Reports carry
`joint_output_groups`, `joint_output_candidates`, the measured
`joint_lane_uses_rewritten`, the policy name `pairwise-unimodular-u-v-v1` and
two fixed skip vocabularies: `joint_node_skips` over examined nodes
(`phi-representation`, `unused-value`, `dependency-walk-bound`,
`no-live-dependency`, `group-budget`, `pair-test-budget`,
`no-compatible-partner`) and `joint_pair_skips` over examined pairs
(`width-mismatch`, `family-mismatch`, `no-dominance`, `shared-dependency`,
`identical-dependencies`, `no-dominated-use`, `already-grouped`). A rolled-back
function reports its attempted groups as attempted, never as coverage.

`connected_check.py` gains `--require-joint-outputs` plus joint self-consistency
checks: groups may not exceed half the candidates, may not appear under the
disabled policy, and must govern at least one lane use per member. A report
written by a compiler that predates the experiment carries no joint fields at
all; that is read as unknown, never as zero, and it cannot satisfy the gate.
`connected_model.py` holds the reference laws (`pair_add`, `pair_sub`,
`pair_double`, `joint_mix`, `joint_unmix`, `decode`) and `connected_proof.py`
checks them bounded in both families at every width.

The schema string is deliberately unchanged at `sre-native-v3`; a bump to v4 is
owed once the parallel v03 field additions are integrated.

### Evidence

Not yet recorded. The gates for this section have not been run in this
checkout, so nothing here may be cited as measured. Required before this
section can claim anything: the fixture differential at O0 and O2 at two seeds
with `--post-o2-attack`, the flag-off control proving the protected IR hash is
unchanged, the Python suite, the bounded reference proofs, and the honest
stock-O2 survival comparison the handoff asks for — the pinned slots are a
compiler barrier, not a semantic one, so a measurement showing the coupling
survives `opt -passes=default<O2>` says only that, and an attacker who models a
volatile slot as a plain store-to-load recovers X and Y immediately. Density is
not hardness and this ablation is not a hardness claim.

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
   failure when a requested gate has no surviving transformation. Bounded
   shards are implemented as described above; the remaining scale question is
   whether they hold on unchanged large applications, which has not been run.
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
