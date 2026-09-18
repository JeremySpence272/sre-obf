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

## Closed aggregate memory objects

The narrow rule remains the default. `--connected-aggregates` /
`-native-connected-aggregates` is an independent defaults-off experiment that
admits one further object shape: a closed entry allocation whose type is
nothing but bounded integer leaves at constant offsets, so a struct of integer
fields, a nested fixed array and a struct containing an array become eligible
alongside the scalar and flat array that already were. No limit is raised: the
64-slot leaf ceiling is the old 64-element ceiling, the eight-object budget is
unchanged, and nesting is bounded at eight.

Admission is a proof, not a pattern match. `enumerateLeaves()` must account for
the whole type as supported integer leaves — any float, pointer, vector, `i1`,
odd-width integer, opaque or scalable part rejects the object — and their byte
ranges are then checked to be disjoint rather than assumed from the type.
`admitLeafObject()` walks every pointer derived from the allocation, resolves
each to a constant byte offset, and requires every load and store to cover one
leaf exactly at that leaf's own type. A runtime index, a partial or punned
access, a volatile or atomic access, a pointer comparison, a memory intrinsic,
a stored or called address, or any user the walk does not model rejects the
whole object with its own reason. Proving no derived pointer escapes is also
what proves nothing else in the function aliases the object.

The reason vocabulary is `leaf-layout-unsupported`, `overlapping-leaf`,
`dynamic-index`, `partial-leaf-access`, `unsupported-access`,
`memory-intrinsic`, `pointer-compare`, `address-escape-store`,
`address-escape-call`, `address-escape-other`, `offset-out-of-range`,
`uncovered-leaf` and `no-load-or-store`, beside the existing
`unsupported-layout`, `object-budget`, `escape-or-unsupported-access` and
`component-budget`. With the experiment off only the existing coarse reasons
appear. The walk is a retry, never a replacement: a scalar or flat array that
the narrow rule admits, including with a runtime index, is still admitted by
the narrow rule and encoded exactly as before.

The bounded byte-copy normalization in `findObjects()` is deliberately **not**
extended. Its trigger still matches only an `i8` allocation or a flat `i8`
array, so a `memcpy` touching a struct or nested array rejects that object as
`memory-intrinsic` instead of being rewritten. A copy that one of its `i8` ends
does get normalized may land on an aggregate; the leaf walk then admits it only
if every resulting byte access covers an `i8` leaf exactly.

The shard invariant is preserved rather than assumed. An aggregate is one
object, so `MemoryLoads` registers all of its leaf loads and the planner's
atomic unit grows to hold them; a unit that cannot fit the remaining budget is
dropped whole and `prepareMemory()` then redirects none of that object's
stores. The eligible denominators only grow: `eligible_memory_objects` and
`eligible_memory_edges` count every admitted object, and the report adds
`eligible_aggregate_memory_objects`, `eligible_memory_leaves`,
`memory_layout_policy`, per-object `layout` and `leaves`, and the encoded
`aggregate_memory_objects` / `aggregate_memory_edges`. `connected_check.py`
gains `--require-aggregates` and fails a report whose encoded objects, memory
edges or aggregate counts exceed or contradict its own eligible denominators.
`scale.py` gains `--connected-aggregates` and `--require-aggregate-memory`.
The schema string is untouched, so the new denominators are read as unknown —
never zero — when a report does not carry them in every planned row.
## Lane-keyed dispatcher transitions (P6 relation experiment)

`--lane-transitions` / `-native-lane-transitions` is an independent defaults-off
experiment with three values: `off` (0), `on` (1) and `stale-relation` (2).
Mode 2 is an **attack replay**, not a protection mode; it is described with the
arms below. The experiment requires `--coupled-state`, because the word it uses
is the value pass's per-activation context.

### What changed

Before this work the flattening transition folded the encoded-data word into
`fla.multi.key` and `fla.multi.salt` and then stored those words. The dispatcher
loaded them back and re-encoded each candidate label, so the emitted token was a
function of the three flattening words alone. The only other coupling was
`nativeResidual()`, whose value is zero at every reachable program point by
construction; resetting the witness together with the context changes nothing
observable, which is why it never forced an analyst to recover live data.

With the experiment on, `storeState()` fixes the next context word **before**
encoding, keeps it out of the stored key and salt, and keys the token with it;
`buildMultiStateDispatch()` re-reads that word (`fla.multi.lane.load`, volatile)
and applies the same relation to the candidates. Both ends call one definition,
`obf::nativeLaneKeys()` in `NativeInvariant.h`, so they cannot drift apart. The
word itself is written only by `pin()`, from the pinned coordinates of live
connected-region values through volatile slots, and by the transition. Under the
flag its entry seed is additionally mixed with a frozen integer argument, so the
first transition of an activation is not keyed on a build constant. The
known-zero residual term is left exactly as it was and is superseded, not
removed.

**All four words are ordinary software state that is present in the binary.**
An analyst who reads the fourth word can still rebase the control state. This is
not secrecy, it does not defeat canonical repair, and it is not a hardness
claim. The only thing it can do is raise the joint cost of following control and
recovering data at the same time, which is what the arms below measure.

### Arms

`conformance/relation_recovery.py` (schema `sre-relation-recovery-v1`) runs
three arms over one protected module. It reads value names, which a stripped
binary does not carry, so it is deliberately generous to the analyst.

- **supplied-relation.** The family and the participating words are handed over.
  Inversion stays closed-form in `conformance/state_model.py`; no search is
  required. The residual cost is exactly that one further per-activation word
  must be read at runtime. Word count goes from two to three.
- **inferred-relation.** Nothing is handed over; the word set is recovered by a
  backward slice from each dispatcher comparison. It succeeds in every module
  tested, in 0.08 to 0.20 seconds. The slice per comparison grows from 33 to 39
  instructions on the whole-program fixture and from 780 to 923 on `obf_target`,
  about 18 percent. **Inference cost barely moves.**
- **canonical-repair.** The previous relation — token as a function of
  state/key/salt only — is replayed unchanged. With the experiment off it
  describes 2 of 2 and 2 of 2 dispatcher-bearing functions. With it on it
  describes 1 of 2 and 0 of 2: it fails in exactly the functions that carry
  encoded data. Mode 2 emits that stale relation into a real build, and the
  protected binary then does not terminate: the dispatcher matches no case and
  cycles through its miss chain. The repair is nevertheless available, and the
  report says so: read one more word.

### Evidence

LLVM 22.1.8 in `sre-obf-dev:llvm22`, plugin
`4ff8d68dd25a30117bee1a661f31d5cb2fc268d73de146570f092b226f198158`, the new
`conformance/fixtures/connected_aggregate.c` plus its second translation unit,
and 593 vectors through clean, native and stock-post-O2 arms.

- `out/E-final-agg-o0-s3` and `out/E-final-agg-o0-s7`: O0 at two seeds, all
  three arms agree on 593 vectors, and the required memory, predicate and
  aggregate gates pass with no planning violations. Eligible closed objects
  grow from 17 to 20 and eligible closed edges from 112 to 142 against the
  same fixture; all 142 are encoded, 30 of them across three aggregates — a
  four-leaf struct, an eight-leaf nested array and a five-leaf struct holding
  an array.
- `out/E-final-flagoff-o0-s3` versus `out/E-baseline2-o0-s3`: with the
  experiment off the new compiler reproduces the previous compiler's protected
  IR exactly, `3db23a68a918441633bbf394f81a0822dc9819f60665438a2bddf91e3864c856`,
  and every arm's binary hash. The post-O2 `.ll` text differs only in the
  input path `opt` records as its module id; its binary is identical.
- The three negative cases are reported, not encoded: the escaping local as
  `address-escape-store`, the runtime-indexed array of structs as
  `dynamic-index`, and the aggregate handed to the other translation unit as
  `address-escape-call`.
- `out/E-final-shards64-o0-s3`: `--connected-shards` at a 64-node cap, so the
  84-node component is oversized while the new objects exist. Four shards
  select 163 of 184 nodes; one aggregate stays whole inside a single shard and
  is encoded, and the two that do not fit are dropped whole and reported as
  `component-budget` with no store redirected. All three arms still agree. At
  a 40-node cap the same run is correct with all three aggregates dropped, so
  `--require-aggregates` fails there honestly.
- `out/E-final-kernel-o0-s3` and `out/E-kernel-o0-s3-noagg`: on the existing
  connected kernel the experiment is a no-op — eight eligible objects and 54
  edges either way, and byte-identical protected IR. Turning it on does not
  shrink or disturb the existing denominator.
- `out/E-final-kernel-o2-s5` and `out/E-kernel-o2-s4`: O2 at two seeds, six
  shards and 124 nodes, correct in all three arms with the predicate, shard
  and family-conversion gates passing.
- 59 Python unit tests pass, 13 of them new.

**This is eligibility, not protection, and it is narrow.** At O2 the feature
adds nothing on this fixture: `out/E-final-agg-o2-s4` is correct in all three
arms and passes its predicate gate, but frontend SROA promotes exactly the
closed constant-index aggregates the walk accepts, leaving **zero** eligible
closed-memory objects — the same zero the baseline reports. What survives O2
there is precisely what the walk rejects. The O2 memory gate therefore fails
on both fixtures at both flag settings and is not claimed. Real Lua and zlib
coverage is **not** measured here; no large-program run was made for this
milestone, so the zero connected-memory coverage recorded for them above still
stands unrefuted. The full-coverage check is flow-insensitive: it proves every
loaded leaf has at least one tracked store, not that a store dominates the
load, so an originally uninitialized read stays an uninitialized read. Runtime
indices into an aggregate remain rejected by design.
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
`a9ff4e25dbf3716d4ada60ca58ade1065db691ecaca758ba9ccfe144ad5366eb`.

- `out/D-lane-off-o0-s3`: the experiment off. Its protected module is
  `0e378f373e7e506737e1d1372b9c39ef361e3c7d1a4d3039e5f3b61232fdd055`,
  byte-identical to the sealed `out/v03-family-transfer-o0-s3` module, from a
  different plugin hash. The post-O2 module differs from a matched `main` build
  only in the embedded `ModuleID` path. The experiment is a no-op when off.
- `out/D-lane-on-o0-s3`, `out/D-lane-on-o0-s4`: 593 vectors agree across clean,
  native and stock-post-O2. Required memory, predicate and lane-coupling gates
  pass. `producer` keeps three state words, 66 data updates, 13 control updates
  and **2 lane-keyed dispatcher reads**; `main` keeps flattening but has no
  encoded data, so it is not couplable. `out/D-lane-off-o0-s4` is the matched
  control.
- `out/D-probe-on` (`run.py --case state`, connected plan, seed 3): 209 vectors
  agree across release, control, native and post-O2. `obf_target` has one
  lane-keyed read and the **recursive** `state_recurse` has two, so per-activation
  state holds across recursion. Ghidra was not configured, so its case status is
  `partial`, never `pass`.
- Survival: the volatile `fla.multi.lane.load` reads are still present after a
  stock `-O2` simplification attack.
- `out/D-lane-stale-o0-s3` and `out/D-probe-stale`: the canonical-repair arm.
  The clean arm is unaffected; the protected and post-O2 arms do not terminate
  within 20 and 10 seconds respectively.
- 61 Python unit tests pass, including 15 new ones covering the flag default,
  the slice, the three arms and the coverage denominator.

### An honest coverage failure at O2

`out/D-lane-on-o2-s4` and `out/D-lane-on-o2-s5`, both with `--connected-shards`,
are correct on 593 vectors and pass their predicate and shard gates, but
**`connected_check.py --require-lane-coupling` fails on them** and that failure
is recorded. At frontend O2 the only function that keeps flattening is `main`,
which has no encoded data; `producer` carries the encoded region but exhausts
the 30,000-instruction per-function IR budget inside the connected pass, so
flattening never runs on it. That is true with the experiment off as well
(19 instructions of headroom left) and on (1 left), so it is a pre-existing
budget interaction, not a regression. No limit was raised to make this green.
The experiment therefore has **zero coverage at O2 on this fixture**, and its
O2 protected module differs from the matched off build only by the argument-mixed
context seed.

`connected_check.py` gains `--require-lane-coupling` plus a
`couplable_flattened_functions` denominator: a function can only be coupled if
it keeps both a flattening state and a data context. Reports that predate the
field report the numerator as null, and unknown never satisfies the gate.

### Where this leaves the canonicalization attack

The existing symbolic recovery harness does not resolve the comparison.
`conformance/recovery.py` with `recovery_probe.py`, in the retained angr 10
image `sha256:1b877636b131a9ed96e2fc9470f6587e493ecfcbbad3068a87b9924eb1799ea8`,
returns `budget` on both control arms and `unsupported-state-or-control-flow` on
both protected arms, at 228 and 230 steps. Those are inconclusive results, not
protection. Running it at all needed a one-line import shim, because angr 10
vendors its solver as `angr.claripy`; the shim does not change what is measured.

The measured conclusion is narrow and should be stated as such. Keying
transitions on a live encoded-data word does **not** defeat dispatcher
canonicalization. It falsifies one specific reusable assumption — that the
token is a function of the three flattening words — and the word an analyst must
add is produced only by actually evaluating the encoded lanes, so a recovery run
that summarizes the data region away can no longer follow control. The repair
costs one further word, which is closed-form, in the binary, and recoverable by
a slice that runs in under a fifth of a second. **This is a small, real,
measured transfer failure, not hardness**, and the coupling only exists where a
function keeps both an encoded region and a surviving dispatcher.
## The values width gate reads the planner that ran

`conformance/run.py` asked for persistent-value width coverage in
`native_report["values"]`, which only the legacy planner writes. Under
`--region-plan connected` the connected branch of `NativeObfuscation.cpp` never
calls `encodeNativeValues`, so that array is always empty and
`python3 -m conformance.run --case values --region-plan connected` failed with
"persistent-value width coverage is incomplete" at every node cap, with every
connected subfeature off. The check predates the connected planner (`7718e7e`).
It was a dead gate, not a finding.

The connected planner now publishes per function the distinct integer widths of
the nodes it actually encoded, ascending, and the number of PHI nodes it
encoded as a pair — the same two facts the legacy planner already reported.
Both are read before the node instructions are erased. `check_value_coverage()`
selects its evidence from `features.region_plan`, the plan the compiler
recorded as active, and requires the same four widths, 8/16/32/64, of whichever
planner ran. Extra widths are extra coverage rather than a violation, because
connected regions also encode i1 branch predicates; the legacy planner's
`supportedWidth()` admits only the four, so its observed set is unchanged.
The requirement was not weakened and no law was narrowed. A planner that
reports no widths now fails by name instead of being read as a pass, and a
`connected-growth-rollback` row keeps only its eligibility denominators, so an
undone encoding still contributes no widths.

Evidence, LLVM 22.1.8, seed 3 unless stated:

- `out/F-values-connected-1`: connected plan at the default 128-node cap. The
  four fixture functions encode widths `[8]`, `[16]`, `[64]` and `[16, 32, 64]`;
  `obf_target` contributes 2 encoded PHI pairs and 125 persistent edges. 209
  vectors agree across the release, control and native arms. The gate passes
  because the coverage exists, not because it was skipped.
- `out/F-values-legacy-1`: legacy plan, unchanged. Widths `[8]`, `[16]`, `[64]`
  and `[32, 64]`, `connected_regions` empty, gate passes as before.
- `out/F-values-cap4`: `--connected-nodes 4`. One region genuinely encodes, four
  nodes at width 64, and the gate fails with "persistent-value width coverage is
  incomplete: missing 8, 16, 32". `out/F-values-connected-cap2` fails earlier
  still, with no encoded region at all. The gate can still fail.
- `out/F-family-o0-s3` and `out/F-family-o0-s5`: cross-TU O0 fixture, two seeds.
  593 vectors, clean/native/stock-post-O2 outputs agree; required memory and
  predicate coverage pass; no planning violations. The producer reports widths
  `[1, 8, 32, 64]`, so the i1 predicates appear in the evidence rather than
  being filtered out of it.
- `out/F-family-o2-s4`: O2 with `--connected-shards`, seed 4. 593 vectors agree
  in all three arms; predicate, family-conversion and shard coverage pass; six
  shards of one oversized component. The requested memory gate fails honestly:
  no closed-memory object survives O2 on this fixture.
  `out/F-control-main-o2-s4` reproduces that same failure from the `49d9b0e`
  compiler with byte-identical protected IR, so it is a pre-existing fixture
  limitation and not a regression from this change.
- Flag-off control: all eleven default `conformance.run` cases at seed 3 produce
  protected IR hashes identical to the `49d9b0e` build
  (`out/F-control-mine-defaults` against `out/F-control-main-defaults`). The
  connected path matches too: `out/F-values-connected-1` and
  `out/F-control-main-connected` share protected IR `8cab6078`. This change adds
  no `cl::opt`, no harness flag and no instruction; it is report-only.
- Python unit suite: 56 tests pass, ten of them new, including the
  incomplete-width, predicate-only, rolled-back and wrong-planner cases that
  must fail.

Report rows gained `widths` and `phi_pairs`; the `schema` string is untouched
and a version bump is owed at integration. This closes a dead gate. It is not
new protection and it is not hardness evidence.
## Private encoded-call interfaces

`--encoded-calls` / `-native-encoded-calls` is an independent defaults-off
experiment. It requires `-native-region-plan=connected`, exactly like the other
connected subfeatures, and runs immediately before connected allocation so the
region planner sees pair interfaces instead of plaintext call boundaries.

An eligible private function is replaced by a twin, `F.sre.encoded`, whose
interface carries no plaintext scalar. Each integer parameter arrives as two
integers of the same width, `(E, R)` with `x = E xor R`; an integer result
leaves as `{iN, iN}` built the same way; a void function keeps its void result.
This is the XOR family of `NativeConnected` (`xor-prefix-pair-v1`), reported as
`xor-pair-v1`; the additive family is out of scope for this milestone. The twin
keeps every `sre.native.*` attribute, so later stages still treat it as
application code, and the original definition is **erased**. There is no
compatibility wrapper: every encoded interface is private, direct-called and
not address-taken, so nothing needs one, and a wrapper would be a second
plaintext body carrying exactly the summary the pair interface is meant to
cost. `wrapper_retained` is false in every row, and the gate fails a report
that claims otherwise.

Four empty metadata nodes mark the four rebuild points so a later pass can
recognize a pair rather than a coincidence: `sre.native.call.split` on the
caller's `xor` that builds `E`, `sre.native.call.arg` on the callee's `xor`
that rebuilds a parameter, `sre.native.call.result` on the callee's `xor` that
builds the returned `E`, and `sre.native.call.join` on the caller's `xor` that
rebuilds the plaintext result. `R` is drawn from a per-activation entry alloca
that seeds itself from its own address and is read back through volatile
accesses. There are no new module globals: concurrent activations of one
interface must not share a mask, and a constant second coordinate folds
straight back into the plaintext it is supposed to hide.

Eligibility is deliberately narrow: `sre.native.original`, local linkage, not
address-taken, not a declaration, no varargs, no personality function or EH
pad, non-recursive, every parameter and the result an integer of 8/16/32/64
bits or void, at least one caller, and every call site a direct non-musttail
`CallInst` with no operand bundles and a matching function type. An interface
that would carry no pair at all — a void function of no arguments — is reported
as an unsupported signature, never as encoded coverage. Recursion is computed
once per module with Tarjan over the direct call graph, seeded from every
function rather than from exported roots, so a recursive helper that no export
reaches is still detected; `NativeFusion`'s per-candidate reachability walk
would be O(module) for every definition. Skips use a fixed vocabulary:
`not-original`, `exported-or-address-taken`, `varargs`, `eh-or-personality`,
`recursive`, `unsupported-signature`, `unsupported-call-site`,
`function-budget`, `no-callers`. At most 32 interfaces per module are encoded
and the rest are `function-budget`.

The native report gains a top-level `encoded_calls` array with one row per
definition considered, and a `features.encoded_calls` flag. Each row reports
the parameters, the encoded parameters, whether the result is a pair, the
interface widths, the callers, the call sites rewritten, the result
rebuilds, the activation allocas, and `absorbed_arguments` /
`absorbed_results`. Both absorbed counters have an explicit denominator in the
same row: `absorbed_arguments` is measured against the interface's parameters,
one reconstruction per parameter however many call sites feed it, and
`absorbed_results` against the pairs actually supplied, one caller split per
argument per call site plus one callee rebuild per return site.
`connected_check.py` gains `--require-encoded-calls` and
`--require-encoded-widths` plus a self-consistency check: a row that claims an
encoded interface carrying no pair, retains a wrapper, encodes only some of its
parameters, rewrites no call site, uses a reason outside the vocabulary, or
reports more absorbed argument pairs than the interface has, fails the gate as
`planning_violations` instead of being read as coverage. A report without the
array has unknown encoded-call denominators, never zero.

**An unabsorbed pair interface only MOVES the decode across the call boundary.**
It does not remove it. The callee still rebuilds each plaintext parameter from
its pair and the caller still rebuilds the plaintext result from the returned
pair; what changes is that the plaintext no longer exists at the call boundary
itself, and that a callee summary is only reusable together with the caller's
mask. `absorbed_arguments` and `absorbed_results` count pairs that
`NativeConnected` consumed **without** a scalar decode. The transform was
built, gated and committed in exactly that unabsorbed state first, and the runs
under *The pair interface alone* below report `0` for both; they are retained
as the control for the absorption measured after them. A run whose absorbed
counters are zero is a moved decode, not a removed one, and must not be read as
anything else.

### Connected absorption

`NativeConnected::input()` no longer freezes a rebuilt parameter into a fresh
boundary pair: when the value is an instruction marked `sre.native.call.arg` it
takes that instruction's two operands as the pair and converts the family
directly with the existing `convertFamily`. The symmetric case runs once every
node has been emitted: where a marked `sre.native.call.split` or
`sre.native.call.result` xor consumes a value that **is** an encoded node, the
region's own pair is supplied to the interface instead of being decoded for it.
Both coordinates move together, which is safe precisely because the xor and the
activation read it hides behind are used only by each other and by the call or
the returned struct; the pass checks that shape and leaves anything else to
decode. A reconstruction left with no users is erased, so an absorbed parameter
does not survive as a dead plaintext value, and the activation read that is no
longer hiding anything is erased with it.

Three of the four interface rebuild points, and the activation reads behind
them, are therefore no longer region candidates: encoding a pair that is
already a pair would put it out of reach of direct absorption. The fourth, the
caller's `join`, deliberately stays a candidate, because its result is the
plaintext value the application itself consumes and encoding it as an ordinary
node is exactly right.

Absorption is published per function only after the connected planner keeps the
transformed body, so a growth rollback cannot leave absorbed pairs credited to
an interface whose regions were undone.

What this does **not** do: the caller's `join` is not absorbed in the §8 sense,
and an argument expression that is not itself a selected node still reaches its
call site through a plaintext split. Both show up as the gap between the
supplied and absorbed counts below, at O2 in particular.

Two interactions are worth recording because they bound what this feature can
cover today:

- **Function merging competes for the same functions and runs first.**
  `fmerge` is part of the default native profile and absorbs every private
  helper of 4..2000 instructions into `__obf_merged__auto*` super-functions
  before this pass sees them. Those super-functions take their arguments as
  `i64`, which erases the per-width interface, and they are routinely mutually
  recursive once the original call graph crosses a chunk boundary in both
  directions, which this pass then skips as `recursive`. On the fixture below
  with merging left on, the encoded-call coverage is exactly zero and every row
  is an honest skip. The coverage runs therefore use `--no-merge`; this is a
  real ordering conflict between two features, not a property of either one.
- **Stock O2 may inline a private encoded interface and fold the pair away.**
  The post-O2 arm is a correctness check here. Nothing in these runs measures
  how much of the pair interface survives normalization, and nothing below
  should be cited as if it did.

### Evidence

LLVM 22.1.8 in `sre-obf-dev:llvm22`, 593 vectors per arm, clean/native/
stock-post-O2 arms that must agree, and a fresh output directory with its own
manifest and sealed plugin copy per run. Ghidra was not configured for any of
these runs, so no decompiler statement is made about any of them.

#### The pair interface alone

Plugin `a64264b14d3f19f134cdbc9057e989ae78d93af300380a76cb9cbb833f63e4de`, the
committed transform before any absorption existed. On the coverage fixture at
O0 it encodes six interfaces, rewrites 16 call sites, and moves 30 argument
pairs and 14 result pairs across private call boundaries, absorbing **none** of
them: `out/C-calls-o0-s3`, `out/C-calls-o0-s4-threads`,
`out/C-calls-o2-s3-threads` and `out/C-calls-o2-s4` all pass their differential
and coverage gates with `absorbed_arguments` and `absorbed_results` at zero.
These are the moved-decode control. Their connected planner still reports 158
boundary inputs and 102 boundary outputs for the O0 build.

#### With connected absorption

Plugin `f59a9fbf54ef5216f6675962630095682a75634b419716bcc56aa4608cf12bcf`.

- `out/C3-flagoff-o0-s3`: the existing O0 connected command with the experiment
  off. Its protected module hashes
  `0e378f373e7e506737e1d1372b9c39ef361e3c7d1a4d3039e5f3b61232fdd055`, identical
  to `out/C-baseline-o0-s3` built from `49d9b0e` before this work and to the
  sealed `out/v03-family-transfer-o0-s3` module recorded above. Both halves of
  this feature are a no-op when the flag is off.
- `out/C3-kernel-o0-s3`: the standard connected fixture and the existing O0
  command with `--encoded-calls` added. All three arms agree, there are no
  planning violations, and the required memory and predicate coverage still
  pass. Encoded-call coverage is **zero**: both definitions in that fixture are
  exported, so both rows are `exported-or-address-taken`. This is a
  no-regression run, not coverage.
- `out/C3-kernel-o2-s4-shards`: the same fixture at frontend O2, seed 4, with
  `--connected-shards`, which is how this ledger's own optimized evidence is
  produced. Six shards select 124 nodes with 66 direct cross-family
  conversions, and the required predicate, family-conversion and shard gates
  pass with the experiment on. `out/C-kernel-o2-s4`, the same run without
  shards, is correct in all three arms but selects no component at all: that is
  the 212-node oversized component recorded above, not anything this pass does.
- `conformance/fixtures/encoded_calls.c` is the coverage fixture: private
  helpers at 8/16/32/64 bits and one void-returning helper, each reached from
  more than one caller, plus the three negative cases. At O0
  (`out/C3-calls-o0-s3`, and `out/C3-calls-o0-s4-threads` at a second seed) it
  encodes **six** interfaces across widths 8, 16, 32 and 64, rewrites 16 call
  sites through 7 per-activation allocas, retains no wrapper, and moves 30
  argument pairs and 14 result pairs. **All 11 parameter reconstructions and
  all 35 supplied pairs are absorbed**: every parameter of every encoded
  interface is consumed as a pair, and every caller-side argument split and
  callee-side result rebuild hands a region's own pair straight to the
  interface. Boundary inputs fall from 158 to 66 and boundary outputs from 102
  to 32 against the unabsorbed control on the same command; part of that drop
  is absorption and part is interface plumbing no longer being selected as
  region nodes, so the absorbed counters, not the boundary counters, are the
  measurement. Required memory, predicate, encoded-call and encoded-width
  coverage all pass.
- At frontend O2 (`out/C3-calls-o2-s3-threads`, `out/C3-calls-o2-s4`) the same
  six interfaces move 46 argument pairs and 23 result pairs across 23 call
  sites, and absorption is **partial and reported as such**: 10 of 12 parameter
  reconstructions and 20 of 52 supplied pairs. An argument expression that is
  not itself a selected region node still reaches its call site as a plaintext
  split, and O2 leaves more such expressions. The O2 runs do not require memory
  coverage: frontend O2 promotes the fixture's local array, exactly as it does
  for the transfer fixture above, so there is no eligible closed object.
- Frontend O2 also changes which negatives exist, and the report says so rather
  than smoothing it over: `climb` stops being recursive because LLVM rewrites
  its accumulator recursion as a loop, so it becomes eligible, and `tap`
  disappears entirely because its only effect is a relaxed store to an internal
  atomic nothing reads. The void-return interface is therefore covered at O0
  only. The skip reasons the fixture actually produced are
  `exported-or-address-taken` (4 or 5, including both entry points),
  `recursive` (1, at O0) and `varargs` (1). The remaining six vocabulary
  entries are implemented and unit-tested but not exercised by this fixture.
- `out/C3-calls-o0-s4-threads` and `out/C3-calls-o2-s3-threads` drive the same
  protected module from four concurrent callers over the same 593 vectors, in
  the pattern of `driver_threads.c`. Per-activation interface state is a stack
  alloca, so the threaded arms must and do print exactly what the
  single-threaded arms print.
- Growth on the coverage fixture, under the same explicit 600,000-instruction
  module cap: 272,852 final instructions with the experiment off, 276,405 with
  the unabsorbed transform, and 273,787 with absorption — the absorbed build
  costs about 0.3% over the unprotected-by-this-feature build, because the
  boundary work it removes nearly pays for the pairs it adds. At O2 seed 4 the
  same comparison is 259,033 unabsorbed against 220,628 absorbed. The module
  cap is raised for this fixture only because ten private definitions each
  saturate the ordinary 30,000-instruction per-function budget; no eligibility
  test, coverage gate or protection limit was changed.
- `out/C3-calls-o0-s3-repeat`: the same command on the same plugin a second
  time produces a byte-identical protected module,
  `ae72818a48bc8251bad620339ad533732a1849f2e86ad4651c955be370f0cee1`. Neither
  the interface nor its absorption lets use-list or pointer order reach the
  output: call sites are collected in caller-symbol order and then in
  instruction order, and every mask is keyed by interface, role, host, site and
  argument index.
- The Python unit suite is 67 tests.

The coverage runs use `--no-disassembly`: this fixture keeps ten private
definitions alive and its per-arm disassembly exceeds the harness's 16 MiB
tool-output limit. The differential, the coverage gates and the post-O2 attack
are unaffected; only the ELF disassembly artifact is not retained. For the same
reason the fixture is driven by `conformance/whole.py` rather than registered
as a `conformance/run.py` case, whose per-arm driver always disassembles.

A pre-existing harness bug surfaced here and is fixed rather than worked
around: `connected_check.invariants()` read planning accounting from every
connected row, but a function the planner never analyzed — a varargs helper
reaches it as `structure-or-size` — carries none. Such a row is now skipped
like the rollback row it resembles. No fixture in the tree had previously put a
varargs definition through a connected build.

## Wave integration, schema v4, and what it cost

Six parallel efforts were merged onto `49d9b0e` and the report schema was
bumped once, here, to `sre-native-v4`. Every feature in the wave is
independently defaults-off. The integrated plugin
`53ba0c1694304edc5d5db1839972eec948e29494e70cf084b7d11938b21d0b33` was gated
as a whole, not only branch by branch.

- **Flag-off control.** With every new flag off, the integrated compiler emits
  a protected module byte-identical to the sealed
  `0e378f373e7e506737e1d1372b9c39ef361e3c7d1a4d3039e5f3b61232fdd055`. Six sets
  of changes to one encoder, and the default path is unchanged to the byte.
- **All six on together**, O0 seed 3: 593 vectors agree across clean, native
  and stock-post-O2, zero planner violations, four joint-output groups, two
  lane-keyed dispatcher reads and encoded memory in one build.
- **Per-feature fixtures** pass their own coverage gates on the integrated
  compiler: the encoded-call fixture absorbs 11 argument reconstructions and
  35 supplied pairs, and the aggregate fixture encodes three aggregate objects.
- 116 unit tests pass.

### Two defects the large-application validation found in the shard commit

Both were in `698212c`, and neither was caught by the fixture evidence.

1. `connected_check.invariants()` raised `KeyError` on every real-application
   report. A function rejected before planning publishes no accounting fields
   at all, and only the growth-rollback case was handled. It crashed rather
   than failing, so no large run could be gated. It now skips exactly the two
   row kinds that never claimed the identity and reports any other missing
   field as a violation, so it can neither crash nor pass by omission. Zero
   violations across 1,801 function rows of real SQLite, Lua and zlib reports.
2. `scale.py` advertised `eligible = selected + skipped + shard loss` as an
   aggregate identity. It holds per function but not in aggregate, because a
   growth-rolled-back function publishes its eligible cost while the rest is
   republished as `attempted_*`. The scope sentence now says so and the gap is
   reported as `connected_rollback_estimated_cost`.

### Shards on unchanged large C applications

Eight `scale.py` runs, matched pairs differing only by `--connected-shards`,
all `conformance-pass` with workloads matching their independently declared
expected output.

| application | selected nodes without shards | with shards |
|---|---|---|
| zlib | 1,912 | 2,088 |
| SQLite seed 1 | 1,629 | 1,777 |
| SQLite seed 2 | 1,607 | 1,763 |
| Lua | 1,821 | 2,087 |

Read against cost this is small. On SQLite shards move 8.63 million of
estimated cost from skipped to shard-lost to gain 13,984 selected, taking
coverage of the eligible pool from 2.34% to 2.55%. Shards buy a bounded
prefix; they do not make a 14.3 million eligible pool tractable.

**A real trade-off, previously unmeasured:** functions retaining control-flow
flattening on Lua fell from 50 to 29. With `--scale-structure` off, flattening
and connected regions share one module cap and shards spend more of it. A
large run requiring both `--require-flattening` and `--require-shards` cannot
be assumed to pass. Memory coverage was unchanged on every application, so
shards did not widen memory anywhere. Compile time is **not** reported: the
frontend compile of unmodified sources differed 26% between two arms that
cannot depend on the flag, so the measurement is confounded.

### An ordering conflict that needs a decision

Bounded function merging runs before the encoded-call pass and absorbs every
private helper of 4 to 2000 instructions into merged super-functions, which
take `i64` arguments and are routinely mutually recursive. With merging left
on, encoded-call coverage on its fixture is **exactly zero**, every row an
honest skip. Its coverage runs therefore pass `--no-merge`. Two features want
the same functions and the earlier one wins. Nothing here decides that.

### What this wave did not establish

No large-application run exists for aggregates, joint outputs, lane
transitions or encoded calls. Canonical dispatcher repair still works; the
lane experiment adds one word that a backward slice recovers in under two
tenths of a second. Aggregate coverage is zero at O2 because frontend
optimization promotes exactly the objects the walk admits. A pinned slot is a
compiler barrier, not a semantic one, so surviving stock optimization shows
only that the optimizer did not fold it. Coverage is not hardness.

## A decode the cross-family conversion was documented not to create

The v04 offline family work applied a rejection criterion to the **shipping**
v03 emitter and found two intermediates that materialize a decoded value as an
SSA value. Both are in code this ledger already describes as avoiding exactly
that.

`NativeConnected.cpp::convertFamily`, the XOR-to-additive path, carries the
comment "without ever creating the decoded scalar as an SSA value" directly
above:

    E = ((X.E + X.R) - 2*(X.E & X.R)) + R

The inner subtraction is `X.E ^ X.R`, the plaintext, and it is a real `sub`
whose result is then fed to an `add`. Confirmed by derivation and by 20,000
random trials at 32 bits: the intermediate equals the decoded value in every
one. The additive multiply has the same shape, where
`((X.E*Y.E) - Cross) + X.R*Y.R` is exactly `x*y` before the output mask is
added, likewise identical in 20,000 trials.

Both are single-instruction regroupings, not design errors: adding the mask to
the first partial product instead of last computes the same value from the same
operands with no such intermediate. The regrouped forms are proved equal to the
originals and are in `conformance/connected_model.py` as
`xor_to_additive_grouped` and `affine_mul_grouped`. **The emitter itself is not
yet fixed**, and the originals are retained as negative controls that SMT
proves contain a decode at 8, 16, 32 and 64 bits.

This is the concrete v03 claim the v04 plan's principle 1 anticipated: a wrapper
around an ordinary operation is only a candidate until normalization tests it.
The claim in commit `b685259` that mixed families connect "without scalar
decodes" is false as implemented for these two paths, and the ledger text above
describing that feature should be read with this correction.

### A labelling artifact, and the supervisor's own misreading

The exposure probe asks whether a suspect intermediate moves when the carrier
masks move. Unsat means it never moves, so it is a function of the logical
values alone, which is the bad outcome; sat means the solver produced a witness
that it does move, which clears it. The runner initially recorded `expect:
proved`, so every cleared intermediate was written out as a failing
`counterexample`. Reading those raw counts, the supervisor twice reported that
three candidate families had been "broken by their own probes". That was
backwards and is retracted here. Under corrected semantics the final sweep has
**zero substantive failures at any width**; all 271 failing entries are
inconclusive. The lesson is the project's own: a count is not a result until
its semantics are stated, and an aggregate with an `expect` field baked in can
invert a conclusion.

## Next implementation batch

The post-integration review repaired private-call eligibility and shard bounds.
Native schema v5 distinguishes partial argument absorption and actual encoded
symbol names; scale and fixture runs share the same report gate, and incomplete
recovery slices are inconclusive.

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
   shards have now been tested on unchanged large applications as recorded
   above; broader coverage and the trade-off with retained flattening remain.
2. Sol recovery regressions: freeze the successful v02 scripts privately;
   separate informed entry/state assumptions from binary-only discovery. Test
   dispatcher inversion, canonical-state rebasing and XOR/additive projection;
   distinguish unchanged transfer, repair, and unsupported/inconclusive tools.
3. P4 direct cross-family transfer and bounded joint-output coupling are
   implemented as separate ablations. Their inverse controls remain relevant;
   measure transfer cost before any hardness promotion.
4. P5 private encoded-call interfaces and connected absorption are implemented
   for the documented narrow signatures. Resolve the merging-order policy,
   broaden eligible effects only with tests, and retain explicit recursion
   exclusions until recursive interfaces are supported.
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
