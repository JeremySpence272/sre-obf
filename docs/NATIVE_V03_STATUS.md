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
