# v05 revision 1: persistent represented computation with measured analysis cost

Status: approved design, 2026-09-22. See [implementation status and validation](NATIVE_V05_STATUS.md)
for completed bounded features, measured results, and remaining contracts. This
design document does not itself establish implementation coverage or resistance.

Revision 1 incorporates the [source-informed theoretical audit](V05_THEORETICAL_AUDIT.md).
It is a proposed tier above the initial runtime plan, not a demonstrated hardness
rating. The substantive change is to require useful computation to remain within
verified representations across operations and activations, including its exact
consumers. More random keys, phases or interpreter instructions alone do not
satisfy this revision.

This supersedes the crackme-centered, static-only v05 plan. The primary target
is now **RevGame C, O0, stripped, static PIE**, with the unchanged
`revgame/c-noopt-nosym-static-sre-obf-max-v04` cell as the baseline. Preserve v04
artifacts. The crackme may remain a small regression but no longer drives
selection, performance acceptance, milestones or promotion.

## 1. Objective and baseline

Increase the cost of extracting and reusing useful semantic models through
static analysis, runtime snapshots and repeated deterministic replay. Preserve
defined behavior and maximize measured benefit within the runtime budget.
Extend [v04 contracts](NATIVE_V04_STATUS.md), ownership proofs, transfers,
selection and rollback instead of creating parallel systems.

The development target is the complete reference replay in **under 1 second**
on the registered reference host. The hard acceptance ceiling is **strictly
under 20x the matched unobfuscated runtime**, including initialization. This
allows a correct initial implementation to leave optimization headroom. One
second is a target, not an additional rejection gate. The 20x allowance is
total protected/clean cost, not an additional multiplier on top of v04.

### Frozen evidence

The exact cell's `eval/protection/` manifests and reports are authoritative.
Local directory names alone do not establish baseline identity.

| Artifact or measurement | Recorded value |
|---|---|
| Cell | `revgame/c-noopt-nosym-static-sre-obf-max-v04` |
| Clean SHA-256 | `284ff2db27b92b3a19fa0e5c7b2acacd948bde79533065ef1711b8af723e0d27` |
| Protected SHA-256 | `27917ff7b0e4936b892eeb9d63d2f6108ea48ad982927ede49d097e504be0b58` |
| Clean / protected bytes | 1,459,168 / 2,380,200 |
| Frontend / backend | O0 / O0; static PIE; stripped |
| Reference replay SHA-256 | `a356a049509ac94ca80ee0338cc5370ed12e7e5c36093e329e639d334903884a` |
| Reference replay | 14,233 actions; 14,012 turns; all six eggs |
| Clean / protected median | 0.1343235066 s / 0.7002253784 s |
| Recorded slowdown | 5.2129772072x |
| Protected maximum sample | 1.0830952814 s |
| Build seed / module cap | 1 / 250,000 instructions |

At that clean median, 20x is approximately 2.686 seconds. These are historical
measurements, not portable thresholds: rerun clean and protected arms on the
same machine. v04 did not stay under one second on every recorded sample.
Earlier conversational estimates of 5–20% added overhead were unmeasured and
are not evidence or acceptance criteria.

The primary agent evidence in `revbench-revX/results/` has prefix:

```text
revgame-c-noopt-nosym-static-sre-obf-max-v04_tier2_codex_20260922_120634_r1
```

The submitted replay scored D only: 588 actions, 558 turns, ending on floor 2.
The agent reconstructed the room-entry FSM, extracted runtime coefficients,
modeled game state and calculated a valid route. It also investigated crafting,
spell history, entropy and Chimera damage checks. Targeted static analysis and
runtime inspection worked together; static recovery was difficult, not defeated.
The run ended with a platform classifier error after 139 command executions and
1,926.4 seconds, below its configured 500-step limit. Treat this as an interrupted
partial solve, not evidence that only one egg was recoverable. Preserve the
termination reason and original grader result.

## 2. Scope, generalization and threat model

Assume the evaluator controls the process and can inspect memory, registers,
calls, branches and outputs across fresh processes and checkpoints. Debugger
access must work. Include combined static/runtime analysis and reusable models
that adapt to new encodings. Different addresses or keys do not establish a new
semantic obstacle.

Software-only representation keys remain observable. Checkpoints preserve their
state, and per-process randomization does not prevent within-process probing.
Observable input/output relations remain available. The goal is increased
measured effort, not secrecy against unlimited observation or guaranteed failure
to solve all eggs.

Production selection uses generic IR properties: ownership, escape, widths,
def-use structure, recurrence, private interfaces, consumer continuity and
execution frequency. Never select by game name, egg label, strings, known
offsets, coefficients, replay seed or transcript addresses. Game-specific labels
belong only in private evaluation reports. Do not protect only the six known
checks by hand and call that a general compiler result.

Freeze alternate valid RevGame workloads spanning different seeds, short and
long sessions, menus and other paths. The reference replay is training evidence,
not a holdout. Add independent parser/state-machine, numerical, indexed-buffer,
table and private-call fixture families, with at least one untouched family and
compiler seeds for evaluation. Preserve existing holdout locks and the separate
[large-program ledger](V04_DEFERRED_SCALE.md).

### Scope changes

v05 admits a small runtime support layer, per-process representation entropy,
bounded phase changes, closed-object layout diversity and selective interpretation.
These extend the earlier static-only scope. Keep a functioning v04 feature-off
arm and retain static correctness and normalization controls.

Sparse internal integrity validation is an optional, separately measured arm.
Debugger denial, instrumentation detection, timing traps, environment-dependent
gameplay, delayed corruption and self-modifying executable pages are outside
this implementation plan. Integrity failures must be explicit rather than
producing plausible wrong results. Hardware/server assistance is outside the
standalone offline cell contract. Passive runtime observation remains in scope
even when integrity checks are enabled.

Do not change game rules, egg predicates, replay schema, seed interpretation,
action limits, death behavior, RNG draw order or grader scoring. Preserve
external ABI, supported memory ordering and defined behavior. Unsupported
aliasing, pointer escapes, atomics, volatile operations and exceptions remain
explicit exclusions rather than silently widened contracts.

## 3. Architecture and feature workstreams

### W0 — freeze the baseline and inventory useful regions

Extend [build.py](../integrations/revgame/build.py),
[check.py](../integrations/revgame/check.py) and
[benchmark.py](../integrations/revgame/benchmark.py), retaining their v04 modes.
Freeze source, generators, compiler image, plugin, flags, binaries, replays,
verifier and prompt hashes. Verify source provenance against packaged manifests.

Inventory original operations and all consumers after canonicalization/fusion.
Report eligibility, selection, retained coverage, escapes, scalar materialization,
unsupported uses and rollback. Generated decoders/handlers are not original
protected work. Include runtime observation boundaries in addition to scalar IR
boundaries. Record all uses of an original value, including unprotected ones.

Define a region contract covering logical widths, storage ownership, lifetime,
initialization, proved indices, representation version, phase, private interfaces
and observable exits. Reserve a complete producer/transfer/storage/consumer
chain before expansion. Reject or label partial chains that exceed ownership or
budget limits. Invalidated analyses require replanning.

### W1 — runtime contexts and independent randomness

Provide a versioned representation-context interface. Separate the compiler
build seed, application RNG and runtime representation seed. Entropy affects
representation only; outputs and gameplay RNG state remain identical. Acquire
entropy at initialization, not on every protected access.

Provide deterministic contexts in test artifacts for reproducible failures and
fresh-process contexts for ordinary release validation. Test controls must not
silently ship as an undocumented production environment override. A fixed,
known context is also a required analysis control: diversity is not key secrecy.

Specify initialization order, allocation/entropy failure, destruction, repeated
library calls, nested activations and supported threading. Use explicit ownership;
a mutable shared key must not change under another activation. Define or exclude
fork, signal reentry, unload and serialization cases before enabling relevant
regions. Never silently report full protection after falling back to static state.

### W2 — continuous encoded state and closed-object layouts

Extend typed native bundle/object contracts across supported stores, calls,
loop backedges and predicates. Start with bounded private scalar groups and
initialized arrays. Preserve i8/i16/i32/i64 semantics, including casts and wrap.

For proved closed objects, admit diversified physical layouts and jointly
represented live cells. Preserve bounds, alignment and allocation provenance.
Public structures, unknown aliases, externally observed bytes and serialization
formats cannot be reordered without an explicit contract. Avoid maintaining a
complete canonical duplicate merely for implementation convenience.

Extend eligibility beyond the current four-cell local tile and experimental
eight-cell shape. Specify bounded, field-sensitive ownership for private portions
of larger aggregates, persistent internal globals and fixed-capacity buffers.
Prove all readers/writers, aliases, resets and lifetime boundaries for each
selected portion. A containing object need not be wholly private, but a selected
field must not be accessible through an unmodeled alias or bytewise operation.
Reject ambiguous overlapping accesses. Merely raising the tile cell limit is
not a proof of aggregate support.

Keep admitted persistent state represented between application operations;
private calls transfer represented values under explicit contracts. Public
rendering, serialization and library interfaces decode only their required
outputs. Record those as unavoidable exposure, not continuous coverage. Do not
create a canonical full-state mirror for rendering or replay. Save compatibility,
where supported, takes precedence over hiding serialized values; keep the
reference cell's existing production exclusions unchanged.

Transfer directly between supported encoded representations where verified.
Inventory unavoidable scalar escapes. A shared decoder can itself become the
easiest observation boundary; measure this instead of adding wrappers. Reuse
`NativeBundle`, `NativeTile`, `NativeEncoding`, `NativeTransfer` and existing
private-call/object-borrowing infrastructure. Retain generic mixed-width and
proved-index eligibility improvements from the earlier plan where needed.

### W3 — bounded representation phases

Introduce verified transitions at generic lifetime/control boundaries chosen
by ownership and frequency analysis: initialization, loop regions and private
call boundaries. A floor transition is an evaluation observation, never a
compiler selection rule based on an application function name.

Preserve logical state across every live value, borrowed object and consumer.
Transitions must not expose partially migrated objects to supported observers.
Bound work and scratch storage; test zero-trip loops, early returns, nested
calls, long sessions and counter wrap. Amortize transition cost over useful work
rather than reallocating or rebuilding objects on every scalar access.

Compare fixed representation, startup-only diversity and continuing phases.
One parameterized projection that handles all phases after cheap fitting is
successful analyst reuse. Phase count alone is not analysis resistance.

### W4 — transient immutable data and consumer continuity

Extend immutable backing so selected values are accessed in bounded pieces and
consumed within represented regions. Avoid retaining full plaintext tables for
lookup convenience. Reuse lazy string infrastructure where appropriate, while
accounting for data tables separately from textual strings.

Include bounded caches and scratch lifetimes in the cost/ownership contract.
Measure repeated-access overhead and remaining plaintext lifetimes. Clearing
scratch reduces later snapshot exposure but cannot retract observed values.
Observation of successive accesses remains a valid evaluation method. Preserve
supported concurrent reads and exact index semantics.

Treat consumer integration as required work, not a later optimization. For
eligible fixed-length equality-only uses, preserve exact equality while keeping
derivation, bounded storage and comparison inside the represented region. Do
not replace equality with a collision-prone digest or silently change general
`memcmp` ordering semantics. Preserve memory accessibility and defined behavior;
unsupported lengths, aliases or other consumers remain explicit boundaries.
Audit lowered code as well as IR for canonical operand arrays and helper calls.
Avoiding one array materialization is useful but does not make the final Boolean
or successive observations secret.

### W5 — selective interpretation

Audit existing `VMPass` emitter, handlers, verifier and call contracts for reuse.
Do not automatically adopt broad VM presets or anti-debug features. Initial
scope: bounded closed integer regions and supported object operations with
useful consumers. Keep floating-point, system calls, unproved pointers and
exceptional control flow native until separately specified.

Specify bytecode operations, widths, branches, object ownership, call boundaries
and context lifetime independently of implementation. Differentially verify
lowering and composition. Select by measured cost; avoid dominant hot loops
unless full-workload performance permits them. Interpreting only a final Boolean
may leave its useful relation directly observable.

Evaluate build diversity and optional runtime dispatch mapping as separate arms.
Opcode renumbering that normalizes cheaply is not substantive protection.
Decoded operands, handler entry/exit and VM/native crossings are observation
boundaries. Compare simple validated interpretation with expensive variants;
retain complexity only after a useful measured tradeoff appears.

The stronger candidate operates on bounded groups of useful original operations,
with represented state retained between activations where ownership allows it.
Evaluate verified composition of existing producer/update/consumer operations
against per-operation dispatch; choose grouping by real dataflow and cost.
Do not invent dead dependencies or change the application's transition system.
Any alternative representation or lowering family needs its own specification,
inverse/transfer checks and emitted-code tests before diversity can select it.
Varying masks or opcode identifiers is a separate, weaker control. Composed
handlers still have recoverable semantics; report whether a single normalized
model works across all selected families.

### W6 — optional internal integrity validation

Define bounded validation of protection metadata, context versions and owned
representation storage, with explicit failure behavior. Amortize validation at
supported boundaries and report its cost separately. If immutable binary-region
checking is admitted, specify relocation/loader compatibility and exact scope;
do not hash a whole image on every action.

Test intact execution and controlled corruption of owned fixture metadata.
Document coverage and collision limits; ordinary consistency checks are not
cryptographic authentication. Never count tamper detection as resistance to
passive observation. Main conformance must still run under instrumentation.

### W7 — cost-aware composition

Reuse `NativeBudget.cpp`, region policy and snapshot infrastructure. Joint units
commit or roll back completely, including runtime declarations, metadata,
attributes, allocations and private signatures. Make new flags and dependencies
explicit, preserving feature-off behavior.

Estimate initialization, per-entry/access, transition and interpreter costs from
generic training profiles. Record displaced work and unprofiled shapes. Never
special-case the known replay, stop protecting after N turns, or disable features
under instrumentation or performance testing. Optimize redundant transfers and
cache behavior only with renewed equivalence and boundary measurements.

### Required stronger-tier coverage contract

At M0, freeze a private evaluation ledger of original recurrent-state regions,
fixed-buffer consumers and private multi-call computations. For every entry,
record input origin, every read/write, storage lifetime, exact consumer, public
exits, eligibility and retained release-code coverage. Distinguish frontend
elimination, unsupported contracts, budget rollback and intentional public
exposure; no category may disappear from the denominator.

Candidate readiness requires an end-to-end recurrent-state chain and an exact
fixed-buffer consumer chain in RevGame, plus independent fixtures for both.
Freeze the actual designated chains before tuning. All logical values necessary
for each designated chain must satisfy its contract, or the report must mark
that chain incomplete. Incidental arithmetic coverage cannot stand in for this
requirement. Other partial/excluded chains remain visible; this does not imply
that every egg is protected. Selection stays generic and does not consume the
private ledger's egg labels. If generic selection cannot meet these requirements
within the existing budget, the stronger-tier candidate fails readiness.

## 4. Correctness and feature conformance

These are planned tests, not already available commands. Extend current fixtures
and `conformance/test_revgame.py`; add focused test modules for new contracts.

| Test group | Required evidence and negative controls |
|---|---|
| Transfer laws | Independent encoding/transfer/phase specifications, exhaustive small domains, bit-vector checks where supported and emitted-code differential tests. Model proof alone does not certify lowering. |
| Lifetime/layout | Initialization, alignment, tails, index bounds, repeated/nested calls and supported thread isolation; reject unsupported escapes. |
| Entropy isolation | Multiple runtime seeds preserve logical results and application RNG; promised physical diversity is observed; failure/fallback is explicit. |
| Phases | Logical equality through transitions, zero-trip loops, early exits, counter wrap and borrowing; malformed context versions fail as specified. |
| Transient data | Random/repeated access, bounded storage and cache behavior; inventory canonical copies and remaining exposure. |
| Persistent regions | State survives multiple calls, resets and phase transitions with logical parity; mixed public/private fields, bytewise aliases and unsupported overlapping accesses are rejected or explicitly bounded. |
| Exact consumers | Equality positives and one-bit/length near misses, signedness and supported alignment; all consumers inventoried; no checksum substitution or accidentally changed ordering semantics. |
| Release boundaries | Verify designated chains after lowering; detect accidental canonical mirrors and diagnostic exports; preserve production save/verifier exclusions and supported public-format compatibility. |
| Interpreter | Every admitted opcode, width boundary, branch and native crossing; feature-off parity; reject unsupported effects; validate malformed bytecode handling in trusted test artifacts. |
| Rollback | Forced rejection at each expansion stage restores IR and attributes completely; no orphan context or partially changed ABI. |
| Game semantics | CLI, strict schema, invalid-prefix, replay-to-TUI, recording and live-input checks; death rejection; exact outputs, turns and logical-state parity. |
| All-egg compatibility | Reference still scores A–F under unchanged private verifier; protected production replay matches clean behavior. Grader success alone does not test the protected binary. |
| Normalization | Supported optimizer and decompiler-normalization arms retain defined behavior; decompiler failure/size is not resistance. |

Use trusted diagnostic builds for logical-state parity with explicit exports.
Keep their decoders/descriptors and expected predicates out of binary-only
evaluation. Independently test observable parity and performance on the stripped
release artifact. Do not ship diagnostic exports or use them for release timing.

Test multiple runtime seeds per designated fixture and at least three frozen
compiler seeds for integrated acceptance. Include pairwise feature combinations
and the full preset. Include positive predicate cases and near misses rather
than relying on random tests that almost always take the false branch.

## 5. Performance conformance and acceptance

### Measurement protocol

Extend the existing RevGame benchmark, which currently reports slowdown without
enforcing a slowdown ceiling. Measure launch through replay-complete prompt,
including context initialization and entropy acquisition, excluding human TUI
wait. Also report full-process and CPU time, peak RSS, binary/application text,
compile time and retained IR growth. Time the packaged release artifact.

Measure clean, frozen v04 and v05 on the same host, affinity, container limits,
toolchain and workload. Match sources and floating-point options. Record CPU
model, OS/kernel, frequency policy when available, load, environment, hashes and
sample order. Historical O0 clean is the primary denominator; an O2 baseline may
be a labeled extra arm, never a mid-comparison substitution.

Acceptance uses one recorded warmup per arm then **31 rotating-order paired
samples**. Every sample starts a fresh process with runtime diversity active.
Warm caches do not remove startup cost. Record the first launch separately.
Retain all raw timings and correctness results. Never discard a failed sample
to publish a passing summary.

For matched clean/protected times `C_i`, `P_i`, compute `R_i = P_i / C_i`.
Report ratio of medians, median paired ratio, paired-ratio p95, protected absolute
median/p95/max and CPU ratios. Use nearest-rank p95: sorted rank `ceil(0.95*n)`.
Record dispersion/noise. Contaminated runs are inconclusive and rerun as complete
blocks; do not cherry-pick samples, workloads or representation seeds.

| Gate | Policy |
|---|---|
| Primary slowdown | Ratio of medians **< 20.0** and paired-ratio p95 **< 20.0**, per accepted compiler seed on the full replay. Exactly 20 fails. |
| Absolute target | Protected median **< 1.0 s** on the registered reference host; separately report p95 below 1 s. Missing this target can still pass the 20x gate. |
| Workload coverage | Enforce 20x individually for frozen substantive alternate replays; averaging cannot hide failures. Tiny CLI cases use separately registered absolute-latency limits. |
| Correctness | Every timed run completes successfully with matching outputs/turns. Incorrect fast runs fail. |
| Robustness | Crashes, deadlocks, timeouts, truncation, missing samples, malformed metrics and unexplained runtime-seed outliers prevent acceptance. |
| Resources | Initially keep the 250k module cap, 600 s compile timeout and existing growth guards. Register memory/size limits before experiments; runtime allowance does not waive them. |
| Visibility | Report incremental cost over v04 and each feature ablation, even below the ceiling. |

Over-budget candidates remain experimental failures with artifacts retained.
Optimize or reduce generically selected scope, then rerun. Do not change the
denominator, exempt the slow workload or raise the limit. The earlier v05
2x-v03 runtime goal is superseded by this clean-relative 20x policy. Other
resource limits are not implicitly relaxed.

### Tests of the benchmark and gate evaluator

Add a pure summary/gate evaluator with deterministic synthetic sample tests,
separate from noisy integration timing:

1. Ratios below, equal to and above 20; the strict 1-second target boundary;
   acceptable slowdown above 1 second reports target missed without failing
   solely because of that target.
2. Passing median with failing paired p95 fails. Slow workloads/build seeds
   cannot be hidden by aggregation. Verify the exact percentile convention.
3. Reject zero/negative/nonfinite times, NaN/Infinity, missing pairs, duplicate
   samples, insufficient samples and mismatched workload/artifact hashes.
4. Exclude warmups from statistics. Failed samples, timeout, output mismatch
   and changing binaries always prevent a pass.
5. A trusted small executable with controlled startup delay proves initialization
   is counted. A delayed exit distinguishes ready from full-process time.
   Verify cleanup and CPU-affinity restoration on every exit path.
6. Verify rotating order, fresh processes, pairing and per-workload/seed reports
   using deterministic fixtures; test seeds must not replace release diversity.
7. Validate persisted raw samples, report schema/version and explicit gate
   reasons. Partial reports cannot become complete; resumed measurements are
   new blocks with their provenance retained.

Fewer-sample developer runs report `smoke_only`; they cannot satisfy acceptance.
Ordinary CI runs evaluator and short parity tests. A registered performance lane
runs the full frozen matrix at milestones, avoiding repeated noisy timing tests
after every small change.

### Concentrated-cost and uncertainty checks

Freeze substantive workloads emphasizing each selected operation family as well
as ordinary mixed play. Include short sessions to expose initialization cost and
long sessions to expose repeated transitions. Enforce the same 20x gates for
each substantive workload, not only the all-egg replay. Select workload classes
from behavior and profiles, not secret egg identifiers. Record startup, steady
work and phase/region costs separately without subtracting them from the gate.

Where clean intervals are below the registered measurement resolution/noise
floor, use a longer semantically representative workload or mark the measurement
inconclusive. Do not turn unstable ratios into passes. Add evaluator tests for
this classification and for a full replay passing while an operation-heavy
workload fails. Validate that instrumentation used for cost attribution is
absent from the release timing arm.

Thirty-one samples define an empirical percentile gate, not a statistical
guarantee of tail latency. Register independent confirmation blocks for finalist
candidates before measurement. Retain every block, report disagreement and
require confirmation rather than choosing the best passing block. At the frozen
medians the 20x ceiling allows about 3.84x v04's runtime; the one-second target
allows about 1.43x. Neither is a predicted overhead or a per-feature allowance.
Every required valid confirmation block must pass. A failed block prevents
promotion; an independently justified invalid block is retained and replaced in
full under the registered noise policy, never merely because its result is slow.

## 6. Analysis-resistance evaluation

Retain static-only controls but use combined static/runtime analysis for the
primary RevGame lane. Allow debugger access, repeated execution, checkpoints,
memory/trace observations and focused decompilation. An observer that cannot
start does not measure the failure mode seen in the baseline.

Use bounded reproducible local assessment tasks to measure:

- Useful table/state visibility in one snapshot or across normal accesses.
- Recovery of logical input/output behavior without reconstructing storage.
- Reuse of inferred projections/summaries across calls, phases, build seeds
  and fresh runtime contexts.
- Substantive new modeling work versus fitting addresses, masks or opcode IDs.
- Exposure at accessors, runtime support, handlers and native/VM crossings.
- Cheaper final-predicate/event routes versus whole-region reconstruction,
  with small-domain and supplied-region controls.

Known-descriptor controls are expected to decode correctly and validate the
contract; that is not an implementation defect. Private source, descriptors,
reference replay and grader details stay out of the binary-only workspace.

Separate this source-informed design audit from the blinded analysis lane. A
reviewer who already knows the source or reference replay must not count as an
independent binary-only discovery trial. Unchanged semantics permit reuse of
an already known solution: obfuscation cannot force rediscovery in that case.
Use untouched workloads/program families and independent evaluators to assess
generalization without claiming source-known replay resistance.

Before promotion, assess each designated chain for canonical consumer exposure,
same-checkpoint reuse, reuse across runtime phases, small logical-domain behavior
and reusable interpreter summaries. Treat successful reuse as evidence against
the mechanism even when the full game has not yet been solved. The requirement
is a measured increase in modeling effort beyond execution slowdown, not a
prescribed number of snapshots, handlers or keys.

Measure time/tool work to first verified behavior, each additional behavior,
first valid 6/6 replay and reusable validated models. Separate first discovery
from final submission. Record observer overhead separately from native runtime.
The score curve and cheapest successful method matter more than trace size,
decompiler line count or one solver's timeout.

Freeze prompts, model/tool versions, resources and limits before comparing
clean/v04/v05. Keep service settings consistent; classifier errors/refusals are
separate outcomes, not protection successes. User-reported clean solves remain
context until matched artifacts are retained. Start with three independent runs
per selected artifact, report variability/censoring and avoid universal claims.
This document does not launch or authorize paid evaluations.

## 7. Ablations, milestones and promotion

Required arms: clean, frozen v04, v05 new-features-off, state/layout only,
transient data only, selective interpretation only, startup diversity versus
continuing phases, full composition, and optional integrity on/off. Include a
fixed-known-context control and matched-cost comparisons where practical.
Do not feed holdouts into tuning or policy generation.

Retain mechanisms only with correctness, acceptable cost and meaningful useful
coverage. Claim resistance improvement only when recovery/transfer effort rises
beyond ordinary runtime slowdown. If one generic projection removes a layer,
report that result; parameter fitting is not a new semantic obstacle.

RevGame is the main integration/performance gate, not a substitute for fixtures.
Zero meaningful coverage on a designated feature fixture is an eligibility
failure. Coverage limits on other programs must remain explicit.

| Milestone | Deliverable and exit requirement |
|---|---|
| M0 | RevGame provenance/workload locks, reproduced v04 parity/cost, generic inventory, frozen designated-chain ledger, production-presence checks and performance-gate tests. |
| M1 | W1 contexts and W2 persistent state across proved aggregate fields/private calls; independent transfer/lifetime checks, feature-off parity and forced rollback. |
| M2 | W4 exact-consumer continuity before W3 phase expansion; release-boundary audit, cross-phase correctness, bounded storage, cost and reuse assessment. |
| M3 | W5 bounded operation-group interpretation, opcode/region differential suite, retained-state contracts, measured selection and crossing inventory. |
| M4 | Optional W6 validation plus W7 integration; combined conformance, full-reference performance gates and ablations. |
| M5 | Immutable v05 RevGame cell, alternate workload checks, held-out family results and candidate-readiness report. |
| M6 | Separately authorized matched analyst evaluation and explicit protection-promotion decision. |

Proposed modules cover runtime contexts, phases, interpreter contracts and
performance gates; choose file names/CLI flags during implementation. Preserve
the existing integration mode and package a new
`revgame/c-noopt-nosym-static-sre-obf-max-v05` cell after validation.

Each report bundle contains source/toolchain/plugin/binary/replay/verifier
hashes; complete feature, compiler-seed, runtime-context and resource settings;
region eligibility/retained coverage/boundaries/rollback; correctness and private
all-egg verification; raw timings/statistics/gate outcomes/noise; and separate
analysis results with budgets, validation level, termination and first-success
evidence. Keep private recovery artifacts out of compiler commits.

**Candidate-ready** means supported contracts pass, the unchanged reference is
6/6-compatible, designated features have meaningful coverage and every required
performance cell passes strict 20x gates. Report the one-second target separately.
Revision 1 additionally requires the designated complete chains above; an
uncovered boundary cannot be waived by increasing arithmetic coverage elsewhere.
**Protection improved** additionally requires matched measured gains and held-out
transfer evidence. An interrupted agent or a larger, slower binary is insufficient.
