# v02 plan: reduce reusable recovery shortcuts

Status: **implementation in progress**; see [the ledger](NATIVE_V02_STATUS.md)
for completed subsets and evidence. Written 2026-09-17 against v01 fork
`19300a007afd45a90c61ebd08036e9544a90f47e` (IR implementation `87eccf0`).
This is the next bounded implementation plan, not a claim of stronger protection.
It refines the [native roadmap](STATIC_NATIVE_PLAN.md) using the completed v01
solve and [v01's implementation limits](NATIVE_V01.md).

## 1. Objective and scope

Make a successful recovery script require more semantic reconstruction and
repair before it works on another protected region, seed, or program. Prioritize
representation boundaries and reusable summaries over additional block count.

All production changes belong in the **generic IR obfuscator**. Keep the crackme
source, validation algorithm, answer contract, and static-analysis rules unchanged.
No recognition of its function names, expected table, flag, password length, or
success strings is allowed in transformation selection. Other C fixtures test
generality; they are not replacements for the unchanged regression target.

The real acceptance target is **large, real-world programs across benchmark
families**, not this crackme. Small targets keep iteration inexpensive; they do
not establish scale or generality. Large-program build/correctness/coverage
checks are required milestones, and held-out large-program recovery is a
promotion gate, not an optional demonstration after declaring success.

Retain native multi-state flattening; no VM, MC transforms, post-link mutation,
custom calling convention, environment/hardware checks, anti-debugging,
self-modification, executable unpacking, prompt injection, or tokenizer tricks.
Ordinary linking and stripping stay unchanged. Do not modify `xollvm-work`.

Limits that remain true:

- Software-only encodings and their coefficients are recoverable, not secrets.
- A source program with independent checks remains mathematically separable
  after its representations are removed. We can raise recovery cost, not claim
  that encoding creates a different validation problem.
- Observable outputs, return values, library interfaces, and actual branch
  choices eventually expose information. Do not promise to hide every decision.
- Volatile storage can preserve code through LLVM; it does not make local
  memory opaque to an analyst. Extra expressions are not automatically harder.
- Angr, SMT, slicing, decompilation, model repair, and manual summaries remain
  allowed. Native target execution and concrete emulation as an oracle do not.

## 2. Evidence motivating this version

One target instance and one obfuscation seed; these are descriptive results,
not statistically established protection improvements or per-pass attribution.

| Historical arm | Exact-match result | Agent wall time |
| --- | --- | --- |
| Clean, static stripped O0 | Solved | 31.7 s |
| v0 native max | Solved | 713.5 s (11m 53.5s) |
| v01 native max plus experiments | Solved | 932.9 s (15m 32.9s) |

v01 closed the original direct checker/transform-call shortcut. The next attack
instead started symbolic execution at main and reconstructed just enough to
reach the success path. Its recorded commands and retained solver show:

1. Startup and output/return behavior still provided useful entry and exit anchors.
2. Constructor disassembly exposed target tables and their XOR initialization.
3. Message decryption was summarized away; message bytes were not needed to
   determine acceptance.
4. The generated expected-table decoder was replaced with a small parity-based
   byte formula. One summary covered repeated reads of that object. This was
   not evidence that every object in every binary shared the same decoder.
5. Splitting one conditional move into two correctly constrained successors
   made the remaining symbolic traversal much cheaper. It preserved both
   alternatives, rather than forcing acceptance.
6. The resulting input passed the independent exact-match grader. The agent
   did not need to recover and explain the entire original transform algorithm.

The audit found no evidence of native target execution; the observed workflow
used disassembly and symbolic interpretation with Unicorn disabled. The raw
run's compliance field is not retroactively changed by this planning document.
Exported tool traces/scripts, not unexported internal model reasoning, are the
evidence. Private traces and binaries remain in the local harness snapshot.

## 3. Selected work and priority

Difficulty is relative engineering scope, not a promised calendar estimate.
All new controls below are proposals, not currently accepted CLI options.

| Workstream | Priority / difficulty | Roadmap connection | What changes |
| --- | --- | --- | --- |
| P0: recovery regression and boundary inventory | First / medium | R5, F1–F3 evaluation | Reproduce and measure the actual shortcuts, including informed-entry controls. |
| P1: connected representation planning | Core / medium–high | R1/R4 architecture | Select whole supported dataflow regions, not the first N integer instructions. |
| P2: storage-to-consumer encoding continuity | Core / high | R1 + R4 + F2 | Join immutable data, mutable memory, and SSA without automatic per-load plaintext. |
| P3: encoded predicates and control handoff | Core / high | R1 + R2 | Extend regions through comparisons and Boolean uses into native state selection. |
| P4: regional families and real multi-output transfers | Core families; joint-output experiment / high | F1 + R1 + R3 | Reduce reuse of one operation/helper model across unrelated regions. |
| P5: generated-support closure and private-call continuity | Core closure; call experiment / medium–high | F3 + F2 + R3 | Remove exposed helper interfaces where safe; audit late helpers and initializers. |
| P6: operation-integrated activation relations | Gated experiment / high | R2 + R4 | Test useful relational state instead of stacking more known-zero witnesses. |

P0 runs throughout. Implement P1–P3 before expanding P4–P6. A working prototype
can ship as opt-in without demonstrating hardness; default promotion requires
the separate recovery and overhead gates below.

### P0. Turn the v01 solve into a reusable regression attack

Extend `conformance/recovery.py` and `recovery_probe.py`; keep the existing
two-integer ABI adapter as a small positive control, not the only evaluation.

- Preserve the exact old solver as an immutable private regression artifact.
  Do not load its pickle checkpoints on the host or use them as a portable format.
- Separate binary location from semantic recovery: record the effort to find
  entry/exit, tables, summaries, and useful branch predicates independently.
- Add a bounded main/argv or buffer/length adapter, explicit initializer
  modeling, and validated helper summaries. Unsupported initialization or
  calling conventions must produce an inconclusive result, not a win.
- Replay three levels: the exact script on its old binary; unchanged recovery
  logic with only locations supplied for new binaries; and binary-only discovery
  plus script repair. Address changes alone do not establish semantic resistance.
- Add independent conditional-select path splitting, state merging, local
  memory propagation, slicing, and summary-enabled arms. A slow default angr
  configuration is insufficient if a small valid modeling change removes the cost.
- Include a known-representation adapter using private compiler maps. This
  diagnostic deliberately grants the encoding model and measures the remaining
  work. Never expose those maps to the binary-only agent.
- Summary correctness needs supported bit-vector/effect equivalence checks
  where feasible. Overapproximating irrelevant outputs is a distinct analysis
  arm; validate independence and the final candidate separately. Unconstrained
  outputs must not silently become evidence of an exact semantic recovery.

Add a private boundary inventory to `native.json`: original and final coverage,
connected regions, memory/SSA edges, helper fan-out, predicates, representation
transfers, explicit plaintext exits and reasons, plus skipped/rolled-back sites.
Distinguish site counts from execution frequency. Report surviving coverage,
not only attempted rewrites or flag settings.

Acceptance: easy controls recover; the v01 summary/path-split approach is
reproduced or its modeling gap explicitly documented before attributing any
new failure to v02. Preserve successful formulas and repairs, not only timings.

### P1. Plan connected regions before lowering

Current `NativeRegions.cpp` chooses the first bounded supported nodes in
instruction order. `NativeMemory.cpp` runs afterward and reconstructs every
loaded scalar locally. Simply adding more passes cannot coordinate that boundary.

Introduce a common typed representation descriptor and a bounded planner shared
by values, memory, immutable data, predicates, and eligible generated helpers.
Descriptors identify width, family/version, lanes, phase/context, legal
transfers, effect requirements, and explicit boundary ownership.

- Discover connected supported producer/load/store/consumer graphs before
  expression expansion. Include PHIs, loop backedges and Boolean consumers.
- Rank eligible regions using generic criteria: supported connectivity,
  avoided boundaries, and proximity to branch predicates, returned values or
  observable stores. Tie-break through stable seeded origin IDs. Do not use
  challenge-specific annotations or a secret answer to select sites.
- Budget by estimated emitted cost and region closure as well as original node
  count. Prefer fewer coherent regions over arbitrary cuts through many regions.
- Retain independently selectable legacy planning and all v01 paths. Do not
  silently reinterpret the existing `native-value-nodes` option.
- Plan joins/conversions before mutating IR. Invalidate analysis and attribute
  promises correctly. Preflight budgets and make failure transactional, including
  module globals/helpers; reject a required-coverage build if rollback is unsafe.
- Scale through bounded per-function/region work and conservative call/object
  summaries, not whole-program symbolic reasoning inside the compiler. Bound
  graph size, planner time and memory, and distribute module budgets fairly
  across eligible functions instead of exhausting them in module order.
- Inventory all application definitions, including unselected and unsupported
  ones. Large/complex functions, escaping memory, indirect calls and unsupported
  ABI constructs must remain visible in coverage denominators. Do not improve
  apparent coverage by excluding the parts that matter to real programs.

Initial scope remains fixed-width i8/i16/i32/i64 and closed C regions. Boolean
representations are introduced explicitly in P3, not squeezed into an i8
descriptor without a defined invariant. No arbitrary pointer or C++ ABI expansion.

Acceptance: selection covers producer → local object → useful consumer on
multiple fixtures; deterministic seeds reproduce the plan and binary; adding
an unrelated function does not perturb unrelated origin-based family streams.

### P2. Carry representations across data and memory

Unify the planned portions of `NativeEncoding.cpp`, `NativeMemory.cpp`, and
`NativeRegions.cpp` instead of emitting a decoded scalar between their passes.

- Immutable arrays: deliver encoded values directly into supported consumer
  regions. Specialize or inline small access transfers into those regions so
  a common scalar-returning decoder is not mandatory.
- Mutable locals: store and load the region's lanes directly; perform a
  representation-to-representation conversion when descriptors differ. Keep
  unsupported/escaping consumers as explicit, counted decode boundaries.
- Support same-element closed scalar/fixed arrays and already supported bounded
  byte copies first. Preserve alias, bounds, alignment and lifetime requirements;
  do not extend to atomics, externally volatile objects, type-punning or escaping
  pointers in this milestone.
- Attach representation phase to a planned region/object and establish valid
  joins. Start with static edge conversions and per-store refresh; only add
  data-dependent phase selection after the simpler ownership model is verified.
- Never refresh an entire partially initialized array by reading uninitialized
  elements. Do not introduce speculative loads, new faults, allocation or I/O.
- Within fully supported paths, there must be no implicit scalar decode just
  because a value crosses an alloca or an immutable-table reader.

This does not prevent static evaluation of immutable data: its contents are
still present in recoverable software form. The test is whether recovering that
data/accessor also provides a drop-in summary for its consumers elsewhere.

Acceptance: full-output fixtures prove memory/SSA continuity, including loop
joins, partial initialization and repeated stores. Reports require zero implicit
per-load decode boundaries inside designated supported test regions. Binary
and decompiler checks must confirm that this is not only an IR-level property.

### P3. Keep comparison operands and Boolean uses inside regions

Current comparisons are plaintext exits from value encoding. Extend the common
representation model through useful decisions, then coordinate lowering with
`Flattening.cpp`.

- Begin with equality/inequality and their Boolean combinations, selects and
  PHIs. Evaluate the relation in encoded coordinates; do not decode both full
  operands merely to recreate the original scalar comparison.
- Carry an explicit encoded Boolean representation through supported uses.
  Integrate its consumption with successor-token construction where profitable.
- Add signed/unsigned ordered comparisons as a separately tested subfeature
  using verified carry/borrow/sign relations. Width, truncation and signedness
  must be explicit; no undefined shifts or overflow assumptions.
- Preserve source short-circuiting and side-effect order. Do not merge early
  checks by reading later inputs that the original execution never accessed.
  Pure, already-evaluated Boolean subgraphs may be regrouped only with a proof
  that their observable behavior and definedness are preserved.
- Count remaining decoded operands, Boolean exits and unavoidable ABI/output
  boundaries separately. There will still be an eventual branch/output choice;
  this is not a promise of branch-free or constraint-free analysis.

Acceptance: equality and signedness edge fixtures, PHI joins, short-circuit and
fault-sensitive access guards pass. Evaluate with BOTH default symbolic
execution and explicit select/path splitting. If splitting still removes most
of the cost, record that result and do not call branchless shape a protection.

### P4. Regional diversity and bounded joint-output experiments

Reusing the same XOR-coordinate algebra everywhere invites one reusable
normalizer. Parameter changes alone are insufficient evidence of diversity.

Core deliverable:

- Extend the existing family registry with operation/effect contracts shared
  by P1–P3. Start with the existing XOR-oriented and modular-affine families,
  adding verified direct transfers only where the operation is supported.
- Choose families per coherent region, not randomly per instruction. Select
  representation-to-representation conversions with no intermediate scalar
  decode where verified and affordable; otherwise report the bridge honestly.
- Target avoidable multiplication bridges through bounded arithmetic regions
  and verified transfers. Do not expand every multiply into a large Boolean
  circuit merely to satisfy a zero-bridge counter.
- Measure effective families after local-memory, compiler and decompiler
  normalization. Collapse equivalent forms in the diversity report. Two forms
  becoming one means one effective family, not a successful two-family result.

Separate R3 experiment:

- Select small pure regions with two or more genuinely used outputs and lower
  joint output representations and transfers back to ordinary native IR.
- Prefer existing producer/consumer connectivity. Merely returning two
  independently transformed scalars or combining an output with a constant-zero
  checksum does not satisfy this experiment's joint-dependency claim.
- Bound interfaces initially to six scalar inputs, four outputs and sixteen
  original operations; emitted-cost caps still apply. No interpreter or dynamic
  opcode dispatch is introduced. These are starting limits, not coverage claims.
- Run an adversarial inverse/normalization control: a simple invertible final
  mixing layer may disappear immediately. Do not promote it for looking dense.

Acceptance: operation and conversion equivalence is checked; normalized family
counts and unchanged/repair-required summary transfer are measured across
programs and seeds. A universal representation recovery remains a valid attack.

### P5. Close generated-helper and initialization gaps

Current helpers are hardened late with a bounded profile, but most do not
participate in the application's persistent value/memory encoding. Their scalar
interfaces can remain convenient summary points.

- Register generated helpers early by identity, origin, role and effect. Give
  eligible small support routines a chance to join P1–P4 before their caller's
  region boundaries are fixed. Do not recreate them automatically via outlining.
- For bounded private direct-call edges that cannot be fused, experiment with
  internal encoded-argument/result interfaces. Preserve exported ABI, address
  identity, varargs, exception and musttail exclusions. This is IR type/signature
  transformation, not custom register conventions.
- Retain per-activation ownership; recursion, callbacks and threads must not
  share a mutable global encoding context. Unsupported edges decode explicitly.
- Audit helpers created by later passes using a finite worklist and generation
  budget. Every relevant helper is protected, absorbed, or explicitly exempted.
- Audit call-table initialization and recovery. Diversify use/initialization
  transfers only if cheap recovery tests justify it. Do not claim that extra
  XOR layers conceal target references or final addresses from static analysis.
- Give initializers only state that exists before their first legal use.
  Preserve constructor ordering and reentrancy; do not introduce unsafe lazy
  initialization or cycles among decoder prerequisites.

Do not spend v02's main budget strengthening message-only AES work. An analyst
may safely summarize work outside the acceptance slice. Protection must cover
the meaningful producer/consumer path even with irrelevant output work removed.

Acceptance: informed helper-entry and constructor-table recovery arms run;
late-helper coverage has no unexplained gaps; private-call tests cover multiple
callers, recursion/reentry and threads. Direct target references remain a stated
IR-only limitation, even when the call-table bytes are encoded.

### P6. Integrate activation relations into useful transfers

The v01 witness is a maintained relation with a zero residual. It is not evidence
that a solver must recover a difficult invariant before following valid states.

Prototype a small set of alternative per-activation relations only after P2–P4:

- Let the representation of real data and the native dispatch context evolve
  together. Implement useful operations and phase transfers over that relation,
  not just independent identity noise attached afterward.
- Verify entry, updates, joins, loop backedges and recursive activations.
  Unsupported combinations fall back visibly; never rely on poison or a
  runtime/environment check to make the invariant hold.
- Test with the relation supplied to the attacker as well as inferred. Track
  whether knowing it unlocks all sites. Give invariant inference and local
  symbolic propagation their own recovery arms.
- Keep only candidates with a cost/transfer benefit over P2–P4 and the existing
  witness. New invariant families are optional, not a prerequisite for v02 core.

This is a bounded R2/R4 experiment, not cryptographic opacity or a LOKI-equivalent
implementation. Do not report a known-zero checksum as a new real source dependency.

## 4. Pipeline and proposed configuration

Use LLVM 22.1.8 and the explicit whole-IR driver. Historical regression builds
remain O0 frontend, O0 backend, static stripped ELF with the same link settings.
Also test a separate matched O2-frontend lane for representative optimized
input. Do not mix these timings or insert a production post-obfuscation O2.

```text
matched C frontend (explicit O0 or O2) -> link application IR
  -> explicit closed-world preparation when authorized
  -> bounded private-call fusion and module preparation/helper registration
  -> connected representation planning: values, data, memory, predicates
  -> verified regional transfers and optional joint outputs/activation relations
  -> native multi-state flattening with predicate/state handoff
  -> remaining native passes and bounded late-helper processing
  -> final coverage, budgets and verification -> backend O0 -> ordinary link/strip
```

This requires an orchestration refactor, not a blind reorder of old passes.
Generated call-table helpers appearing late must have an explicit handling path.
Capture stage IR so a later legacy pass cannot silently reopen an earlier
boundary or consume the entire budget before required protection runs.

Proposed independent controls, all defaults-off until implemented and tested:

| Proposed control | Role |
| --- | --- |
| `native-region-plan=connected` | New planner; keep a legacy selection mode. |
| `native-memory-ssa` | P2 continuous data/memory/SSA representations. |
| `native-predicate-regions` | P3 comparison/Boolean regions and state handoff. |
| `native-regional-families` | P4 coherent regional selection and conversions. |
| `native-joint-outputs` | Optional bounded R3 joint-output experiment. |
| `native-support-regions` | P5 generated-helper absorption and closure. |
| `native-private-encoded-calls` | Optional P5 private encoded interfaces. |
| `native-relation-family` | Optional P6 relation ablation; preserve v01 mode. |

The candidate **v02 core** uses the v01 native max/whole-IR setup plus P1–P3,
regional families and support-region closure. Outlining remains off by default.
Joint outputs, private encoded calls and new relations are separately measured
additions. Do not enable every experimental flag just because the preset says
max. Record resolved flags, dependencies, budgets and actual coverage per build.

## 5. Differential conformance and evaluation

### Correctness gate, before recovery scoring

- Keep clean and protected inputs identical. Check full outputs of integer,
  array and control fixtures, not only the crackme's largely rejecting inputs.
- Exhaust small bit-width models; use bit-vector equivalence checks for each
  supported transfer/conversion/predicate family, retaining assumptions and
  proof results. Validate emitted LLVM behavior separately: a formula proof is
  not a proof of a complete compiler pass.
- Include i8/i16/i32/i64 edge cases, signed comparisons, carries/borrows,
  truncation/extensions, PHI duplicate predecessors, loops, partial memory
  initialization, access guards, nested GEPs, bounded copies, recursion,
  constructors, private-call multiple callers and four-thread execution.
- Run LLVM verification after meaningful stages; use sanitizer-friendly
  correctness fixtures where supported. Never regard sanitizer/tool failure as
  obfuscation. Preserve original memory/call attributes only when still valid.
- Test at least three deterministic obfuscation seeds per development fixture
  in the full suite, both frontend lanes, and experiments-off compatibility.

### Survival and recovery are different gates

Save shared IR, stage IR, assembly, relocations, ELF, Ghidra C/p-code and reports.
Compare clean, v01, v02 feature-alone/cumulative/leave-one-out arms. Keep a
separate post-O2 normalization attack arm; it is not the production artifact.

- Compiler survival: require the intended representation and consumer coverage
  to reach machine code; check for reopened or duplicated plaintext boundaries.
- Decompiler survival: inspect normalized semantics, not only differing C
  hashes, line counts, function counts or timeouts. Exercise local memory
  propagation and known-representation simplification as independent controls.
- Actual recovery: check exact answers or complete supported formulas. Report
  discovered targets, reusable summaries, recovered predicates, repair edits,
  solved regions and cost. Different assembly does not prove different recovery.

An extra compiler that we do not build with is a later portability check, not
a requirement to implement a second compiler plugin in v02.

### Cheap loop first, transfer checks second

1. Per edit: relevant equivalence/unit tests, small full-output differentials,
   one fixed-seed crackme build, assembly/coverage checks and bounded attacks.
   No automatic paid-agent run.
2. Per milestone: three development seeds and a small suite spanning arithmetic,
   mutable arrays, parser/control predicates, constructors/private calls and
   multi-output regions. Run Ghidra and matched feature ablations here.
   Also run full-size build/correctness/coverage checks from the scale suite
   below; do not postpone discovering compiler or coverage limits until release.
3. Before candidate selection: freeze recovery adapters, a bounded configuration
   grid and overhead caps. Screen at 10 seconds per kernel attack, confirm at
   60 seconds; larger target attacks get separately recorded fixed budgets.
4. Holdout: at least two untouched source families and two new obfuscation seeds
   per family. Change programs as well as seeds. Calibrate clean solvability
   independently; do not let source/answer/maps leak into the attack context.
5. Then run fresh-context exact-match agent trials on paired new instances and
   the unchanged historical regression. The old instance is explicitly a
   regression, not a blind holdout. Keep model/config/tools/prompt/budgets fixed
   across paired arms and retain workspaces. Larger RevDeflate/RevGame-like
   targets are required promotion tests, not the per-edit default. At least one
   held-out recovery task must involve a full-size application, not only an
   extracted kernel or a small checker embedded in a large executable.

Use single-feature/cumulative screening first, then leave-one-out tests for the
shortlist; do not run an exponential flag matrix on every edit. An attack timeout
is a right-censored measurement, not infinity or a proven defense. Tool errors,
unsupported models and failed clean controls are inconclusive. Do not select a
winner using those failures; report when the comparison cannot establish one.

### Required large-codebase and anti-overfitting gates

Maintain two separate suites, because compiling a large binary and resisting
recovery of its meaningful computation test different things:

1. **Scale/conformance suite:** pin at least three unmodified real C projects
   with different structures. Initial candidates are SQLite (large parser and
   stateful execution), zstd (arithmetic, tables and specialized hot loops), and
   jq (pointer-rich heap data and branch-heavy parsing). Confirm availability,
   licenses and reproducible workload support before locking the corpus; these
   are planned candidates, not projects already built by this harness. Use
   upstream tests plus deterministic representative workloads, matched clean/
   protected builds and explicit application/dependency boundaries. Keep their
   source logic unchanged and do not insert the crackme into them.
2. **Recovery-transfer suite:** use source-backed targets from at least two
   distinct held-out Revbench families, including a full-size real application
   and a task whose useful path differs from bytewise password validation.
   Preserve their existing task and grading contracts. If the required sources
   or valid matched clean controls are unavailable, state that the generality
   gate is unmet; do not substitute a padded crackme and claim it passed.

Separate development and holdout by project/family, not by filenames, flags,
input passwords or seeds alone. Hold back source families before tuning. If an
agent's held-out solve is used to modify the obfuscator, move that case into the
development set and obtain a new holdout for the next claim. Preserve a common
attacker tool portfolio; do not win by removing tools that solved the small case.

Report for each whole program:

- Total, eligible, selected and finally protected application functions, IR
  operations and objects, plus skipped/rolled-back counts by reason. Include
  both function-count and instruction-weighted views so many trivial functions
  cannot mask unprotected large bodies. Exclude linked runtime code explicitly,
  not silently, and report generated support separately.
- Connected memory/value/predicate coverage and remaining boundaries across
  actual application paths, not only compiler-created decoder helpers. Where
  trusted workload coverage is available, label it separately from static counts.
- Multi-TU boundaries, indirect/recursive calls, escaping data and initializer
  coverage. A successful conservative skip is correct behavior, but not protection.
- Compile wall time/peak memory, linked and protected text size, workload runtime
  and correctness. The current three-word candidate dispatcher can have linear
  per-transition search cost; explicitly test large CFGs rather than multiplying
  small-crackme timings by code size.

Freeze workload-specific required coverage and resource bounds before tuning.
Do not pick one universal coverage percentage without a baseline inventory;
record the denominator and the useful paths required by each task. A program
that compiles but protects only a small easy subset fails broad-coverage
promotion. Keep larger-program budgets separately calibrated and recorded;
raising them merely to hide an asymptotic problem is not a successful gate.

Feature inclusion must be justified by recovery or coverage benefits across
multiple families. No crackme-specific matcher, preferred function name,
eight-byte assumption or answer-dependent rewrite may enter the obfuscator.
The fixed crackme remains useful for regressions even if it keeps being solved.

### Resource gates

Preserve existing absolute compiler/module limits unless explicitly revised.
Initial additional screening caps: at most 1.5x protected application text and
2x trusted workload execution time relative to matched v01, while also reporting
both ratios against clean. These are proposed engineering budgets, not measured
v02 results; calibrate and freeze them before candidate selection. A v01 build
that fails on a large project is a recorded baseline limitation, not a missing
denominator to ignore: use explicit clean-relative bounds for that lane and do
not publish an invalid v01-relative ratio.

Static libc can hide application growth in total ELF size. Record protected
application text, generated support, whole ELF size, compiler wall time/peak
memory and execution overhead separately. Use trusted in-process repeated-work
measurements; existing container-startup-inclusive timings remain labeled and
must not become precise runtime claims. If comparable timing is missing, a
candidate is ineligible for overhead-gated promotion.

## 6. Work order, commits and version retention

Implement in meaningful reviewable commits, not one commit per tiny family:

1. P0 regression adapters and boundary reports; record v01 attack/control results.
2. P1 shared planner/descriptors plus P2 memory/data continuity and correctness.
3. P3 predicates/control handoff plus split/merge recovery tests.
4. P4 regional families and P5 helper closure, with independent ablations.
5. Optional joint-output/private-call/P6 prototypes; keep unsuccessful variants
   opt-in or defer them with evidence rather than holding up the core candidate.
6. Freeze v02 configuration, run transfer/resource gates, then package an agent
   trial only when requested. Publish results including solves and regressions.

Commit author and committer remain repository owner `jeremyspence272`. Push fork
commits to its existing origin; the separate local harness has no configured
remote. Do not include private answers, build maps or agent artifacts in Git.

Reserve `/home/jeremy/obfuscation-harness/versions/v02/` for this plan and future
artifacts. Do not overwrite v0/v01, change their sealed binaries, or relabel a
development build as a completed v02 release. Each frozen v02 artifact set needs
its own source/plugin/toolchain hashes, commands, flags/seeds, clean/protected
binaries, conformance/recovery data, configuration-selection record and checksums.
For each agent run retain prompt, launch configuration, transcript/tool logs,
submission, full workspace and exact-match/time/token results. Exported reasoning
is retained if supplied; do not imply access to unexported internal reasoning.

## 7. Deferred deliberately

| Item | v02 disposition |
| --- | --- |
| Stronger cryptographic/proof-erased opaque predicates (R6 / original #2) | Defer: known-input hash evaluation is easy; unsatisfiable does not mean difficult. Prioritize observed boundaries. |
| Semantic mimicry and idiom transplant (#11/#16), lying data (#4) | Defer: removable output work did not protect acceptance in this solve; corpus complexity is not the best first return. |
| Unrestricted cross-function fragmentation (#13), global distributed state (#7) | Defer: bounded fusion and private interfaces first; ABI, lifetimes and concurrency make arbitrary interleaving much larger work. |
| General e-graph/evolutionary synthesis (#15) | Bounded verified family/configuration selection only; no large synthesis engine or model-training-distribution objective. |
| General nonlinear multiplication, variable shifts, division, vectors, FP, arbitrary C++ ABI | Extend only by measured coverage need and independent correctness; unsupported boundaries remain visible. |
| More CFF/fake cases/MBA/message crypto as the main lever | Retain existing ingredients and cost-match them; additional volume is not the principal v02 feature. |
| All MC/post-link work (#18–26), VM and excluded environment/model-directed tricks | Unchanged exclusions/backlog in [FUTURE_MACHINE_BINARY_IDEAS.md](FUTURE_MACHINE_BINARY_IDEAS.md). |

Definition of success: a correct, reproducible, measured IR-only candidate with
fewer cheaply reusable summaries and boundaries across multiple real program
families, with required large-codebase correctness and coverage demonstrated.
The crackme alone cannot satisfy this definition. Implementation completion,
compiler/decompiler survival, and increased
recovery cost are three separate outcomes and must be reported separately.
