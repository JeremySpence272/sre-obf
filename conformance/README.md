# Native IR conformance

This is a trusted build/test harness, not an attacker sandbox. Private output
contains source, IR, maps, seeds, and decompiler entry addresses. Never expose it
to a binary-only agent. Ghidra is deliberately given the target entry address:
this diagnostic measures normalization separately from discovery.

## What the test groups prove

Conformance separates correctness, retained coverage, normalization survival,
recovery cost and generalization. Passing one does not establish the others.

| Group | Main entry points | Question answered |
|---|---|---|
| Representation mathematics | `*_model.py`, `connected_proof.py` | Do the bounded integer transfer, conversion and state laws preserve values? |
| Actual emitted expressions | `bundle_lift.py`, `bundle_control_proof.py` | Does a supported emitted IR slice agree with its independent specification? |
| Basic compiler integration | `run.py`, `whole.py` | Do matched clean and protected builds produce the same complete outputs? |
| Persistent values and loops | `bundle_run.py`, `bundle_loop_run.py`, `value_edges.py` | Are values preserved across updates, PHIs, zero-trip loops, joins and exits? |
| Mutable and immutable storage | `tile_run.py`, `immutable_run.py` | Are initialization, indexed accesses, updates, tails and phase changes correct? |
| Private interfaces | `recursive_run.py`, call-bundle report gates | Do arguments/results remain correct across callers, recursion and per-activation state? |
| Safe fallback | `*_controls.py`, `rollback.py` | Are unsupported shapes refused, and do failed transactions restore valid code? |
| Compiler normalization | `--post-o2-attack`, saved assembly | What remains after a second, explicitly experimental stock-O2 simplification pass? |
| Decompiler normalization | Ghidra integration, `bundle_decompile.py` | What C/p-code does the matched stripped binary produce at the supplied entry? |
| Semantic recovery | `extract_supplied.py`, `extract_discovery.py`, `relation_recovery.py` | Can a particular recovery method find and validate a simpler semantic description? |
| Honest accounting | `*_check.py`, `test_*.py`, `compare.py` | Are coverage, losses, boundaries, resource caps and reproducibility reported consistently? |
| Scale and holdouts | `scale.py`, `scale_stage.py`, `prepare_holdouts.py` | Does the compiler preserve unchanged real workloads at fixed costs, and are holdout contracts frozen? |

Threaded/reentrant checks live in the relevant differential runners, not a
separate claim that all possible interleavings were proved. Finite runtime
corpora do not prove whole-program equivalence. Solver unknown, unsupported
lifting, missing requested tools and tool crashes are not protection wins.
Decompiler size and assembly differences are diagnostics, not hardness scores.
Known-descriptor inverses are expected to succeed; supplied and discovered
interfaces must not be conflated. Live-agent evaluation is a separate acceptance
layer with its own binary-only artifacts, policy and matched resource budget.

## Build this fork

```sh
docker build -t sre-obf-dev:llvm22 conformance/toolchain
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -w /work sre-obf-dev:llvm22 \
  cmake -S . -B build -G Ninja -DLLVM_DIR=/usr/lib/llvm-22/lib/cmake/llvm \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -w /work sre-obf-dev:llvm22 cmake --build build -j4
```

Initial tested toolchain: stock LLVM 22.1.8 (`ca7933e47d3a`), Ubuntu 24.04.
The Docker recipe pins the exact LLVM package version; the Ubuntu/development
dependencies are not a hermetic lock. Retain the built image by digest. If the
upstream apt mirror stops retaining that version, reuse the retained image or
explicitly select and revalidate a replacement; never silently upgrade. Runs
record actual image IDs, compiler
versions, plugin hashes, commands, time limits, outputs, and return codes.
Do not substitute an existing prebuilt xollvm image for this fork's plugin.

## Differential gates

```sh
python3 -m unittest conformance.test_conformance -v
python3 -m conformance.run --out out/conformance/run-001 \
  --toolchain-image sre-obf-dev:llvm22 --seed 1 --seed 2
```

For decompiler gates also supply `--ghidra-image IMAGE` containing
`/opt/ghidra/support/analyzeHeadless`, or `--ghidra /path/to/analyzeHeadless`,
and `--require-ghidra`. Initial integration uses Ghidra 12.0.3 / Java 21.
Missing Ghidra is **partial**, not evidence that obfuscation survived it.
Decompiler errors are inconclusive, never successful protection.

Each fixture starts with shared `clang -O2` IR. Clean and obfuscated arms use
the same backend and PIE link settings, with no second `-O2`. Both execute 81
edge pairs plus 128 deterministic random pairs by default; complete output and
the expected output count must match. Arithmetic and recursion/state require flattening to have
actually changed the function. One-block fixtures explicitly lack that
requirement. All runtime execution belongs to trusted correctness testing.

An ordinary source `clang -O2` release arm is also checked, so backend/wrapper
differences cannot be mistaken for obfuscation. Correctness precedes optional
decompilation. Use `--no-diversity`, `--no-data`, `--no-helpers`, `--no-late`
for F1–F3 ablations; `--family 0..3` forces a representation family. `--passes`
filters application passes, while feature/helper flags remain independent.
The widths fixture requires all four supported array widths to be encoded.
Module string encoding and function merging are enabled by default; use
`--no-strings` and `--no-merge` for their ablations. The merging fixture requires
actual flattening of each merged group, not just of an unrelated function.

Relational flattening is enabled in the native preset. `--no-multistate` restores
the old scalar-state mode, and `--state-family 0/1/2` forces a state family (`3`
is seeded). The `state` fixture exercises non-tail recursion, multiple callers
of one protected callee, loops and joins. `--threads` uses four concurrent
callers with ordered full-output comparison (at most 4096 vectors). This is
trusted conformance execution, not dynamic analysis available to the attacker.

`--post-o2-attack` adds an explicitly separate normalization arm: stock LLVM
`default<O2>` runs on protected IR, then that arm is compiled, differentially
checked and optionally decompiled too. It never changes the production build
order. Retain this as a cheap simplification attack, not a substitute for
Ghidra/symbolic recovery. All requested arms must preserve output.

The state-model unit tests include modular inverse recovery for all three
families. That control is expected to succeed: keys are available software
state, not unavailable secrets. Ghidra exports operation counts and variable-
operand multiplication counts as retention diagnostics, not resistance scores.
Inside the toolchain image, `python3 -m conformance.flattening_flags --out
out/conformance/flags-001` additionally tests the annotated flattening pass in
isolation: legacy/new state, all three state families, and `hybrid=0/1`, with
unrelated protections disabled and full-output comparison.

`--probe-helpers 2` additionally decompiles up to two distinct generated-helper
roles at known entry addresses. It uses private symbols from an unstripped
intermediate, but Ghidra still receives the stripped final binary. A missing or
failed requested helper probe cannot count as successful normalization survival.
Private local-label retention can change the GNU linker build ID even when
assembly is identical. Compare exact final artifacts from the same diagnostic
configuration; do not silently treat those different hashes as identical.

Assembly, relocations, stripped ELF, Ghidra C and high-pcode counts are saved.
The literal positive control must be recovered by Ghidra; the deliberately
foldable negative control must simplify. `--require-literal-hiding` additionally
requires the declared literal probes to disappear from assembly and decompiled
C. A missing literal does not establish resistance to static evaluation or SMT.
Pseudocode length and normalized hashes are diagnostics, not hardness scores.

Compare saved runs with `python3 -m conformance.compare LEFT/summary.json
RIGHT/summary.json`. Add `--require-identical-binaries` and/or
`--require-identical-ir` for reproducibility gates. Comparisons reject missing
cases, incorrect builds and mismatched source. Missing decompiler measurements
remain null, never "equal" evidence.

`--profile max` is the default bounded high-intensity native candidate.
`--profile smoke` is a separately labeled faster integration profile.
`--passes flattening,constenc` requests an explicit pass ablation. VM, injected
assembly and timing reads are prohibited by the native entry point.

## Further IR experiments

For the manifest-pinned large runner, `--scale-budget --scale-structure`
reserves usable CFF transactions before distributing expression budgets.
`--scale-budget` alone retains the uniform-allocation control. Use explicit
`--require-flattening` and/or `--require-memory` to fail zero-coverage builds;
`--post-o2-attack` adds stock optimization and workload comparison. The report
distinguishes input memory operations, eligible closed-object edges and selected
edges. Passing a nonzero gate is not broad source coverage or hardness promotion.

`python3 -m conformance.rollback --out out/rollback-001 --toolchain-image
sre-obf-dev:llvm22` forces repeated budget rollback on a computed-goto function
with a global jump table and recursive calls. Three seeds, 593 full-output
vectors and the stock-O2 normalization arm must pass. The IR check also rejects
the `inttoptr(1)` table corruption that previously crashed unchanged Lua. Use
`--plugin PATH` to replay a retained historical compiler as a negative control.

`python3 -m conformance.scale_stage --spec MANIFEST --ir STAGE.ll --out OUT
--toolchain-image IMAGE` runs the independently specified workloads against a
retained IR stage without changing the production artifact. This diagnostic
retains private symbols and links dynamic libc. Tool failures remain failures,
never evidence of resistance. This is stage isolation, not sanitizer coverage.

`--values` enables persistent paired integer SSA representations; `--outline`
enables bounded native pure-region outlining. They are independent and opt-in.
`--coupled-state` additionally ties data masks to per-call flattening state and
requires `--values` plus multi-state flattening. `--value-nodes 2..64` controls
per-function value coverage (default 24). For example:

```sh
python3 -m conformance.run --out out/conformance/experiments-001 \
  --toolchain-image sre-obf-dev:llvm22 --profile max --case values \
  --values --outline --coupled-state --threads --post-o2-attack
```

The `values` fixture requires i8/i16/i32/i64 coverage, paired loop PHIs, and
multiple real outputs from an outlined region. Coupling requires surviving
updates from both data and control. Missing requested coverage fails the run.
Inside the pinned image, `python3 -m conformance.value_edges --out
out/conformance/value-edges-001` tests duplicate switch-predecessor PHIs under
partial/full value coverage and combined flattening.

See [the design and limits](../docs/NATIVE_VALUE_REGIONS.md). Enabled experiments
are not a claim of measured agent resistance; known-representation inverse
recovery is deliberately tested as a successful control.

## Standalone crackme adapter

Use `python3 /absolute/path/sre-obf/conformance/cc.py` as the existing harness's
`--cc` command. Set `SRE_OBF_TOOLCHAIN_IMAGE=sre-obf-dev:llvm22`,
`SRE_OBF_PROFILE=max`, and `SRE_OBF_SEED=1`. Set `SRE_OBF_MULTISTATE=0` for the old
state representation with the other native settings unchanged. Profile `none` produces the matched
unobfuscated IR/backend control. The adapter supports separate C compile/link
commands, refuses LTO and frontend settings other than O0/O2, and never silently falls
back to an unobfuscated build. Sidecars and intermediate work stay beside
private objects; only the validated final binary belongs in the public bundle.
Set `SRE_OBF_VALUES=1`, `SRE_OBF_OUTLINE=1` and optionally
`SRE_OBF_COUPLED_STATE=1` to enable the same experiments in crackme builds.

O2 remains the default. An explicit `-O0` selects a no-opt experiment: both
protected and control frontend commands disable only the `optnone` attribute so
explicit transformations can run. No optimization pipeline is added, and the
backend remains at its default O0. Object sidecars record these settings. The
[Revbench crackmes integration](../integrations/revbench_crackmes/README.md) builds
the matched stripped/static O0 pair, installs its exact-match grader and prompt,
and retains private compiler provenance separately from agent-visible assets.

## Locked evaluation matrix and coverage accounting

`conformance/corpora.lock.json` fixes the programs, seeds and resource limits
later milestones are measured against, as data rather than as arguments spread
through commands. `python3 -m conformance.scale --corpus zlib --purpose
regression --seed 3` takes the module cap, compile timeout, container limits
and permitted seed set from the lock and records the lock revision and hash in
the result. `--high-cap` selects the separately labelled 1.5M-instruction
experiment; it never rewrites a primary-cap comparison. The lock also names the
build flags a comparable scale run requires — currently `--scale-budget`, since
without bounded growth allocation unchanged zlib passes 2.2M instructions where
the retained v03 evidence stayed under 1.5M. A locked run that omits them is
refused rather than silently switched on: a defaults-off flag stays off.

The lock enforces the split rather than describing it. zlib, Lua and SQLite are
`scale-regression`: they already influenced this work and cannot be relabelled
held out. bzip2 and cJSON are `holdout`: they refuse every purpose but
`holdout`, require their frozen IO-manifest hashes, and have only clean-contract
preparation evidence so far (see the chronology below). Seeds 1/3/4 are regression, 11/13/17 promotion,
23/29/31 holdout, and the three sets are disjoint. Another seed of the same
program is not a held-out program.

Scale coverage is reported as several views at once, never one number.
`source_ledger` puts every source-owned function into exactly one disposition —
encoded, rolled back, planner-skipped, not planned, not selected, absorbed
before selection, or unaccounted — weighted both by count and by input
instructions, crediting a merged origin at the function that owns its body. A
function no pass touched is a bucket, not an absence. `coverage_views` reports
stage-mixed operation ratios beside cost- and source-weighted coverage; on SQLite
those differ by two orders of magnitude, which is the point. `loss_ledger`
keeps selection loss and growth rollback apart and closes the identity
`eligible = selected + skipped + shard-lost + rolled-back`. `cap_ledger` keeps
the module, per-function, per-region, per-shard and per-object caps distinct;
published object leaf/depth caps are read from current reports and stay null
for older reports without those fields. `support_charge` charges each generated helper once at its
owning symbol, so a helper called from forty functions is one charge.

`--require-accounting` fails a run whose cost identity does not close or whose
source denominator is unknown, with status `accounting-failure` or
`accounting-unknown`. Unknown exits non-zero instead of passing by omission.

No paid-agent solve or general obfuscation-hardness claim is established by
these tests. The wider evaluation and remaining acceptance criteria are in
[the plan](../docs/STATIC_NATIVE_PLAN.md).

## v04 checkpoint validation

The v04 work includes infrastructure, offline family research and experimental
bounded representation lowerings, not a completed or promoted protection preset. The active delivery
criteria are in [the v04 plan](../docs/NATIVE_V04_PLAN.md).

```sh
python3 -m unittest discover -s conformance -p 'test_*.py'
python3 -m conformance.review_v04 --out out/FRESH-v04-review \
  --toolchain-image sre-obf-dev:llvm22
```

The latter archives its plugin and inputs, checks that observing the typed plan
does not change emitted IR, exercises merge/call arbitration and an explicit
non-interface owner, and compares full outputs before/after an O2 attack. Its
aggregate case deliberately uses O0 to retain stack objects; that is not an O2
memory-coverage result. `conformance.test_review_v04` also contains four real
solver checks: run it inside the pinned analysis image. Hosts without Claripy
skip those four explicitly; they do not count as passed proofs.

Typed-plan format 2 preserves operand and bundle-member identities. Its graph is
**pre-connected-lowering**, not frontend-source IR: earlier transforms may have
inserted instructions. Useful-work depth is a deterministic cycle-cut DFS
estimate, not an exact longest path. Rolled-back plans retain attempted graph
and boundary records and label them as attempted. Input source counts are a
separate inventory; stage-mixed ratios are diagnostics, not instruction-level
source coverage. Encoded-call renames preserve function ownership, while fusion
removals retain explicit provenance and unknown body coverage.

Both recovery adapters use `recovery_grammar.py` and the symbolic models in
`extract_phases.py`. Constructed samples propose a model; only a complete
declared-domain enumeration or an equivalence proof validates it. Partial
lookup domains, unresolved guard variables, incomplete returns, solver unknowns
and missing clean summaries cannot be promoted to protection. The discovery
probe currently assumes two 32-bit System V scalar arguments; it does not infer
callee signatures. Supplied byte-buffer controls have different phase/ABI
coverage, so their times are not a matched comparison with that scalar probe.
Cross-region sample agreement remains unverified transfer evidence.

The offline family catalogue cannot mark anything `ready_to_lower`: its sampled
screens can nominate `screened_for_proof` candidates only. Mask-independence SMT
checks do not prove the sampled bijection or a cheap inverse. The known-parameter
reference decoder is a threat-model control, not an implemented binary constant
extractor. No compiler, decompiler, scale or agent hardness follows from those
reference-model checks.

Fixture and whole-program runners expose `--plan`, `--call-policy` (requires
`--encoded-calls`) and `--semantic-budget 0..50`; scale exposes them on its
connected `v02` base variant as explicit v04 experiments. Locked scale runs also
check upstream revision/archive identity; a held-out workload needs a frozen
manifest hash before it can run. Scale-regression manifests retain their own
recorded hashes rather than claiming the lock pins their entire source tree.

### Native bundles and frozen holdout contracts

The experimental descriptor-driven bundle emitter, supported scope, flags and
exact checkpoint evidence are documented in
[`NATIVE_BUNDLE_V1.md`](../docs/NATIVE_BUNDLE_V1.md). It does not complete v04.

`bundle_loop_run` adds the narrow joint-recurrence matrix and explicit unsupported
shape controls. `--bundle-loops` and `--bundle-phases` also round-trip through the
fixture/whole/scale drivers. The phase arm and static-phase ablation share the
same representation family. Complete byte input pairs at two iterations are
optional; zero/one/many iterations, all-width edges, full two-word outputs,
reentry, concurrent calls and post-O2 checks are always part of the loop fixture.
`bundle_decompile --loop` exports matched stripped informed-entry controls;
successful export does not establish semantic recovery or protection strength.

The v2 loop contract adds dominated multi-block/multi-backedge header joins and
edge-specific input mappings. `--bundle-loop-boundaries` explicitly permits and
accounts for scalar header projections; it is off by default and requires loops.
`test_bundle_joins` checks path choices, exposure accounting and negative reports.
The loop compiler runner includes earlier-region binding replacement, outside
PHI uses, actual early exits and negative CFG shapes; these are still correctness
and coverage controls, not demonstrated resistance to semantic recovery.

`--bundle-control` additionally binds the actual recurrence storage to native
dispatch. `bundle_loop_run --control-ablation` keeps flattening in the off arm;
`bundle_control_proof` validates supported emitted key/salt slices. See
[`NATIVE_BUNDLE_CONTROL_V1.md`](../docs/NATIVE_BUNDLE_CONTROL_V1.md) for ownership,
coverage, normalization controls and the successful supplied-relation inverse.

`--bundle-predicates` consumes selected two-to-four-output equality reductions
directly from a joint tuple. `predicate_run` retains matched off/O2 arms, exact
positives and safe-exclusion controls; `bundle_loop_run --shapes predicate-exit`
can combine it with recurrence phases and control binding. See
[`NATIVE_BUNDLE_PREDICATES_V1.md`](../docs/NATIVE_BUNDLE_PREDICATES_V1.md).
Large-program gates are temporarily deferred for development per
[`V04_DEFERRED_SCALE.md`](../docs/V04_DEFERRED_SCALE.md); their results are not
silently promoted to passing.

Corpus-lock revision `m0-3` freezes bzip2/cJSON IO manifests under ignored
`out/v04-frozen-holdouts-20260918/`. Existing seeds and resource caps are unchanged.
Only unobfuscated reference programs were built during preparation; their
outputs were checked against independent Python bz2/JSON expectations. No
protected holdout or candidate-ranking measurement was performed. This freeze
occurred after the first experimental bundle emitter, not before its authoring;
the chronology is explicit rather than retroactively relabelled M0 evidence.

`python3 -m conformance.prepare_holdouts --out FRESH --bzip2-archive ARCHIVE
--cjson-archive ARCHIVE --toolchain-image sre-obf-dev:llvm22` verifies the pinned
archives, preserves upstream source/header hashes and prepares clean contracts.
It never updates the corpus lock automatically. Moving or regenerating a
manifest changes its hash because source roots are bound into the manifest;
record a deliberate lock revision instead of silently accepting a new hash.
Neither holdout is authorized for tuning by this preparation step.
