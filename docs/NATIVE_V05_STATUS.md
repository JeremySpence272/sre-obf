# v05 implementation status — 2026-09-22

The bounded persistent-buffer and selective-interpreter features are implemented.
The registered performance matrix passed all 30 blocks. This remains an experimental
candidate: completion of these features is not a demonstrated increase in
analysis resistance or completion of every stronger contract in the
[revision 1 plan](NATIVE_V05_PLAN.md).

One second is an ideal absolute target, **not a design or acceptance gate**.
Performance acceptance requires both the ratio of medians and the empirical
paired-ratio p95 to remain strictly below 20 times the matched clean runtime,
individually for every registered workload, compiler seed, and confirmation.

## Implemented contracts

| Component | Retained behavior and limits |
|---|---|
| Runtime context | One independent `getentropy` context at startup; no application RNG use or environment seed override. Entropy failure exits explicitly with status 78. Diagnostic fixed contexts are opt-in and excluded from release timing. |
| Persistent scalars | Closed private i8/i16/i32/i64 globals retain value/mask pairs across calls. Supported arithmetic, casts, selections, and equality operate on pairs; unsupported uses have reported scalar exits. |
| Persistent buffers | Closed private arrays of 2–64 integer cells, separate per-cell masks, represented initialization, element loads/stores, and full byte-array `memset` resets. Optional phases refresh representations on stores and resets. No complete canonical mirror is maintained. |
| Bounds and ownership | Direct whole-array or equivalent flattened element GEPs must preserve the original `inbounds` allocation contract. Defined original element accesses justify corresponding mask accesses; this is not a separate proof that all source executions are bounds-safe. Pointer escapes, unmodeled aliases, volatile/atomic source accesses, packed structures, partial resets, and unsupported aggregate operations are rejected. |
| Exact consumers | Bounded private producer inlining, statically bounded loop expansion, exact byte equality, and scratch-array elimination. General comparison ordering and volatile/escaping arrays are excluded. |
| Selective interpretation | Existing VM emitter and mandatory bytecode verifier; up to four private, address-unexposed, single-block pure i32/i64 functions, each 5–64 instructions and at most four arguments. Register values use per-slot rolling XOR representation. No anti-debugging, timing traps, nested interpretation, or broad VM presets. |
| Interpreter limits | Bytecode is not encrypted in this initial low-cost configuration. The shared engine includes unused general handlers and requires `libm`, already linked by RevGame. Native/VM arguments and results remain observable boundaries. |
| Budgets and rollback | Complete selected runtime objects are reserved; buffers take priority over scalar fragments. Runtime state and interpreter expansion have separate atomic transactions with post-lowering growth and LLVM verification. Forced rollback controls verify semantic restoration and absence of orphan support. |
| Performance | Frozen build/workload identities, clean and frozen v04 controls, rotating fresh-process samples, retained failures, resource limits, two confirmation blocks, and no averaging away a failed cell. |

Production selection contains no game or egg names. The observations below are
specific evaluation evidence, not compiler selection rules.

## Final RevGame builds

All three final builds use the same archived compiler plugin and matched O0,
stripped static-PIE clean binary. Each retains 16 runtime-owned objects, including
the 32-byte persistent buffer with 32 reads and its reset; 36 exact predicates
are reported. There are still **50 scalar exit uses**. These are partial
represented chains, not a claim of complete end-to-end protection.

The exact-consumer preparation removes both 32-byte stack arrays in the game
comparison. Later passes absorb that function, so the preparation report alone
does not prove every final machine-code observation boundary is closed.
The initial interpreter selector retains one seven-instruction private rotation
function in this application. Its coverage is narrow; handler size is not
counted as useful original work.

| Compiler seed | Directory | Protected SHA-256 |
|---|---|---|
| 1 | `out/revgame-v05-final-s1` | `0c8a99884df201b2808f3fd865204c947df5282d83db9a06e3e37832d766d781` |
| 2 | `out/revgame-v05-final-s2` | `2f8a6c100a31ce0cc91133b152bc611ea252b0329906b5dcf0ed8d68b452b3b0` |
| 3 | `out/revgame-v05-final-s3` | `e6039b10c260869a4a47eeee3911712288f93a1a1ee84ac92d69d854812cb1a2` |

The final feature-off build, `out/revgame-v05-final-off`, reproduces the frozen
v04 protected SHA-256 exactly:
`27917ff7b0e4936b892eeb9d63d2f6108ea48ad982927ede49d097e504be0b58`.
Final IR inspection found all 16 mask definitions and no inline assembly calls
or timing intrinsics in each seed. This is artifact inspection, not a complete
machine-code continuity audit.

## Validation evidence

- Full Python conformance suite: 564 tests, four existing skips; no failures.
- `out/v05-runtime-conformance-r6`: 18 compiler-seed/phase/context combinations,
  repeated fresh processes, persistent byte and wider arrays, nonzero initial
  values, resets, wraparound, explicit escapes, plus rollback, reservation,
  and entropy-failure controls.
- `out/v05-consumer-conformance-r3`: three seeds with the final compiler; valid equality, mismatch at
  every byte, and ordering/volatile negative controls.
- `out/v05-interpreter-conformance-r3`: nine interpreter/composition/rollback
  cases across three seeds. Covers signed widening, predicates, variable
  shifts, bounded division, arithmetic, and preserved pointer/FP boundaries.
- `out/revgame-v05-final-s{1,2,3}-check`: all 17 production parity cases passed
  for each seed, including all-egg replay and replay/live continuation.
- Final focused conformance: 21 tests passed; three additional v05 accounting
  tests reject zero retained coverage, invalid bounds/budgets, and unsupported claims.
- `out/v05-normalization-r1`: runtime, exact-consumer, and composed interpreter
  outputs remain identical after LLVM O2 normalization, across repeated processes.
  The normalized consumer input is byte-identical to the final compiler rerun.
- Matrix unit tests exercise all 30 scheduled blocks, failure retention,
  missing cells, changed artifacts, output mismatch, resource overruns, and
  successful acceptance above the one-second ideal target.

Historical failed development runs remain on disk; they are not acceptance
results. Their fixes are validated by the later directories named above.

## Registered performance experiment

Registration: `out/v05-final-registration-r1/registration.json`.
Results: `out/v05-final-performance-matrix-r1/summary.json`.

Five frozen workloads run at three compiler seeds, with two confirmations and
31 measured samples plus one warmup per arm: **30 blocks and 2,880 process
launches**, including clean, v04, and v05 arms. Each workload passes a clean-only
correctness preflight before registration. The matrix freezes expected output
and turn counts as well as replay hashes.

| Workload | Purpose | Consumed turns |
|---|---|---:|
| Reference all eggs | Full mixed replay | 14,012 |
| Reference deathless | Alternate long reference | 12,639 |
| Short mixed | First 1,024 actions; startup included | 1,019 |
| Alternate movement | Different application seed; recurrent movement | 2,048 |
| Long movement | Third application seed; concentrated repeated updates | 16,384 |

All 30 blocks passed, with no discarded failures. Every timed output matched
its frozen clean preflight, all registered resource gates passed, and the
measurement code and block hashes were verified and archived under `protocol/`.
`results.csv` contains all per-block metrics. Across the six blocks for each
workload (three seeds, two confirmations):

| Workload | Range of protected medians | Worst ratio of medians | Worst paired-ratio p95 |
|---|---:|---:|---:|
| reference-all-eggs | 0.698–0.992 s | 7.36x | 9.95x |
| reference-deathless | 0.598–0.909 s | 7.71x | 8.94x |
| short-mixed | 0.054–0.141 s | 9.69x | 13.27x |
| alternate-movement | 0.111–0.142 s | 4.81x | 5.70x |
| long-movement | 0.722–0.856 s | 5.13x | 6.28x |

The overall worst median ratio was **9.69x** and worst paired-ratio p95 was
**13.27x**. All protected medians were below one second in this experiment;
individual samples exceeded one second and were retained. The absolute target
was not used to reject a design or accept a failed ratio.

These are development workloads, not untouched analysis holdouts. Several old
conformance replays fail the production parser; those were retained as parity
rejection controls and were not used as supposedly substantive timings.

Registered limits: 16 MiB per binary, 512 MiB per-process peak RSS, 250,000 module
instructions, and the existing 600-second per-tool compile timeout. The timing
floor is 1 ms. Reports include full-process and CPU timing, peak RSS, text/binary
size, build command duration, toolchain identity, and raw samples. One second
has no effect on pass/fail.

Reproduce with fresh output directories:

```sh
python3 -m integrations.revgame.build --source SOURCE --out BUILD --revision v05 --seed 1
python3 -m integrations.revgame.check --build BUILD --out CHECK
python3 -m integrations.revgame.matrix register \
  --build BUILD_S1 --build BUILD_S2 --build BUILD_S3 \
  --previous FROZEN_V04 --out REGISTRATION
python3 -m integrations.revgame.matrix run \
  --registration REGISTRATION/registration.json --out MATRIX
```

## Remaining limits of the stronger plan

General field-sensitive structures, arbitrary private-call continuity, and
broader useful interpreter regions remain outside these initial contracts.
The matrix concentrates movement/update cost but does not attribute every
selected operation family in isolation. A final machine-code continuity audit,
untouched workload/fixture holdouts, and independent analysis-resistance
measurements are still required before promotion under the stronger plan.
No paid analyst evaluation or autonomous reverse-engineering run was launched.
