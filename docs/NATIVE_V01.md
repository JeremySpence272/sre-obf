# v01: recovery-guided native IR experiments

All additions are **opt-in**. The prior native max profile and per-TU compiler
adapter remain available. No VM, MC, post-link, environmental checks, anti-debug,
self-modification, executable unpacking, or model-directed text is added.

## Pipeline and boundaries

`python3 -m conformance.whole` compiles each application C source at the explicit
frontend O0/O2 level, links LLVM IR, optionally internalizes under `--closed-world`,
then applies the native pass once and codegens at O0. The clean arm shares the
same linked/prepared IR. There is no LTO or second production O2. The optional
post-O2 arm is an attack/conformance test, not the production pipeline.

Closed-world mode is an explicit API decision: only `main`, `--export` roots and
LLVM-preserved roots stay public. Do not enable it for a library, plugin, dlsym
target, external object callback, or foreign-runtime interface without declaring
all exports. Default mode does **not** silently internalize public data/functions.
Declarations resolved by llvm-link now become visible to existing call indirection.
External library declarations still retain their ABI and are not protected.

## Implemented experiments

| Flag | Implemented boundary | Limits / recovery avenue |
| --- | --- | --- |
| `native-fusion` | Inline bounded, non-address-taken private callees into callers; promote eligible private scalar allocas; protect the combined region | Eight calls/caller, 32/module, 500 instructions/callee, 2,000 combined. Recursion, EH, indirect/unsafe calls and exported callees are skipped. This deliberately overrides private noinline boundaries; not arbitrary function interleaving or synthesis. |
| `native-values-wide` + `native-values` | XOR shares across bitwise ops, constant shifts, casts, PHIs/selects, parallel-prefix add/sub | 8/16/32/64 bits, bounded nodes. Multiplication uses a **reported decode bridge**; comparisons, variable shifts and unsupported consumers remain boundaries. Original affine mode remains available. |
| `native-memory` | Two encoded per-activation lanes for closed scalar/fixed integer-array storage; refresh mask on each store; normalize bounded byte copies | Eight objects/function, 64/module, 64 elements/object; eight byte copies/function, up to 64 bytes each. Closed same-element inbounds GEP graphs are supported; reject escape, type-punning, atomics, volatility and unsupported users. Loads currently decode locally: this is not end-to-end memory/SSA representation fusion. |
| `native-invariant` + coupled values/state | Maintain witness `W = rol(H,7)*(H|1)+C`; inject `W-f(H)` into real encoded data and next-state semantics, update after both data and control writes | Relation is valid on reachable states, not arbitrary independent H/W. Per activation, no race/recursion-global state. The witness is transparent software redundancy, not cryptographic secrecy; invariant inference can recover it. |
| recovery replay | Identical bounded angr/Claripy adapter across seeds/programs, oracle entry only, symbolic inputs, no Unicorn/native target execution | ABI currently `uint32_t f(uint32_t,uint32_t)`. Initializers/unmodeled state are inconclusive. This is informed-entry formula extraction, not a full flag-solving agent or checker locator. |

Use `--fusion --memory --values --values-wide --coupled-state --invariant` with
the whole-IR driver for the combined experiment. Outlining remains independently
available but is off in this experiment: fusion should not automatically recreate
the same small helper boundary. `native-merge` and multistate flattening remain on.
Every stage has actual transformed/skipped coverage in `native.json`; enabled
flags alone are not a coverage claim. Defaults-off should retain prior codegen.

## Differential and transfer gates

```
python3 -m unittest conformance.test_conformance conformance.test_v01
python3 -m conformance.whole conformance/fixtures/whole_main.c \
  conformance/fixtures/whole_producer.c --out out/whole-example \
  --toolchain-image sre-obf-dev:llvm22 --optimization O0 --closed-world \
  --fusion --memory --values --values-wide --coupled-state --invariant
python3 -m conformance.whole_check out/whole-example \
  --toolchain-image sre-obf-dev:llvm22
```

`conformance.run` also exposes the new flags. Use edge/random vectors, multiple
seeds, `--threads`, `--post-o2-attack`, and `--require-ghidra`. The wide fixture
adds bitwise/cast/shift coverage; the two-TU fixture requires real call fusion and
an encoded eight-element mutable object, not just incidental helper protection.

`python3 -m conformance.recovery --tune <summary.json> --holdout <summary.json>
--analysis-image <image> --out <fresh-dir>` replays the same static adapter over
correctness-proven binaries. Supply multiple tuning summaries for flag ablations;
the source/seed grids must match. Selection ranks only completed supported
recoveries under binary-growth and trusted-runtime caps; it may select nothing.
Runtime measurements include batch process/container startup and are not precise
microbenchmarks; older reports without timing are ineligible for selection.
Held-out source/seed
pairs must be disjoint and are evaluated only after choosing the configuration.
Timeout, tool failure, missing entry, unmodeled state, or a failed clean positive
control **never counts as protection**. Scores are relative recovery cost, not
security guarantees. The expression artifact is a bounded SMT expression, not an
untrusted pickle. No paid model runs are launched by this workflow.

Still future work: typed memory/SSA representations with no per-load plaintext
boundary, multiple independent invariant families, larger safe cross-boundary
regions, richer ABI/initializer recovery adapters, end-to-end blind-entry agent
transfer studies, accurate workload-specific overhead measurements, and broader C++ ABI support.
MC/post-link ideas remain in `FUTURE_MACHINE_BINARY_IDEAS.md`.

## Validation recorded for this delivery

- 22 unit tests pass (including carry transfers, witness counterexamples and
  rejection of timeouts/missing overhead data by selection).
- `out/conformance/v01-wide`: three fixtures, two seeds, 593 vectors each,
  four-thread drivers; clean/control/native/post-O2 outputs agree. Ghidra was
  not requested there, so overall reports correctly say `partial`.
- `v01-affine`: two fixtures × 593 vectors verify invariant coupling with the
  older affine family independently of wide shares.
- `v01-edges`: duplicate-PHI predecessor edges, node caps 2/64 and flattening,
  593 vectors/configuration, all pass.
- `v01-whole-final`: max-profile O0 linked C, 593 vectors across clean/native/
  post-O2, with required real fusion and eight-element i8/i32 mutable objects.
- `v01-ghidra`: max wide fixture; all configured Ghidra decompiles succeed,
  clean/native/post-O2 remain different (normalized C 1,059 / 209,422 / 134,739
  bytes). `v01-final-codegen` reproduces the exact native and post-O2 binaries
  with the final plugin. Size/difference is survival evidence, **not** a
  hardness score or proof that individual transforms resist simplification.
- `v01-disabled` reproduces the prior `regions-disabled-final` arithmetic
  binary byte-for-byte with experiments off.
- `v01-recovery-transfer`: unchanged adapter recovers the deliberately easy
  tuning and held-out controls (different programs/seeds). This validates the
  machinery, not protection. On the initial values experiment it recovered
  clean in 2.49 s and hit the protected 10 s cap; no winner was selected.
- `out/v01-crackme-final`: both static, stripped O0 binaries pass 318 exact
  acceptance/rejection checks each. The clean binary is byte-identical to v0.
  The protected build fuses checker/transform into main, encodes the expected
  table and intermediate byte buffer, and has 34 wide nodes, 27 persistent edges,
  eight PHI pairs and two explicitly reported multiplication decode bridges.

The local harness versions are `/home/jeremy/obfuscation-harness/versions/v0`
and `v01`. The first v01 agent run completed on 2026-09-17: exact-match success
in 932.9 seconds (15m 32.9s), versus the historical v0 protected run's 713.5
seconds and clean run's 31.7 seconds. This is one instance/seed, not per-pass
attribution or evidence of general-purpose resistance. The agent summarized a
generated data decoder and irrelevant message work, then used constrained
path splitting during symbolic execution of main. See the [v02 plan](NATIVE_V02_PLAN.md)
for the resulting priorities. Private binaries/answers/transcripts stay outside
Git; reproducible sources, configuration and test code are committed.
