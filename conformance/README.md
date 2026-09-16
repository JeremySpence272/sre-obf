# Native IR conformance

This is a trusted build/test harness, not an attacker sandbox. Private output
contains source, IR, maps, seeds, and decompiler entry addresses. Never expose it
to a binary-only agent. Ghidra is deliberately given the target entry address:
this diagnostic measures normalization separately from discovery.

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

## Standalone crackme adapter

Use `python3 /absolute/path/sre-obf/conformance/cc.py` as the existing harness's
`--cc` command. Set `SRE_OBF_TOOLCHAIN_IMAGE=sre-obf-dev:llvm22`,
`SRE_OBF_PROFILE=max`, and `SRE_OBF_SEED=1`. Set `SRE_OBF_MULTISTATE=0` for the old
state representation with the other native settings unchanged. Profile `none` produces the matched
unobfuscated IR/backend control. The adapter supports separate C compile/link
commands, refuses LTO and non-O2 frontend settings, and never silently falls
back to an unobfuscated build. Sidecars and intermediate work stay beside
private objects; only the validated final binary belongs in the public bundle.

No paid-agent solve or general obfuscation-hardness claim is established by
these tests. The wider evaluation and remaining acceptance criteria are in
[the plan](../docs/STATIC_NATIVE_PLAN.md).
