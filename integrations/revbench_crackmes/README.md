# Revbench crackmes integration

This small control family measures exact password recovery, not reimplementation
of a large application. It uses the existing standalone C crackme: a reversible
eight-byte check with no intended baseline cryptographic difficulty. Do not expose
this operator README, generator, sibling builds, private manifests, or seeds to an
agent. Use fresh independent agent contexts for the two cells (they share a flag).

Cells:

- `crackmes/c-noopt-nosym-static`: matched unobfuscated control.
- `crackmes/c-noopt-nosym-static-sre-obf-max`: native max IR preset, multi-state
  flattening, persistent values, outlining and local data/control coupling enabled.

Both compile the same two C translation units with Clang 22 `-O0 -g0 -fno-pie`,
link with `-static -no-pie -s -Wl,--build-id=none`, and use no LTO or post-obfuscation
optimization pipeline. The adapter disables Clang's `optnone` attribute in BOTH
arms so explicit transformation passes can run; this is not enabling optimization.
The backend runs at Clang's default O0. The toolchain's prebuilt static libc is
identical in both arms, not rebuilt at O0 or passed through the obfuscator. No VM,
packer, MC transform, post-link obfuscation, license service, or environment check
is used. Ordinary linker stripping is the only post-link readability operation.

The fork's normal adapter default remains **source O2 → obfuscation → backend**.
This explicit noopt experiment does not replace that production/default pipeline.
Enabled passes can skip unsupported sites; inspect private actual coverage rather
than assuming every experimental feature transformed this small O0 input.

## Install and build

From the `sre-obf` checkout (with `build/Obfuscator.so` and the local LLVM image):

```sh
python3 integrations/revbench_crackmes/install.py /path/to/revbench-revX
python3 integrations/revbench_crackmes/build.py \
  --revbench /path/to/revbench-revX \
  --harness /path/to/obfuscation-harness \
  --out out/revbench-crackmes-001
```

The installer checks a narrow versioned harness patch, refuses incompatible files,
and is idempotent. `--check` is read-only. The builder refuses existing destination
cells and retains all diagnostics under a new private output directory. To rebuild
the same instance into a different Revbench distribution, pass `--instance-file`
pointing at the previous private `instance.json`; otherwise a fresh random instance
is created and shared by the pair. Never disclose the instance seed: it derives
the flag. Keep generated binaries/answers out of the obfuscator's Git repository.

Builder gates include original 12 semantic checks per binary, additional paired
bit-mutation/random/length tests, matching frontend IR (apart from source paths),
source/header/toolchain identity, final three-word CFF coverage, no plaintext flag,
ELF64 x86-64, no interpreter/needed shared libraries, and no symbol/debug sections.
Private `eval/build-manifest.json` records flags, hashes, source revision/status,
coverage, and build environment; `eval/build/` retains source, IR and compiler logs.
These are finite correctness/retention checks, not an agent-hardness measurement.

## Verify and run

Inside Revbench:

```sh
python3 harness/harness.py --list-binaries
python3 harness/harness.py crackmes/c-noopt-nosym-static --verify
python3 harness/harness.py crackmes/c-noopt-nosym-static-sre-obf-max --verify
python3 -m pytest tests/test_crackmes.py tests/test_schemas.py -q
python3 harness/harness.py crackmes/c-noopt-nosym-static-sre-obf-max \
  --tier tier2 --agent codex --max-steps 200 --no-internet
```

The same standard tool/step/agent options work for the clean cell. No paid agent
run is launched by installation, build, tests, or `--verify`.

The prompt truthfully describes an owner-authorized, synthetic benchmark with no
real credentials, external target, or malicious operation. This provides context;
it does not guarantee how any provider's safety checks will classify a run.

## Grader and isolation

Submission is `/workspace/submission/flag.txt`: the eight ASCII password characters,
without a wrapper, with at most one trailing LF. `crackmes_exact` in
`harness/crackmes.py` returns score/max **0/1 or 1/1**, unlike older 0–6 families.
It compares bytes against private `eval/flag.txt`, never executes a submission or
target, rejects symlinks/hard links/nonregular/oversized files, and does not echo
the flag. Missing/inconsistent operator assets are infrastructure errors.
`eval/submission/flag.txt` is the private positive control used by `--verify`.

Workspace construction allowlists only `binary` and `prompt.md`; the agent's
challenge is additionally bind-mounted read-only. There is no grader endpoint or
private reference mounted into the agent container. A changed agent copy cannot
change grading, which validates the operator artifact's recorded hash.

Static-recovery-v2 prohibits target execution/concrete target emulation while
allowing lifting, symbolic execution, SMT, taint and recovered-algorithm scripts.
This is a **prompt-and-trace-audit policy**, not a technically enforced execution
sandbox: even a read-only/noexec binary can be copied or emulated. A correct flag
does not prove compliance. Reports explicitly retain `static_only_compliance:
unverified`; audit traces separately before counting a result as a static solve.
Tier 2 exposes static tools; tier 3 availability never overrides the task policy.

## Versioning

The local Revbench distribution has no Git metadata/remote. Therefore this
directory versions its minimal wiring patch, grader, tests, prompt and rebuild
recipe in `sre-obf`; generated challenges and private truth stay in Revbench.
No remote for Revbench or the standalone harness is created implicitly.
