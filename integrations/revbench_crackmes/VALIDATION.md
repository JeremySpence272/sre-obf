# Local acceptance, 2026-09-16

Installed into `/home/jeremy/revbench-revX/binaries/crackmes/`. Trusted build
diagnostics are retained privately at `out/revbench-crackmes-o0-static-001/`
and each installed cell's `eval/` directory. No agent run was purchased/launched.

| Cell | Bytes | SHA-256 |
| --- | ---: | --- |
| `c-noopt-nosym-static` | 714848 | `c1b34cd1b0cf352a1a585e388831156bf0d6f9890a9e50f603f670a6eda4300a` |
| `c-noopt-nosym-static-sre-obf-max` | 900424 | `b9c70a58d33803dfffd70d1fdfaeb2bf231b330c7fb528ed601e29f9cbbecc63` |

Both are non-PIE x86-64 ELF64, statically linked, stripped, with no symbol/debug
sections or dynamic interpreter/dependencies. Both use the same C source,
instance, compiler image, O0 frontend and O0 backend, and static linker flags.
The frontend IR matches apart from source paths. The 12 original semantic cases
and 318 additional accepted/mutated/random/length cases pass for EACH binary.

The native preset actually leaves three-word CFF in `main`, `check_password`,
`transform`, and several generated helpers. `transform` retains eight encoded
i32 nodes with one persistent edge; the final IR has eight data context updates
and sixteen control context updates. Outlining is enabled but **skips all original
functions** (`no-bounded-pure-region`) for this O0 input; it is not counted as
protection. No VM or injected assembly is reported. These are coverage diagnostics,
not measurements of decompiler difficulty or agent resistance.

Passed: 18 fork conformance unit tests; all 24 crackmes tests; both actual CLI
`--verify` positive controls (1/1); challenge discovery. The final combined
crackmes/schema selection passed 41 tests and 2845 subtests. Fresh installation
and idempotent reinstallation matched the local integration byte-for-byte. An
offline real-container smoke test confirmed the public-only, read-only challenge
mount and writable submission mailbox without executing the target.
The schema/runtime/image-tag regression selection had 25 passes and 2843 subtest
passes, with one unrelated existing failure:
`test_revmalware_prompt_explains_strict_five_case_matrix` expects wording absent
from the unchanged malware prompt. No malware files were edited for this task.

The exact-answer grader does not establish static-only compliance. That remains
explicitly unverified pending trace review. The integration does not claim a new
technical execution sandbox or any agent solve/fail result.
