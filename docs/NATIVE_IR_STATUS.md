# Native IR implementation status

The working path is source → stock Clang 22.1.8 `-O2` → this fork's explicit
native opt pass → backend without a second `-O2` → PIE link. VM, MC/post-link
changes, injected assembly and timing reads are not enabled by this entry point.
The legacy automatic Clang hook and legacy VM presets remain separate.

## Further implemented IR experiments

[Persistent values, native regions and coupling](NATIVE_VALUE_REGIONS.md) are
now implemented as independent opt-in experiments:

- `native-values=1`: two-lane modular integer representations carried through
  add/sub/mul/constant-shift computations and paired PHI/select joins; widths
  8/16/32/64, explicit conversion boundaries and per-function node caps.
- `native-outline=1`: bounded 3–8-instruction pure regions, up to six inputs/four
  outputs, ordinary ABI, generated-helper provenance and existing hardening.
  This is not unrestricted fragmentation or general multi-output synthesis.
- `native-coupled-state=1`: optional per-activation data/control context shared
  with multi-state flattening. Requires values and multi-state; final IR must
  retain both data and control updates for the dedicated fixture's gate.

No missing approval or MC dependency blocked this work. The experiments can be
enabled now; agent resistance has not been demonstrated, so they are not
silently added to the existing default preset.

Validation in this round:

- Seventeen conformance unit tests, including exact-width transfer/inverse and
  coupled-round model controls. The inverse controls deliberately succeed.
- Uncoupled and coupled maximum matrices: ten fixtures × two seeds × 593
  vectors each (11,860 cases per matrix), against both clean build arms.
- Values-only and outlining-only ablations: three fixtures × 593 vectors each,
  four threads and stock-O2 normalization. Coupled smoke: three fixtures × two
  seeds × 593 vectors, also threaded and normalized.
- A hand-written LLVM duplicate-predecessor fixture passes with partial value
  coverage, full coverage, and full coverage plus flattening.
- Ghidra target, normalized-target and outlined-helper probes complete for
  uncoupled and coupled maximum candidates. This is retention/tool coverage,
  not a successful anti-agent benchmark.
- The real crackme with all three flags passes twelve semantic checks.
- With experiments disabled, arithmetic and state fixtures reproduce the
  previous milestone's exact protected IR and stripped binaries.

Retained reports: `out/conformance/regions-max`, `regions-coupled-max`,
`regions-values-only`, `regions-outline-only`, `regions-coupled-smoke`,
`regions-edges`, `regions-ghidra` and `regions-coupled-ghidra`.
The separate harness bundle is `out/native-regions-coupled/public/`.

Cost warning: on maximum seed 1 for the dedicated `values` fixture, the
uncoupled experimental binary is 190,664 bytes versus 14,384 bytes for clean
controls; stock O2 reduces it to 157,856 bytes. This comparison includes the
entire native preset, not solely these two passes. Ghidra variable-multiply
counts change from 188 to 64 after extra O2 (clean: 9); operation counts are
not recovery scores. Boundaries and recoverable coefficients remain important
targets for static simplification. Phase-changing objects, new predicate
generators, search/corpus machinery and generalized interprocedural state are
still pending engineering/research, not secretly implemented by these flags.

## IR-only expansion: first milestone

The [full source audit and technique ledger](IR_HARDENING_AUDIT.md) records what
exists, what this milestone changes, and what remains unimplemented. MC and
post-link/LIEF stay in the backlog.

- Native flattening now requests per-activation three-word state, with two
  evolving masks and encoded candidate comparisons instead of centrally
  decoding a scalar switch selector. Three seeded/forceable families, explicit
  legacy-state ablation, final-IR storage coverage. This is not cross-function
  global state, general application-data encoding or a claim of irreversibility.
- The previously ignored `hybrid` flattening flag now controls dispatcher count.
- Fixed shared encrypted-call-table keys being incorrectly derived per caller,
  which the new recursion/multiple-caller fixture exposed as an invalid call.
- Added four-thread and recursive differential execution; inverse-recovery
  model controls; Ghidra operation metrics; and an optional fourth arm that
  subjects protected IR to stock O2 before compiling/decompiling it. Private
  assembler labels are retained for informed helper probes and stripped from
  the final agent binary.

Verified during this expansion:

- Maximum preset: nine fixtures × two seeds × 593 vectors = 10,674 cases,
  compared against both ordinary source-O2 and matched optimized-IR controls.
- Every state family: arithmetic and recursion, seed 17, 593 vectors, four
  concurrent callers; six configurations. Legacy-state ablation: three
  fixtures × two seeds × 593 vectors. All correctness/coverage gates pass.
- Stock-O2 normalization attack: arithmetic, recursion and data, maximum seed
  1, 593 vectors; all four execution arms agree.
- The actual standalone maximum-preset crackme passes twelve semantic checks.
- Fourteen conformance unit tests and eleven standalone-harness regressions.
- Eight isolated annotated-pass configurations (hybrid on/off, old state and
  every new family), 593 vectors each, pass structure and correctness checks.
- Ghidra 12.0.3 successfully decompiles the state target, a call-forwarder helper
  and the stock-O2-normalized target. The target matches the final matrix's
  exact stripped binary. Data target/decoder probes and old-state target
  controls also pass; the data run predates private-label retention, which
  changes only the link build ID in the checked binary, not IR or assembly.
- Repeated final-pipeline state/data builds reproduce protected IR and stripped
  binaries in different directories.

These correctness-only runs are labelled `partial` because they do not run
Ghidra. Retained reports: `out/conformance/multistate-max`,
`multistate-family-{0,1,2}`, `multistate-off`, and `multistate-o2-attack`.
The finalized pipeline's full matrix is `multistate-final`; isolated flags are
in `multistate-flags-final`; successful state/normalized/helper probes are in
`multistate-ghidra-verified`. The earlier `multistate-initial` caught the call-key
miscompile, and `multistate-ghidra` records a failed state helper-map gate; these
failed runs are retained for diagnosis, not counted as successful protection.
The new public crackme bundle is the separate harness's
`out/native-multistate/public/`. Agent recovery/repair cost remains unmeasured;
candidate scanning introduces O(block-count) worst-case transition overhead.

Measured warning: for maximum seed 1 on the state fixture, the old-state binary
is 27,600 bytes and the new-state binary 31,656 bytes. Stock O2 reduces the latter
to 23,464 bytes. Ghidra reports 8 variable-operand multiplications before that
normalization and 3 after (clean control: 0). This is partial retention plus
substantial simplification, not a proof that the state representation resisted
semantic recovery. No decompiler-hash/operation-count threshold is presented as
an anti-agent success gate.

## Implemented first pass

- F1: a shared, versioned family registry used by OpaqueUtils consumers,
  including constant materialization and eligible flattening expressions.
  Independent seed namespaces select families and coefficients. Original,
  helper and late stages use distinct site namespaces. Each factory is bounded
  to 64 new sites; module-wide emission is bounded to 4,096. Beyond the bound,
  legacy representations remain and the report records that fallback.
- F2: immutable encoded backing for non-escaping private integer arrays at
  i8/i16/i32/i64, including indexed/repeated and constructor-time reads. Each
  object has its own decoder and index-dependent keys. Plaintext load-range
  facts are removed when reads become encoded. Escaping, partial, atomic,
  volatile, external and unsupported accesses are skipped with reasons. A
  separate late constant sweep processes at most 16 sites per selected function.
- F3: generated functions are discovered by identity, assigned explicit roles,
  inventoried, and processed once with a bounded helper profile. This includes
  the new data decoders and upstream indirect-call initializers/thunks. The
  helper profile cannot recursively generate more call-table or VM helpers.
  At most 256 generated helpers and 250,000 module instructions are allowed.
- Module preparation: AES string encoding and bounded internal function merging
  run once before the array inventory. Merged application groups inherit the
  native profile and required flattening. Cipher helpers join the bounded F3
  worklist. Call helpers report explicit origin/role and direct function/global
  dependencies. Modules without eligible strings do not acquire a cipher runtime.

These are initial mechanisms, not completed resistance research. Registered
family counts are **emission counts**, including possible rollback artifacts;
they are not a claim of four effective decompiler-resistant families.

| Registry v1 family | Stored encoding | Recovery operation |
|---|---|---|
| xor-shares | `E = C xor K` | xor |
| add-shares | `E = C + K` | modular subtraction |
| rotate-xor | `E = rotl(C xor K, r)` | rotate-right then xor |
| odd-multiply-add | `E = C * a + K`, odd `a` | subtract, multiply by modular inverse |

All operations have exact unsigned bit-vector semantics. Rotation counts stay
strictly between zero and width. No `nsw`/`nuw` claims are introduced. Scalar
shares occupy compiler-owned writable storage but are never modified; array
backing is immutable. The keys are recoverable coefficients, not secrets.
These simple families can be statically decoded. The next evaluation is whether
a recovered script transfers unchanged, then whether relational/fused designs
from the roadmap materially increase repair cost at matched resource budgets.

## Differential conformance

[Commands and artifact layout](../conformance/README.md).

The runner saves release, matched optimized-IR, and protected builds, checks
full output against both controls, requires actual target flattening where
eligible, and records Ghidra C/high-pcode output. Ghidra receives the entry
address intentionally; this separates discovery from normalization. Literal
recovery and deliberately foldable positive/negative controls calibrate the
probe. A decompiler error is inconclusive; absent Ghidra is partial.

Verified during initial development:

- Ten conformance unit tests and eleven standalone-harness regression tests.
- Six fixtures × two seeds × 593 vectors for both smoke and maximum profiles.
- Final integrated maximum profile: eight fixtures × two seeds × 593 vectors
  (9,488 cases), each compared against both release and matched-IR controls.
- Six leave-one-feature-out smoke matrices across data, widths, strings and
  merging: 24 configurations, 209 vectors each; all correctness/coverage gates pass.
- Every forced family on signed/narrow/wide array and scalar fixtures, including
  constructor reads; 593 vectors per fixture. Legacy-family late-anchor ablation.
- Actual maximum-profile crackme build, with twelve trusted semantic checks.
- Maximum-profile Ghidra literal and array probes pass the explicit compiler/
  decompiler literal-hiding gate; the foldable negative control also passes.
- Integrated data/string target probes and directly identified decoder/cipher
  helper probes all decompile successfully. This verifies that the probes work,
  not that those helpers resist semantic recovery. The final build reproduces
  the exact binaries used for those successful decompiler checks.
- Same-seed literal and data fixtures reproduce byte-identical protected IR
  and final binaries in different output directories. A matched clean crackme
  control is built from the same private instance and also passes twelve checks.

Local retained reports (private, ignored by Git):

- `out/conformance/final-verified/summary.json`: integrated maximum correctness.
- `out/conformance/final-helper-ghidra/summary.json`: data/string/helper probes.
- `out/conformance/final-controls-ghidra/summary.json`: literal/negative controls.
- `out/conformance/ablation-no-*/summary.json`: leave-one-feature-out checks.

The separate harness's `out/native-final/public/` is the validated final crackme
bundle; `out/native-control/public/` is its matched unobfuscated instance.
Only public bundles may be copied into an attacker workspace.

Two regressions were caught and fixed: LLVM 22 narrow APInts require explicit
truncation of random 64-bit values; a late opaque anchor must not reuse storage
before its initialization. The width matrix and no-diversity ablation retain
coverage of both. Finite differential tests are not an equivalence proof.

## Remaining acceptance work / limitations

- Effective family diversity through decompilation and bulk recovery-script
  transfer are not established by visible-literal probes or C fingerprints.
- No paid-agent baseline/attack loop or secure static-only agent sandbox is
  configured. The standalone runner records protocol v2, but enforcement and
  trace auditing belong to the eventual launcher.
- Original immutable-array handling is conservative; pointers exposed to real
  APIs, initializer dependency graphs and generated data need further coverage.
- Module string handling follows upstream eligibility restrictions, including
  exclusions for format strings and address-sensitive uses. It is not universal
  protection of all strings or arbitrary data exposed to external APIs.
- Helper processing is reported separately from required pass effectiveness.
  Function budgets can skip later passes; inspect reports instead of treating
  a profile name or binary growth as full coverage. Function rollback does not
  transactionally remove module globals created by the rolled-back pass.
- Seed/site IDs are stable for fixed pipeline inputs. They are not promised to
  remain unchanged when upstream transformations change the site sequence.
- Call-target references in constructors and ELF relocations remain legitimate
  static recovery clues. No IR-only claim of removing all such clues is made.

Future machine/binary ideas are kept in
[their separate document](FUTURE_MACHINE_BINARY_IDEAS.md).
