# Native IR implementation status

The working path is source → stock Clang 22.1.8 `-O2` → this fork's explicit
native opt pass → backend without a second `-O2` → PIE link. VM, MC/post-link
changes, injected assembly and timing reads are not enabled by this entry point.
The legacy automatic Clang hook and legacy VM presets remain separate.

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

- Eight conformance unit tests and eleven standalone-harness regression tests.
- Six fixtures × two seeds × 593 vectors for both smoke and maximum profiles.
- Every forced family on signed/narrow/wide array and scalar fixtures, including
  constructor reads; 593 vectors per fixture. Legacy-family late-anchor ablation.
- Actual maximum-profile crackme build, with twelve trusted semantic checks.
- Maximum-profile Ghidra literal and array probes pass the explicit compiler/
  decompiler literal-hiding gate; the foldable negative control also passes.
- Same-seed literal and data fixtures reproduce byte-identical protected IR
  and final binaries in different output directories. A matched clean crackme
  control is built from the same private instance and also passes twelve checks.

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
- The plan's module-wide string encryption and bounded function merging are not
  yet enabled by the initial native profile. Existing implementations remain
  available separately; their helper/cache integration needs its own validation.
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
