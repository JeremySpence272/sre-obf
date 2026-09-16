# Future machine-code and post-link ideas

Status: deferred research/engineering backlog, not implementation scope.
Written 2026-09-16. The active work is
[STATIC_NATIVE_PLAN.md](STATIC_NATIVE_PLAN.md): native flattening, F1-F3, and
follow-on IR research. VM remains excluded from that plan.

## Entry conditions

Do not build these layers merely to have coverage of every compilation stage.
Revisit a feature when:

1. A reproducible recovery attack survives the IR configuration.
2. Stage-level artifacts identify a specific leak or normalization step.
3. A bounded machine/post-link change plausibly addresses that observation.
4. Correctness, portability, unwind/ABI, performance, and evaluation costs are
   explicitly budgeted.

All future features retain the same policy: no environment/hardware/timing
checks, anti-debugging, runtime gating, self-modifying code, executable-code
decryption, or prompt manipulation. Normal integer instruction semantics and
runtime decoding of data are different from those excluded mechanisms.

## Machine-level candidates

| Candidate | Useful trigger | Approach and constraints | Priority |
|---|---|---|---|
| Instruction-selection diversity | Distinct IR families repeatedly become the same machine idiom. | Target-aware machine rewrites with accurate flags, implicit operands, register liveness, and memory effects; compare after decompiler normalization. | First machine candidate if measured. |
| Carry/condition-flag dataflow | Native arithmetic remains trivially recoverable in registers/pseudocode. | Verified local computations using carry chains, conditional moves, or flag-dependent arithmetic. Avoid undefined flags and preserve exact dependencies. | Research after instruction diversity. |
| Internal calling-convention variation | Calling interfaces remain the main reliable decomposition boundary. | Matched caller/callee lowering for controlled internal groups. Preserve external ABI, stack alignment, unwind, callbacks, and platform protections. | Expensive; defer. |
| Junk-byte gadgets | A relevant analyzer has a reproducible boundary/discovery weakness. | Evaluate existing x86 gadgets independently first; carefully bounded unreachable regions with valid entry paths. | Supporting experiment only. |
| Alignment/padding diversity | Existing attacks rely on byte signatures or fixed offsets. | Seeded layout changes with budgets and normalized-view comparisons. | Cheap support, not semantic protection. |
| Prologue variation | Function discovery, rather than semantics, is the measured bottleneck. | Measure normal discovery versus analysis with known entry addresses. Preserve stack and unwind requirements. | Low: optimized code already varies. |

### Integration design

The current project is an out-of-tree LLVM obfuscation extension, not a complete
backend fork. Establish a supported hook or explicitly budget maintaining a
pinned backend modification before promising MachineFunction features.

Prefer transformations while the information needed for correctness exists:

- Before register allocation, account for new virtual registers and pressure.
- After register allocation, account for physical-register liveness, scavenging,
  spills, flags, and unwind effects.
- At MC emission, use byte/layout control only where semantic rewriting no
  longer requires missing control-flow/liveness/type information.

An MCStreamer wrapper is not a drop-in substitute for a machine optimization
pass. Pin target, CPU features, ABI, LLVM revision, assembler, and linker.
Test relevant CET/CFI, shadow-stack, or pointer-authentication compatibility
where those features are actually in scope; do not disable them silently.

## Post-link candidates

| Candidate | Useful trigger | Approach and constraints | Priority |
|---|---|---|---|
| Internal pointer/dispatch table patching | Targets remain exposed in IR-generated constructors or relocation metadata. | Have the compiler reserve explicit patch regions and emit a private contract. Patch only supported internal targets after final layout; design for PIE/ASLR and relocation handling. | First post-link candidate if measured. |
| Final-address-dependent encoding diversity | Different logical tables still normalize to one direct pointer representation. | Per-table/site encodings with defined widths/ranges and corresponding generated decoders. Encoding keys in the program are recoverable, not secret keys. | Combine with the preceding item. |
| Section/layout variation | Section/offset-based extraction remains an effective shortcut. | Preserve segment mapping and permissions; use names/layout only as weak supporting diversity. | Low. |
| Symbol cleanup | Residual nonessential names expose generated roles. | Prefer ordinary release/link-time stripping now. Preserve necessary dynamic symbols and private maps. | Hygiene, largely not future research. |
| Overlapping instruction regions | Other approaches leave a specific discovery problem unresolved and correctness risk is acceptable. | Deliberately generated, isolated x86 regions with controlled entries and relocation/unwind treatment, behind a separate flag. | Last; high risk. |

### Compiler-to-patcher contract

If internal table patching becomes justified, design a private sidecar carrying:

- Schema/version and exact input artifact hash/build identity.
- Reserved region IDs, expected contents, sizes, alignment, and permissions.
- Target symbol/origin IDs and supported relocation information.
- Encoding widths, range checks, image-base conventions, and decoder versions.
- Allowed mutations, expected final invariants, and output hash/provenance.

Use fixed-size reserved regions initially so patching need not relocate arbitrary
instructions. Validate every precondition and reject mismatched artifacts.
Keep manifests/maps out of the agent bundle and delivered binary.

Design PIE/ASLR support explicitly. An encoded absolute address cannot generally
be fixed at build time and remain valid after rebasing. Internal image-relative
representations may help, but require correct range and base calculations.
External imports, PLT/GOT resolution, symbol interposition/versioning, and IFUNC
are separate work; do not claim arbitrary pointer coverage in the first version.

LIEF can edit ELF structures; it does not automatically repair instruction
semantics, dynamic relocations, exception/unwind information, or signed-image
integrity. A "high-byte key" is not portable cryptographic protection or a safe
assumption about spare pointer bits.

## Evaluation gates

- Retain the exact pre/post transform artifacts, assembly, mappings, and
  relocations privately. Compare against the same IR input and link settings.
- Differentially test real outputs, startup, repeated calls, and supported
  ABI/unwind behavior. Include loader/layout variation for correctness, not as
  a target runtime check or protection mechanism.
- Test normal discovery and informed-entry analysis separately.
- Re-run existing extractors unchanged, then measure agent repair and transfer
  to held-out builds/programs.
- Compare code-size/runtime/build-cost-matched alternatives. Changed bytes,
  analysis crashes, and unsupported lifting are separate diagnostics.
- Preserve static-only tool access and independent exact-answer grading.
- Reject changes that introduce unexplained crashes, invalid memory/stack
  behavior, silent coverage loss, or assumptions about the analyst's hardware.

## Ideas deliberately not promoted

Tokenizer/attention manipulation, misleading metadata narratives, blanket
nonstandard calling conventions, and arbitrary overlapping post-link rewriting
do not currently justify their cost. Corpus-based semantic mimicry and
algorithm-impersonation decoys remain optional separate experiments, not a
requirement for the generic compiler or a substitute for recovery resistance.

Persistent relational encodings, invariant-dependent operations, native
multi-output fusion, local memory representations, and attack-guided selection
belong to the **main IR roadmap**, not this deferred machine/binary document.
