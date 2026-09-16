# IR-only expansion: audit and implementation ledger

Scope confirmed 2026-09-16: expand the native IR path; retain MC and post-link
ideas in [FUTURE_MACHINE_BINARY_IDEAS.md](FUTURE_MACHINE_BINARY_IDEAS.md). No VM,
prompt/tokenizer manipulation, environment/hardware checks, anti-debugging, or
self-modifying code. This ledger distinguishes existing ingredients from new
features. It is not a declaration that the original list is implemented.

## What the existing protections actually do

| Component / source | Existing mechanism | Recovery opportunity / hardening decision |
|---|---|---|
| `Flattening.cpp` | Random block IDs; one encoded logical state; 1–3 dispatchers; router hash; dispatcher-specific bijections; hard-false fake transitions; opaque state-pointer aliases. | More advanced than a classic plain switch, but all dispatchers consume the same scalar state. Build per-activation relational state, then measure recovery. The parsed `hybrid` option was unused; this expansion fixes it. |
| `OpaqueUtils.cpp` | Many expression families; `hardTrue`/`hardFalse` compare equal mixes of two volatile reads from one unchanged local slot. | LLVM must preserve volatile reads, but a static analyzer can establish that the private memory is unchanged. Hash-looking arithmetic is not a cryptographic hardness guarantee. Prioritize memory-aware simplification controls and later invariant-backed predicates. |
| `MBAObfuscation.cpp`, `MBAUtils.cpp`, `ObfuscationConfig.cpp` | `preset=max` already combines nonlinear slot noise, layered rewrites, input-derived zeros, and SLE pool zeros. `high` uses SLE in place of much slot noise. | These are not LOKI-style key-dependent operation semantics. Compare high/max at matched cost and after normalizing local memory; do not add another large zero merely because it looks nonlinear. Pool forms need independent equivalence and transfer tests. |
| `SemanticDiffusion.cpp` | Volatile local slots and comparison/data transformations. Slot initialization can incorporate a stack address; it is not an environment check or a secret. | A recoverer can model these local locations. This is not general aliasing denial or changing object representations. Work toward bounded, nonescaping object representations; never use cross-allocation pointer arithmetic. |
| `NativeEncoding.cpp`, `ConstantEncryption.cpp` | Seeded scalar families and per-object/index encoded immutable integer arrays; decoder helpers and a late sweep. | Existing keys and decode boundaries are statically recoverable. Extend representations across useful operations rather than immediately undoing them. Escape/partial-access exclusions remain necessary. |
| `StringEncryption.cpp` | AES/ChaCha machinery upstream; native selects AES with split material and helper hardening. | Cipher recognition, key recovery and constructor/dataflow analysis still apply. Decoding data is not executable-code decryption. Test initialization order before extending to decoy initializers or arbitrary writable data. |
| `VirtualCall.cpp` | Encrypted call tables, decoys, forwarding thunks and runtime initializer; native uses nonmerged tables. | Initializers still refer to targets and materialize XOR keys. Index deltas use equal volatile loads. F3 includes these helpers but does not remove target references. Diversify per-table semantics in IR; final-address removal stays post-link backlog. |
| `FunctionMerging.cpp` | Bounded internal groups and dispatcher-based bodies, with call rewriting and optional compatibility thunks. Native uses switch dispatch and no address-taken thunk expansion. | Merging is not arbitrary cross-function fragmentation or aggressive outlining. Preserve external ABI and independently audit group formation and selector recovery. New flattening also applies to eligible merged groups. |
| `Substitution.cpp`, `BogusControlFlow.cpp`, `SplitBasicBlock.cpp` | Expression substitution, fake branches and splitting, with budgets. | Retain as supporting diversity. Local identities and opaque-condition dependencies can be simplified; block count is not an attack score. |
| `AntiOptimizationShield.cpp`, `AntiDecompiler.cpp` | IR preservation/laundering plus optional architecture/assembly techniques upstream. | Native explicitly disables injected assembly, timing reads and fake loops. A compiler barrier is not a decompiler barrier. Keep MC gadgets out of this expansion. |
| Native driver / reports | After-O2 entry point, per-pass budgets, helper worklist, final verification and coverage reports. | Later passes can skip as budgets fill; function rollback does not remove newly created module globals. Harden reporting and transactionality separately from protection claims. |

This is a targeted source audit, not an exhaustive correctness review of every
legacy mode. Upstream comments asserting SMT resistance are hypotheses until
reproduced against a declared solver, memory model and timeout.

The new recursion fixture also exposed a correctness defect in encrypted
indirect calls: table identity was per callee, but key identity was per caller.
The second caller could decrypt a shared entry with the wrong key and crash.
This expansion derives the key from a module seed namespace and callee identity,
so every user agrees with the initializer. This is a correctness fix, not a
claim of stronger pointer encryption. Constructor ordering remains a separate
coverage concern.

## Original technique list: disposition

| # | Technique | IR-only decision / remaining work |
|---|---|---|
| 1 | Constant diffusion | Initial F1/F2 exists. Extend lifetime of representations; test bulk scalar/array recovery. |
| 2 | Cryptographic opaque predicates | Not implemented as proposed. Fixed known preimages permit forward evaluation; random live predicates cannot be assumed invariant. Plan bounded predicates with privately checked invariants, not an infeasibility promise. |
| 3 | Lift-gap poisoning | Exact-width integer diversity is in scope. No UB, poison, unspecified promotion assumptions, x87 dependence or changed FP contraction. A faithful bit-vector lift remains possible. |
| 4 | Lying read-only data | Not implemented. A writable shadow/decoy-data experiment needs closed-use analysis and constructor-order proofs. Do not overwrite ELF read-only memory or confuse encoded backing with plausible decoy plaintext. |
| 5 | Tokenizer constants | Excluded under the agreed non-prompt/tokenizer direction. |
| 6 | Seeded template diversity | Initial registry exists; multi-state adds three function-level state families. Neither establishes a 10% distribution cap or effective post-decompiler diversity. |
| 7 | Distributed multi-state CFF | First implementation: local three-word, history-dependent state and encoded candidate dispatch. Cross-function activation contexts and global distribution are NOT implemented. Globals are not the default because recursion, threads and callbacks need isolation. |
| 8 | Key-dependent MBA | Existing SLE/input-zero machinery is not LOKI. Initial two-lane modular transfers and optional data/control coupling are implemented; generalized invariant-dependent semantics remain research. |
| 9 | Static dataflow denial | Existing slot/pointer techniques are ingredients. Plan nonescaping bounded objects with proven index/lifetime rules and changing representations (R4). |
| 10 | Indirect calls / outlining | Existing call protection reused; bounded native pure-integer outlining is now implemented, including multi-output helpers. Further call-table hardening remains work. External ABI is unchanged. |
| 11 | Semantic mimicry blocks | Optional corpus experiment, not implemented. A checksum feeding an invariant branch may still disappear once that invariant is known; measure live semantic dependencies. |
| 12 | Induction-head poisoning | Not promoted: depends on repetition/attention effects explicitly outside the primary strategy. Real template diversity belongs to #6. |
| 13 | Function-boundary dissolution | Existing merge plus new bounded multi-output outlining/value encoding are initial ingredients. Not unrestricted fragments across unrelated functions or general joint-output synthesis. |
| 14 | Merged-handler virtualization | Excluded: native flattening, no VM. |
| 15 | Anti-idiom/e-graph selection | Bounded verified candidate search is planned (R5). Score recovery-script transfer and cost, not assumed distance from unknown training data. |
| 16 | Idiom transplant | Optional corpus experiment, not implemented. Arbitrary algorithms cannot acquire another algorithm's structure without a semantic matching restriction or substantial overhead. |
| 17 | Engineered corroboration | Bespoke challenge design, not a generic compiler pass. Not part of the generic IR implementation contract. |
| 18–22 | MC features | Deferred unchanged. |
| 23–26 | Post-link/LIEF features | Deferred unchanged, including pointer-table patching. Ordinary stripping already used by the harness is hygiene, not a new post-link obfuscator. |

“All relevant IR features” therefore means implementing and evaluating the
generic semantic mechanisms, plus explicitly tracked optional corpus research;
it does not mean silently enabling excluded or inherently bespoke ideas.

## First expansion milestone: relational flattening

Configuration: `flattening(multiState=1,stateFamily=3)`. The legacy default is
`multiState=0`; the native max/smoke entry points request the new mode. Disable
with `-native-multistate=0`. `-native-state-family=0/1/2` forces a family for
testing; `3` selects from the independent seeded `multi-state-v1` stream.

Each activation owns a token `T`, key `K` and salt `S`. Entry initialization
uses a frozen integer argument, when available, and seeded constants. No extra
argument dereferences, process-global state, new API, environment read or
hardware entropy is introduced. On each transition, including back edges:

```
K' = rotl32(K xor S, 5) + edge_constant_0
S' = rotl32(S + T, 7) xor (K' + edge_constant_1)
T' = E(next_encoded_block_ID, K', S')
```

All arithmetic is modulo 2^32. Each of the three `E` families is bijective in
the block ID for every key/salt pair: it composes XOR, addition, fixed rotates
and multiplication by an odd word. Thus a real token matches exactly one real
candidate; fake IDs are globally disjoint from real IDs within the function.

The router chooses a starting candidate group using the current key. A miss
advances to the next group, forming a ring; a valid state reaches its unique
target within at most one traversal. Groups compare encoded candidates against
the stored token; no central inverse creates a decoded switch selector. Optional
dispatcher domains are applied symmetrically to both sides. Invalid internal
states are outside the invariant; no runtime integrity/environment check is added.

Tradeoffs and limits:

- The same logical successor acquires different stored representations along
  different histories. Key, salt and token persist over application blocks.
- This is still ONE logical control location represented by three physical
  words. It does not magically create independent semantic state machines.
- Per-call allocation isolates recursion/reentry and threads by construction.
  EH/indirect-control/ABI exclusions of the native driver remain unchanged.
- Candidate comparisons cost O(number of flattened blocks) per transition in
  the worst case, instead of an efficient scalar switch. Code size and runtime
  must be measured; keep the ablation available and do not equate this cost
  with equivalent recovery difficulty.
- An analyst who recovers `E`, `K` and `S` can invert the representation.
  `conformance/state_model.py` deliberately implements that recovery control.
  Constants still materialize transiently when the next ID is encoded. This
  milestone is not general persistent application-data encoding (R1).
- Private final-IR inventory counts actual surviving state allocations, not
  attempted emissions or attributes left over from rollback. Named comparison
  counts are diagnostics because downstream passes can replace comparisons.

The recurrence and bijections give a hand-checkable invariant. Model tests and
finite binary differentials supplement it; they are not an LLVM equivalence
proof or a demonstrated cost increase against an agent.

## Further implemented experiments and next gates

See [NATIVE_VALUE_REGIONS.md](NATIVE_VALUE_REGIONS.md) for the new persistent-value,
pure-region outlining and local data/control-coupling passes. They can be enabled
now; research validation is not a prerequisite for adding an experimental pass.
Default promotion remains separate from implementation and correctness.

1. First state milestone implemented and conformance-checked. See
   [NATIVE_IR_STATUS.md](NATIVE_IR_STATUS.md) for state-family, recursion, thread,
   seed, legacy-ablation, stock-O2 and Ghidra evidence. Recovery-cost validation
   is still outstanding; this is not yet a demonstrated stronger preset.
2. R1: initial two-lane modular encoding carries supported operations and joins,
   with a known-representation recovery control. Extend operation families and
   evaluate normalization/repair before treating the research objective as met.
3. R3 / #10 / #13: bounded pure-region outlining with real multiple outputs is
   implemented and can receive R1 encoding. General joint-output synthesis and
   cross-function fragmentation remain work. No interpreter.
4. R2/R4: initial local data/control context coupling is implemented. Phase-
   changing source objects and safely shared contexts across internal calls
   remain work; prove initialization, transitions, joins and concurrency.
5. R6 / #2: invariant-backed predicate candidates; retain proof artifacts
   privately. Known-hash evaluation and solver normalization are controls.
6. R5 / #6 / #15: bounded selection against cheap recovery scripts, with held-out
   seeds, programs and tools. Corpus #11/#16 is a separate opt-in experiment.

Remaining research milestones are not all implemented. None of the above requires MC or
post-link changes, and none promises that angr, Z3, Ghidra or taint analysis
becomes unusable. The target metric is additional verified recovery/repair work
at matched binary, runtime and agent budgets.
