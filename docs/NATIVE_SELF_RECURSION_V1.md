# Direct self-recursive private activations

The default-off `-native-self-recursion=1` option extends encoded integer
interfaces to a deliberately narrow recursive contract. It requires
`-native-encoded-calls=1`; the shared conformance option is `--self-recursion`.
This is one W5 increment, not completion of bundle interfaces or pointer
ownership, and is not evidence of increased reverse-engineering cost.

## Contract and exclusions

The direct-call SCC must contain exactly one function. Its body may call itself
and contain non-observing lifetime/debug intrinsics, but may not call another
function, an unknown callback, inline assembly, or a stack/frame observer.
Existing local-linkage, integer-signature, identity, EH, musttail, returns-twice
and operand-bundle restrictions still apply. Mutual recursion remains excluded.
The policy planner and actual emitter use the same eligibility check.

Every invocation has its own activation slot. The recursive edge and ordinary
call sites pass encoded argument pairs and return an encoded result pair;
no plaintext wrapper or shared global activation state is created. Explicit
`notail` calls retain that property. Other tail-call hints are not promised for
the changed private ABI. Scalar reconstruction remains where no supported
consumer absorbs a pair; the report distinguishes full and partial absorption.

Arbitration ignores only a proved direct self edge on a reserved, standalone
encoded interface. It does not ignore cycles introduced by merging other
functions. A fixture requires an independently emitted merged group alongside
the recursive encoded interface, rather than inferring coexistence from flags.

With this option enabled, every interface report has
`recursion_contract: direct-self-activation-v1`, a `self_recursive` Boolean and
`recursive_calls_rewritten`. The count must be positive exactly for encoded
self-recursive interfaces and cannot exceed all rewritten call sites.

## Reproduction and evidence

Run `python3 -m conformance.recursive_run --out out/FRESH
--toolchain-image sre-obf-dev:llvm22 --widths 8 16 32 64 --seeds 1 3 4 --merge`.
The fixture is genuinely non-tail recursive, has two external call sites and
multiple live parent-frame values, and compares all four outputs with an
independent oracle. It covers base cases, variable depth, repeated activations,
threads, post-O2 output equivalence and exact same-seed IR/report determinism.
The i8 case exhausts all 65,536 input pairs. Optional `--ablation-plugin PATH`
requires feature-off IR equality with that prior plugin plus oracle equivalence.

`conformance.recursive_controls` separately verifier-checks and compiles eight
excluded cases: another callee, callback, frame observation, operand bundle,
musttail, returns-twice, address taken and mutual recursion. None is executed;
invalid IR or compiler failure is never credited as a successful rejection.

Local artifacts retain the initial i8/i32 seed-1 tests, i16/i64 seeds 3/4,
and the final non-tail-preserving i8/i32/i64 seed-4 tests with prior-plugin
ablations. These directories are under `out/native-self-recursion-*-20260918`.
Their manifests identify exact plugins, commands and outputs. This is compiler
correctness and contract coverage, not a semantic-recovery or agent result.
