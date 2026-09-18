# Bounded joint private-call arguments

This default-off W5 increment does not finish W5 or v04 and is not a promoted
preset. Enable `-native-joint-call-arguments=1`, or shared harness
`--joint-call-arguments`, together with encoded calls and native bundles.
All existing private-interface safety exclusions remain in force. Public and
address-taken interfaces are unchanged; no VM, MC, post-link or runtime checks
are introduced.

## Contract

An otherwise eligible private function with two through four same-width integer
arguments and at most eight direct call sites receives a triangular XOR tuple:
N coordinates plus one carrier, rather than N independent coordinate/mask pairs.
The agreed descriptor has one salt and rotation per argument. Its mask depends
on the carrier and previous encoded coordinate; later arguments therefore share
a representation relation with earlier arguments. The existing activation-local
carrier mechanism is reused. Descriptors are build constants, not secrets.

Zero/one/five-or-more arguments, mixed argument widths and more than eight sites
retain the paired interface and an explicit reason. Argument counts are source
ABI denominators, not a claim that every argument remains semantically useful
after later simplification. Integer results still use the prior pair ABI.
Pointer contracts, mixed-width joint groups, aggregate results and joint
return tuples are not implemented by this increment.

The twin retains source function attributes subject to the existing memory-effect
repair, removes parameter/result attributes tied to the old signature, and
rewrites every admitted direct call. No plaintext wrapper is retained. Supported
self-recursion keeps a separate activation per invocation; the shared source
eligibility and merge/fusion arbitration are unchanged. Functions outside the
joint subset can still receive the existing paired protection.

Each callee argument has an `(E, derived-mask)` view. Existing bundle input
consumption imports that view without reconstructing a scalar. A bundle supplier
remasks its output under the destination tuple relation; replacing an earlier
coordinate also updates the later masks that use it. The old connected supplier
must **not** replace coordinate and mask independently for this ABI. It explicitly
keeps an interface boundary where direct bundle supply has not handled the site.
Other scalar consumers still reconstruct values and remain counted exposures.

The argument-mask reservation is `8*N*(call_sites+1)`, bounded to 288 per joint
interface; emission records its actual mask instruction count, at most seven per
lane at each site and entry. This is local plumbing accounting, not a new module
allowance or total final-code cost. Existing module caps and downstream budget
computation remain unchanged. Descriptor generation uses a separate per-function
seed stream. Feature-off IR compatibility is tested against the prior compiler.

## Reports and controls

`joint_arguments` records disposition, exact ABI word count, descriptor, reserved
mask work and emitted mask work. `argument_widths` preserves source denominators,
including unsupported signatures. The common gate validates the shape, fallback,
cost and feature dependencies before summaries are computed. Bundle input/supply
reports separately distinguish partial and full absorption; a joint flag or
descriptor is not itself a claim of useful consumer coverage or final survival.

`interfaces.ll` is a private stage snapshot immediately after interface rewriting.
`joint_call_proof` lifts only participating entry-mask slices, using unconstrained
formal bit vectors and the supplied descriptor. Unknown syntax/flags/shift bounds
fail closed. Positive, wrong-law counterexample, missing-root and wrong-ABI tests
exercise the validator. This proves neither caller lowering nor whole-function
correctness, and measures no binary discovery or repair cost.

`joint_call_controls` tests argument counts 0..5, the eight/nine-site boundary,
multiple word widths, deterministic reports/IR, all-output source oracles and
stock-O2 normalization. `recursive_run --joint-call-arguments` adds a matched
joint-off control that retains bundle consumers while reverting to independent
pairs. Homogeneous recursion fixtures test activation isolation and threads.
`--straight-line --drop-unused-depth --direct-return` tests a true two-argument
interface with full useful input absorption and direct encoded result supply.
`bundle_decompile --private-calls --joint-call-ablation` compares stripped,
informed-entry joint/pair arms with the same full-output workload.

2026-09-18 retained evidence under ignored `out/`:

- `native-joint-calls-first-20260918`: i8/i32/i64 XOR unpinned true recursion,
  independent outputs, threads, O2 and pair-interface controls all pass.
- `native-joint-calls-mixed-20260918`: i16/i32 mixed signature correctly keeps
  pairs and passes additive/pinned output controls.
- `native-joint-calls-composed-20260918`: i16/i32 additive/pinned recursion with
  actual separate-group merging all pass. Each imports three arguments partially
  (three scalar uses remain) and directly supplies three recursive arguments.
- `native-joint-calls-full-inputs-20260918`: i8/i64 two-argument cases pass;
  both useful inputs are fully absorbed, zero scalar input uses remain, and one
  direct bundle result supply is recorded. Rare/normal returns are exercised.
- `native-joint-call-controls-20260918`: all ten ABI/limit cases pass. Its
  `emitted-proofs.json` proves 25 actual entry slices across eight cases,
  including the composed recursion runs. This is a known-descriptor control.
- Full pinned unit/model suite: 524 tests pass.
- `native-joint-calls-off-compat-20260918`: feature-off IR is byte-identical to
  the preceding larger-tile compiler.
- `native-joint-calls-decompile-20260918`: all five joint/pair/clean normalized
  arms pass the full-output workload and Ghidra export. Semantic recovery is
  explicitly `not_measured`; C size is not a hardness score.
- `native-joint-calls-max-fixed-20260918`: i32 seeded/pinned recursion passes
  with the full maximum application-pass set, real separate-group merging,
  paired-interface and supplier-off controls, threads and stock O2. Strings,
  numeric-data encoding, helper hardening and late constants remain disabled
  explicitly by this focused runner; this is not the final combined preset.
- Final affected unit subset after the full-absorption fixture: 30 pass.

Retained plugin SHA-256:
`4fc4a737814aecbb8d84519f918be9a0a247e24018928f78d0e619066592d5bb`.
The first max-application runner command incorrectly passed literal `all` to the
compiler's ablation option; its failure remains archived. The runner now treats
`--passes all` as the compiler's full default application set.

No large-program, protected-holdout or fresh-agent run is implied by these
focused checks. They establish a supported implementation increment, not
resistance to general inverse recovery or promotion of the combined v04 preset.
