# Closed private borrowing of encoded objects

This default-off W3/W5 increment carries a real encoded object across a private
pointer edge. It is not a general alias analysis, unrestricted pointer ABI,
completion of v04, or a measured agent-resistance result.

Enable `-native-object-calls=1`, or shared CLI `--object-calls`, with object
bundles and native bundles. Existing local-tile safety checks still apply.
Admission and lowering use no program-specific recognition or expected answers.
There are no environment checks, VM or later pipeline-layer transforms.

## Ownership contract

The owner is an admitted completely initialized entry alloca. One direct call
passes its exact root to one private, non-address-taken leaf function. That call
must be the callee's sole use. There is exactly one pointer formal, address space
zero; other formals and any result are integers. Both bodies obey the existing
structural limits. There are no nested calls or callbacks, except debug markers.

The callee's complete pointer-use walk admits only the same proved root-relative
accesses as a local tile. Each dynamic index is proved in the callee's own
dominator tree; caller constants are not guessed as callee facts. The selected
callee must perform at least four useful load-to-store operations. Shared
callees, subobject arguments, escapes/identity observations, unknown bounds,
volatile/atomic/partial accesses, and by-value/by-reference/sret/special ABI
parameters remain explicit fallbacks. The feature is applied to calls still
present at the tile stage; it does not silently undo prior fusion or merging.

Every initial cell store must precede and dominate the call. Existing supported
caller lifetimes are retained: for the caller's lifetime CFG, remote memory
accesses are projected to the proved call. An end followed only by a remote
access is therefore rejected, even if no caller load follows it. Callee lifetime
intrinsics remain outside this leaf contract. There are no new alias assumptions
and no speculative extra access before initialization.

## Lowering and atomic rollback

The caller allocates one coordinate/carrier/optional-phase object. It passes
that actual backing to the same private callee; no plaintext object shadow or
copy-in/copy-out wrapper is introduced. The callee computes tuple addresses from
its **own pointer argument**, never from caller-local SSA. Both sides share the
same descriptor. Store phases and remasking therefore persist across calls.
Integer outputs, other scalar consumers and packed-read outputs keep explicit
boundary accounting.

Original alloca alignment and promised call/formal alignment are preserved.
Memory-effect/speculation attributes invalidated by the new accesses are
relaxed on the callee and call. Both source owners are reserved together, so no
other object transaction can simultaneously claim the callee. The existing
shared module allowance and 65,536 growth reservation are unchanged; costs and
before/attempted/after counts cover both bodies as one coherent unit.

`-native-object-retained-growth=1..65536` is an additional downward-only actual
growth ceiling, default 65,536. It does not raise the estimate or shared budget.
If emitted growth exceeds the smaller of this ceiling and the reservation,
**both** bodies are restored. Both snapshots also restore function attributes.
The focused harness uses a ceiling of one to exercise this path, then requires
the entire object-stage IR to equal the feature-off control, without stripping
names or attributes to manufacture equality.

That exact comparison exposed a pre-existing `FunctionSnapshot` defect: making
the snapshot internal made it `dso_local`, and cloning it back leaked that
property onto a preemptable exported original. The helper now saves and restores
the original DSO-local property. Runtime-output equality alone did not detect
this ABI defect. Historical pre-fix artifacts are retained, not relabelled as
exact-rollback successes.

## Reporting and validation

Object contract 5 adds the actual retention ceiling and a `closed_call`
sub-contract: caller, callee, pointer ordinal, direct-site count, layout words,
useful callee operations and ownership proof. Each memory access names its source
function. The common gate checks both ownership identities, rejects duplicate
claims, validates limits, and distinguishes retained/rolled-back work. The source
ledger separates storage owners from borrowers and counts both as containing
encoded work, not as completely protected functions.

`borrow_run` compares all output words against an independent oracle through
clean, object-stage, final, stock-O2, feature-off and forced-rollback arms, with
thread/reentry checks and deterministic IR/reports. Rejection fixtures are
compile-only; invalid-memory or undefined-initialization controls are never run.
`--c-o2` compiles unchanged C with a kept private helper and exercises real clang
lifetimes, `fastcc`, scalar initialization and a packed two-word output read.
`bundle_decompile --tile --object-call-ablation --stem native` exports the actual
private borrower under matched stripped binary controls; the full program's
outputs are checked separately. This is informed-entry tooling, not an agent run.

Retained 2026-09-18 artifacts under ignored `out/`:

- `native-object-borrows-first-20260918`: initial i32 two-cell case.
- `native-object-borrows-phased-20260918`: eight i8/i64 four-cell cases, including
  returned values, promised alignment, both pin modes and additive phases.
- `native-object-borrows-negative-20260918`: eight early conservative exclusions;
  its lifetime rejection predates the later proved lifetime extension.
- `native-object-borrows-max-20260918`: full maximum application-pass composition
  with phases and a real scalar return (merge/data/helpers/late explicitly off).
- `native-object-borrows-c-o2-20260918`: both pin modes of ordinary optimized C.
- `native-object-borrows-lifetimes-20260918`: admitted caller lifetimes and a
  remote-only post-lifetime access that is correctly rejected, both pin modes.
- `native-object-borrows-decompile-20260918`: all five C borrower/normalized/off
  arms pass output checks and Ghidra export. Semantic recovery is `not_measured`.
- Full pinned suite before the final lifetime/ledger changes: 530 tests pass;
  affected tile/borrow subset after those changes: 34 pass.

These initial output-correctness matrices predate the snapshot-preemption fix.
Final repaired evidence:

- `native-object-borrows-exact-rollback-20260918`: three i32 maximum-preset
  cases (ordinary borrow, caller lifetime, scalar return) pass all output/thread
  controls and exact whole-module rollback comparison.
- `native-object-borrows-c-exact-20260918`: optimized C passes the same strict
  comparison, including its existing DSO-local binding and parameter attributes.
- `native-object-borrows-snapshot-regression-20260918`: repeated rollback with
  global block addresses and recursive calls passes for all three seeds.
- Final full pinned unit/model suite: 530 tests pass.

Final retained plugin:
`03a043e5fd8e6eb71fa47bfed0099c3da6eeacdf7aefce839ee815e2e60fb8f6`.
No deferred large-program, holdout, fresh-agent or promotion result is implied
by this evidence.
