# Private encoded arguments into persistent bundles

`-native-bundle-call-inputs=1` is an experimental, default-off W5 increment.
It requires bundles, encoded calls and the connected planner. The shared
fixture/whole-program/scale spelling is `--bundle-call-inputs`. It does not
complete joint argument/result descriptors, pointer interfaces or W5.

## Semantics and ownership

A validated encoded-call argument is an XOR pair `(E, R)`. A selected pure
bundle or local-tile arithmetic consumer imports those coordinates separately,
converts to its XOR/additive representation using the existing verified
transfer primitives, and remasks into its joint tuple. Pure-bundle entry derives
the activation carrier from coordinates; it does not rebuild the scalar first.
Local-tile initialization and unsupported consumers retain explicit boundaries.

The original reconstruction survives if another consumer still needs it.
Actual imports attach a body-owned marker; merely recognizing a candidate does
not count. The ordinary body snapshot restores markers alongside instructions
on rollback. A retained connected consumer reconciles and clears its marker
when it counts the same parameter. A final stable-order walk counts remaining
markers, including functions with no connected selection, and erases only
unused reconstructions. Thus partial imports are not counted twice, and a
connected rollback cannot discard an earlier retained bundle's absorption.
No ABI, pointer lifetime, recursion eligibility or resource cap is relaxed.

The `bundle_call_inputs` inventory is explicitly measured **after bundles,
before connected lowering**. It identifies the actual encoded function and
counts imported parameters, fully/partially absorbed parameters and remaining
scalar uses. The existing final interface inventory remains authoritative for
total absorption. Gates check uniqueness, fixed parameter denominators, both
feature dependencies, stage identity and preservation in the final inventory.
Scale summaries retain zero coverage rather than dropping empty inventories.

## Tests and limits of the evidence

`conformance.recursive_run --bundle-call-inputs` checks independent full outputs,
real recursion, threads, exact seed determinism and post-O2 equivalence. Its
`--straight-line` arm requires removal of both scalar input reconstructions.
The XOR/additive and pins-off arms are separate; i8 inputs are exhaustive.
Matched disabled and disabled-post-O2 arms keep bundles and private calls on,
turning off only the new coordinate import.

Local evidence under `out/native-bundle-call-input-*-20260918` includes:

- recursive i8/i32 seed 1, XOR, partial scalar consumers;
- straight-line i16/i64 seed 3, additive, pins removed, full absorption;
- straight-line i8/i32 seed 4, additive, two-node connected limit, matched
  disabled arms: the private callee selects **zero** connected nodes but retains
  and correctly accounts for both imported bundle inputs;
- matched stripped-binary Ghidra checks use the callable local symbol only in
  an explicitly informed arm. Private symbol tables are not attacker inputs.

The initial Ghidra attempt assumed a linker map contained local symbols and
failed before decompilation; it is preserved. The corrected runner resolves
the unique text symbol in the private unstripped build and still strips the
binary presented to Ghidra. Decompiler size is a diagnostic, not recovery cost.

Unchanged zlib passes source/output/post-O2 and accounting gates at 249,659 IR
instructions under the original 250,000 cap. It has zero encoded integer-only
interfaces and therefore zero new private-input coverage. This is no evidence
of broader interface protection; closed-object pointers remain necessary.
Unchanged Lua also passes at 237,151 instructions with zero imported bundle-call
inputs. The five Ghidra arms each match all four outputs on 1,105 inputs; C text
sizes are clean/native/post-O2/disabled/disabled-post-O2 =
327/8,947/7,203/8,815/7,145 bytes. These small size differences are not evidence
of increased semantic recovery cost.

Tested compiler plugin: `45a6dd713a6c850ef3c55d882b067ceb57391c1b5d54dc35759fba08a756d929`.
The local artifact manifests identify exact commands and hashes. No fresh-agent
or semantic-recovery claim is made by this increment.
