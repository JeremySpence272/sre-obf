# Persistent bundle supplies to private interfaces

`-native-bundle-call-outputs=1` supplies encoded argument/result pairs directly
from selected pure bundles and local tiles. It is default off and requires
bundles plus encoded calls; the shared harness option is
`--bundle-call-outputs`. It is independent of `--bundle-call-inputs`, so each
direction can be ablated separately. This is not a joint multi-value ABI,
closed-pointer interface, complete W5 implementation or hardness claim.

## Transfer and ownership contract

Only the exact generated private split/result structure is eligible: an XOR
whose first operand is the bundle output, with one use in a direct call argument
or result-pair insertion. Other users retain their scalar boundary. Site order
is stable instruction order, not use-list or hash iteration order.

For a source coordinate pair `(E, R)`, the emitter converts an additive source
to XOR coordinates when necessary and remasks to the interface's existing
activation mask. No scalar value is reconstructed first. The interface still
receives its ordinary `(encoded value, mask)` pair, so its private ABI and
activation ownership do not change. The existing transfer algebra proves
equivalence; this does not imply that a solver cannot recover the projection.

Each supplied value has a distinct freeze identity with a body-owned accounting
marker. The same body transaction that owns the source bundle owns its supplies.
Rollback restores all users and markers; no separate module object is created.
A collector counts retained supplies before connected lowering, then removes
its accounting markers. Connected lowering cannot count the old split/result
again because it has been replaced, and its rollback cannot erase an earlier
retained bundle's supply. Input and output accounting remain separate.

Planning reserves 384 IR instructions per eligible supply in the existing
bundle/tile allowance. Actual emitted growth still passes the body transaction
and module cap. No per-function or module ceiling is raised. The original
`scalar_output_uses` in a plan is the source-boundary denominator; the new
`call_supply_uses` records the converted subset. Tile summaries now expose both
the original denominator and remaining scalar uses after these supplies.

The `bundle_call_outputs` inventory uses contract `bundle-call-supply-v1` and
stage `after-bundles-before-regions`. It identifies caller and actual encoded
interface, with separate argument/result counts. Gates require exact agreement
with retained pure/tile reservations, exclude rolled-back work, and reconcile
against the final interface supply denominator. Disabled features cannot claim
nonempty continuity inventories.

## Reproduction and retained evidence

`conformance.recursive_run --bundle-call-inputs --bundle-call-outputs --merge`
tests recursive supplies; add `--straight-line --direct-return` for a direct
result. That fixture has both a live scalar predicate and a directly supplied
result, rather than assuming every output can lose its scalar representation.
Wide positive cases use x=16, y=2^(width-2)-13 to reach its exact rare return.

`conformance.tile_run --private-calls --object-phases --ablation --shapes
supported --cells 3` routes every tile cell through a real private integer
consumer, checks all four final outputs and keeps matched tile-disabled arms.
The extra private activation alloca is inventoried separately, not hidden from
the object denominator. The first run failed a harness assumption that there
would still be exactly one alloca; that failure is preserved.

Local final-plugin tests under `out/native-bundle-call-output-*-20260918` cover:

- i16/i64 seed1 recursive XOR supplies, with earlier i8/i64 seed3 controls;
- i8/i32/i64 seed4 additive result supplies, unpinned, two-node connected cap,
  exact positive returns, matched output-disabled and post-O2 controls;
- all three outputs of phased i8/i64 tiles, both families and pin settings,
  including stage-local output checks, threads and exact same-seed determinism;
- feature-off i32 seed3 IR byte equality with the prior private-input plugin;
- five informed stripped-binary Ghidra arms, 1,107 full-output vectors each.

The Ghidra C sizes for clean/native/post-O2/output-disabled/disabled-post-O2
are 260/20,313/11,184/19,523/10,395 bytes. These are shape diagnostics, not a
measurement of semantic-recovery resistance. Unchanged Lua passes source,
post-O2 and accounting gates at 237,151 IR instructions under the original
250,000 cap, but has zero new bundle-call input/output coverage. Do not promote
the feature on fixture coverage alone.

Final tested plugin:
`11f2aa586d5760b6e88b83859e9115784b700696c09e6d243d59d56a22fc8c71`.
The pinned solver suite passed 485 tests. No fresh-agent or held-out protection
run is part of this increment.
