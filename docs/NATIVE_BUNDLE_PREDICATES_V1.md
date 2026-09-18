# Exact compound predicates over joint bundles

`-native-bundle-predicates=1` / `--bundle-predicates` consumes selected compound
equalities directly from a persistent bundle. Default off; requires bundles.
This is a bounded W4 increment, not complete comparison-loop conversion or a
claim of measured agent resistance. Large-scale development gates are deferred
as recorded in [the scale ledger](V04_DEFERRED_SCALE.md).

## Eligibility and exact law

Eligible roots are conjunctions of two to four integer equalities against
constants, or disjunctions of two to four inequalities. Every leaf must consume
a different output of the same selected bundle. The whole tree must follow that
bundle in the same basic block; interior nodes and comparison leaves have one
use. Shared leaves, mixed predicates, repeated outputs and cross-block trees
retain ordinary boundaries. At most four roots per region are selected in stable
order. Outer complete reductions are considered before nested ones.

Let `Z = Encode_M(X)` be the current triangular tuple. Construct `Expected` by
substituting the target constants into their selected slots while remasking
untested coordinates to preserve their original logical values. This does not
first reconstruct the selected scalar outputs. Because the representation is
invertible, `Z == Expected` exactly when all selected logical values match.

The emitter XORs corresponding coordinates, applies a full-width triangular
rotate/XOR residual map, then OR-reduces every word and tests zero. The residual
map is invertible and preserves zero. This is exact equality, not a compressed
hash or probabilistic checksum; no collision changes program behavior. The
`any-different` mode negates the same exact relation.

No loads, calls, divisions, exceptions or other effects move across a guard.
An existing eligible predicate inside a supported loop may be transformed, but
this feature does not turn short-circuit code into an eager comparison loop.
The final Boolean remains available to legitimate consumers. Other consumers
of a compared data value keep their required scalar projection.

## Ownership, cost and reports

Planning records each target's output/slot, width-limited constant and original
comparison lineage, plus the root's lineage, tree size and exact law. Missing
source lineage remains unknown rather than being invented. LLVM instruction
bindings stay separate from the value-only plan.

Each root reserves `512 + 256 * lanes` instructions inside the existing bundle
allowance; hard caps are unchanged. Predicate lowering belongs to the same body
transaction as its source bundle, so rollback restores both the original pure
operations and their comparison tree. No module-global helper or state is added.

Each generated Boolean has a unique frozen identity and origin marker. The
`bundle_predicates` inventory observes actual live roots at
`after-bundles-before-regions`, with contract `joint-predicate-v1`. The common
gate reconciles that inventory exactly against retained plans, rejects unknown
or duplicate roots, excludes rolled-back work, and checks that absorbed uses
plus private-interface supplies do not exceed original data-boundary uses.

The summary reports original, absorbed and remaining scalar **data** uses, and
separately counts live Boolean consumers. Removing a data projection does not
mean that the Boolean outcome is hidden. This stage-local accounting does not
claim final decompiler survival or whole-program source coverage.

## Focused evidence

Tested plugin:
`2ec62ebf6966752a75df7587b65712fc04ba1b080f2af28d4460f58ee9bc213d`.

- `out/native-bundle-predicates-matrix-20260918`: 22 i8/i32 XOR cases, including
  two/three/four-value predicates, partial matches, retained scalar consumers,
  shared/mixed/repeated-output exclusions and cross-block short circuit.
  Byte inputs enumerate every pair; all widths include constructed positives.
- `out/native-bundle-predicates-wide-20260918`: eight i16/i64 additive, pinned
  cases. Both matrices compare clean/native/feature-off/post-O2 outputs and
  require actual requested coverage and deterministic emission.
- `out/native-bundle-predicates-combined-20260918`: four-value and partial-use
  fixtures pass with the max application profile. Strings, data, helper hardening,
  late constants and merging remain explicitly off in this focused runner.
- `out/native-bundle-predicates-off-compat-20260918`: disabled-feature IR is
  byte-identical to the preceding control-state compiler.
- `out/native-bundle-predicates-loop-control-20260918`: four i8/i32 cases pass
  with real early exits, static/two-phase recurrences, actual control binding,
  zero-trip and constructed-positive inputs, threads and post-O2. These retain
  control-off arms; the separate straight-line matrices ablate the predicate.
- The pinned unit suite passed 509 tests before adding one further early-exit
  oracle regression. Exact small-domain tuple tests and all-width residual
  bit-vector proofs are separate from compiler differential execution.
- The final affected unit groups passed 32 tests, including the new early-exit
  oracle and actual solver checks.
- `out/native-bundle-predicates-decompile-20260918`: five informed stripped
  Ghidra arms pass 1,109 vectors each. Clean/native/post-O2/off/off-post-O2 C
  sizes are 378/18,779/17,139/43,574/17,064 bytes. The native C is smaller than
  the disabled arm here; size is not a resistance metric. Semantic recovery
  was not measured by this diagnostic.

The initial integration attempt failed a harness formatting mismatch (decimal
expectations versus the existing hexadecimal driver); that artifact is retained.
Three actual emitted-IR proofs at a three-second solver budget were
**inconclusive** and are retained in `emitted-proofs.json` in the first matrix.
They are neither equivalence proofs nor obfuscation wins. Complete byte-domain
differentials and the independent law checks are separate positive evidence.

The informed model deliberately decodes the descriptor and recovers the original
conjunction. An analyst may infer that simpler predicate too. The feature removes
specific scalar crossings; discovery/repair cost and fresh-agent improvement
remain to be measured. No large-application or protected-holdout run is a gate
for this increment, and no such improvement is claimed.
