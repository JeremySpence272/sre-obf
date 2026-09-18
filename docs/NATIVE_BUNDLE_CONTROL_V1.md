# Persistent recurrence-to-control binding

`-native-bundle-control=1` binds multi-state flattening to the actual storage of
one selected persistent bundle recurrence per function. It is default off and
requires bundles, bundle loops and multi-state flattening. The shared harness
option is `--bundle-control`. This is a bounded W4 increment, not the complete
predicate/control workstream, a private-pointer interface or a hardness result.

## Ownership and relation

The bundle emitter marks two live coordinate PHIs, their carrier PHI and the
optional phase PHI with a common origin. CFG demotion transfers those identities
to the actual recurrence allocas. Flattening binds the first stable complete
group only if every word has a useful read, simple direct loads/stores, the same
supported integer type and an entry zero store dominating every load. This uses
the existing demotion initialization; it does not speculate application reads or
read uninitialized objects on zero-trip paths. Each activation owns its storage.

These are **not copies in a temporary pin buffer**. The next useful recurrence
computation reads the same storage as dispatch. The control code only reads it;
it never replaces a useful update or writes a new arbitrary mask into the tuple.
Other coordinates of a larger bundle are not claimed as bound control words.

At transitions and dispatcher checks, a shared emitter mixes the three/four
words into the effective 32-bit key and salt after existing lane/context logic.
The original per-activation key/salt state is still stored in its original form.
Both ends read the same recurrence state. Narrow words zero-extend; 64-bit words
fold their low/high halves by XOR. Fixed defined rotates, XORs, additions and
multiplications mix the folded words. This fold has known collisions; neither
injectivity nor secret entropy is claimed.

The new control loads are volatile, preventing the post-flattening mem2reg pass
from discarding the shared backing. Original useful accesses retain their data
ownership. Late alias confusion skips bound recurrence allocas: its integer
pointer aliases would invalidate the closed direct-access proof. Ordinary stores
remain eligible. The first full-profile phased test caught this interaction and
is retained as a failed artifact, not reclassified as successful protection.

The feature does not increase any budget. Existing body transactions and hard
module caps still apply; a rollback or skipped flattening can leave a selected
recurrence with no retained control binding. That is reported as unavailable,
not successful coverage. Metadata is private evidence, not attacker input.

## Final-IR accounting

`bundle_control` has one row per bundle owner, with contract
`persistent-bundle-control-v1` and stage `final-ir`. Its requested-region
denominator comes from retained persistent bundle plans. A coupled row names the
origin and gives each word's width, initialization proof, dispatcher/transition
reads, useful reads, useful store sites and unclassified accesses.

The gate requires complete ordered roles, all useful/control counts nonzero,
equal control-read counts across words, zero unclassified accesses and exact
aggregate totals. It rejects wrong origins/phases, missing owners, duplicate
owners, rollback credited as retained work and disabled-feature coverage.
Unavailable rows retain their denominator/reason but have exactly zero coverage;
missing/unknown counts cannot stand in for zero. Scale summaries preserve that
distinction. `hardness_evaluated` remains false.

## Validation and limits

`bundle_loop_run --bundle-control --control-ablation` retains flattening in its
matched control-disabled arm. Both arms and their stock-O2 normalization arms
must agree with the independent source oracle for both outputs. Use
`--control-profile max --control-passes all` to exercise all application passes;
the runner still explicitly disables strings, data, helper hardening, late
constants and merging. It is not a test with every native feature enabled.

`bundle_control_proof` checks the actual emitted key/salt expressions in its
supported final-IR subset against an independent bit-vector specification. It
is informed by private names/metadata and treats each storage read as an
unconstrained input. It does not prove initialization, execution ordering or
whole-function equivalence. Unknown syntax, incomplete slices and solver unknown
do not pass. Later expression-rewriting passes can leave this narrow subset;
full-profile differentials provide separate evidence, not a claimed SMT proof.

The known-relation model deliberately recovers labels for all three dispatcher
families after incorporating the live words. The frozen key/salt-only decoder
fails some inputs, but the repaired decoder succeeds. This demonstrates a
changed dependency, not discovery difficulty or resistance to semantic slicing.
An analyst may still recover a simpler computation and discard its dispatcher.

Retained 2026-09-18 evidence under ignored `out/`:

- `native-bundle-control-inventory-*`: i8/i32 XOR, both phase modes.
- `native-bundle-control-broad-*`: 24 i16/i64 additive cases, both pin/phase
  settings, ordinary loops, early exits and multiple latches; matched off arms.
- `native-bundle-control-boundaries-*`: six exposed-header cases plus two
  guarded-preheader fallbacks, with the exact source boundary accounted for.
- `native-bundle-control-proof-matrix-*`: 176 emitted slices proved across 34
  coupled cases and all four widths; supplied positive and wrong-constant
  counterexample controls run in the unit suite.
- `native-bundle-control-max-*`: original failed late-alias interaction;
  `native-bundle-control-max-closed-*`: both phases pass after its fix.
- `native-bundle-control-off-compat-*`: feature-disabled i32 seed4 full
  application-profile IR is byte-identical to the retained pre-control compiler.
- `native-bundle-control-byte-final-*`: all 65,536 byte pairs at two iterations,
  plus edges/random vectors, both phases, threads and matched normalized arms.
- `native-bundle-control-decompile-*`: five informed stripped Ghidra arms,
  599 two-output vectors each. C sizes for clean/native/post-O2/control-off/
  control-off-post-O2 are 844/58,021/26,176/56,209/24,471 bytes. Semantic recovery
  was not measured; these are only normalization diagnostics.

The broad and Ghidra matrices precede the narrow late-alias exclusion and use an
isolated flattening application filter; the final-plugin byte and max-profile
runs cover the rebuilt compiler. Final plugin:
`18e2f38e6116814b26b775db5f526efa5944b0d737dc8a16cf33cc098a42111e`.
The pinned unit suite passed 499 tests. No protected holdout or fresh-agent
evaluation is part of this increment.

Unchanged Lua (`v04-bundle-control-lua-20260918`) passes full-output, post-O2,
source-immutability and accounting gates at 237,151 IR instructions under the
unchanged 250,000 cap. All 552 bundle owners are inventoried, but there are zero
selected persistent loop regions and zero coupled control functions. Its six
straight-line bundle regions retain 50 source-ancestry operations; none is a new
control-binding gain. This is scale continuity, not broader feature coverage.
