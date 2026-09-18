# Bounded continuity-first selection

`-native-continuity-priority=1` / `--continuity-priority` requires native bundles
and remains default-off. This is a deterministic engineering selection policy,
**not completion of W6's attack-guided candidate-library research or v04**.

The motivation is a measured gap: joint immutable backing passed correctness
and encoding gates in zlib/Lua, yet no eligible read's scalar fallback disappeared.
The connected importer worked in isolated tests; it often lost the consumer
selection contest under real application budgets.

## Policy and limits

Roots are supported original-graph operations consuming an existing immutable
coordinate interface or validated private-call argument pair, plus loads from
proved closed memory objects. Nothing matches application names or data values.
The planner inspects every candidate, records all roots, and prioritizes at most
the first 256 in stable IR order.

Root-bearing components rank before ordinary components, with the existing
benefit/cost ordering within those classes. They may use the existing semantic
reserve; the function/module cap is unchanged. A complete fitting component
still wins as a complete component.

When a component needs shards, all loads of one closed memory object still form
an indivisible unit. Each prioritized root may join one actual candidate
consumer, choosing smallest estimated operation cost and then original IR
position. Such joins cannot produce a unit larger than eight nodes. Existing
larger memory units remain intact; the eight-node rule is not permission to
split them. Priority units rank first, with density and stable-order ties.
Units too large for a shard or remaining allowance are lost whole, with existing
node/cost loss accounting. No emitter hoists or speculates source work.

`continuity_selection` reports eligible/prioritized/selected roots, attempted
atomic joins and the limits. Function growth rollback preserves the inventory
as `attempted-selection`, not retained coverage. Actual scalar-use elimination
is measured separately by the immutable/call boundary inventories.

The non-priority path preserves its previous unit order and output. Both prior
large-corpus protected IR artifacts were re-emitted byte-identically after the
refactor, rather than relying only on unit tests of the policy.

## Evidence

Compiler plugin:
`156bbc4c82daf0450a3b5973df12a762a2ed1b2ea46a2bc7d555ed439bf61d4b`.

- `out/continuity-priority-bounded-20260918`: eight i8/i32 cases, N=5, seed4,
  four-node shards with pure bundles deliberately excluded. Partial boundary
  counts, all outputs, post-O2, threads and deterministic builds pass. Byte
  inputs are exhaustive; selected priority units and actual absorption required.
- `out/continuity-priority-additive-backing-20260918`: four i16/i64 cases,
  seed3 additive backing and mixed XOR/additive connected regions under the
  same four-node selection cap; complete-output controls pass.
- `out/continuity-off-scale-reemit-20260918`: previous zlib AND Lua protected
  IR hashes unchanged with the policy disabled; current accounting gates pass.
- `out/v04-continuity-priority-zlib-20260918` and `...-lua-20260918`: unchanged
  workloads, post-O2 and accounting pass at the original 250k cap. These are
  tuning regressions, not fresh holdout evidence.
- Full solver-enabled unit suite: 464 tests, no skips, PASS (86.184 seconds).

| Regression | Prior final IR | Priority final IR | Immutable scalar-use edges removed (off → on) |
|---|---:|---:|---:|
| zlib | 239,337 | 249,659 | 0 → 2 of 83 |
| Lua | 236,694 | 236,685 | 0 → 4 of 85 |

This is modest nonzero consumer continuity, not broad memory coverage or a
recovery-cost improvement. Persistent pure-bundle absorption remains zero in
those two scale runs; the improvement is through the connected encoder. No
local joint tiles were newly admitted, no cap was increased, and no protected
holdout, fresh-agent evaluation or preset promotion occurred.
