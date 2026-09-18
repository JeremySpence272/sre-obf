# Offline native-bundle family policy v1

This is a bounded W6 implementation, not an empirical v04 promotion. It connects
an offline, measured Pareto selector to ordinary compiler planning. No solver or
model runs during compilation. No application names, constants, addresses or
answers are selection keys. Existing allocation, emission and rollback caps
are unchanged.

## Compiler contract

`-native-bundle-policy=/path/cache.json` requires `-native-bundles=1` and the
default `-native-transfer-family=seeded`. Shared conformance drivers expose
`--bundle-policy`. Explicit XOR/additive selection and the original seeded
policy remain independent ablations. An absent policy has no behavior change.

The cache has schema `sre-bundle-policy-v1`, an evidence-file SHA-256, and at
most 128 rules in a file of at most 64 KiB. Each rule matches exactly width,
logical lanes, operation count and pin setting. Its one or two candidates are
the existing revision-one `xor` and `additive` emitters. Unsupported fields,
versions, shapes, duplicate rules and unknown candidates fail explicitly.
Ties use a separate deterministic RNG fork and canonical candidate ordering.

Version one selects only straight pure bundle families. Persistent loop,
predicate, call-output and enabled call-input contracts use the original seeded
fallback; unmeasured shapes also fall back without changing their emitted IR.
It does not tune phase policies, object layouts or private ABIs yet. A shape
class is a coarse generalization across operations, not an equivalence class
of attack difficulty. Every selected or fallback decision carries cache and
evidence hashes and a reason in private provenance. No cache claims that the
current program has been attacked. The compiler validates configuration, not
the authenticity or empirical truth of an offline report.

## Offline acceptance and ranking

`python3 -m conformance.bundle_policy evidence.json --out fresh-directory`
exports `selection.json` and `policy.json`. The input fixes a training-only
protocol before measurements: cases, both candidates, attack routes and
compile/runtime/text caps. Selection rejects incomplete matrices, altered
protocols, duplicate or unfrozen observations, and holdout input. Every
candidate must pass correctness and accounting on every case, have a proved
clean recovery control, have conclusive candidate measurements, and stay within
all recorded resource limits. Sampled fits, unknown proofs, timeouts, missing
repair costs and unsupported states do not qualify.

The Pareto frontier uses attacker success, the cheapest measured mechanism plus
repair steps at the strongest successful recovery level, and worst measured
compile/runtime/text costs. Discovery is not scored. The report retains every
rejection and dominated candidate; ties remain available to seeded selection.
The selector cannot make measurements trustworthy merely by reading JSON; keep
the original artifacts and use the collection/provenance controls.

## Focused evidence, 2026-09-18

Compiler plugin SHA-256:
`bab1ea910e85ab8186c6f811d9cd86eed4dfee88dd7da5eff4d60a1b39b0a901`.

`conformance.policy_controls` produced six passing compiler arms in
`out/native-policy-controls-20260918`: off, forced cached additive, empty cache,
unmeasured shape, and both orderings of tied candidates. Full scalar outputs
match before and after stock O2. Emission and reports are deterministic. Empty
and unmatched policies preserve feature-off IR exactly. Eleven malformed
configurations are rejected. These deliberately synthetic caches test plumbing,
not hardness. All retained reports pass the shared provenance gate.

`conformance.policy_run` froze two easy eight-operation, two-output i32 training
computations, seed 1, and tested both families against direct binary lifting and
LLVM-O2-then-binary lifting. Both routes use the same angr/bit-vector grammar;
they are not independent solvers. Entry addresses are supplied. All clean
controls were fully summarized with verified equivalence. Protected outputs
match on 337 edge/random inputs. Evidence and failures are retained under
`out/native-policy-training-20260918`.

The additive affine arm and XOR bitwise arm were recovered. The other six
observations were inconclusive at the declared bounds. Text growth was
2.916–31.561x, exceeding the frozen 2x training cap in every arm. Runtime is a
median of three trusted I/O batches including startup, not a kernel benchmark.
The correct result is **zero admitted cache rules**, not a protection win and
not a reason to increase the caps. The combined candidate therefore keeps
seeded selection. The pinned unit/model suite passed all 538 tests.

## Remaining research

Measured pseudocode repair, cross-site summary transfer, additional independent
normalizers, context/phase/storage candidate policies and held-out Pareto gains
are still unestablished. Ghidra and existing descriptor/inverse controls remain
separate diagnostics. This increment provides a usable fail-closed selection
loop; it does not satisfy W6's held-out-improvement deliverable or M7 promotion.
Large-program work is tracked in `V04_DEFERRED_SCALE.md` and is not a blocker
for continuing the combined crackme iteration.
