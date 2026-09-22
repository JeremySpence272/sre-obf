# v05 theoretical audit and proposed stronger revision

Date: 2026-09-22. Scope: design review of the initial runtime v05 plan against
the exact RevGame source and existing compiler contracts. This is not a dynamic
penetration test, a new model run or evidence of a measured hardness increase.
The revised requirements are in [NATIVE_V05_PLAN.md](NATIVE_V05_PLAN.md).

## Verdict

The initial plan improves on static-only protection but permits an expensive
implementation that still exposes a small reusable logical model. Its weakest
point is continuity: protecting storage is insufficient when computation,
comparison or a helper interface restores the values an observer needs.
Startup diversity and repeated phase changes do not fix that by themselves.

The proposed next tier therefore prioritizes complete, persistent computations
and their exact consumers. It adds release-code coverage requirements and
failure criteria before adding more diversity. This is a testable hypothesis,
not a claim that unlimited-budget analysis can be defeated.

## Evidence and limits

All 131 files in the packaged cell's `eval/protection/source-manifest.json`
were SHA-256 checked against `out/revgame-v4-release/source`; all matched.
The cell is `revgame/c-noopt-nosym-static-sre-obf-max-v04`. Binary hashes,
historical timings and run provenance remain in the main plan.

Source references below are relative to `out/revgame-v4-release/source/c/`.
These identify semantics and possible compiler boundaries. They do not establish
the exact shape of the final stripped machine code; the revised M0 explicitly
requires that additional check. Generated sources and emitted-code coverage
also require their own build provenance; matching the input manifest is not a
rebuild verification.

The original agent obtained D and investigated other checks before a platform
classifier error ended its run. That is an interrupted partial result, not a
measurement of the protection's ultimate ceiling.

## Source-informed findings

| Priority / finding | Evidence | Consequence and required response |
|---|---|---|
| P0: canonical comparison operands | `src/combat/combat.c:160` constructs two 32-byte arrays, derives the expected array and tests equality through `memcmp`. | Protected storage can still end in a compact semantic boundary. Include derivation, buffer history and exact comparison in the eligibility/coverage contract. Check emitted code before asserting where exposure remains. |
| P0: insufficient ownership coverage | `include/llvm/Transforms/Obfuscator/NativeBundle.h:16,33` in this repository describes four-cell local tiles and an eight-cell experiment. Game state includes persistent fields and a 32-byte history buffer. | Passing local fixtures does not show useful RevGame coverage. Require field-sensitive aggregate/global lifetime contracts and complete designated chains. |
| P1: checkpoint reuse | The threat model allows snapshots and repeated execution. A checkpoint retains representation context as well as application state. | Fresh startup keys do not invalidate observations within that checkpoint. Measure reuse within a process and across phases, not only fresh-process differences. |
| P1: small logical state | `src/gameloop/gameloop.c:1115` feeds a 16-state, 16-input room transition. | Representation changes leave the logical transition domain small. A larger physical state is not a larger game state; evaluate behavioral-model recovery and retain this limitation. |
| P1: compact arithmetic rule | `src/crafting/crafting.c:278` combines four predicates over item attributes; named recipes are considered first by the caller. | Algebraic complexity can disappear after semantic recovery. Protect the actual producer/consumer path where eligible, preserve recipe precedence, and avoid equating code size with rule complexity. |
| P1: narrow history-dependent relation | `src/gameloop/gameloop.c:616` uses a spell-history index, a monster attribute and player intelligence. | The useful relation may be much smaller than the surrounding game loop. Evaluate recovered summaries across valid changing inputs rather than only one long trace. |
| P1: fixed semantic target | `src/combat/combat.c:125` derives its byte target from fixed application constants. | Recovery can amortize across representation seeds. Per-process encoding cannot make that unchanged logical target different. Keep it unchanged and report transferability. |
| P1: projected predicate versus full recurrence | `src/gameloop/gameloop.c:2738` tests a low-byte relation, but faction/quest/status state updates mix wider bits. | Audit update histories and final consumers together. Do not assume only eight state bits matter, or claim an independent 1/256 success probability. |
| P1: production presence | The A event body at `src/gameloop/gameloop.c:1036` is under `VERIFIER`. | The production comparison may be eliminated. Track absent code separately; do not claim to protect a predicate merely because it appears in source or the verifier. |
| P1: concentrated runtime cost | Historical v04 is already about 5.213x clean. A full replay averages many different actions. | A passing aggregate can conceal an expensive selected operation. Require frozen operation-heavy and short/long workload gates as well as the full replay. |
| P2: optional serialization boundary | `src/save/save.c:767` serializes entropy state and history. `Makefile` excludes this subsystem from production; the CLI gates it with `SAVELOAD`. | This is not an established save-file shortcut in the shipped cell. Preserve exclusions and test them. For generalized save-enabled applications, acknowledge exposure required by the public format. |

P0 means a design gap that can invalidate the central protection claim; P1
means a material evaluation or implementation risk. These are review priorities,
not exploit severity ratings. Game labels and source locations are review-only
information and must never become compiler selectors or analyst prompt hints.

## What the stronger tier changes

1. **Select complete computations.** Inventory all producers, readers, writers,
   reset paths and exact consumers before expansion. Give every chain an explicit
   supported, incomplete, excluded or eliminated status. Reserve cost for the
   complete chain; partial transformation cannot be reported as full coverage.
2. **Support real state lifetimes.** Extend small local tiles to proved private
   fields, bounded buffers and internal persistent state. Maintain representation
   across admitted calls and application operations without canonical mirrors.
   Public output and unsupported aliases remain declared boundaries.
3. **Integrate exact consumers.** A bounded equality-only consumer can remain
   in the represented computation under a verified contract. Preserve exact
   semantics and all supported inputs; a probabilistic checksum is not a valid
   substitute. Audit other uses of the same values and final machine code.
4. **Compose useful operations before adding variants.** Compare bounded
   multi-operation interpretation with per-operation dispatch. Keep state across
   activations where proved safe. Only admit independently specified and tested
   representation families; mere identifier/key changes remain control arms.
5. **Spend budget on demonstrated gaps.** Prioritize lifetime and consumer
   continuity before more phases, and keep integrity optional. A costly layer
   removed by the same reusable semantic model does not justify its cost.

This extends existing ownership, transfer and rollback systems; it does not
require rewriting the game, selecting named eggs or virtualizing the entire
application. It also does not prohibit observation, alter gameplay, change the
save format, detect debuggers or rely on secrets remaining hidden in the process.

## Theoretical challenges that the candidate must survive

These are review/evaluation questions, not an automated extraction procedure.
Use the existing authorized local benchmark environment for future measurements.

| Challenge | Evidence against the proposed mechanism | Required reporting |
|---|---|---|
| Consumer continuity | Useful logical operands still appear together at an unaccounted helper or comparison boundary. | Mark the designated chain incomplete, or classify an unavoidable public exit explicitly. |
| Persistent coverage | A canonical object is reconstructed between calls or a second unprotected reader bypasses the representation. | Fail claimed continuity and identify the uncovered original use. |
| Context reuse | One recovered parameterized projection works after inexpensive fitting across phases or processes. | Count parameter fitting separately; do not call every new context a new recovery problem. |
| Interpreter normalization | A single compact handler summary explains all selected variants. | Report semantic reuse rather than opcode count or trace volume. |
| Behavioral equivalence | A small useful input/output model works without recovering encoded storage. | Count it as analysis success; full decompilation is unnecessary. |
| Performance isolation | Full replay passes but a frozen substantive operation-heavy workload reaches 20x. | Fail the candidate; averages cannot waive the workload gate. |
| Familiar-source contamination | Evaluator already has the rule or known valid replay. | Exclude from blinded discovery statistics; retain as compatibility/source-informed evidence. |

Neither the compiler nor evaluation should deliberately make the unchanged
application output less informative. Public behavior is an unavoidable channel.
No software-only plan here prevents reuse of a solution already known from source.

## Acceptance additions

- Freeze a recurrent-state chain and an exact fixed-buffer consumer chain in
  RevGame before tuning; both must achieve their complete supported contracts
  through generic selection. Require independent fixtures for the same features.
- Test positive and near-miss consumers, aliases, lifetimes, resets, mixed public
  fields, phases, private calls, rollback and release diagnostic exclusions.
- Keep strict total clean-relative slowdown below 20x for median and empirical
  paired p95. Keep under one second as the reference-host target, not a promise.
- Add concentrated-cost, timing-resolution and confirmation-block checks. At
  historical medians, the hard ceiling is about 3.84x v04 runtime and the absolute
  target about 1.43x; use fresh matched measurements for acceptance.
- Distinguish candidate readiness from protection improvement. The latter needs
  matched measured gains beyond ordinary slowdown, independent blinded trials
  and holdout transfer results. There is no justified numerical hardness rating
  or all-eggs failure prediction before those measurements.

## Work performed in this review

Read the initial plan, compiler interface, integration builder, exact cell
manifests and relevant challenge source. Verified the 131-file input manifest.
Revised the planning document and checked documentation consistency. No compiler
changes, new binaries, runtime benchmarks, analyst automation or paid evaluations
were performed. All new conformance tests described here remain planned work.
