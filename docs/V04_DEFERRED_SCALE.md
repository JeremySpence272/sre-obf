# Deferred v04 large-scale engineering

Per the user's direction on 2026-09-18, large-program conformance and scale
coverage issues are recorded here but are **not development blockers** for the
remaining v04 roadmap or the next crackme iteration. Do not run the large corpus
at every feature milestone. Keep targeted correctness, rollback, normalization
and recovery controls; a broken small-program transform is still a real failure.

This is a scheduling decision, not a claim that the deferred checks passed or
that large-program coverage is sufficient. Preserve the corpus lock, original
resource caps, failed artifacts and source/coverage denominators. Later large
runs must remain comparable; higher caps need separately labelled experiments.

## Retained issues and evidence

- The primary SQLite 250k-instruction lane previously exceeded the cap after
  fusion (282,760 instructions). Keep that failed primary result distinct from
  the separately labelled 1.5M-instruction lane. Allocation and growth engineering
  can be revisited after the next useful crackme iterations.
- The latest unchanged Lua run is `out/v04-bundle-control-lua-20260918`:
  conformance passes at 237,151 IR instructions under the 250k cap, with unchanged
  sources, post-O2 correctness and consistent accounting. It has **zero** new
  bundle-call input/output and persistent loop/control-binding coverage.
- Lua selected six straight-line bundle regions across five owners, covering
  50 unique input-ancestry operations. Every selected region's recurrence fallback
  is `not-natural-loop-header`. 539 owners lack a fitting multi-output region,
  five are structure/size skips, and three lose to the module-unit budget.
  Selection alone cannot make those regions meet the current loop contract.
- The most recent zlib continuity-selection measurement retained 249,659 IR
  instructions under the primary cap. Its private integer-interface eligibility
  and local joint-tile coverage remain limited. These are scale regressions,
  not evidence of generalization from untouched programs.
- Bzip2/cJSON have frozen clean IO contracts; protected holdout and generalization
  measurements remain unperformed. Do not tune on these programs to resolve the
  deferred engineering issues.

Revisit: broader safely proved loop/object shapes, cost-effective selection and
reservation, encoded pointer interfaces, source-weighted coverage, and unchanged
application resource distributions. Until then, label intermediate artifacts by
their implemented scope rather than advertising general-purpose scale readiness.
