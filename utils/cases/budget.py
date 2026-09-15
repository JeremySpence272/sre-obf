"""IR-budget system tests (multiplier, verbose, exhaustion, hardcap).

Budget tests intentionally drive the pipeline into the `budget_exhausted`
skip path — that is the system under test. They allowlist the single
reason token rather than disabling strict-skip enforcement entirely so
unrelated regressions still surface.
"""

from __future__ import annotations

from ._common import Registry, ann_extra, render_budget_recursive_flatten_program


_BUDGET_OK = {"budget_exhausted", "budget_rollback"}

# Strong flattening + a tight per-annotation hard cap (budgetMax=200): the
# transactional rollback gate keys off Cfg.budgetHardCap (the *annotation*
# override), not the CLI-only --obf-ir-budget-max fallback, so the cap must
# be carried in the annotation itself for the driver's snapshot/restore path
# to actually engage. flattening does not read the IR budget at all, so on
# a recursive+branchy obf_target it reliably blows past 200 instructions in
# a single invocation, forcing the driver to roll the function back.
_ROLLBACK_ANN = (
    "obf: flattening(prob=100,budgetMax=200,budgetMultiplier=100,"
    "minBlocks=2,maxBlocks=2000,opaqueState=1,fakeTransitions=1,"
    "fakeCases=4,domain=1,ptr=1,alias=1)"
)


def register(reg: Registry, **_opts) -> None:
    reg.add(
        name="rt_budget_low", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=8"],
        gates=["budget_clamped_8"], category="budget",
        expect_no_skips=True, allowed_skip_reasons=_BUDGET_OK,
    )
    reg.add(
        name="rt_budget_verbose", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=20", "--obf-verbose"],
        gates=["budget_verbose"], category="budget",
        expect_no_skips=True, allowed_skip_reasons=_BUDGET_OK,
    )
    # Deterministically drives the driver's hard budget-skip path. The
    # budget-aware passes (mba/bcf/substitution) self-throttle to hug the
    # limit from *below*, so exhaustion only ever fired via a fragile granular
    # overshoot that was sensitive to exact instruction counts. Instead:
    # mba throttles under the 256 hard cap, then `split` (which does not read
    # the budget) expands past it, so the driver skips `bcf` with
    # `budget_exhausted`. Robust across seeds and to small per-pass count
    # changes (e.g. the MBA operand-freeze fix in MBAUtils.cpp).
    reg.add(
        name="rt_budget_exhaust", passes=["mba", "split", "bcf"],
        ann_override="mba(prob=100,depth=3,maxSites=300), "
                     "split(num=8), bcf(prob=100,loop=2)",
        extra_opts=["--obf-ir-budget-multiplier=100", "--obf-ir-budget-max=256",
                    "--obf-verbose"],
        gates=["budget_exhaustion"], category="budget",
        expect_no_skips=True, allowed_skip_reasons=_BUDGET_OK,
    )
    reg.add(
        name="rt_budget_unlimited", passes=["mba", "bcf"],
        extra_opts=["--obf-ir-budget-multiplier=0"], category="budget",
        expect_no_skips=True,
    )
    reg.add(
        name="rt_budget_hardcap", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=100", "--obf-ir-budget-max=2000"],
        gates=["budget_hardcap_2000"], category="budget",
        expect_no_skips=True, allowed_skip_reasons=_BUDGET_OK,
    )
    # Exercises the transactional (snapshot + rollback) hard-cap enforcement:
    # flattening ignores the IR budget entirely, so on a recursive+branchy
    # obf_target it overshoots the tight annotation-level budgetMax=200 in
    # one shot. The driver must detect the overshoot after the pass runs,
    # roll the function back to its pre-pass body, and record the pass as
    # skipped with reason "budget_rollback" -- rather than merely catching
    # the overshoot late (one pass too late) via the pre-pass exhaustion
    # check. budget_exhaustion greps stderr for "skipping", which the
    # ROLLBACK verbose line also contains.
    reg.add(
        name="rt_budget_rollback", passes=["flattening"],
        ann_override=_ROLLBACK_ANN,
        src_override=render_budget_recursive_flatten_program(_ROLLBACK_ANN),
        extra_opts=["--obf-ir-budget-multiplier=100", "--obf-ir-budget-max=200",
                    "--obf-verbose"],
        gates=["budget_exhaustion"], category="budget",
        expect_no_skips=True, allowed_skip_reasons=_BUDGET_OK,
    )
