"""IR-budget system tests (multiplier, verbose, exhaustion, hardcap).

Budget tests intentionally drive the pipeline into the `budget_exhausted`
skip path — that is the system under test. They allowlist the single
reason token rather than disabling strict-skip enforcement entirely so
unrelated regressions still surface.
"""

from __future__ import annotations

from ._common import Registry, ann_extra


_BUDGET_OK = {"budget_exhausted"}


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
