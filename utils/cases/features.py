"""Feature gates: MBA-advanced and opaque-predicate families."""

from __future__ import annotations

import programs

from ._common import Registry, ann_extra


def register(reg: Registry, **_opts) -> None:
    reg.add(
        name="rt_mba_advanced", passes=["mba"],
        ann_override=ann_extra("mba_advanced"),
        gates=["mba_advanced"], category="feature",
    )
    # Correctness regression for the applyMBARecursive operand-freeze fix
    # (MBAUtils.cpp): feeds a poison-tainted i32 (oversized shl/lshr, per
    # LLVM's LangRef "Poison Values") into add/sub/and/or/xor binops that
    # MBA is free to rewrite/duplicate, at the strongest MBA preset. See
    # programs/mba_ops/poison_operand.c.tmpl for why the poison-derived
    # terms are kept out of the observable return value.
    reg.add(
        name="rt_mba_poison_operand", passes=["mba"],
        ann_override=ann_extra("mba_advanced"),
        src_override=programs.render(
            "mba_ops.poison_operand", annotation=ann_extra("mba_advanced")),
        gates=["mba_advanced"], category="feature",
    )
    reg.add(
        name="rt_opaque_families", passes=["flattening", "bcf"],
        ann_override=ann_extra("opaque_families"),
        gates=["opaque_families"], category="feature",
    )
