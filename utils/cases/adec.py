"""Anti-decompiler pass tests."""

from __future__ import annotations

import programs

from ._common import Registry, ann_extra


def register(reg: Registry, **_opts) -> None:
    reg.add(name="rt_adec", passes=["adec"],
            gates=["adec_patterns"], category="adec")
    reg.add(name="rt_adec_full", passes=["adec"],
            ann_override=ann_extra("adec_full"),
            gates=["adec_patterns", "adec_type_confusion"], category="adec")
    reg.add(name="rt_adec_combo", passes=["mba", "bcf", "adec"],
            ann_override=ann_extra("adec_combo"),
            gates=["adec_patterns"], category="adec")
    reg.add(name="rt_adec_selective", passes=["adec"],
            ann_override=ann_extra("adec_selective"),
            gates=["adec_patterns"], category="adec")
    reg.add(name="rt_adec_flat", passes=["flattening", "adec"],
            ann_override=ann_extra("adec_with_flat"),
            gates=["adec_patterns"], category="adec")
    # Regression guard for the indirectBr fold-back bug: a single known
    # BlockAddress trampoline gets constant-propagated through the volatile
    # load and folded straight back to a direct branch under stock -O2,
    # silently erasing the "conversion". This case isolates indirectBr
    # (every other technique off, prob=100) on a function with several
    # unconditional-branch join points -- several of them PHI targets, via
    # ternaries that lower to two-predecessor phi joins even at -O0 -- so
    # both correctness (PHI incoming-edge fixup) and IR survival are
    # exercised. The "adec_indirectbr" gate only checks the pre-O2 IR
    # (indirectbr + blockaddress present); the harness's --o2-gate flag
    # checks obf-vs-base runtime output after -O2 but does not re-run IR
    # gates against the post-O2 .ll, so post-O2 survival of the indirectbr
    # itself is not asserted here -- verify that manually with
    # `opt -passes=default<O2>` on the emitted obf .ll when needed.
    _ann_ibr = ann_extra("adec_indirectbr_only")
    reg.add(name="rt_adec_indirectbr_phi", passes=["adec"],
            ann_override=_ann_ibr,
            src_override=programs.render("edge.indirectbr_phi", annotation=_ann_ibr),
            gates=["adec_indirectbr"], category="adec")
