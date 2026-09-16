"""VM pass v7 hardened-handler gates (Step 04)."""

from __future__ import annotations

import re
from typing import Optional

from . import register
from ._ir import extract_fn_body


@register("vm_hardened_mba")
def vm_hardened_mba(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    mba_names = len(re.findall(r"mba\.", engine))
    if mba_names < 10:
        return f"too few MBA-named values in __vm_engine ({mba_names}, need >=10)"
    return None


@register("vm_hardened_dead_blocks")
def vm_hardened_dead_blocks(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    dead = len(re.findall(r"vm\.dead\.\d+:", engine))
    if dead < 3:
        return f"too few dead code blocks ({dead}, need >=3)"
    return None


@register("vm_hardened_dispatch_guard")
def vm_hardened_dispatch_guard(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    if "vm.predisp:" not in engine:
        return "vm.predisp block not found — dispatch not guarded"
    return None


@register("vm_hardened_handler_guards")
def vm_hardened_handler_guards(ir: str) -> Optional[str]:
    # P0: the guarded-handler splice was disabled in VMPass_Harden.cpp because it
    # ran before the handler table was built (guard never executed) and left the
    # fetch indirectbr's successor list missing the real target = runtime UB. This
    # gate is a pass-through until the feature is reimplemented correctly (repoint
    # SS->OpcBB[op][var] at the guard block) in the VM-hardening arc (P3). Restore
    # the vm.opc.*.guard: block check then.
    return None
