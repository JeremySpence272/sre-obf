"""Stage-local runtime ownership accounting, distinct from candidate promotion."""

REASONS = {
    "unsupported-buffer-index", "unsupported-buffer-reset",
    "external-storage", "unsupported-storage-lifetime", "unsupported-initializer",
    "unsupported-load", "unsupported-store", "unmodeled-pointer-use", "unsupported-owner",
    "not-recurrent-storage", "unsupported-aggregate-or-width", "existing-constructor-order",
    "runtime-symbol-collision", "module-inline-assembly", "growth-reservation",
}


def runtime_violations(report):
    enabled = report.get("features", {}).get("runtime_state", False)
    state = report.get("runtime_state")
    if not enabled:
        return ["runtime report without enabled feature"] if state is not None else []
    if not isinstance(state, dict) or state.get("schema") != "sre-runtime-state-v1":
        return ["missing or unsupported runtime-state report"]
    errors = []
    status = state.get("status")
    if status not in ("encoded", "rolled-back", "no-eligible-storage"):
        errors.append("unknown runtime-state status")
    if state.get("hardness_evaluated") is not False or state.get("complete_chain_claim") is not False:
        errors.append("runtime experiment cannot claim measured hardness or complete chains")
    rows = state.get("objects")
    if not isinstance(rows, list):
        return errors + ["missing runtime object inventory"]
    names, encoded = set(), 0
    for row in rows:
        if not isinstance(row, dict):
            errors.append("malformed runtime object row")
            continue
        name = row.get("object")
        if not isinstance(name, str) or not name or name in names:
            errors.append("missing or duplicate runtime object identity")
        else:
            names.add(name)
        kind = row.get("status")
        if kind == "excluded":
            if row.get("reason") not in REASONS:
                errors.append("unknown runtime exclusion")
        elif kind in ("encoded", "rolled-back"):
            if kind != status:
                errors.append("object status disagrees with transaction")
            if row.get("width") not in (8, 16, 32, 64):
                errors.append("unsupported retained width")
            for field in ("source_loads", "source_stores"):
                if type(row.get(field)) is not int or row[field] < 1:
                    errors.append("missing original load/store evidence")
            if row.get("phase") != ("per-store" if state.get("phases") else "startup-only"):
                errors.append("phase contract mismatch")
            encoded += kind == "encoded"
        else:
            errors.append("unknown runtime object status")
    if status == "encoded" and encoded == 0:
        errors.append("encoded transaction with zero retained objects")
    if status in ("encoded", "rolled-back"):
        for key in ("instructions_before", "instructions_after", "growth_budget",
                    "retained_operations", "scalar_exit_uses", "exact_predicates"):
            if type(state.get(key)) is not int or state[key] < 0:
                errors.append("invalid runtime counter: " + key)
        if not errors:
            growth = state["instructions_after"] - state["instructions_before"]
            if growth > state["growth_budget"]:
                errors.append("runtime retained growth exceeds budget")
            if status == "rolled-back" and (growth or state["retained_operations"] or state["scalar_exit_uses"]):
                errors.append("runtime rollback did not restore its transaction")
            if status == "encoded" and state.get("closed_scalar_exits") is not (state["scalar_exit_uses"] == 0):
                errors.append("runtime boundary summary disagrees with scalar exits")
    return errors


def runtime_summary(report):
    state = report.get("runtime_state", {})
    return {
        "enabled": report.get("features", {}).get("runtime_state", False),
        "status": state.get("status", "disabled"),
        "retained_objects": sum(row.get("status") == "encoded" for row in state.get("objects", [])),
        "scalar_exit_uses": state.get("scalar_exit_uses"),
        "complete_chain_claim": False,
        "candidate_ready": False,
        "retained_buffers": sum(row.get("status") == "encoded" and row.get("cells", 1) > 1
                                for row in state.get("objects", [])),
        "interpreter_status": report.get("selective_interpreter", {}).get("status", "disabled"),
        "pending_contracts": [
            "general field-sensitive aggregates and complete private interfaces",
            "final-release continuity audit and independent analysis-resistance evaluation",
        ],
    }


def v05_violations(report):
    """Retained feature accounting; deliberately not a hardness certificate."""
    errors = []
    features = report.get("features", {})
    if features.get("runtime_buffers"):
        rows = report.get("runtime_state", {}).get("objects", [])
        owned = [r for r in rows if r.get("status") == "encoded" and r.get("cells", 1) > 1]
        if not owned:
            errors.append("RevGame v05 has no retained persistent buffer")
        for row in owned:
            if not 2 <= row["cells"] <= 64 or row.get("bounds_contract") != "defined-inbounds-element-access":
                errors.append("invalid persistent buffer contract")
            if type(row.get("source_resets")) is not int or row["source_resets"] < 0:
                errors.append("missing buffer reset accounting")
    if features.get("exact_consumers"):
        rows = report.get("exact_consumers", [])
        integrated = [r for r in rows if r.get("status") == "integrated"]
        if not integrated:
            errors.append("RevGame v05 has no retained exact consumer")
        for row in integrated:
            if row.get("complete_chain_claim") is not False or row.get("hardness_evaluated") is not False:
                errors.append("unsupported exact-consumer coverage claim")
            if row.get("exact_consumers", 0) < 1 or row.get("compared_bytes", 0) < 1:
                errors.append("empty exact-consumer integration")
    if report.get("vm"):
        state = report.get("selective_interpreter", {})
        if state.get("schema") != "sre-selective-interpreter-v1" or state.get("status") != "interpreted":
            errors.append("RevGame v05 has no retained interpreter region")
        else:
            if (state.get("anti_debug") is not False or state.get("bytecode_verifier") is not True or
                    state.get("hardness_evaluated") is not False or state.get("complete_chain_claim") is not False):
                errors.append("interpreter contract or claim mismatch")
            if state.get("original_instructions", 0) < 1:
                errors.append("interpreter has no original-operation evidence")
            if state["instructions_after"] - state["instructions_before"] > state["growth_budget"]:
                errors.append("interpreter exceeds growth budget")
    return errors
