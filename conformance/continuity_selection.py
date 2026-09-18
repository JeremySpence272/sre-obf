"""Bounded ownership-priority accounting; selection is not measured hardness."""


def continuity_violations(report):
    enabled = report.get("features", {}).get("continuity_priority", False)
    errors = []
    if enabled and not report.get("features", {}).get("bundles"):
        errors.append("continuity priority requires bundles")
    for row in report.get("connected_regions", []):
        value = row.get("continuity_selection")
        if not enabled:
            if value is not None: errors.append("continuity selection with feature disabled")
            continue
        if row.get("reason") == "structure-or-size":
            if value is not None: errors.append("unplanned structure claims continuity selection")
            continue
        name = row["function"]
        if value is None:
            errors.append(f"{name}: missing continuity inventory")
            continue
        def require(condition, message):
            if not condition: errors.append(f"{name}: {message}")
        require(value["contract"] == "sre-continuity-selection-v1", "unknown continuity policy")
        require(value["root_limit"] == 256 and value["joined_unit_limit"] == 8, "untracked continuity limits")
        keys = ("eligible_roots", "prioritized_roots", "selected_roots", "atomic_joins")
        if any(type(value[key]) is not int or value[key] < 0 for key in keys):
            errors.append(f"{name}: invalid continuity counts")
            continue
        require(value["prioritized_roots"] == min(value["eligible_roots"], 256), "root denominator mismatch")
        require(value["eligible_roots"] <= row["eligible_nodes"] and
                value["selected_roots"] <= value["prioritized_roots"] and
                value["atomic_joins"] <= value["prioritized_roots"], "invented continuity coverage")
        rolled = row.get("reason") == "connected-growth-rollback"
        require(value["scope"] == ("attempted-selection" if rolled else "retained-selection"), "rollback scope mismatch")
        count = row.get("attempted_nodes", 0) if rolled else row.get("nodes", 0)
        require(value["selected_roots"] <= count, "selected roots exceed emitted/attempted operations")
        require(value["hardness_evaluated"] is False, "selection claimed hardness")
    return errors


def continuity_summary(report):
    if not report.get("features", {}).get("continuity_priority"): return None
    rows = report.get("connected_regions", [])
    planned = [r["continuity_selection"] for r in rows if "continuity_selection" in r]
    return {"planned_functions": len(planned), "unplanned_functions": len(rows) - len(planned),
            "eligible_roots": sum(r["eligible_roots"] for r in planned),
            "prioritized_roots": sum(r["prioritized_roots"] for r in planned),
            "retained_selected_roots": sum(r["selected_roots"] for r in planned if r["scope"] == "retained-selection"),
            "rolled_back_selected_roots": sum(r["selected_roots"] for r in planned if r["scope"] == "attempted-selection"),
            "attempted_atomic_joins": sum(r["atomic_joins"] for r in planned),
            "scope": "planning priorities, not emitted consumer continuity or recovery resistance",
            "hardness_evaluated": False}
