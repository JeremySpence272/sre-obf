"""Private input continuity at the bundle-stage boundary, not hardness."""


def call_bundle_violations(report):
    if not report.get("features", {}).get("bundle_call_inputs", False): return []
    features = report["features"]
    errors = []
    if not features.get("bundles") or not features.get("encoded_calls"):
        errors.append("bundle call inputs require bundles and encoded calls")
    rows = report.get("bundle_call_inputs")
    if not isinstance(rows, list): return errors + ["missing bundle-call input inventory"]
    interfaces = {r.get("encoded_function"): r for r in report.get("encoded_calls", []) if r.get("status") == "encoded"}
    seen = set()
    for row in rows:
        name = row.get("function")
        if name in seen or name not in interfaces:
            errors.append(f"{name}: duplicate or non-encoded bundle-call owner")
            continue
        seen.add(name)
        if row.get("contract") != "bundle-call-input-v1" or row.get("stage") != "after-bundles-before-regions":
            errors.append(f"{name}: unknown bundle-call inventory contract")
        keys = ("imported_arguments", "fully_absorbed_arguments", "partially_absorbed_arguments", "remaining_scalar_uses")
        if any(type(row.get(k)) is not int or row[k] < 0 for k in keys):
            errors.append(f"{name}: invalid bundle-call counts")
            continue
        total, full, partial, uses = (row[k] for k in keys)
        interface = interfaces[name]
        if not total or total != full + partial or total > interface["encoded_parameters"]:
            errors.append(f"{name}: inconsistent bundle-call parameter denominator")
        if uses < partial or bool(uses) != bool(partial):
            errors.append(f"{name}: inconsistent bundle-call scalar uses")
        if full > interface["absorbed_arguments"] or total > interface["absorbed_arguments"] + interface.get("partially_absorbed_arguments", 0):
            errors.append(f"{name}: final interface lost retained bundle-input absorption")
    return errors


def call_bundle_summary(report):
    if not report.get("features", {}).get("bundle_call_inputs"): return None
    rows = report.get("bundle_call_inputs", [])
    return {"functions": len(rows), "stage": "after-bundles-before-regions", "hardness_evaluated": False,
            **{k: sum(r[k] for r in rows) for k in ("imported_arguments", "fully_absorbed_arguments",
                "partially_absorbed_arguments", "remaining_scalar_uses")}}
