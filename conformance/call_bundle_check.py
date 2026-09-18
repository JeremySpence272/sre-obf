"""Private input continuity at the bundle-stage boundary, not hardness."""


def call_bundle_violations(report):
    if not report.get("features", {}).get("bundle_call_inputs", False):
        return ["disabled bundle-call inputs claim continuity"] if report.get("bundle_call_inputs") else []
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


def call_supply_violations(report):
    enabled = report.get("features", {}).get("bundle_call_outputs", False)
    errors, planned = [], {}
    for row in report.get("bundles", []) + report.get("object_bundles", []):
        plans = row.get("regions", []) if "regions" in row else ([row["plan"]] if "plan" in row else [])
        for plan in plans:
            n, reserve = plan.get("call_supply_uses", 0), plan.get("call_supply_reservation", 0)
            if type(n) is not int or n < 0 or type(reserve) is not int or reserve != n * 384 or (not enabled and n):
                errors.append("invalid bundle-call supply reservation")
                continue
            if n > plan.get("scalar_output_uses", 0): errors.append("bundle-call supplies exceed source boundary uses")
            if row["status"] == "encoded": planned[row["function"]] = planned.get(row["function"], 0) + n
    if not enabled:
        if report.get("bundle_call_outputs"): errors.append("disabled bundle-call outputs claim supplies")
        return errors
    if not report["features"].get("bundles") or not report["features"].get("encoded_calls"):
        errors.append("bundle call outputs require bundles and encoded calls")
    rows = report.get("bundle_call_outputs")
    if not isinstance(rows, list): return errors + ["missing bundle-call output inventory"]
    interfaces = {r.get("encoded_function"): r for r in report.get("encoded_calls", []) if r.get("status") == "encoded"}
    seen, observed, supplied = set(), {}, {}
    for row in rows:
        name, owner = row["function"], row["interface"]
        key = name, owner
        if key in seen or owner not in interfaces:
            errors.append("duplicate or unknown bundle-call supply owner")
            continue
        seen.add(key)
        if row.get("contract") != "bundle-call-supply-v1" or row.get("stage") != "after-bundles-before-regions":
            errors.append("unknown bundle-call supply contract")
        a, r = row.get("argument_pairs"), row.get("result_pairs")
        if type(a) is not int or type(r) is not int or a < 0 or r < 0 or not a + r:
            errors.append("invalid bundle-call supply counts")
            continue
        if r and name != owner: errors.append("bundle result credited to another interface")
        supplied[owner] = supplied.get(owner, 0) + a + r
        observed[name] = observed.get(name, 0) + a + r
    for owner, n in supplied.items():
        if n > interfaces[owner]["absorbed_results"]: errors.append("retained bundle-call supplies lost in final inventory")
    if {k: v for k, v in planned.items() if v} != observed:
        errors.append("retained bundle-call supplies differ from their owned reservations")
    return errors


def call_supply_summary(report):
    if not report.get("features", {}).get("bundle_call_outputs"): return None
    rows = report.get("bundle_call_outputs", [])
    return {"owners": len(rows), "stage": "after-bundles-before-regions", "hardness_evaluated": False,
            "argument_pairs": sum(r["argument_pairs"] for r in rows),
            "result_pairs": sum(r["result_pairs"] for r in rows)}
