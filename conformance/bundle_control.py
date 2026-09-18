"""Final shared-recurrence control contract and supplied-relation model.

Known-descriptor repair is an attacker control, never evidence of resistance.
"""
MASK = (1 << 32) - 1


def keys(key, salt, words, width):
    if width not in (8, 16, 32, 64) or len(words) not in (3, 4):
        raise ValueError("unsupported persistent control tuple")
    def rotate(x, n): return ((x << n) | (x >> (32 - n))) & MASK
    for i, word in enumerate(words):
        word &= (1 << width) - 1
        folded = (word & MASK) ^ (word >> 32) if width == 64 else word
        key = (key + (rotate(folded, 5 + 7 * i) ^ ((0x9e3779b9 * (i + 1)) & MASK))) & MASK
        salt = (salt ^ ((rotate(folded, 3 + 5 * i) + folded * (0x85ebca6b + 2 * i)) & MASK)) & MASK
    return key, salt


def bundle_control_violations(report):
    features = report.get("features", {})
    if not features.get("bundle_control"):
        return ["disabled bundle control claims coverage"] if report.get("bundle_control") else []
    errors = []
    if not all(features.get(k) for k in ("bundles", "bundle_loops", "multistate")):
        errors.append("bundle control requires persistent bundles and multi-state flattening")
    rows = report.get("bundle_control")
    if not isinstance(rows, list): return errors + ["missing bundle-control inventory"]
    bundles = {r["function"]: r for r in report.get("bundles", [])}
    seen = set()
    for row in rows:
        name = row["function"]
        if name in seen or name not in bundles:
            errors.append(f"{name}: duplicate or unknown control owner")
            continue
        seen.add(name)
        bundle = bundles[name]
        selected = [r for r in bundle.get("regions", []) if bundle["status"] == "encoded" and r.get("loop", {}).get("status") == "encoded"]
        if row.get("contract") != "persistent-bundle-control-v1" or row.get("stage") != "final-ir" or row.get("hardness_evaluated") is not False:
            errors.append(f"{name}: unknown or overstated control contract")
        if type(row.get("requested_regions")) is not int or row["requested_regions"] != len(selected):
            errors.append(f"{name}: recurrence denominator mismatch")
        if row["status"] == "unavailable":
            reason = "no-retained-complete-control-contract" if selected else "no-selected-persistent-loop"
            if (row["reason"] != reason or row["words"] != [] or row["bound_origin"] != "" or
                    any(type(row[k]) is not int or row[k] != 0 for k in ("useful_reads", "dispatcher_reads", "transition_reads"))):
                errors.append(f"{name}: unavailable control claims coupling")
            continue
        if row["status"] != "coupled" or row["reason"]:
            errors.append(f"{name}: incomplete retained control binding")
            continue
        region = next((r for r in selected if row["bound_origin"] == f"{name}/native-bundle/{r['id']}"), None)
        if region is None:
            errors.append(f"{name}: control origin is not a selected recurrence")
            continue
        roles = ["state0", "state1", "carrier"] + (["phase"] if region["loop"]["phase_mode"] == "two-phase" else [])
        words = row["words"]
        if [w["role"] for w in words] != roles: errors.append(f"{name}: incomplete or reordered recurrence words")
        for word in words:
            if word.get("width") != region["width"] or word.get("initialized_before_all_reads") is not True:
                errors.append(f"{name}: unproved word type or initialization")
            for key in ("useful_reads", "dispatcher_reads", "transition_reads", "data_store_sites"):
                if type(word.get(key)) is not int or word[key] <= 0:
                    errors.append(f"{name}: word lacks actual {key}")
            if type(word.get("unclassified_accesses")) is not int or word["unclassified_accesses"]:
                errors.append(f"{name}: unclassified shared-storage access")
        for key in ("useful_reads", "dispatcher_reads", "transition_reads"):
            if type(row.get(key)) is not int or row[key] != sum(w[key] for w in words):
                errors.append(f"{name}: inconsistent {key} count")
        for key in ("dispatcher_reads", "transition_reads"):
            if len({w[key] for w in words}) != 1: errors.append(f"{name}: control reads only part of the tuple")
    if seen != set(bundles): errors.append("bundle control omitted source owners")
    return errors


def bundle_control_summary(report):
    if not report.get("features", {}).get("bundle_control"): return None
    rows = report.get("bundle_control", [])
    coupled = [r for r in rows if r["status"] == "coupled"]
    return {"inspected_functions": len(rows), "requested_regions": sum(r["requested_regions"] for r in rows),
            "coupled_functions": len(coupled), "live_words": sum(len(r["words"]) for r in coupled),
            "stage": "final-ir", "hardness_evaluated": False,
            **{k: sum(r[k] for r in coupled) for k in ("useful_reads", "dispatcher_reads", "transition_reads")}}
