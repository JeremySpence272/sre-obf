"""Exact joint predicates: informed model, stage-local accounting, no hardness claim."""


def predicate(descriptor, state, carrier, targets, mode="all-equal"):
    if mode not in ("all-equal", "any-different") or not 2 <= len(targets) <= 4:
        raise ValueError("unsupported compound predicate")
    if any(type(k) is not int or not 0 <= k < len(state) or not 0 <= v <= descriptor.bits
           for k, v in targets.items()):
        raise ValueError("invalid target coordinate")
    # Independent specification uses a known-descriptor inverse; the emitter
    # never materializes these plaintext values at the predicate boundary.
    values = list(descriptor.decode(state, carrier))
    for k, value in targets.items(): values[k] = value
    expected = descriptor.encode(values, carrier)
    residuals = [a ^ b for a, b in zip(state, expected)]
    combined = 0
    for k, value in enumerate(residuals):
        if k:
            r, previous = descriptor.rotations[k], residuals[k - 1]
            residuals[k] = value ^ (((previous << r) | (previous >> (descriptor.width - r))) & descriptor.bits)
        combined |= residuals[k]
    return bool(combined) if mode == "any-different" else not combined


def predicate_violations(report):
    enabled = report.get("features", {}).get("bundle_predicates", False)
    errors, expected = [], {}
    sources = {r["function"]: r["instructions"] for r in report.get("bundle_input_inventory", [])}
    def check_origin(origin):
        if origin is None: return  # Generated comparisons remain unknown-source.
        name, number = origin.rsplit("/input-op/", 1)
        if name not in sources or not 0 <= int(number) < sources[name]:
            errors.append("predicate has invented input lineage")
    for row in report.get("bundles", []):
        for region in row.get("regions", []):
            plans = region.get("predicates", [])
            uses, reservation = region.get("predicate_operand_uses", 0), region.get("predicate_reservation", 0)
            if (type(uses) is not int or uses < 0 or type(reservation) is not int or
                    reservation != len(plans) * (512 + 256 * region["lanes"])):
                errors.append("predicate reservation does not match the plan")
            if len(plans) > 4 or (not enabled and plans): errors.append("unsupported or disabled predicate plan")
            counted = 0
            for index, plan in enumerate(plans):
                targets = plan["targets"]
                if (plan["id"] != index or not 2 <= len(targets) <= 4 or
                        plan["mode"] not in ("all-equal", "any-different") or
                        plan["law"] != "exact-tuple-replacement-v1" or
                        plan["source_operand_uses"] != len(targets) or
                        plan["tree_instructions"] != 2 * len(targets) - 1):
                    errors.append("unsupported exact predicate descriptor")
                check_origin(plan["input_origin"])
                outputs = set()
                for target in targets:
                    output = target["output"]
                    if (type(output) is not int or not 0 <= output < region["outputs"] or output in outputs):
                        errors.append("predicate repeats or invents an output")
                        continue
                    outputs.add(output)
                    if target["slot"] != region["output_slots"][output] or not 0 <= int(target["constant_hex"], 16) < 1 << region["width"]:
                        errors.append("predicate target differs from bundle output")
                    check_origin(target["input_origin"])
                counted += len(targets)
                if row["status"] == "encoded":
                    expected[(row["function"], f"{row['function']}/native-bundle/{region['id']}", index)] = len(targets)
            if uses != counted or uses + region.get("call_supply_uses", 0) > region.get("scalar_output_uses", 0):
                errors.append("predicate/source boundary denominator does not reconcile")
    if not enabled:
        return errors + (["disabled predicates claim emitted roots"] if report.get("bundle_predicates") else [])
    if not report["features"].get("bundles"): errors.append("joint predicates require bundles")
    rows = report.get("bundle_predicates")
    if not isinstance(rows, list): return errors + ["missing predicate emission inventory"]
    seen = set()
    for row in rows:
        key = row["function"], row["origin"], row["id"]
        if key in seen or key not in expected:
            errors.append("duplicate, rolled-back or unknown predicate root")
        seen.add(key)
        if (row.get("contract") != "joint-predicate-v1" or row.get("stage") != "after-bundles-before-regions" or
                row.get("hardness_evaluated") is not False or
                type(row.get("source_operand_uses")) is not int or row["source_operand_uses"] != expected.get(key) or
                type(row.get("live_consumers")) is not int or row["live_consumers"] <= 0):
            errors.append("invalid emitted predicate ownership or consumer count")
    if seen != set(expected): errors.append("retained predicate plan lacks emitted live roots")
    return errors


def predicate_summary(report):
    if not report.get("features", {}).get("bundle_predicates"): return None
    rows = report.get("bundle_predicates", [])
    regions = [p for r in report.get("bundles", []) if r["status"] == "encoded" for p in r.get("regions", [])]
    source = sum(r["scalar_output_uses"] for r in regions)
    absorbed = sum(r.get("predicate_operand_uses", 0) for r in regions)
    supplied = sum(r.get("call_supply_uses", 0) for r in regions)
    return {"roots": len(rows), "owners": len({r["function"] for r in rows}),
            "absorbed_data_uses": absorbed, "source_data_uses": source,
            "remaining_scalar_data_uses": source - absorbed - supplied,
            "live_boolean_consumers": sum(r["live_consumers"] for r in rows),
            "stage": "after-bundles-before-regions", "hardness_evaluated": False}
