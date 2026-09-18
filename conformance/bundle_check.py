"""Common fail-closed accounting gate for authoritative native bundle schedules."""
from conformance.bundle_model import Descriptor, OPCODES


def bundle_summary(report):
    """Stage-local work and unique input ancestry, never whole-program protection."""
    if not report.get("features", {}).get("bundles"):
        return None
    rows = report["bundles"]
    retained = [r for r in rows if r["retained_operations"]]
    steps = [step for r in retained for region in r["regions"] for step in region["steps"]]
    ancestry = {s["input_origin"] for s in steps if s["input_origin"] is not None}
    sources = report["bundle_input_inventory"]
    loops = [region["loop"] for r in retained for region in r["regions"]
             if region.get("loop", {}).get("status") == "encoded"]
    return {"functions": len(retained), "regions": sum(len(r["regions"]) for r in retained),
            "input_ir_instructions": sum(s["instructions"] for s in sources),
            "input_eligible_pure_operations": (sum(s["eligible_pure_operations"] for s in sources)
                if all("eligible_pure_operations" in s for s in sources) else None),
            "pre_bundle_eligible_operations": sum(r["eligible_operations"] for r in rows),
            "retained_step_instances": len(steps), "retained_unique_input_ancestry_ids": len(ancestry),
            "retained_steps_without_input_ancestry": sum(s["input_origin"] is None for s in steps),
            "rolled_back_step_instances": sum(r.get("rolled_back_operations", 0) for r in rows),
            "reserved_growth": sum(r["growth_allocation"] for r in rows),
            "persistent_backedges": len(loops),
            "encoded_recurrence_uses": sum(loop["backedge_uses"] for loop in loops),
            "two_phase_backedges": sum(loop["phase_mode"] == "two-phase" for loop in loops),
            "actual_growth": sum(max(0, r["instructions_after"] - r["instructions_before"]) for r in rows),
            "final_surviving_semantic_coverage": None,
            "scope": "pre-bundle operation instances and deduplicated input-IR ancestry; "
                     "ancestry reach is not full source-operation protection or decompiler survival"}


def bundle_violations(report):
    errors = []
    enabled = report.get("features", {}).get("bundles", False)
    if not enabled:
        if report.get("bundles"):
            errors.append("bundle rows exist with feature disabled")
        return errors
    if "bundle_input_inventory" not in report or "bundles" not in report:
        return ["enabled bundle inventory is missing"]
    sources = {r["function"]: r["instructions"] for r in report["bundle_input_inventory"]}
    limits = {row["module_growth_limit"] for row in report["bundles"] if "module_growth_limit" in row}
    if limits:
        if len(limits) != 1 or any("module_growth_limit" not in row for row in report["bundles"]):
            errors.append("bundle owners disagree on the module reservation")
        elif sum(row["growth_allocation"] for row in report["bundles"]) > next(iter(limits)):
            errors.append("whole-region allocations exceed the shared module budget")
    seen = set()
    for row in report["bundles"]:
        name = row["function"]
        if name in seen: errors.append(f"{name}: duplicate bundle owner")
        seen.add(name)
        if row["schema"] != "sre-bundle-plan-v1":
            errors.append(f"{name}: unsupported bundle schema")
            continue
        eligible = row["eligible_operations"]
        retained = row["retained_operations"]
        for key in ("eligible_operations", "retained_operations", "growth_allocation", "instructions_before", "instructions_after"):
            if type(row[key]) is not int or row[key] < 0:
                errors.append(f"{name}: invalid nonnegative counter {key}")
        if row["growth_allocation"] > 65536:
            errors.append(f"{name}: function reservation exceeds its hard cap")
        if row.get("reason") == "structure-or-size":
            if retained or row["instructions_after"] != row["instructions_before"]:
                errors.append(f"{name}: skipped body claims bundle coverage")
            continue
        if eligible != retained + row["unselected_operations"] + row["rolled_back_operations"]:
            errors.append(f"{name}: operation denominator does not reconcile")
        selected = sum(r["useful_operations"] for r in row["regions"])
        if selected != row["attempted_operations"]:
            errors.append(f"{name}: schedule total differs from selected operations")
        rolled = row["status"] == "rolled-back"
        if retained != (0 if rolled else selected) or row["regions_scope"] != ("attempted" if rolled else "retained"):
            errors.append(f"{name}: attempted and retained coverage conflated")
        if row["estimated_cost"] != sum(r["estimated_cost"] for r in row["regions"]):
            errors.append(f"{name}: estimated costs differ from owned regions")
        if row["estimated_cost"] > row["growth_allocation"]:
            errors.append(f"{name}: schedule exceeds its reserved budget")
        if row["instructions_after"] > row["instructions_before"] + row["growth_allocation"]:
            errors.append(f"{name}: retained growth exceeds allocation")
        if rolled and row["instructions_after"] != row["instructions_before"]:
            errors.append(f"{name}: rollback did not restore the body")
        for index, region in enumerate(row["regions"]):
            Descriptor.from_plan(region)
            lanes, width = region["lanes"], region["width"]
            descriptor = region.get("representation")
            if descriptor is not None:
                if (f"{descriptor['family']}-v{descriptor['revision']}" != region["family"] or
                        descriptor["physical_lanes"] != lanes + 1 or
                        descriptor["logical_width"] != width or descriptor["lane_width"] != width or
                        descriptor["verification"] != "algebraic" or not descriptor["seed_namespace"]):
                    errors.append(f"{name}: typed descriptor and lowering schedule disagree")
            if region["id"] != index or len(region["salts_hex"]) != lanes:
                errors.append(f"{name}: noncanonical descriptor identity")
            if not 2 <= region["inputs"] <= lanes or not 2 <= region["outputs"] <= lanes:
                errors.append(f"{name}: bundle lacks multiple real inputs/outputs")
            if not 8 <= len(region["steps"]) <= 32 or len(region["steps"]) != region["useful_operations"]:
                errors.append(f"{name}: invalid combined transfer length")
            if len(region["output_slots"]) != region["outputs"] or len(set(region["output_slots"])) != region["outputs"]:
                errors.append(f"{name}: output ownership mismatch")
            for slot in region["output_slots"]:
                if not 0 <= slot < lanes: errors.append(f"{name}: invalid output slot")
            errors.extend(loop_violations(region, row, report.get("features", {}), name))
            for step in region["steps"]:
                if step["opcode"] not in OPCODES or not 0 <= step["destination"] < lanes:
                    errors.append(f"{name}: unsupported transfer")
                for op in (step["x"], step["y"]):
                    if set(op) == {"slot"}:
                        if not 0 <= op["slot"] < lanes: errors.append(f"{name}: invalid input slot")
                    elif set(op) == {"constant_hex"}:
                        if not 0 <= int(op["constant_hex"], 16) < 1 << width:
                            errors.append(f"{name}: out-of-width constant")
                    else: errors.append(f"{name}: invalid operand descriptor")
                if step["opcode"] in ("shl", "lshr", "ashr"):
                    if "constant_hex" not in step["y"] or not 0 <= int(step["y"]["constant_hex"], 16) < width:
                        errors.append(f"{name}: shift is variable or poison")
                if step["input_origin"] is not None:
                    owner, number = step["input_origin"].rsplit("/input-op/", 1)
                    if owner not in sources or not 0 <= int(number) < sources[owner]:
                        errors.append(f"{name}: invented input lineage")
    return errors


def loop_violations(region, row, features, name):
    loop = region.get("loop")
    enabled = features.get("bundle_loops", False)
    phases = features.get("bundle_phases", False)
    errors = []
    if phases and not enabled:
        errors.append(f"{name}: phases enabled without loops")
    if loop is None:
        return errors + ([f"{name}: missing recurrence report"] if enabled else [])
    if row.get("loops", False) != enabled or row.get("phases", False) != phases:
        errors.append(f"{name}: recurrence options disagree with feature report")
    if loop["status"] == "encoded":
        mapping = loop["next_input_slots"]
        if (not enabled or loop["reason"] or loop["law"] != "triangular-recurrence-rebase-v1" or
                len(mapping) != region["inputs"] or loop["backedge_uses"] != len(mapping) or
                any(k not in region["output_slots"] for k in mapping) or loop["scalar_input_uses"] != 0):
            errors.append(f"{name}: invalid persistent recurrence contract")
        if (loop["phase_mode"] != ("two-phase" if phases else "static") or
                loop["phase_count"] != (2 if phases else 1) or loop["initial_phase"] != 0):
            errors.append(f"{name}: finite phase graph disagrees with lowering options")
    elif loop["status"] == "straight-line":
        reasons = {"disabled", "not-single-block-self-loop", "requires-unconditional-preheader",
                   "input-is-not-header-recurrence", "recurrence-has-external-users",
                   "backedge-is-not-region-output"}
        if (loop["next_input_slots"] or loop["backedge_uses"] or not loop["reason"] or
                loop["phase_mode"] != "static" or loop["phase_count"] != 1 or
                loop["initial_phase"] != 0 or loop["scalar_input_uses"] != 0 or
                loop["reason"] not in reasons or (loop["reason"] == "disabled") == enabled):
            errors.append(f"{name}: fallback claims persistent state")
    else:
        errors.append(f"{name}: unknown recurrence status")
    return errors
