"""Fail-closed ownership, exposure and cost accounting for bounded local tiles.

These are stage-local contracts, not decompiler survival or hardness scores.
"""
from collections import Counter

from conformance.bundle_model import Descriptor, OPCODES

SKIPS = {
    "existing-owner", "requires-small-flat-integer-array", "unsupported-width",
    "unsupported-pointer-layout", "unproved-index", "derived-pointer",
    "partial-volatile-or-atomic-access", "lifetime-not-supported",
    "pointer-escape-or-observation", "unreachable-access", "memory-access-limit",
    "requires-complete-entry-initialization", "initialization-does-not-dominate",
    "no-loads", "operation-limit", "no-useful-encoded-update", "function-cost-limit",
    "function-structure-or-size", "one-object-per-function", "module-unit-budget",
    "requires-root-lifetime-marker", "requires-single-entry-lifetime",
    "unreachable-lifetime-marker", "lifetime-end-limit",
    "lifetime-start-does-not-dominate", "access-after-lifetime-end",
    "repeated-lifetime-end", "unaligned-or-unbounded-byte-offset",
    "requires-single-private-borrow", "unproved-private-borrow", "unsupported-borrow-signature",
    "unsupported-borrow-effect", "borrow-lifetime-not-supported", "borrow-no-useful-update",
}


def tile_violations(report):
    errors = []
    enabled = report.get("features", {}).get("object_bundles", False)
    if not enabled:
        if report.get("features", {}).get("object_phases"): return ["object phases require object bundles"]
        if report.get("features", {}).get("object_max_cells", 4) != 4: return ["wide tiles require object bundles"]
        if report.get("features", {}).get("object_calls"): return ["object calls require object bundles"]
        if report.get("features", {}).get("object_retained_growth", 65536) != 65536: return ["object growth ceiling requires object bundles"]
        return ["tile rows exist with feature disabled"] if report.get("object_bundles") else []
    if not report.get("features", {}).get("bundles") or "object_bundles" not in report:
        return ["enabled tiles require bundles and an object inventory"]
    contract = report.get("features", {}).get("object_bundle_contract", 1)
    if type(contract) is not int or contract not in (1, 2, 3, 4, 5): return ["unsupported object bundle contract"]
    features = report.get("features", {})
    calls = features.get("object_calls", False)
    ceiling = features.get("object_retained_growth", 65536 if contract < 5 else None)
    if type(calls) is not bool or (calls and contract < 5): return ["invalid object-call policy"]
    if type(ceiling) is not int or not 1 <= ceiling <= 65536 or (contract < 5 and ceiling != 65536):
        return ["invalid object retained-growth policy"]
    max_cells = report.get("features", {}).get("object_max_cells", 4 if contract < 4 else None)
    if type(max_cells) is not int or max_cells not in (4, 8) or (contract < 4 and max_cells != 4):
        return ["missing or unsupported tile shape ceiling"]
    phases = report.get("features", {}).get("object_phases", False)
    if type(phases) is not bool or (phases and contract < 3): return ["invalid object phase feature"]
    rows = report["object_bundles"]
    sources = {r["function"]: r["instructions"] for r in report.get("bundle_input_inventory", [])}
    seen, owners, limits, allocated = set(), set(), set(), 0
    for row in rows:
        name = f'{row["function"]}:object-{row["object"]}'
        def require(condition, message):
            if not condition: errors.append(f"{name}: {message}")
        require(name not in seen, "duplicate object")
        seen.add(name)
        require(row["schema"] == "sre-object-bundle-v1", "unknown schema")
        for key in ("object", "growth_allocation", "module_growth_limit", "attempted_operations",
                    "retained_operations", "rolled_back_operations"):
            require(type(row[key]) is int and row[key] >= 0, f"invalid {key}")
        limits.add(row["module_growth_limit"])
        allocated += row["growth_allocation"]
        attempted, retained, lost = (row[k] for k in
                                    ("attempted_operations", "retained_operations", "rolled_back_operations"))
        require(attempted == retained + lost, "attempted/retained/rollback mismatch")
        require(row["hardness_evaluated"] is False, "engineering gate claimed hardness")
        require(type(row["pins"]) is bool, "invalid pin mode")
        if contract >= 4:
            require(type(row.get("max_cells")) is int and row["max_cells"] == max_cells,
                    "object shape ceiling differs from policy")
        if row["status"] == "skipped":
            require(row["reason"] in SKIPS, "unknown fallback")
            require(attempted == retained == lost == row["growth_allocation"] == 0, "skipped work credited")
            require("plan" not in row, "skipped object has executable plan")
            if contract >= 5: require(row.get("retained_growth_limit") == 0, "skipped object has a retention allowance")
            continue
        require(row["status"] in ("encoded", "rolled-back"), "unknown disposition")
        require(row["function"] not in owners, "multiple selected objects in one owner")
        owners.add(row["function"])
        plan = row["plan"]
        closed = plan.get("closed_call")
        if closed is not None:
            require(calls and closed.get("contract") == "sole-private-leaf-borrow-v1", "unrequested or unknown private borrow")
            callee = closed.get("callee")
            require(closed.get("caller") == row["function"] and isinstance(callee, str) and
                    bool(callee) and callee != row["function"], "invalid borrow owners")
            require(callee not in owners, "callee belongs to multiple object transactions")
            owners.add(callee)
            require(type(closed.get("pointer_argument")) is int and closed["pointer_argument"] >= 0 and
                    closed.get("direct_sites") == 1, "invalid private pointer interface")
            require(closed.get("proof") == "sole-use-leaf-single-pointer-closed-accesses-initialization-dominates-call",
                    "missing borrowing proof")
            require(type(closed.get("callee_operations")) is int and 4 <= closed["callee_operations"] <= len(plan["steps"]),
                    "no useful encoded update in borrower")
        try:
            desc = Descriptor.from_plan(plan, max_lanes=max_cells)
        except (KeyError, TypeError, ValueError):
            errors.append(f"{name}: invalid bounded tile descriptor")
            continue
        n = plan["cells"]
        require(desc.width in (8, 16, 32, 64) and 2 <= n <= max_cells and len(desc.salts) == n, "invalid shape")
        require(sorted(plan["physical_slots"]) == list(range(n)), "non-bijective layout")
        require(plan["law"] == "closed-initialized-tile-v1" and
                plan["phase_mode"] == ("store-toggle-v1" if phases else "static"), "unknown law")
        require(plan["ownership"] == ("closed-private-borrow" if closed else "closed-entry-alloca") and
                plan["initialization"] == ("complete-entry-stores-dominate-accesses-and-call" if closed else
                                          "complete-entry-stores-dominate-accesses"), "missing ownership proof")
        accesses = plan["accesses"]
        if closed:
            require(closed.get("layout_words") == n + 1 + int(phases), "borrowed layout disagrees with storage")
            require(all(a.get("function") in (row["function"], callee) for a in accesses) and
                    any(a.get("function") == callee and a["kind"] == "store" for a in accesses), "invalid borrowed accesses")
            require(all(a.get("function") == row["function"] for a in accesses if a["initializer"]), "callee initializes private backing")
        modern = contract >= 2
        if modern:
            require("lifetime" in plan, "missing lifetime contract")
            require(all("elements" in a for a in accesses), "missing access spans")
            require(all(k in plan for k in ("vector_output_values", "vector_output_uses", "decoded_vector_lanes")),
                    "missing vector boundary accounting")
        life = plan.get("lifetime")
        if life is not None:
            require(life["contract"] == "sre-tile-lifetime-v1" and life["proof"] ==
                    "start-dominates-accesses-no-access-or-marker-reachable-after-end", "unknown lifetime proof")
            for key in ("source_starts", "source_ends", "translated_markers"):
                require(type(life[key]) is int and life[key] >= 0, f"invalid lifetime {key}")
            starts, ends = life["source_starts"], life["source_ends"]
            require(life["translated_markers"] == starts + ends, "lifetime markers lost")
            require((life["mode"] == "whole-function" and starts == ends == 0) or
                    (life["mode"] == "single-entry" and starts == 1 and 0 <= ends <= 8),
                    "unsupported lifetime shape")
        initial = [a for a in accesses if a["initializer"]]
        require(len(initial) == n and sorted(a["index"] for a in initial) == list(range(n)),
                "incomplete or duplicate initialization")
        require(initial == accesses[:n] and all(a["kind"] == "store" for a in initial),
                "read/update precedes initialization")
        for a in accesses:
            span = a.get("elements", 1)
            require(type(span) is int and 1 <= span <= n, "invalid element span")
            require(span == 1 or (a["kind"] == "load" and a["index"] is not None and
                                 0 <= a["index"] and a["index"] + span <= n and not a["initializer"]),
                    "unproved vector span")
            require(a["kind"] in ("load", "store"), "invalid memory operation")
            require(type(a["initializer"]) is bool, "invalid initializer marker")
            if a["index"] is None:
                require(a["bounds"] == "known-bits-nonnegative-in-range", "unproved dynamic index")
            else:
                require(type(a["index"]) is int and 0 <= a["index"] < n and a["bounds"] == "constant",
                        "invalid constant index")
        loads = sum(a["kind"] == "load" for a in accesses)
        stores = len(accesses) - loads
        require(loads > 0 and stores > n and len(accesses) <= 64, "no bounded useful memory update")
        require(plan["source_loads"] == loads and plan["source_stores"] == stores, "memory denominator mismatch")
        require(plan["dynamic_accesses"] == sum(a["index"] is None for a in accesses), "dynamic count mismatch")
        lanes = n + 1 + int(phases)
        require(plan["physical_loads"] == (loads + stores - n) * lanes, "extra-read accounting mismatch")
        require(plan["physical_stores"] == (1 + stores - n) * lanes, "write accounting mismatch")
        if contract >= 3:
            require(plan.get("phase_contract") == {
                "states": 2 if phases else 1, "entry": 0,
                "transition": "toggle-after-update" if phases else "identity",
                "carrier": "history-and-encoded-update-v1" if phases else "entry-only",
                "layout": "rotate-logical-slots-by-phase" if phases else "seeded-permutation",
                "static_update_sites": stores - n if phases else 0,
                "bytes_reencoded_per_update": lanes * desc.width // 8 if phases else 0},
                "missing or inconsistent phase contract")
        for key in ("scalar_input_values", "scalar_output_values", "scalar_output_uses", "scalar_address_uses"):
            require(type(plan[key]) is int and plan[key] >= 0, f"invalid {key}")
        require(plan["scalar_output_uses"] >= plan["scalar_output_values"] and
                plan["scalar_output_uses"] >= plan["scalar_address_uses"], "exposure accounting mismatch")
        vector_reads = [a for a in accesses if a.get("elements", 1) > 1]
        require(plan.get("vector_output_values", 0) == len(vector_reads) and
                plan.get("decoded_vector_lanes", 0) == sum(a["elements"] for a in vector_reads),
                "vector exposure accounting mismatch")
        uses = plan.get("vector_output_uses", 0)
        require(type(uses) is int and uses >= 0 and (bool(vector_reads) or uses == 0), "invalid vector use count")
        require(4 <= len(plan["steps"]) <= 32 and attempted == len(plan["steps"]), "operation accounting mismatch")
        require(all(s["opcode"] in OPCODES for s in plan["steps"]), "unsupported useful operation")
        for item in (*accesses, *plan["steps"]):
            if item["input_origin"]:
                owner, number = item["input_origin"].rsplit("/input-op/", 1)
                require(owner in sources and 0 <= int(number) < sources[owner], "invented input lineage")
        phase_cost = 64 * len(accesses) * (n + 2) if phases else 0
        require(row["growth_allocation"] == 512 + attempted * 1200 + len(accesses) * n * 192 + phase_cost + plan.get("call_supply_reservation", 0),
                "cost estimate mismatch")
        require(row["growth_allocation"] <= 65536, "function cap exceeded")
        retained_limit = row.get("retained_growth_limit", row["growth_allocation"]) if contract >= 5 else row["growth_allocation"]
        if contract >= 5:
            require(type(row.get("retained_growth_limit")) is int and retained_limit == min(ceiling, row["growth_allocation"]),
                    "retained object ceiling differs from policy")
        before, after = row["instructions_before"], row["instructions_after"]
        require(before >= 0 and after >= 0 and row["attempted_instructions"] >= 0, "negative instruction count")
        if row["status"] == "encoded":
            require(row["reason"] == "" and retained == attempted and lost == 0, "invalid retained disposition")
            require(after == row["attempted_instructions"] and after <= before + retained_limit,
                    "retained growth exceeds allowance")
        else:
            require(row["reason"] == "growth-budget" and retained == 0 and lost == attempted and after == before,
                    "rollback not restored/accounted")
            require(row["attempted_instructions"] > before + retained_limit, "spurious growth rollback")
    if len(limits) > 1 or (limits and allocated > next(iter(limits))):
        errors.append("tile allocations exceed/disagree on shared module allowance")
    return errors


def tile_summary(report):
    if not report.get("features", {}).get("object_bundles"): return None
    rows = report["object_bundles"]
    retained = [r for r in rows if r["status"] == "encoded"]
    steps = [step for row in retained for step in row["plan"]["steps"]]
    return {"inspected_entry_allocas": len(rows), "retained_objects": len(retained),
            "retained_private_borrows": sum("closed_call" in r["plan"] for r in retained),
            "retained_operations": sum(r["retained_operations"] for r in retained),
            "retained_unique_operation_ancestry": len({s["input_origin"] for s in steps if s["input_origin"]}),
            "retained_operations_without_ancestry": sum(not s["input_origin"] for s in steps),
            "retained_source_loads": sum(r["plan"]["source_loads"] for r in retained),
            "retained_source_stores": sum(r["plan"]["source_stores"] for r in retained),
            "source_scalar_output_uses": sum(r["plan"]["scalar_output_uses"] for r in retained),
            "scalar_output_uses": sum(r["plan"]["scalar_output_uses"] - r["plan"].get("call_supply_uses", 0) for r in retained),
            "private_interface_supplies": sum(r["plan"].get("call_supply_uses", 0) for r in retained),
            "scalar_address_uses": sum(r["plan"]["scalar_address_uses"] for r in retained),
            "decoded_vector_lanes": sum(r["plan"].get("decoded_vector_lanes", 0) for r in retained),
            "lifetime_owned_objects": sum(r["plan"].get("lifetime", {}).get("mode") == "single-entry" for r in retained),
            "translated_lifetime_markers": sum(r["plan"].get("lifetime", {}).get("translated_markers", 0) for r in retained),
            "phase_objects": sum(r["plan"]["phase_mode"] != "static" for r in retained),
            "phase_update_sites": sum(r["plan"].get("phase_contract", {}).get("static_update_sites", 0) for r in retained),
            "skip_reasons": dict(Counter(r["reason"] for r in rows if r["status"] == "skipped")),
            "final_surviving_semantic_coverage": None, "hardness_evaluated": False}
