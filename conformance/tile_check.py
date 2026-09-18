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
}


def tile_violations(report):
    errors = []
    enabled = report.get("features", {}).get("object_bundles", False)
    if not enabled:
        return ["tile rows exist with feature disabled"] if report.get("object_bundles") else []
    if not report.get("features", {}).get("bundles") or "object_bundles" not in report:
        return ["enabled tiles require bundles and an object inventory"]
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
        if row["status"] == "skipped":
            require(row["reason"] in SKIPS, "unknown fallback")
            require(attempted == retained == lost == row["growth_allocation"] == 0, "skipped work credited")
            require("plan" not in row, "skipped object has executable plan")
            continue
        require(row["status"] in ("encoded", "rolled-back"), "unknown disposition")
        require(row["function"] not in owners, "multiple selected objects in one owner")
        owners.add(row["function"])
        plan = row["plan"]
        desc = Descriptor.from_plan(plan)
        n = plan["cells"]
        require(desc.width in (8, 16, 32, 64) and 2 <= n <= 4 and len(desc.salts) == n, "invalid shape")
        require(sorted(plan["physical_slots"]) == list(range(n)), "non-bijective layout")
        require(plan["law"] == "closed-initialized-tile-v1" and plan["phase_mode"] == "static", "unknown law")
        require(plan["ownership"] == "closed-entry-alloca" and
                plan["initialization"] == "complete-entry-stores-dominate-accesses", "missing ownership proof")
        accesses = plan["accesses"]
        initial = [a for a in accesses if a["initializer"]]
        require(len(initial) == n and sorted(a["index"] for a in initial) == list(range(n)),
                "incomplete or duplicate initialization")
        require(initial == accesses[:n] and all(a["kind"] == "store" for a in initial),
                "read/update precedes initialization")
        for a in accesses:
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
        require(plan["physical_loads"] == (loads + stores - n) * (n + 1), "extra-read accounting mismatch")
        require(plan["physical_stores"] == (1 + stores - n) * (n + 1), "write accounting mismatch")
        for key in ("scalar_input_values", "scalar_output_values", "scalar_output_uses", "scalar_address_uses"):
            require(type(plan[key]) is int and plan[key] >= 0, f"invalid {key}")
        require(plan["scalar_output_uses"] >= plan["scalar_output_values"] and
                plan["scalar_output_uses"] >= plan["scalar_address_uses"], "exposure accounting mismatch")
        require(4 <= len(plan["steps"]) <= 32 and attempted == len(plan["steps"]), "operation accounting mismatch")
        require(all(s["opcode"] in OPCODES for s in plan["steps"]), "unsupported useful operation")
        for item in (*accesses, *plan["steps"]):
            if item["input_origin"]:
                owner, number = item["input_origin"].rsplit("/input-op/", 1)
                require(owner in sources and 0 <= int(number) < sources[owner], "invented input lineage")
        require(row["growth_allocation"] == 512 + attempted * 1200 + len(accesses) * n * 192,
                "cost estimate mismatch")
        require(row["growth_allocation"] <= 65536, "function cap exceeded")
        before, after = row["instructions_before"], row["instructions_after"]
        require(before >= 0 and after >= 0 and row["attempted_instructions"] >= 0, "negative instruction count")
        if row["status"] == "encoded":
            require(row["reason"] == "" and retained == attempted and lost == 0, "invalid retained disposition")
            require(after == row["attempted_instructions"] and after <= before + row["growth_allocation"],
                    "retained growth exceeds allowance")
        else:
            require(row["reason"] == "growth-budget" and retained == 0 and lost == attempted and after == before,
                    "rollback not restored/accounted")
            require(row["attempted_instructions"] > before + row["growth_allocation"], "spurious growth rollback")
    if len(limits) > 1 or (limits and allocated > next(iter(limits))):
        errors.append("tile allocations exceed/disagree on shared module allowance")
    return errors


def tile_summary(report):
    if not report.get("features", {}).get("object_bundles"): return None
    rows = report["object_bundles"]
    retained = [r for r in rows if r["status"] == "encoded"]
    steps = [step for row in retained for step in row["plan"]["steps"]]
    return {"inspected_entry_allocas": len(rows), "retained_objects": len(retained),
            "retained_operations": sum(r["retained_operations"] for r in retained),
            "retained_unique_operation_ancestry": len({s["input_origin"] for s in steps if s["input_origin"]}),
            "retained_operations_without_ancestry": sum(not s["input_origin"] for s in steps),
            "retained_source_loads": sum(r["plan"]["source_loads"] for r in retained),
            "retained_source_stores": sum(r["plan"]["source_stores"] for r in retained),
            "scalar_output_uses": sum(r["plan"]["scalar_output_uses"] for r in retained),
            "scalar_address_uses": sum(r["plan"]["scalar_address_uses"] for r in retained),
            "skip_reasons": dict(Counter(r["reason"] for r in rows if r["status"] == "skipped")),
            "final_surviving_semantic_coverage": None, "hardness_evaluated": False}
