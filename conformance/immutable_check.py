"""Stage-local immutable ownership/continuity gate; not a protection score."""
from collections import Counter

from conformance.bundle_model import Descriptor


def immutable_violations(report):
    features = report.get("features", {})
    rows = report.get("immutable_continuity", [])
    if not features.get("immutable_bundles"):
        return ["immutable rows with feature disabled"] if rows or report.get("immutable_connected_continuity") else []
    errors = []
    def require(condition, message):
        if not condition: errors.append(message)
    require(features.get("data") and features.get("bundles") and "immutable_continuity" in report,
            "immutable feature prerequisites/inventory missing")
    objects = {}
    previous_available = None
    for row in report["data"]:
        if row.get("contract") != "sre-immutable-tile-v1":
            require(row["status"] == "skipped", "unknown immutable data contract")
            continue
        for key in ("read_sites", "growth_estimate", "growth_available", "growth_retained"):
            require(type(row[key]) is int and row[key] >= 0, f"invalid immutable {key}")
        require(row["growth_estimate"] == 192 * row["read_sites"], "immutable cost estimate mismatch")
        if previous_available is not None:
            require(row["growth_available"] == previous_available, "immutable reservation mismatch")
        previous_available = row["growth_available"] - row["growth_retained"]
        require(previous_available >= 0, "immutable module allowance exceeded")
        require(type(row["pins"]) is bool, "invalid immutable pin policy")
        if row["status"] != "encoded":
            require(row["status"] in ("skipped", "rolled-back") and row["growth_retained"] == 0 and
                    row["reason"] == "immutable-growth-budget", "invalid immutable loss accounting")
            if row["status"] == "rolled-back":
                require(row["growth_attempted"] > row["growth_estimate"], "spurious immutable rollback")
            else:
                require(row["growth_estimate"] > row["growth_available"], "spurious immutable budget skip")
            continue
        require(row["object"] not in objects, "duplicate immutable owner")
        objects[row["object"]] = row
        desc = Descriptor.from_plan(row)
        require(desc.width in (8, 16, 32, 64) and len(desc.salts) == 4, "invalid immutable tile descriptor")
        require(type(row["cells"]) is int and row["cells"] > 0 and
                row["bytes"] == row["cells"] * desc.width // 8 <= 65536, "invalid immutable extent")
        require(row["tile_cells"] == row["physical_reads_per_site"] == 4 and
                row["tail"] == "duplicate-last-valid-coordinate" and
                row["storage"] == "immutable-closed-initialized-array", "unproved immutable storage layout")
        require(row["growth_retained"] == row["growth_attempted"] <= row["growth_estimate"] and
                row["reason"] == "", "immutable growth accounting mismatch")
        require(0 <= int(row["carrier_base_hex"], 16) <= desc.bits and
                0 <= int(row["carrier_step_hex"], 16) <= desc.bits and
                int(row["carrier_step_hex"], 16) & 1, "invalid immutable carrier law")
    seen = {name: set() for name in objects}
    for row in rows:
        require(row["schema"] == "sre-immutable-continuity-v1", "unknown immutable continuity schema")
        require(row["object"] in objects, "continuity without encoded object")
        if row["object"] not in objects: continue
        sites = seen[row["object"]]
        require(type(row["site"]) is int and row["site"] not in sites and
                0 <= row["site"] < objects[row["object"]]["read_sites"], "duplicate or invented immutable read")
        sites.add(row["site"])
        for key in ("original_scalar_uses", "remaining_scalar_uses", "eliminated_scalar_uses", "added_scalar_uses"):
            require(type(row[key]) is int and row[key] >= 0, f"invalid immutable {key}")
        delta = row["original_scalar_uses"] - row["remaining_scalar_uses"]
        require(row["eliminated_scalar_uses"] == max(delta, 0) and
                row["added_scalar_uses"] == max(-delta, 0), "immutable scalar crossings do not reconcile")
        require(row["scope"] == "after-bundles-before-legacy-lowering" and row["hardness_evaluated"] is False,
                "immutable continuity overstated its evidence")
    for name, obj in objects.items():
        require(len(seen[name]) == obj["read_sites"], "immutable read denominator lost")
    contract = features.get("immutable_continuity_contract", 1)
    require(type(contract) is int and contract in (1, 2), "unknown immutable continuity contract")
    if contract == 2:
        require("immutable_connected_continuity" in report, "missing final immutable boundary inventory")
        final = report.get("immutable_connected_continuity", [])
        prior = {(r["object"], r["site"]): r for r in rows}
        seen_final = set()
        for row in final:
            identity = row["object"], row["site"]
            require(identity in prior and identity not in seen_final, "lost or duplicate final immutable read")
            seen_final.add(identity)
            require(row["schema"] == "sre-immutable-continuity-v1" and
                    row["scope"] == "after-regions-before-function-driver" and row["hardness_evaluated"] is False,
                    "unknown final immutable stage")
            for key in ("original_scalar_uses", "remaining_scalar_uses", "eliminated_scalar_uses", "added_scalar_uses"):
                require(type(row[key]) is int and row[key] >= 0, f"invalid final immutable {key}")
            delta = row["original_scalar_uses"] - row["remaining_scalar_uses"]
            require(row["eliminated_scalar_uses"] == max(delta, 0) and row["added_scalar_uses"] == max(-delta, 0),
                    "final immutable crossing mismatch")
            if identity in prior:
                require(row["original_scalar_uses"] == prior[identity]["original_scalar_uses"] and
                        row["reader_at_encoding"] == prior[identity]["reader_at_encoding"], "immutable input denominator changed")
        require(seen_final == set(prior), "final immutable reads missing")
    return errors


def immutable_summary(report):
    if not report.get("features", {}).get("immutable_bundles"): return None
    objects = report["data"]
    encoded = [r for r in objects if r["status"] == "encoded"]
    early = report["immutable_continuity"]
    edges = report.get("immutable_connected_continuity", early)
    return {"inspected_integer_arrays": len(objects), "encoded_objects": len(encoded),
            "encoded_bytes": sum(r["bytes"] for r in encoded),
            "read_sites": sum(r["read_sites"] for r in encoded),
            "reads_with_no_scalar_uses": sum(r["remaining_scalar_uses"] == 0 and r["original_scalar_uses"] > 0 for r in edges),
            "original_scalar_uses": sum(r["original_scalar_uses"] for r in edges),
            "remaining_scalar_uses": sum(r["remaining_scalar_uses"] for r in edges),
            "eliminated_scalar_uses": sum(r["eliminated_scalar_uses"] for r in edges),
            "added_scalar_uses": sum(r["added_scalar_uses"] for r in edges),
            "bundle_eliminated_scalar_uses": sum(r["eliminated_scalar_uses"] for r in early),
            "growth_retained": sum(r["growth_retained"] for r in encoded),
            "skip_reasons": dict(Counter(r["reason"] for r in objects if r["status"] != "encoded")),
            "scope": "eligible integer-array inventory and post-region scalar-use edges; not all globals or source memory",
            "final_surviving_semantic_coverage": None, "hardness_evaluated": False}
