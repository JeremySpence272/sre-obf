"""Private argument-tuple contracts; supplied descriptors are not secrets."""
from conformance.bundle_model import Descriptor


def joint_call_violations(report):
    features = report.get("features", {})
    enabled = features.get("joint_call_arguments", False)
    rows = report.get("encoded_calls", [])
    if type(enabled) is not bool: return ["invalid joint-call feature"]
    if not enabled:
        return ["joint-call data exists with feature disabled"] if any(
            "joint_arguments" in r or r.get("representation") == "triangular-xor-arguments-v1" for r in rows) else []
    if not features.get("encoded_calls") or not features.get("bundles"):
        return ["joint calls require encoded calls and bundles"]
    errors = []
    for row in rows:
        name = row["function"]
        def require(ok, message):
            if not ok: errors.append(f"{name}: {message}")
        widths = row.get("argument_widths")
        valid_widths = (isinstance(widths, list) and len(widths) == row["parameters"] and
                        all(type(w) is int and w in (0, 8, 16, 32, 64) for w in widths))
        require(valid_widths, "missing argument width denominator")
        if not valid_widths: continue
        if row["status"] != "encoded":
            require("joint_arguments" not in row, "skipped interface claims joint work")
            continue
        require(all(widths), "encoded interface has unsupported argument type")
        p = row.get("joint_arguments")
        if not isinstance(p, dict):
            errors.append(f"{name}: missing argument contract")
            continue
        require(p.get("contract") == "triangular-call-arguments-v1", "unknown argument contract")
        n, sites = row["parameters"], row["call_sites_rewritten"]
        for key in ("abi_words", "mask_reservation", "mask_instructions"):
            require(type(p.get(key)) is int and p[key] >= 0, f"invalid {key}")
        fallback = ("argument-count" if not 2 <= n <= 4 else
                    "mixed-argument-widths" if not widths or len(set(widths)) != 1 else
                    "call-site-limit" if sites > 8 else "")
        require(p.get("reason") == fallback, "incorrect joint argument disposition")
        if fallback:
            require(p.get("status") == "paired-fallback" and row["representation"] == "xor-pair-v1", "invalid paired fallback")
            require(p.get("abi_words") == 2 * n and p.get("mask_reservation") == p.get("mask_instructions") == 0 and
                    "descriptor" not in p, "fallback credited as joint work")
            continue
        require(p.get("status") == "joint" and row["representation"] == "triangular-xor-arguments-v1", "invalid joint representation")
        require(p.get("abi_words") == n + 1, "joint ABI is not one carrier plus coordinates")
        require(p.get("mask_reservation") == 8 * n * (sites + 1) and p.get("mask_reservation", 0) <= 288,
                "joint mask reservation mismatch")
        instructions = p.get("mask_instructions", 0)
        require(type(instructions) is int and 0 < instructions <= 7 * n * (sites + 1), "invalid emitted mask accounting")
        try:
            desc = Descriptor.from_plan(p["descriptor"])
            require(len(desc.salts) == n and desc.family == "triangular-xor-v1" and
                    widths == [desc.width] * n, "descriptor does not match argument tuple")
        except (KeyError, TypeError, ValueError):
            errors.append(f"{name}: invalid joint descriptor")
    return errors


def joint_call_summary(report):
    if not report.get("features", {}).get("joint_call_arguments"): return None
    rows = [r for r in report.get("encoded_calls", []) if r["status"] == "encoded"]
    joint = [r for r in rows if r["joint_arguments"]["status"] == "joint"]
    return {"joint_interfaces": len(joint), "paired_fallback_interfaces": len(rows) - len(joint),
            "joint_source_parameters": sum(r["parameters"] for r in joint),
            "joint_call_sites": sum(r["call_sites_rewritten"] for r in joint),
            "abi_argument_words": sum(r["joint_arguments"]["abi_words"] * r["call_sites_rewritten"] for r in joint),
            "mask_instructions_at_interface_stage": sum(r["joint_arguments"]["mask_instructions"] for r in joint),
            "hardness_evaluated": False}
