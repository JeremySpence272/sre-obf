"""W5 arbitration between bounded merging and encoded private calls.

Merging runs before the encoded-call pass and absorbs the same private helpers,
so before either runs the compiler picks one owner per source-owned function and
records it. Two different things are reported per function and must not be read
as one: `policy` is the decision taken before the passes ran, and `outcome` is
what the module actually showed afterwards. Crediting a decision as protection
is exactly the failure the v04 plan warns about, so every check below is stated
against the outcome.
"""

# Exactly one policy owns each source-owned function.
POLICIES = ("encoded-interface", "fused", "scalar-boundary")
# Why the encoded interface did or did not win that function.
REASONS = ("interface-preferred", "interface-budget", "merge-induced-recursion",
           "interface-ineligible", "not-selected")
# What the module showed after merging and the call pass had run. `unclaimed`
# is the load-bearing one: neither pass took the function, so no protection may
# be credited for it. `unknown` means no reconciliation ran, never zero.
OUTCOMES = ("encoded", "merged", "thunked", "unclaimed", "absent", "unknown")
TAKEN = ("encoded", "merged", "thunked")
FIELDS = ("function", "policy", "reason", "merge_group", "merge_candidate",
          "selected", "interface_blocker", "outcome")


def policy_violations(report):
    """Arbitration rows checked against themselves, as explicit strings."""
    rows = report.get("call_policy")
    if rows is None:
        return (["call-policy feature has no arbitration report"]
                if report.get("features", {}).get("call_policy") else [])
    violations, seen = [], set()
    for row in rows:
        where = row.get("function", "<unnamed>")
        missing = sorted(field for field in FIELDS if field not in row)
        if missing:
            violations.append(f"{where}: arbitration row is missing {missing}")
            continue
        if where in seen:
            violations.append(f"{where}: arbitrated twice; one policy owns one function")
        seen.add(where)
        for field, vocabulary in (("policy", POLICIES), ("reason", REASONS),
                                  ("outcome", OUTCOMES)):
            if row[field] not in vocabulary:
                violations.append(f"{where}: {field} {row[field]!r} is outside the vocabulary")
        # The decision and the reason for it have to agree.
        if (row["policy"] == "encoded-interface") != (row["reason"] == "interface-preferred"):
            violations.append(f"{where}: policy {row['policy']!r} disagrees with "
                              f"reason {row['reason']!r}")
        if row["policy"] == "fused" and not row["merge_candidate"]:
            violations.append(f"{where}: left to merging, which was never offered it")
        if row["reason"] == "interface-preferred" and row["interface_blocker"]:
            violations.append(f"{where}: won an interface the call pass refuses "
                              f"({row['interface_blocker']})")
        if row["reason"] == "interface-ineligible" and not row["interface_blocker"]:
            violations.append(f"{where}: called ineligible with no blocker named")
        # A decision must never be read back as a result it did not get.
        if row["policy"] == "encoded-interface" and row["outcome"] not in ("encoded", "unknown"):
            violations.append(f"{where}: reserved for an encoded interface but ended "
                              f"{row['outcome']!r}")
        if row["policy"] == "scalar-boundary" and row["outcome"] in TAKEN:
            violations.append(f"{where}: recorded as a scalar boundary but ended "
                              f"{row['outcome']!r}")
        if row["policy"] == "fused" and row["outcome"] == "encoded":
            violations.append(f"{where}: left to merging but ended encoded")
    return violations


def policy_coverage(report):
    """The denominator first: every source-owned function, then who took it.

    A report without the array has an unknown denominator, never zero.
    """
    rows = report.get("call_policy")
    if rows is None:
        return dict.fromkeys(("source_functions", "contested", "policies", "outcomes",
                              "unclaimed", "reasons"))
    return {"source_functions": len(rows),
            # Functions both passes could have taken: the actual competition.
            "contested": sum(1 for row in rows if not row["interface_blocker"]),
            "policies": {name: sum(1 for row in rows if row["policy"] == name)
                         for name in POLICIES},
            "outcomes": {name: sum(1 for row in rows if row["outcome"] == name)
                         for name in OUTCOMES},
            "reasons": {name: sum(1 for row in rows if row["reason"] == name)
                        for name in REASONS},
            "unclaimed": sum(1 for row in rows if row["outcome"] == "unclaimed")}
