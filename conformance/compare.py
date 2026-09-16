"""Compare private conformance artifacts across seeds, ablations or revisions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def compare(left: dict, right: dict) -> list[dict]:
    key = lambda case: (case["case"], case["seed"])
    a = {key(case): case for case in left["cases"]}
    b = {key(case): case for case in right["cases"]}
    rows = []
    for identity in sorted(a.keys() | b.keys()):
        row = {"case": identity[0], "seed": identity[1]}
        if identity not in a or identity not in b:
            rows.append({**row, "status": "missing_case"})
            continue
        x, y = a[identity], b[identity]
        if not x.get("correctness") or not y.get("correctness"):
            rows.append({**row, "status": "invalid_correctness"})
            continue
        source = x.get("source_sha256")
        if not source or source != y.get("source_sha256"):
            rows.append({**row, "status": "different_source"})
            continue
        nx, ny = x["arms"]["native"], y["arms"]["native"]
        equal = lambda u, v: u == v if u is not None and v is not None else None
        row.update({
            "status": "comparable",
            "optimized_ir_equal": equal(x.get("optimized_ir_sha256"),
                                        y.get("optimized_ir_sha256")),
            "protected_ir_equal": equal(x.get("protected_ir_sha256"),
                                        y.get("protected_ir_sha256")),
            "binary_equal": equal(nx.get("binary_sha256"), ny.get("binary_sha256")),
            "binary_bytes": [nx["binary_bytes"], ny["binary_bytes"]],
            "decompiled_c_equal": equal(
                nx.get("decompiler", {}).get("metrics", {}).get("normalized_sha256"),
                ny.get("decompiler", {}).get("metrics", {}).get("normalized_sha256")),
            "literal_hiding": [x.get("literal_hiding"), y.get("literal_hiding")],
        })
        rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path, help="First summary.json")
    parser.add_argument("right", type=Path, help="Second summary.json")
    parser.add_argument("--require-identical-binaries", action="store_true")
    parser.add_argument("--require-identical-ir", action="store_true")
    args = parser.parse_args()
    rows = compare(json.loads(args.left.read_text()), json.loads(args.right.read_text()))
    print(json.dumps({"cases": rows, "interpretation":
        "Differences are diagnostics, not evidence of semantic recovery difficulty."}, indent=2))
    bad = not rows or any(row["status"] != "comparable" for row in rows)
    if args.require_identical_binaries:
        bad |= any(row.get("binary_equal") is not True for row in rows)
    if args.require_identical_ir:
        bad |= any(row.get("protected_ir_equal") is not True or
                   row.get("optimized_ir_equal") is not True for row in rows)
    return int(bad)


if __name__ == "__main__":
    raise SystemExit(main())
