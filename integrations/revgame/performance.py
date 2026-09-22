"""Pure, fail-closed v05 performance conformance; no timing or process execution."""
from __future__ import annotations

import math
import re
import statistics

SCHEMA = "sre-revgame-performance-v1"
MIN_SAMPLES = 31
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def positive(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value > 0
    except OverflowError:
        return False


def percentile95(values):
    """Nearest-rank empirical percentile, not a tail-confidence guarantee."""
    return sorted(values)[math.ceil(0.95 * len(values)) - 1]


def evaluate(report):
    """Validate a complete measurement block, retaining errors instead of dropping rows.

    The caller must independently freeze and recheck files, restore affinity and
    record process failures. This gate evaluates evidence, not filesystem truth.
    Optional previous/v04 arms are correctness controls, not the denominator.
    """
    result = {"schema": SCHEMA, "status": "failed", "reasons": [],
              "metrics": {}, "target_met": None, "target_p95_met": None}
    errors = result["reasons"]
    if not isinstance(report, dict):
        errors.append("report must be an object")
        return result
    if report.get("schema") != SCHEMA:
        errors.append("unsupported report schema")
    if report.get("measurement_status") != "complete":
        errors.append("measurement block is not complete")
    if report.get("artifacts_unchanged") is not True:
        errors.append("artifact and workload hashes were not verified at completion")
    n = report.get("requested_samples")
    if type(n) is not int or n < 1:
        errors.append("invalid requested sample count")
        return result
    binaries = report.get("binaries")
    if not isinstance(binaries, dict) or not {"clean", "native"} <= binaries.keys():
        errors.append("missing matched clean/native binaries")
        return result
    hashes = {}
    for arm, binary in binaries.items():
        value = binary.get("sha256") if isinstance(binary, dict) else None
        if not isinstance(arm, str) or not isinstance(value, str) or not SHA256.fullmatch(value):
            errors.append("invalid binary identity")
        hashes[arm] = value
    reference = report.get("reference_sha256")
    if not isinstance(reference, str) or not SHA256.fullmatch(reference):
        errors.append("invalid workload identity")
    if not isinstance(report.get("workload_id"), str) or not report["workload_id"]:
        errors.append("missing workload id")
    seed = report.get("compiler_seed")
    if not isinstance(seed, str) or not seed.isdecimal() or not 0 <= int(seed) < 2**64:
        errors.append("missing or invalid compiler seed")
    floor = report.get("minimum_clean_seconds")
    if not positive(floor):
        errors.append("missing positive timing resolution/noise floor")
    samples = report.get("samples")
    if not isinstance(samples, list):
        errors.append("samples must be an array")
        return result
    seen = set()
    measured = {arm: {} for arm in binaries}
    baseline = None
    expected_order = []
    arms = list(binaries)
    for index in range(-1, n):
        offset = max(0, index) % len(arms)
        expected_order.extend((index, arm) for arm in arms[offset:] + arms[:offset])
    actual_order = []
    for row in samples:
        if not isinstance(row, dict):
            errors.append("malformed sample")
            continue
        arm, index = row.get("arm"), row.get("index")
        if not isinstance(arm, str) or arm not in binaries or type(index) is not int or not -1 <= index < n:
            errors.append("unknown arm or invalid sample index")
            continue
        key = (index, arm)
        actual_order.append(key)
        if key in seen:
            errors.append("duplicate sample")
        seen.add(key)
        if row.get("warmup") is not (index == -1):
            errors.append("incorrect warmup classification")
        if row.get("binary_sha256") != hashes[arm] or row.get("reference_sha256") != reference:
            errors.append("sample artifact/workload identity mismatch")
        if row.get("status") != "ok" or row.get("correct") is not True or type(row.get("exit_code")) is not int or row["exit_code"] != 0:
            errors.append("failed or incorrect sample")
        elapsed, full, cpu = (row.get(k) for k in ("replay_seconds", "full_process_seconds", "cpu_seconds"))
        if not positive(elapsed) or not positive(full) or full < elapsed:
            errors.append("invalid elapsed time")
            continue
        if cpu != 0 and not positive(cpu) or type(cpu) not in (int, float):
            errors.append("invalid CPU time")
        output, turns = row.get("output_sha256"), row.get("turns")
        if not isinstance(output, str) or not SHA256.fullmatch(output) or type(turns) is not int or turns < 0:
            errors.append("missing output/turn correctness evidence")
        observed = (output, turns)
        if baseline is None:
            baseline = observed
        elif observed != baseline:
            errors.append("output or turn mismatch")
        if index >= 0:
            measured[arm][index] = elapsed
    if actual_order != expected_order:
        errors.append("missing samples or non-rotating sample order")
    result["reasons"] = list(dict.fromkeys(errors))
    if errors:
        return result
    clean = [measured["clean"][i] for i in range(n)]
    protected = [measured["native"][i] for i in range(n)]
    ratios = [p / c for p, c in zip(protected, clean)]
    # Finite input times can still overflow a ratio. Reject derived non-finites.
    ratio = statistics.median(protected) / statistics.median(clean)
    if not all(positive(v) for v in [ratio, *ratios]):
        result["reasons"].append("nonfinite derived ratio")
        return result
    result["metrics"] = {
        "ratio_of_medians": ratio, "median_paired_ratio": statistics.median(ratios),
        "paired_ratio_p95": percentile95(ratios),
        "protected_median_seconds": statistics.median(protected),
        "protected_p95_seconds": percentile95(protected), "protected_max_seconds": max(protected),
        "clean_median_seconds": statistics.median(clean), "paired_ratios": ratios,
        "protected_mad_seconds": statistics.median(abs(x - statistics.median(protected)) for x in protected),
    }
    for arm in ("clean", "native"):
        measured_rows = [r for r in samples if r["arm"] == arm and not r["warmup"]]
        result["metrics"][arm + "_cpu_median_seconds"] = statistics.median(r["cpu_seconds"] for r in measured_rows)
        result["metrics"][arm + "_full_process_median_seconds"] = statistics.median(r["full_process_seconds"] for r in measured_rows)
        rss = [r.get("peak_rss_kib") for r in measured_rows]
        if all(type(v) is int and v > 0 for v in rss):
            result["metrics"][arm + "_peak_rss_kib"] = max(rss)
    cpu_clean = result["metrics"]["clean_cpu_median_seconds"]
    result["metrics"]["cpu_ratio_of_medians"] = (result["metrics"]["native_cpu_median_seconds"] / cpu_clean
                                                if cpu_clean > 0 else None)
    cpu_ratio = result["metrics"]["cpu_ratio_of_medians"]
    if cpu_ratio is not None and not math.isfinite(cpu_ratio):
        result["reasons"].append("nonfinite derived CPU ratio")
        return result
    result["target_met"] = statistics.median(protected) < 1.0
    result["target_p95_met"] = percentile95(protected) < 1.0
    if ratio >= 20.0 or percentile95(ratios) >= 20.0:
        result["reasons"].append("strict total clean-relative 20x ceiling exceeded")
        return result
    if min(clean) < floor:
        result.update(status="inconclusive", reasons=["clean timing below registered resolution/noise floor"])
    elif n < MIN_SAMPLES:
        result.update(status="smoke_only", reasons=[f"requires at least {MIN_SAMPLES} measured pairs"])
    else:
        result["status"] = "pass"
    return result


def evaluate_matrix(blocks, required_cells, confirmations=2):
    """No averaging across workload/seed cells or selection of a passing block.

    required_cells must be frozen outside this function. Independent confirmation
    block ids are required; an invalid/failed block is never silently discarded.
    """
    reasons, seen, counts, identities = [], set(), {}, {}
    if type(confirmations) is not int or confirmations < 2:
        return {"status": "failed", "reasons": ["at least two confirmation blocks required"]}
    if not required_cells or len(required_cells) != len(set(required_cells)):
        return {"status": "failed", "reasons": ["empty or duplicate required cells"]}
    for block in blocks:
        if not isinstance(block, dict):
            reasons.append("malformed confirmation block")
            continue
        cell = (block.get("compiler_seed"), block.get("workload_id"), block.get("reference_sha256"))
        identifier = block.get("block_id")
        if cell not in required_cells or not isinstance(identifier, str) or not identifier or identifier in seen:
            reasons.append("unexpected cell or missing/duplicate block id")
            continue
        seen.add(identifier)
        verdict = evaluate(block)
        if verdict["status"] != "pass":
            reasons.append(f"{identifier}: {verdict['status']}")
        identity = block.get("binaries")
        if cell in identities and identity != identities[cell]:
            reasons.append(f"{identifier}: confirmation binary identity changed")
        identities[cell] = identity
        counts[cell] = counts.get(cell, 0) + 1
    for cell in required_cells:
        if counts.get(cell, 0) < confirmations:
            reasons.append(f"missing confirmation blocks for {cell}")
    return {"status": "failed" if reasons else "pass", "reasons": reasons}
