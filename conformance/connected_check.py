"""Trusted full-output differential and actual connected-region coverage gate."""
import argparse
import json
from pathlib import Path
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, test_inputs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("build", type=Path)
    p.add_argument("--toolchain-image")
    p.add_argument("--require-memory", action="store_true")
    p.add_argument("--require-predicates", action="store_true")
    args = p.parse_args()
    out = args.build.resolve()
    manifest = json.loads((out / "manifest.json").read_text())
    runner = Runner(ROOT, out / "connected-check-logs", args.toolchain_image, mounts=(out,))
    values = {}
    for arm, info in manifest["artifacts"].items():
        binary = out / arm
        if digest(binary) != info["binary_sha256"]:
            raise ToolFailure("binary hash changed")
        values[arm] = runner.run([str(binary)], stdin=test_inputs(512))
    report = json.loads((out / "native.json").read_text())
    regions = [row for row in report["connected_regions"] if row["status"] == "encoded"]
    encoded_objects = [obj for row in regions for obj in row["objects"] if obj["status"] == "encoded"]
    coverage = {"regions": bool(regions), "memory": bool(encoded_objects),
                "predicates": any(row["predicates"] > 0 for row in regions)}
    correct = len(values["clean"].splitlines()) == 593 and all(value == values["clean"] for value in values.values())
    passed = correct and coverage["regions"] and (not args.require_memory or coverage["memory"]) and (not args.require_predicates or coverage["predicates"])
    result = {"passed": passed, "correctness": correct, "vectors": 593, "coverage": coverage,
              "manifest_sha256": digest(out / "manifest.json"), "commands": runner.records}
    dump(out / "connected-correctness.json", result)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
