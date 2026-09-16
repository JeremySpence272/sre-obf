"""Trusted correctness/coverage gate for whole.py's cross-TU fixture builds."""
import argparse
import json
from pathlib import Path
import sys
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, test_inputs


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("build", type=Path)
    p.add_argument("--toolchain-image")
    args = p.parse_args(argv)
    out = args.build.resolve()
    manifest = json.loads((out / "manifest.json").read_text())
    runner = Runner(ROOT, out / "correctness-logs", args.toolchain_image, mounts=(out,))
    inputs = test_inputs(512)
    outputs = {}
    for arm, info in manifest["artifacts"].items():
        binary = out / arm
        if digest(binary) != info["binary_sha256"]:
            raise ToolFailure("binary differs from build manifest")
        outputs[arm] = runner.run([str(binary)], stdin=inputs)
    correct = all(value == outputs["clean"] for value in outputs.values()) and len(outputs["clean"].splitlines()) == 593
    report = json.loads((out / "native.json").read_text())
    covered = {
        "fusion": any(x["status"] == "fused" for x in report["fused_calls"]),
        "memory": {x["width"] for x in report["memory"] if x["status"] == "encoded" and x["elements"] == 8} == {8, 32},
        "invariant": any(x.get("reachable_invariant") for x in report["values"]),
    }
    required = [name for name in covered if f"-native-{name}=1" in manifest["features"]]
    result = {"correctness": correct, "vectors": 593, "coverage": covered,
              "required_coverage": required, "manifest_sha256": digest(out / "manifest.json")}
    dump(out / "correctness.json", result)
    return 0 if correct and all(covered[k] for k in required) else 1


if __name__ == "__main__":
    sys.exit(main())
