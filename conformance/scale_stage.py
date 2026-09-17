"""Replay retained whole-application IR stages with private symbols.

This diagnostic runs trusted compiler output. It does not change the frozen
production artifacts or turn a tool failure into a protection result.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, image_identity


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--spec", required=True, type=Path)
    p.add_argument("--ir", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--toolchain-image", required=True)
    args = p.parse_args()
    spec = json.loads(args.spec.read_text())
    if spec.get("schema") != "sre-scale-v1" or not spec.get("workloads"):
        p.error("a scale manifest with independently specified workloads is required")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    ir = args.ir.resolve(strict=True)
    result = {"schema": "sre-scale-stage-v1", "ir_sha256": digest(ir),
              "spec_sha256": digest(args.spec), "toolchain_image": image_identity(args.toolchain_image),
              "link_scope": "dynamic diagnostic; not the static production lane",
              "status": "incomplete", "workloads": []}
    runner = Runner(ROOT, out / "logs", args.toolchain_image, timeout=180, mounts=(out, ir.parent))
    try:
        # Easier library backtraces; distinct from the matched static lane.
        links = [f for f in spec.get("link_flags", []) if f not in ("-static", "-s")]
        binary = out / "binary"
        runner.run(["clang", "-O0", "-Wa,-L", str(ir), *links,
                    "-Wl,--discard-none", "-o", str(binary)])
        result["binary_sha256"] = digest(binary)
        for workload in spec["workloads"]:
            stdout = runner.run([str(binary), *workload.get("argv", [])],
                                stdin=base64.b64decode(workload["stdin_base64"], validate=True))
            result["workloads"].append({"name": workload["name"],
                "expected_output": hashlib.sha256(stdout).hexdigest() == workload["stdout_sha256"]})
        result["status"] = "pass" if all(w["expected_output"] for w in result["workloads"]) else "mismatch"
    except (OSError, ToolFailure) as exc:
        result.update(status="failure", reason=str(exc))
    finally:
        result["commands"] = runner.records
        dump(out / "result.json", result)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
