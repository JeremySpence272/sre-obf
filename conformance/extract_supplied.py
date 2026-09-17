"""Supplied-region control: recover a region whose interface is handed over.

The first of the two W0 adapters. It is given a region or typed expression
interface from private provenance -- entry address, ABI, widths, and the
addresses of any immutable backing -- and recovers that region's semantics
from machine code. It never searches for a region, never reads a symbol table
to guess one, and never consults the answer.

That omission is the point. Isolating mechanism cost from discovery cost means
this control must pay no discovery cost at all, so whatever it reports is the
cost of the protection mechanism alone. The binary-discovery adapter finds the
same interfaces itself and pays both, and the difference between the two is the
discovery cost. Every phase after lifting is shared with it, in
`conformance/extract_phases.py`, so the two remain comparable.

What the control does NOT do, and no field here should be read as claiming:

* It does not execute the supplied target. Lifting is symbolic, Unicorn is off,
  and every value comes from a solver over the lifted expression.
* It does not prove security. Costs are relative to this adapter and these
  budgets. A budget, a tool error or a solver `unknown` is inconclusive: it is
  never protection and never a win.
* It does not accept a summary on sampled agreement. Acceptance needs
  constructed positives, constructed negatives the probe set can actually
  separate, and a counterexample check that is exhaustive or a solver proof.
* A model that predicts only the one site it was fitted on is reported
  `single-site`, not as a successful summary.

Usage:

    python3 -m conformance.extract_supplied --spec <private-interface.json> \
        --out <fresh-dir> --analysis-image <image> [--toolchain-image <image>]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import sys

from conformance import extract_phases as phases
from conformance.process import Runner, ToolFailure, digest, dump

SPEC_SCHEMA = "sre-supplied-interface-v1"
DEFINE = re.compile(r"^define\b[^@]*@\"?([\w.$]+)\"?\s*\(")


def validate(spec):
  """Reject anything that would turn this control into a discovery run."""
  if spec.get("schema") != SPEC_SCHEMA:
    raise ValueError(f"expected {SPEC_SCHEMA}")
  if not spec.get("targets"):
    raise ValueError("no targets")
  for target in spec["targets"]:
    for region in target.get("regions", []):
      if "entry" not in region:
        raise ValueError(f"region {region.get('region')!r} has no supplied entry; "
                         "this control does not locate regions")
      if region["entry"] is None and not region.get("absent_reason"):
        raise ValueError(f"region {region.get('region')!r} declares no entry and "
                         "no reason; an absent interface must say why")
      if "interface" not in region:
        raise ValueError(f"region {region.get('region')!r} has no supplied interface")
  return spec


def count_instructions(text, function):
  """Instructions in one textual LLVM function body, for the normalizer arm."""
  body, inside = 0, False
  for line in text.splitlines():
    if not inside:
      found = DEFINE.match(line)
      if found and found.group(1) == function:
        inside = True
      continue
    if line.startswith("}"):
      return body, True
    stripped = line.strip()
    if stripped and not stripped.startswith(";") and not stripped.endswith(":"):
      body += 1
  return body, False


def normalize(runner, module, function, out, image):
  """Re-optimize the supplied module and measure simplification.

  A v03 `-fwhole-program` attempt discarded the recovered function because
  nothing referenced it, leaving an empty output. An empty normalizer output is
  an invalid test, not a perfect simplification, so it is refused here.
  """
  if module is None or function is None:
    return phases.phase("normalize", "skipped", "not-attempted")
  module = Path(module)
  if not module.is_file():
    return phases.phase("normalize", "inconclusive", "tool-error",
                        detail="supplied module is missing")
  before, closed = count_instructions(module.read_text(), function)
  if not closed:
    return phases.phase("normalize", "inconclusive", "interface-mismatch",
                        tool="opt", function=function,
                        detail="the supplied module defines no such function")
  result = out / "normalized.ll"
  try:
    runner.run(["opt", "-passes=default<O2>", "-S", str(module), "-o", str(result)],
               image=image)
  except ToolFailure as exc:
    return phases.phase("normalize", "inconclusive", "tool-error",
                        tool="opt", detail=str(exc)[:200])
  after, produced = count_instructions(result.read_text(), function)
  return phases.normalize_result(before, after, "opt", ["-passes=default<O2>"],
                                 produced and after > 0)


def run_region(runner, target, region, out, analysis_image, toolchain_image):
  """Every phase for one supplied region."""
  out.mkdir(parents=True, exist_ok=True)
  binary = Path(target["binary"]).resolve()
  before = digest(binary)

  # A supplied interface that has no counterpart in this build is a result, not
  # an error: the protection removed the interface the control was to be given.
  # It is reported as a boundary with its origin, never as a recovery.
  if region["entry"] is None:
    absent = phases.region_report(
        region["region"], "supplied-region",
        [phases.phase("lift", "inconclusive", "interface-mismatch",
                      absent_reason=region["absent_reason"],
                      evidence=region.get("absent_evidence"),
                      note="no interface of this shape exists in this build, so "
                           "nothing was lifted; this is a measured boundary and "
                           "not evidence about how hard the region would be")],
        interface=region["interface"], target=target["name"], entry=None,
        binary_sha256=before)
    dump(out / "region.json", absent)
    return absent

  spec = {"region": region["region"], "adapter": "supplied-region",
          "binary": str(binary), "entry": region["entry"],
          "interface": region["interface"], "domain": region.get("domain"),
          "limits": region.get("limits", target.get("limits", {}))}
  dump(out / "worker-spec.json", spec)

  worker = out / "extract_phases.py"
  shutil.copy2(Path(phases.__file__), worker)
  try:
    runner.run(["python3", str(worker), "worker", "--spec", str(out / "worker-spec.json"),
                "--out", str(out / "worker-result.json")], image=analysis_image)
    report = json.loads((out / "worker-result.json").read_text())
  except (ToolFailure, OSError, ValueError) as exc:
    report = phases.region_report(
        region["region"], "supplied-region",
        [phases.phase("lift", "inconclusive", "tool-error", detail=str(exc)[:200])],
        interface=region["interface"])

  # Immutable backing is read from the ELF directly: no image, no execution.
  if region.get("immutable_data"):
    report["phases"].append(phases.recover_immutable_data(binary, region["immutable_data"]))
  else:
    report["phases"].append(phases.phase("immutable", "skipped", "not-attempted"))

  report["phases"].append(normalize(runner, region.get("module", target.get("module")),
                                    region.get("normalize_function"), out, toolchain_image))

  if digest(binary) != before:
    raise ValueError("the supplied binary changed during recovery")
  rebuilt = phases.region_report(region["region"], "supplied-region", report["phases"],
                                 interface=region["interface"],
                                 target=target["name"], entry=region["entry"],
                                 binary_sha256=before,
                                 limits=report.get("limits"),
                                 solver_queries=report.get("solver_queries"))
  dump(out / "region.json", rebuilt)
  return rebuilt


def main(argv=None):
  p = argparse.ArgumentParser(description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
  p.add_argument("--spec", type=Path, required=True,
                 help="supplied interface spec, from private provenance")
  p.add_argument("--out", type=Path, required=True, help="fresh output directory")
  p.add_argument("--analysis-image", required=True,
                 help="image providing the symbolic lifter; used as a toolbox only")
  p.add_argument("--toolchain-image", default=None, help="image providing opt")
  args = p.parse_args(argv)
  try:
    spec = validate(json.loads(args.spec.read_text()))
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    regions, mounts = [], set()
    for target in spec["targets"]:
      mounts.add(Path(target["binary"]).resolve().parent)
      if target.get("module"):
        mounts.add(Path(target["module"]).resolve().parent)
    runner = Runner(out, out / "logs", None, timeout=900, mounts=tuple(sorted(mounts)))
    for target in spec["targets"]:
      for index, region in enumerate(target.get("regions", [])):
        regions.append(run_region(runner, target, region,
                                  out / f"{target['name']}-{index}-{region['region']}",
                                  args.analysis_image, args.toolchain_image))
    report = phases.adapter_report(
        "supplied-region", regions,
        spec_sha256=digest(args.spec),
        phases_sha256=digest(Path(phases.__file__)),
        adapter_sha256=digest(Path(__file__)),
        discovery_performed=False,
        discovery_note="every entry and interface was supplied from private "
                       "provenance; this adapter measures mechanism cost only, "
                       "and its cost is not comparable to an attack that must "
                       "first find the region",
        execution_note="the supplied target is never executed; lifting is "
                       "symbolic with Unicorn disabled",
        targets=[{"name": t["name"], "binary_sha256": digest(Path(t["binary"]))}
                 for t in spec["targets"]])
    dump(out / "summary.json", report)
    print(json.dumps({k: report[k] for k in ("schema", "adapter", "regions_total",
                                             "regions_recovered", "regions_inconclusive",
                                             "regions_failed")}, indent=2))
    return 0
  except (OSError, ValueError, ToolFailure) as exc:
    print(f"sre-extract-supplied: {exc}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  sys.exit(main())
