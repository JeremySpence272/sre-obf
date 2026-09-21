"""Check the shipped static-PIE TUI pair through CLI, replay and live input."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import time

from conformance.connected_check import report_violations
from conformance.process import digest, dump
from conformance.scale import coverage


def elf_properties(binary):
    header = subprocess.check_output(["readelf", "-hW", str(binary)], text=True)
    phdrs = subprocess.check_output(["readelf", "-lW", str(binary)], text=True)
    sections = subprocess.check_output(["readelf", "-SW", str(binary)], text=True)
    dynamic = subprocess.check_output(["readelf", "-dW", str(binary)], text=True)
    if not ("ELF64" in header and "DYN" in header and "X86-64" in header):
        raise ValueError("expected Linux x86-64 static-PIE ELF")
    if "INTERP" in phdrs or "(NEEDED)" in dynamic:
        raise ValueError("binary is not statically linked")
    if any(name in sections for name in (".symtab", ".debug_", ".zdebug_")):
        raise ValueError("binary is not stripped")
    return {"static": True, "pie": True, "stripped": True,
            "sha256": digest(binary), "bytes": binary.stat().st_size}


def run(binary, argv, path, keys=None, timeout=120):
    env = dict(os.environ, TERM="xterm-256color", LINES="40", COLUMNS="120",
               LC_ALL="C")
    command = [str(binary), *map(str, argv)]
    if keys is not None:
        # Early cooked-mode echo races with the program's startup output.
        # Compare program output only; keys are already checked via recordings.
        command = ["/usr/bin/script", "--echo=never", "-qefc", shlex.join(command), "/dev/null"]
    start = time.monotonic()
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, start_new_session=True)
    try:
        output, _ = proc.communicate(keys or b"", timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        output, _ = proc.communicate()
        path.write_bytes(output)
        raise
    path.write_bytes(output)
    return proc.returncode, output, time.monotonic() - start


def actions_match(recording, expected):
    """Do not accept missing/empty/corrupted recordings as live-input success."""
    if not isinstance(recording, dict):
        return False
    runs = recording.get("runs")
    return (isinstance(runs, list) and len(runs) == 1 and isinstance(runs[0], dict)
            and runs[0].get("actions") == expected)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True, help="adapter output directory")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=120)
    args = p.parse_args(argv)
    build, out = args.build.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((build / "build/manifest.json").read_text())
    binaries = {name: build / "build" / name for name in ("clean", "native")}
    checks = []
    result = {"status": "running", "cases": checks}
    try:
        result["elf"] = {name: elf_properties(path) for name, path in binaries.items()}
        for name in binaries:
            if result["elf"][name]["sha256"] != manifest["artifacts"][name]["binary_sha256"]:
                raise ValueError("binary differs from build manifest")
        if manifest["frontend_optimization"] != "O0" or manifest["backend_optimization"] != "O0":
            raise ValueError("expected O0 frontend/backend")
        for name, options in (
                ("help", ["--help"]), ("unknown-flag", ["--invalid"]),
                ("short-seed", ["--seed", "bad"]),
                ("missing-replay", ["--replay", str(out / "missing.json")])):
            rows = [run(binary, options, out / (name + "-" + arm + ".log"),
                        timeout=args.timeout)
                    for arm, binary in binaries.items()]
            passed = rows[0][:2] == rows[1][:2] and rows[0][0] == (0 if name == "help" else 1)
            checks.append({"case": name, "passed": passed,
                           "seconds": {arm: row[2] for arm, row in zip(binaries, rows)}})
            if not passed:
                raise ValueError("CLI mismatch: " + name)

        source = build / "source"
        fixtures = sorted((source / "testdata").rglob("*.json"))
        fixtures += sorted((source / "docs/reference").glob("submission-all-eggs.json"))
        fixtures = [path for path in fixtures if "runs" in json.loads(path.read_text())]
        # Deterministic fresh sessions and a replay-to-live continuation.
        prefix = out / "prefix.json"
        dump(prefix, {"runs": [{"seed": [11529215046068471596, 16434892977836155571,
                                         8951483993266974514, 4110194298260983404],
                               "actions": [{"type": "move", "dir": "south"}]}]})
        live_actions = [{"type": "move", "dir": "south"}, {"type": "move", "dir": "east"},
                        {"type": "wait"}, {"type": "move", "dir": "north"}]
        cases = [("fresh-" + str(seed), ["--seed", ("%064x" % seed)], b"\njl.kQ", live_actions)
                 for seed in (1, 17, 65537)]
        cases += [("replay-" + str(index), ["--replay", str(path)], b"\nQ", None)
                  for index, path in enumerate(fixtures)]
        cases += [("continuation", ["--replay", str(prefix)], b"\njQ",
                   [{"type": "move", "dir": "south"}] * 2)]
        for name, options, keys, expected_actions in cases:
            rows, recordings = [], []
            for arm, binary in binaries.items():
                record = out / (name + "-" + arm + ".json")
                code, output, elapsed = run(binary, [*options, "--record", str(record)],
                                            out / (name + "-" + arm + ".log"), keys,
                                            timeout=args.timeout)
                rows.append((code, output.replace(str(record).encode(), b"<record>"), elapsed))
                recordings.append(json.loads(record.read_text()) if record.exists() else None)
            passed = (rows[0][:2] == rows[1][:2] and recordings[0] == recordings[1]
                      and rows[0][0] in (0, 1))
            if rows[0][0] == 0:
                passed = passed and recordings[0] is not None
            if name.startswith("fresh") or name == "continuation":
                passed = passed and rows[0][0] == 0 and recordings[0] is not None
            if expected_actions is not None:
                passed = passed and actions_match(recordings[0], expected_actions)
            checks.append({"case": name, "passed": bool(passed), "exit_code": rows[0][0],
                           "options": options, "recorded": recordings[0] is not None,
                           "outcome": "gameplay" if rows[0][0] == 0 else "matched-rejection",
                           "seconds": {arm: row[2] for arm, row in zip(binaries, rows)}})
            if not passed:
                raise ValueError("TUI/replay mismatch: " + name)
            dump(out / "summary.json", result)
        report = json.loads((build / "build/native.json").read_text())
        violations = report_violations(report)
        result["coverage"] = coverage(report)
        result["coverage_violations"] = violations
        result["structural_statuses"] = dict(Counter(
            row["status"] for row in report.get("structural_allocations", [])))
        if violations:
            raise ValueError("native accounting violations")
        if not report.get("flattening_state"):
            raise ValueError("no retained flattening")
        result["status"] = "pass"
        print(json.dumps({"status": result["status"], "cases": len(checks),
                          "elf": result["elf"]}, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result.update(status="failed", error=str(exc))
        print(str(exc))
        return 1
    finally:
        dump(out / "summary.json", result)


if __name__ == "__main__":
    raise SystemExit(main())
