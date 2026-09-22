"""Time a complete RevGame reference replay, excluding interactive TUI waiting."""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import math
import os
import platform
from pathlib import Path
import pty
import re
import selectors
import signal
import statistics
import sys
import struct
import subprocess
import termios
import time

from conformance.process import digest, dump
from integrations.revgame.check import elf_properties
from integrations.revgame.performance import SCHEMA, evaluate

PROMPT = b"Press Enter to enter the TUI..."


def replay(binary, reference, log, timeout):
    master, slave = pty.openpty()
    proc = None
    output = bytearray()
    ready = None
    selector = selectors.DefaultSelector()
    started = time.perf_counter()
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        env = dict(os.environ, TERM="xterm-256color", LINES="40", COLUMNS="120", LC_ALL="C")
        started = time.perf_counter()
        proc = subprocess.Popen([str(binary), "--replay", str(reference)],
                                stdin=slave, stdout=slave, stderr=slave, env=env,
                                start_new_session=True,
                                preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.close(slave)
        slave = None
        selector.register(master, selectors.EVENT_READ)
        while selector.get_map():
            if time.perf_counter() - started > timeout:
                raise TimeoutError("reference replay timed out")
            for key, _ in selector.select(0.2):
                try:
                    chunk = os.read(key.fd, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                output.extend(chunk)
                if len(output) > 16 * 1024 * 1024:
                    raise ValueError("reference replay output limit exceeded")
                if ready is None and PROMPT in output:
                    ready = time.perf_counter() - started
                    os.write(master, b"\nQ")
        # Reap this child specifically: RUSAGE_CHILDREN.ru_maxrss is a cumulative
        # high-water mark and cannot measure each sample's memory independently.
        while True:
            pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
            if pid:
                code = os.waitstatus_to_exitcode(status)
                proc.returncode = code
                break
            if time.perf_counter() - started > timeout:
                raise TimeoutError("reference replay exit timed out")
            time.sleep(0.005)
        turns = re.search(rb"Replay complete: (\d+) turns consumed", output)
        if code != 0 or ready is None or turns is None:
            raise ValueError("replay did not complete successfully")
        return {"replay_seconds": ready, "full_process_seconds": time.perf_counter() - started,
                "cpu_seconds": usage.ru_utime + usage.ru_stime,
                "peak_rss_kib": usage.ru_maxrss,
                "exit_code": code, "turns": int(turns[1]),
                "output_sha256": hashlib.sha256(output).hexdigest()}
    finally:
        if proc is not None:
            # A reaped leader can leave descendants holding the PTY open.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        selector.close()
        os.close(master)
        if slave is not None:
            os.close(slave)
        log.write_bytes(output)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--previous", type=Path, help="optional pre-change adapter build")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--runs", type=int, default=31,
                   help="fewer than 31 measured pairs are smoke_only")
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("--reference", type=Path, help="frozen alternate substantive replay")
    p.add_argument("--workload-id", default="reference-all-eggs")
    p.add_argument("--minimum-clean-seconds", type=float, default=0.00001)
    p.add_argument("--policy", choices=("v05", "report-only"), default="v05",
                   help="report-only retains the v04 measurement mode without accepting v05")
    args = p.parse_args(argv)
    if (args.runs < 1 or not math.isfinite(args.timeout) or args.timeout <= 0
            or not math.isfinite(args.minimum_clean_seconds) or args.minimum_clean_seconds <= 0):
        p.error("runs, timeout and minimum-clean-seconds must be finite and positive")
    build, out = args.build.resolve(), args.out.resolve()
    reference = (args.reference or build / "source/docs/reference/submission-all-eggs.json").resolve()
    manifest_path = build / "build/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    binaries = {"clean": build / "build/clean", "native": build / "build/native"}
    for arm, path in binaries.items():
        if digest(path) != manifest["artifacts"][arm]["binary_sha256"]:
            raise ValueError("binary does not match build manifest: " + arm)
    if args.previous:
        previous = args.previous.resolve()
        if digest(previous / "build/clean") != digest(binaries["clean"]):
            raise ValueError("previous build does not have the same clean baseline")
        if not args.reference and digest(previous / "source/docs/reference/submission-all-eggs.json") != digest(reference):
            raise ValueError("previous build does not have the same replay")
        binaries["previous"] = previous / "build/native"
    out.mkdir(parents=True, exist_ok=False)
    affinity = os.sched_getaffinity(0)
    cpu = min(affinity)
    samples = []
    result = {"schema": SCHEMA, "status": "running", "measurement_status": "running",
              "requested_samples": args.runs, "artifacts_unchanged": False,
              "block_id": out.name, "workload_id": args.workload_id,
              "compiler_seed": str(manifest["seed"]), "policy": args.policy,
              "minimum_clean_seconds": args.minimum_clean_seconds,
              "manifest_sha256": digest(manifest_path),
              "cpu": cpu, "samples": samples,
              "host": {"platform": platform.platform(), "machine": platform.machine(),
                       "cpuinfo": Path("/proc/cpuinfo").read_text(),
                       "affinity": sorted(affinity), "load_average": list(os.getloadavg()),
                       "clock_resolution_seconds": time.get_clock_info("perf_counter").resolution,
                       "environment": {k: os.environ.get(k) for k in ("LANG", "LC_ALL", "OMP_NUM_THREADS")}},
              "method": "one warmup per arm; rotating arm order; launch to replay-complete prompt",
              "reference_sha256": digest(reference),
              "actions": sum(len(run["actions"]) for run in json.loads(reference.read_text())["runs"]),
              "binaries": {name: elf_properties(path) for name, path in binaries.items()}}
    try:
        os.sched_setaffinity(0, {cpu})
        expected = None
        arms = list(binaries)
        for index in range(-1, args.runs):
            offset = max(0, index) % len(arms)
            for arm in arms[offset:] + arms[:offset]:
                row = {"arm": arm, "index": index, "warmup": index < 0,
                       "status": "running", "correct": False,
                       "binary_sha256": digest(binaries[arm]), "reference_sha256": digest(reference)}
                samples.append(row)
                dump(out / "summary.json", result)
                try:
                    row.update(replay(binaries[arm], reference, out / f"{index + 1:02d}-{arm}.log", args.timeout))
                except Exception as exc:
                    row.update(status="failed", error=str(exc))
                    raise
                observed = (row["output_sha256"], row["turns"])
                if expected is None:
                    expected = observed
                if observed != expected:
                    row["status"] = "failed"
                    raise ValueError("reference replay output mismatch: " + arm)
                row.update(status="ok", correct=True)
                print(f"{index}: {arm} {row['replay_seconds']:.6f}s", flush=True)
                dump(out / "summary.json", result)
        result["replay"] = {}
        for arm in arms:
            times = [row["replay_seconds"] for row in samples if row["arm"] == arm and not row["warmup"]]
            result["replay"][arm] = {"median_seconds": statistics.median(times),
                                     "min_seconds": min(times), "max_seconds": max(times)}
        medians = {arm: value["median_seconds"] for arm, value in result["replay"].items()}
        result["slowdown"] = medians["native"] / medians["clean"]
        if "previous" in medians:
            result["speedup_vs_previous"] = medians["previous"] / medians["native"]
        for arm, path in binaries.items():
            if digest(path) != result["binaries"][arm]["sha256"]:
                raise ValueError("binary changed during benchmark")
        if digest(reference) != result["reference_sha256"] or digest(manifest_path) != result["manifest_sha256"]:
            raise ValueError("workload or build manifest changed during benchmark")
        result.update(measurement_status="complete", artifacts_unchanged=True)
        result["acceptance"] = evaluate(result)
        result["status"] = result["acceptance"]["status"] if args.policy == "v05" else "report_only"
        print(json.dumps({key: value for key, value in result.items() if key != "samples"}, indent=2))
    except Exception as exc:
        result.update(status="failed", measurement_status="failed", error=str(exc))
        result["acceptance"] = evaluate(result)
        raise
    finally:
        try:
            os.sched_setaffinity(0, affinity)
        finally:
            dump(out / "summary.json", result)
    return 0 if result["status"] in ("pass", "report_only", "smoke_only") else 1


if __name__ == "__main__":
    sys.exit(main())
