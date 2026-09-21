"""Time a complete RevGame reference replay, excluding interactive TUI waiting."""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import resource
import selectors
import signal
import statistics
import struct
import subprocess
import termios
import time

from conformance.process import digest, dump
from integrations.revgame.check import elf_properties

PROMPT = b"Press Enter to enter the TUI..."


def replay(binary, reference, log, timeout):
    master, slave = pty.openpty()
    proc = None
    output = bytearray()
    ready = None
    selector = selectors.DefaultSelector()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
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
        code = proc.wait(timeout=max(0.1, timeout - (time.perf_counter() - started)))
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        turns = re.search(rb"Replay complete: (\d+) turns consumed", output)
        if code != 0 or ready is None or turns is None:
            raise ValueError("replay did not complete successfully")
        return {"replay_seconds": ready, "full_process_seconds": time.perf_counter() - started,
                "cpu_seconds": after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
                "exit_code": code, "turns": int(turns[1]),
                "output_sha256": hashlib.sha256(output).hexdigest()}
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
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
    p.add_argument("--runs", type=int, default=11)
    p.add_argument("--timeout", type=float, default=120)
    args = p.parse_args(argv)
    if args.runs < 1 or args.timeout <= 0:
        p.error("runs and timeout must be positive")
    build, out = args.build.resolve(), args.out.resolve()
    reference = build / "source/docs/reference/submission-all-eggs.json"
    binaries = {"clean": build / "build/clean", "native": build / "build/native"}
    if args.previous:
        previous = args.previous.resolve()
        if digest(previous / "build/clean") != digest(binaries["clean"]):
            raise ValueError("previous build does not have the same clean baseline")
        if digest(previous / "source/docs/reference/submission-all-eggs.json") != digest(reference):
            raise ValueError("previous build does not have the same replay")
        binaries["previous"] = previous / "build/native"
    out.mkdir(parents=True, exist_ok=False)
    affinity = os.sched_getaffinity(0)
    cpu = min(affinity)
    samples = []
    result = {"status": "running", "cpu": cpu, "samples": samples,
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
                row = replay(binaries[arm], reference, out / f"{index + 1:02d}-{arm}.log", args.timeout)
                row.update(arm=arm, index=index, warmup=index < 0)
                observed = (row["output_sha256"], row["turns"])
                if expected is None:
                    expected = observed
                if observed != expected:
                    raise ValueError("reference replay output mismatch: " + arm)
                samples.append(row)
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
        result["status"] = "pass"
        print(json.dumps({key: value for key, value in result.items() if key != "samples"}, indent=2))
    except Exception as exc:
        result.update(status="failed", error=str(exc))
        raise
    finally:
        os.sched_setaffinity(0, affinity)
        dump(out / "summary.json", result)


if __name__ == "__main__":
    main()
