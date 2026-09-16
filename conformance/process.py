"""Bounded trusted tool execution with process-group and Docker cleanup."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class ToolFailure(RuntimeError):
    pass


class Runner:
    def __init__(self, root: Path, logs: Path, image: str | None = None,
                 timeout: float = 180, mounts: tuple[Path, ...] = ()):
        self.root, self.logs, self.image = root.resolve(), logs.resolve(), image
        self.mounts = tuple(path.resolve() for path in mounts)
        self.timeout, self.records = timeout, []
        self.logs.mkdir(parents=True, exist_ok=True)

    def run(self, args: list[str], *, stdin: bytes | None = None,
            image: str | None = None, timeout: float | None = None) -> bytes:
        use_image = image or self.image
        container = "sre-conformance-" + uuid.uuid4().hex if use_image else None
        command = list(map(str, args))
        if container:
            mounts = [self.root]
            for path in self.mounts:
                if not any(path.is_relative_to(parent) for parent in mounts):
                    mounts.append(path)
            mount_args = [arg for path in mounts for arg in ("-v", f"{path}:{path}")]
            command = ["docker", "run", "--rm", "-i", "--network", "none",
                       "--hostname", "sre-conformance",
                       "--add-host", "sre-conformance:127.0.0.1",
                       "--name", container, "--user", f"{os.getuid()}:{os.getgid()}",
                       "--memory", "6g", "--cpus", "4", "-e", "HOME=/tmp",
                       *mount_args, "-w", str(self.root),
                       "--entrypoint", command[0], use_image, *command[1:]]
        number = len(self.records)
        out = self.logs / f"{number:04d}.stdout"
        err = self.logs / f"{number:04d}.stderr"
        started = time.monotonic()
        record = {"command": command, "stdout": str(out), "stderr": str(err)}
        self.records.append(record)
        proc = None
        try:
            with out.open("wb") as stdout, err.open("wb") as stderr:
                proc = subprocess.Popen(command, cwd=self.root, stdin=subprocess.PIPE,
                                        stdout=stdout, stderr=stderr,
                                        start_new_session=True)
                try:
                    proc.communicate(stdin, timeout=timeout or self.timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    record["status"] = "timeout"
                    raise ToolFailure(f"tool timed out; see {err}") from None
            record["returncode"] = proc.returncode
            if proc.returncode:
                record["status"] = "tool_error"
                raise ToolFailure(f"tool exited {proc.returncode}; see {err}")
            if out.stat().st_size > 16 * 1024 * 1024:
                record["status"] = "output_limit"
                raise ToolFailure(f"tool output exceeded 16 MiB; see {out}")
            record["status"] = "ok"
            return out.read_bytes()
        finally:
            record["seconds"] = round(time.monotonic() - started, 4)
            if proc is not None and proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            if container:
                subprocess.run(["docker", "rm", "-f", container],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=15, check=False)
            dump(self.logs / "commands.json", self.records)
