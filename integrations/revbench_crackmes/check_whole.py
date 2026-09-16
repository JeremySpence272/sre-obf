"""Trusted differential checks for a versioned whole-IR crackme pair; no agent run."""
import argparse
import json
import os
from pathlib import Path
import random
import subprocess
import sys

from conformance.process import digest, dump
from integrations.revbench_crackmes.build import elf_properties


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--instance", type=Path, required=True)
    args = p.parse_args(argv)
    build = args.build.resolve()
    manifest = json.loads((build / "manifest.json").read_text())
    password = json.loads(args.instance.read_text())["password"].encode("ascii")
    candidates = [password] + [b"A" * n for n in (0, 1, 7, 9, 64)]
    for i in range(8):
        for bit in range(7):
            changed = bytearray(password)
            changed[i] ^= 1 << bit
            if 0 not in changed:
                candidates.append(bytes(changed))
    rng = random.Random(91827)
    candidates += [bytes(rng.randrange(1, 128) for _ in range(8)) for _ in range(256)]
    hashes = {}
    for arm in ("clean", "native"):
        binary = build / arm
        if digest(binary) != manifest["artifacts"][arm]["binary_sha256"]:
            raise RuntimeError("binary hash mismatch")
        elf_properties(binary)
        if password in binary.read_bytes():
            raise RuntimeError("plaintext answer found in public binary")
        for candidate in candidates:
            expected = (0, b"Access granted!\n", b"") if candidate == password else (1, b"Access denied.\n", b"")
            run = subprocess.run([os.fsencode(binary), candidate], capture_output=True, timeout=10)
            if (run.returncode, run.stdout, run.stderr) != expected:
                raise RuntimeError("whole-IR crackme correctness failure")
        hashes[arm] = digest(binary)
    native = json.loads((build / "native.json").read_text())
    if not any(f["status"] == "fused" and f["callee"] == "check_password" for f in native["fused_calls"]):
        raise RuntimeError("checker call boundary survived requested fusion")
    dump(build / "correctness.json", {"correctness": True, "vectors_per_binary": len(candidates),
        "hashes": hashes, "instance_sha256": digest(args.instance), "agent_benchmark": "not_run"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
