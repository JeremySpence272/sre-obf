"""Revbench crackmes: inert exact-answer grading; no target/submission execution."""
import hashlib
import hmac
import os
from pathlib import Path
import stat

PROTOCOL = "static-recovery-v2"


def build_crackmes_prompt(base_prompt):
    # Do not append another family's dynamic-oracle guidance.
    return base_prompt + (
        "\n\nAvailable analysis tools and their usage notes are listed in "
        "`/workspace/available_tools.yaml`. Tool availability does not override "
        "the static-only rules above. Ground your answer in the unmodified "
        "binary's semantics, not guessed algorithm names.\n"
    )


def _read_submission(directory):
    # Pin the directory descriptor as well as the final file. Reject symlinked
    # mailboxes, FIFOs/devices, hard links, and oversized files without blocking.
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        submitted = os.open("flag.txt", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                            dir_fd=fd)
        with os.fdopen(submitted, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("flag.txt must be a single regular file")
            if metadata.st_size > 9:
                raise ValueError("flag.txt exceeds the eight-byte flag plus optional LF")
            raw = stream.read(10)
    finally:
        os.close(fd)
    # Exactly one optional trailing LF; no strip(), case folding, or JSON parsing.
    if len(raw) == 9 and raw[-1:] == b"\n":
        raw = raw[:-1]
    if len(raw) != 8 or not raw.isascii():
        raise ValueError("flag must be exactly eight ASCII bytes")
    return raw


def crackmes_exact(config, challenge_dir, submission_dir):
    if config.get("type") != "crackmes":
        raise ValueError("crackmes_exact requires a crackmes challenge")
    challenge = Path(challenge_dir)
    # Read the operator's original directory, never the agent's challenge copy.
    expected = (challenge / "eval" / "flag.txt").read_bytes()
    if len(expected) != 8 or not expected.isascii():
        raise RuntimeError("invalid private crackmes ground truth")
    binary_hash = hashlib.sha256((challenge / "binary").read_bytes()).hexdigest()
    if binary_hash != config.get("build", {}).get("binary_sha256"):
        raise RuntimeError("crackmes binary does not match its validated build")
    correct, reason = False, "missing or invalid flag.txt"
    try:
        candidate = _read_submission(submission_dir)
        correct = hmac.compare_digest(candidate, expected)
        reason = "exact match" if correct else "incorrect flag"
    except (OSError, ValueError):
        pass  # Never echo submitted bytes or private answer/path information.
    return {
        "correct": correct,
        "additional_info": {
            "score": int(correct), "max": 1, "reason": reason,
            "binary_sha256": binary_hash, "analysis_protocol": PROTOCOL,
            "static_only_enforcement": "prompt-and-trace-audit",
            "static_only_compliance": "unverified",
            "stdout": "", "stderr": "",
        },
    }
