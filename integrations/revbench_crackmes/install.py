#!/usr/bin/env python3
"""Install the small crackmes integration into the supported Revbench layout.

Refuses changed anchors and unrelated destination files. --check performs no writes.
The patch is versioned because the local Revbench distribution is not a Git repo.
"""
import argparse
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revbench", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.revbench.resolve()
    patch = HERE / "harness.patch"
    copies = {HERE / "crackmes.py": root / "harness/crackmes.py",
              HERE / "revbench_tests.py": root / "tests/test_crackmes.py"}
    for source, target in copies.items():
        if target.exists() and target.read_bytes() != source.read_bytes():
            raise SystemExit(f"refusing to replace a different file: {target}")
    forward = subprocess.run(["git", "apply", "--check", str(patch)], cwd=root,
                             capture_output=True)
    if forward.returncode:
        reverse = subprocess.run(["git", "apply", "--reverse", "--check", str(patch)],
                                 cwd=root, capture_output=True)
        if reverse.returncode:
            raise SystemExit("Revbench wiring differs from the supported patch; review manually")
    if not args.check:
        if not forward.returncode:
            subprocess.run(["git", "apply", str(patch)], cwd=root, check=True)
        for source, target in copies.items():
            shutil.copyfile(source, target)
    print("crackmes integration compatible" if args.check else "crackmes integration installed")


if __name__ == "__main__":
    main()
