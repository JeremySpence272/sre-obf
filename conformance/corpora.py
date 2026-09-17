"""The frozen v04 evaluation matrix: corpora, seeds, resource limits, splits.

The lock beside this module is data, not a pile of command-line arguments, so
that two measurements taken a milestone apart are comparable and so that the
held-out split exists before there is anything to overfit to.

Nothing here decides whether a build is good. It decides what a run is allowed
to call itself. A holdout entry cannot be used to tune, a scale regression
cannot be called a holdout, and an entry whose input/output contract is not
frozen yet cannot produce a reported result at all: that is unknown, and
unknown exits non-zero rather than defaulting to a pass.
"""
from __future__ import annotations

import json
from pathlib import Path

from conformance.process import digest

LOCK = Path(__file__).with_name("corpora.lock.json")
SCHEMA = "sre-corpus-lock-v1"

# What a run says it is doing. The seed set follows from it, so a promotion
# number cannot quietly be taken on a regression seed.
PURPOSES = {"tuning": "regression", "regression": "regression",
            "promotion": "promotion", "holdout": "holdout"}


class CorpusError(ValueError):
    """A use the lock forbids. Never downgraded to a warning."""


def load(path: Path | None = None):
    path = Path(path) if path else LOCK
    lock = json.loads(path.read_text())
    violations = validate(lock)
    if violations:
        raise CorpusError("corpus lock is invalid: " + "; ".join(violations))
    lock["lock_path"] = str(path)
    lock["lock_sha256"] = digest(path)
    return lock


def validate(lock):
    """Self-consistency of the lock itself, as explicit strings."""
    violations = []
    if lock.get("schema") != SCHEMA:
        return [f"schema {lock.get('schema')!r} is not {SCHEMA}"]
    if not lock.get("revision"):
        violations.append("a lock revision is required")
    seeds = lock.get("seeds", {})
    sets = {name: seeds.get(name) for name in ("regression", "promotion", "holdout")}
    for name, values in sets.items():
        if not isinstance(values, list) or not values or any(type(v) is not int for v in values):
            violations.append(f"seed set {name} must be a non-empty list of integers")
    if all(isinstance(values, list) for values in sets.values()):
        for left in sets:
            for right in sets:
                if left < right and set(sets[left]) & set(sets[right]):
                    violations.append(f"seed sets {left} and {right} overlap: "
                                      f"{sorted(set(sets[left]) & set(sets[right]))}")
    splits = lock.get("splits", {})
    for name, split in splits.items():
        if not isinstance(split.get("tuning_allowed"), bool):
            violations.append(f"split {name} must say whether tuning is allowed")
    if splits.get("holdout", {}).get("tuning_allowed"):
        violations.append("the holdout split must not allow tuning")
    build = lock.get("resources", {}).get("build", {})
    for key in ("module_instruction_limit", "compile_timeout_seconds"):
        if not isinstance(build.get(key), (int, float)) or build[key] <= 0:
            violations.append(f"resources.build.{key} must be a positive number")
    corpora = lock.get("corpora", {})
    if not corpora:
        violations.append("the lock names no corpora")
    for name, entry in corpora.items():
        if entry.get("split") not in splits:
            violations.append(f"{name}: unknown split {entry.get('split')!r}")
        if not entry.get("family"):
            violations.append(f"{name}: a program family is required")
        acquisition = entry.get("acquisition")
        if not isinstance(acquisition, dict) or not acquisition.get("kind"):
            violations.append(f"{name}: an acquisition record is required")
            continue
        if acquisition["kind"] == "upstream-archive":
            for key in ("revision", "url"):
                if not acquisition.get(key):
                    violations.append(f"{name}: upstream archive needs {key}")
            # An unacquired entry is allowed to exist; it is not allowed to
            # pretend. A null hash must be labelled, never guessed.
            if acquisition.get("archive_sha256") is None and acquisition.get("state") == "acquired":
                violations.append(f"{name}: claims acquisition without an archive hash")
    if not any(entry.get("split") == "holdout" for entry in corpora.values()):
        violations.append("the matrix has no held-out corpus")
    holdout_families = {entry["family"] for entry in corpora.values()
                        if entry.get("split") == "holdout"}
    tuned_families = {entry["family"] for entry in corpora.values()
                      if entry.get("split") != "holdout"}
    if holdout_families & tuned_families:
        violations.append("a held-out family is also used for tuning: "
                          + ", ".join(sorted(holdout_families & tuned_families)))
    if len(holdout_families) < 2:
        violations.append("gate 7D requires at least two held-out program families")
    return violations


def entry(lock, name):
    if name not in lock["corpora"]:
        raise CorpusError(f"{name!r} is not in the evaluation matrix; "
                          f"known: {', '.join(sorted(lock['corpora']))}")
    return lock["corpora"][name]


def seed_set(lock, purpose):
    if purpose not in PURPOSES:
        raise CorpusError(f"unknown purpose {purpose!r}")
    return list(lock["seeds"][PURPOSES[purpose]])


def resolve(lock, name, purpose, seed=None, high_cap=False):
    """The pinned plan for one measurement, or an explicit refusal.

    Returns the exact limits and provenance a result must record. Raises when
    the lock forbids the use: a holdout program tuned against, a regression
    corpus relabelled as held-out, a seed from the wrong set, or a corpus whose
    input/output contract has never been frozen.
    """
    record = entry(lock, name)
    split = lock["splits"][record["split"]]
    if purpose not in PURPOSES:
        raise CorpusError(f"unknown purpose {purpose!r}")
    if record["split"] == "holdout" and purpose != "holdout":
        raise CorpusError(f"{name} is held out; it may not be used for {purpose}. "
                          "Rotating it into tuning requires reporting its holdout result first.")
    if purpose == "holdout" and record["split"] != "holdout":
        raise CorpusError(f"{name} is in the {record['split']} split; a "
                          "regression corpus is not fresh generalization evidence")
    if purpose != "holdout" and not split["tuning_allowed"]:
        raise CorpusError(f"{name}: the {record['split']} split does not allow {purpose}")
    seeds = seed_set(lock, purpose)
    if seed is None:
        seed = seeds[0]
    elif seed not in seeds:
        raise CorpusError(f"seed {seed} is not in the {PURPOSES[purpose]} seed set {seeds}")
    if record.get("workload_state") == "pending" or record.get("workload_contract") is None:
        raise CorpusError(f"{name}: no frozen input/output contract, so no result may be "
                          "reported from it yet. Unknown is not a pass.")
    build = lock["resources"]["build"]
    limit = (build["high_cap_experiment_module_instruction_limit"] if high_cap
             else build["module_instruction_limit"])
    if high_cap and not limit:
        raise CorpusError("no high-cap experiment limit is pinned")
    return {"corpus": name, "split": record["split"], "family": record["family"],
            "purpose": purpose, "seed": seed, "seed_set": seeds,
            "tuning_allowed": bool(split["tuning_allowed"]) and purpose != "holdout",
            "module_instruction_limit": limit,
            "module_instruction_cap_label": "high-cap-experiment" if high_cap else "primary",
            "compile_timeout": float(build["compile_timeout_seconds"]),
            "required_build_flags": list(build.get("required_scale_flags", [])),
            "container": dict(lock["resources"]["container"]),
            "workload_timeout": lock["resources"]["workload"]["timeout_seconds"],
            "lock_revision": lock["revision"], "lock_sha256": lock.get("lock_sha256"),
            "result_is_evidence_of": ("held-out generalization" if purpose == "holdout"
                                      else "scale or fixture continuity, not generalization")}


def file_drift(lock, root=None):
    """Enumerated in-repo corpus files whose bytes no longer match the lock."""
    root = Path(root) if root else Path(__file__).parents[1]
    drift = []
    for name, record in lock["corpora"].items():
        acquisition = record["acquisition"]
        if acquisition["kind"] != "in-repo":
            continue
        base = root / acquisition["root"]
        for relative, expected in sorted(acquisition["files"].items()):
            path = base / relative
            if not path.exists():
                drift.append(f"{name}: {relative} is missing")
            elif digest(path) != expected:
                drift.append(f"{name}: {relative} no longer matches the lock")
    return drift


def summary(lock):
    """What a result file records so the matrix it was taken under is legible."""
    return {"lock_revision": lock["revision"], "lock_sha256": lock.get("lock_sha256"),
            "seeds": {name: list(lock["seeds"][name])
                      for name in ("regression", "promotion", "holdout")},
            "splits": {name: sorted(key for key, record in lock["corpora"].items()
                                    if record["split"] == name)
                       for name in lock["splits"]},
            "resources": lock["resources"]}
