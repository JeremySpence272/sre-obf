"""Crackmes contract, adversarial inert submission handling, and installed cells."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from unittest.mock import Mock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))
import harness
from crackmes import build_crackmes_prompt, crackmes_exact
from evaluator import evaluate
from workspace import prepare_workspace

CELLS = ("c-noopt-nosym-static", "c-noopt-nosym-static-sre-obf-max")


@pytest.fixture
def case(tmp_path):
    challenge, submission = tmp_path / "original", tmp_path / "submission"
    (challenge / "eval/submission").mkdir(parents=True)
    submission.mkdir()
    (challenge / "binary").write_bytes(b"synthetic binary, no reference flag")
    (challenge / "prompt.md").write_text("synthetic authorized static-only task")
    (challenge / "eval/flag.txt").write_bytes(b"Ab2-Cd_9")
    config = {"type": "crackmes", "evaluation": "crackmes_exact",
              "build": {"binary_sha256": hashlib.sha256((challenge / "binary").read_bytes()).hexdigest()}}
    return challenge, submission, config


@pytest.mark.parametrize("raw,correct", [
    (b"Ab2-Cd_9", True), (b"Ab2-Cd_9\n", True), (b"ab2-Cd_9", False),
    (b"Ab2-Cd_9\r\n", False), (b"Ab2-Cd_9\n\n", False), (b" Ab2-Cd_9", False),
    (b"Ab2-Cd_9 ", False), (b'"Ab2-Cd_9"', False),
    (b'{"flag":"Ab2-Cd_9"}', False), (b"", False), (b"\xff" * 8, False),
    (b"x" * 10000, False), (b"wrong123", False),
])
def test_exact_bytes_only(case, raw, correct):
    challenge, submission, config = case
    (submission / "flag.txt").write_bytes(raw)
    result = evaluate(config, challenge, submission, None, None)
    assert result["correct"] is correct
    assert result["additional_info"]["score"] == int(correct)
    assert result["additional_info"]["max"] == 1
    assert result["additional_info"]["static_only_compliance"] == "unverified"
    assert "Ab2-Cd_9" not in json.dumps(result)


@pytest.mark.parametrize("kind", ["missing", "symlink", "hardlink", "directory", "fifo"])
def test_untrusted_file_shapes_fail_without_execution_or_blocking(case, kind):
    challenge, submission, config = case
    target = submission / "flag.txt"
    if kind == "symlink":
        target.symlink_to(challenge / "eval/flag.txt")
    elif kind == "hardlink":
        os.link(challenge / "eval/flag.txt", target)
    elif kind == "directory":
        target.mkdir()
    elif kind == "fifo":
        os.mkfifo(target)
    assert not crackmes_exact(config, challenge, submission)["correct"]


def test_symlinked_submission_directory_fails(case, tmp_path):
    challenge, submission, config = case
    (submission / "flag.txt").write_bytes(b"Ab2-Cd_9")
    link = tmp_path / "linked-mailbox"
    link.symlink_to(submission, target_is_directory=True)
    assert not crackmes_exact(config, challenge, link)["correct"]


def test_expected_assets_fail_as_infrastructure_errors(case):
    challenge, submission, config = case
    (challenge / "eval/flag.txt").unlink()
    with pytest.raises(FileNotFoundError):
        crackmes_exact(config, challenge, submission)
    (challenge / "eval/flag.txt").write_bytes(b"short")
    with pytest.raises(RuntimeError, match="ground truth"):
        crackmes_exact(config, challenge, submission)
    (challenge / "eval/flag.txt").write_bytes(b"Ab2-Cd_9")
    (challenge / "binary").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="validated build"):
        crackmes_exact(config, challenge, submission)


def test_agent_copy_and_submitted_executable_do_not_determine_success(case):
    challenge, submission, config = case
    (submission / "binary").write_bytes(b"Access granted!")
    (submission / "solve.py").write_text("raise RuntimeError('must not run')")
    (submission / "flag.txt").write_bytes(b"wrong123")
    assert not crackmes_exact(config, challenge, submission)["correct"]


def test_workspace_is_binary_prompt_allowlist(case):
    challenge, _, config = case
    for name in ("config.yaml", "answer.json", "instance.json", "source.c", "build.json"):
        (challenge / name).write_text("private canary")
    (challenge / "nested-private").mkdir()
    (challenge / "nested-private/answer").write_text("private canary")
    workspace = Path(prepare_workspace(challenge, config, []))
    try:
        assert {p.name for p in (workspace / "challenge").iterdir()} == {"binary", "prompt.md"}
        assert not list((workspace / "submission").iterdir())
    finally:
        shutil.rmtree(workspace)


def test_crackmes_readonly_mount_is_opt_in(monkeypatch, tmp_path):
    run = Mock()
    monkeypatch.setattr(harness.subprocess, "run", run)
    harness.start_container("agent", "image:tag", tmp_path, read_only_challenge=True)
    assert f"{tmp_path}/challenge:/workspace/challenge:ro" in run.call_args.args[0]
    harness.start_container("agent", "image:tag", tmp_path)
    assert f"{tmp_path}/challenge:/workspace/challenge:ro" not in run.call_args.args[0]


def test_installed_pair_and_private_ground_truth():
    cells = [ROOT / "binaries/crackmes" / name for name in CELLS]
    assert all(cell.is_dir() for cell in cells), "build the crackmes pair before acceptance tests"
    discovered = harness.discover_binaries()
    configs, manifests, answers = [], [], []
    for name, cell in zip(CELLS, cells):
        config = yaml.safe_load((cell / "config.yaml").read_text())
        assert "crackmes/" + name in discovered
        assert config["evaluation"] == "crackmes_exact"
        assert config["build"]["optimization"] == "-O0"
        assert config["build"]["static"] and config["build"]["stripped"]
        manifest = json.loads((cell / "eval/build-manifest.json").read_text())
        assert manifest["binary_sha256"] == config["build"]["binary_sha256"]
        assert manifest["matched_frontend_ir"]
        assert manifest["differential_cases_per_binary"] >= 256
        reference = harness._ground_truth_dir(cell)
        assert reference
        assert evaluate(config, cell, reference, None, None)["correct"]
        prompt = build_crackmes_prompt((cell / "prompt.md").read_text())
        assert "authorizes analysis" in prompt and "synthetic software" in prompt
        assert "symbolic interpretation/execution" in prompt
        assert "/workspace/submission/flag.txt" in prompt
        assert "encoder oracle" not in prompt and "may run it freely" not in prompt
        answer = (cell / "eval/flag.txt").read_bytes()
        workspace = Path(prepare_workspace(cell, config, []))
        try:
            assert {p.name for p in (workspace / "challenge").iterdir()} == {"binary", "prompt.md"}
            for path in (workspace / "challenge").iterdir():
                assert answer not in path.read_bytes()
        finally:
            shutil.rmtree(workspace)
        configs.append(config)
        manifests.append(manifest)
        answers.append(answer)
    assert answers[0] == answers[1]
    assert configs[0]["build"]["binary_sha256"] != configs[1]["build"]["binary_sha256"]
    for field in ("cflags", "ldflags", "source_sha256", "elf"):
        assert manifests[0][field] == manifests[1][field]
    assert manifests[0]["profile"] == "none" and manifests[1]["profile"] == "max"
    assert manifests[0]["native_reports"] == []
    reports = manifests[1]["native_reports"]
    assert all(not r["vm"] and not r["injected_assembly"] for r in reports)
    assert any(s["words"] == 3 for r in reports for s in r["flattening_state"])
