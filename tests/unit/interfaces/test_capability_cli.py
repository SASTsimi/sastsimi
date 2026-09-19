"""Capability CLI exposes probe/list/approve without leaking local inputs."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from sastsimi.interfaces.cli.main import main


def _run_isolated_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sastsimi", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def test_capability_probe_and_list_emit_only_sanitized_structured_data(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_dir = tmp_path / "TEST_ONLY_PRIVATE_PATH"
    assert (
        main(
            [
                "--data-dir",
                str(data_dir),
                "capability",
                "probe",
                "PYTHON_AST",
                "--format",
                "json",
            ]
        )
        == 0
    )
    probe = json.loads(capsys.readouterr().out)
    assert probe["data"]["activation_supported"] is True
    assert probe["data"]["approval_target_hash"] is not None
    assert probe["data"]["approved_profile_ref"] is None
    assert probe["data"]["kind"] == "PYTHON_AST"
    assert probe["data"]["safe_summary"] == "Python AST parse probe passed"
    assert probe["data"]["status"] == "PASSED"
    assert "TEST_ONLY_PRIVATE_PATH" not in json.dumps(probe)

    assert (
        main(
            [
                "--data-dir",
                str(data_dir),
                "capability",
                "list",
                "--format",
                "json",
            ]
        )
        == 0
    )
    listed = json.loads(capsys.readouterr().out)
    assert listed["data"]["count"] == 1
    assert listed["data"]["probes"] == [probe["data"]]
    assert "TEST_ONLY_PRIVATE_PATH" not in json.dumps(listed)


def test_python_runtime_probe_is_distinct_from_python_ast(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catches PYTHON_RUNTIME being omitted or published as the AST tool."""

    data_dir = tmp_path / "TEST_ONLY_PRIVATE_PATH"
    assert (
        main(
            [
                "--data-dir",
                str(data_dir),
                "capability",
                "probe",
                "PYTHON_RUNTIME",
                "--format",
                "json",
            ]
        )
        == 0
    )

    probe = json.loads(capsys.readouterr().out)["data"]
    assert probe["activation_supported"] is True
    assert probe["approval_target_hash"] is not None
    assert probe["approved_profile_ref"] is None
    assert probe["kind"] == "PYTHON_RUNTIME"
    assert probe["safe_summary"] == "Python runtime start probe passed"
    assert probe["status"] == "PASSED"
    assert "TEST_ONLY_PRIVATE_PATH" not in json.dumps(probe)


def test_capability_approve_rejects_wrong_exact_target_hash_safely(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_dir = tmp_path / "TEST_ONLY_PRIVATE_PATH"
    assert (
        main(
            [
                "--data-dir",
                str(data_dir),
                "capability",
                "probe",
                "PYTHON_AST",
                "--format",
                "json",
            ]
        )
        == 0
    )
    probe = json.loads(capsys.readouterr().out)["data"]

    assert (
        main(
            [
                "--data-dir",
                str(data_dir),
                "capability",
                "approve",
                probe["probe_id"],
                "--target-hash",
                "f" * 64,
                "--format",
                "json",
            ]
        )
        == 4
    )
    output = capsys.readouterr()
    assert output.out == ""
    denied = json.loads(output.err)
    assert denied["status"] == "error"
    assert denied["code"] == "CAPABILITY_UNSUPPORTED"
    assert denied["data"] == {
        "probe_id": probe["probe_id"],
        "safe_summary": "Capability approval was denied",
        "status": "BLOCKED",
    }
    assert "APPROVAL_TARGET_MISMATCH" not in json.dumps(denied)
    assert "TEST_ONLY_PRIVATE_PATH" not in json.dumps(denied)


def test_capability_probe_can_be_approved_by_a_separate_cli_process(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "TEST_ONLY_PRIVATE_PATH"
    common = ("--data-dir", str(data_dir), "capability")

    probed = _run_isolated_cli(
        *common,
        "probe",
        "PYTHON_AST",
        "--format",
        "json",
    )
    assert probed.returncode == 0, probed.stderr
    probe = json.loads(probed.stdout)["data"]

    orphan = b"unreferenced-artifact"
    orphan_hash = hashlib.sha256(orphan).hexdigest()
    orphan_path = (
        data_dir / "artifacts" / "sha256" / orphan_hash[:2] / orphan_hash[2:]
    )
    orphan_path.parent.mkdir(parents=True, exist_ok=True)
    orphan_path.write_bytes(orphan)

    approved = _run_isolated_cli(
        *common,
        "approve",
        probe["probe_id"],
        "--target-hash",
        probe["approval_target_hash"],
        "--format",
        "json",
    )
    assert approved.returncode == 0, approved.stderr
    activation = json.loads(approved.stdout)["data"]
    assert activation["probe_id"] == probe["probe_id"]
    assert activation["status"] == "ACTIVE"
    assert activation["profile_ref"]["content_hash"]
    assert "TEST_ONLY_PRIVATE_PATH" not in approved.stdout

    listed = _run_isolated_cli(*common, "list", "--format", "json")
    assert listed.returncode == 0, listed.stderr
    saved = json.loads(listed.stdout)["data"]["probes"]
    assert len(saved) == 1
    assert saved[0]["approved_profile_ref"] == activation["profile_ref"]
    assert not orphan_path.exists()
    assert (data_dir / "quarantine" / orphan_hash).read_bytes() == orphan


def test_capability_approval_rejects_corrupt_persisted_probe_evidence(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "TEST_ONLY_PRIVATE_PATH"
    common = ("--data-dir", str(data_dir), "capability")
    probed = _run_isolated_cli(
        *common,
        "probe",
        "PYTHON_AST",
        "--format",
        "json",
    )
    assert probed.returncode == 0, probed.stderr
    probe = json.loads(probed.stdout)["data"]
    evidence_files = tuple((data_dir / "artifacts" / "sha256").glob("*/*"))
    assert len(evidence_files) == 1
    evidence_files[0].write_bytes(b"corrupt-evidence")

    denied = _run_isolated_cli(
        *common,
        "approve",
        probe["probe_id"],
        "--target-hash",
        probe["approval_target_hash"],
        "--format",
        "json",
    )
    assert denied.returncode == 4
    assert denied.stdout == ""
    response = json.loads(denied.stderr)
    assert response["code"] == "CAPABILITY_UNSUPPORTED"
    assert response["data"]["status"] == "BLOCKED"
    assert "TEST_ONLY_PRIVATE_PATH" not in denied.stderr


def test_codeql_capability_probe_requires_an_explicit_production_profile(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catches the legacy host-CodeQL probe being reachable without a profile."""

    private_data_dir = tmp_path / "PRIVATE_CODEQL_DATA"

    assert (
        main(
            [
                "--data-dir",
                str(private_data_dir),
                "capability",
                "probe",
                "CODEQL",
                "--format",
                "json",
            ]
        )
        == 2
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert "PRIVATE_CODEQL_DATA" not in output.err
