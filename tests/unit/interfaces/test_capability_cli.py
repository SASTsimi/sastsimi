"""Capability CLI exposes probe/list/approve without leaking local inputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.interfaces.cli.main import main


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
