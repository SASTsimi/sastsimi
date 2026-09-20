from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import run_local_evaluation_smoke as smoke

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "scripts" / "run_local_evaluation_smoke.py"


def test_plan_uses_real_evaluate_command_and_exact_pygoat_commit(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "local-evaluation.toml"
    profile.write_text('purpose = "LOCAL_EVALUATION"\n', encoding="utf-8")
    data_dir = tmp_path / "runtime"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--profile",
            str(profile),
            "--data-dir",
            str(data_dir),
            "--target",
            "pygoat",
            "--print-plan",
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "runs": [
            {
                "commit": "19d17cc8874861142b330636d068bbde54e86b85",
                "command": [
                    sys.executable,
                    "-m",
                    "sastsimi",
                    "--data-dir",
                    str(data_dir.resolve()),
                    "evaluate",
                    "analyze",
                    "--repo",
                    "https://github.com/adeyosemanputra/pygoat.git",
                    "--commit",
                    "19d17cc8874861142b330636d068bbde54e86b85",
                    "--profile",
                    str(profile.resolve()),
                    "--format",
                    "json",
                ],
                "repository": "https://github.com/adeyosemanputra/pygoat.git",
                "target": "pygoat",
            }
        ],
        "schema_version": 1,
    }


def test_missing_local_profile_returns_safe_reason(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--profile",
            str(tmp_path / "missing.toml"),
            "--data-dir",
            str(tmp_path / "runtime"),
            "--target",
            "itsdangerous",
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert json.loads(completed.stderr) == {
        "reason_code": "LOCAL_EVALUATION_PROFILE_NOT_FOUND",
        "schema_version": 1,
        "status": "failed",
    }


def test_validate_run_accepts_exported_local_pygoat_report(tmp_path: Path) -> None:
    report = tmp_path / "reports" / "analysis-pygoat" / "F-001.md"
    report.parent.mkdir(parents=True)
    report.write_text(
        "# SQL injection\n\n"
        "- 실행 목적: `LOCAL_EVALUATION`\n"
        "- 운영 준비 상태: `NOT_PRODUCTION_READY`\n",
        encoding="utf-8",
    )

    summary = smoke.validate_run(
        target=smoke.TARGETS[0],
        evaluate={
            "schema_version": 1,
            "command": "evaluate analyze",
            "status": "ok",
            "code": "OK",
            "data": {
                "analysis_id": "analysis-pygoat",
                "status": "TERMINAL",
                "result_record_id": "result-1",
                "purpose": "LOCAL_EVALUATION",
                "production_ready": False,
            },
        },
        result={
            "schema_version": 1,
            "command": "results",
            "status": "ok",
            "code": "OK",
            "data": {
                "analysis_id": "analysis-pygoat",
                "status": "COMPLETE",
                "purpose": "LOCAL_EVALUATION",
                "production_ready": False,
                "finding_count": 1,
                "report_count": 1,
                "verdict_counts": {"TRUE": 1},
            },
        },
        reports={
            "schema_version": 1,
            "command": "reports",
            "status": "ok",
            "code": "OK",
            "data": {
                "count": 1,
                "reports": [
                    {
                        "analysis_id": "analysis-pygoat",
                        "finding_id": "finding-1",
                        "hypothesis_id": "hypothesis-1",
                        "title": "SQL injection",
                        "status": "DRAFTED_CURRENT",
                        "cwe": "CWE-89",
                        "purpose": "LOCAL_EVALUATION",
                        "production_ready": "false",
                    }
                ],
            },
        },
        exported_reports={"finding-1": report},
        data_dir=tmp_path,
    )

    assert summary == {
        "analysis_id": "analysis-pygoat",
        "commit": "19d17cc8874861142b330636d068bbde54e86b85",
        "finding_count": 1,
        "report_count": 1,
        "reports": ["reports/analysis-pygoat/F-001.md"],
        "repository": "https://github.com/adeyosemanputra/pygoat.git",
        "result_status": "COMPLETE",
        "target": "pygoat",
        "verdict_counts": {"TRUE": 1},
    }


def test_validate_run_rejects_pygoat_without_true_report(tmp_path: Path) -> None:
    with pytest.raises(smoke.SmokeFailure, match="PYGOAT_TRUE_REPORT_REQUIRED"):
        smoke.validate_run(
            target=smoke.TARGETS[0],
            evaluate={
                "command": "evaluate analyze",
                "status": "ok",
                "code": "OK",
                "data": {
                    "analysis_id": "analysis-pygoat",
                    "status": "TERMINAL",
                    "purpose": "LOCAL_EVALUATION",
                    "production_ready": False,
                },
            },
            result={
                "command": "results",
                "status": "ok",
                "code": "OK",
                "data": {
                    "analysis_id": "analysis-pygoat",
                    "status": "COMPLETE",
                    "purpose": "LOCAL_EVALUATION",
                    "production_ready": False,
                    "finding_count": 0,
                    "report_count": 0,
                    "verdict_counts": {"FALSE": 1},
                },
            },
            reports={
                "command": "reports",
                "status": "ok",
                "code": "OK",
                "data": {"count": 0, "reports": []},
            },
            exported_reports={},
            data_dir=tmp_path,
        )


def test_run_target_queries_results_and_exports_every_report(tmp_path: Path) -> None:
    profile = (tmp_path / "profile.toml").resolve()
    profile.write_text('purpose = "LOCAL_EVALUATION"\n', encoding="utf-8")
    data_dir = (tmp_path / "runtime").resolve()
    calls: list[list[str]] = []

    def execute(command: list[str], _timeout_seconds: int) -> dict[str, object]:
        calls.append(command)
        if "evaluate" in command:
            return {
                "command": "evaluate analyze",
                "status": "ok",
                "code": "OK",
                "data": {
                    "analysis_id": "analysis-pygoat",
                    "status": "TERMINAL",
                    "purpose": "LOCAL_EVALUATION",
                    "production_ready": False,
                },
            }
        if "results" in command:
            return {
                "command": "results",
                "status": "ok",
                "code": "OK",
                "data": {
                    "analysis_id": "analysis-pygoat",
                    "status": "COMPLETE",
                    "purpose": "LOCAL_EVALUATION",
                    "production_ready": False,
                    "finding_count": 1,
                    "report_count": 1,
                    "verdict_counts": {"TRUE": 1},
                },
            }
        if "reports" in command:
            return {
                "command": "reports",
                "status": "ok",
                "code": "OK",
                "data": {
                    "count": 1,
                    "reports": [
                        {
                            "analysis_id": "analysis-pygoat",
                            "finding_id": "finding-1",
                            "purpose": "LOCAL_EVALUATION",
                            "production_ready": "false",
                        }
                    ],
                },
            }
        report = data_dir / "reports" / "analysis-pygoat" / "F-001.md"
        report.parent.mkdir(parents=True)
        report.write_text(
            "# Finding\n\n"
            "- 실행 목적: `LOCAL_EVALUATION`\n"
            "- 운영 준비 상태: `NOT_PRODUCTION_READY`\n",
            encoding="utf-8",
        )
        return {
            "finding_id": "finding-1",
            "path": "reports/analysis-pygoat/F-001.md",
        }

    summary = smoke.run_target(
        target=smoke.TARGETS[0],
        profile=profile,
        data_dir=data_dir,
        timeout_seconds=60,
        execute=execute,
    )

    assert summary["analysis_id"] == "analysis-pygoat"
    assert [
        command[5] if command[5] != "report" else "report export" for command in calls
    ] == ["evaluate", "results", "reports", "report export"]
    assert all("demo" not in command for command in calls)
