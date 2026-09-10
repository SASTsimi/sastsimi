"""The CLI exposes analysis start, persisted results and report queries."""

import json
from pathlib import Path

import pytest

from sastsimi.interfaces.cli.main import main


def test_results_reports_persisted_not_found_for_missing_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--data-dir", str(tmp_path), "results", "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["data"] == {
        "analysis_id": "fake-analysis",
        "status": "NOT_FOUND",
        "work_counts": {},
    }


def test_fake_cli_analyze_results_and_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "--data-dir",
                str(tmp_path),
                "analyze",
                "--scenario",
                "FALSE",
                "--format",
                "json",
            ]
        )
        == 0
    )
    first = json.loads(capsys.readouterr().out)
    assert first["data"]["verdict_counts"] == {"FALSE": 1}
    assert main(["--data-dir", str(tmp_path), "results", "--format", "json"]) == 0
    persisted = json.loads(capsys.readouterr().out)
    assert persisted["data"]["status"] == "COMPLETE"
    assert main(["--data-dir", str(tmp_path), "reports", "--format", "json"]) == 0
    reports = json.loads(capsys.readouterr().out)
    assert reports["data"] == {"count": 0, "reports": []}
