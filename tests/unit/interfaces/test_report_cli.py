"""The public CLI exposes report list, show, and Markdown export commands."""

import json
from pathlib import Path

import pytest

from sastsimi.interfaces.cli import report as report_command
from sastsimi.interfaces.cli import reports as reports_command
from sastsimi.interfaces.cli.main import main


def test_report_show_and_export_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exported = tmp_path / "reports" / "analysis-1" / "finding-1.md"
    requested_analyses: list[str] = []

    def list_reports(_data_dir: Path, analysis_id: str) -> dict[str, object]:
        requested_analyses.append(analysis_id)
        return {"count": 0, "reports": []}

    monkeypatch.setattr(reports_command, "run", list_reports)
    assert (
        main(
            [
                "--data-dir",
                str(tmp_path),
                "reports",
                "analysis-1",
                "--format",
                "json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["data"] == {
        "count": 0,
        "reports": [],
    }
    assert requested_analyses == ["analysis-1"]
    monkeypatch.setattr(
        report_command, "show", lambda _data_dir, _finding_id: "# Current report\n"
    )
    monkeypatch.setattr(
        report_command, "export", lambda _data_dir, _finding_id: exported
    )

    assert main(["--data-dir", str(tmp_path), "report", "show", "finding-1"]) == 0
    assert capsys.readouterr().out == "# Current report\n"

    assert (
        main(
            [
                "--data-dir",
                str(tmp_path),
                "report",
                "export",
                "finding-1",
                "--format",
                "markdown",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "finding_id": "finding-1",
        "path": str(exported),
    }
