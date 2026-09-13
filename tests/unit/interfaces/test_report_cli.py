"""The public CLI exposes report list, show, and Markdown export commands."""

import io
import json
import sys
from pathlib import Path

import pytest

from sastsimi.interfaces.cli import report as report_command
from sastsimi.interfaces.cli import reports as reports_command
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import _configure_standard_streams, main


def test_cli_configures_real_standard_streams_for_utf8_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_bytes = io.BytesIO()
    stderr_bytes = io.BytesIO()
    stdout = io.TextIOWrapper(stdout_bytes, encoding="cp1252", errors="strict")
    stderr = io.TextIOWrapper(stderr_bytes, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    _configure_standard_streams()
    sys.stdout.write("취약점 보고서")
    sys.stderr.write("실행 오류")
    sys.stdout.flush()
    sys.stderr.flush()

    assert stdout.encoding == "utf-8"
    assert stderr.encoding == "utf-8"
    assert stdout_bytes.getvalue() == "취약점 보고서".encode()
    assert stderr_bytes.getvalue() == "실행 오류".encode()


def test_report_show_and_export_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exported = tmp_path / "reports" / "analysis-1" / "finding-1.md"
    exported.parent.mkdir(parents=True)
    exported.write_text("# Current report\n", encoding="utf-8")
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
        "path": "reports/analysis-1/finding-1.md",
    }


def test_report_export_rejects_a_path_outside_the_data_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path.parent / "outside-report.md"
    outside.write_text("# Must not be disclosed\n", encoding="utf-8")
    monkeypatch.setattr(
        report_command, "export", lambda _data_dir, _finding_id: outside
    )

    assert main(
        [
            "--data-dir",
            str(tmp_path),
            "report",
            "export",
            "finding-1",
            "--format",
            "markdown",
        ]
    ) == int(ExitCode.REPORT_UNAVAILABLE)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(outside) not in captured.err
