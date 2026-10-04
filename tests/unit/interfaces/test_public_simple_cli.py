from __future__ import annotations

import json
from collections.abc import Callable
from io import StringIO
from pathlib import Path

import pytest

from sastsimi.config.user_config import UserConfig, UserConfigStore
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.interfaces.cli.public import emit_public
from sastsimi.progress.models import ProgressSnapshot


class _PublicApplication:
    def analyze(self, repository: str, commit: str) -> dict[str, object]:
        return {
            "analysis_id": "A-001",
            "exact_analysis_id": "analysis-exact",
            "repository": repository,
            "commit": commit,
            "status": "RUNNING",
            "current_stage": "STATIC_DONE",
            "dashboard_url": "http://127.0.0.1:8765/analyses/A-001",
        }

    def status(self, analysis_id: str) -> dict[str, object]:
        return {
            "analysis_id": analysis_id,
            "status": "BLOCKED",
            "percent": 40,
            "attempt_number": 3,
            "attempt_limit": 3,
            "error_code": "RECOVERY_EXHAUSTED",
        }

    def resume(self, analysis_id: str) -> dict[str, object]:
        return {"analysis_id": analysis_id, "status": "COMPLETE", "percent": 100}

    def result(self, analysis_id: str) -> dict[str, object]:
        return {"analysis_id": analysis_id, "finding_count": 1}

    def poc(self, finding_id: str) -> str:
        return f"PoC {finding_id}\n"

    def report(self, finding_id: str) -> str:
        return f"Report {finding_id}\n"

    def export_report(self, finding_id: str) -> str:
        return f"reports/analysis/{finding_id}.md"

    def export_report_bundle(self, finding_id: str) -> str:
        return f"reports/analysis/{finding_id}/bundle.zip"

    def export_report_group(self, analysis_id: str, group_id: str) -> str:
        return f"reports/{analysis_id}/groups/{group_id}/digest/bundle.zip"


def test_result_text_distinguishes_raw_findings_from_verified_groups() -> None:
    stream = StringIO()
    emit_public(
        "text",
        stream,
        command="result",
        data={
            "analysis_id": "A-001",
            "finding_count": 3,
            "finding_group_count": 1,
            "finding_group_undetermined_count": 0,
        },
    )
    output = stream.getvalue()
    assert "Finding: 3개" in output
    assert "표시 묶음: 1개" in output
    assert "묶음 미확정: 0개" in output


class _ProgressApplication(_PublicApplication):
    def analyze_with_progress(
        self,
        repository: str,
        commit: str,
        callback: Callable[[ProgressSnapshot], None],
    ) -> dict[str, object]:
        callback(
            ProgressSnapshot(
                analysis_id="analysis-exact",
                status="RUNNING",
                completed_units=1,
                known_units=4,
                percent=25,
                current_stage="STATIC_DONE",
            )
        )
        callback(
            ProgressSnapshot(
                analysis_id="analysis-exact",
                status="COMPLETE",
                completed_units=4,
                known_units=4,
                percent=100,
                current_stage="REPORT_DONE",
            )
        )
        return self.analyze(repository, commit)


class _BusyPublicApplication(_PublicApplication):
    def resume(self, analysis_id: str) -> dict[str, object]:
        return {
            "analysis_id": analysis_id,
            "status": "RUNNING",
            "percent": 60,
            "resume_skipped_reason": "ANALYSIS_ALREADY_RUNNING",
        }


class _RepairPublicApplication(_PublicApplication):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    def resume(
        self, analysis_id: str, *, repair_exhausted_hypothesis: str | None = None
    ) -> dict[str, object]:
        self.calls.append(("plain", analysis_id, repair_exhausted_hypothesis))
        return super().resume(analysis_id)

    def resume_with_progress(
        self,
        analysis_id: str,
        _callback: Callable[[ProgressSnapshot], None],
        *,
        repair_exhausted_hypothesis: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(("progress", analysis_id, repair_exhausted_hypothesis))
        return super().resume(analysis_id)


def test_repair_flag_reaches_json_and_progress_resume(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    application = _RepairPublicApplication()
    store = _config(tmp_path)
    arguments = [
        "resume",
        "A-001",
        "--repair-exhausted-hypothesis",
        "hypothesis-1",
    ]

    assert (
        main(
            [*arguments, "--format", "json"],
            public_application=application,
            user_config_store=store,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["data"]["status"] == "COMPLETE"
    assert (
        main(
            arguments,
            public_application=application,
            user_config_store=store,
        )
        == 0
    )
    capsys.readouterr()
    assert application.calls == [
        ("plain", "A-001", "hypothesis-1"),
        ("progress", "A-001", "hypothesis-1"),
    ]


class _StaleReportApplication(_PublicApplication):
    def report(self, finding_id: str) -> str:
        raise LookupError("CURRENT_REPORT_STALE")


def test_public_stale_report_is_unavailable_not_internal_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        ["report", "show", "F-001"],
        public_application=_StaleReportApplication(),
        user_config_store=_config(tmp_path),
    )

    assert code == int(ExitCode.REPORT_UNAVAILABLE)
    error = capsys.readouterr().err
    assert "stale" in error
    assert "internal error" not in error


def test_public_report_export_includes_additive_bundle_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            ["report", "export", "F-001", "--format", "markdown"],
            public_application=_PublicApplication(),
            user_config_store=_config(tmp_path),
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "finding_id": "F-001",
        "path": "reports/analysis/F-001.md",
        "bundle_path": "reports/analysis/F-001/bundle.zip",
    }


def test_public_group_export_has_explicit_analysis_and_group_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    group_id = "a" * 64
    assert main(
        ["report", "export-group", "A-001", group_id, "--format", "json"],
        public_application=_PublicApplication(),
        user_config_store=_config(tmp_path),
    ) == int(ExitCode.OK)
    assert json.loads(capsys.readouterr().out)["data"] == {
        "analysis_id": "A-001",
        "group_id": group_id,
        "bundle_path": f"reports/A-001/groups/{group_id}/digest/bundle.zip",
    }


def _config(tmp_path: Path) -> UserConfigStore:
    store = UserConfigStore(tmp_path / "config.toml")
    store.save(
        UserConfig(
            data_dir=tmp_path / "data",
            profile_path=tmp_path / "profile.toml",
            auth_mode="SUBSCRIPTION_LOGIN",
            provider="codex",
            model="configured-model",
            credential_ref="OFFICIAL_CLIENT_SESSION",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=100_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
            enabled_tools=("AST", "OPENGREP", "DOCKER"),
            detected_versions={},
            setup_ready=True,
        )
    )
    return store


def test_public_resume_explains_concurrent_run_without_internal_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(
        ["resume", "A-001", "--no-progress"],
        public_application=_BusyPublicApplication(),
        user_config_store=_config(tmp_path),
    )

    assert code == 0
    output = capsys.readouterr()
    assert "이미 다른 프로세스" in output.out
    assert "INTERNAL_ERROR" not in output.err


def test_public_analyze_uses_positional_repo_and_human_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(
        [
            "analyze",
            "https://example.invalid/repository.git",
            "--commit",
            "a" * 40,
            "--no-progress",
        ],
        public_application=_PublicApplication(),
        user_config_store=_config(tmp_path),
    )

    assert code == 0
    output = capsys.readouterr().out
    assert "분석이 시작되었습니다" in output
    assert "분석 ID: A-001" in output
    assert "STATIC_DONE" in output
    assert not output.startswith("{")


def test_public_commands_emit_json_only_when_requested(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    application = _PublicApplication()
    store = _config(tmp_path)

    assert (
        main(
            ["status", "A-001", "--format", "json"],
            public_application=application,
            user_config_store=store,
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["percent"] == 40
    status = payload["data"]
    assert status["attempt_number"] == 3
    assert status["attempt_limit"] == 3

    assert (
        main(
            ["resume", "A-001", "--format", "json"],
            public_application=application,
            user_config_store=store,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["data"]["status"] == "COMPLETE"

    assert (
        main(
            ["result", "A-001", "--format", "json"],
            public_application=application,
            user_config_store=store,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["data"]["finding_count"] == 1


def test_public_analyze_renders_checkpoint_progress_when_enabled(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "analyze",
                "https://example.invalid/repository.git",
                "--commit",
                "a" * 40,
            ],
            public_application=_ProgressApplication(),
            user_config_store=_config(tmp_path),
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "현재 단계: STATIC_DONE (1/4)" in output
    assert "현재 단계: REPORT_DONE (4/4)" in output
    assert "분석 ID: A-001" in output


def test_public_status_shows_recovery_attempt_and_terminal_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            ["status", "A-001"],
            public_application=_PublicApplication(),
            user_config_store=_config(tmp_path),
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "복구 시도: 3/3" in output
    assert "오류: RECOVERY_EXHAUSTED" in output
    assert "수동 검토가 필요합니다" in output
    assert "sastsimi resume" not in output


def test_public_poc_and_report_aliases_keep_legacy_report_commands(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sastsimi.interfaces.cli import report as report_command

    monkeypatch.setattr(
        report_command,
        "show",
        lambda _data_dir, finding_id: f"Report {finding_id}\n",
    )
    exported = tmp_path / "data" / "reports" / "analysis" / "F-001.md"
    exported.parent.mkdir(parents=True)
    exported.write_text("# report", encoding="utf-8")
    monkeypatch.setattr(report_command, "export", lambda *_args: exported)
    application = _PublicApplication()
    store = _config(tmp_path)

    assert (
        main(
            ["poc", "F-001"],
            public_application=application,
            user_config_store=store,
        )
        == 0
    )
    assert capsys.readouterr().out == "PoC F-001\n"

    assert (
        main(
            ["report", "F-001"],
            public_application=application,
            user_config_store=store,
        )
        == 0
    )
    assert capsys.readouterr().out == "Report F-001\n"

    assert (
        main(
            ["report", "F-001", "--export", "markdown"],
            public_application=application,
            user_config_store=store,
        )
        == 0
    )
    assert "reports/analysis/F-001.md" in capsys.readouterr().out


def test_installed_entrypoint_normalizes_compact_report_syntax(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sastsimi.interfaces.cli import report as report_command

    monkeypatch.setattr(
        report_command,
        "show",
        lambda _data_dir, finding_id: f"Report {finding_id}\n",
    )
    monkeypatch.setattr("sys.argv", ["sastsimi", "report", "F-001"])

    assert main(user_config_store=_config(tmp_path)) == 0
    assert capsys.readouterr().out == "Report F-001\n"


def test_demo_is_not_a_public_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["demo", "analyze", "--scenario", "TRUE"]) == 2
    assert "Invalid command or option; use --help." in capsys.readouterr().err
