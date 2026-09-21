from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from sastsimi.config.user_config import UserConfig, UserConfigStore
from sastsimi.interfaces.cli.main import main
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
        return {"analysis_id": analysis_id, "status": "BLOCKED", "percent": 40}

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
