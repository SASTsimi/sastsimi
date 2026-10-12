"""The explicit auth replay flag reaches exactly one candidate repair."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.config.user_config import UserConfig, UserConfigStore
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.ports.public_commands import PublicCommandApplication
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.models import SimpleStage, StageStatus
from tests.simple_runtime.test_a002_auth_required_replay import _failed_auth_candidate


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


class _AuthReplayPublicApplication:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    def resume(
        self,
        analysis_id: str,
        *,
        repair_auth_required_hypothesis: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(("json", analysis_id, repair_auth_required_hypothesis))
        if repair_auth_required_hypothesis == "wrong":
            raise ValueError("AUTH_REQUIRED_REPLAY_ROOT_BOUND_INVALID")
        return {"analysis_id": analysis_id, "status": "RUNNING"}

    def resume_with_progress(
        self,
        analysis_id: str,
        _callback: object,
        *,
        repair_auth_required_hypothesis: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(("progress", analysis_id, repair_auth_required_hypothesis))
        return {"analysis_id": analysis_id, "status": "RUNNING"}


def test_auth_replay_flag_routes_json_and_progress_and_reports_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    application = _AuthReplayPublicApplication()
    public_application = cast(PublicCommandApplication, application)
    arguments = ["resume", "A-002", "--repair-auth-required-hypothesis", "child-a002"]
    config = _config(tmp_path)

    assert main(
        [*arguments, "--format", "json"],
        public_application=public_application,
        user_config_store=config,
    ) == int(ExitCode.OK)
    assert json.loads(capsys.readouterr().out)["data"]["status"] == "RUNNING"
    assert main(
        arguments,
        public_application=public_application,
        user_config_store=config,
    ) == int(ExitCode.OK)
    capsys.readouterr()
    assert application.calls == [
        ("json", "A-002", "child-a002"),
        ("progress", "A-002", "child-a002"),
    ]

    assert main(
        [
            "resume",
            "A-002",
            "--repair-auth-required-hypothesis",
            "wrong",
            "--format",
            "json",
        ],
        public_application=public_application,
        user_config_store=config,
    ) == int(ExitCode.INTEGRITY_ERROR)
    assert "AUTH_REQUIRED_REPLAY_ROOT_BOUND_INVALID" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_auth_replay_application_requires_explicit_child_and_reopens_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped = _failed_auth_candidate(tmp_path)
    child = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(child.analysis_id)

    class _PinnedStatic:
        def __init__(self) -> None:
            self._profile = SimpleNamespace(
                workspace_root=tmp_path / "data" / "workspaces"
            )

        async def _verify_opengrep_workspace(self, *_args: object) -> None:
            return None

        def coverage_fingerprint(self) -> None:
            return None

    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStatic(),  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=child.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-002",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_validate_static_evidence", lambda *_args: None)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda *_args: None
    )
    monkeypatch.setattr(application, "_resume_locked", resume_locked)

    await application.resume(child.analysis_id)
    assert store.require(child, SimpleStage.POC_CANDIDATE_DONE) == stopped

    await application.resume(
        child.analysis_id,
        repair_auth_required_hypothesis=child.hypothesis_id,
    )
    pending = store.require(child, SimpleStage.POC_CANDIDATE_DONE)
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == stopped.attempt_number
    assert store.get(child, SimpleStage.POC_EXECUTION_DONE) is None


@pytest.mark.asyncio
async def test_auth_replay_application_rejects_other_child_before_mutation(
    tmp_path: Path,
) -> None:
    store, _artifacts, stopped = _failed_auth_candidate(tmp_path)
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        stopped.identity.analysis_id
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="AUTH_REQUIRED_REPLAY_HYPOTHESIS_INVALID"):
        await application.resume(
            stopped.identity.analysis_id,
            repair_auth_required_hypothesis="another-child",
        )
    assert store.require(stopped.identity, stopped.stage) == stopped
