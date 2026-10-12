"""Attempt-nine recovery requires an explicit, one-shot public flag."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

import sastsimi.composition.simple_runtime_composition as composition
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.progress.models import ProgressSnapshot
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageStatus,
)
from tests.simple_runtime.test_poc_sensitive_auth_recap_replay import _attempt_eight
from tests.simple_runtime.test_poc_sensitive_replay import (  # type: ignore[attr-defined]
    _PinnedStaticStub,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication
from tests.unit.simple_runtime.test_recovery_composition import (
    _config as _composition_config,
)
from tests.unit.simple_runtime.test_recovery_composition import _profile


@pytest.mark.asyncio
async def test_application_reopens_attempt_eight_only_with_auth_recap_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _attempt_eight(tmp_path)
    identity = exhausted.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )

    await application.resume(identity.analysis_id)
    assert store.require(identity, exhausted.stage) == exhausted

    await application.resume(
        identity.analysis_id,
        repair_poc_sensitive_auth_recap_hypothesis=identity.hypothesis_id,
    )
    assert store.require(identity, exhausted.stage).status is StageStatus.PENDING


def test_cli_forwards_auth_recap_flag_in_plain_and_progress_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_sensitive_auth_recap_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_sensitive_auth_recap_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_sensitive_auth_recap_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_sensitive_auth_recap_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    for extra, mode in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-002",
                "--repair-poc-sensitive-auth-recap",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (mode, "hypothesis-1")
        capsys.readouterr()


@pytest.mark.parametrize("with_progress", [False, True])
def test_public_adapter_forwards_auth_recap_flag_to_application(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_progress: bool
) -> None:
    public = composition.PublicSimpleRuntimeApplication(
        _composition_config(tmp_path), _profile(tmp_path)
    )
    seen: list[tuple[str, str | None]] = []
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    outcome = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id="A-001",
        status="BLOCKED",
        current_stage=SimpleStage.POC_CANDIDATE_DONE,
    )

    class Application:
        async def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_sensitive_auth_recap_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> SimpleAnalysisOutcome:
            seen.append((analysis_id, repair_poc_sensitive_auth_recap_hypothesis))
            return outcome

    async def track(
        task: asyncio.Task[SimpleAnalysisOutcome],
        _started: list[str],
        _callback: Callable[[ProgressSnapshot], None],
    ) -> SimpleAnalysisOutcome:
        return await task

    monkeypatch.setattr(
        composition, "build_analysis_application", lambda *_args: Application()
    )
    monkeypatch.setattr(public._display, "resolve", lambda _id: "analysis-1")
    monkeypatch.setattr(
        public._store,
        "require_analysis_run",
        lambda _id: SimpleNamespace(
            repository="https://example.invalid/repo", commit_id="a" * 40
        ),
    )
    monkeypatch.setattr(public, "_resume_outcome", lambda *_args: {"status": "BLOCKED"})
    monkeypatch.setattr(public, "_track", track)

    if with_progress:
        public.resume_with_progress(
            "A-001",
            lambda _snapshot: None,
            repair_poc_sensitive_auth_recap_hypothesis="hypothesis-1",
        )
    else:
        public.resume(
            "A-001", repair_poc_sensitive_auth_recap_hypothesis="hypothesis-1"
        )
    assert seen == [("analysis-1" if with_progress else "A-001", "hypothesis-1")]
