"""The migration-settings replay is explicit and reaches the bound store path."""

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
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_django_migration_settings_replay import (
    _blocked_migration_candidate_attempt,
    _exhausted_migration_attempt,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication
from tests.unit.simple_runtime.test_recovery_composition import (
    _config as _composition_config,
)
from tests.unit.simple_runtime.test_recovery_composition import (
    _profile,
)


def test_cli_forwards_migration_replay_in_plain_and_progress_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_django_migration_settings_exhaustion_hypothesis: str
            | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("plain", repair_poc_django_migration_settings_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_django_migration_settings_exhaustion_hypothesis: str
            | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_django_migration_settings_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, route in ((["--format", "json"], "plain"), ([], "progress")):
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-django-migration-settings-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (route, "hypothesis-1")
        capsys.readouterr()


@pytest.mark.parametrize("with_progress", [False, True])
def test_public_wrapper_forwards_migration_replay_scope(
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
        current_stage=SimpleStage.POC_EXECUTION_DONE,
    )

    class Application:
        async def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_django_migration_settings_exhaustion_hypothesis: str
            | None = None,
            **_kwargs: object,
        ) -> SimpleAnalysisOutcome:
            seen.append(
                (
                    analysis_id,
                    repair_poc_django_migration_settings_exhaustion_hypothesis,
                )
            )
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
            repair_poc_django_migration_settings_exhaustion_hypothesis="hypothesis-1",
        )
    else:
        public.resume(
            "A-001",
            repair_poc_django_migration_settings_exhaustion_hypothesis="hypothesis-1",
        )
    assert seen == [("analysis-1" if with_progress else "A-001", "hypothesis-1")]


def test_application_requires_explicit_migration_replay_and_excludes_other_repairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_migration_attempt(tmp_path)
    identity = exhausted.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    seen: list[tuple[str, str]] = []

    async def bound(_analysis_id: str, _hypothesis_id: str, *, mode: str) -> None:
        seen.append((_hypothesis_id, mode))

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_prepare_bound_fallback_stop_locked", bound)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    asyncio.run(application.resume(identity.analysis_id))
    assert seen == []
    asyncio.run(
        application.resume(
            identity.analysis_id,
            repair_poc_django_migration_settings_exhaustion_hypothesis=(
                identity.hypothesis_id
            ),
        )
    )
    assert seen == [(identity.hypothesis_id, "django_migration_settings")]
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_REPAIR_CONFLICT"):
        asyncio.run(
            application.resume(
                identity.analysis_id,
                repair_poc_django_migration_settings_exhaustion_hypothesis=(
                    identity.hypothesis_id
                ),
                repair_poc_django_relation_settings_exhaustion_hypothesis=(
                    identity.hypothesis_id
                ),
            )
        )


def test_application_migration_replay_checks_scope_and_dispatches_to_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_migration_attempt(tmp_path)
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

    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_HYPOTHESIS_INVALID"
    ):
        asyncio.run(
            application.resume(
                identity.analysis_id,
                repair_poc_django_migration_settings_exhaustion_hypothesis="missing",
            )
        )
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted

    asyncio.run(
        application.resume(
            identity.analysis_id,
            repair_poc_django_migration_settings_exhaustion_hypothesis=(
                identity.hypothesis_id
            ),
        )
    )
    pending = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    assert pending.status is StageStatus.PENDING
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


def test_application_routes_second_migration_replay_to_blocked_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    identity = stopped.identity
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
    asyncio.run(
        application.resume(
            identity.analysis_id,
            repair_poc_django_migration_settings_exhaustion_hypothesis=(
                identity.hypothesis_id
            ),
        )
    )
    pending = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == stopped.attempt_number
