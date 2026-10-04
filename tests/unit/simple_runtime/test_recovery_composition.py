from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import sastsimi.composition.simple_runtime_composition as composition
from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    SimpleToolBinding,
    UserConfig,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.progress.models import ProgressSnapshot
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisOutcome,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageFailure,
    StageStatus,
)
from sastsimi.simple_runtime.portable_docker import PortableDockerRuntime
from sastsimi.simple_runtime.run_lease import analysis_run_lease
from sastsimi.simple_runtime.stages import PoCCandidateStage, RuleScopeGateStage


def _config(tmp_path: Path) -> UserConfig:
    return UserConfig(
        data_dir=tmp_path / "data",
        profile_path=tmp_path / "profile.toml",
        auth_mode="API_KEY",
        provider="openai",
        model="configured-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        enabled_tools=("DOCKER",),
        detected_versions={"docker": "test"},
        setup_ready=True,
    )


def _profile(tmp_path: Path) -> SimpleExecutionProfile:
    executable = tmp_path / "docker.exe"
    executable.write_bytes(b"docker")
    return SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="configured-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=tmp_path / "data",
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        tools={
            "docker": SimpleToolBinding(
                executable_path=executable,
                version="test",
                executable_sha256=hashlib.sha256(b"docker").hexdigest(),
            )
        },
    )


def _ref(identity: CheckpointIdentity, name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{name}"),
        data_kind=name,
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId(identity.workspace_id),
        commit_id=CommitId(identity.commit_id),
        record_id=None,
    )


def test_composition_passes_llm_timeout_to_both_hypothesis_paths(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path).model_copy(update={"llm_timeout_seconds": 300})
    application = composition.build_analysis_application(_config(tmp_path), profile)

    assert isinstance(application._hypotheses, DirectHypothesisBootstrap)
    assert application._hypotheses._llm_timeout_ms == 300_000
    assert isinstance(application._candidate_hypotheses, DirectHypothesisBootstrap)
    assert application._candidate_hypotheses._llm_timeout_ms == 300_000


@pytest.mark.parametrize(
    "saved_repository",
    [None, "https://github.com/acme/app"],
)
def test_composition_injects_identity_scoped_recovery_into_app_and_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    saved_repository: str | None,
) -> None:
    created: list[CheckpointIdentity] = []

    class Coordinator:
        def __init__(
            self,
            *,
            client: object,
            artifacts: SimpleArtifactRepository,
        ) -> None:
            del client
            self.identity = artifacts.identity
            created.append(self.identity)

    monkeypatch.setattr(composition, "SimpleRecoveryCoordinator", Coordinator)
    application = composition.build_analysis_application(
        _config(tmp_path),
        _profile(tmp_path),
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref(identity, "profile"),
        static_bundle_ref=_ref(identity, "bundle"),
        workspace_path=tmp_path / "workspace",
    )
    if saved_repository is not None:
        application._store.save_analysis_run(
            SimpleAnalysisRun(
                analysis_id=identity.analysis_id,
                display_analysis_id="A-1",
                workspace_id=identity.workspace_id,
                commit_id=identity.commit_id,
                repository=saved_repository,
            )
        )

    assert application._candidate_pipeline_enabled is True
    assert application._candidate_client_factory is not None
    assert application._max_cost_minor_units == 10_000
    assert application._recovery_factory is not None
    app_recovery = cast(Coordinator, application._recovery_factory(identity))
    runner = application._runner_factory(application._store, identity, static)

    assert app_recovery.identity == identity
    assert runner.recovery is not None
    assert cast(Coordinator, runner.recovery).identity == identity
    assert runner.cleanup_artifacts is not None
    assert runner.cleanup_artifacts.identity == identity
    assert runner.cleanup_artifacts.data_dir == tmp_path / "data"
    candidate = runner.handlers[SimpleStage.POC_CANDIDATE_DONE]
    assert isinstance(candidate, PoCCandidateStage)
    assert candidate._workspace_path == static.workspace_path
    assert candidate._static_bundle_ref == static.static_bundle_ref
    scope_gate = runner.handlers[SimpleStage.SCOPE_GATE_DONE]
    assert isinstance(scope_gate, RuleScopeGateStage)
    assert scope_gate._repository_url == saved_repository
    assert created == [identity, identity]


@pytest.mark.parametrize("configured_digest", [None, "sha256:" + "b" * 64])
@pytest.mark.asyncio
async def test_composition_wires_local_only_offline_base_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configured_digest: str | None,
) -> None:
    wheel_path = tmp_path / "wheels.tar"
    wheel_path.write_bytes(b"fixture")
    profile = _profile(tmp_path).model_copy(
        update={
            "poc_wheel_archive_path": wheel_path,
            "poc_wheel_archive_sha256": "a" * 64,
            "poc_offline_base_image_digest": configured_digest,
        }
    )
    application = composition.build_analysis_application(_config(tmp_path), profile)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref(identity, "profile"),
        static_bundle_ref=_ref(identity, "bundle"),
        workspace_path=tmp_path / "workspace",
    )
    calls: list[tuple[str, str]] = []

    async def inspect(_docker: object, image: str) -> str:
        calls.append(("inspect", image))
        return "sha256:" + "b" * 64

    async def pin(_docker: object, digest: str) -> str:
        calls.append(("tag", digest))
        return "sastsimi-offline-base:" + "b" * 64

    monkeypatch.setattr(PortableDockerRuntime, "local_base_image_digest", inspect)
    monkeypatch.setattr(PortableDockerRuntime, "pin_local_base", pin)
    runner = application._runner_factory(application._store, identity, static)

    assert runner.offline_base_ready is not None
    assert await runner.offline_base_ready() is True
    assert calls == [
        ("inspect", configured_digest or "python:3.12-slim"),
        ("tag", "sha256:" + "b" * 64),
    ]
    assert (application._offline_repair_preflight is not None) is (
        configured_digest is not None
    )


@pytest.mark.parametrize("with_progress", [False, True])
def test_public_resume_forwards_explicit_offline_repair_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    with_progress: bool,
) -> None:
    public = composition.PublicSimpleRuntimeApplication(
        _config(tmp_path), _profile(tmp_path)
    )
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
    calls: list[tuple[str, str | None]] = []

    class _Application:
        async def resume(
            self,
            analysis_id: str,
            *,
            repair_exhausted_hypothesis: str | None = None,
        ) -> SimpleAnalysisOutcome:
            calls.append((analysis_id, repair_exhausted_hypothesis))
            return outcome

    async def track(
        task: asyncio.Task[SimpleAnalysisOutcome],
        _started: list[str],
        _callback: Callable[[ProgressSnapshot], None],
    ) -> SimpleAnalysisOutcome:
        return await task

    monkeypatch.setattr(
        composition, "build_analysis_application", lambda *_args: _Application()
    )
    monkeypatch.setattr(public._display, "resolve", lambda _id: "analysis-1")
    monkeypatch.setattr(
        public._store,
        "require_analysis_run",
        lambda _id: SimpleNamespace(
            repository="https://example.invalid/repo", commit_id="a" * 40
        ),
    )
    monkeypatch.setattr(
        public, "_outcome", lambda *_args: {"display_analysis_id": "A-001"}
    )
    monkeypatch.setattr(public, "_track", track)

    if with_progress:
        public.resume_with_progress(
            "A-001",
            lambda _snapshot: None,
            repair_exhausted_hypothesis="hypothesis-1",
        )
    else:
        public.resume("A-001", repair_exhausted_hypothesis="hypothesis-1")

    assert calls == [("analysis-1" if with_progress else "A-001", "hypothesis-1")]


def test_public_candidate_status_marks_unleased_running_stage_interrupted(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    app = composition.PublicSimpleRuntimeApplication(config, _profile(tmp_path))
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    AnalysisDisplayIdStore(app._store.database_path).get_or_allocate(
        identity.analysis_id
    )
    app._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://github.com/example/repo",
            candidate_pipeline_version=1,
        )
    )
    app._store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1"
    )
    lease_directory = config.data_dir / "db" / "analysis-leases"
    assert not lease_directory.exists()

    idle = app.status("A-001")
    assert idle["status"] == "PAUSED"
    assert idle["error_code"] == "INTERRUPTED_RESUME_REQUIRED"
    assert idle["resume_action"] == "RESUME_INTERRUPTED"
    assert not lease_directory.exists()
    assert app.result("A-001")["status"] == "PAUSED"

    with analysis_run_lease(config.data_dir, identity.analysis_id):
        live = app.status("A-001")
        assert live["status"] == "RUNNING"
        assert live["error_code"] is None

    assert app.status("A-001")["status"] == "PAUSED"
    checkpoint = app._store.get(identity, SimpleStage.STATIC_DONE)
    assert checkpoint is not None and checkpoint.status is StageStatus.RUNNING
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(composition, "analysis_run_lease_active", lambda *_: None)
        assert app.status("A-001")["status"] == "RUNNING"


def test_public_candidate_status_requires_cleanup_for_unresolved_codex_call(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    app = composition.PublicSimpleRuntimeApplication(config, _profile(tmp_path))
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    AnalysisDisplayIdStore(app._store.database_path).get_or_allocate(
        identity.analysis_id
    )
    app._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://github.com/example/repo",
            candidate_pipeline_version=1,
        )
    )
    app._store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1"
    )
    assert app._store.begin_codex_call("unresolved-call", identity.analysis_id)

    idle = app.status("A-001")
    assert idle["status"] == "BLOCKED"
    assert idle["error_code"] == "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
    assert idle["resume_action"] == "MANUAL_CODEX_CLEANUP_REVIEW"

    with analysis_run_lease(config.data_dir, identity.analysis_id):
        assert app.status("A-001")["status"] == "RUNNING"


def test_public_candidate_status_requires_review_for_unconfirmed_codex_cleanup(
    tmp_path: Path,
) -> None:
    app = composition.PublicSimpleRuntimeApplication(
        _config(tmp_path), _profile(tmp_path)
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    AnalysisDisplayIdStore(app._store.database_path).get_or_allocate(
        identity.analysis_id
    )
    app._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://github.com/example/repo",
            candidate_pipeline_version=1,
        )
    )
    running = app._store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1"
    )
    app._store.mark_failure(
        running,
        StageFailure(
            code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            retryable=False,
            safe_message="Codex process cleanup was not confirmed",
        ),
        StageStatus.BLOCKED,
    )

    idle = app.status("A-001")
    assert idle["status"] == "BLOCKED"
    assert idle["error_code"] == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert idle["resume_action"] == "MANUAL_CODEX_CLEANUP_REVIEW"


def test_public_candidate_status_shows_resume_after_exact_cleanup_confirmation(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    app = composition.PublicSimpleRuntimeApplication(config, _profile(tmp_path))
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    AnalysisDisplayIdStore(app._store.database_path).get_or_allocate(
        identity.analysis_id
    )
    app._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://github.com/example/repo",
            candidate_pipeline_version=1,
        )
    )
    running = app._store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1"
    )
    blocked = app._store.mark_failure(
        running,
        StageFailure(
            code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            retryable=False,
            safe_message="Codex process cleanup was not confirmed",
        ),
        StageStatus.BLOCKED,
    )
    call_id = "confirmed-call"
    assert app._store.begin_codex_call(call_id, identity.analysis_id)
    artifacts = SimpleArtifactRepository(config.data_dir, identity)
    confirmation = artifacts.put_json(
        {
            "kind": "simple_codex_cleanup_confirmation",
            "analysis_id": identity.analysis_id,
            "stage": blocked.stage.value,
            "attempt_id": blocked.attempt_id,
            "checkpoint_sha256": hashlib.sha256(canonical_bytes(blocked)).hexdigest(),
            "call_id": call_id,
            "process_tree_stopped": True,
            "verification_method": "windows_process_inventory",
            "former_parent_pid": 12345,
            "observed_matching_process_count": 0,
            "observed_at": (blocked.updated_at + timedelta(seconds=1)).isoformat(),
        }
    )
    assert app.status("A-001")["resume_action"] == "MANUAL_CODEX_CLEANUP_REVIEW"
    app._store.confirm_codex_cleanup(blocked, confirmation, artifacts)

    with analysis_run_lease(config.data_dir, identity.analysis_id):
        assert app.status("A-001")["resume_action"] != "RESUME_INTERRUPTED"
    resumed = app.status("A-001")
    assert resumed["status"] == "PAUSED"
    assert resumed["error_code"] == "INTERRUPTED_RESUME_REQUIRED"
    assert resumed["resume_action"] == "RESUME_INTERRUPTED"


def test_public_legacy_running_status_is_not_reclassified_without_lease(
    tmp_path: Path,
) -> None:
    app = composition.PublicSimpleRuntimeApplication(
        _config(tmp_path), _profile(tmp_path)
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    AnalysisDisplayIdStore(app._store.database_path).get_or_allocate(
        identity.analysis_id
    )
    app._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://github.com/example/repo",
        )
    )
    app._store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1"
    )

    assert app.status("A-001")["status"] == "RUNNING"
