"""A stopped Docker API may reopen only its exact saved initial child."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome, DockerOperationError
from sastsimi.simple_runtime.application import (
    HypothesisBootstrap,
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
)
from sastsimi.simple_runtime.portable_docker import DockerBuildAttemptsError
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner, StageBlocked
from sastsimi.simple_runtime.stages import (
    InitialVerificationStage,
    ReproductionEnvironment,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import (
    _PinnedStaticStub,
    _seed,
)
from tests.unit.simple_runtime.test_initial_environment_terminal import (
    _checkpoint_with_environment_block,
)

_API_DIAGNOSTIC = (
    b"open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified"
)


def _failed_docker_initial(
    tmp_path: Path,
    *,
    legacy: bool = True,
    diagnostic: bytes = _API_DIAGNOSTIC,
    successful_root: bool = True,
    timed_out: bool = False,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, old_stop, _ = _seed(tmp_path)
    identity = old_stop.identity
    initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    attempt_number = 3 if legacy else 1
    pending = initial.model_copy(
        update={
            "status": StageStatus.PENDING,
            "output_refs": (),
            "attempt_id": None,
            "attempt_number": attempt_number - 1,
            "error_code": None,
            "retryable": False,
            "recipe_ref": None,
            "image_digest": None,
        }
    )
    store.replace_from(pending)
    running = store.mark_running(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        pending.input_refs,
        attempt_id=f"docker-attempt-{attempt_number}",
    )
    initial_ref = artifacts.put_json(
        {"kind": "simple_initial_verification", "attempt_id": running.attempt_id}
    )
    dockerfile_ref = artifacts.put_bytes(
        b"FROM python:3.12-slim\n", "text/x-dockerfile"
    )
    stderr_ref = artifacts.put_bytes(diagnostic, "text/plain")
    failure_code = "DOCKER_BUILD_FAILED" if legacy else "DOCKER_API_UNAVAILABLE"
    attempt_ref = artifacts.put_json(
        {
            "kind": "simple_docker_build_attempt",
            "identity": identity.model_dump(mode="json"),
            "attempt_id": running.attempt_id,
            "dockerfile_source": "GENERATED",
            "dockerfile_ref": dockerfile_ref.model_dump(mode="json"),
            "status": "FAILED",
            "error_code": failure_code,
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "stdout_ref": None,
            "timed_out": timed_out,
        }
    )
    recipe_ref = artifacts.put_json(
        {
            "kind": "simple_environment_recipe",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "attempt_id": running.attempt_id,
            "dockerfile_source": "GENERATED",
            "dockerfile_ref": dockerfile_ref.model_dump(mode="json"),
            "build_attempt_refs": [attempt_ref.model_dump(mode="json")],
            "status": "BLOCKED",
        }
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code=failure_code,
            retryable=legacy,
            safe_message="Docker API unavailable",
            evidence_refs=(initial_ref, attempt_ref, recipe_ref),
        ),
        StageStatus.BLOCKED,
    )
    stopped = store.mark_recovery_exhausted(failed) if legacy else failed
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    if successful_root:
        bundle_ref = store.require_analysis_run(identity.analysis_id).static_bundle_ref
        assert bundle_ref is not None
        root_running = store.mark_running(
            root_identity,
            SimpleStage.HYPOTHESIS_DONE,
            (bundle_ref,),
            attempt_id="root-complete-after-child-failure",
        )
        root_ref = artifacts.put_json({"kind": "candidate-partial"})
        store.complete(root_running, StageResult(output_refs=(root_ref,)))
        run = store.require_analysis_run(identity.analysis_id)
        store.save_analysis_run(
            run.model_copy(
                update={
                    "candidate_terminal": CandidateTerminal(
                        status="PARTIAL",
                        bundle_hash=bundle_ref.content_hash,
                        scope_fingerprint=run.candidate_scope_fingerprint or "",
                        decision_counts={},
                        deep_counts={},
                        hypothesis_count=1,
                        surface_proof_version=3,
                    ),
                    "surface_enrichment_plan_ref": root_ref,
                    "surface_enrichment_v5_plan_ref": root_ref,
                    "surface_enrichment_v6_plan_ref": root_ref,
                    "python_scope_certificate_ref": root_ref,
                }
            )
        )
    else:
        root_running = store.mark_running(
            root_identity,
            SimpleStage.HYPOTHESIS_DONE,
            root.input_refs,
            attempt_id="root-bound-to-docker-child",
        )
        store.mark_failure(
            root_running,
            StageFailure(
                code=(
                    f"CANDIDATE_CHILD_ERROR_BOUND:{stopped.error_code}:"
                    f"{identity.hypothesis_id}:{stopped.attempt_id}"
                ),
                retryable=False,
                safe_message="Child blocked on Docker",
            ),
            StageStatus.BLOCKED,
        )
    return store, artifacts, stopped


@pytest.mark.parametrize("legacy", [True, False])
def test_docker_daemon_resume_reopens_exact_child_once_and_preserves_root(
    tmp_path: Path, legacy: bool
) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path, legacy=legacy)
    identity = stopped.identity
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    run_before = store.require_analysis_run(identity.analysis_id)
    pro_con_before = store.require(identity, SimpleStage.PRO_CON_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_id is None
    assert pending.attempt_number == (3 if legacy else 0)
    assert pending.input_refs == stopped.input_refs
    assert pending.output_refs == ()
    assert store.require(identity, SimpleStage.PRO_CON_DONE) == pro_con_before
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root_before
    assert store.require_analysis_run(identity.analysis_id) == run_before
    events_after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert events_after[:-1] == events_before
    assert events_after[-1].kind is ActivityKind.DECISION_RECORDED
    assert events_after[-1].error_code == "DOCKER_DAEMON_REPLAYED"
    with pytest.raises(ValueError, match="DOCKER_DAEMON_REPLAY_"):
        store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)


def test_docker_daemon_resume_rejects_unhealthy_probe(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path)
    before = store.require(stopped.identity, stopped.stage)

    with pytest.raises(ValueError, match="DOCKER_DAEMON_REPLAY_UNAVAILABLE"):
        store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=False)

    assert store.require(stopped.identity, stopped.stage) == before


def test_docker_daemon_resume_accepts_new_builder_timeout_after_recovery(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _failed_docker_initial(
        tmp_path,
        legacy=False,
        diagnostic=b"buildx inspect timed out",
        timed_out=True,
    )

    pending = store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 0


def test_docker_daemon_resume_rejects_legacy_timeout_without_exact_failure(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path, timed_out=True)

    with pytest.raises(ValueError, match="DOCKER_DAEMON_REPLAY_EVIDENCE_INVALID"):
        store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)


def test_docker_daemon_resume_rejects_unrelated_build_error(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_docker_initial(
        tmp_path, diagnostic=b"Dockerfile parse error: unknown instruction"
    )
    before = store.require(stopped.identity, stopped.stage)

    with pytest.raises(ValueError, match="DOCKER_DAEMON_REPLAY_EVIDENCE_INVALID"):
        store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)

    assert store.require(stopped.identity, stopped.stage) == before


def test_docker_daemon_resume_rejects_forged_saved_stage_event(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path)
    activity = AgentActivityStore(store.database_path)
    original = next(
        event
        for event in activity.list_analysis(
            stopped.identity.analysis_id,
            hypothesis_id=stopped.identity.hypothesis_id,
        )
        if event.attempt_id == stopped.attempt_id
        and event.error_code == "DOCKER_BUILD_FAILED"
    )
    activity.append(
        original.model_copy(
            update={
                "event_id": f"{original.event_id}-forged",
                "sequence": 999,
                "output_refs": (),
            }
        )
    )

    with pytest.raises(ValueError, match="DOCKER_DAEMON_REPLAY_EVENT_INVALID"):
        store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)

    assert store.require(stopped.identity, stopped.stage) == stopped
    assert not any(
        event.error_code == "DOCKER_DAEMON_REPLAYED"
        for event in activity.list_analysis(stopped.identity.analysis_id)
    )


def test_docker_daemon_resume_rejects_stale_success_metadata(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path)
    contaminated = stopped.model_copy(
        update={
            "verdict": "TRUE",
            "recovery_decision_refs": (stopped.output_refs[0],),
        }
    )
    store.save_checkpoint(contaminated)

    with pytest.raises(ValueError, match="DOCKER_DAEMON_REPLAY_CHECKPOINT_INVALID"):
        store.prepare_docker_daemon_replay(contaminated, artifacts, daemon_ready=True)

    assert store.require(stopped.identity, stopped.stage) == contaminated


def test_docker_daemon_resume_rejects_unresolved_codex_call(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path)
    assert store.begin_codex_call(
        "unresolved-docker-replay", stopped.identity.analysis_id
    )
    before = store.require(stopped.identity, stopped.stage)

    with pytest.raises(ValueError, match="DOCKER_DAEMON_REPLAY_CODEX_UNRESOLVED"):
        store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)

    assert store.require(stopped.identity, stopped.stage) == before


def test_docker_daemon_resume_rolls_back_marker_and_checkpoint(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path)
    identity = stopped.identity
    before_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_docker_daemon_replay(
            stopped, artifacts, daemon_ready=True, fail_before_commit=True
        )

    assert store.require(identity, stopped.stage) == stopped
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == before_events
    )


def test_docker_daemon_resume_preserves_unrelated_sibling_checkpoint(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path)
    sibling = stopped.identity.model_copy(update={"hypothesis_id": "hypothesis-other"})
    sibling_ref = SimpleArtifactRepository(tmp_path / "data", sibling).put_json(
        {"kind": "sibling-evidence"}
    )
    sibling_checkpoint = stopped.model_copy(
        update={
            "identity": sibling,
            "status": StageStatus.SUCCEEDED,
            "output_refs": (sibling_ref,),
            "attempt_id": "sibling-complete",
            "error_code": None,
        }
    )
    store.save_checkpoint(sibling_checkpoint)

    store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)

    assert (
        store.require(sibling, SimpleStage.VERIFICATION_INITIAL_DONE)
        == sibling_checkpoint
    )


def test_docker_daemon_resume_accepts_exact_bound_blocked_root(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path, successful_root=False)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)

    pending = store.prepare_docker_daemon_replay(stopped, artifacts, daemon_ready=True)

    assert pending.status is StageStatus.PENDING
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root_before


@pytest.mark.asyncio
async def test_initial_docker_api_outage_blocks_without_recovery_retry(
    tmp_path: Path,
) -> None:
    artifacts, template = _checkpoint_with_environment_block(tmp_path)
    checkpoint = template.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "output_refs": (),
            "environment_block_ref": None,
        }
    )
    attempt_ref = artifacts.put_json({"kind": "build-attempt"})
    recipe_ref = artifacts.put_json({"kind": "recipe"})

    class _Client:
        async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "TRUE",
                    "rationale": "Run the reproduction.",
                    "reproduction_goal": "Exercise the pinned route.",
                    "environment_requirements": [],
                    "unmet_external_prerequisites": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _Environment:
        async def prepare(
            self,
            checkpoint: StageCheckpoint,
            prior: Mapping[SimpleStage, StageCheckpoint],
            requirements: tuple[str, ...],
        ) -> ReproductionEnvironment:
            error = DockerOperationError(
                "DOCKER_API_UNAVAILABLE",
                DockerCommandOutcome(1, b"", _API_DIAGNOSTIC, False),
            )
            raise DockerBuildAttemptsError(error, (attempt_ref,), recipe_ref)

    with pytest.raises(StageBlocked) as caught:
        await InitialVerificationStage(_Client(), artifacts, _Environment())(
            checkpoint, {}
        )

    assert caught.value.failure.code == "DOCKER_API_UNAVAILABLE"
    assert caught.value.failure.retryable is False
    assert caught.value.failure.evidence_refs[-2:] == (attempt_ref, recipe_ref)


@pytest.mark.asyncio
@pytest.mark.parametrize("enrich_saved_surface_evidence", [False, True])
async def test_ordinary_same_id_resume_runs_reopened_docker_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    enrich_saved_surface_evidence: bool,
) -> None:
    store, artifacts, stopped = _failed_docker_initial(tmp_path)
    identity = stopped.identity
    data_dir = tmp_path / "data"
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    health_checks = 0
    attempts: list[int] = []

    async def api_available() -> bool:
        nonlocal health_checks
        health_checks += 1
        return True

    async def initial(
        checkpoint: StageCheckpoint, prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        attempts.append(checkpoint.attempt_number)
        result_ref = artifacts.put_json(
            {
                "kind": "simple_initial_verification",
                "attempt_id": checkpoint.attempt_id,
                "result": {"unmet_external_prerequisites": ["external service absent"]},
            }
        )
        return StageResult(
            output_refs=(result_ref,),
            verdict="HOLD",
            external_prerequisites_ref=result_ref,
        )

    def runner_factory(
        current_store: SimpleCheckpointStore,
        _identity: CheckpointIdentity,
        _static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        return SimpleRuntimeRunner(
            current_store,
            {SimpleStage.VERIFICATION_INITIAL_DONE: initial},
        )

    app = SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=_PinnedStaticStub(data_dir / "workspaces"),
        hypothesis_bootstrap=cast(HypothesisBootstrap, object()),
        runner_factory=runner_factory,
        docker_api_available=api_available,
    )

    async def already_pinned_enrichment(_analysis_id: str) -> None:
        return None

    monkeypatch.setattr(
        app, "_prepare_surface_enrichment_locked", already_pinned_enrichment
    )

    async def continue_saved_run(exact: str) -> SimpleAnalysisOutcome:
        assert exact == identity.analysis_id
        assert (
            store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE).status
            is StageStatus.PENDING
        )
        run = store.require_analysis_run(exact)
        assert run.repository_profile_ref is not None
        assert run.static_bundle_ref is not None
        assert run.workspace_path is not None
        static = StaticBootstrapResult(
            repository_profile_ref=run.repository_profile_ref,
            static_bundle_ref=run.static_bundle_ref,
            static_coverage_ref=run.static_coverage_ref,
            workspace_path=run.workspace_path,
        )
        child_outcome = await runner_factory(store, identity, static).resume_hypothesis(
            identity
        )
        assert child_outcome.status is StageStatus.SUCCEEDED
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id=run.display_analysis_id,
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    monkeypatch.setattr(app, "_resume_locked", continue_saved_run)
    outcome = await app.resume(
        identity.analysis_id,
        enrich_saved_surface_evidence=enrich_saved_surface_evidence,
    )

    assert outcome.status == "PARTIAL"
    assert health_checks == 1
    assert attempts == [4]
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE).status
        is StageStatus.SUCCEEDED
    )
