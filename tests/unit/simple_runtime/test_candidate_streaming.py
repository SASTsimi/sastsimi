"""Candidate batches must release runnable children before the producer ends."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest

from sastsimi.progress.projector import ProgressProjector
from sastsimi.simple_runtime.application import (
    BatchProposalResult,
    CandidateProposalOutcome,
    ChainingEvidenceInvalid,
    HypothesisBootstrap,
    HypothesisSeed,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.candidate_batches import CandidateBatch
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import RunOutcome, SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from tests.unit.simple_runtime.test_candidate_batches import _fixture
from tests.unit.simple_runtime.test_candidate_pipeline import _setup


class _SeedBatches:
    def __init__(self, data_dir: Path, events: list[str]) -> None:
        self.data_dir = data_dir
        self.events = events
        self.calls = 0

    async def propose_batch(
        self,
        identity: CheckpointIdentity,
        _static: StaticBootstrapResult,
        batch: CandidateBatch,
        *,
        requested_ids: tuple[str, ...] | None = None,
    ) -> BatchProposalResult:
        self.calls += 1
        self.events.append(f"batch-{self.calls}")
        ids = requested_ids or batch.candidate_ids
        artifacts = SimpleArtifactRepository(self.data_dir, identity)
        response_ref = artifacts.put_json(
            {
                "kind": "simple_candidate_batch_response_v1",
                "batch_id": batch.batch_id,
                "requested_ids": ids,
                "candidate_results": [
                    {"candidate_id": item, "status": "HYPOTHESES"} for item in ids
                ],
            }
        )
        outcomes = {}
        for candidate_id in ids:
            hypothesis_id = f"hypothesis-{candidate_id}"
            proposal_ref = artifacts.put_prompt_proposal(
                {
                    "kind": "simple_hypothesis_proposal",
                    "analysis_id": identity.analysis_id,
                    "hypothesis_id": hypothesis_id,
                    "candidate_id": candidate_id,
                    "proposal": {"summary": "Qualified input to eval"},
                }
            )
            outcomes[candidate_id] = CandidateProposalOutcome(
                status="HYPOTHESES",
                reason="Visible source and operation",
                seeds=(
                    HypothesisSeed(
                        hypothesis_id=hypothesis_id,
                        proposal_ref=proposal_ref,
                    ),
                ),
                result_ref=response_ref,
            )
        return BatchProposalResult(
            results=outcomes,
            missing_ids=(),
            attempt_refs=(response_ref,),
        )


class _RecordingRunner:
    def __init__(
        self, store: SimpleCheckpointStore, events: list[str], *, blocked: bool = False
    ) -> None:
        self.store = store
        self.events = events
        self.blocked = blocked

    async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
        self.events.append(f"child-{identity.hypothesis_id}")
        if self.blocked:
            return RunOutcome(
                current_stage=SimpleStage.PRO_CON_DONE,
                status=StageStatus.BLOCKED,
                error_code="TEST_CHILD_BLOCKED",
            )
        self.store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=SimpleStage.VERIFICATION_FINAL_DONE,
                stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                verdict="FALSE",
            )
        )
        return RunOutcome(
            current_stage=SimpleStage.VERIFICATION_FINAL_DONE,
            status=StageStatus.SUCCEEDED,
        )


@pytest.mark.asyncio
async def test_surface_provider_failure_stays_blocked_with_scoped_error_and_evidence(
    tmp_path: Path,
) -> None:
    app, store, _client, _ = _setup(
        tmp_path,
        decision="EXCLUDE",
        with_ast_summary=True,
        pipeline_version=2,
    )

    class FailedSurface:
        evidence_ref = None

        async def propose_batch(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("Excluded candidates must not be proposed")

        async def propose_surface(
            self,
            identity: CheckpointIdentity,
            _static: StaticBootstrapResult,
            context: SurfaceContext,
        ) -> StageFailure:
            self.evidence_ref = SimpleArtifactRepository(
                tmp_path / "data", identity
            ).put_json(
                {
                    "kind": "simple_surface_hypothesis_prompt_v1",
                    "surface_id": context.surface_id,
                    "context_id": context.context_id,
                }
            )
            return StageFailure(
                code="FAILED",
                retryable=True,
                safe_message="Codex call did not succeed: FAILED",
                evidence_refs=(self.evidence_ref,),
            )

    producer = FailedSurface()
    app._candidate_hypotheses = cast(HypothesisBootstrap, producer)

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    root = store.require(outcome.identity, SimpleStage.HYPOTHESIS_DONE)
    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "HYPOTHESIS_SURFACE_PROVIDER_FAILED"
    assert root.status is StageStatus.BLOCKED
    assert root.error_code == outcome.error_code
    assert producer.evidence_ref in root.output_refs
    assert store.list_surface_exploration_progress(outcome.identity, "scope-1") == {}


@pytest.mark.asyncio
async def test_streaming_starts_verification_before_next_batch(tmp_path: Path) -> None:
    app, store, _client, _ = _setup(
        tmp_path,
        result_count=17,
        decision="INCLUDE",
        with_ast_summary=True,
        pipeline_version=2,
    )
    events: list[str] = []
    producer = _SeedBatches(tmp_path / "data", events)
    app._candidate_hypotheses = cast(HypothesisBootstrap, producer)
    app._runner_factory = lambda *_: cast(
        SimpleRuntimeRunner, _RecordingRunner(store, events)
    )

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert outcome.status != "COMPLETE"
    assert producer.calls == 2
    assert (
        events.index("batch-1")
        < next(
            index for index, value in enumerate(events) if value.startswith("child-")
        )
        < events.index("batch-2")
    )
    assert sum(value.startswith("child-") for value in events) == 17


@pytest.mark.asyncio
async def test_blocked_child_is_attempted_once_across_batches(tmp_path: Path) -> None:
    app, store, _client, _ = _setup(
        tmp_path,
        result_count=17,
        decision="INCLUDE",
        with_ast_summary=True,
        pipeline_version=2,
    )
    events: list[str] = []
    producer = _SeedBatches(tmp_path / "data", events)
    app._candidate_hypotheses = cast(HypothesisBootstrap, producer)
    app._runner_factory = lambda *_: cast(
        SimpleRuntimeRunner, _RecordingRunner(store, events, blocked=True)
    )

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert outcome.status == "BLOCKED"
    child_events = [value for value in events if value.startswith("child-")]
    assert len(child_events) == len(set(child_events))
    assert len(child_events) == 17
    assert producer.calls == 2
    root = store.require(outcome.identity, SimpleStage.HYPOTHESIS_DONE)
    assert root.status is StageStatus.BLOCKED
    assert root.error_code == "CANDIDATE_CHILD_ERROR:TEST_CHILD_BLOCKED"
    snapshot = ProgressProjector(store).snapshot(
        outcome.identity.analysis_id, candidate_pipeline_version=2
    )
    assert snapshot.status == "BLOCKED"
    assert snapshot.error_code == "TEST_CHILD_BLOCKED"


@pytest.mark.asyncio
async def test_child_cleanup_block_does_not_create_unconfirmable_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, _client, _ = _setup(
        tmp_path,
        result_count=1,
        decision="INCLUDE",
        with_ast_summary=True,
        pipeline_version=2,
    )
    events: list[str] = []
    app._candidate_hypotheses = cast(
        HypothesisBootstrap, _SeedBatches(tmp_path / "data", events)
    )

    class CleanupBlockedRunner:
        async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
            pending = store.require(identity, SimpleStage.PRO_CON_DONE)
            store.save_checkpoint(
                pending.model_copy(
                    update={
                        "status": StageStatus.BLOCKED,
                        "attempt_id": "child-cleanup-attempt",
                        "error_code": "CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                    }
                )
            )
            return RunOutcome(
                current_stage=SimpleStage.PRO_CON_DONE,
                status=StageStatus.BLOCKED,
                error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                attempt_id="child-cleanup-attempt",
            )

    app._runner_factory = lambda *_: cast(SimpleRuntimeRunner, CleanupBlockedRunner())
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "BLOCKED"
    root = store.require(first.identity, SimpleStage.HYPOTHESIS_DONE)
    assert root.status is StageStatus.BLOCKED
    assert root.error_code != "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert (root.error_code or "").startswith("CANDIDATE_CHILD_CODEX_STATE_PENDING:")
    snapshot = ProgressProjector(store).snapshot(
        first.identity.analysis_id, candidate_pipeline_version=2
    )
    assert snapshot.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"

    monkeypatch.setattr(
        store,
        "has_codex_cleanup_confirmation",
        lambda checkpoint, _artifacts: checkpoint.identity.hypothesis_id is not None,
    )
    app._runner_factory = lambda *_: cast(
        SimpleRuntimeRunner, _RecordingRunner(store, events)
    )
    resumed = await app.resume(first.identity.analysis_id)
    assert resumed.error_code != "CODEX_PROCESS_CLEANUP_UNCONFIRMED"


@pytest.mark.asyncio
async def test_missing_codex_child_checkpoint_cannot_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, store, _client, _ = _setup(
        tmp_path,
        result_count=1,
        decision="INCLUDE",
        with_ast_summary=True,
        pipeline_version=2,
    )
    events: list[str] = []
    app._candidate_hypotheses = cast(
        HypothesisBootstrap, _SeedBatches(tmp_path / "data", events)
    )

    calls: list[str] = []

    class UnpersistedCleanupRunner:
        async def resume_hypothesis(self, _identity: CheckpointIdentity) -> RunOutcome:
            calls.append("run")
            return RunOutcome(
                current_stage=SimpleStage.PRO_CON_DONE,
                status=StageStatus.BLOCKED,
                error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                attempt_id="new-unrecorded-attempt",
            )

    app._runner_factory = lambda *_: cast(
        SimpleRuntimeRunner, UnpersistedCleanupRunner()
    )
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "BLOCKED"
    assert (
        store.require(first.identity, SimpleStage.HYPOTHESIS_DONE).error_code or ""
    ).startswith("CANDIDATE_CHILD_CODEX_STATE_PENDING:")
    assert not any(
        checkpoint.identity.hypothesis_id is not None
        and checkpoint.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
        for checkpoint in store.list_checkpoints(first.identity.analysis_id)
    )
    root_code = store.require(first.identity, SimpleStage.HYPOTHESIS_DONE).error_code
    assert root_code is not None
    child_id = root_code.split(":", 2)[1]
    stale = first.identity.model_copy(update={"hypothesis_id": child_id})
    store.save_checkpoint(
        StageCheckpoint(
            identity=stale,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.BLOCKED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            attempt_id="old-attempt",
            updated_at=store.require(
                first.identity, SimpleStage.HYPOTHESIS_DONE
            ).updated_at
            - timedelta(seconds=1),
        )
    )
    monkeypatch.setattr(store, "has_codex_cleanup_confirmation", lambda *_: True)
    monkeypatch.setattr(app, "_verify_registered_candidate_proposals", lambda _: None)
    snapshot = ProgressProjector(store).snapshot(
        first.identity.analysis_id, candidate_pipeline_version=2
    )
    assert snapshot.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert snapshot.current_hypothesis_id is None

    resumed = await app.resume(first.identity.analysis_id)

    assert resumed.status == "BLOCKED"
    assert resumed.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert calls == ["run"]


@pytest.mark.asyncio
async def test_invalid_chaining_child_closes_running_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, _client, _ = _setup(
        tmp_path,
        result_count=1,
        decision="INCLUDE",
        with_ast_summary=True,
        pipeline_version=2,
    )

    async def invalid_chaining(
        _run: object, identity: CheckpointIdentity, static: StaticBootstrapResult
    ) -> object:
        store.mark_running(
            identity,
            SimpleStage.HYPOTHESIS_DONE,
            (static.static_bundle_ref,),
            attempt_id="root-attempt",
        )
        child = identity.model_copy(update={"hypothesis_id": "invalid-chain"})
        checkpoint = StageCheckpoint(
            identity=child,
            stage=SimpleStage.CHAINING_DONE,
            status=StageStatus.RUNNING,
            input_refs=(),
            input_hash=input_reference_hash(()),
            attempt_id="child-attempt",
        )
        store.save_checkpoint(checkpoint)
        raise ChainingEvidenceInvalid(checkpoint)

    monkeypatch.setattr(app, "_run_candidate_pipeline_inner", invalid_chaining)
    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert outcome.status == "BLOCKED"
    root_identity = outcome.identity.model_copy(update={"hypothesis_id": None})
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE).status is (
        StageStatus.BLOCKED
    )
    snapshot = ProgressProjector(store).snapshot(
        outcome.identity.analysis_id, candidate_pipeline_version=2
    )
    assert snapshot.status == "BLOCKED"
    assert snapshot.error_code == "CHAINING_EVIDENCE_INVALID"


@pytest.mark.asyncio
async def test_partial_batch_verifies_committed_sibling_before_resume(
    tmp_path: Path,
) -> None:
    app, store, _client, _ = _setup(
        tmp_path,
        result_count=17,
        decision="INCLUDE",
        with_ast_summary=True,
        pipeline_version=2,
    )
    events: list[str] = []

    class PartialProducer(_SeedBatches):
        async def propose_batch(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
            batch: CandidateBatch,
            *,
            requested_ids: tuple[str, ...] | None = None,
        ) -> BatchProposalResult:
            whole = await super().propose_batch(
                identity, static, batch, requested_ids=requested_ids
            )
            if self.calls != 1:
                return whole
            ids = requested_ids or batch.candidate_ids
            return BatchProposalResult(
                results={ids[0]: whole.results[ids[0]]},
                missing_ids=ids[1:],
                attempt_refs=whole.attempt_refs,
                failure=StageFailure(
                    code="HYPOTHESIS_BATCH_OUTPUT_INVALID",
                    retryable=False,
                    safe_message="One candidate result was valid",
                ),
            )

    producer = PartialProducer(tmp_path / "data", events)
    app._candidate_hypotheses = cast(HypothesisBootstrap, producer)
    app._runner_factory = lambda *_: cast(
        SimpleRuntimeRunner, _RecordingRunner(store, events)
    )
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "BLOCKED"
    assert events[0] == "batch-1"
    assert events[1].startswith("child-")
    assert len(store.list_candidate_batch_outcomes(first.identity, "scope-1")) == 1

    second = await app.resume("analysis-1")
    assert second.status == "BLOCKED"
    assert second.error_code == "HYPOTHESIS_SURFACE_UNAVAILABLE"
    assert len(store.list_candidate_batch_outcomes(first.identity, "scope-1")) == 17
    assert events.count(events[1]) == 1


@pytest.mark.asyncio
async def test_backpressure_stops_production_with_pending_children(
    tmp_path: Path,
) -> None:
    app, store, _client, _ = _setup(
        tmp_path,
        result_count=65,
        decision="INCLUDE",
        with_ast_summary=True,
        pipeline_version=2,
    )
    app._max_pending_candidate_children = 64
    events: list[str] = []
    producer = _SeedBatches(tmp_path / "data", events)
    app._candidate_hypotheses = cast(HypothesisBootstrap, producer)
    app._runner_factory = lambda *_: cast(
        SimpleRuntimeRunner, _RecordingRunner(store, events, blocked=True)
    )

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )

    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "CANDIDATE_BACKPRESSURE_BLOCKED"
    assert producer.calls == 1
    assert store.hypothesis_count(outcome.identity) <= 64
    assert len(store.list_candidate_batch_outcomes(outcome.identity, "scope-1")) < 65

    app._runner_factory = lambda *_: cast(
        SimpleRuntimeRunner, _RecordingRunner(store, events)
    )
    resumed = await app.resume("analysis-1")
    assert resumed.status == "BLOCKED"
    assert resumed.error_code == "HYPOTHESIS_SURFACE_UNAVAILABLE"
    assert producer.calls == 5
    assert len(store.list_candidate_batch_outcomes(outcome.identity, "scope-1")) == 65


def test_atomic_child_claim_rejects_duplicate_owner(tmp_path: Path) -> None:
    store, identity, _artifacts, _workspace, _candidates, _ids = _fixture(
        tmp_path, count=1
    )
    assert store.claim_hypothesis(identity, "hypothesis-one", "turn-1") is True
    assert store.claim_hypothesis(identity, "hypothesis-one", "turn-2") is False
    store.release_hypothesis_claim(identity, "hypothesis-one", "turn-1")
    assert store.claim_hypothesis(identity, "hypothesis-one", "turn-2") is True
