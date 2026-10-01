"""Candidate batches must release runnable children before the producer ends."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.application import (
    HypothesisSeed,
    SimpleAnalysisRequest,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import (
    BatchProposalResult,
    CandidateProposalOutcome,
)
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import RunOutcome
from sastsimi.simple_runtime.store import SimpleCheckpointStore
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
        _static: object,
        batch: object,
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
    app._candidate_hypotheses = producer
    app._runner_factory = lambda *_: _RecordingRunner(store, events)

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
    app._candidate_hypotheses = producer
    app._runner_factory = lambda *_: _RecordingRunner(store, events, blocked=True)

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
            static: object,
            batch: object,
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
    app._candidate_hypotheses = producer
    app._runner_factory = lambda *_: _RecordingRunner(store, events)
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
    assert second.status == "PAUSED"
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
    app._candidate_hypotheses = producer
    app._runner_factory = lambda *_: _RecordingRunner(store, events, blocked=True)

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

    app._runner_factory = lambda *_: _RecordingRunner(store, events)
    resumed = await app.resume("analysis-1")
    assert resumed.status == "PAUSED"
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
