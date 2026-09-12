from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from sastsimi.chaining.work_handlers import PrimitiveUpdateHandler
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.ids import (
    CommitId,
    ProposalId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.chaining import (
    ChainingResultReconciliationRequest,
    PrimitiveUpdateOutcome,
    PrimitiveUpdateReconciliationRequest,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.runtime.chaining_reconciliation import ChainingReconciliationService
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta as fixture_meta
from tests.contract.domain.fixtures import wire


@dataclass
class _Sources:
    result: ChainingResult
    reads: int = 0

    def chaining_result(self, source_result_ref: StoredDataRef) -> ChainingResult:
        self.reads += 1
        return self.result


class _Child:
    def __init__(self, works: dict[str, WorkExecutionState]) -> None:
        self.works = works
        self.calls: list[str] = []

    def enqueue_ready(
        self,
        *,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState:
        del source_result_ref, requester_identity_ref
        self.calls.append(str(proposal_id))
        return self.works[str(proposal_id)]


class _Cohorts:
    def __init__(self) -> None:
        self.pending: dict[str, object] | None = None
        self.promoted = False

    def register_pending(self, **kwargs: object) -> object:
        self.pending = kwargs
        return SimpleNamespace(status="PENDING")

    def promote_ready(self, **kwargs: object) -> object:
        self.promoted = True
        return SimpleNamespace(status="READY")


class _Records:
    def __init__(self, value: WorkExecutionState) -> None:
        self.value = value

    def get_exact(self, ref: object) -> object:
        del ref
        return self.value


def _result(*proposal_ids: str) -> ChainingResult:
    proposals = tuple(
        SimpleNamespace(proposal_id=ProposalId(value), origin="CHAINING")
        for value in proposal_ids
    )
    meta = wire(
        RecordMeta,
        make("ChainingResult")["meta"]
        | {"record_type": "chaining_result", "hypothesis_id": None},
    )
    return ChainingResult.model_construct(
        meta=meta,
        chained_hypothesis_proposals=proposals,
    )


def _ref(kind: str, value: str = "a") -> StoredDataRef:
    return StoredDataRef(
        data_kind=kind,
        record_id=RecordId(f"{kind}-{value}"),
        stored_data_id=StoredDataId(f"stored-{kind}-{value}"),
        content_hash=value * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )


def _work(proposal_id: str) -> WorkExecutionState:
    return WorkExecutionState.model_construct(
        work_id=f"work-{proposal_id}",
        work_type="HYPOTHESIS_PROPOSAL",
        subject_type="PROPOSAL",
        subject_id=proposal_id,
        status="READY",
        active_attempt_id=None,
        output_refs=(),
    )


def _completed_primitive_work(
    primitive_ref: StoredDataRef, commit_ref: StoredDataRef
) -> WorkExecutionState:
    data = {
        "meta": fixture_meta("work_execution_state", hypothesis="h1", attempt=None),
        "work_id": "primitive-work",
        "parent_work_ref": None,
        "work_type": "PRIMITIVE_UPDATE",
        "subject_type": "HYPOTHESIS",
        "subject_id": "h1",
        "work_generation": 4,
        "status": "SUCCEEDED",
        "state_version": 3,
        "last_transition_ref": _ref("state_transition").model_dump(mode="json"),
        "last_transition_commit_ref": commit_ref.model_dump(mode="json"),
        "active_attempt_id": None,
        "input_hash": content_hash(()),
        "dedupe_key": content_hash(["primitive-work"]),
        "trigger_primitive_ref": None,
        "input_refs": [],
        "output_refs": [primitive_ref.model_dump(mode="json")],
        "gap_ids": [],
        "error_ids": [],
        "waiting_for": [],
        "stop_reason": "COMPLETED",
        "started_at": "2026-09-08T00:00:00Z",
        "finished_at": "2026-09-08T00:00:01Z",
        "elapsed_ms": 1000,
    }
    return wire(WorkExecutionState, data)


def test_reconciliation_replays_committed_handoff_without_agent_execution() -> None:
    result = _result("proposal-1", "proposal-2")
    source = _Sources(result)
    child = _Child({value: _work(value) for value in ("proposal-1", "proposal-2")})
    service = ChainingReconciliationService(
        sources=source,
        cohorts=SimpleNamespace(),
        children=child,
        records=SimpleNamespace(),
        budget_scope_ref=_ref("budget_scope"),
        requester_identity_ref=_ref("requester_identity"),
    )

    works = service.reconcile_chaining_result(
        ChainingResultReconciliationRequest(_ref("chaining_result"))
    )

    assert tuple(str(work.subject_id) for work in works) == (
        "proposal-1",
        "proposal-2",
    )
    assert child.calls == ["proposal-1", "proposal-2"]
    assert source.reads == 1

    repeated = service.reconcile_chaining_result(
        ChainingResultReconciliationRequest(_ref("chaining_result"))
    )
    assert tuple(work.work_id for work in repeated) == tuple(
        work.work_id for work in works
    )
    assert tuple(child.works) == ("proposal-1", "proposal-2")


def test_primitive_reconciliation_rebuilds_whole_cohort_from_committed_update() -> None:
    primitive_ref = _ref("primitive")
    index_ref = _ref("primitive_index_state")
    commit_ref = _ref("transition_commit")
    completed = _completed_primitive_work(primitive_ref, commit_ref)
    outcome = PrimitiveUpdateOutcome(
        source_work_ref=reference(completed),  # type: ignore[arg-type]
        transition_commit_ref=commit_ref,
        admission_decision_ref=_ref("primitive_admission_decision"),
        primitive_refs=(primitive_ref,),
        primitive_index_ref=index_ref,
    )
    sources = SimpleNamespace(
        primitive_update=lambda value: outcome,
        chaining_result=lambda value: _result(),
    )
    cohorts = _Cohorts()
    service = ChainingReconciliationService(
        sources=sources,
        cohorts=cohorts,  # type: ignore[arg-type]
        children=SimpleNamespace(),
        records=_Records(completed),  # type: ignore[arg-type]
        budget_scope_ref=_ref("budget_scope"),
        requester_identity_ref=_ref("requester_identity"),
    )

    registration = service.reconcile_primitive_update(
        PrimitiveUpdateReconciliationRequest(commit_ref)
    )

    assert registration.status == "READY"  # type: ignore[union-attr]
    assert cohorts.pending is not None
    assert cohorts.pending["outcome"] == outcome
    assert cohorts.pending["generation"] == 4
    assert cohorts.promoted


@pytest.mark.asyncio
async def test_primitive_update_commits_before_promoting_complete_cohort() -> None:
    primitive_ref = _ref("primitive")
    commit_ref = _ref("transition_commit")
    completed = _completed_primitive_work(primitive_ref, commit_ref)
    running = completed.model_copy(
        update={
            "status": "RUNNING",
            "active_attempt_id": "primitive-attempt",
            "output_refs": (),
            "finished_at": None,
            "stop_reason": None,
        }
    )
    attempt = WorkAttempt.model_construct(
        meta=running.meta.model_copy(update={"attempt_id": "primitive-attempt"}),
        work_id=running.work_id,
        attempt_id="primitive-attempt",
        status="RUNNING",
        input_hash=running.input_hash,
    )
    outcome = PrimitiveUpdateOutcome(
        source_work_ref=reference(completed),  # type: ignore[arg-type]
        transition_commit_ref=commit_ref,
        admission_decision_ref=_ref("primitive_admission_decision"),
        primitive_refs=(primitive_ref,),
        primitive_index_ref=_ref("primitive_index_state"),
    )
    cohorts = _Cohorts()
    handler = PrimitiveUpdateHandler(
        admission=SimpleNamespace(admit=lambda context: completed),
        sources=SimpleNamespace(primitive_update=lambda value: outcome),
        cohorts=cohorts,  # type: ignore[arg-type]
        budget_scope_ref=_ref("budget_scope"),
        requester_identity_ref=_ref("requester_identity"),
    )

    result = await handler.execute(WorkContext(running, attempt))

    assert result.output_refs == completed.output_refs
    assert cohorts.pending is not None
    assert cohorts.pending["outcome"] == outcome
    assert cohorts.promoted
