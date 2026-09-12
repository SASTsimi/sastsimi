from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.ids import ProposalId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.chaining import (
    ChainingResultReconciliationRequest,
)
from sastsimi.runtime.chaining_child_registration import (
    ChainingChildRegistrationService,
)
from sastsimi.runtime.chaining_reconciliation import ChainingReconciliationService
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import wire


@dataclass
class _Sources:
    result: ChainingResult
    reads: int = 0

    def chaining_result(self, source_result_ref: StoredDataRef) -> ChainingResult:
        self.reads += 1
        return self.result


class _Ready:
    def __init__(self, work: WorkExecutionState) -> None:
        self.work = work
        self.calls: list[dict[str, object]] = []

    def enqueue(self, *args: object, **kwargs: object) -> WorkExecutionState:
        self.calls.append({"args": args, **kwargs})
        return self.work


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
    return StoredDataRef.model_construct(
        data_kind=kind,
        record_id=f"{kind}-{value}",
        stored_data_id=f"stored-{kind}-{value}",
        content_hash=value * 64,
        workspace_id="ws1",
        commit_id="c1",
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


def test_child_registration_reads_exact_committed_source_and_only_enqueues_ready() -> None:
    result = _result("proposal-1")
    source = _Sources(result)
    ready = _Ready(_work("proposal-1"))
    service = ChainingChildRegistrationService(
        sources=source,
        ready=ready,
        budget_scope_ref=_ref("budget_scope"),
    )
    result_ref = _ref("chaining_result")

    work = service.enqueue_ready(
        source_result_ref=result_ref,
        proposal_id=ProposalId("proposal-1"),
        requester_identity_ref=_ref("requester_identity"),
    )

    assert work.status == "READY"
    assert ready.calls[0]["work_type"] == "HYPOTHESIS_PROPOSAL"
    assert ready.calls[0]["inputs"] == (result_ref,)
    assert ready.calls[0]["subject_id"] == "proposal-1"
    assert source.reads == 1


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
