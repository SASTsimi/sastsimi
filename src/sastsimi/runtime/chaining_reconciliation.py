"""Repair post-commit Chaining handoffs without rerunning an Agent."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.ids import AnalysisId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.chaining import (
    ChainingChildHandoffPort,
    ChainingCohortPort,
    ChainingCohortRegistration,
    ChainingCommittedSourcePort,
    ChainingReconciliationPort,
    ChainingResultReconciliationRequest,
    PrimitiveUpdateReconciliationRequest,
)
from sastsimi.ports.dto import Record
from sastsimi.ports.record_store import RecordStore

type PublishedRecordsResolver = Callable[[str], tuple[Record, ...]]


@dataclass(frozen=True, slots=True)
class ChainingStartupReconciliationResult:
    """Exact committed sources replayed for one analysis startup."""

    analysis_id: AnalysisId
    primitive_update_refs: tuple[StoredDataRef, ...]
    chaining_result_refs: tuple[StoredDataRef, ...]


class ChainingStartupReconciler:
    """Replay committed T13 handoff sources without scheduling any work."""

    def __init__(
        self,
        *,
        reconciliation: ChainingReconciliationPort,
        published_records: PublishedRecordsResolver,
    ) -> None:
        self._reconciliation = reconciliation
        self._published_records = published_records

    def __call__(self, analysis_id: AnalysisId) -> ChainingStartupReconciliationResult:
        updates: list[StoredDataRef] = []
        results: list[StoredDataRef] = []
        for record in self._published_records(str(analysis_id)):
            if str(getattr(record.meta, "analysis_id", "")) != str(analysis_id):
                raise ValueError("CHAINING_STARTUP_SCOPE_MISMATCH")
            source_ref = reference(record)
            if not isinstance(source_ref, StoredDataRef):
                raise ValueError("CHAINING_STARTUP_SOURCE_NOT_STORED")
            if isinstance(record, WorkExecutionState):
                if (
                    record.work_type == WorkType.PRIMITIVE_UPDATE
                    and record.status == WorkStatus.SUCCEEDED
                ):
                    commit_ref = record.last_transition_commit_ref
                    if not isinstance(commit_ref, StoredDataRef):
                        raise ValueError("CHAINING_STARTUP_SOURCE_NOT_COMMITTED")
                    if commit_ref not in updates:
                        updates.append(commit_ref)
            elif isinstance(record, ChainingResult) and source_ref not in results:
                results.append(source_ref)

        for source_ref in updates:
            self._reconciliation.reconcile_primitive_update(
                PrimitiveUpdateReconciliationRequest(source_ref)
            )
        for source_ref in results:
            self._reconciliation.reconcile_chaining_result(
                ChainingResultReconciliationRequest(source_ref)
            )
        return ChainingStartupReconciliationResult(
            analysis_id=analysis_id,
            primitive_update_refs=tuple(updates),
            chaining_result_refs=tuple(results),
        )


class ChainingReconciliationService:
    """Replay only deterministic handoffs from exact committed sources."""

    def __init__(
        self,
        *,
        sources: ChainingCommittedSourcePort,
        cohorts: ChainingCohortPort,
        children: ChainingChildHandoffPort,
        records: RecordStore,
        budget_scope_ref: BudgetScopeRef,
        requester_identity_ref: BudgetScopeRef,
    ) -> None:
        self._sources = sources
        self._cohorts = cohorts
        self._children = children
        self._records = records
        self._scope = budget_scope_ref
        self._identity = requester_identity_ref

    def reconcile_primitive_update(
        self,
        request: PrimitiveUpdateReconciliationRequest,
    ) -> ChainingCohortRegistration | None:
        outcome = self._sources.primitive_update(request.source_update_ref)
        if outcome.transition_commit_ref != request.source_update_ref:
            raise ValueError("CHAINING_RECONCILIATION_SOURCE_MISMATCH")
        if not outcome.primitive_refs:
            return None
        source_work = self._records.get_exact(outcome.source_work_ref)
        if (
            not isinstance(source_work, WorkExecutionState)
            or reference(source_work) != outcome.source_work_ref
            or source_work.status != WorkStatus.SUCCEEDED
            or not isinstance(source_work.meta, RecordMeta)
        ):
            raise ValueError("CHAINING_RECONCILIATION_SOURCE_MISMATCH")
        pending = self._cohorts.register_pending(
            outcome=outcome,
            scope=self._scope,
            requester_identity_ref=self._identity,
            metadata=source_work.meta,
            generation=source_work.work_generation,
        )
        return self._cohorts.promote_ready(
            registration=pending,
            scope=self._scope,
            requester_identity_ref=self._identity,
        )

    def reconcile_chaining_result(
        self,
        request: ChainingResultReconciliationRequest,
    ) -> tuple[WorkExecutionState, ...]:
        result = self._sources.chaining_result(request.source_result_ref)
        return tuple(
            self._children.enqueue_ready(
                source_result_ref=request.source_result_ref,
                proposal_id=proposal.proposal_id,
                requester_identity_ref=self._identity,
            )
            for proposal in result.chained_hypothesis_proposals
        )


__all__ = [
    "ChainingReconciliationService",
    "ChainingStartupReconciler",
    "ChainingStartupReconciliationResult",
]
