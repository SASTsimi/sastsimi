"""Repair post-commit Chaining handoffs without rerunning an Agent."""

from __future__ import annotations

from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.chaining import (
    ChainingChildHandoffPort,
    ChainingCohortPort,
    ChainingCohortRegistration,
    ChainingCommittedSourcePort,
    ChainingResultReconciliationRequest,
    PrimitiveUpdateReconciliationRequest,
)
from sastsimi.ports.record_store import RecordStore


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


__all__ = ["ChainingReconciliationService"]
