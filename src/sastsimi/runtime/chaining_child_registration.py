"""Ready-only child-proposal registration boundary for Chaining."""

from __future__ import annotations

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.ids import ProposalId
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, require_record_ref
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.chaining import ChainingCommittedSourcePort
from sastsimi.ports.ready_work import ReadyWorkPort


class ChainingChildRegistrationService:
    """Create only a READY proposal work from one committed result."""

    def __init__(
        self,
        *,
        sources: ChainingCommittedSourcePort,
        ready: ReadyWorkPort,
        budget_scope_ref: BudgetScopeRef,
    ) -> None:
        self._sources = sources
        self._ready = ready
        self._scope = budget_scope_ref

    def enqueue_ready(
        self,
        *,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState:
        require_record_ref(source_result_ref, "chaining_result")
        result = self._sources.chaining_result(source_result_ref)
        if not isinstance(result, ChainingResult):
            raise ValueError("CHAINING_COMMITTED_SOURCE_MISMATCH")
        matches = tuple(
            proposal
            for proposal in result.chained_hypothesis_proposals
            if proposal.proposal_id == proposal_id and proposal.origin == "CHAINING"
        )
        if len(matches) != 1:
            raise ValueError("CHAINING_CHILD_NOT_COMMITTED")
        work = self._ready.enqueue(
            scope=self._scope,
            metadata=result.meta,
            work_type="HYPOTHESIS_PROPOSAL",
            subject_type="PROPOSAL",
            subject_id=str(proposal_id),
            identity=requester_identity_ref,
            role="ORCHESTRATION",
            generation=1,
            inputs=(source_result_ref,),
        )
        if (
            work.status != WorkStatus.READY
            or work.active_attempt_id is not None
            or work.output_refs
            or str(work.subject_id) != str(proposal_id)
        ):
            raise ValueError("CHAINING_CHILD_NOT_READY")
        return work


__all__ = ["ChainingChildRegistrationService"]
