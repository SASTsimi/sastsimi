"""Claimed-work adapters for Primitive admission and Chaining."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import ProposalId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.work import AttemptStatus, SubjectType, WorkStatus, WorkType
from sastsimi.ports.chaining import (
    ChainingCohortPort,
    ChainingCommittedSourcePort,
    ChainingProposalRegistrationPort,
    PrimitiveAdmissionPort,
)
from sastsimi.ports.dto import WorkContext, WorkHandlerResult

from .service import ChainingCallRefs, ChainingWorkflowService


def require_claimed_context(context: WorkContext, expected: WorkType | str) -> None:
    """Reject stale, unclaimed, or cross-attempt handler input."""

    work, attempt = context.work, context.attempt
    if (
        work.work_type != WorkType(expected)
        or work.status != WorkStatus.RUNNING
        or attempt.status != AttemptStatus.RUNNING
        or work.active_attempt_id is None
        or work.active_attempt_id != attempt.attempt_id
        or work.work_id != attempt.work_id
        or work.input_hash != attempt.input_hash
        or work.input_hash != content_hash(work.input_refs)
        or not isinstance(work.meta, RecordMeta)
        or not isinstance(attempt.meta, RecordMeta)
        or work.meta.analysis_id != attempt.meta.analysis_id
        or work.meta.workspace_id != attempt.meta.workspace_id
        or work.meta.commit_id != attempt.meta.commit_id
    ):
        raise ValueError("WORK_CONTEXT_NOT_CURRENT")


class ChainingCallResolver(Protocol):
    def __call__(self, context: WorkContext) -> ChainingCallRefs: ...


@dataclass(frozen=True, slots=True)
class PrimitiveUpdateHandler:
    admission: PrimitiveAdmissionPort
    sources: ChainingCommittedSourcePort
    cohorts: ChainingCohortPort
    budget_scope_ref: BudgetScopeRef
    requester_identity_ref: BudgetScopeRef

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        require_claimed_context(context, WorkType.PRIMITIVE_UPDATE)
        completed = self.admission.admit(context)
        commit_ref = completed.last_transition_commit_ref
        completed_ref = reference(completed)
        if (
            completed.status != WorkStatus.SUCCEEDED
            or completed.active_attempt_id is not None
            or not isinstance(commit_ref, StoredDataRef)
            or not isinstance(completed_ref, StoredDataRef)
        ):
            raise ValueError("PRIMITIVE_UPDATE_NOT_COMMITTED")
        outcome = self.sources.primitive_update(commit_ref)
        if (
            outcome.transition_commit_ref != commit_ref
            or outcome.source_work_ref != completed_ref
        ):
            raise ValueError("PRIMITIVE_UPDATE_SOURCE_MISMATCH")
        if outcome.primitive_refs:
            pending = self.cohorts.register_pending(
                outcome=outcome,
                scope=self.budget_scope_ref,
                requester_identity_ref=self.requester_identity_ref,
                metadata=completed.meta,
                generation=completed.work_generation,
            )
            self.cohorts.promote_ready(
                registration=pending,
                scope=self.budget_scope_ref,
                requester_identity_ref=self.requester_identity_ref,
            )
        return WorkHandlerResult(completed.output_refs)


@dataclass(frozen=True, slots=True)
class ChainingWorkHandler:
    service: ChainingWorkflowService
    resolve_call: ChainingCallResolver

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        require_claimed_context(context, WorkType.CHAINING)
        outcome = await self.service.execute(
            context=context,
            call=self.resolve_call(context),
        )
        return WorkHandlerResult(outcome.completed_work.output_refs)


@dataclass(frozen=True, slots=True)
class HypothesisProposalHandler:
    registration: ChainingProposalRegistrationPort
    requester_identity_ref: BudgetScopeRef

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        require_claimed_context(context, WorkType.HYPOTHESIS_PROPOSAL)
        if context.work.subject_type != SubjectType.PROPOSAL:
            raise ValueError("CHAINING_CHILD_SOURCE_MISMATCH")
        source_refs = tuple(
            ref
            for ref in context.work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "chaining_result"
        )
        if len(context.work.input_refs) != 1 or len(source_refs) != 1:
            raise ValueError("CHAINING_CHILD_SOURCE_MISMATCH")
        proposal_id = ProposalId(str(context.work.subject_id))
        result = self.registration.register_claimed(
            context=context,
            source_result_ref=source_refs[0],
            proposal_id=proposal_id,
            requester_identity_ref=self.requester_identity_ref,
        )
        verification = result.verification_work
        if (
            result.source_result_ref != source_refs[0]
            or result.proposal.proposal_id != proposal_id
            or verification.status != WorkStatus.READY
            or verification.active_attempt_id is not None
            or verification.output_refs
        ):
            raise ValueError("CHAINING_CHILD_REGISTRATION_MISMATCH")
        return WorkHandlerResult(
            (result.proposal_ref, result.hypothesis_ref, result.process_ref)
        )


__all__ = [
    "ChainingCallResolver",
    "ChainingWorkHandler",
    "HypothesisProposalHandler",
    "PrimitiveUpdateHandler",
    "require_claimed_context",
]
