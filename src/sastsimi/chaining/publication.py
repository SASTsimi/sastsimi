"""Runtime adapter for atomic Chaining result publication."""

from __future__ import annotations

from typing import Protocol

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record, WorkContext

from .work_handlers import require_claimed_context


class ResultCommitter(Protocol):
    """Narrow WorkflowRunner completion seam used by this adapter."""

    def complete(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        outputs: tuple[Record, ...],
        *,
        action_input_refs: tuple[RecordRef, ...] | None = None,
    ) -> WorkExecutionState: ...


class RuntimeChainingResultPublisher:
    """Commit one result through the trusted CHAINING SAVE_RESULT path.

    The storage TransitionService behind ``complete`` is responsible for
    reserving match identities in the same transaction as result publication.
    """

    def __init__(
        self,
        committer: ResultCommitter,
        requester_identity_ref: BudgetScopeRef,
    ) -> None:
        self._committer = committer
        self._identity = requester_identity_ref

    def publish(
        self,
        *,
        context: WorkContext,
        result: ChainingResult,
        action_input_refs: tuple[RecordRef, ...],
    ) -> WorkExecutionState:
        require_claimed_context(context, "CHAINING")
        work = context.work
        work_meta = work.meta
        meta = result.meta
        if (
            not isinstance(work_meta, RecordMeta)
            or not isinstance(meta, RecordMeta)
            or meta.analysis_id != work_meta.analysis_id
            or meta.workspace_id != work_meta.workspace_id
            or meta.commit_id != work_meta.commit_id
            or meta.attempt_id != work.active_attempt_id
            or not action_input_refs
        ):
            raise ValueError("CHAINING_RESULT_CONTEXT_MISMATCH")
        return self._committer.complete(
            work,
            self._identity,
            "CHAINING",
            (result,),
            action_input_refs=action_input_refs,
        )


__all__ = ["RuntimeChainingResultPublisher"]
