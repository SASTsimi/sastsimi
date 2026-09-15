"""Runtime work API; the injected ports own each atomic state change."""

from typing import Protocol

from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.work import (
    TERMINAL_WORK_STATUSES,
    AttemptStatus,
    StateTransition,
    WorkExecutionState,
    WorkStatus,
)
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.runtime_store import WorkStatePort


class HandlerFailureRecorder(Protocol):
    """Persist a safe BLOCKED/FAILED outcome for one exact failed attempt."""

    def record_handler_failure(
        self, context: WorkContext, reason_code: str
    ) -> WorkExecutionState: ...


class HandlerDidNotFinalizeError(ValueError):
    """The exact claimed attempt returned while its work was still RUNNING."""


class StaleHandlerResultError(ValueError):
    """A late or mismatched handler result is not the current attempt's result."""


class WorkService:
    def __init__(
        self,
        store: WorkStatePort,
        failure_recorder: HandlerFailureRecorder | None = None,
    ) -> None:
        self.store = store
        self._failure_recorder = failure_recorder

    def get(self, work_id: str) -> WorkExecutionState:
        return self.store.get(work_id)

    def registration_scope(self, work_id: str) -> BudgetScopeRef:
        return self.store.registration_scope(work_id)

    def register(
        self,
        work: WorkExecutionState,
        decision_ref: RecordRef,
        reservation_ref: RecordRef | None,
    ) -> WorkExecutionState:
        return self.store.register(work, decision_ref, reservation_ref)

    def make_ready(self, transition: StateTransition) -> WorkExecutionState:
        return self.store.make_ready(transition)

    def require_failure_recorder(self) -> None:
        if self._failure_recorder is None:
            raise ValueError("HANDLER_FAILURE_RECORDER_REQUIRED")

    def record_handler_failure(self, context: WorkContext) -> WorkExecutionState:
        self.require_failure_recorder()
        assert self._failure_recorder is not None
        failed = self._failure_recorder.record_handler_failure(
            context, "WORK_HANDLER_FAILED"
        )
        if failed.status not in {WorkStatus.BLOCKED, WorkStatus.FAILED}:
            raise ValueError("WORK_HANDLER_FAILURE_NOT_PERSISTED")
        if (
            self.accept_handler_result(context, WorkHandlerResult(failed.output_refs))
            != failed
        ):
            raise ValueError("WORK_HANDLER_FAILURE_NOT_PERSISTED")
        return failed

    def accept_handler_result(
        self, context: WorkContext, result: WorkHandlerResult
    ) -> WorkExecutionState:
        """Observe, but never create, the exact handler-owned terminal revision."""

        current = self.get(str(context.work.work_id))
        if current == context.work:
            raise HandlerDidNotFinalizeError("WORK_HANDLER_DID_NOT_FINALIZE")
        attempts = self.store.attempts_for_work(str(context.work.work_id))
        completed_attempt = attempts[-1] if attempts else None
        allowed_statuses = TERMINAL_WORK_STATUSES | {WorkStatus.BLOCKED}
        expected_attempt_status = {
            WorkStatus.BLOCKED: AttemptStatus.CANCELLED,
            WorkStatus.SUCCEEDED: AttemptStatus.SUCCEEDED,
            WorkStatus.PARTIAL: AttemptStatus.PARTIAL,
            WorkStatus.FAILED: AttemptStatus.FAILED,
            WorkStatus.CANCELLED: AttemptStatus.CANCELLED,
        }.get(current.status)
        if (
            current.meta.analysis_id != context.work.meta.analysis_id
            or current.work_id != context.work.work_id
            or current.work_type != context.work.work_type
            or current.input_hash != context.work.input_hash
            or current.state_version <= context.work.state_version
            or current.status not in allowed_statuses
            or current.active_attempt_id is not None
            or any(ref not in result.output_refs for ref in current.output_refs)
            or completed_attempt is None
            or completed_attempt.attempt_id != context.attempt.attempt_id
            or completed_attempt.work_id != context.work.work_id
            or completed_attempt.status == "RUNNING"
            or completed_attempt.status != expected_attempt_status
            or completed_attempt.input_hash != context.attempt.input_hash
            or completed_attempt.output_refs != current.output_refs
        ):
            raise StaleHandlerResultError("WORK_HANDLER_RESULT_NOT_CURRENT")
        return current


__all__ = [
    "HandlerDidNotFinalizeError",
    "HandlerFailureRecorder",
    "StaleHandlerResultError",
    "WorkService",
]
