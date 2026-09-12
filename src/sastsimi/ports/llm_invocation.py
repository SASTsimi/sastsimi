"""Stable Agent-facing types for one persisted LLM invocation."""

from dataclasses import dataclass
from typing import Literal, Protocol

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    RequesterRole,
)
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMRole,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState, WorkType

type ExternalDispatchState = Literal["RETURNED", "UNRESOLVED"]


@dataclass(frozen=True)
class PersistedLLMInvocation:
    """One exact request/result/log set persisted by the trusted runtime."""

    request: LLMInvocationRequest
    result: LLMInvocationResult
    log_ref: StoredDataRef
    dispatch_state: ExternalDispatchState


class InvocationMetadataFactory(Protocol):
    """Issue immutable record metadata at the composition boundary."""

    def __call__(
        self,
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta: ...


class ExactRecordReader(Protocol):
    """Read one immutable record revision by its exact reference."""

    def get_exact(self, ref: RecordRef) -> object: ...


@dataclass(frozen=True)
class LLMInvocationExpectation:
    """Trusted facts an Agent expects from one authorized LLM call."""

    work_type: WorkType
    action_type: ActionType
    requested_by: RequesterRole
    requester_identity_ref: BudgetScopeRef
    agent_role: LLMRole
    task_kind: str
    required_context: tuple[RecordRef, ...]
    require_new_session: bool = True
    forbid_tools: bool = False


@dataclass(frozen=True)
class ValidatedLLMInvocation:
    """Exact authorization and log closure validated by the trusted runtime."""

    issued_decision: ActionDecision
    claimed_decision: ActionDecision
    action: ActionRequest
    reservation: BudgetReservation
    call_spec: LLMCallSpec
    log: LLMInvocationLog
    save_input_refs: tuple[RecordRef, ...]


class LLMInvocationProvenanceValidator(Protocol):
    """Validate exact LLM-call provenance without exposing runtime internals."""

    def __call__(
        self,
        *,
        records: ExactRecordReader,
        work: WorkExecutionState,
        issued_decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
        invocation: PersistedLLMInvocation,
        expectation: LLMInvocationExpectation,
    ) -> ValidatedLLMInvocation: ...


__all__ = [
    "ExactRecordReader",
    "ExternalDispatchState",
    "InvocationMetadataFactory",
    "LLMInvocationExpectation",
    "LLMInvocationProvenanceValidator",
    "PersistedLLMInvocation",
    "ValidatedLLMInvocation",
]
