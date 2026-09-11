"""Fail-closed post-call provenance checks shared by LLM workflow stages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
    RequesterRole,
    UseStatus,
    validate_decision_for_action,
    validate_decision_revision,
)
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMRole,
    LLMToolPolicy,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType

from .llm_call_service import PersistedLLMInvocation


class ExactRecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


@dataclass(frozen=True)
class LLMInvocationExpectation:
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
    issued_decision: ActionDecision
    claimed_decision: ActionDecision
    action: ActionRequest
    reservation: BudgetReservation
    call_spec: LLMCallSpec
    log: LLMInvocationLog
    save_input_refs: tuple[RecordRef, ...]


_REQUEST_FIELDS = (
    "llm_call_id",
    "agent_role",
    "task_kind",
    "purpose",
    "provider_profile_ref",
    "model",
    "session_policy",
    "parent_session_ref",
    "context_refs",
    "prompt_registry_entry_ref",
    "prompt_key",
    "prompt_template_ref",
    "prompt_template_version",
    "prompt_payload_ref",
    "execution_limits_ref",
    "retry_policy_ref",
    "tool_policy_ref",
    "redaction_policy_ref",
    "semantic_validator_ref",
    "output_schema_ref",
    "output_schema",
    "token_budget",
    "timeout_ms",
)
_LOG_SPEC_FIELDS = tuple(
    name
    for name in _REQUEST_FIELDS
    if name not in {"output_schema", "token_budget", "timeout_ms"}
)


def validate_llm_invocation_provenance(
    *,
    records: ExactRecordReader,
    work: WorkExecutionState,
    issued_decision_ref: StoredDataRef,
    reservation_ref: RecordRef,
    call_spec_ref: StoredDataRef,
    invocation: PersistedLLMInvocation,
    expectation: LLMInvocationExpectation,
) -> ValidatedLLMInvocation:
    """Validate one exact issued-to-claimed invocation and return its save closure."""

    request, result = invocation.request, invocation.result
    request_ref = reference(request)
    result_ref = reference(result)
    log = _exact(records, invocation.log_ref)
    expected_scope = _work_scope(work)
    if (
        work.work_type != expectation.work_type
        or work.status != WorkStatus.RUNNING
        or work.active_attempt_id is None
        or invocation.dispatch_state != "RETURNED"
        or not isinstance(request_ref, StoredDataRef)
        or not isinstance(result_ref, StoredDataRef)
        or _exact(records, request_ref) != request
        or _exact(records, result_ref) != result
        or not isinstance(log, LLMInvocationLog)
        or reference(log) != invocation.log_ref
        or _record_scope(request.meta) != expected_scope
        or _record_scope(result.meta) != expected_scope
        or _record_scope(log.meta) != expected_scope
    ):
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")

    issued = _exact(records, issued_decision_ref)
    claimed = _exact(records, request.action_decision_ref)
    if (
        not isinstance(issued, ActionDecision)
        or not isinstance(claimed, ActionDecision)
        or reference(issued) != issued_decision_ref
        or reference(claimed) != request.action_decision_ref
        or issued.decision != Decision.ALLOW
        or issued.use_status != UseStatus.UNUSED
        or claimed.decision != Decision.ALLOW
        or claimed.use_status != UseStatus.USED
        or _record_scope(issued.meta) != expected_scope
        or _record_scope(claimed.meta) != expected_scope
    ):
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")
    try:
        validate_decision_for_action(issued, expectation.action_type)
        validate_decision_for_action(claimed, expectation.action_type)
        validate_decision_revision(issued, claimed)
    except ValueError as error:
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH") from error

    action = _exact(records, claimed.action_ref)
    reservation = _exact(records, reservation_ref)
    spec = _exact(records, call_spec_ref)
    work_ref = reference(work)
    if (
        not isinstance(action, ActionRequest)
        or reference(action) != claimed.action_ref
        or action.action_type != expectation.action_type
        or action.requested_by != expectation.requested_by
        or action.requester_identity_ref != expectation.requester_identity_ref
        or action.work_ref != work_ref
        or action.expected_state_version != work.state_version
        or action.llm_call_spec_ref != call_spec_ref
        or _record_scope(action.meta) != expected_scope
        or not isinstance(reservation, BudgetReservation)
        or reference(reservation) != reservation_ref
        or reservation.action_ref != claimed.action_ref
        or reservation.work_ref != work_ref
        or reservation.status != "RESERVED"
        or _record_scope(reservation.meta) != expected_scope
        or not isinstance(spec, LLMCallSpec)
        or reference(spec) != call_spec_ref
        or _record_scope(spec.meta) != expected_scope
    ):
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")

    required_context = expectation.required_context
    new_session_mismatch = expectation.require_new_session and (
        spec.session_policy != "NEW"
        or spec.parent_session_ref is not None
        or request.session_policy != "NEW"
        or request.parent_session_ref is not None
        or result.actual_session_mode != "NEW"
    )
    if (
        len(required_context) != len(set(required_context))
        or tuple(spec.context_refs) != required_context
        or any(
            getattr(request, name) != getattr(spec, name) for name in _REQUEST_FIELDS
        )
        or request.call_spec_ref != call_spec_ref
        or request.action_decision_ref != reference(claimed)
        or request.agent_role != expectation.agent_role
        or request.task_kind != expectation.task_kind
        or new_session_mismatch
        or result.status != "SUCCEEDED"
        or result.llm_call_id != request.llm_call_id
        or result.purpose != request.purpose
        or result.model != request.model
        or result.parsed_output_ref is None
        or result.response_ref != result.parsed_output_ref
        or not _artifact_ref(result.parsed_output_ref)
    ):
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")

    if (
        any(getattr(log, name) != getattr(spec, name) for name in _LOG_SPEC_FIELDS)
        or log.llm_call_id != request.llm_call_id
        or log.action_decision_ref != request.action_decision_ref
        or log.call_spec_ref != request.call_spec_ref
        or log.status != result.status
        or log.provider != result.provider
        or log.model != result.model
        or log.session_ref != result.session_ref
        or log.exposed_response_ref != result.response_ref
        or log.parsed_output_ref != result.parsed_output_ref
        or log.usage != result.usage
        or log.started_at != result.started_at
        or log.finished_at != result.finished_at
        or log.elapsed_ms != result.elapsed_ms
        or log.safe_error != result.safe_error
    ):
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")

    if expectation.forbid_tools:
        tool_policy = _exact(records, spec.tool_policy_ref)
        if (
            not isinstance(tool_policy, LLMToolPolicy)
            or reference(tool_policy) != spec.tool_policy_ref
            or tool_policy.policy_key != "tools.none.v1"
            or tool_policy.allowed_tools
            or log.tool_calls
        ):
            raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")

    refs = llm_invocation_save_refs(
        records=records,
        work=work,
        issued_decision_ref=issued_decision_ref,
        reservation_ref=reservation_ref,
        call_spec_ref=call_spec_ref,
        invocation=invocation,
    )
    return ValidatedLLMInvocation(
        issued_decision=issued,
        claimed_decision=claimed,
        action=action,
        reservation=reservation,
        call_spec=spec,
        log=log,
        save_input_refs=refs,
    )


def llm_invocation_save_refs(
    *,
    records: ExactRecordReader,
    work: WorkExecutionState,
    issued_decision_ref: StoredDataRef,
    reservation_ref: RecordRef,
    call_spec_ref: StoredDataRef,
    invocation: PersistedLLMInvocation,
) -> tuple[RecordRef, ...]:
    """Build the immutable SAVE_RESULT input set after provenance validation."""

    request = invocation.request
    result = invocation.result
    request_ref = reference(request)
    result_ref = reference(result)
    if not isinstance(request_ref, StoredDataRef) or not isinstance(
        result_ref, StoredDataRef
    ):
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")
    claimed = _exact(records, invocation.request.action_decision_ref)
    if not isinstance(claimed, ActionDecision):
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")
    action = _exact(records, claimed.action_ref)
    log = _exact(records, invocation.log_ref)
    if not isinstance(action, ActionRequest) or not isinstance(log, LLMInvocationLog):
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")
    refs: tuple[RecordRef, ...] = (
        *work.input_refs,
        issued_decision_ref,
        reference(action),
        reservation_ref,
        call_spec_ref,
        *action.input_refs,
        request.action_decision_ref,
        request_ref,
        result_ref,
        invocation.log_ref,
        log.exposed_request_ref,
        *(log.tool_calls),
        *(
            (invocation.result.parsed_output_ref,)
            if invocation.result.parsed_output_ref
            else ()
        ),
    )
    return tuple(dict.fromkeys(refs))


def _work_scope(work: WorkExecutionState) -> tuple[object, ...]:
    if not isinstance(work.meta, RecordMeta) or work.active_attempt_id is None:
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH")
    return (
        work.meta.analysis_id,
        work.meta.workspace_id,
        work.meta.commit_id,
        work.meta.hypothesis_id,
        work.active_attempt_id,
    )


def _exact(records: ExactRecordReader, ref: RecordRef) -> object:
    try:
        return records.get_exact(ref)
    except Exception as error:
        raise ValueError("LLM_INVOCATION_PROVENANCE_MISMATCH") from error


def _record_scope(meta: object) -> tuple[object, ...] | None:
    if not isinstance(meta, RecordMeta):
        return None
    return (
        meta.analysis_id,
        meta.workspace_id,
        meta.commit_id,
        meta.hypothesis_id,
        meta.attempt_id,
    )


def _artifact_ref(ref: StoredDataRef) -> bool:
    return (
        ref.record_id is None
        and ref.data_kind == "artifact"
        and str(ref.stored_data_id) == ref.content_hash
    )


__all__ = [
    "ExactRecordReader",
    "LLMInvocationExpectation",
    "ValidatedLLMInvocation",
    "llm_invocation_save_refs",
    "validate_llm_invocation_provenance",
]
