"""Trusted single-call LLM dispatch with exact closure and durable provenance."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    Decision,
    UseStatus,
)
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.llm import (
    InvocationStatus,
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    PromptPayload,
    ProviderProfile,
)
from sastsimi.contracts.llm_closure import llm_action_input_refs
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.record_store import RecordStore
from sastsimi.runtime.action_validator import RuntimeValidator
from sastsimi.runtime.external_call_service import ExternalCallService


@dataclass(frozen=True)
class PersistedLLMInvocation:
    request: LLMInvocationRequest
    result: LLMInvocationResult
    log_ref: StoredDataRef


class InvocationMetadataFactory(Protocol):
    """Issue immutable metadata at the composition boundary."""

    def __call__(
        self,
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta: ...


class AnalysisRunStateResolver(Protocol):
    """Return the current run state used to bind invocation purpose."""

    def current_state(self, analysis_id: str) -> AnalysisRunState: ...


class LLMCurrentSelectionGuard(Protocol):
    """Recheck exact current prompt/profile selection immediately before I/O."""

    def require_current(self, request: LLMInvocationRequest) -> None: ...


class ExactAdapterResolver:
    """Resolve an adapter by the exact profile revision and exact model only."""

    def __init__(
        self,
        adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter],
    ) -> None:
        self._adapters = dict(adapters)

    def resolve(self, profile_ref: StoredDataRef, model: str) -> LLMProviderAdapter:
        try:
            return self._adapters[(profile_ref, model)]
        except KeyError as error:
            raise ValueError("PROVIDER_ADAPTER_EXACT_MATCH_REQUIRED") from error


class LLMCallService:
    """Run one authorized provider call without implicit retry, repair, or fallback."""

    def __init__(
        self,
        *,
        records: RecordStore,
        artifacts: ArtifactStore,
        external: ExternalCallService,
        validator: RuntimeValidator,
        adapters: ExactAdapterResolver,
        metadata_factory: InvocationMetadataFactory,
        run_states: AnalysisRunStateResolver,
        current_selection: LLMCurrentSelectionGuard,
        clock: Clock,
    ) -> None:
        self._records = records
        self._artifacts = artifacts
        self._external = external
        self._validator = validator
        self._adapters = adapters
        self._metadata_factory = metadata_factory
        self._run_states = run_states
        self._current_selection = current_selection
        self._clock = clock

    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation:
        spec, profile, action = self._resolve_authorized_inputs(
            work, decision_ref, call_spec_ref
        )
        adapter = self._adapters.resolve(spec.provider_profile_ref, spec.model)

        async def operation(claimed_ref: RecordRef) -> PersistedLLMInvocation:
            if not isinstance(claimed_ref, StoredDataRef):
                raise ValueError("INVOCATION_ACTION_SCOPE_MISMATCH")
            self._require_claimed_decision(decision_ref, claimed_ref, action)
            request = self._request(work, claimed_ref, call_spec_ref, spec)
            request_ref = self._records.stage_record(request)
            if request_ref != reference(request):
                raise ValueError("INVOCATION_REQUEST_STAGE_MISMATCH")
            exposed_request_ref = self._commit_json(canonical_bytes(request))

            started_at = self._clock.now()
            started_ms = self._clock.monotonic_ms()
            try:
                self._current_selection.require_current(request)
                result = await adapter.invoke(request)
                result = self._checked_result(request, profile, result)
            except asyncio.CancelledError:
                result = self._failure_result(
                    request,
                    profile,
                    "CANCELLED",
                    _SAFE_FAILURES["CANCELLED"],
                    started_at,
                    started_ms,
                )
            except Exception as error:
                status, safe_error = _normalize_failure(error)
                result = self._failure_result(
                    request,
                    profile,
                    status,
                    safe_error,
                    started_at,
                    started_ms,
                )
            log = self._log(request, result, exposed_request_ref)
            log_ref = self._validator.record_invocation(request, result, log)
            if log_ref != reference(log):
                raise ValueError("INVOCATION_LOG_STAGE_MISMATCH")
            return PersistedLLMInvocation(request, result, log_ref)

        outcome, _claimed = await self._external.invoke_bound(
            str(work.work_id),
            decision_ref,
            reservation_ref,
            operation,
            idempotency_key=str(action.action_id),
        )
        return outcome

    def _resolve_authorized_inputs(
        self,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        call_spec_ref: StoredDataRef,
    ) -> tuple[LLMCallSpec, ProviderProfile, ActionRequest]:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        spec_value = self._records.get_exact(call_spec_ref)
        if (
            not isinstance(spec_value, LLMCallSpec)
            or reference(spec_value) != call_spec_ref
        ):
            raise ValueError("LLM_CALL_SPEC_EXACT_REF_REQUIRED")
        spec = spec_value
        profile_value = self._records.get_exact(spec.provider_profile_ref)
        if (
            not isinstance(profile_value, ProviderProfile)
            or reference(profile_value) != spec.provider_profile_ref
            or profile_value.support_status != "SUPPORTED"
            or profile_value.model != spec.model
            or profile_value.meta.analysis_id != work.meta.analysis_id
            or profile_value.meta.workspace_id != work.meta.workspace_id
            or profile_value.meta.commit_id != work.meta.commit_id
        ):
            raise ValueError("PROVIDER_PROFILE_EXACT_MATCH_REQUIRED")
        profile = profile_value
        payload_value = self._records.get_exact(spec.prompt_payload_ref)
        if (
            not isinstance(payload_value, PromptPayload)
            or reference(payload_value) != spec.prompt_payload_ref
        ):
            raise ValueError("PROMPT_PAYLOAD_EXACT_REF_REQUIRED")
        payload = payload_value
        if (
            spec.meta.attempt_id != work.active_attempt_id
            or payload.meta.attempt_id != work.active_attempt_id
        ):
            raise ValueError("INVOCATION_ATTEMPT_MISMATCH")
        run_state = self._run_states.current_state(str(work.meta.analysis_id))
        if (
            run_state.meta.analysis_id != work.meta.analysis_id
            or run_state.status != "RUNNING"
            or run_state.workspace_id != work.meta.workspace_id
            or run_state.commit_id != work.meta.commit_id
            or run_state.purpose != spec.purpose
            or run_state.purpose != payload.purpose
        ):
            raise ValueError("LLM_PURPOSE_OR_RUN_SCOPE_MISMATCH")
        if any(
            getattr(spec.meta, field) != getattr(work.meta, field)
            for field in ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        ):
            raise ValueError("INVOCATION_SCOPE_MISMATCH")
        decision_value = self._records.get_exact(decision_ref)
        if (
            not isinstance(decision_value, ActionDecision)
            or reference(decision_value) != decision_ref
            or decision_value.decision != Decision.ALLOW
            or decision_value.use_status != UseStatus.UNUSED
        ):
            raise ValueError("INVOCATION_ACTION_MISMATCH")
        action_value = self._records.get_exact(decision_value.action_ref)
        if (
            not isinstance(action_value, ActionRequest)
            or reference(action_value) != decision_value.action_ref
        ):
            raise ValueError("INVOCATION_ACTION_MISMATCH")
        action = action_value
        if not isinstance(action.meta, RecordMeta):
            raise ValueError("INVOCATION_ACTION_MISMATCH")
        action_meta = action.meta
        expected_inputs = llm_action_input_refs(call_spec_ref, spec, payload)
        if (
            action_meta.analysis_id != work.meta.analysis_id
            or action_meta.workspace_id != work.meta.workspace_id
            or action_meta.commit_id != work.meta.commit_id
            or action_meta.hypothesis_id != work.meta.hypothesis_id
            or action_meta.attempt_id != work.active_attempt_id
            or action.work_ref != reference(work)
            or action.expected_state_version != work.state_version
            or action.llm_call_spec_ref != call_spec_ref
            or action.provider_profile_ref != spec.provider_profile_ref
            or action.session_mode != spec.session_policy
            or tuple(action.input_refs) != expected_inputs
        ):
            raise ValueError("LLM_ACTION_INPUT_CLOSURE_MISMATCH")
        return spec, profile, action

    def _require_claimed_decision(
        self,
        original_ref: StoredDataRef,
        claimed_ref: StoredDataRef,
        action: ActionRequest,
    ) -> None:
        value = self._records.get_exact(claimed_ref)
        original = self._records.get_exact(original_ref)
        if (
            not isinstance(value, ActionDecision)
            or not isinstance(original, ActionDecision)
            or reference(value) != claimed_ref
            or value.meta.logical_record_id != original.meta.logical_record_id
            or value.meta.previous_record_id != original.meta.record_id
            or value.action_ref != reference(action)
            or value.decision != Decision.ALLOW
            or value.use_status != UseStatus.USED
        ):
            raise ValueError("INVOCATION_ACTION_MISMATCH")

    def _request(
        self,
        work: WorkExecutionState,
        claimed_ref: StoredDataRef,
        spec_ref: StoredDataRef,
        spec: LLMCallSpec,
    ) -> LLMInvocationRequest:
        assert isinstance(work.meta, RecordMeta)
        meta = self._metadata_factory(
            work.meta, "llm_invocation_request", work.active_attempt_id
        )
        request = LLMInvocationRequest.model_validate(
            spec.model_dump()
            | {
                "meta": meta,
                "action_decision_ref": claimed_ref,
                "call_spec_ref": spec_ref,
            }
        )
        if (
            request.meta.attempt_id != work.active_attempt_id
            or request.meta.analysis_id != work.meta.analysis_id
            or request.meta.workspace_id != work.meta.workspace_id
            or request.meta.commit_id != work.meta.commit_id
            or request.meta.hypothesis_id != work.meta.hypothesis_id
        ):
            raise ValueError("INVOCATION_REQUEST_SCOPE_MISMATCH")
        return request

    @staticmethod
    def _checked_result(
        request: LLMInvocationRequest,
        profile: ProviderProfile,
        result: LLMInvocationResult,
    ) -> LLMInvocationResult:
        validated = LLMInvocationResult.model_validate(result)
        expected_session_mode = (
            "NEW"
            if request.session_policy == "NEW"
            or (request.session_policy == "AUTO" and request.parent_session_ref is None)
            else "RESUMED"
        )
        fields = (
            "analysis_id",
            "workspace_id",
            "commit_id",
            "hypothesis_id",
            "attempt_id",
        )
        if (
            any(
                getattr(validated.meta, field) != getattr(request.meta, field)
                for field in fields
            )
            or validated.llm_call_id != request.llm_call_id
            or validated.purpose != request.purpose
            or validated.provider != profile.provider
            or validated.model != request.model
            or validated.actual_session_mode != expected_session_mode
            or (
                validated.status == "SUCCEEDED"
                and (
                    validated.parsed_output_ref is None
                    or validated.response_ref is None
                    or validated.safe_error is not None
                )
            )
            or (
                validated.status != "SUCCEEDED"
                and (
                    validated.parsed_output_ref is not None
                    or validated.response_ref is not None
                    or validated.safe_error is None
                )
            )
        ):
            raise ValueError("PROVIDER_RESULT_MISMATCH")
        return validated

    def _failure_result(
        self,
        request: LLMInvocationRequest,
        profile: ProviderProfile,
        status: InvocationStatus,
        safe_error: str,
        started_at: datetime,
        started_ms: int,
    ) -> LLMInvocationResult:
        return LLMInvocationResult.model_validate(
            {
                "meta": self._metadata_factory(
                    request.meta,
                    "llm_invocation_result",
                    request.meta.attempt_id,
                ),
                "llm_call_id": request.llm_call_id,
                "purpose": request.purpose,
                "status": status,
                "provider": profile.provider,
                "model": request.model,
                "actual_session_mode": (
                    "RESUMED" if request.session_policy == "RESUME" else "NEW"
                ),
                "session_ref": None,
                "response_ref": None,
                "parsed_output_ref": None,
                "usage": None,
                "started_at": started_at,
                "finished_at": self._clock.now(),
                "elapsed_ms": max(0, self._clock.monotonic_ms() - started_ms),
                "safe_error": safe_error,
            }
        )

    def _log(
        self,
        request: LLMInvocationRequest,
        result: LLMInvocationResult,
        exposed_request_ref: StoredDataRef,
    ) -> LLMInvocationLog:
        validation_errors = (
            ("Provider output did not pass validated output checks",)
            if result.status == "INVALID_OUTPUT"
            else ()
        )
        return LLMInvocationLog.model_validate(
            {
                "meta": self._metadata_factory(
                    request.meta, "llm_invocation_log", request.meta.attempt_id
                ),
                "llm_call_id": request.llm_call_id,
                "action_decision_ref": request.action_decision_ref,
                "call_spec_ref": request.call_spec_ref,
                "agent_role": request.agent_role,
                "task_kind": request.task_kind,
                "purpose": request.purpose,
                "provider_profile_ref": request.provider_profile_ref,
                "provider": result.provider,
                "model": result.model,
                "session_policy": request.session_policy,
                "session_ref": result.session_ref,
                "parent_session_ref": request.parent_session_ref,
                "prompt_registry_entry_ref": request.prompt_registry_entry_ref,
                "prompt_key": request.prompt_key,
                "prompt_template_ref": request.prompt_template_ref,
                "prompt_template_version": request.prompt_template_version,
                "prompt_payload_ref": request.prompt_payload_ref,
                "execution_limits_ref": request.execution_limits_ref,
                "retry_policy_ref": request.retry_policy_ref,
                "tool_policy_ref": request.tool_policy_ref,
                "redaction_policy_ref": request.redaction_policy_ref,
                "semantic_validator_ref": request.semantic_validator_ref,
                "output_schema_ref": request.output_schema_ref,
                "context_refs": request.context_refs,
                "retrieved_code_locations": (),
                "exposed_request_ref": exposed_request_ref,
                "exposed_response_ref": result.response_ref,
                "parsed_output_ref": result.parsed_output_ref,
                "tool_calls": (),
                "usage": result.usage,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "elapsed_ms": result.elapsed_ms,
                "retry_count": 0,
                "status": result.status,
                "safe_error": result.safe_error,
                "validation_errors": validation_errors,
                "repair_attempts": 0,
                "retry_of_llm_call_id": None,
                "failover_from_llm_call_id": None,
                "redaction_result": "APPLIED",
            }
        )

    def _commit_json(self, data: bytes) -> StoredDataRef:
        return self._artifacts.commit(
            self._artifacts.stage_bytes(data, "application/json")
        )


_SAFE_FAILURES: Mapping[InvocationStatus, str] = {
    "AUTH_REQUIRED": "AUTH_REQUIRED: provider authentication is required",
    "TIMED_OUT": "TIMED_OUT: provider request exceeded its deadline",
    "RATE_LIMITED": "RATE_LIMITED: provider rate limit was reached",
    "INVALID_OUTPUT": "INVALID_OUTPUT: provider returned invalid structured output",
    "CANCELLED": "CANCELLED: provider request was cancelled",
    "FAILED": "FAILED: provider request failed",
}


def _normalize_failure(error: Exception) -> tuple[InvocationStatus, str]:
    """Classify failures without copying potentially sensitive exception text."""
    name = type(error).__name__
    status_code = getattr(error, "status_code", None)
    status: InvocationStatus
    if name in {"CredentialUnavailableError", "AuthenticationError"}:
        status = "AUTH_REQUIRED"
    elif (
        isinstance(error, TimeoutError)
        or name == "APITimeoutError"
        or status_code == 408
    ):
        status = "TIMED_OUT"
    elif name == "RateLimitError" or status_code == 429:
        status = "RATE_LIMITED"
    elif name in {
        "ProviderInvalidOutputError",
        "APIResponseValidationError",
        "ValidationError",
    }:
        status = "INVALID_OUTPUT"
    else:
        status = "FAILED"
    return status, _SAFE_FAILURES[status]


__all__ = [
    "AnalysisRunStateResolver",
    "ExactAdapterResolver",
    "InvocationMetadataFactory",
    "LLMCurrentSelectionGuard",
    "LLMCallService",
    "PersistedLLMInvocation",
    "llm_action_input_refs",
]
