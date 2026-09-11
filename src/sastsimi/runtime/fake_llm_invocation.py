"""Deterministic provider orchestration through the public runtime boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from pydantic import BaseModel

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    PromptPayload,
    ProviderProfile,
)
from sastsimi.contracts.llm_closure import llm_action_input_refs
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.ports.dto import Record
from sastsimi.ports.fake_workflow import ProviderInvoker
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner


@dataclass(frozen=True)
class FakeInvocation:
    request: LLMInvocationRequest
    result: LLMInvocationResult
    log: LLMInvocationLog
    output: Record


def invoke_fake_provider(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    work: object,
    scope: StoredDataRef,
    identity: BudgetScopeRef,
    action_role: RequesterRole,
    action_type: str,
    call_spec_ref: StoredDataRef,
    provider_profile_ref: StoredDataRef,
    artifact: Callable[[str], StoredDataRef],
    build_output: Callable[[StoredDataRef], Record],
    provider_invoke: ProviderInvoker,
    bind_request: Callable[[Record, StoredDataRef], Record] | None = None,
) -> tuple[Record, FakeInvocation]:
    """Invoke one configured fake call and return its not-yet-published output."""
    from sastsimi.contracts.work import WorkExecutionState

    if not isinstance(work, WorkExecutionState):
        raise TypeError("Fake provider requires a running work")
    spec = runtime.unit_of_work.records.get_exact(call_spec_ref)
    profile = runtime.unit_of_work.records.get_exact(provider_profile_ref)
    if not isinstance(spec, LLMCallSpec) or not isinstance(profile, ProviderProfile):
        raise ValueError("FAKE_PROVIDER_CONFIGURATION_MISMATCH")
    prompt_payload = runtime.unit_of_work.records.get_exact(spec.prompt_payload_ref)
    if not isinstance(prompt_payload, PromptPayload):
        raise ValueError("FAKE_PROVIDER_CONFIGURATION_MISMATCH")
    action_inputs = llm_action_input_refs(call_spec_ref, spec, prompt_payload)
    action = runner.action(
        work,
        identity,
        action_role.value,
        action_type,
        llm_call_spec_ref=call_spec_ref,
        provider_profile_ref=provider_profile_ref,
        session_mode="NEW",
        input_refs=action_inputs,
    )
    units = runner.units(elapsed_ms=1, llm_call_count=1, cost_minor_units=1)
    reservation = runner.reserve(work, scope, action, units)
    decision = runner.authorize(work, action, reservation)

    async def operation(
        claimed_ref: object,
    ) -> tuple[Record, LLMInvocationRequest, LLMInvocationResult]:
        if not isinstance(claimed_ref, StoredDataRef):
            raise ValueError("FAKE_PROVIDER_DECISION_SCOPE_MISMATCH")
        output = build_output(claimed_ref)
        request = LLMInvocationRequest.model_validate(
            spec.model_dump()
            | dict(
                meta=runner.metadata(
                    work.meta,
                    "llm_invocation_request",
                    attempt_id=work.active_attempt_id,
                ),
                action_decision_ref=claimed_ref,
                call_spec_ref=call_spec_ref,
            )
        )
        request_ref = reference(request)
        if not isinstance(request_ref, StoredDataRef):
            raise ValueError("FAKE_PROVIDER_REQUEST_SCOPE_MISMATCH")
        if bind_request is not None:
            output = bind_request(output, request_ref)
        if isinstance(output, BaseModel) and "llm_call_id" in type(output).model_fields:
            output = cast(
                Record,
                output.model_copy(update={"llm_call_id": spec.llm_call_id}),
            )
        response_ref = _artifact_bytes(runtime, canonical_bytes(output))
        result = LLMInvocationResult.model_validate(
            dict(
                meta=runner.metadata(
                    work.meta,
                    "llm_invocation_result",
                    attempt_id=work.active_attempt_id,
                ),
                llm_call_id=spec.llm_call_id,
                purpose=spec.purpose,
                status="SUCCEEDED",
                provider=profile.provider,
                model=profile.model,
                actual_session_mode="NEW",
                session_ref=f"fake-session-{spec.llm_call_id}",
                response_ref=response_ref,
                parsed_output_ref=reference(output),
                usage=dict(
                    token_source="PROVIDER_REPORTED",
                    input_tokens=1,
                    output_tokens=1,
                    total_tokens=2,
                    token_unavailable_reason=None,
                    provider_units={"requests": 1},
                    cost_source="UNAVAILABLE",
                    cost_minor_units=None,
                    currency=None,
                    pricing_revision_ref=None,
                    cost_unavailable_reason="Deterministic fake has no price",
                ),
                started_at=runner.clock.now(),
                finished_at=runner.clock.now(),
                elapsed_ms=1,
                safe_error=None,
            )
        )
        returned = await provider_invoke(request, result)
        if (
            returned.status != "SUCCEEDED"
            or returned.safe_error is not None
            or returned.parsed_output_ref != reference(output)
            or returned.response_ref != response_ref
            or returned.llm_call_id != spec.llm_call_id
            or returned.purpose != spec.purpose
            or returned.provider != profile.provider
            or returned.model != profile.model
            or returned.actual_session_mode != "NEW"
            or returned.session_ref != f"fake-session-{spec.llm_call_id}"
            or returned.usage is None
        ):
            raise ValueError("FAKE_PROVIDER_OUTPUT_MISMATCH")
        return output, request, returned

    payload, _claimed = asyncio.run(
        runtime.external.invoke_bound(
            str(work.work_id),
            decision,
            reference(reservation),
            operation,
            idempotency_key=str(action.action_id),
        )
    )
    output, request, result = payload
    runner.account(reservation, units)
    request_bytes_ref = _artifact_bytes(runtime, canonical_bytes(request))
    log = LLMInvocationLog.model_validate(
        dict(
            meta=runner.metadata(
                work.meta, "llm_invocation_log", attempt_id=work.active_attempt_id
            ),
            llm_call_id=spec.llm_call_id,
            action_decision_ref=request.action_decision_ref,
            call_spec_ref=call_spec_ref,
            agent_role=spec.agent_role,
            task_kind=spec.task_kind,
            purpose=spec.purpose,
            provider_profile_ref=provider_profile_ref,
            provider=profile.provider,
            model=profile.model,
            session_policy=spec.session_policy,
            session_ref=result.session_ref,
            parent_session_ref=spec.parent_session_ref,
            prompt_registry_entry_ref=spec.prompt_registry_entry_ref,
            prompt_key=spec.prompt_key,
            prompt_template_ref=spec.prompt_template_ref,
            prompt_template_version=spec.prompt_template_version,
            prompt_payload_ref=spec.prompt_payload_ref,
            execution_limits_ref=spec.execution_limits_ref,
            retry_policy_ref=spec.retry_policy_ref,
            tool_policy_ref=spec.tool_policy_ref,
            redaction_policy_ref=spec.redaction_policy_ref,
            semantic_validator_ref=spec.semantic_validator_ref,
            output_schema_ref=spec.output_schema_ref,
            context_refs=spec.context_refs,
            retrieved_code_locations=(),
            exposed_request_ref=request_bytes_ref,
            exposed_response_ref=result.response_ref,
            parsed_output_ref=result.parsed_output_ref,
            tool_calls=(),
            usage=result.usage,
            started_at=result.started_at,
            finished_at=result.finished_at,
            elapsed_ms=result.elapsed_ms,
            retry_count=0,
            status=result.status,
            safe_error=result.safe_error,
            validation_errors=(),
            repair_attempts=0,
            retry_of_llm_call_id=None,
            failover_from_llm_call_id=None,
            redaction_result="APPLIED",
        )
    )
    return output, FakeInvocation(request, result, log, output)


def _artifact_bytes(runtime: RuntimeServices, data: bytes) -> StoredDataRef:
    staged = runtime.unit_of_work.artifacts.stage_bytes(data, "application/json")
    return runtime.unit_of_work.artifacts.commit(staged)


def persist_fake_invocation(
    runtime: RuntimeServices, invocation: FakeInvocation
) -> StoredDataRef:
    """Commit complete call provenance before any domain candidate is published."""
    candidate_ref = runtime.unit_of_work.records.stage_record(invocation.output)
    if candidate_ref != invocation.result.parsed_output_ref:
        raise ValueError("INVOCATION_OUTPUT_MISMATCH")
    return runtime.validator.record_invocation(
        invocation.request, invocation.result, invocation.log
    )
