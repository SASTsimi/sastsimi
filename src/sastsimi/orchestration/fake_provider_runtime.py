"""Deterministic provider orchestration through the public runtime boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderProfile,
)
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.ports.dto import Record
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .fake_base import ProviderInvoker


@dataclass(frozen=True)
class FakeInvocation:
    request: LLMInvocationRequest
    result: LLMInvocationResult
    log: LLMInvocationLog


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
) -> tuple[Record, FakeInvocation]:
    """Invoke one configured fake call and return its not-yet-published output."""
    from sastsimi.contracts.work import WorkExecutionState

    if not isinstance(work, WorkExecutionState):
        raise TypeError("Fake provider requires a running work")
    spec = runtime.unit_of_work.records.get_exact(call_spec_ref)
    profile = runtime.unit_of_work.records.get_exact(provider_profile_ref)
    if not isinstance(spec, LLMCallSpec) or not isinstance(profile, ProviderProfile):
        raise ValueError("FAKE_PROVIDER_CONFIGURATION_MISMATCH")
    action = runner.action(
        work,
        identity,
        action_role.value,
        action_type,
        llm_call_spec_ref=call_spec_ref,
        provider_profile_ref=provider_profile_ref,
        session_mode="NEW",
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
        output_ref = runtime.unit_of_work.records.stage_record(output)
        if not isinstance(output_ref, StoredDataRef):
            raise ValueError("FAKE_PROVIDER_OUTPUT_SCOPE_MISMATCH")
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
                response_ref=artifact(f"response-{spec.llm_call_id}"),
                parsed_output_ref=output_ref,
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
            exposed_request_ref=artifact(f"request-{spec.llm_call_id}"),
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
    return output, FakeInvocation(request, result, log)


def persist_fake_invocation(
    runtime: RuntimeServices, invocation: FakeInvocation, output_ref: StoredDataRef
) -> StoredDataRef:
    return runtime.validator.record_invocation(
        invocation.request, invocation.result, invocation.log, output_ref
    )
