from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import pytest

from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    Decision,
    RequesterRole,
    SessionMode,
    UseStatus,
)
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.dto import Record
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.verification.completion import VerificationCompletionCoordinator
from tests.integration.verification.test_verification_service import (
    ATTEMPT_ID,
    HYPOTHESIS_ID,
    _Fixture,
    _meta,
)


@dataclass
class _RecordingRunner(WorkflowRunner):
    calls: list[dict[str, Any]] = field(default_factory=list)

    def complete(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        outputs: tuple[Record, ...],
        *,
        status: str = "SUCCEEDED",
        cause: str = "COMPLETED",
        error_ids: tuple[str, ...] = (),
        gap_ids: tuple[str, ...] = (),
        action_input_refs: tuple[RecordRef, ...] | None = None,
    ) -> WorkExecutionState:
        assert status == "SUCCEEDED"
        assert cause == "COMPLETED"
        assert error_ids == ()
        assert gap_ids == ()
        assert action_input_refs is not None
        self.calls.append(
            {
                "work": work,
                "identity": identity,
                "role": role,
                "outputs": outputs,
                "action_input_refs": action_input_refs,
            }
        )
        output_ref = reference(outputs[0])
        assert isinstance(output_ref, StoredDataRef)
        return work.model_copy(
            update={
                "status": WorkStatus.SUCCEEDED,
                "active_attempt_id": None,
                "output_refs": (output_ref,),
            }
        )


def _process(
    fixture: _Fixture,
    request: DynamicReproductionRequest,
    *,
    generation: int = 1,
) -> HypothesisProcessState:
    return HypothesisProcessState.model_construct(
        meta=_meta("hypothesis_process_state", suffix="process", attempt=None),
        proposal_ref=fixture.proposal_ref,
        status="VERIFYING",
        verification_assignment_ref=request.verification_assignment_ref,
        verification_generation=generation,
        verification_work_ref=reference(fixture.work),
        verification_result_ref=None,
        started_at=fixture.work.meta.created_at,
        finished_at=None,
        elapsed_ms=0,
    )


def _persist_final_invocation(
    fixture: _Fixture,
    *,
    claimed_variant: str = "valid",
) -> PersistedLLMInvocation:
    invocation = fixture.llm.outcomes[0]
    provider_ref = fixture._opaque_record("provider_profile", "final-provider")
    action = ActionRequest.model_validate(
        {
            "meta": _meta("action_request", suffix="final-action", attempt=ATTEMPT_ID),
            "action_id": "final-action",
            "requested_by": RequesterRole.VERIFICATION,
            "requester_identity_ref": fixture._opaque_record(
                "agent_identity", "verification"
            ),
            "action_type": ActionType.CALL_LLM,
            "work_ref": reference(fixture.work),
            "expected_state_version": fixture.work.state_version,
            "expected_verification_generation": None,
            "generation_restart_reason": None,
            "generation_restart_basis_refs": (),
            "input_refs": (),
            "dynamic_request_ref": None,
            "reproduction_plan_ref": None,
            "result_kind": None,
            "candidate_result_ref": None,
            "llm_call_spec_ref": invocation.request.call_spec_ref,
            "tool_name": None,
            "file_paths": (),
            "provider_profile_ref": provider_ref,
            "session_mode": SessionMode.NEW,
            "sandbox_profile_ref": None,
            "resource_profile_ref": None,
            "run_policy_state_ref": None,
            "image_digest": None,
            "network_targets": (),
            "resource_limits": None,
            "reason": "Authorize the exact final verdict call",
            "requested_at": fixture.work.meta.created_at,
        }
    )
    action_ref = fixture.records.add(action)
    required_checks = tuple(REQUIRED_CHECKS[ActionType.CALL_LLM])
    issued = ActionDecision.model_validate(
        {
            "meta": _meta("action_decision", suffix="final-issued", attempt=ATTEMPT_ID),
            "decision_id": "final-decision",
            "action_ref": action_ref,
            "decision": Decision.ALLOW,
            "required_checks": required_checks,
            "check_results": tuple(
                ActionCheck(
                    check_type=check,
                    result=CheckResult.PASS,
                    reason_code="APPROVED",
                    safe_message="Approved",
                )
                for check in required_checks
            ),
            "checked_state_version": fixture.work.state_version,
            "checked_config_refs": (),
            "valid_until": fixture.work.meta.created_at + timedelta(hours=1),
            "error_ids": (),
            "use_status": UseStatus.UNUSED,
            "used_at": None,
            "expired_at": None,
            "expire_reason": None,
            "outcome_refs": (),
            "decided_at": fixture.work.meta.created_at,
        }
    )
    issued_ref = fixture.records.add(issued)
    claimed_meta = RecordMeta.model_validate(
        _meta(
            "action_decision", suffix="final-claimed", attempt=ATTEMPT_ID
        ).model_dump()
        | {
            "logical_record_id": issued.meta.logical_record_id,
            "revision_number": 2,
            "previous_record_id": issued.meta.record_id,
        }
    )
    claimed = ActionDecision.model_validate(
        issued.model_dump()
        | {
            "meta": claimed_meta,
            "use_status": UseStatus.USED,
            "used_at": fixture.work.meta.created_at,
        }
    )
    claimed_ref = fixture.records.add(claimed)
    if claimed_variant == "reused":
        reused_meta = RecordMeta.model_validate(
            _meta(
                "action_decision", suffix="final-reused", attempt=ATTEMPT_ID
            ).model_dump()
            | {
                "logical_record_id": issued.meta.logical_record_id,
                "revision_number": 3,
                "previous_record_id": claimed.meta.record_id,
            }
        )
        reused = ActionDecision.model_validate(
            claimed.model_dump()
            | {
                "meta": reused_meta,
                "outcome_refs": (fixture._opaque_record("artifact", "prior-output"),),
            }
        )
        claimed_ref = fixture.records.add(reused)
    elif claimed_variant == "unrelated":
        unrelated_issued_meta = _meta(
            "action_decision", suffix="other-issued", attempt=ATTEMPT_ID
        )
        unrelated_claimed_meta = RecordMeta.model_validate(
            _meta(
                "action_decision", suffix="other-claimed", attempt=ATTEMPT_ID
            ).model_dump()
            | {
                "logical_record_id": unrelated_issued_meta.logical_record_id,
                "revision_number": 2,
                "previous_record_id": unrelated_issued_meta.record_id,
            }
        )
        unrelated = ActionDecision.model_validate(
            claimed.model_dump()
            | {
                "meta": unrelated_claimed_meta,
                "decision_id": "other-decision",
            }
        )
        claimed_ref = fixture.records.add(unrelated)
    request = LLMInvocationRequest.model_construct(
        **(
            invocation.request.__dict__
            | {
                "action_decision_ref": claimed_ref,
                "provider_profile_ref": provider_ref,
                "model": "fake-model",
                "session_policy": "NEW",
                "parent_session_ref": None,
                "prompt_registry_entry_ref": fixture._opaque_record(
                    "prompt_registry_entry", "final-registry"
                ),
                "prompt_key": "verification.final",
                "prompt_template_ref": fixture._opaque_record(
                    "prompt_template", "final-template"
                ),
                "prompt_template_version": "1",
                "prompt_payload_ref": fixture._opaque_record(
                    "prompt_payload", "final-payload"
                ),
                "execution_limits_ref": fixture._opaque_record(
                    "execution_limits", "final-limits"
                ),
                "retry_policy_ref": fixture._opaque_record(
                    "retry_policy", "final-retry"
                ),
                "tool_policy_ref": fixture._opaque_record("tool_policy", "final-tool"),
                "redaction_policy_ref": fixture._opaque_record(
                    "redaction_policy", "final-redaction"
                ),
                "semantic_validator_ref": fixture._opaque_record(
                    "semantic_validator_spec", "final-validator"
                ),
                "output_schema_ref": fixture._opaque_record(
                    "output_schema", "final-schema"
                ),
                "output_schema": "verification-result",
                "token_budget": 100,
                "timeout_ms": 1_000,
            }
        )
    )
    result = LLMInvocationResult.model_construct(
        **invocation.result.__dict__,
        provider="fake",
        model="fake-model",
        actual_session_mode="NEW",
        session_ref="session-final",
        started_at=fixture.work.meta.created_at,
        finished_at=fixture.work.meta.created_at,
        safe_error=None,
    )
    request_ref = fixture.records.add(request)
    result_ref = fixture.records.add(result)
    log = LLMInvocationLog.model_construct(
        meta=_meta("llm_invocation_log", suffix="final-log", attempt=ATTEMPT_ID),
        llm_call_id=request.llm_call_id,
        action_decision_ref=request.action_decision_ref,
        call_spec_ref=request.call_spec_ref,
        agent_role="VERIFICATION",
        task_kind="FINAL_VERDICT",
        purpose="PRODUCTION",
        provider_profile_ref=request.provider_profile_ref,
        provider="fake",
        model="fake-model",
        session_policy="NEW",
        session_ref="session-final",
        parent_session_ref=None,
        prompt_registry_entry_ref=request.prompt_registry_entry_ref,
        prompt_key=request.prompt_key,
        prompt_template_ref=request.prompt_template_ref,
        prompt_template_version=request.prompt_template_version,
        prompt_payload_ref=request.prompt_payload_ref,
        execution_limits_ref=request.execution_limits_ref,
        retry_policy_ref=request.retry_policy_ref,
        tool_policy_ref=request.tool_policy_ref,
        redaction_policy_ref=request.redaction_policy_ref,
        semantic_validator_ref=request.semantic_validator_ref,
        output_schema_ref=request.output_schema_ref,
        context_refs=request.context_refs,
        retrieved_code_locations=(),
        exposed_request_ref=result.parsed_output_ref,
        exposed_response_ref=result.parsed_output_ref,
        parsed_output_ref=result.parsed_output_ref,
        tool_calls=(),
        usage=None,
        started_at=fixture.work.meta.created_at,
        finished_at=fixture.work.meta.created_at,
        elapsed_ms=3,
        retry_count=0,
        status="SUCCEEDED",
        safe_error=None,
        validation_errors=(),
        repair_attempts=0,
        retry_of_llm_call_id=None,
        failover_from_llm_call_id=None,
        redaction_result="NOT_REQUIRED",
    )
    log_ref = fixture.records.add(log)
    persisted = PersistedLLMInvocation(
        request,
        result,
        log_ref,
        dispatch_state="RETURNED",
    )
    fixture.llm.outcomes[0] = persisted
    fixture.call = fixture.call.__class__(
        decision_ref=issued_ref,
        reservation_ref=fixture.call.reservation_ref,
        call_spec_ref=fixture.call.call_spec_ref,
    )
    assert fixture.records.get_exact(request_ref) == request
    assert fixture.records.get_exact(result_ref) == result
    return persisted


async def _ready_fixture() -> tuple[
    _Fixture,
    StoredDataRef,
    dict[str, StoredDataRef],
    DynamicReproductionRequest,
]:
    fixture = _Fixture()
    fixture.work = fixture.work.model_copy(
        update={
            "parent_work_ref": None,
            "subject_type": "HYPOTHESIS",
            "subject_id": HYPOTHESIS_ID,
            "state_version": 1,
            "last_transition_ref": None,
            "last_transition_commit_ref": None,
            "input_hash": "a" * 64,
            "dedupe_key": "b" * 64,
            "trigger_primitive_ref": None,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": fixture.work.meta.created_at,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    fixture.queue(
        fixture.assessment_payload("TRUE", next_step="POC_CONFIRMATION"),
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
    )
    assessment = await fixture.service.assess_initial(
        generation=fixture.generation,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )
    assessment_ref = reference(assessment)
    assert isinstance(assessment_ref, StoredDataRef)
    dynamic = fixture.install_dynamic_success()
    request = fixture.records.get_exact(dynamic["request"])
    assert isinstance(request, DynamicReproductionRequest)
    return fixture, assessment_ref, dynamic, request


@pytest.mark.asyncio
async def test_completion_publishes_exact_dynamic_verdict_with_invocation_chain() -> (
    None
):
    fixture, assessment_ref, dynamic, request = await _ready_fixture()
    fixture.queue(
        fixture.final_payload("TRUE", outcome="NOT_DISPROVED"),
        task_kind="FINAL_VERDICT",
        context_refs=fixture.dynamic_context(assessment_ref, dynamic),
    )
    invocation = _persist_final_invocation(fixture)
    runner = _RecordingRunner()
    owner = fixture._opaque_record("verification_assignment", "owner")
    coordinator = VerificationCompletionCoordinator(
        verification=fixture.service,
        runner=runner,
        records=fixture.records,
        work_resolver=lambda _: fixture.work,
        current_process=lambda _: _process(fixture, request),
        verification_identity_ref=owner,
    )

    completed = await coordinator.complete_dynamic(
        generation=fixture.generation,
        assessment_ref=assessment_ref,
        dynamic_request_ref=dynamic["request"],
        dynamic_result_ref=dynamic["result"],
        poc_ref=dynamic["poc"],
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )

    assert completed.outcome.record.verdict == "TRUE"
    assert completed.completed_work.status == "SUCCEEDED"
    assert len(runner.calls) == 1
    call = runner.calls[0]
    result_ref = reference(completed.outcome.record)
    request_ref = reference(invocation.request)
    invocation_result_ref = reference(invocation.result)
    assert call["outputs"] == (completed.outcome.record,)
    assert call["role"] == "VERIFICATION"
    assert len(call["action_input_refs"]) == len(set(call["action_input_refs"]))
    assert set(call["action_input_refs"]) == {
        *fixture.work.input_refs,
        fixture.generation.hypothesis_ref,
        fixture.generation.policy_ref,
        fixture.generation.playbook_ref,
        fixture.generation.application_ref,
        fixture.generation.evidence_ref,
        assessment_ref,
        dynamic["request"],
        dynamic["result"],
        dynamic["poc"],
        fixture.pro_ref,
        fixture.con_ref,
        fixture.call.decision_ref,
        invocation.request.action_decision_ref,
        fixture.call.reservation_ref,
        fixture.call.call_spec_ref,
        request_ref,
        invocation_result_ref,
        invocation.log_ref,
        invocation.result.parsed_output_ref,
    }
    assert completed.completed_work.output_refs == (result_ref,)


@pytest.mark.asyncio
@pytest.mark.parametrize("claimed_variant", ["reused", "unrelated"])
async def test_completion_rejects_non_fresh_or_unrelated_claimed_decision(
    claimed_variant: str,
) -> None:
    fixture, assessment_ref, dynamic, request = await _ready_fixture()
    fixture.queue(
        fixture.final_payload("TRUE", outcome="NOT_DISPROVED"),
        task_kind="FINAL_VERDICT",
        context_refs=fixture.dynamic_context(assessment_ref, dynamic),
    )
    _persist_final_invocation(fixture, claimed_variant=claimed_variant)
    runner = _RecordingRunner()
    coordinator = VerificationCompletionCoordinator(
        verification=fixture.service,
        runner=runner,
        records=fixture.records,
        work_resolver=lambda _: fixture.work,
        current_process=lambda _: _process(fixture, request),
        verification_identity_ref=fixture._opaque_record(
            "verification_assignment", "owner"
        ),
    )

    with pytest.raises(ValueError, match="VERIFICATION_INVOCATION_PROVENANCE_MISMATCH"):
        await coordinator.complete_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic["request"],
            dynamic_result_ref=dynamic["result"],
            poc_ref=dynamic["poc"],
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )

    assert runner.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["BLOCKED", "FAILED", "CANCELLED"])
async def test_operational_dynamic_status_creates_no_verdict(
    status: str,
) -> None:
    fixture, assessment_ref, dynamic, request = await _ready_fixture()
    successful = fixture.records.get_exact(dynamic["result"])
    assert isinstance(successful, DynamicReproductionResult)
    failed = successful.model_copy(
        update={
            "meta": _meta(
                "dynamic_reproduction_result",
                suffix=status.lower(),
                attempt=successful.meta.attempt_id,
            ),
            "status": status,
            "failure_category": "EXECUTION",
            "failure_reason": "Sandbox execution did not complete",
            "hypothesis_outcome": "INCONCLUSIVE",
            "poc_ref": None,
        }
    )
    failed_ref = fixture.records.add(failed)
    runner = _RecordingRunner()
    coordinator = VerificationCompletionCoordinator(
        verification=fixture.service,
        runner=runner,
        records=fixture.records,
        work_resolver=lambda _: fixture.work,
        current_process=lambda _: _process(fixture, request),
        verification_identity_ref=fixture._opaque_record(
            "verification_assignment", "owner"
        ),
    )

    with pytest.raises(ValueError, match="EXECUTION_FAILURE_IS_NOT_VERDICT"):
        await coordinator.complete_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic["request"],
            dynamic_result_ref=failed_ref,
            poc_ref=None,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )

    assert runner.calls == []
    assert not any(
        ref.data_kind == "verification_result" for ref in fixture.records.values
    )


@pytest.mark.asyncio
async def test_stale_process_generation_is_rejected_before_finalization() -> None:
    fixture, assessment_ref, dynamic, request = await _ready_fixture()
    runner = _RecordingRunner()
    coordinator = VerificationCompletionCoordinator(
        verification=fixture.service,
        runner=runner,
        records=fixture.records,
        work_resolver=lambda _: fixture.work,
        current_process=lambda _: _process(fixture, request, generation=2),
        verification_identity_ref=fixture._opaque_record(
            "verification_assignment", "owner"
        ),
    )

    with pytest.raises(ValueError, match="STALE_RESULT"):
        await coordinator.complete_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic["request"],
            dynamic_result_ref=dynamic["result"],
            poc_ref=dynamic["poc"],
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )

    assert runner.calls == []
    assert fixture.llm.outcomes == []
    assert not any(
        ref.data_kind == "verification_result" for ref in fixture.records.values
    )
