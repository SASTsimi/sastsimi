from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest

from sastsimi.agents.reporter import ReporterAgent, ReporterCallRefs
from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    RequesterRole,
)
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMCallSpec, OutputSchemaSpec, PromptPayload
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkType
from sastsimi.reporting.content_validation import validate_report_content
from tests.integration.providers.test_llm_call_service import (
    Fixture,
    LLMCallService,
    build_service,
    fixture,
    llm_action_input_refs,
)


def _reporter_call_fixture(
    *,
    raw_output: bytes | None = None,
    request_validators: dict[tuple[str, str], Callable[[object, object], None]]
    | None = None,
) -> tuple[Fixture, WorkExecutionState, StoredDataRef, StoredDataRef, LLMCallService]:
    data = fixture()
    data.raw_output = raw_output or canonical_bytes(
        {
            "title": "Validated finding",
            "summary": "The validated path is exploitable.",
            "details": "Static and dynamic evidence agree.",
            "recommendation": "Validate and constrain the input.",
            "citations": [],
        }
    )
    work = WorkExecutionState.model_validate(
        data.work.model_dump() | {"work_type": WorkType.REPORT_DRAFT}
    )
    work_ref = cast(StoredDataRef, data.records.publish(work))
    old_spec = data.records.get_exact(data.spec_ref)
    assert isinstance(old_spec, LLMCallSpec)
    old_schema = data.records.get_exact(old_spec.output_schema_ref)
    assert isinstance(old_schema, OutputSchemaSpec)
    schema = OutputSchemaSpec.model_validate(
        old_schema.model_dump() | {"result_kind": "report_draft"}
    )
    schema_ref = data.records.publish(schema)
    old_payload = data.records.get_exact(data.payload_ref)
    assert isinstance(old_payload, PromptPayload)
    payload = PromptPayload.model_validate(
        old_payload.model_dump()
        | {
            "agent_role": "REPORTER",
            "task_kind": "CREATE_DRAFT",
            "output_schema_ref": schema_ref,
        }
    )
    payload_ref = data.records.publish(payload)
    spec = LLMCallSpec.model_validate(
        old_spec.model_dump()
        | {
            "agent_role": "REPORTER",
            "task_kind": "CREATE_DRAFT",
            "prompt_payload_ref": payload_ref,
            "output_schema_ref": schema_ref,
        }
    )
    spec_ref = data.records.publish(spec)
    expected_inputs = llm_action_input_refs(spec_ref, spec, payload)
    old_decision = data.records.get_exact(data.decision_ref)
    old_claimed = data.records.get_exact(data.claimed_ref)
    assert isinstance(old_decision, ActionDecision)
    assert isinstance(old_claimed, ActionDecision)
    old_action = data.records.get_exact(old_decision.action_ref)
    assert isinstance(old_action, ActionRequest)
    action = ActionRequest.model_validate(
        old_action.model_dump()
        | {
            "requested_by": RequesterRole.REPORTER,
            "action_type": ActionType.CREATE_REPORT_DRAFT,
            "work_ref": work_ref,
            "llm_call_spec_ref": spec_ref,
            "input_refs": expected_inputs,
        }
    )
    action_ref = data.records.publish(action)
    required_checks = tuple(REQUIRED_CHECKS[ActionType.CREATE_REPORT_DRAFT])
    check_results = tuple(
        ActionCheck(
            check_type=check,
            result=CheckResult.PASS,
            reason_code="APPROVED",
            safe_message="Approved",
        )
        for check in required_checks
    )
    decision = ActionDecision.model_validate(
        old_decision.model_dump()
        | {
            "action_ref": action_ref,
            "required_checks": required_checks,
            "check_results": check_results,
            "checked_config_refs": tuple(
                item for item in expected_inputs if item.record_id is not None
            ),
        }
    )
    decision_ref = data.records.publish(decision)
    claimed = ActionDecision.model_validate(
        old_claimed.model_dump()
        | {
            "action_ref": action_ref,
            "required_checks": required_checks,
            "check_results": check_results,
            "checked_config_refs": decision.checked_config_refs,
        }
    )
    claimed_ref = data.records.publish(claimed)
    reservation = BudgetReservation.model_construct(
        meta=data.metadata_factory(
            data.work.meta, "budget_reservation", data.work.active_attempt_id
        ),
        reservation_id="reporter-reservation",
        budget_binding_ref=data.reservation_ref,
        action_ref=action_ref,
        work_ref=work_ref,
        requested_units=None,
        status="RESERVED",
        ledger_entry_ref=None,
        reserved_at=data.work.started_at,
        finalized_at=None,
    )
    reservation_ref = data.records.publish(reservation)
    data.work = work
    data.payload_ref = payload_ref
    data.spec_ref = spec_ref
    data.decision_ref = decision_ref
    data.claimed_ref = claimed_ref
    data.reservation_ref = reservation_ref
    service, _, _ = build_service(
        data, "SUCCEEDED", request_semantic_validators=request_validators
    )
    return data, work, spec_ref, decision_ref, service


@pytest.mark.asyncio
async def test_reporter_accepts_and_returns_the_claimed_used_decision() -> None:
    data, work, spec_ref, decision_ref, service = _reporter_call_fixture(
        request_validators={
            ("REPORTER", "CREATE_DRAFT"): lambda value, _request: (
                validate_report_content(value, allowed_locations=())
            )
        }
    )

    invocation = await service.invoke(
        work=work,
        decision_ref=decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=spec_ref,
    )
    for value in data.records.staged.values():
        data.records.publish(value)
    reporter = ReporterAgent(
        llm_calls=service,
        records=data.records,
        artifacts=data.artifacts,
        metadata_factory=data.metadata_factory,
        identity_ref=cast(
            ActionRequest,
            data.records.get_exact(
                cast(ActionDecision, data.records.get_exact(decision_ref)).action_ref
            ),
        ).requester_identity_ref,
    )
    request, result = invocation.request, invocation.result
    checks = {
        "result_status": result.status == "SUCCEEDED",
        "result_parsed": result.parsed_output_ref is not None,
        "result_response": result.response_ref == result.parsed_output_ref,
        "role": request.agent_role == "REPORTER"
        and request.task_kind == "CREATE_DRAFT",
        "session": request.session_policy == "NEW"
        and request.parent_session_ref is None,
        "call": request.call_spec_ref == spec_ref,
        "context": request.context_refs == work.input_refs,
        "call_id": request.llm_call_id == result.llm_call_id,
        "attempt": request.meta.attempt_id == work.active_attempt_id
        and result.meta.attempt_id == work.active_attempt_id,
        "scope": (
            request.meta.analysis_id,
            request.meta.workspace_id,
            request.meta.commit_id,
            request.meta.hypothesis_id,
        )
        == (
            work.meta.analysis_id,
            work.meta.workspace_id,
            work.meta.commit_id,
            work.meta.hypothesis_id,
        )
        and (
            result.meta.analysis_id,
            result.meta.workspace_id,
            result.meta.commit_id,
            result.meta.hypothesis_id,
        )
        == (
            work.meta.analysis_id,
            work.meta.workspace_id,
            work.meta.commit_id,
            work.meta.hypothesis_id,
        ),
    }
    assert all(checks.values()), checks
    content, used_ref, save_refs = reporter._content(
        invocation,
        work=work,
        call=ReporterCallRefs(decision_ref, data.reservation_ref, spec_ref),
    )

    assert content.title == "Validated finding"
    claimed_ref = data.claimed_ref
    claimed = data.records.get_exact(claimed_ref)
    assert isinstance(claimed, ActionDecision)
    assert used_ref == claimed_ref
    assert used_ref == invocation.request.action_decision_ref
    assert used_ref != decision_ref
    assert reference(claimed) == used_ref
    issued = cast(ActionDecision, data.records.get_exact(decision_ref))
    for required_ref in (
        decision_ref,
        issued.action_ref,
        data.reservation_ref,
        spec_ref,
        used_ref,
        reference(invocation.request),
        reference(invocation.result),
        invocation.log_ref,
        invocation.result.parsed_output_ref,
    ):
        assert required_ref in save_refs

    with pytest.raises(ValueError):
        reporter._content(
            invocation,
            work=work,
            call=ReporterCallRefs(claimed_ref, data.reservation_ref, spec_ref),
        )


@pytest.mark.asyncio
async def test_reporter_rejects_unsafe_provider_output_before_artifact_commit() -> None:
    unsafe = canonical_bytes(
        {
            "title": "Unsafe draft",
            "summary": "The finding is exploitable.",
            "details": "Static and dynamic evidence agree.",
            "recommendation": "Validate the input.",
            "citations": [
                {"file_path": "src/unsupported.py", "start_line": 1, "end_line": 1}
            ],
        }
    )
    data, work, spec_ref, decision_ref, service = _reporter_call_fixture(
        raw_output=unsafe,
        request_validators={
            ("REPORTER", "CREATE_DRAFT"): lambda value, _request: (
                validate_report_content(value, allowed_locations=())
            )
        },
    )
    invocation = await service.invoke(
        work=work,
        decision_ref=decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=spec_ref,
    )

    assert invocation.result.status == "INVALID_OUTPUT"
    assert invocation.result.parsed_output_ref is None
    assert unsafe not in data.artifacts.data.values()
