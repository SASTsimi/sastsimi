from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
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
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from tests.integration.providers.test_llm_call_service import (
    Fixture,
    build_service,
    fixture,
    llm_action_input_refs,
)


@dataclass(frozen=True)
class _ReporterCase:
    data: Fixture
    reporter: ReporterAgent
    invocation: PersistedLLMInvocation
    work: WorkExecutionState
    call: ReporterCallRefs
    decision_ref: StoredDataRef
    claimed_ref: StoredDataRef
    claimed: ActionDecision


def _validate_test_report(value: object, _request: object) -> None:
    validate_report_content(value, allowed_locations=())


async def _reporter_case(
    *,
    action_type: ActionType = ActionType.CREATE_REPORT_DRAFT,
    requested_by: RequesterRole = RequesterRole.VERIFICATION,
    raw_output: bytes | None = None,
    request_validators: dict[tuple[str, str], Callable[..., None]] | None = None,
) -> _ReporterCase:
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
            "requested_by": requested_by,
            "action_type": action_type,
            "work_ref": work_ref,
            "llm_call_spec_ref": spec_ref,
            "input_refs": expected_inputs,
        }
    )
    action_ref = data.records.publish(action)
    required_checks = tuple(REQUIRED_CHECKS[action_type])
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
        data,
        "SUCCEEDED",
        request_semantic_validators=request_validators
        or {("REPORTER", "CREATE_DRAFT"): _validate_test_report},
    )
    invocation = await service.invoke(
        work=work,
        decision_ref=decision_ref,
        reservation_ref=reservation_ref,
        call_spec_ref=spec_ref,
    )
    for value in data.records.staged.values():
        data.records.publish(value)
    reporter = ReporterAgent(
        llm_calls=service,
        records=data.records,
        artifacts=data.artifacts,
        metadata_factory=data.metadata_factory,
        owner_resolver=lambda _work: action.requester_identity_ref,
    )
    return _ReporterCase(
        data=data,
        reporter=reporter,
        invocation=invocation,
        work=work,
        call=ReporterCallRefs(decision_ref, reservation_ref, spec_ref),
        decision_ref=decision_ref,
        claimed_ref=claimed_ref,
        claimed=claimed,
    )


@pytest.mark.asyncio
async def test_reporter_accepts_verification_owned_create_draft_decision() -> None:
    case = await _reporter_case()

    content, used_ref, save_refs = case.reporter._content(
        case.invocation,
        work=case.work,
        call=case.call,
    )

    assert content.title == "Validated finding"
    assert used_ref == case.claimed_ref
    assert used_ref == case.invocation.request.action_decision_ref
    assert used_ref != case.decision_ref
    assert reference(case.claimed) == used_ref
    issued = cast(ActionDecision, case.data.records.get_exact(case.decision_ref))
    for required_ref in (
        case.decision_ref,
        issued.action_ref,
        case.call.reservation_ref,
        case.call.call_spec_ref,
        used_ref,
        reference(case.invocation.request),
        reference(case.invocation.result),
        case.invocation.log_ref,
        case.invocation.result.parsed_output_ref,
    ):
        assert required_ref in save_refs

    with pytest.raises(ValueError):
        case.reporter._content(
            case.invocation,
            work=case.work,
            call=ReporterCallRefs(
                case.claimed_ref,
                case.call.reservation_ref,
                case.call.call_spec_ref,
            ),
        )


@pytest.mark.asyncio
async def test_reporter_rejects_generic_call_llm_decision() -> None:
    case = await _reporter_case(
        action_type=ActionType.CALL_LLM,
        requested_by=RequesterRole.REPORTER,
    )

    with pytest.raises(ValueError, match="LLM_INVOCATION_PROVENANCE_MISMATCH"):
        case.reporter._content(
            case.invocation,
            work=case.work,
            call=case.call,
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
                {
                    "file_path": "src/unsupported.py",
                    "start_line": 1,
                    "end_line": 1,
                }
            ],
        }
    )
    case = await _reporter_case(raw_output=unsafe)

    assert case.invocation.result.status == "INVALID_OUTPUT"
    assert case.invocation.result.parsed_output_ref is None
    assert unsafe not in case.data.artifacts.data.values()
