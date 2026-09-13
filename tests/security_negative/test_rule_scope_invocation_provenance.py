from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from io import BytesIO
from typing import cast

import pytest

from sastsimi.agents.rule_scope_gate import (
    RuleScopeCallRefs,
    RuleScopeEvidenceSelection,
    RuleScopeGateAgent,
    RuleScopeProposal,
)
from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionDecision,
    ActionRequest,
)
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.gates import RuleScopeImpactReview
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMToolPolicy,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record
from sastsimi.reporting.rule_scope_gate_handler import WorkflowRuleScopePublisher
from sastsimi.reporting.rule_scope_gate_workflow import RuleScopeExecution
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.llm_invocation_provenance import (
    validate_llm_invocation_provenance,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref, wire

NOW = datetime(2026, 9, 12, tzinfo=UTC)


def _meta(
    kind: str,
    record_id: str,
    *,
    attempt: str = "at-gate",
    logical_id: str | None = None,
    revision: int = 1,
    previous: str | None = None,
) -> RecordMeta:
    return RecordMeta.model_validate(
        meta(kind, hypothesis="h1", attempt=attempt)
        | {
            "record_id": record_id,
            "logical_record_id": logical_id or f"{record_id}-logical",
            "revision_number": revision,
            "previous_record_id": previous,
            "created_at": NOW,
        }
    )


class _Records:
    def __init__(self) -> None:
        self.values: dict[RecordRef, object] = {}

    def add(self, value: Record) -> StoredDataRef:
        value_ref = reference(value)
        assert isinstance(value_ref, StoredDataRef)
        self.values[value_ref] = value
        return value_ref

    def get_exact(self, value_ref: RecordRef) -> object:
        return self.values[value_ref]


class _Artifacts:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def add(self, value: object) -> StoredDataRef:
        raw = canonical_bytes(value)
        digest = content_hash(value)
        self.values[digest] = raw
        return StoredDataRef.model_validate(
            {
                "stored_data_id": digest,
                "data_kind": "artifact",
                "record_id": None,
                "content_hash": digest,
                "workspace_id": "ws1",
                "commit_id": "c1",
            }
        )

    def open_verified(self, value_ref: StoredDataRef) -> BytesIO:
        return BytesIO(self.values[value_ref.content_hash])


class _LLM:
    def __init__(self, invocation: PersistedLLMInvocation) -> None:
        self.invocation = invocation

    async def invoke(self, **_kwargs: object) -> PersistedLLMInvocation:
        return self.invocation


def _closure() -> tuple[
    WorkExecutionState,
    RuleScopeCallRefs,
    StoredDataRef,
    tuple[StoredDataRef, ...],
    RuleScopeProposal,
    PersistedLLMInvocation,
    _Records,
    _Artifacts,
]:
    records = _Records()
    artifacts = _Artifacts()
    tool = wire(
        LLMToolPolicy,
        make("LLMToolPolicy", "llm_tool_policy")
        | {
            "meta": meta("llm_tool_policy", hypothesis="h1", attempt="at-gate"),
            "policy_key": "tools.none.v1",
            "allowed_tools": [],
            "forbidden_actions": ["ALL"],
        },
    )
    tool_ref = records.add(tool)
    context = (tool_ref,)
    proposal = RuleScopeProposal(
        rule_compliance="PASS",
        scope_compliance="PASS",
        testing_restriction_compliance="PASS",
        security_impact="SUFFICIENT",
        report_permission="ALLOW",
        evidence_links=(
            RuleScopeEvidenceSelection(
                area="RULE", policy_item_ids=("rule-1",), evidence_indexes=(0,)
            ),
        ),
        reasons=("The exact current policy supports reporting.",),
        missing_information=(),
    )
    output_ref = artifacts.add(proposal)
    work = wire(
        WorkExecutionState,
        make("WorkExecutionState")
        | {
            "meta": meta("work_execution_state", hypothesis="h1", attempt=None),
            "work_type": "RULE_SCOPE_GATE",
            "subject_type": "HYPOTHESIS",
            "subject_id": "h1",
            "status": "RUNNING",
            "state_version": 3,
            "last_transition_ref": ref("state_transition"),
            "last_transition_commit_ref": ref("transition_commit"),
            "active_attempt_id": "at-gate",
            "input_refs": [item.model_dump(mode="json") for item in context],
            "work_generation": 1,
            "dedupe_key": "d" * 64,
            "started_at": NOW.isoformat(),
        },
    )
    work_ref = cast(StoredDataRef, reference(work))
    owner_ref = StoredDataRef.model_validate(ref("agent_identity"))
    spec = LLMCallSpec.model_construct(
        meta=_meta("llm_call_spec", "rule-scope-spec-r1"),
        llm_call_id="rule-scope-call-1",
        agent_role="RULE_SCOPE_GATE",
        task_kind="REVIEW",
        purpose="PRODUCTION",
        provider_profile_ref=StoredDataRef.model_validate(ref("provider_profile")),
        model="test-model",
        session_policy="NEW",
        parent_session_ref=None,
        context_refs=context,
        prompt_registry_entry_ref=StoredDataRef.model_validate(
            ref("prompt_registry_entry")
        ),
        prompt_key="rule-scope-gate.review",
        prompt_template_ref=StoredDataRef.model_validate(ref("prompt_template")),
        prompt_template_version="1.0.0",
        prompt_payload_ref=StoredDataRef.model_validate(ref("prompt_payload")),
        execution_limits_ref=StoredDataRef.model_validate(ref("execution_limits")),
        retry_policy_ref=StoredDataRef.model_validate(ref("retry_policy")),
        tool_policy_ref=tool_ref,
        redaction_policy_ref=StoredDataRef.model_validate(ref("redaction_policy")),
        semantic_validator_ref=StoredDataRef.model_validate(ref("semantic_validator")),
        output_schema_ref=StoredDataRef.model_validate(ref("output_schema_spec")),
        output_schema="rule-scope-output.v1",
        token_budget=100,
        timeout_ms=1_000,
    )
    spec_ref = records.add(spec)
    action = ActionRequest.model_validate_json(
        canonical_bytes(
            make("ActionRequest")
            | {
                "meta": _meta("action_request", "rule-scope-action-r1"),
                "action_id": "rule-scope-action-1",
                "requested_by": "VERIFICATION",
                "requester_identity_ref": owner_ref,
                "action_type": "CALL_RULE_SCOPE_GATE",
                "work_ref": work_ref,
                "expected_state_version": work.state_version,
                "input_refs": context,
                "llm_call_spec_ref": spec_ref,
                "provider_profile_ref": spec.provider_profile_ref,
                "session_mode": "NEW",
                "reason": "Review current program policy.",
                "requested_at": NOW,
            }
        )
    )
    action_ref = records.add(action)
    required_checks = tuple(REQUIRED_CHECKS[action.action_type])
    issued = ActionDecision.model_validate_json(
        canonical_bytes(
            make("ActionDecision")
            | {
                "meta": _meta(
                    "action_decision",
                    "rule-scope-decision-r1",
                    logical_id="rule-scope-decision-logical",
                ),
                "decision_id": "rule-scope-decision-1",
                "action_ref": action_ref,
                "decision": "ALLOW",
                "required_checks": required_checks,
                "check_results": tuple(
                    {
                        "check_type": check,
                        "result": "PASS",
                        "reason_code": "OK",
                        "safe_message": "Trusted runtime check passed.",
                    }
                    for check in required_checks
                ),
                "checked_state_version": work.state_version,
                "valid_until": "2026-09-12T00:01:00Z",
                "use_status": "UNUSED",
                "used_at": None,
                "outcome_refs": (),
                "decided_at": NOW,
            }
        )
    )
    issued_ref = records.add(issued)
    claimed = ActionDecision.model_validate_json(
        canonical_bytes(
            issued.model_dump()
            | {
                "meta": _meta(
                    "action_decision",
                    "rule-scope-decision-r2",
                    logical_id="rule-scope-decision-logical",
                    revision=2,
                    previous="rule-scope-decision-r1",
                ),
                "use_status": "USED",
                "used_at": NOW,
            }
        )
    )
    claimed_ref = records.add(claimed)
    reservation = BudgetReservation.model_validate_json(
        canonical_bytes(
            make("BudgetReservation")
            | {
                "meta": _meta("budget_reservation", "rule-scope-reservation-r1"),
                "reservation_id": "rule-scope-reservation-1",
                "budget_binding_ref": StoredDataRef.model_validate(
                    ref("budget_profile_binding")
                ),
                "action_ref": action_ref,
                "work_ref": work_ref,
                "status": "RESERVED",
                "reserved_at": NOW,
            }
        )
    )
    reservation_ref = records.add(reservation)
    request = LLMInvocationRequest.model_validate_json(
        canonical_bytes(
            spec.model_dump()
            | {
                "meta": _meta("llm_invocation_request", "rule-scope-request-r1"),
                "action_decision_ref": claimed_ref,
                "call_spec_ref": spec_ref,
            }
        )
    )
    request_ref = records.add(request)
    result = LLMInvocationResult.model_validate_json(
        canonical_bytes(
            make("LLMInvocationResult", "llm_invocation_result")
            | {
                "meta": _meta("llm_invocation_result", "rule-scope-result-r1"),
                "llm_call_id": spec.llm_call_id,
                "purpose": "PRODUCTION",
                "status": "SUCCEEDED",
                "provider": "test-provider",
                "model": spec.model,
                "actual_session_mode": "NEW",
                "session_ref": "rule-scope-session-1",
                "response_ref": output_ref,
                "parsed_output_ref": output_ref,
                "usage": None,
                "started_at": NOW,
                "finished_at": NOW,
                "elapsed_ms": 1,
                "safe_error": None,
            }
        )
    )
    result_ref = records.add(result)
    log = LLMInvocationLog.model_validate_json(
        canonical_bytes(
            make("LLMInvocationLog", "llm_invocation_log")
            | {
                "meta": _meta("llm_invocation_log", "rule-scope-log-r1"),
                "llm_call_id": spec.llm_call_id,
                "action_decision_ref": claimed_ref,
                "call_spec_ref": spec_ref,
                "agent_role": spec.agent_role,
                "task_kind": spec.task_kind,
                "purpose": spec.purpose,
                "provider_profile_ref": spec.provider_profile_ref,
                "provider": result.provider,
                "model": spec.model,
                "session_policy": "NEW",
                "session_ref": result.session_ref,
                "parent_session_ref": None,
                "prompt_registry_entry_ref": spec.prompt_registry_entry_ref,
                "prompt_key": spec.prompt_key,
                "prompt_template_ref": spec.prompt_template_ref,
                "prompt_template_version": spec.prompt_template_version,
                "prompt_payload_ref": spec.prompt_payload_ref,
                "execution_limits_ref": spec.execution_limits_ref,
                "retry_policy_ref": spec.retry_policy_ref,
                "tool_policy_ref": spec.tool_policy_ref,
                "redaction_policy_ref": spec.redaction_policy_ref,
                "semantic_validator_ref": spec.semantic_validator_ref,
                "output_schema_ref": spec.output_schema_ref,
                "context_refs": context,
                "exposed_response_ref": output_ref,
                "parsed_output_ref": output_ref,
                "status": "SUCCEEDED",
                "usage": None,
                "safe_error": None,
                "started_at": NOW,
                "finished_at": NOW,
            }
        )
    )
    log_ref = records.add(log)
    invocation = PersistedLLMInvocation(request, result, log_ref, "RETURNED")
    call = RuleScopeCallRefs(issued_ref, reservation_ref, spec_ref)
    assert records.get_exact(request_ref) == request
    assert records.get_exact(result_ref) == result
    return work, call, owner_ref, context, proposal, invocation, records, artifacts


@pytest.mark.asyncio
async def test_rule_scope_publisher_keeps_complete_invocation_chain() -> None:
    work, call, owner, context, proposal, invocation, records, artifacts = _closure()
    agent = RuleScopeGateAgent(
        llm_calls=_LLM(invocation),
        records=records,
        artifacts=artifacts,
        provenance_validator=validate_llm_invocation_provenance,
    )
    agent_outcome = await agent.review(
        work=work,
        call=call,
        owner_ref=owner,
        required_context=context,
    )
    assert agent_outcome.proposal == proposal
    assert agent_outcome.invocation is invocation

    class _Completed:
        output_refs: tuple[RecordRef, ...]

        def __init__(self, output_ref: RecordRef) -> None:
            self.output_refs = (output_ref,)

    class _Runner:
        def __init__(self) -> None:
            self.kwargs: dict[str, object] | None = None

        def complete(self, *args: object, **kwargs: object) -> _Completed:
            self.kwargs = kwargs
            return _Completed(reference(args[3][0]))  # type: ignore[index]

    review_record = wire(
        RuleScopeImpactReview,
        make("RuleScopeImpactReview")
        | {
            "meta": meta(
                "rule_scope_impact_review", hypothesis="h1", attempt="at-gate"
            ),
            "action_decision_ref": invocation.request.action_decision_ref.model_dump(
                mode="json"
            ),
        },
    )
    execution = RuleScopeExecution(work, call, owner, owner)
    runner = _Runner()
    publisher = WorkflowRuleScopePublisher(cast(WorkflowRunner, runner))

    assert publisher(execution, review_record, invocation) == reference(review_record)
    assert runner.kwargs is not None
    assert runner.kwargs["action_input_refs"] == tuple(
        dict.fromkeys(
            (
                *context,
                call.decision_ref,
                call.reservation_ref,
                call.call_spec_ref,
                invocation.request.action_decision_ref,
                reference(invocation.request),
                reference(invocation.result),
                invocation.log_ref,
                invocation.result.parsed_output_ref,
            )
        )
    )


@pytest.mark.asyncio
async def test_rule_scope_agent_rejects_log_from_another_attempt() -> None:
    work, call, owner, context, _proposal, invocation, records, artifacts = _closure()
    original_log = cast(LLMInvocationLog, records.get_exact(invocation.log_ref))
    wrong_log = original_log.model_copy(
        update={
            "meta": _meta(
                "llm_invocation_log", "wrong-attempt-log-r1", attempt="at-other"
            )
        }
    )
    wrong_log_ref = records.add(wrong_log)
    agent = RuleScopeGateAgent(
        llm_calls=_LLM(replace(invocation, log_ref=wrong_log_ref)),
        records=records,
        artifacts=artifacts,
        provenance_validator=validate_llm_invocation_provenance,
    )

    with pytest.raises(ValueError, match="RULE_SCOPE_INVOCATION_CLOSURE_MISMATCH"):
        await agent.review(
            work=work,
            call=call,
            owner_ref=owner,
            required_context=context,
        )
