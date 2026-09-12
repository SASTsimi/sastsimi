from __future__ import annotations

from dataclasses import replace

import pytest

from sastsimi.contracts.actions import ActionType, RequesterRole
from sastsimi.contracts.llm import LLMInvocationLog
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkType
from sastsimi.runtime.llm_invocation_provenance import (
    LLMInvocationExpectation,
    validate_llm_invocation_provenance,
)
from tests.security_negative.test_rule_scope_invocation_provenance import _closure


def _expectation(
    owner: BudgetScopeRef, context: tuple[StoredDataRef, ...]
) -> LLMInvocationExpectation:
    return LLMInvocationExpectation(
        work_type=WorkType.RULE_SCOPE_GATE,
        action_type=ActionType.CALL_RULE_SCOPE_GATE,
        requested_by=RequesterRole.VERIFICATION,
        requester_identity_ref=owner,
        agent_role="RULE_SCOPE_GATE",
        task_kind="REVIEW",
        required_context=context,
        require_new_session=True,
        forbid_tools=True,
    )


def test_common_validator_returns_complete_exact_save_closure() -> None:
    work, call, owner, context, _proposal, invocation, records, _artifacts = _closure()

    validated = validate_llm_invocation_provenance(
        records=records,
        work=work,
        issued_decision_ref=call.decision_ref,
        reservation_ref=call.reservation_ref,
        call_spec_ref=call.call_spec_ref,
        invocation=invocation,
        expectation=_expectation(owner, context),
    )

    assert reference(validated.action) in validated.save_input_refs
    assert reference(invocation.request) in validated.save_input_refs
    assert reference(invocation.result) in validated.save_input_refs
    assert invocation.log_ref in validated.save_input_refs
    assert invocation.result.parsed_output_ref in validated.save_input_refs


def test_common_validator_rejects_log_result_reference_swap() -> None:
    work, call, owner, context, _proposal, invocation, records, _artifacts = _closure()
    original = records.get_exact(invocation.log_ref)
    assert isinstance(original, LLMInvocationLog)
    swapped = original.model_copy(
        update={
            "parsed_output_ref": call.call_spec_ref,
            "exposed_response_ref": call.call_spec_ref,
        }
    )
    swapped_ref = records.add(swapped)

    with pytest.raises(ValueError, match="LLM_INVOCATION_PROVENANCE_MISMATCH"):
        validate_llm_invocation_provenance(
            records=records,
            work=work,
            issued_decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            invocation=replace(invocation, log_ref=swapped_ref),
            expectation=_expectation(owner, context),
        )
