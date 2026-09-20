"""Executable LOCAL_EVALUATION prompt catalog contracts."""

from __future__ import annotations

import json

import pytest

from sastsimi.prompts.local_catalog import (
    LOCAL_EVALUATION_PROMPT_SPECS,
    local_output_schema,
    validate_local_output,
)


def _spec(role: str, task: str):  # type: ignore[no-untyped-def]
    return next(
        item
        for item in LOCAL_EVALUATION_PROMPT_SPECS
        if item.role == role and item.task_kind == task
    )


def test_catalog_covers_every_fresh_session_route_and_excludes_execute() -> None:
    keys = {(item.role, item.task_kind) for item in LOCAL_EVALUATION_PROMPT_SPECS}

    assert len(keys) == 16
    assert ("DYNAMIC_REPRODUCTION", "EXECUTE_REPRODUCTION") not in keys
    assert ("HYPOTHESIS", "GENERATE_INITIAL") in keys
    assert ("REPORTER", "CREATE_DRAFT") in keys
    assert all(
        len({str(slot.data_kind) for slot in item.input_slots}) == len(item.input_slots)
        for item in LOCAL_EVALUATION_PROMPT_SPECS
    )


def test_catalog_declares_exact_current_runtime_input_kinds() -> None:
    hypothesis = _spec("HYPOTHESIS", "GENERATE_INITIAL")
    actual = [
        (str(slot.slot), str(slot.data_kind), slot.cardinality)
        for slot in hypothesis.input_slots
    ]
    assert actual == [("facts", "static_fact_bundle", "REQUIRED_ONE")]

    candidate = _spec("DYNAMIC_REPRODUCTION", "CREATE_POC_CANDIDATE")
    assert {
        (str(slot.data_kind), slot.cardinality) for slot in candidate.input_slots
    } == {
        ("dynamic_reproduction_request", "REQUIRED_ONE"),
        ("reproduction_plan", "REQUIRED_ONE"),
        ("sandbox_environment", "REQUIRED_ONE"),
        ("code_context_response", "REQUIRED_MANY"),
        ("artifact", "REQUIRED_MANY"),
    }

    assessment = _spec("VERIFICATION", "ASSESS_INITIAL")
    assessment_kinds = {str(slot.data_kind) for slot in assessment.input_slots}
    assert "hypothesis_proposal" not in assessment_kinds
    assert assessment_kinds == {
        "vulnerability_hypothesis",
        "playbook_policy",
        "verification_playbook",
        "static_fact_bundle",
        "playbook_application",
        "pro_evidence_result",
        "con_evidence_result",
    }

    dynamic_request = _spec("VERIFICATION", "CREATE_DYNAMIC_REQUEST")
    assert (
        "code_context_response",
        "REQUIRED_MANY",
    ) in {
        (str(slot.data_kind), slot.cardinality) for slot in dynamic_request.input_slots
    }

    technical = _spec("TECHNICAL_GATE", "REVIEW_TECHNICAL")
    assert "budget_profile_binding" in {
        str(slot.data_kind) for slot in technical.input_slots
    }

    rule_scope = _spec("RULE_SCOPE_GATE", "REVIEW")
    rule_scope_kinds = {str(slot.data_kind) for slot in rule_scope.input_slots}
    assert {"dynamic_reproduction_result", "poc_bundle"} <= rule_scope_kinds

    reporter = _spec("REPORTER", "CREATE_DRAFT")
    assert "policy_collection_result" in {
        str(slot.data_kind) for slot in reporter.input_slots
    }


def test_content_schema_is_strict_and_matches_agent_parser() -> None:
    schema = json.loads(
        local_output_schema("DYNAMIC_REPRODUCTION", "CREATE_POC_CANDIDATE")
    )
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["content"]

    validate_local_output(
        "DYNAMIC_REPRODUCTION", "CREATE_POC_CANDIDATE", {"content": "echo ok"}
    )
    with pytest.raises(ValueError, match="LOCAL_EVALUATION_OUTPUT_INVALID"):
        validate_local_output(
            "DYNAMIC_REPRODUCTION",
            "CREATE_POC_CANDIDATE",
            {"content": "echo ok", "attempt_id": "provider-owned"},
        )


def test_hypothesis_schema_is_content_only_array() -> None:
    schema = json.loads(local_output_schema("HYPOTHESIS", "GENERATE_INITIAL"))
    assert schema["type"] == "array"

    validate_local_output("HYPOTHESIS", "GENERATE_INITIAL", [])
    with pytest.raises(ValueError, match="LOCAL_EVALUATION_OUTPUT_INVALID"):
        validate_local_output("HYPOTHESIS", "GENERATE_INITIAL", {"proposals": []})


def test_unknown_or_execute_route_is_fail_closed() -> None:
    with pytest.raises(ValueError, match="LOCAL_EVALUATION_OUTPUT_ROUTE_UNAVAILABLE"):
        local_output_schema("DYNAMIC_REPRODUCTION", "EXECUTE_REPRODUCTION")
    with pytest.raises(ValueError, match="LOCAL_EVALUATION_OUTPUT_ROUTE_UNAVAILABLE"):
        local_output_schema("HYPOTHESIS", "UNKNOWN")
