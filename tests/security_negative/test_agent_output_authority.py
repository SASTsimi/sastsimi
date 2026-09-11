import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.prompts.validation import validate_output
from tests.contract.domain.canonical_fixtures import make


def test_provider_output_cannot_set_runtime_owned_metadata_or_ids() -> None:
    forged = make("HypothesisProposal")

    with pytest.raises(ValueError, match="PROMPT_OUTPUT_AUTHORITY_DENIED"):
        validate_output(
            canonical_bytes(forged),
            json_schema={"type": "object", "additionalProperties": True},
            result_kind="hypothesis_proposal",
            agent_role="HYPOTHESIS",
            semantic_validator=lambda _value: None,
        )


@pytest.mark.parametrize(
    ("agent_role", "result_kind", "forged"),
    (
        ("VERIFICATION", "verification_result", {"attempt_id": "forged"}),
        ("POLICY_PARSER", "policy_parser_result", {"action_id": "forged"}),
        ("CWE_LABELING", "cwe_label", {"record_id": "forged"}),
        (
            "TECHNICAL_GATE",
            "technical_evidence_review",
            {"action_decision_ref": {"record_id": "forged"}},
        ),
        (
            "RULE_SCOPE_GATE",
            "rule_scope_impact_review",
            {"verification_generation": 2},
        ),
        ("REPORTER", "report_draft", {"work_id": "forged"}),
    ),
)
def test_every_production_role_rejects_runtime_owned_fields(
    agent_role: str, result_kind: str, forged: dict[str, object]
) -> None:
    with pytest.raises(ValueError, match="PROMPT_OUTPUT_AUTHORITY_DENIED"):
        validate_output(
            canonical_bytes({"semantic_result": forged}),
            json_schema={"type": "object", "additionalProperties": True},
            result_kind=result_kind,
            agent_role=agent_role,  # type: ignore[arg-type]
            semantic_validator=lambda _value: None,
        )


def test_semantic_identifiers_and_labels_remain_valid_agent_output() -> None:
    value = {
        "cwe_id": "CWE-89",
        "rule_id": "sql-injection",
        "question_id": "existing-question-1",
        "label": "SQL injection",
    }

    assert (
        validate_output(
            canonical_bytes(value),
            json_schema={"type": "object", "additionalProperties": True},
            result_kind="technical_evidence_review",
            agent_role="TECHNICAL_GATE",
            semantic_validator=lambda _value: None,
        )
        == value
    )
