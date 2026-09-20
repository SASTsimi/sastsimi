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


def test_hypothesis_may_copy_exact_static_evidence_for_runtime_validation() -> None:
    existing_static_evidence = [
        {
            "statement": "Request input may reach a database query",
            "target_locations": [
                {
                    "workspace_id": "existing-workspace",
                    "commit_id": "existing-commit",
                    "file_path": "app/views.py",
                    "start_line": 12,
                    "start_column": 1,
                    "end_line": 12,
                    "end_column": 20,
                }
            ],
            "observed_facts": [
                {
                    "fact_id": "existing-source",
                    "producer": {
                        "attempt_id": "existing-static-attempt",
                        "raw_result_ref": {
                            "stored_data_id": "existing-raw-output",
                            "data_kind": "artifact",
                            "content_hash": "a" * 64,
                            "workspace_id": "existing-workspace",
                            "commit_id": "existing-commit",
                            "record_id": None,
                        },
                    },
                }
            ],
        }
    ]

    assert (
        validate_output(
            canonical_bytes(existing_static_evidence),
            json_schema={
                "type": "array",
                "items": {"type": "object", "additionalProperties": True},
            },
            result_kind="hypothesis_proposal",
            agent_role="HYPOTHESIS",
            semantic_validator=lambda _value: None,
        )
        == existing_static_evidence
    )


@pytest.mark.parametrize(
    ("agent_role", "result_kind"),
    (
        ("PRO", "pro_evidence_result"),
        ("CON", "con_evidence_result"),
    ),
)
def test_evidence_agent_may_copy_schema_bound_evidence_citations(
    agent_role: str, result_kind: str
) -> None:
    existing_citations = {
        "evidence": [
            {
                "statement": "The exact supplied path supports this claim",
                "evidence_refs": [
                    {
                        "stored_data_id": "existing-facts",
                        "data_kind": "static_fact_bundle",
                        "content_hash": "a" * 64,
                        "workspace_id": "existing-workspace",
                        "commit_id": "existing-commit",
                        "record_id": "existing-record",
                    }
                ],
                "code_locations": [
                    {
                        "workspace_id": "existing-workspace",
                        "commit_id": "existing-commit",
                        "file_path": "app/views.py",
                        "start_line": 12,
                        "start_column": 1,
                        "end_line": 12,
                        "end_column": 20,
                    }
                ],
                "limitations": [],
            }
        ],
        "summary": "Independent evidence review",
        "limitations": [],
    }

    assert (
        validate_output(
            canonical_bytes(existing_citations),
            json_schema={"type": "object", "additionalProperties": True},
            result_kind=result_kind,
            agent_role=agent_role,  # type: ignore[arg-type]
            semantic_validator=lambda _value: None,
        )
        == existing_citations
    )


@pytest.mark.parametrize(
    ("agent_role", "result_kind"),
    (
        ("PRO", "pro_evidence_result"),
        ("CON", "con_evidence_result"),
    ),
)
def test_evidence_agent_cannot_emit_runtime_owned_fields_outside_claim_citations(
    agent_role: str, result_kind: str
) -> None:
    with pytest.raises(ValueError, match="PROMPT_OUTPUT_AUTHORITY_DENIED"):
        validate_output(
            canonical_bytes(
                {
                    "evidence": [],
                    "summary": "forged",
                    "limitations": [],
                    "record_id": "forged-record",
                }
            ),
            json_schema={"type": "object", "additionalProperties": True},
            result_kind=result_kind,
            agent_role=agent_role,  # type: ignore[arg-type]
            semantic_validator=lambda _value: None,
        )


@pytest.mark.parametrize(
    ("agent_role", "result_kind", "value"),
    (
        (
            "VERIFICATION",
            "verification_initial_assessment",
            {
                "evidence_refs": [
                    {
                        "stored_data_id": "existing-evidence",
                        "data_kind": "pro_evidence_result",
                        "content_hash": "a" * 64,
                        "workspace_id": "existing-workspace",
                        "commit_id": "existing-commit",
                        "record_id": "existing-record",
                    }
                ]
            },
        ),
        (
            "VERIFICATION",
            "verification_result",
            {
                "falsification_results": [
                    {
                        "evidence_refs": [
                            {
                                "stored_data_id": "existing-evidence",
                                "data_kind": "artifact",
                                "content_hash": "a" * 64,
                                "workspace_id": "existing-workspace",
                                "commit_id": "existing-commit",
                                "record_id": None,
                            }
                        ]
                    }
                ],
                "provided_primitive_candidates": [
                    {
                        "entity_refs": [
                            {
                                "symbol_id": "existing-symbol",
                                "location": {
                                    "workspace_id": "existing-workspace",
                                    "commit_id": "existing-commit",
                                    "file_path": "app/views.py",
                                    "start_line": 12,
                                    "start_column": 1,
                                    "end_line": 12,
                                    "end_column": 20,
                                },
                            }
                        ],
                        "evidence_refs": [],
                    }
                ],
            },
        ),
        (
            "REPORTER",
            "report_draft",
            {
                "citations": [
                    {
                        "workspace_id": "existing-workspace",
                        "commit_id": "existing-commit",
                        "file_path": "app/views.py",
                        "start_line": 12,
                        "start_column": 1,
                        "end_line": 12,
                        "end_column": 20,
                    }
                ]
            },
        ),
    ),
)
def test_schema_bound_citations_reach_trusted_role_finalizers(
    agent_role: str, result_kind: str, value: dict[str, object]
) -> None:
    assert (
        validate_output(
            canonical_bytes(value),
            json_schema={"type": "object", "additionalProperties": True},
            result_kind=result_kind,
            agent_role=agent_role,  # type: ignore[arg-type]
            semantic_validator=lambda _value: None,
        )
        == value
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
