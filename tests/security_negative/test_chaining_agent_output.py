from __future__ import annotations

import pytest

from sastsimi.agents.chaining import parse_chaining_output
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.ports.chaining import (
    ChainingAgentInput,
    ChainingComparison,
    ChainingEvidence,
    ChainingPrimitive,
    ChainingPrimitiveInput,
    ChainingPrimitiveResult,
)


def _input() -> ChainingAgentInput:
    return ChainingAgentInput(
        evidence=(
            ChainingEvidence(
                evidence_key="evidence-1",
                kind="CODE_FLOW",
                summary="The validated result reaches the required input.",
            ),
        ),
        primitives=(
            ChainingPrimitive(
                primitive_key="upstream",
                description="A validated capability",
                inputs=(),
                result=ChainingPrimitiveResult(
                    description="Provides the required state",
                    entity_keys=("entity-1",),
                    privilege_level=None,
                    evidence_keys=("evidence-1",),
                ),
                restrictions=(),
            ),
            ChainingPrimitive(
                primitive_key="downstream",
                description="A pending capability",
                inputs=(
                    ChainingPrimitiveInput(
                        input_key="required-1",
                        description="Needs the provided state",
                        entity_keys=("entity-1",),
                        privilege_level=None,
                        evidence_keys=("evidence-1",),
                    ),
                ),
                result=None,
                restrictions=(),
            ),
        ),
        comparisons=(
            ChainingComparison(
                comparison_key="comparison-1",
                upstream_key="upstream",
                downstream_key="downstream",
                input_key="required-1",
            ),
        ),
    )


def _match() -> dict[str, object]:
    return {
        "comparison_key": "comparison-1",
        "outcome": "MATCH",
        "reason_code": None,
        "detail": "The exact evidence supports this connection.",
        "evidence_keys": ["evidence-1"],
        "child": {
            "statement": "The two validated capabilities may compose.",
            "vulnerability_type_candidates": ["CWE-639"],
            "falsification_questions": ["Can the supplied state reach the consumer?"],
            "validation_checks": ["Revalidate the complete child path."],
        },
    }


def test_content_only_match_is_accepted() -> None:
    output = parse_chaining_output(
        canonical_bytes({"decisions": [_match()]}),
        _input(),
    )

    assert output.decisions[0].outcome == "MATCH"
    assert output.decisions[0].child is not None


@pytest.mark.parametrize(
    "payload,error",
    [
        ({"decisions": []}, "CHAINING_DECISION_COVERAGE_MISMATCH"),
        (
            {"decisions": [_match() | {"evidence_keys": ["unknown"]}]},
            "CHAINING_EVIDENCE_SELECTION_MISMATCH",
        ),
        (
            {
                "decisions": [
                    _match()
                    | {
                        "primitive_match_id": "provider-owned",
                        "upstream_result_ref": {},
                    }
                ]
            },
            "CHAINING_OUTPUT_INVALID",
        ),
        (
            {
                "decisions": [
                    _match()
                    | {
                        "child": {
                            **_match()["child"],  # type: ignore[dict-item]
                            "proposal_id": "provider-owned",
                        }
                    }
                ]
            },
            "CHAINING_OUTPUT_INVALID",
        ),
    ],
)
def test_provider_cannot_omit_comparisons_or_supply_authority(
    payload: dict[str, object], error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        parse_chaining_output(canonical_bytes(payload), _input())
