from typing import Any

import pytest
from pydantic import ValidationError

from .fixtures import evidence, meta, mutations, proposal, ref, verification, wire


def test_proposal_preserves_nonfinal_origin() -> None:
    from sastsimi.contracts.hypothesis import HypothesisProposal

    value = proposal()
    wire(HypothesisProposal, value)
    for field in value:
        with pytest.raises(ValidationError):
            wire(HypothesisProposal, {k: v for k, v in value.items() if k != field})
    for patch in mutations(
        dict(assertion_mode="FINAL"),
        dict(source_primitive_match_id="m1"),
        dict(origin="CHAINING"),
        dict(falsification_questions=[]),
        dict(vulnerability_type_candidates=["X", "X"]),
    ):
        with pytest.raises(ValidationError):
            wire(HypothesisProposal, value | patch)


def test_duplicate_target_must_be_exact_candidate() -> None:
    from sastsimi.contracts.hypothesis import HypothesisDuplicateReview

    value: dict[str, Any] = dict(
        meta=meta("hypothesis_duplicate_review"),
        proposal_ref=ref("hypothesis_proposal"),
        candidate_hypothesis_refs=[ref("vulnerability_hypothesis")],
        decision="DUPLICATE",
        duplicate_of_hypothesis_ref=ref("vulnerability_hypothesis"),
        rationale="Same path",
        llm_call_id="call",
    )
    wire(HypothesisDuplicateReview, value)
    with pytest.raises(ValidationError, match="INVALID_DUPLICATE_TARGET"):
        wire(
            HypothesisDuplicateReview,
            value
            | {
                "duplicate_of_hypothesis_ref": ref("vulnerability_hypothesis")
                | {"content_hash": "c" * 64}
            },
        )


def test_evidence_roles_are_independent_and_exact() -> None:
    from sastsimi.contracts.verification import (
        EvidenceAgentResult,
        validate_evidence_pair,
    )

    pro, con = (
        wire(EvidenceAgentResult, evidence()),
        wire(EvidenceAgentResult, evidence("CON")),
    )
    validate_evidence_pair(
        pro,
        con,
        parent_work_id=pro.parent_work_id,
        generation=1,
        debate_input_hash="b" * 64,
    )
    with pytest.raises(ValueError, match="CROSS_ROLE_INPUT_DENIED"):
        validate_evidence_pair(
            con,
            pro,
            parent_work_id=pro.parent_work_id,
            generation=1,
            debate_input_hash="b" * 64,
        )
    for patch in mutations(
        dict(verification_generation=2),
        dict(debate_input_hash="a" * 64),
        dict(meta=meta("con_evidence_result", hypothesis="other", attempt="CON")),
        dict(evidence_work_id="PRO-work"),
        dict(llm_call_id="PRO-call"),
    ):
        with pytest.raises(ValueError):
            validate_evidence_pair(
                pro,
                wire(EvidenceAgentResult, evidence("CON") | patch),
                parent_work_id=pro.parent_work_id,
                generation=1,
                debate_input_hash="b" * 64,
            )
    with pytest.raises(ValidationError, match="CROSS_ROLE_INPUT_DENIED"):
        wire(
            EvidenceAgentResult, evidence() | {"evidence": evidence("CON")["evidence"]}
        )


def test_final_verdict_rejects_missing_debate_poc_and_error_as_verdict() -> None:
    from sastsimi.contracts.verification import VerificationResult

    value = verification()
    wire(VerificationResult, value)
    for field in value:
        with pytest.raises(ValidationError):
            wire(VerificationResult, {k: v for k, v in value.items() if k != field})
    for patch in mutations(
        dict(verdict="TRUE"),
        dict(verdict="FALSE"),
        dict(pro_evidence_ref=None),
        dict(unresolved_conditions=[]),
        dict(poc_ref=ref("poc_candidate")),
        dict(
            validation_results=[
                value["validation_results"][0] | {"completion": "INCOMPLETE"}
            ]
        ),
        dict(
            falsification_results=[
                value["falsification_results"][0] | {"outcome": "DISPROVED"}
            ]
        ),
    ):
        with pytest.raises(ValidationError):
            wire(VerificationResult, value | patch)
