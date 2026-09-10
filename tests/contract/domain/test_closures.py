import pytest

from sastsimi.contracts.actions import SessionMode
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    PoCBundle,
)
from sastsimi.contracts.verification import EvidenceAgentResult, VerificationResult

from .canonical_fixtures import make
from .fixtures import (
    dynamic_failure,
    dynamic_request,
    evidence,
    ref,
    verification,
    wire,
)


def test_final_verification_cannot_consume_failed_dynamic_execution() -> None:
    from sastsimi.contracts.verification import validate_dynamic_verdict

    request = wire(DynamicReproductionRequest, dynamic_request())
    request_ref = ref("dynamic_reproduction_request") | {
        "content_hash": content_hash(request)
    }
    dynamic = wire(
        DynamicReproductionResult, dynamic_failure() | {"request_ref": request_ref}
    )
    result = wire(
        VerificationResult,
        verification()
        | dict(
            dynamic_request_ref=request_ref,
            dynamic_result_ref=ref("dynamic_reproduction_result")
            | {"content_hash": content_hash(dynamic)},
        ),
    )
    with pytest.raises(ValueError, match="EXECUTION_FAILURE_IS_NOT_VERDICT"):
        validate_dynamic_verdict(result, request, dynamic, None, generation=1)


def test_pro_con_cannot_share_or_resume_provider_session() -> None:
    from sastsimi.contracts.verification import validate_evidence_sessions

    pro, con = (
        wire(EvidenceAgentResult, evidence()),
        wire(EvidenceAgentResult, evidence("CON")),
    )
    validate_evidence_sessions(
        pro,
        con,
        pro_session_id="one",
        con_session_id="two",
        pro_mode=SessionMode.NEW,
        con_mode=SessionMode.NEW,
    )
    with pytest.raises(ValueError, match="EVIDENCE_NEW_SESSION_REQUIRED"):
        validate_evidence_sessions(
            pro,
            con,
            pro_session_id="one",
            con_session_id="one",
            pro_mode=SessionMode.NEW,
            con_mode=SessionMode.NEW,
        )
    with pytest.raises(ValueError, match="EVIDENCE_NEW_SESSION_REQUIRED"):
        validate_evidence_sessions(
            pro,
            con,
            pro_session_id="one",
            con_session_id="two",
            pro_mode=SessionMode.RESUME,
            con_mode=SessionMode.NEW,
        )


def test_poc_digest_joins_executed_candidate_not_latest() -> None:
    from sastsimi.contracts.dynamic import PoCCandidate, validate_poc_candidate

    candidate = wire(PoCCandidate, make("PoCCandidate", "poc_candidate"))
    candidate_ref = ref("poc_candidate") | {"content_hash": content_hash(candidate)}
    poc = wire(
        PoCBundle, make("PoCBundle", "poc_bundle") | dict(candidate_ref=candidate_ref)
    )
    validate_poc_candidate(poc, candidate)
    with pytest.raises(ValueError, match="POC_CANDIDATE_DIGEST_MISMATCH"):
        validate_poc_candidate(
            wire(
                PoCBundle, poc.model_dump(mode="json") | {"candidate_digest": "b" * 64}
            ),
            candidate,
        )
