from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import evidence_closure
from sastsimi.contracts.verification import VerificationResult

from .canonical_fixtures import make
from .fixtures import ref, wire


def test_r14_complete_verification_evidence_reaches_finding() -> None:
    roots = [
        ref(name, record=False)
        for name in ("validation", "falsification", "required_primitive")
    ]
    value = make("VerificationResult") | dict(
        verification_mode="BASIC",
        debate_input_hash=None,
        pro_evidence_ref=None,
        con_evidence_ref=None,
        supporting_evidence=[],
        counter_evidence=[],
        validation_results=[
            dict(
                validation_id="v1",
                completion="COMPLETE",
                evidence_refs=[roots[0]],
                summary="checked",
            )
        ],
        falsification_results=[
            dict(
                question_id="q1",
                outcome="INCONCLUSIVE",
                evidence_refs=[roots[1]],
                rationale="not disproved",
            )
        ],
        required_primitive_candidates=[
            dict(
                draft_id="required",
                entity_refs=[],
                privilege_level=None,
                evidence_refs=[roots[2]],
                description="required condition",
            )
        ],
    )
    result = wire(VerificationResult, value)
    assert set(evidence_closure(result, {})) == {
        wire(StoredDataRef, item) for item in roots
    }
