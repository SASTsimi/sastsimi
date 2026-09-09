import pytest

from sastsimi.contracts.verification import (
    FalsificationResult,
    ValidationCheckResult,
    VerificationInitialAssessment,
)

from .canonical_fixtures import make
from .fixtures import ref, wire
from .success_fixture import bound


def test_r2_application_cannot_join_another_hypothesis() -> None:
    from sastsimi.contracts.hypothesis import (
        HypothesisProposal,
        VulnerabilityHypothesis,
    )
    from sastsimi.contracts.verification import (
        PlaybookApplication,
        PlaybookPolicy,
        VerificationPlaybook,
        validate_playbook_application,
    )

    proposal = wire(
        HypothesisProposal,
        make("HypothesisProposal") | dict(vulnerability_type_candidates=[]),
    )
    hypothesis = wire(
        VulnerabilityHypothesis,
        make("VulnerabilityHypothesis")
        | dict(
            proposal_ref=bound(proposal),
            target_locations=proposal.model_dump(mode="json")["target_locations"],
            falsification_questions=[dict(question_id="q1", question="guard?")],
            validation_checks=[dict(validation_id="v1", instruction="check guard")],
        ),
    )
    playbook = wire(
        VerificationPlaybook,
        make("VerificationPlaybook")
        | dict(
            scope="COMMON", vulnerability_type=None, falsification_question_templates=[]
        ),
    )
    policy = wire(
        PlaybookPolicy,
        make("PlaybookPolicy")
        | dict(common_playbook_ref=bound(playbook), type_playbooks=[]),
    )
    application = wire(
        PlaybookApplication,
        make("PlaybookApplication")
        | dict(
            hypothesis_ref=bound(hypothesis),
            proposal_ref=bound(proposal),
            policy_ref=bound(policy),
            playbook_ref=bound(playbook),
            selection="COMMON",
            selected_type=None,
            selection_reason="NO_TYPE",
            questions=[],
        ),
    )
    validate_playbook_application(application, hypothesis, proposal, policy, playbook)
    changed = application.model_dump(mode="json")
    changed["meta"]["hypothesis_id"] = "other"
    with pytest.raises(ValueError, match="RECORD_SCOPE_MISMATCH"):
        validate_playbook_application(
            wire(PlaybookApplication, changed), hypothesis, proposal, policy, playbook
        )


@pytest.mark.parametrize(
    "model", [FalsificationResult, ValidationCheckResult, VerificationInitialAssessment]
)
@pytest.mark.parametrize("kind", ["analysis_error", "data_gap"])
def test_r1_failure_records_never_become_decisive_evidence(
    model: type, kind: str
) -> None:
    value = make(model.__name__) | {"evidence_refs": [ref(kind)]}
    with pytest.raises(ValueError, match="ERROR_IS_NOT_EVIDENCE"):
        wire(model, value)
