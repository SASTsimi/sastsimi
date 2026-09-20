from __future__ import annotations

from typing import cast

from sastsimi.composition.local_evaluation_evidence import (
    ExactLocalEvaluationTrustedEvidence,
)
from sastsimi.contracts.capabilities import CapabilityApprovalEvidence
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.llm import LLMRecord
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.ports.trusted_evidence import UnprovenEvidence


class _CapabilityEvidence(UnprovenEvidence):
    def capability_approval_authorized(
        self, evidence: CapabilityApprovalEvidence
    ) -> bool:
        return evidence == "approved-capability"


def test_exact_local_authority_keeps_configuration_categories_separate() -> None:
    evidence = ExactLocalEvaluationTrustedEvidence(
        capability_evidence=_CapabilityEvidence(),
        llm_records=(cast(LLMRecord, "llm-a"),),
        playbook_records=(cast(VerificationPlaybook, "playbook-a"),),
        sandbox_profiles=(cast(SandboxProfile, "sandbox-a"),),
    )

    assert evidence.capability_approval_authorized(
        cast(CapabilityApprovalEvidence, "approved-capability")
    )
    assert evidence.llm_configuration_approved(cast(LLMRecord, "llm-a"))
    assert evidence.playbook_configuration_approved(
        cast(VerificationPlaybook, "playbook-a")
    )
    assert evidence.sandbox_configuration_approved(cast(SandboxProfile, "sandbox-a"))
    assert not evidence.llm_configuration_approved(cast(LLMRecord, "playbook-a"))
    assert not evidence.playbook_configuration_approved(cast(PlaybookPolicy, "llm-a"))
    assert not evidence.sandbox_configuration_approved(cast(SandboxProfile, "other"))


# mypy: disable-error-code="comparison-overlap"
