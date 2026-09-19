"""Exact, run-prepared trust inventory for ``LOCAL_EVALUATION`` only."""

from __future__ import annotations

from collections.abc import Iterable

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.capabilities import CapabilityApprovalEvidence
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.llm import LLMRecord
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.ports.trusted_evidence import TrustedEvidencePort, UnprovenEvidence


def _digests(values: Iterable[object]) -> frozenset[str]:
    return frozenset(content_hash(value) for value in values)


class ExactLocalEvaluationTrustedEvidence(UnprovenEvidence):
    """Approve only exact records prepared for one explicit local run.

    Host capability approval remains owned by the durable capability-probe
    authority.  This class only joins that authority with immutable local LLM,
    playbook, Sandbox, and optional static configuration inventories.
    """

    def __init__(
        self,
        *,
        capability_evidence: TrustedEvidencePort,
        llm_records: Iterable[LLMRecord],
        playbook_records: Iterable[VerificationPlaybook | PlaybookPolicy],
        sandbox_profiles: Iterable[SandboxProfile],
        static_profiles: Iterable[StaticToolProfile] = (),
    ) -> None:
        self._capabilities = capability_evidence
        self._llm = _digests(llm_records)
        self._playbooks = _digests(playbook_records)
        self._sandboxes = _digests(sandbox_profiles)
        self._static = _digests(static_profiles)

    def capability_approval_authorized(
        self, evidence: CapabilityApprovalEvidence
    ) -> bool:
        return self._capabilities.capability_approval_authorized(evidence)

    def static_tool_configuration_approved(self, profile: StaticToolProfile) -> bool:
        return content_hash(profile) in self._static

    def playbook_configuration_approved(
        self, record: VerificationPlaybook | PlaybookPolicy
    ) -> bool:
        return content_hash(record) in self._playbooks

    def llm_configuration_approved(self, record: LLMRecord) -> bool:
        return content_hash(record) in self._llm

    def sandbox_configuration_approved(self, profile: SandboxProfile) -> bool:
        return content_hash(profile) in self._sandboxes


__all__ = ["ExactLocalEvaluationTrustedEvidence"]
