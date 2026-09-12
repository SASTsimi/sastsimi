"""Transport types for resolving exact inputs to a human-readable report."""

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.dynamic import (
    AgentLog,
    DynamicReproductionResult,
    PoCBundle,
    PoCCandidate,
    SandboxCommandRecord,
)
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.reporting import Finding, ReportContent, ReportDraft
from sastsimi.contracts.verification import VerificationResult


class ReportUnavailable(ValueError):
    """The requested draft is missing, stale, unsafe, or has a broken closure."""


@dataclass(frozen=True, slots=True)
class CurrentReport:
    """Exact, already-resolved records needed to render one current report."""

    draft: ReportDraft
    finding: Finding
    verification: VerificationResult
    cwe: CWELabel
    technical: TechnicalEvidenceReview
    rule_scope: RuleScopeImpactReview
    dynamic: DynamicReproductionResult
    poc: PoCBundle
    poc_candidate: PoCCandidate
    agent_log: AgentLog
    execution_command: SandboxCommandRecord
    content: ReportContent
    poc_text: str
    report_action: ActionRequest
    report_decision: ActionDecision

    @property
    def analysis_id(self) -> str:
        return str(self.draft.meta.analysis_id)

    @property
    def hypothesis_id(self) -> str:
        value = self.draft.meta.hypothesis_id
        if value is None:
            raise ReportUnavailable("REPORT_SCOPE_INVALID")
        return str(value)

    @property
    def finding_id(self) -> str:
        return str(self.finding.meta.record_id)


class CurrentReportSource(Protocol):
    def list_current(self, analysis_id: str) -> tuple[CurrentReport, ...]: ...

    def get_current(self, finding_id: str) -> CurrentReport: ...


__all__ = [
    "CurrentReport",
    "CurrentReportSource",
    "ReportUnavailable",
]
