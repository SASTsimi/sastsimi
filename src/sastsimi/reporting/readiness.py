"""Deterministic preflight for the Reporter Agent."""

from dataclasses import dataclass

from sastsimi.contracts.domain import exact
from sastsimi.contracts.gates import RuleScopeImpactReview, TechnicalEvidenceReview
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.reporting import Finding, FindingIndexState
from sastsimi.contracts.verification import VerificationResult


@dataclass(frozen=True, slots=True)
class ReportReadiness:
    ready: bool
    reasons: tuple[str, ...]


class ReportingReadinessService:
    """Keep Finding existence separate from permission to call Reporter."""

    def evaluate(
        self,
        *,
        finding: Finding,
        index: FindingIndexState,
        verification: VerificationResult,
        technical: TechnicalEvidenceReview,
        scope: RuleScopeImpactReview,
        policy_state: RunPolicyState,
    ) -> ReportReadiness:
        reasons: list[str] = []
        try:
            exact(finding.verification_result_ref, verification, finding.meta)
            exact(finding.technical_review_ref, technical, finding.meta)
            exact(finding.rule_scope_impact_review_ref, scope, finding.meta)
            exact(scope.run_policy_state_ref, policy_state, finding.meta)
        except ValueError:
            reasons.append("REPORT_UPSTREAM_CLOSURE_MISMATCH")
        if index.status != "CURRENT" or index.finding_ref != self._ref(finding):
            reasons.append("STALE_FINDING")
        if verification.verdict != "TRUE":
            reasons.append("FINAL_TRUE_REQUIRED")
        if technical.status != "ACCEPT":
            reasons.append("TECHNICAL_ACCEPT_REQUIRED")
        if policy_state.status != "CURRENT":
            reasons.append("CURRENT_POLICY_REQUIRED")
        for passed, reason in (
            (scope.review_status == "PASS", "RULE_SCOPE_REVIEW_NOT_PASS"),
            (scope.rule_compliance == "PASS", "RULE_COMPLIANCE_NOT_PASS"),
            (scope.scope_compliance == "PASS", "SCOPE_COMPLIANCE_NOT_PASS"),
            (
                scope.testing_restriction_compliance == "PASS",
                "TESTING_RESTRICTION_NOT_PASS",
            ),
            (scope.security_impact == "SUFFICIENT", "IMPACT_NOT_SUFFICIENT"),
            (scope.report_permission == "ALLOW", "REPORT_PERMISSION_DENIED"),
            (
                not any(item.blocks_allow for item in scope.missing_information),
                "BLOCKING_POLICY_INFORMATION_MISSING",
            ),
        ):
            if not passed:
                reasons.append(reason)
        return ReportReadiness(not reasons, tuple(dict.fromkeys(reasons)))

    @staticmethod
    def _ref(finding: Finding) -> StoredDataRef:
        value = reference(finding)
        if not isinstance(value, StoredDataRef):
            raise ValueError("REPORT_FINDING_SCOPE_MISMATCH")
        return value
