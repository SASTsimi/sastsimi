"""Human-readable report rendering is current-only and fail-closed."""

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from sastsimi.contracts.actions import (
    ActionCheck,
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    CheckType,
    Decision,
    RequesterRole,
    UseStatus,
)
from sastsimi.contracts.dynamic import (
    DynamicReproductionResult,
    PoCBundle,
    PoCCandidate,
)
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import Finding, ReportContent, ReportDraft
from sastsimi.contracts.verification import EvidenceClaim, VerificationResult
from sastsimi.reporting.markdown_export import (
    CurrentReport,
    ReportMarkdownService,
    ReportUnavailable,
)


class Source:
    def __init__(self, report: CurrentReport) -> None:
        self.report = report

    def list_current(self) -> tuple[CurrentReport, ...]:
        return (self.report,)

    def get_current(self, finding_id: str) -> CurrentReport:
        if finding_id != self.report.finding_id:
            raise ReportUnavailable("REPORT_NOT_FOUND")
        return self.report


class StaleSource(Source):
    def get_current(self, finding_id: str) -> CurrentReport:
        raise ReportUnavailable("STALE_REPORT")


def ref(kind: str, record_id: str) -> StoredDataRef:
    return StoredDataRef.model_construct(
        stored_data_id=record_id,
        data_kind=kind,
        content_hash="a" * 64,
        workspace_id="workspace-1",
        commit_id="commit-1",
        record_id=record_id,
    )


def current_report() -> CurrentReport:
    now = datetime(2026, 9, 12, tzinfo=UTC)
    meta = SimpleNamespace(
        analysis_id="analysis-1",
        hypothesis_id="hypothesis-1",
        record_id="draft-1",
        created_at=now,
    )
    evidence_ref = ref("artifact", "evidence-1")
    pro = EvidenceClaim.model_construct(
        claim_id="pro-1",
        statement="User input reaches the sink.",
        source_role="PRO",
        evidence_refs=(evidence_ref,),
        code_locations=(),
        limitations=(),
    )
    con = EvidenceClaim.model_construct(
        claim_id="con-1",
        statement="No effective sanitizer was found.",
        source_role="CON",
        evidence_refs=(evidence_ref,),
        code_locations=(),
        limitations=(),
    )
    finding_ref = ref("finding", "finding-1")
    poc_ref = ref("poc_bundle", "poc-1")
    action_meta = RecordMeta.model_construct(
        record_id="report-action-1",
        logical_record_id="report-action-1",
        record_type="action_request",
        schema_version="5.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=now,
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
        attempt_id="attempt-1",
    )
    report_action = ActionRequest.model_construct(
        meta=action_meta,
        action_type=ActionType.CREATE_REPORT_DRAFT,
        requested_by=RequesterRole.VERIFICATION,
    )
    report_decision = ActionDecision.model_construct(
        action_ref=ref("action_request", "report-action-1"),
        decision=Decision.ALLOW,
        use_status=UseStatus.USED,
        check_results=(
            ActionCheck(
                check_type=CheckType.REDACTION,
                result=CheckResult.PASS,
                reason_code="SAFE",
                safe_message="Safe output.",
            ),
        ),
    )
    draft = ReportDraft.model_construct(
        meta=meta,
        finding_ref=finding_ref,
        poc_ref=poc_ref,
        restrictions=(),
        limitations=("Requires an authenticated account.",),
        unresolved_conditions=(),
        redaction_status="PASSED",
        draft_status="DRAFTED",
    )
    return CurrentReport(
        draft=draft,
        finding=Finding.model_construct(
            meta=SimpleNamespace(record_id="finding-1"), evidence_refs=(evidence_ref,)
        ),
        verification=VerificationResult.model_construct(
            verdict="TRUE",
            verdict_rationale="The stored static, debate, and dynamic evidence agrees.",
            supporting_evidence=(pro,),
            counter_evidence=(con,),
        ),
        cwe=CWELabel.model_construct(
            primary="CWE-89",
            alternatives=(),
            taxonomy_version="4.17",
            rationale="The stored flow reaches an SQL sink.",
        ),
        technical=TechnicalEvidenceReview.model_construct(
            status="ACCEPT", rationale="All exact evidence refs are connected."
        ),
        rule_scope=RuleScopeImpactReview.model_construct(
            review_status="PASS",
            rule_compliance="PASS",
            scope_compliance="PASS",
            testing_restriction_compliance="PASS",
            security_impact="SUFFICIENT",
            report_permission="ALLOW",
            reasons=("The tested target and method are allowed.",),
        ),
        dynamic=DynamicReproductionResult.model_construct(
            purpose="POC_CONFIRMATION",
            status="SUCCEEDED",
            hypothesis_outcome="SUPPORTED",
            hypothesis_linkage="The stored observation supports the hypothesis.",
            observation_refs=(evidence_ref,),
            limitations=(),
        ),
        poc=PoCBundle.model_construct(
            candidate_digest="b" * 64,
            validated_at=now,
        ),
        poc_candidate=PoCCandidate.model_construct(),
        content=ReportContent(
            title="Validated vulnerability finding",
            summary="A validated input reaches a sensitive SQL operation.",
            details="The stored source, propagation, and sink evidence is linked.",
            recommendation="Review the PoC and the affected flow before submission.",
            citations=(),
        ),
        poc_text="python poc.py --target local-test",
        report_action=report_action,
        report_decision=report_decision,
    )


def test_markdown_export_contains_human_review_sections_and_exact_path(
    tmp_path: Path,
) -> None:
    report = current_report()
    service = ReportMarkdownService(tmp_path, Source(report))

    markdown = service.show(report.finding_id)
    path = service.export(report.finding_id)

    assert path == tmp_path / "reports" / "analysis-1" / "finding-1.md"
    assert path.read_text(encoding="utf-8") == markdown
    for heading in (
        "# Validated vulnerability finding",
        "## 취약점 요약",
        "## CWE 분류",
        "## 영향받는 코드 위치",
        "## source → propagation → sink 흐름",
        "## 정적 분석 근거",
        "## Pro·Con 검증 근거와 최종 판단 이유",
        "## 동적 재현 결과",
        "## 검증된 PoC와 실행 방법",
        "## 영향도와 제한사항",
        "## Gate 결과",
        "## 사람이 추가로 확인해야 할 내용",
        "## 생성 및 식별 정보",
    ):
        assert heading in markdown


def test_markdown_export_rejects_unproven_redaction_and_unsafe_path(
    tmp_path: Path,
) -> None:
    report = current_report()
    unsafe_draft = report.draft.model_copy(update={"redaction_status": "FAILED"})
    with pytest.raises(ReportUnavailable, match="REDACTION"):
        unsafe_service = ReportMarkdownService(
            tmp_path, Source(replace(report, draft=unsafe_draft))
        )
        unsafe_service.show(report.finding_id)

    unsafe_summary = replace(
        report,
        cwe=report.cwe.model_copy(update={"primary": "token=not-for-output"}),
    )
    with pytest.raises(ReportUnavailable, match="REDACTION"):
        ReportMarkdownService(tmp_path, Source(unsafe_summary)).summaries()

    stale_file = tmp_path / "reports" / "analysis-1" / "finding-1.md"
    stale_file.parent.mkdir(parents=True)
    stale_file.write_text("obsolete report", encoding="utf-8")
    with pytest.raises(ReportUnavailable, match="STALE"):
        ReportMarkdownService(tmp_path, StaleSource(report)).show(report.finding_id)

    unsafe_meta = SimpleNamespace(
        analysis_id="../other-analysis",
        hypothesis_id="hypothesis-1",
        record_id="draft-1",
        created_at=report.draft.meta.created_at,
    )
    unsafe_report = replace(
        report, draft=report.draft.model_copy(update={"meta": unsafe_meta})
    )
    with pytest.raises(ReportUnavailable, match="UNSAFE_REPORT_PATH_ID"):
        ReportMarkdownService(tmp_path, Source(unsafe_report)).export(
            unsafe_report.finding_id
        )
