"""Fail-closed rendering and atomic export of current report drafts."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    CheckType,
    Decision,
    RequesterRole,
    UseStatus,
)
from sastsimi.contracts.canonical_json import canonical_bytes
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
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import Finding, ReportContent, ReportDraft
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import EvidenceClaim, VerificationResult
from sastsimi.storage.artifact_store import sync_directory

_SAFE_PATH_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


class ReportUnavailable(ValueError):
    """The requested draft is missing, stale, unsafe, or has a broken closure."""


@dataclass(frozen=True, slots=True)
class CurrentReport:
    draft: ReportDraft
    finding: Finding
    verification: VerificationResult
    cwe: CWELabel
    technical: TechnicalEvidenceReview
    rule_scope: RuleScopeImpactReview
    dynamic: DynamicReproductionResult
    poc: PoCBundle
    poc_candidate: PoCCandidate
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
    def list_current(self) -> tuple[CurrentReport, ...]: ...

    def get_current(self, finding_id: str) -> CurrentReport: ...


class ReportMarkdownService:
    """Render only current exact records; never infer new vulnerability facts."""

    def __init__(self, data_dir: Path, source: CurrentReportSource) -> None:
        self._data_dir = data_dir.resolve()
        self._source = source

    def summaries(self) -> tuple[dict[str, str], ...]:
        summaries: list[dict[str, str]] = []
        for report in self._source.list_current():
            validate_redaction_authority(report)
            summary = {
                "analysis_id": report.analysis_id,
                "finding_id": report.finding_id,
                "hypothesis_id": report.hypothesis_id,
                "title": report.content.title,
                "status": "DRAFTED_CURRENT",
                "cwe": report.cwe.primary or "UNCLASSIFIED",
            }
            try:
                assert_safe_provider_text(canonical_bytes(summary))
            except ValueError as error:
                raise ReportUnavailable("REPORT_REDACTION_NOT_PROVEN") from error
            summaries.append(summary)
        return tuple(summaries)

    def show(self, finding_id: str) -> str:
        return render_markdown(self._source.get_current(finding_id))

    def export(self, finding_id: str) -> Path:
        report = self._source.get_current(finding_id)
        markdown = render_markdown(report)
        destination = self._destination(report)
        _atomic_write(destination, markdown.encode("utf-8"))
        return destination

    def _destination(self, report: CurrentReport) -> Path:
        for value in (report.analysis_id, report.finding_id):
            if _SAFE_PATH_SEGMENT.fullmatch(value) is None or value in {".", ".."}:
                raise ReportUnavailable("UNSAFE_REPORT_PATH_ID")
        root = RuntimePaths(self._data_dir).reports.resolve()
        parent = (root / report.analysis_id).resolve()
        if parent.parent != root:
            raise ReportUnavailable("UNSAFE_REPORT_PATH_ID")
        return parent / f"{report.finding_id}.md"


def validate_redaction_authority(report: CurrentReport) -> None:
    """Require the exact used Reporter authorization and its redaction PASS."""

    redaction_checks = tuple(
        check
        for check in report.report_decision.check_results
        if check.check_type == CheckType.REDACTION
    )
    action_ref = report.report_decision.action_ref
    if (
        report.draft.redaction_status != "PASSED"
        or report.report_action.action_type != ActionType.CREATE_REPORT_DRAFT
        or report.report_action.requested_by != RequesterRole.VERIFICATION
        or not isinstance(action_ref, StoredDataRef)
        or action_ref.record_id != report.report_action.meta.record_id
        or action_ref.data_kind != report.report_action.meta.record_type
        or report.report_decision.decision != Decision.ALLOW
        or report.report_decision.use_status != UseStatus.USED
        or len(redaction_checks) != 1
        or redaction_checks[0].result != CheckResult.PASS
    ):
        raise ReportUnavailable("REPORT_REDACTION_NOT_PROVEN")


def render_markdown(report: CurrentReport) -> str:
    """Render existing record values without creating new security claims."""

    validate_redaction_authority(report)
    locations = _locations(report.verification, report.content.citations)
    pro = tuple(
        claim
        for claim in report.verification.supporting_evidence
        if claim.source_role == "PRO"
    )
    con = tuple(
        claim
        for claim in report.verification.counter_evidence
        if claim.source_role == "CON"
    )
    static_claims = tuple(
        claim
        for claim in (
            *report.verification.supporting_evidence,
            *report.verification.counter_evidence,
        )
        if claim.source_role == "VERIFICATION"
    )
    if report.draft.poc_ref is None:
        raise ReportUnavailable("REPORT_TRUE_CLOSURE_MISSING")
    lines = [
        f"# {report.content.title}",
        "",
        "- 현재 상태: `DRAFTED / CURRENT`",
        f"- final Verification 판정: `{report.verification.verdict}`",
        "",
        "## 취약점 요약",
        "",
        report.content.summary,
        "",
        "## CWE 분류",
        "",
        f"- Primary: `{report.cwe.primary or 'UNCLASSIFIED'}`",
        f"- Alternatives: {_inline(report.cwe.alternatives)}",
        f"- Taxonomy: `{report.cwe.taxonomy_version}`",
        f"- 근거: {report.cwe.rationale}",
        "",
        "## 영향받는 코드 위치",
        "",
        *_location_lines(locations),
        "",
        "## source → propagation → sink 흐름",
        "",
        report.content.details,
        "",
        "## 정적 분석 근거",
        "",
        *_claim_lines(static_claims),
        f"- Finding evidence refs: {_refs(report.finding.evidence_refs)}",
        "",
        "## Pro·Con 검증 근거와 최종 판단 이유",
        "",
        "### Pro",
        "",
        *_claim_lines(pro),
        "",
        "### Con",
        "",
        *_claim_lines(con),
        "",
        f"- 최종 판단 이유: {report.verification.verdict_rationale}",
        "",
        "## 동적 재현 결과",
        "",
        f"- 목적: `{report.dynamic.purpose}`",
        f"- 실행 상태: `{report.dynamic.status}`",
        f"- 가설 결과: `{report.dynamic.hypothesis_outcome}`",
        f"- 가설 연결 설명: {report.dynamic.hypothesis_linkage}",
        f"- 관찰 refs: {_refs(report.dynamic.observation_refs)}",
        "",
        "## 검증된 PoC와 실행 방법",
        "",
        f"- validated PoC ref: `{report.draft.poc_ref.record_id}`",
        f"- candidate digest: `{report.poc.candidate_digest}`",
        f"- validated at: `{report.poc.validated_at.isoformat()}`",
        "",
        *_indented(report.poc_text),
        "",
        "## 영향도와 제한사항",
        "",
        f"- 정책상 보안 영향: `{report.rule_scope.security_impact}`",
        "- 제한사항: "
        + _inline((*report.draft.limitations, *report.dynamic.limitations)),
        "- 제약: "
        + _inline(tuple(item.statement for item in report.draft.restrictions)),
        "",
        "## Gate 결과",
        "",
        f"- Technical Gate: `{report.technical.status}` — {report.technical.rationale}",
        f"- Rule Scope Gate: `{report.rule_scope.review_status}`",
        f"- rule / scope / testing: `{report.rule_scope.rule_compliance}` / "
        f"`{report.rule_scope.scope_compliance}` / "
        f"`{report.rule_scope.testing_restriction_compliance}`",
        f"- report permission: `{report.rule_scope.report_permission}`",
        f"- 정책 검토 이유: {_inline(report.rule_scope.reasons)}",
        "",
        "## 사람이 추가로 확인해야 할 내용",
        "",
        f"- 미해결 조건: {_inline(report.draft.unresolved_conditions)}",
        f"- 권고 사항: {report.content.recommendation}",
        "",
        "## 생성 및 식별 정보",
        "",
        f"- 생성 시각: `{report.draft.meta.created_at.isoformat()}`",
        f"- analysis_id: `{report.analysis_id}`",
        f"- hypothesis_id: `{report.hypothesis_id}`",
        f"- finding_id: `{report.finding_id}`",
        f"- ReportDraft record_id: `{report.draft.meta.record_id}`",
        "",
    ]
    rendered = "\n".join(lines)
    try:
        assert_safe_provider_text(rendered.encode("utf-8"))
    except ValueError as error:
        raise ReportUnavailable("REPORT_REDACTION_NOT_PROVEN") from error
    return rendered


def _locations(
    verification: VerificationResult, citations: tuple[CodeLocation, ...]
) -> tuple[CodeLocation, ...]:
    values = [
        *citations,
        *(
            location
            for claim in (
                *verification.supporting_evidence,
                *verification.counter_evidence,
            )
            for location in claim.code_locations
        ),
    ]
    return tuple(dict.fromkeys(values))


def _location_lines(locations: tuple[CodeLocation, ...]) -> list[str]:
    if not locations:
        return ["- 없음"]
    return [
        f"- `{item.file_path}:{item.start_line}-{item.end_line}`" for item in locations
    ]


def _claim_lines(claims: tuple[EvidenceClaim, ...]) -> list[str]:
    if not claims:
        return ["- 없음"]
    return [
        f"- `{claim.claim_id}` {claim.statement} "
        f"(evidence: {_refs(claim.evidence_refs)})"
        for claim in claims
    ]


def _refs(values: tuple[StoredDataRef, ...]) -> str:
    if not values:
        return "없음"
    return ", ".join(f"`{value.record_id or value.stored_data_id}`" for value in values)


def _inline(values: tuple[object, ...]) -> str:
    return "없음" if not values else ", ".join(str(value) for value in values)


def _indented(value: str) -> list[str]:
    return [f"    {line}" for line in value.splitlines()] or ["    "]


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
        if path.read_bytes() != data:
            raise ReportUnavailable("REPORT_EXPORT_WRITE_FAILED")
    finally:
        temporary.unlink(missing_ok=True)


__all__ = [
    "CurrentReport",
    "CurrentReportSource",
    "ReportMarkdownService",
    "ReportUnavailable",
    "render_markdown",
]
