"""Fail-closed Scope Gate source checks and citation-based status reduction."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .github_policy import _repository_identity
from .models import STAGE_VERSION, SimpleStage, StageCheckpoint, StageStatus

AXES = ("rules", "asset_scope", "impact", "testing", "reporting")
_POLICY_PATHS = frozenset({".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"})
_BLOB_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_LIMIT_HINT = re.compile(
    r"\b(?:do\s+not|don't|must\s+not|may\s+not|should\s+not|"
    r"not\s+(?:permitted|allowed)|prohibit(?:ed|s)?|forbid(?:den)?|"
    r"avoid|never|no|must|require(?:s|d)?|unless|except|"
    r"disallow(?:ed)?|only|out[\s-]+of[\s-]+scope|"
    r"prior\s+(?:approval|permission)|"
    r"rate[\s-]?limit(?:ed)?)\b|금지|제외|제한|허용되지|해서는\s*안|"
    r"사전\s*(?:승인|허가)",
    re.IGNORECASE,
)


def verified_policy_snapshot(
    snapshot: dict[str, Any],
    policy_bytes: bytes,
    *,
    analysis_id: str,
    workspace_id: str,
    commit_id: str,
    repository_url: str,
) -> bool:
    """Check an exact run binding and official GitHub content identity."""

    target = _repository_identity(repository_url)
    if (
        target is None
        or snapshot.get("kind") != "simple_policy_snapshot"
        or snapshot.get("version") != 1
        or snapshot.get("analysis_id") != analysis_id
        or snapshot.get("workspace_id") != workspace_id
        or snapshot.get("commit_id") != commit_id
        or snapshot.get("target_repository") != repository_url
        or snapshot.get("status") != "FOUND"
        or snapshot.get("source_kind") != "github_contents_api"
        or snapshot.get("content_type") != "text/markdown"
        or not policy_bytes
        or hashlib.sha256(policy_bytes).hexdigest() != snapshot.get("body_sha256")
    ):
        return False
    owner = snapshot.get("owner")
    repo = snapshot.get("repo")
    publisher = snapshot.get("publisher")
    path = snapshot.get("source_path")
    blob_sha = snapshot.get("blob_sha")
    url_value = snapshot.get("source_url")
    checked_at = snapshot.get("checked_at")
    if (
        not isinstance(owner, str)
        or not isinstance(repo, str)
        or not isinstance(publisher, str)
        or not isinstance(path, str)
        or not isinstance(blob_sha, str)
        or not isinstance(url_value, str)
        or not isinstance(checked_at, str)
        or owner.casefold() != target[0].casefold()
        or repo.casefold() not in {target[1].casefold(), ".github"}
        or publisher.casefold() != f"{owner}/{repo}".casefold()
        or path not in _POLICY_PATHS
        or not _BLOB_SHA.fullmatch(blob_sha)
    ):
        return False
    try:
        if datetime.fromisoformat(checked_at).tzinfo is None:
            return False
        parsed = urlsplit(url_value)
        query = parse_qs(parsed.query, keep_blank_values=True)
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != "api.github.com"
        or parsed.fragment
        or parsed.path != f"/repos/{owner}/{repo}/contents/{path}"
        or set(query) != {"ref"}
        or len(query["ref"]) != 1
        or not query["ref"][0]
    ):
        return False
    computed_blob = hashlib.sha1(
        b"blob " + str(len(policy_bytes)).encode() + b"\0" + policy_bytes
    ).hexdigest()
    return computed_blob == blob_sha.casefold()


def uncertain_scope_result(
    snapshot: dict[str, Any] | None, reason: str
) -> dict[str, Any]:
    source = _source(snapshot)
    return {
        "status": "UNCERTAIN",
        "rationale": "공식 정책 근거를 완전하게 확인하지 못했습니다.",
        "checks": [reason],
        "restrictions": ["외부 제출·공개 허가가 확인되지 않았습니다."],
        "testing_restriction_compliance": "UNCERTAIN",
        "axes": {
            axis: {
                "status": "UNCERTAIN",
                "line": None,
                "quote": "",
                "reason": reason,
            }
            for axis in AXES
        },
        "missing_information": list(AXES),
        "policy_source": source,
    }


def validate_scope_decision(
    snapshot: dict[str, object],
    policy_text: str,
    model_result: Mapping[str, object],
    *,
    poc_evidence_text: str | None = None,
) -> dict[str, Any]:
    """Reduce cited per-axis judgments; never trust model-proposed ALLOW."""

    if snapshot.get("status") != "FOUND" or not policy_text:
        return uncertain_scope_result(snapshot, "POLICY_SOURCE_UNVERIFIED")
    lines = policy_text.splitlines()
    model_axes = model_result.get("axes")
    if not isinstance(model_axes, dict):
        model_axes = {}
    axes: dict[str, dict[str, object]] = {}
    missing: list[str] = []
    for name in AXES:
        raw_axis = model_axes.get(name)
        raw = raw_axis if isinstance(raw_axis, dict) else {}
        status = raw.get("status")
        line = raw.get("line")
        quote = raw.get("quote")
        reason = raw.get("reason")
        cited = (
            type(line) is int
            and 1 <= line <= len(lines)
            and isinstance(quote, str)
            and bool(quote.strip())
            and quote in lines[line - 1]
            and isinstance(reason, str)
            and bool(reason.strip())
        )
        if status not in {"PASS", "FAIL"} or not cited:
            status = "UNCERTAIN"
            line = None
            quote = ""
            reason = "POLICY_CITATION_MISSING_OR_INVALID"
            missing.append(name)
        axes[name] = {
            "status": status,
            "line": line,
            "quote": quote,
            "reason": reason,
        }
    compliance = model_result.get("testing_restriction_compliance")
    if compliance not in {"PASS", "FAIL", "UNCERTAIN"}:
        compliance = "UNCERTAIN"
    restrictions = model_result.get("restrictions")
    if not isinstance(restrictions, list) or any(
        not isinstance(item, str) or not item.strip() or item not in policy_text
        for item in restrictions
    ):
        restrictions = []
        compliance = "UNCERTAIN"
    cited_limits = {
        line.strip() for line in lines if line.strip() and _LIMIT_HINT.search(line)
    }
    if not cited_limits.issubset(set(restrictions)):
        compliance = "UNCERTAIN"
    restriction_review_required = compliance == "PASS" and bool(
        cited_limits or restrictions
    )
    if restriction_review_required:
        compliance = "UNCERTAIN"
    poc_quote = model_result.get("testing_poc_quote")
    if compliance in {"PASS", "FAIL"} and (
        not isinstance(poc_quote, str)
        or len(poc_quote.strip()) < 8
        or poc_evidence_text is None
        or poc_quote not in poc_evidence_text
        or not any(
            poc_quote in line and not line.lstrip().startswith("#")
            for line in poc_evidence_text.splitlines()
        )
    ):
        compliance = "UNCERTAIN"
    if not isinstance(poc_quote, str):
        poc_quote = ""
    testing_status = axes["testing"]["status"]
    if (
        testing_status == "PASS"
        and compliance != "PASS"
        or testing_status == "FAIL"
        and compliance != "FAIL"
    ):
        axes["testing"] = {
            **axes["testing"],
            "status": "UNCERTAIN",
            "reason": (
                "POLICY_RESTRICTIONS_REQUIRE_HUMAN_REVIEW"
                if restriction_review_required
                else "POLICY_TESTING_RESTRICTION_CONFLICT"
            ),
        }
        if "testing" not in missing:
            missing.append("testing")
    statuses = {str(axis["status"]) for axis in axes.values()}
    if "FAIL" in statuses:
        status = "DENY"
    elif statuses == {"PASS"} and compliance == "PASS" and not restrictions:
        status = "ALLOW"
    else:
        status = "UNCERTAIN"
    rationale = model_result.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        rationale = "정책 근거별 검토 결과입니다."
    return {
        "status": status,
        "rationale": rationale[:4000],
        "checks": [f"{name}:{axes[name]['status']}" for name in AXES],
        "restrictions": restrictions,
        "testing_restriction_compliance": compliance,
        "testing_poc_quote": poc_quote,
        "axes": axes,
        "missing_information": missing,
        "policy_source": _source(snapshot),
    }


def project_scope_review(
    gate: StageCheckpoint | None,
    artifacts: SimpleArtifactRepository,
    *,
    policy_snapshot_ref: StoredDataRef | None,
    repository_url: str | None,
) -> dict[str, Any]:
    """Recheck the exact Gate and source at every public read boundary."""

    raw_gate: dict[str, Any] | None = None
    raw_status: str | None = None
    try:
        if gate is not None and gate.output_refs:
            candidate = json.loads(artifacts.read(gate.output_refs[0]))
            if isinstance(candidate, dict):
                raw_gate = candidate
                raw_result = candidate.get("result")
                if isinstance(raw_result, dict) and isinstance(
                    raw_result.get("status"), str
                ):
                    raw_status = raw_result["status"]
    except (OSError, ValueError, TypeError, sqlite3.Error):
        pass

    def restricted(
        reason: str, snapshot: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return {
            **uncertain_scope_result(snapshot, reason),
            "private_reporting_policy_passed": False,
            "external_disclosure_allowed": False,
            "provenance_verified": False,
            "legacy_status": raw_status,
        }

    if (
        gate is None
        or gate.stage is not SimpleStage.SCOPE_GATE_DONE
        or gate.stage_version != STAGE_VERSION[SimpleStage.SCOPE_GATE_DONE]
        or gate.status is not StageStatus.SUCCEEDED
        or policy_snapshot_ref is None
        or policy_snapshot_ref not in gate.input_refs
        or repository_url is None
        or raw_gate is None
        or raw_gate.get("kind") != "simple_rule_scope_gate"
        or raw_gate.get("policy_snapshot_ref")
        != policy_snapshot_ref.model_dump(mode="json")
        or raw_gate.get("attempt_id") != gate.attempt_id
    ):
        return restricted("POLICY_GATE_PROVENANCE_UNVERIFIED")
    try:
        snapshot = json.loads(artifacts.read(policy_snapshot_ref))
        if not isinstance(snapshot, dict):
            return restricted("POLICY_SNAPSHOT_INVALID")
        if (
            snapshot.get("kind") != "simple_policy_snapshot"
            or snapshot.get("version") != 1
            or snapshot.get("analysis_id") != gate.identity.analysis_id
            or snapshot.get("workspace_id") != gate.identity.workspace_id
            or snapshot.get("commit_id") != gate.identity.commit_id
            or snapshot.get("target_repository") != repository_url
        ):
            return restricted("POLICY_SNAPSHOT_UNVERIFIED")
        if snapshot.get("status") != "FOUND":
            return restricted(
                str(snapshot.get("reason_code", "POLICY_SOURCE_UNVERIFIED")),
                snapshot,
            )
        body_ref = StoredDataRef.model_validate(snapshot.get("body_ref"))
        body = artifacts.read(body_ref)
        if not verified_policy_snapshot(
            snapshot,
            body,
            analysis_id=gate.identity.analysis_id,
            workspace_id=gate.identity.workspace_id,
            commit_id=gate.identity.commit_id,
            repository_url=repository_url,
        ):
            return restricted("POLICY_SNAPSHOT_UNVERIFIED")
        source_refs = raw_gate.get("source_refs")
        model_result = raw_gate.get("model_result")
        stored_result = raw_gate.get("result")
        if not isinstance(source_refs, list) or not isinstance(stored_result, dict):
            return restricted("POLICY_GATE_EVIDENCE_INCOMPLETE")
        if not isinstance(model_result, dict):
            reason = _preserved_stage_uncertain_reason(
                raw_gate, snapshot, source_refs, stored_result
            )
            return restricted(reason or "POLICY_GATE_EVIDENCE_INCOMPLETE", snapshot)
        poc_evidence_text = _verified_gate_poc_evidence(
            artifacts, source_refs, body_ref
        )
        if poc_evidence_text is None:
            return restricted("POLICY_GATE_EVIDENCE_INCOMPLETE", snapshot)
        recomputed = validate_scope_decision(
            snapshot,
            body.decode("utf-8"),
            model_result,
            poc_evidence_text=poc_evidence_text,
        )
        if stored_result != recomputed:
            return restricted("POLICY_GATE_DECISION_MISMATCH")
        return {
            **recomputed,
            "private_reporting_policy_passed": recomputed["status"] == "ALLOW",
            "external_disclosure_allowed": False,
            "provenance_verified": True,
            "legacy_status": raw_status,
        }
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return restricted("POLICY_SOURCE_INCOMPLETE")


def _preserved_stage_uncertain_reason(
    raw_gate: dict[str, Any],
    snapshot: dict[str, Any],
    source_refs: list[object],
    stored_result: dict[str, Any],
) -> str | None:
    if source_refs or "model_result" in raw_gate:
        return None
    checks = stored_result.get("checks")
    if not isinstance(checks, list) or len(checks) != 1:
        return None
    reason = checks[0]
    if not isinstance(reason, str) or reason not in {
        "POLICY_TECHNICAL_CONTEXT_MISSING",
        "POLICY_POC_CONTEXT_UNVERIFIED",
        "POLICY_SOURCE_INCOMPLETE",
    }:
        return None
    return (
        reason
        if stored_result
        in (
            uncertain_scope_result(snapshot, reason),
            uncertain_scope_result(None, reason),
        )
        else None
    )


def _verified_gate_poc_evidence(
    artifacts: SimpleArtifactRepository,
    source_refs: list[object],
    body_ref: StoredDataRef,
) -> str | None:
    if len(source_refs) != 6:
        return None
    refs = tuple(StoredDataRef.model_validate(value) for value in source_refs)
    if refs[0] != body_ref:
        return None
    _, content_ref, validated_ref, technical_ref, execution_ref, verification_ref = refs
    content = artifacts.read(content_ref)
    if not content:
        return None
    validated = json.loads(artifacts.read(validated_ref))
    technical = json.loads(artifacts.read(technical_ref))
    execution = json.loads(artifacts.read(execution_ref))
    verification = json.loads(artifacts.read(verification_ref))
    if not all(
        isinstance(value, dict)
        for value in (validated, technical, execution, verification)
    ):
        return None
    candidate_ref = StoredDataRef.model_validate(validated.get("candidate_ref"))
    candidate = json.loads(artifacts.read(candidate_ref))
    if not isinstance(candidate, dict):
        return None
    candidate_json = candidate_ref.model_dump(mode="json")
    content_json = content_ref.model_dump(mode="json")
    validated_json = validated_ref.model_dump(mode="json")
    execution_json = execution_ref.model_dump(mode="json")
    verification_json = verification_ref.model_dump(mode="json")
    technical_result = technical.get("result")
    verification_result = verification.get("result")
    if (
        candidate.get("kind") != "simple_poc_candidate"
        or execution.get("kind") != "simple_poc_execution"
        or validated.get("kind") != "simple_validated_poc"
        or technical.get("kind") != "simple_technical_gate"
        or verification.get("kind") != "simple_verification_result"
        or candidate.get("content_ref") != content_json
        or execution.get("candidate_ref") != candidate_json
        or execution.get("content_ref") != content_json
        or validated.get("candidate_ref") != candidate_json
        or validated.get("content_ref") != content_json
        or validated.get("execution_ref") != execution_json
        or not isinstance(execution.get("attempt_id"), str)
        or not execution["attempt_id"]
        or validated.get("attempt_id") != execution["attempt_id"]
        or not isinstance(verification_result, dict)
        or verification_result.get("verdict") != "TRUE"
        or not isinstance(technical_result, dict)
        or technical_result.get("status") != "ACCEPT"
        or not isinstance(verification.get("source_refs"), list)
        or validated_json not in verification["source_refs"]
        or execution_json not in verification["source_refs"]
        or not isinstance(technical.get("source_refs"), list)
        or validated_json not in technical["source_refs"]
        or execution_json not in technical["source_refs"]
        or verification_json not in technical["source_refs"]
    ):
        return None
    return content.decode("utf-8")


def safe_public_report(markdown: bytes, review: Mapping[str, object]) -> bytes:
    """Never serve an old report that still claims unverified permission."""

    text = markdown.decode("utf-8", errors="replace")
    if "- 외부 제출·공개 허용: 예" in text or "- 외부 공개 허용: 예" in text:
        return _restricted_public_report(review)
    if review.get("provenance_verified") is True and review.get("status") == "ALLOW":
        return markdown
    unverified_decision = review.get("provenance_verified") is not True and review.get(
        "legacy_status"
    ) in {"ALLOW", "DENY"}
    affirmative = (
        "- 외부 제출·공개 허용: 예" in text
        or re.search(r"(?m)^- 상태: CONFIRMED\s*$", text) is not None
        or "- Rule Scope Gate: ALLOW" in text
    )
    if not unverified_decision and not affirmative:
        return markdown
    return _restricted_public_report(review)


def _restricted_public_report(review: Mapping[str, object]) -> bytes:
    source = review.get("policy_source")
    collection = (
        source.get("collection_status", "UNVERIFIED")
        if isinstance(source, dict)
        else "UNVERIFIED"
    )
    checks = review.get("checks")
    reason = checks[0] if isinstance(checks, list) and checks else "POLICY_UNVERIFIED"
    return (
        "# 정책 검증 대기 — 제보 불가\n\n"
        "기술 분석 기록은 유지되지만, 이 보고서의 외부 제출·공개 허가는 "
        "검증되지 않았습니다. 원본은 내부 기록으로만 보관합니다.\n\n"
        "- 상태: CONFIRMED_RESTRICTED\n"
        "- Rule Scope Gate: UNCERTAIN\n"
        f"- 정책 수집 상태: {collection}\n"
        f"- 이유: {reason}\n"
        "- 외부 제출·공개 허용: 아니요\n"
    ).encode()


def _source(snapshot: dict[str, Any] | None) -> dict[str, object]:
    value = snapshot or {}
    found = value.get("status") == "FOUND"
    return {
        "collection_status": value.get("status", "UNVERIFIED"),
        "reason_code": value.get("reason_code", "POLICY_SOURCE_UNVERIFIED"),
        "publisher": value.get("publisher") if found else None,
        "source_url": value.get("source_url") if found else None,
        "source_path": value.get("source_path") if found else None,
        "blob_sha": value.get("blob_sha") if found else None,
        "body_sha256": value.get("body_sha256") if found else None,
        "checked_at": value.get("checked_at"),
    }


__all__ = [
    "AXES",
    "project_scope_review",
    "safe_public_report",
    "uncertain_scope_result",
    "validate_scope_decision",
    "verified_policy_snapshot",
]
