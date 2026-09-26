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
        not isinstance(item, str) for item in restrictions
    ):
        restrictions = []
        compliance = "UNCERTAIN"
    testing_status = axes["testing"]["status"]
    if (
        testing_status == "PASS"
        and (compliance != "PASS" or restrictions)
        or testing_status == "FAIL"
        and compliance != "FAIL"
    ):
        axes["testing"] = {
            **axes["testing"],
            "status": "UNCERTAIN",
            "reason": "POLICY_TESTING_RESTRICTION_CONFLICT",
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
        if (
            not isinstance(source_refs, list)
            or body_ref.model_dump(mode="json") not in source_refs
            or not isinstance(model_result, dict)
            or not isinstance(stored_result, dict)
        ):
            return restricted("POLICY_GATE_EVIDENCE_INCOMPLETE")
        recomputed = validate_scope_decision(
            snapshot, body.decode("utf-8"), model_result
        )
        if stored_result != recomputed:
            return restricted("POLICY_GATE_DECISION_MISMATCH")
        return {
            **recomputed,
            "external_disclosure_allowed": recomputed["status"] == "ALLOW",
            "provenance_verified": True,
            "legacy_status": raw_status,
        }
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return restricted("POLICY_SOURCE_INCOMPLETE")


def safe_public_report(markdown: bytes, review: Mapping[str, object]) -> bytes:
    """Never serve an old report that still claims unverified permission."""

    if review.get("external_disclosure_allowed") is True:
        return markdown
    text = markdown.decode("utf-8", errors="replace")
    unverified_decision = (
        review.get("provenance_verified") is not True
        and review.get("legacy_status") in {"ALLOW", "DENY"}
    )
    affirmative = (
        "- 외부 제출·공개 허용: 예" in text
        or re.search(r"(?m)^- 상태: CONFIRMED\s*$", text) is not None
        or "- Rule Scope Gate: ALLOW" in text
    )
    if not unverified_decision and not affirmative:
        return markdown
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
