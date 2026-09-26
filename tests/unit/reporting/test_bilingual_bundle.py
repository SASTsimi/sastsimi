"""The portable Finding bundle has one factual spine and two prose languages."""

import hashlib
import json
from dataclasses import replace
from typing import Any, cast

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import BilingualReportContent
from sastsimi.contracts.static import CodeLocation
from sastsimi.reporting.bilingual_bundle import (
    BundleFacts,
    BundleFile,
    render_bundle_files,
)


def _ref(kind: str, digest: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": kind,
            "data_kind": kind,
            "content_hash": digest,
            "workspace_id": "ws-1",
            "commit_id": "a" * 40,
            "record_id": kind,
        }
    )


def _facts(**changes: object) -> BundleFacts:
    poc_digest = hashlib.sha256(b"#!/bin/sh\necho safe\n").hexdigest()
    base = BundleFacts(
        analysis_id="A-004",
        display_id="F-002",
        finding_id="finding-2",
        repository="example/project",
        tested_commit="a" * 40,
        cwe="CWE-79",
        ecosystem=None,
        package_name=None,
        affected_versions=None,
        patched_versions=None,
        severity=None,
        technical_status="ACCEPTED",
        scope_status="UNCERTAIN",
        report_permission="REVIEW_REQUIRED",
        execution_command="/bin/sh /tmp/sastsimi-poc-candidate",
        exit_code=0,
        poc_language="shell",
        poc_original_sha256=poc_digest,
        source_refs=(
            ("finding", _ref("finding", "b" * 64)),
            ("poc", _ref("poc_bundle", "c" * 64)),
        ),
    )
    # Tests intentionally pass invalid field values to exercise runtime validation.
    return replace(base, **cast(dict[str, Any], changes))


def _content() -> BilingualReportContent:
    return BilingualReportContent.model_validate_json(
        json.dumps(
            {
                "schema_version": 2,
                "en": {
                    "title": "Example Finding",
                    "summary": "One tested flow is vulnerable.",
                    "details": "The input reaches the output.",
                    "impact": "An attacker may read data.",
                    "recommendation": "Validate the input.",
                    "limitations": ["Only one commit was tested."],
                    "review_items": ["Check affected releases."],
                },
                "ko": {
                    "title": "예시 발견",
                    "summary": "테스트한 흐름 하나에서 취약성이 확인되었습니다.",
                    "details": "입력이 출력에 도달합니다.",
                    "impact": "공격자가 데이터를 읽을 수 있습니다.",
                    "recommendation": "입력을 검증하세요.",
                    "limitations": ["한 커밋만 테스트했습니다."],
                    "review_items": ["영향받는 릴리스를 확인하세요."],
                },
                "citations": [],
            }
        )
    )


def _render(
    *,
    facts: BundleFacts | None = None,
    poc: bytes = b"#!/bin/sh\necho safe\n",
    stdout: bytes | None = None,
    stderr: bytes | None = None,
) -> dict[str, BundleFile]:
    return {
        item.path: item
        for item in render_bundle_files(
            facts or _facts(), _content(), poc=poc, stdout=stdout, stderr=stderr
        )
    }


def test_bilingual_reports_share_section_order_and_exact_facts() -> None:
    files = _render()
    assert set(files) == {
        "report_en.md",
        "report_kr.md",
        "poc.sh",
        "evidence/provenance.json",
    }
    en = files["report_en.md"].body.decode()
    ko = files["report_kr.md"].body.decode()
    assert [line for line in en.splitlines() if line.startswith("## ")] == [
        "## Summary",
        "## Affected products and tested version",
        "## Severity and weakness",
        "## Technical details",
        "## Reproduction and PoC",
        "## Evidence",
        "## Impact",
        "## Scope Gate and limitations",
        "## Remediation",
    ]
    assert len([line for line in ko.splitlines() if line.startswith("## ")]) == 9
    for value in ("A-004", "F-002", "a" * 40, "CWE-79", "UNCERTAIN", "REVIEW_REQUIRED"):
        assert value in en
        assert value in ko
    assert "Needs review" in en
    assert "검토 필요" in ko
    assert "report_en.md" not in en  # Report prose does not invent a new source.
    assert files["poc.sh"].body == b"#!/bin/sh\necho safe\n"
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert (
        provenance["poc"]["original_sha256"]
        == hashlib.sha256(files["poc.sh"].body).hexdigest()
    )
    assert provenance["poc"]["redacted"] is False
    assert provenance["sources"]["finding"]["content_hash"] == "b" * 64
    assert provenance["sources"]["poc"]["content_hash"] == "c" * 64


def test_unverified_metadata_cannot_be_filled_by_reporter_prose() -> None:
    files = _render()
    en = files["report_en.md"].body.decode()
    ko = files["report_kr.md"].body.decode()
    assert "Affected versions: Needs review" in en
    assert "Patched versions: Needs review" in en
    assert "Severity: Needs review" in en
    assert "영향받는 버전: 검토 필요" in ko
    assert "수정된 버전: 검토 필요" in ko
    assert "심각도: 검토 필요" in ko


@pytest.mark.parametrize(
    ("language", "field", "text"),
    [
        ("en", "impact", "CVSS 3.1 score: 9.8."),
        ("en", "summary", "Severity is Critical."),
        ("en", "details", "Versions before 1.2.3 are affected."),
        ("en", "recommendation", "This was fixed in v1.2.4."),
        ("en", "summary", "This is safe to publish."),
        ("ko", "impact", "CVSS 점수는 9.8입니다."),
        ("ko", "details", "1.2.3 이전 버전이 영향을 받습니다."),
        ("ko", "summary", "공개 제보가 가능합니다."),
    ],
)
def test_unsupported_metadata_claims_in_prose_are_rejected(
    language: str, field: str, text: str
) -> None:
    content = _content()
    prose = getattr(content, language).model_copy(update={field: text})
    content = content.model_copy(update={language: prose})

    with pytest.raises(ValueError, match="REPORT_UNSUPPORTED_METADATA_CLAIM"):
        render_bundle_files(
            _facts(), content, poc=b"#!/bin/sh\necho safe\n", stdout=None, stderr=None
        )


def test_citation_subrange_is_rendered_in_both_reports() -> None:
    allowed = CodeLocation.model_validate(
        {
            "workspace_id": "ws-1",
            "commit_id": "a" * 40,
            "file_path": "src/app.py",
            "start_line": 10,
            "start_column": None,
            "end_line": 20,
            "end_column": None,
        }
    )
    citation = allowed.model_copy(update={"start_line": 12, "end_line": 13})
    content = _content().model_copy(update={"citations": (citation,)})

    files = {
        item.path: item
        for item in render_bundle_files(
            _facts(allowed_locations=(allowed,)),
            content,
            poc=b"#!/bin/sh\necho safe\n",
            stdout=None,
            stderr=None,
        )
    }

    for path in ("report_en.md", "report_kr.md"):
        assert "- src/app.py:12-13" in files[path].body.decode()


def test_redacted_poc_and_output_are_labeled_not_exactly_executed() -> None:
    raw = b"#!/bin/sh\necho sk-Abcdefghijk99999\n"
    files = _render(
        facts=_facts(
            poc_original_sha256=hashlib.sha256(raw).hexdigest(),
            source_refs=(
                ("finding", _ref("finding", "b" * 64)),
                ("poc", _ref("poc_bundle", "c" * 64)),
                ("stdout", _ref("sandbox_output", "d" * 64)),
            ),
        ),
        poc=raw,
        stdout=b"authorization=Bearer verysecretvalue\n",
    )
    for item in files.values():
        assert b"sk-Abcdefghijk99999" not in item.body
        assert b"verysecretvalue" not in item.body
    assert "evidence/stdout.txt" in files
    assert "evidence/stderr.txt" not in files
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["poc"]["redacted"] is True
    assert provenance["poc"]["original_sha256"] == hashlib.sha256(raw).hexdigest()
    assert (
        provenance["poc"]["attachment_sha256"]
        == hashlib.sha256(files["poc.sh"].body).hexdigest()
    )
    assert "not the exact executed bytes" in files["report_en.md"].body.decode()
    assert "실행된 원본과 동일하지" in files["report_kr.md"].body.decode()


def test_bundle_file_and_poc_language_reject_unsupported_paths() -> None:
    for path in ("../poc.sh", "report_fr.md", "evidence/other.txt"):
        with pytest.raises(ValueError, match="BUNDLE_FILE_PATH_INVALID"):
            BundleFile(path, b"data", "text/plain")
    with pytest.raises(ValueError, match="POC_LANGUAGE_UNSUPPORTED"):
        _facts(poc_language="ruby")
