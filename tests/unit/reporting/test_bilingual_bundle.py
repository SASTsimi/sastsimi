"""The portable Finding bundle has one factual spine and two prose languages."""

import hashlib
import json
from dataclasses import replace
from typing import Any, cast

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import (
    BilingualReportContent,
    has_legacy_report_ipv4_false_positive,
)
from sastsimi.contracts.static import CodeLocation
from sastsimi.reporting.bilingual_bundle import (
    BundleFacts,
    BundleFile,
    render_bundle_files,
)
from sastsimi.reporting.coverage_disclosure import coverage_disclosure


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
    assert provenance["static_coverage"] is None
    assert (
        provenance["poc"]["original_sha256"]
        == hashlib.sha256(files["poc.sh"].body).hexdigest()
    )
    assert provenance["poc"]["redacted"] is False
    assert provenance["sources"]["finding"]["content_hash"] == "b" * 64
    assert provenance["sources"]["poc"]["content_hash"] == "c" * 64


def test_local_repository_path_is_redacted_from_bundle_metadata() -> None:
    repository = "file:///C:/Users/example/private/source"

    files = _render(facts=_facts(repository=repository))

    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["repository"] != repository
    for path in ("report_en.md", "report_kr.md", "evidence/provenance.json"):
        assert repository.encode() not in files[path].body


@pytest.mark.parametrize(
    "repository",
    (
        "file:///mnt/private-project/source",
        "file://server/private-share/source",
        "FILE:relative/private-source",
    ),
)
def test_any_file_repository_url_is_redacted_from_bundle_metadata(
    repository: str,
) -> None:
    files = _render(facts=_facts(repository=repository))

    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["repository"] != repository
    for path in ("report_en.md", "report_kr.md", "evidence/provenance.json"):
        assert repository.encode() not in files[path].body


@pytest.mark.parametrize(
    "language, local_url",
    (
        ("en", "file:///mnt/private-project/source"),
        ("ko", "FILE://server/private-share/source"),
        ("en", "file:///C:/Users/example/private/source"),
        ("ko", "file:relative/private-source"),
        ("en", "file:///C:/Program Files/private/report.txt"),
        ("ko", "file:relative/private folder/report.txt"),
        ("en", "file:///C:/Users/Smith,John/private/report.txt"),
        ("ko", "file:relative/private;archive/report.txt"),
    ),
)
def test_bundle_redacts_file_url_echoed_in_model_prose(
    language: str, local_url: str
) -> None:
    content = _content()
    prose = getattr(content, language).model_copy(
        update={
            "details": (
                f"Review local source {local_url}, then consult "
                "https://example.org/docs."
            )
        }
    )
    content = content.model_copy(update={language: prose})

    for _ in range(2):  # A saved draft can be rendered on every resume.
        files = {
            item.path: item
            for item in render_bundle_files(
                _facts(),
                content,
                poc=b"#!/bin/sh\necho safe\n",
                stdout=None,
                stderr=None,
            )
        }
        body = files["report_kr.md" if language == "ko" else "report_en.md"].body
        assert b"Review local source [REDACTED:LOCAL_FILE_URL]" in body
        assert b"then consult" not in body
        assert b"https://example.org/docs." not in body
        assert local_url.encode() not in body
        assert all(local_url.encode() not in item.body for item in files.values())
    assert local_url in prose.details


def test_bundle_redacts_file_urls_from_every_prose_field() -> None:
    content = _content()
    local_url = "file:///mnt/private-project/source?version=private"
    prose = content.en.model_copy(
        update={
            "title": f"Title {local_url}",
            "summary": f"Summary {local_url}",
            "details": f"Details {local_url}.",
            "impact": f"Impact {local_url}",
            "recommendation": f"Recommendation {local_url}",
            "limitations": (f"Limit {local_url}",),
            "review_items": (f"Review {local_url}",),
        }
    )
    content = content.model_copy(update={"en": prose})

    files = {
        item.path: item
        for item in render_bundle_files(
            _facts(),
            content,
            poc=b"#!/bin/sh\necho safe\n",
            stdout=None,
            stderr=None,
        )
    }
    body = files["report_en.md"].body
    assert body.count(b"[REDACTED:LOCAL_FILE_URL]") == 7
    assert local_url.encode() not in body
    assert b"Details [REDACTED:LOCAL_FILE_URL]" in body


def test_https_repository_url_is_preserved_in_bundle_metadata() -> None:
    repository = "https://example.com/organization/project"

    files = _render(facts=_facts(repository=repository))

    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["repository"] == repository
    assert repository.encode() in files["report_en.md"].body
    assert repository.encode() in files["report_kr.md"].body


def test_partial_coverage_is_disclosed_equally_without_embedding_ledger() -> None:
    coverage_ref = _ref("coverage", "d" * 64)
    coverage = coverage_disclosure(
        {
            "kind": "simple_static_coverage_v1",
            "fingerprint": "e" * 64,
            "analysis_id": "A-004",
            "workspace_id": "ws-1",
            "commit_id": "a" * 40,
            "expected_count": 100000,
            "verified_count": 12,
            "gaps": [
                {
                    "path": f"secret-{index}.py",
                    "rule_id": "r1",
                    "reason": "not_attempted_budget",
                }
                for index in range(99988)
            ],
            "unsupported_files": [
                {"path": "Dockerfile", "reason": "unsupported_language"}
            ],
            "engine_errors": ["opengrep_timeout"],
        },
        coverage_ref,
        analysis_id="A-004",
        workspace_id="ws-1",
        commit_id="a" * 40,
    )
    files = _render(facts=_facts(coverage=coverage))
    for name in ("report_en.md", "report_kr.md"):
        body = files[name].body.decode()
        assert "PARTIAL" in body
        assert "12 / 100000" in body
        assert "99988" in body
        assert "unsupported_language" in body
        assert "not_attempted_budget" in body
        assert "d" * 64 in body
        assert "secret-99987.py" not in body
        assert len(body) < 20000
    assert "confirmed Finding" in files["report_en.md"].body.decode()
    assert "Finding 확인" in files["report_kr.md"].body.decode()
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["static_coverage"]["scope"] == "python_only"
    assert provenance["static_coverage"]["disposition"] == "PARTIAL"
    assert provenance["static_coverage"]["verified_count"] == 12
    assert provenance["static_coverage"]["ref"]["content_hash"] == "d" * 64


def test_bilingual_report_discloses_excluded_tests_and_out_of_scope_code() -> None:
    coverage = coverage_disclosure(
        {
            "kind": "simple_static_coverage_v1",
            "fingerprint": "e" * 64,
            "analysis_id": "A-004",
            "workspace_id": "ws-1",
            "commit_id": "a" * 40,
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported_files": [],
            "excluded_test_files": [
                {"path": "tests/test_api.py", "reason": "test-directory:tests"}
            ],
            "out_of_scope_product_files": [
                {"path": "web/app.ts", "reason": "non_python_product_source"}
            ],
            "engine_errors": [],
        },
        _ref("coverage", "d" * 64),
        analysis_id="A-004",
        workspace_id="ws-1",
        commit_id="a" * 40,
    )

    files = _render(facts=_facts(coverage=coverage))
    en = files["report_en.md"].body.decode()
    ko = files["report_kr.md"].body.decode()
    assert coverage.partial is False
    assert "Excluded test files: 1" in en
    assert "제외된 테스트 파일: 1" in ko
    assert "tests/test_api.py" in en and "tests/test_api.py" in ko
    assert "Out-of-scope product files: 1" in en
    assert "검사 범위 밖 제품 파일: 1" in ko
    assert "web/app.ts" in en and "web/app.ts" in ko
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["static_coverage"]["scope"] == "python_only"
    assert provenance["static_coverage"]["disposition"] == "FULL"
    assert provenance["static_coverage"]["excluded_test_file_count"] == 1
    assert provenance["static_coverage"]["out_of_scope_product_count"] == 1


def test_bilingual_report_discloses_unavailable_python_paths_separately() -> None:
    coverage = coverage_disclosure(
        {
            "kind": "simple_static_coverage_v1",
            "fingerprint": "e" * 64,
            "analysis_id": "A-004",
            "workspace_id": "ws-1",
            "commit_id": "a" * 40,
            "expected_count": 0,
            "verified_count": 0,
            "gaps": [],
            "unsupported_files": [],
            "unavailable_paths": [
                {"path": "src/a.py", "reason": "OPENGREP_EXECUTION_FAILED"},
                {"path": "src/b.py", "reason": "OPENGREP_EXECUTION_FAILED"},
            ],
            "engine_errors": ["OPENGREP_EXECUTION_FAILED"],
        },
        _ref("coverage", "d" * 64),
        analysis_id="A-004",
        workspace_id="ws-1",
        commit_id="a" * 40,
        disposition="PARTIAL",
    )
    files = _render(facts=_facts(coverage=coverage))
    en = files["report_en.md"].body.decode()
    ko = files["report_kr.md"].body.decode()
    assert coverage.partial is True
    assert "Unverified pairs: 0" in en
    assert "검증되지 않은 쌍: 0" in ko
    assert "Unavailable Python source files: 2" in en
    assert "미검증 Python 소스 파일: 2" in ko
    assert "src/a.py" in en and "src/a.py" in ko
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["static_coverage"]["unavailable_file_count"] == 2
    assert provenance["static_coverage"]["gap_count"] == 0


@pytest.mark.parametrize(
    ("key", "unsafe_path"),
    [
        ("excluded_test_files", r"tests\test_api.py"),
        ("out_of_scope_product_files", r"web\app.ts"),
    ],
)
def test_coverage_rejects_windows_separator_in_scope_path(
    key: str, unsafe_path: str
) -> None:
    data: dict[str, object] = {
        "kind": "simple_static_coverage_v1",
        "fingerprint": "e" * 64,
        "analysis_id": "A-004",
        "workspace_id": "ws-1",
        "commit_id": "a" * 40,
        "expected_count": 1,
        "verified_count": 1,
        "gaps": [],
        "unsupported_files": [],
        "engine_errors": [],
        key: [{"path": unsafe_path, "reason": "test-directory:tests"}],
    }
    with pytest.raises(ValueError, match="REPORT_STATIC_COVERAGE_INVALID"):
        coverage_disclosure(
            data,
            _ref("coverage", "d" * 64),
            analysis_id="A-004",
            workspace_id="ws-1",
            commit_id="a" * 40,
        )


def test_full_disposition_rejects_unverified_python_stub() -> None:
    with pytest.raises(ValueError, match="REPORT_STATIC_COVERAGE_DISPOSITION_INVALID"):
        coverage_disclosure(
            {
                "kind": "simple_static_coverage_v1",
                "fingerprint": "e" * 64,
                "analysis_id": "A-004",
                "workspace_id": "ws-1",
                "commit_id": "a" * 40,
                "expected_count": 1,
                "verified_count": 1,
                "gaps": [],
                "unsupported_files": [],
                "excluded_test_files": [],
                "out_of_scope_product_files": [
                    {"path": "api/types.pyi", "reason": "python_stub_not_scanned"}
                ],
            },
            _ref("coverage", "d" * 64),
            analysis_id="A-004",
            workspace_id="ws-1",
            commit_id="a" * 40,
            disposition="FULL",
        )


def test_legacy_bundle_does_not_claim_full_static_coverage() -> None:
    files = _render()
    assert "coverage unknown" in files["report_en.md"].body.decode()
    assert "분석 범위 미확인" in files["report_kr.md"].body.decode()
    assert "confirmed Finding" in files["report_en.md"].body.decode()
    assert "Finding 확인" in files["report_kr.md"].body.decode()


def test_coverage_rejects_wrong_analysis_scope() -> None:
    with pytest.raises(ValueError, match="REPORT_STATIC_COVERAGE_SCOPE_INVALID"):
        coverage_disclosure(
            {
                "kind": "simple_static_coverage_v1",
                "analysis_id": "different-analysis",
                "workspace_id": "ws-1",
                "commit_id": "a" * 40,
                "fingerprint": "e" * 64,
                "expected_count": 1,
                "verified_count": 1,
                "gaps": [],
                "unsupported_files": [],
                "engine_errors": [],
            },
            _ref("coverage", "d" * 64),
            analysis_id="A-004",
            workspace_id="ws-1",
            commit_id="a" * 40,
        )


def test_localized_ast_failure_keeps_coverage_partial() -> None:
    coverage = coverage_disclosure(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": "A-004",
            "workspace_id": "ws-1",
            "commit_id": "a" * 40,
            "fingerprint": "e" * 64,
            "expected_count": 2,
            "verified_count": 2,
            "gaps": [],
            "unsupported_files": [],
            "engine_errors": [],
            "ast_parse_error_count": 1,
        },
        _ref("coverage", "d" * 64),
        analysis_id="A-004",
        workspace_id="ws-1",
        commit_id="a" * 40,
    )
    files = _render(facts=_facts(coverage=coverage))
    assert "PARTIAL" in files["report_en.md"].body.decode()
    assert "ast_parse_errors" in files["report_kr.md"].body.decode()


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
        ("en", "details", "Affected version 1.2.3."),
        ("en", "details", "This affects 1.2.3."),
        ("en", "details", "This affects 1.2.3.4."),
        ("en", "details", "Affected in 1.2.3."),
        ("en", "details", "Affected:1.2.3."),
        ("en", "details", "Affected: product-1.2.3."),
        ("en", "details", "1.2.3 is affected."),
        ("en", "details", "1.2.3.4 is affected."),
        ("en", "details", "Affected build 1.2.3.4 on the server."),
        ("en", "details", "The server version 1.2.3.4 was affected."),
        ("en", "details", "1.2.3.4"),
        ("en", "details", "1.2.3 versions are affected."),
        (
            "en",
            "details",
            "PoC: http://localhost:8000/?version=1.2.3. This affects 2.3.4.",
        ),
        ("en", "recommendation", "This was fixed in v1.2.4."),
        ("en", "summary", "This is safe to publish."),
        ("ko", "impact", "CVSS 점수는 9.8입니다."),
        ("ko", "details", "1.2.3 이전 버전이 영향을 받습니다."),
        ("ko", "details", "영향받는 버전 1.2.3."),
        ("ko", "details", "1.2.3 버전이 영향을 받습니다."),
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


@pytest.mark.parametrize(
    ("address", "limitation"),
    [
        ("127.0.0.1", "The direct-run configuration binds to 127.0.0.1."),
        ("127.0.0.1", "The PoC connects to: 127.0.0.1 only."),
        ("192.168.1.20", "The local PoC connects to 192.168.1.20 only."),
        ("8.8.8.8", "The local PoC connects to 8.8.8.8 only."),
        (
            "127.0.0.1",
            "The standalone server defaults to 127.0.0.1, while the deployed "
            "bind address is unverified.",
        ),
        (
            "127.0.0.1",
            "The app defaults to 127.0.0.1; external reachability is unverified.",
        ),
        (
            "127.0.0.1",
            "The request notes the default 127.0.0.1 bind; reachability is unverified.",
        ),
        (
            "127.0.0.1",
            "The server defaults to 127.0.0.1; the affected version is not verified.",
        ),
        (
            "127.0.0.1",
            "The default listener is 127.0.0.1, which limits default network exposure.",
        ),
    ],
)
def test_report_prose_accepts_bare_ipv4_poc_endpoint(
    address: str, limitation: str
) -> None:
    content = _content()
    en = content.en.model_copy(update={"limitations": (limitation,)})
    content = content.model_copy(update={"en": en})

    files = {
        item.path: item
        for item in render_bundle_files(
            _facts(), content, poc=b"#!/bin/sh\necho safe\n", stdout=None, stderr=None
        )
    }

    assert address in files["report_en.md"].body.decode()


@pytest.mark.parametrize(
    "limitation",
    [
        "기본 수신 주소는 127.0.0.1이므로 기본 설정의 네트워크 노출은 제한됩니다.",
        "기본 수신 주소는 127.0.0.1 이므로 기본 설정의 네트워크 노출은 제한됩니다.",
    ],
)
def test_report_prose_accepts_korean_listener_ipv4_limitation(
    limitation: str,
) -> None:
    content = _content()
    ko = content.ko.model_copy(update={"limitations": (limitation,)})
    content = content.model_copy(update={"ko": ko})

    files = {
        item.path: item
        for item in render_bundle_files(
            _facts(), content, poc=b"#!/bin/sh\necho safe\n", stdout=None, stderr=None
        )
    }

    assert "기본 수신 주소는 127.0.0.1" in files["report_kr.md"].body.decode()


@pytest.mark.parametrize(
    ("language", "limitation"),
    [
        ("en", "The local test server defaults to 127.0.0.1."),
        ("en", "The default listener is 127.0.0.1, which limits default exposure."),
        ("ko", "기본 수신 주소는 127.0.0.1이므로 외부 노출이 제한됩니다."),
        ("ko", "기본 수신 주소는 127.0.0.1 이므로 외부 노출이 제한됩니다."),
    ],
)
def test_report_replay_recognizes_endpoint_false_positive(
    language: str, limitation: str
) -> None:
    content = _content()
    prose = getattr(content, language).model_copy(update={"limitations": (limitation,)})
    content = content.model_copy(update={language: prose})

    assert has_legacy_report_ipv4_false_positive(content)


@pytest.mark.parametrize(
    "claim",
    [
        "The default listener version is 1.2.3.4.",
        "The default listener is 1.2.3.4 as its release version.",
        "The release <= 1.2.3.4 is affected; the default listener is unknown.",
    ],
)
def test_report_replay_does_not_misidentify_version_claim_as_endpoint(
    claim: str,
) -> None:
    content = _content()
    en = content.en.model_copy(update={"limitations": (claim,)})
    content = content.model_copy(update={"en": en})

    assert not has_legacy_report_ipv4_false_positive(content)


@pytest.mark.parametrize(
    "claim",
    [
        "The release defaults to 1.2.3.4.",
        "The default 1.2.3.4 version is affected.",
        "The app defaults to 1.2.3.4 as its release version.",
        "The default listener version is 1.2.3.4.",
        "The release <= 1.2.3.4 is affected; the default listener is unknown.",
        "기본 수신 주소의 버전은 1.2.3.4입니다.",
    ],
)
def test_report_ipv4_wording_does_not_allow_version_claims(claim: str) -> None:
    content = _content()
    en = content.en.model_copy(update={"limitations": (claim,)})
    content = content.model_copy(update={"en": en})

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


def test_validated_shell_poc_keeps_container_tmp_path_and_exact_bytes() -> None:
    poc = (
        b"#!/bin/sh\nset -eu\n"
        b"fixture=/tmp/sastsimi-fixture\n"
        b"printf 'safe' > \"$fixture\"\n"
    )
    digest = hashlib.sha256(poc).hexdigest()

    files = _render(facts=_facts(poc_original_sha256=digest), poc=poc)

    assert files["poc.sh"].body == poc
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["poc"] == {
        "path": "poc.sh",
        "original_sha256": digest,
        "attachment_sha256": digest,
        "redacted": False,
    }
    assert (
        "attached PoC bytes match the validated original"
        in files["report_en.md"].body.decode()
    )
    assert (
        "첨부된 PoC 바이트는 검증된 원본과 동일" in files["report_kr.md"].body.decode()
    )


def test_validated_shell_poc_keeps_multiple_container_tmp_paths_on_one_line() -> None:
    poc = (
        b"#!/bin/sh\nset -eu\nprintf fixture > /tmp/source\n"
        b"cp /tmp/source /tmp/destination\n"
    )
    digest = hashlib.sha256(poc).hexdigest()

    files = _render(facts=_facts(poc_original_sha256=digest), poc=poc)

    assert files["poc.sh"].body == poc
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["poc"]["original_sha256"] == digest
    assert provenance["poc"]["attachment_sha256"] == digest
    assert provenance["poc"]["redacted"] is False


def test_shell_poc_preserves_tmp_path_in_command_substitution() -> None:
    poc = (
        b"#!/bin/sh\nset -eu\n"
        b"scratch=$(mktemp -d /tmp/sastsimi.XXXXXX) || { "
        b"printf '%s\\n' 'scratch setup failed' >&2; exit 2; }\n"
        b"trap 'rm -rf \"$scratch\"' EXIT\n"
    )
    digest = hashlib.sha256(poc).hexdigest()

    files = _render(facts=_facts(poc_original_sha256=digest), poc=poc)

    assert files["poc.sh"].body == poc
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["poc"]["attachment_sha256"] == digest
    assert provenance["poc"]["redacted"] is False


@pytest.mark.parametrize(
    "poc, sensitive_fragment",
    (
        (b"#!/bin/sh\necho /home/alice/private.txt\n", b"/home/alice/private.txt"),
        (
            b"#!/bin/sh\nscratch=$(mktemp -d /tmp/sastsimi.XXXXXX)\n"
            b"echo /home/alice/private.txt\n",
            b"/home/alice/private.txt",
        ),
        (b"#!/bin/sh\necho /root/private.txt\n", b"/root/private.txt"),
        (b"#!/bin/sh\necho C:\\Users\\Alice\\private.txt\n", b"C:\\Users\\Alice"),
        (
            b"#!/bin/sh\necho /tmp/safe sk-Abcdefghijk99999\n",
            b"sk-Abcdefghijk99999",
        ),
        (
            b"#!/bin/sh\nmkdir -p /tmp/sk-ABCDEFGH12345678\n",
            b"sk-ABCDEFGH12345678",
        ),
        (b"#!/bin/sh\necho /usr/local/private.txt\n", b"/usr/local/private.txt"),
        (b"#!/bin/sh\necho /tmp/../var/log/private\n", b"/tmp/../var/log/private"),
    ),
)
def test_shell_poc_with_host_path_or_secret_is_redacted(
    poc: bytes, sensitive_fragment: bytes
) -> None:
    digest = hashlib.sha256(poc).hexdigest()

    files = _render(facts=_facts(poc_original_sha256=digest), poc=poc)

    attached = files["poc.sh"].body
    assert attached != poc
    assert sensitive_fragment not in attached
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["poc"]["original_sha256"] == digest
    assert (
        provenance["poc"]["attachment_sha256"] == hashlib.sha256(attached).hexdigest()
    )
    assert provenance["poc"]["redacted"] is True
    assert "not the exact executed bytes" in files["report_en.md"].body.decode()
    assert "실행된 원본과 동일하지" in files["report_kr.md"].body.decode()


def test_python_poc_with_tmp_path_still_uses_generic_redaction() -> None:
    poc = b"print(open('/tmp/sastsimi-fixture').read())\n"

    files = _render(
        facts=_facts(
            poc_language="python",
            poc_original_sha256=hashlib.sha256(poc).hexdigest(),
        ),
        poc=poc,
    )

    assert b"/tmp/sastsimi-fixture" not in files["poc.py"].body
    assert b"[REDACTED:HOST_ABSOLUTE_PATH]" in files["poc.py"].body
    provenance = json.loads(files["evidence/provenance.json"].body)
    assert provenance["poc"]["redacted"] is True


def test_bundle_file_and_poc_language_reject_unsupported_paths() -> None:
    for path in ("../poc.sh", "report_fr.md", "evidence/other.txt"):
        with pytest.raises(ValueError, match="BUNDLE_FILE_PATH_INVALID"):
            BundleFile(path, b"data", "text/plain")
    with pytest.raises(ValueError, match="POC_LANGUAGE_UNSUPPORTED"):
        _facts(poc_language="ruby")
