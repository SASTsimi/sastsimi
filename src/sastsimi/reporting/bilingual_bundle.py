"""Deterministic bilingual Finding text from validated facts and safe bytes."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    assert_safe_provider_text,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import (
    BilingualReportContent,
    ReportProse,
    validate_report_content,
)
from sastsimi.contracts.static import CodeLocation

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SOURCE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_MEDIA_TYPES = {
    "report_en.md": "text/markdown; charset=utf-8",
    "report_kr.md": "text/markdown; charset=utf-8",
    "poc.sh": "text/x-shellscript; charset=utf-8",
    "poc.py": "text/x-python; charset=utf-8",
    "evidence/provenance.json": "application/json",
    "evidence/stdout.txt": "text/plain; charset=utf-8",
    "evidence/stderr.txt": "text/plain; charset=utf-8",
}
_SECTIONS = (
    ("Summary", "요약"),
    ("Affected products and tested version", "영향 대상과 테스트 버전"),
    ("Severity and weakness", "심각도와 취약점 분류"),
    ("Technical details", "기술 설명"),
    ("Reproduction and PoC", "재현 방법과 PoC"),
    ("Evidence", "근거"),
    ("Impact", "영향"),
    ("Scope Gate and limitations", "Scope Gate와 한계"),
    ("Remediation", "수정 제안"),
)


@dataclass(frozen=True, slots=True)
class BundleFacts:
    """Factual fields supplied by exact Finding, gate and execution records."""

    analysis_id: str
    display_id: str
    finding_id: str
    repository: str
    tested_commit: str
    cwe: str | None
    ecosystem: str | None
    package_name: str | None
    affected_versions: str | None
    patched_versions: str | None
    severity: str | None
    technical_status: str
    scope_status: str
    report_permission: str
    execution_command: str
    exit_code: int | None
    poc_language: Literal["shell", "python"]
    poc_original_sha256: str
    source_refs: tuple[tuple[str, StoredDataRef], ...]
    allowed_locations: tuple[CodeLocation, ...] = ()

    def __post_init__(self) -> None:
        if any(
            _ID.fullmatch(value) is None
            for value in (self.analysis_id, self.display_id, self.finding_id)
        ):
            raise ValueError("BUNDLE_ID_INVALID")
        if _COMMIT.fullmatch(self.tested_commit) is None:
            raise ValueError("BUNDLE_COMMIT_INVALID")
        if _SHA256.fullmatch(self.poc_original_sha256) is None:
            raise ValueError("BUNDLE_POC_DIGEST_INVALID")
        if self.poc_language not in {"shell", "python"}:
            raise ValueError("POC_LANGUAGE_UNSUPPORTED")
        names = [name for name, _ in self.source_refs]
        if (
            len(names) != len(set(names))
            or any(_SOURCE_NAME.fullmatch(name) is None for name in names)
            or not {"finding", "poc"}.issubset(names)
        ):
            raise ValueError("BUNDLE_SOURCE_REFS_INVALID")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise ValueError("BUNDLE_EXIT_CODE_INVALID")


@dataclass(frozen=True, slots=True)
class BundleFile:
    """One allowlisted downloadable file, never an arbitrary filesystem path."""

    path: str
    body: bytes
    media_type: str

    def __post_init__(self) -> None:
        if self.path not in _MEDIA_TYPES:
            raise ValueError("BUNDLE_FILE_PATH_INVALID")
        if self.media_type != _MEDIA_TYPES[self.path]:
            raise ValueError("BUNDLE_MEDIA_TYPE_INVALID")
        if not isinstance(self.body, bytes):
            raise ValueError("BUNDLE_BODY_INVALID")


def _safe_attachment(data: bytes) -> tuple[bytes, bool]:
    try:
        data.decode("utf-8")
        redacted = redact_untrusted_text(data)
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("BUNDLE_TEXT_UNSAFE") from error
    assert_safe_provider_text(redacted.data)
    return redacted.data, redacted.data != data


def _value(value: str | None, *, korean: bool) -> str:
    return value if value else ("검토 필요" if korean else "Needs review")


def _source_lines(facts: BundleFacts) -> list[str]:
    return [
        f"- {name}: {ref.data_kind} / {ref.record_id or ref.stored_data_id} / "
        f"SHA-256 `{ref.content_hash}`"
        for name, ref in facts.source_refs
    ]


def _render_report(
    facts: BundleFacts,
    prose: ReportProse,
    *,
    korean: bool,
    citations: tuple[CodeLocation, ...],
    poc_name: str,
    poc_attachment_sha256: str,
    poc_redacted: bool,
    output_names: tuple[str, ...],
    command: str,
) -> bytes:
    def heading(index: int) -> str:
        return f"## {_SECTIONS[index][int(korean)]}"

    def labeled(english: str, korean_label: str, value: str) -> str:
        return f"- {korean_label if korean else english}: {value}"

    exit_code = str(facts.exit_code) if facts.exit_code is not None else None
    lines = [
        f"# {prose.title}",
        "",
        heading(0),
        "",
        f"- {'분석 ID' if korean else 'Analysis ID'}: `{facts.analysis_id}`",
        f"- Finding ID: `{facts.display_id}` (`{facts.finding_id}`)",
        prose.summary,
        "",
        heading(1),
        "",
        f"- {'저장소' if korean else 'Repository'}: {facts.repository}",
        f"- {'테스트 커밋' if korean else 'Tested commit'}: `{facts.tested_commit}`",
        labeled("Ecosystem", "생태계", _value(facts.ecosystem, korean=korean)),
        labeled("Package name", "패키지명", _value(facts.package_name, korean=korean)),
        labeled(
            "Affected versions",
            "영향받는 버전",
            _value(facts.affected_versions, korean=korean),
        ),
        labeled(
            "Patched versions",
            "수정된 버전",
            _value(facts.patched_versions, korean=korean),
        ),
        "",
        heading(2),
        "",
        labeled("Severity", "심각도", _value(facts.severity, korean=korean)),
        f"- CWE: {_value(facts.cwe, korean=korean)}",
        "",
        heading(3),
        "",
        prose.details,
        "",
        *(
            f"- {item.file_path}:{item.start_line}-{item.end_line}"
            for item in facts.allowed_locations
            if item in citations
        ),
        "",
        heading(4),
        "",
        f"- {'실행 명령' if korean else 'Executed command'}: `{command}`",
        labeled("Exit code", "종료 코드", _value(exit_code, korean=korean)),
        f"- PoC: `{poc_name}`",
        labeled(
            "Original PoC SHA-256", "원본 PoC SHA-256", f"`{facts.poc_original_sha256}`"
        ),
        labeled(
            "Attached PoC SHA-256", "첨부 PoC SHA-256", f"`{poc_attachment_sha256}`"
        ),
        (
            "- 가림 처리된 첨부파일은 실제 실행된 원본과 동일하지 않습니다."
            if korean
            else "- The redacted attachment is not the exact executed bytes."
        )
        if poc_redacted
        else (
            "- 첨부된 PoC 바이트는 검증된 원본과 동일합니다."
            if korean
            else "- The attached PoC bytes match the validated original."
        ),
        "",
        heading(5),
        "",
        *_source_lines(facts),
        *(f"- `{name}`" for name in output_names),
        "",
        heading(6),
        "",
        prose.impact,
        "",
        heading(7),
        "",
        f"- Technical Gate: `{facts.technical_status}`",
        f"- Scope Gate: `{facts.scope_status}`",
        labeled("Report permission", "제보 허용 상태", f"`{facts.report_permission}`"),
        *(
            [f"- {item}" for item in prose.limitations]
            if prose.limitations
            else [
                "- 검토할 제한사항 없음"
                if korean
                else "- No additional limitations supplied."
            ]
        ),
        *(
            [f"- {item}" for item in prose.review_items]
            if prose.review_items
            else ["- 사람의 최종 검토 필요" if korean else "- Human review required."]
        ),
        "",
        heading(8),
        "",
        prose.recommendation,
        "",
    ]
    rendered = "\n".join(lines).encode("utf-8")
    assert_safe_provider_text(rendered)
    return rendered


def render_bundle_files(
    facts: BundleFacts,
    content: BilingualReportContent,
    *,
    poc: bytes,
    stdout: bytes | None,
    stderr: bytes | None,
) -> tuple[BundleFile, ...]:
    """Render a curated bundle; LLM prose cannot set the factual metadata."""

    validate_report_content(
        content.model_dump(mode="json"), allowed_locations=facts.allowed_locations
    )
    if hashlib.sha256(poc).hexdigest() != facts.poc_original_sha256:
        raise ValueError("BUNDLE_POC_SOURCE_MISMATCH")
    safe_poc, poc_redacted = _safe_attachment(poc)
    poc_name = "poc.sh" if facts.poc_language == "shell" else "poc.py"
    sources = dict(facts.source_refs)
    attachments: list[BundleFile] = [
        BundleFile(poc_name, safe_poc, _MEDIA_TYPES[poc_name])
    ]
    outputs: dict[str, object] = {}
    output_names: list[str] = []
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        if raw is None:
            continue
        if name not in sources:
            raise ValueError("BUNDLE_OUTPUT_SOURCE_REQUIRED")
        safe, redacted = _safe_attachment(raw)
        path = f"evidence/{name}.txt"
        attachments.append(BundleFile(path, safe, _MEDIA_TYPES[path]))
        output_names.append(path)
        outputs[name] = {
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "attachment_sha256": hashlib.sha256(safe).hexdigest(),
            "redacted": redacted,
        }
    command, command_redacted = _safe_attachment(facts.execution_command.encode())
    provenance = {
        "schema_version": 1,
        "analysis_id": facts.analysis_id,
        "display_id": facts.display_id,
        "finding_id": facts.finding_id,
        "repository": facts.repository,
        "tested_commit": facts.tested_commit,
        "cwe": facts.cwe,
        "ecosystem": facts.ecosystem,
        "package_name": facts.package_name,
        "affected_versions": facts.affected_versions,
        "patched_versions": facts.patched_versions,
        "severity": facts.severity,
        "technical_status": facts.technical_status,
        "scope_status": facts.scope_status,
        "report_permission": facts.report_permission,
        "execution": {
            "command": command.decode("utf-8"),
            "command_redacted": command_redacted,
            "exit_code": facts.exit_code,
        },
        "poc": {
            "path": poc_name,
            "original_sha256": facts.poc_original_sha256,
            "attachment_sha256": hashlib.sha256(safe_poc).hexdigest(),
            "redacted": poc_redacted,
        },
        "outputs": outputs,
        "sources": {
            name: ref.model_dump(mode="json") for name, ref in facts.source_refs
        },
    }
    provenance_body = canonical_bytes(provenance)
    assert_safe_provider_text(provenance_body)

    def report(prose: ReportProse, *, korean: bool) -> bytes:
        return _render_report(
            facts,
            prose,
            korean=korean,
            citations=content.citations,
            poc_name=poc_name,
            poc_attachment_sha256=hashlib.sha256(safe_poc).hexdigest(),
            poc_redacted=poc_redacted,
            output_names=tuple(output_names),
            command=command.decode("utf-8"),
        )

    return (
        BundleFile(
            "report_en.md",
            report(content.en, korean=False),
            _MEDIA_TYPES["report_en.md"],
        ),
        BundleFile(
            "report_kr.md",
            report(content.ko, korean=True),
            _MEDIA_TYPES["report_kr.md"],
        ),
        *attachments,
        BundleFile(
            "evidence/provenance.json",
            provenance_body,
            _MEDIA_TYPES["evidence/provenance.json"],
        ),
    )
