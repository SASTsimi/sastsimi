"""Fail-closed rendering and atomic export of current report drafts."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import stat
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.actions import (
    ActionType,
    CheckResult,
    CheckType,
    Decision,
    RequesterRole,
    UseStatus,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    POC_RUNTIME_PATH,
    SandboxCommandRecord,
)
from sastsimi.contracts.ids import StoredDataId
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import BilingualReportContent
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import EvidenceClaim, VerificationResult
from sastsimi.ports.report_export import (
    CurrentReport,
    CurrentReportSource,
    ReportUnavailable,
)
from sastsimi.reporting.bilingual_bundle import (
    BundleFacts,
    BundleFile,
    render_bundle_files,
)
from sastsimi.reporting.bundle_files import (
    MAX_BUNDLE_ARCHIVE_BYTES,
    MAX_BUNDLE_MANIFEST_BYTES,
    parse_bundle_manifest,
    read_bundle_archive,
)
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.reporting.safe_windows_directory import (
    _capture_directory_identity as _capture_directory_identity,
)
from sastsimi.reporting.safe_windows_directory import (
    _directory_identity as _directory_identity,
)
from sastsimi.reporting.safe_windows_directory import (
    _guarded_windows_replace_directory as _guarded_windows_replace_directory,
)
from sastsimi.reporting.safe_windows_directory import _Kernel32 as _Kernel32
from sastsimi.reporting.safe_windows_directory import (
    _locked_windows_directory as _locked_windows_directory,
)
from sastsimi.reporting.safe_windows_directory import (
    _platform_attribute as _platform_attribute,
)

_SAFE_PATH_SEGMENT = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}\Z")
_WINDOWS_RESERVED_STEMS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class ReportMarkdownService:
    """Render only current exact records; never infer new vulnerability facts."""

    def __init__(self, data_dir: Path, source: CurrentReportSource) -> None:
        self._data_dir = data_dir.resolve()
        self._data_dir_identity = _capture_directory_identity(self._data_dir)
        self._source = source
        self._display_ids = FindingDisplayIdStore(RuntimePaths(self._data_dir).database)

    def summaries(self, analysis_id: str) -> tuple[dict[str, str], ...]:
        summaries: list[dict[str, str]] = []
        for report in self._source.list_current(analysis_id):
            if report.analysis_id != analysis_id:
                raise ReportUnavailable("REPORT_SCOPE_INVALID")
            validate_redaction_authority(report)
            summary = {
                "analysis_id": report.analysis_id,
                "finding_id": report.finding_id,
                "display_id": self._display_id(report),
                "hypothesis_id": report.hypothesis_id,
                "title": (
                    report.content.ko.title
                    if isinstance(report.content, BilingualReportContent)
                    else report.content.title
                ),
                "status": "DRAFTED_CURRENT",
                "cwe": report.cwe.primary or "UNCLASSIFIED",
            }
            if report.purpose == "LOCAL_EVALUATION":
                summary.update(purpose="LOCAL_EVALUATION", production_ready="false")
            try:
                assert_safe_provider_text(canonical_bytes(summary))
                for value in summary.values():
                    _assert_terminal_safe(value)
            except ValueError as error:
                raise ReportUnavailable("REPORT_REDACTION_NOT_PROVEN") from error
            summaries.append(summary)
        return tuple(summaries)

    def show(self, finding_id: str) -> str:
        report = self._source.get_current(finding_id)
        return render_markdown(report, display_id=self._display_id(report))

    def export(self, finding_id: str) -> Path:
        report = self._source.get_current(finding_id)
        expected_identity = _report_identity(report)
        destination = self._destination(report)
        markdown = render_markdown(report, display_id=self._display_id(report))

        def assert_still_current() -> None:
            current = self._source.get_current(finding_id)
            if _report_identity(current) != expected_identity:
                raise ReportUnavailable("STALE_REPORT")

        _atomic_write_report(
            destination,
            report.analysis_id,
            markdown.encode("utf-8"),
            self._data_dir_identity,
            assert_still_current,
        )
        if isinstance(report.content, BilingualReportContent):
            self._publish_bundle(report, display_id=self._display_id(report))
            assert_still_current()
        return destination

    def bundle_reference(self, exported: Path) -> str | None:
        """Find only the bundle of the current v2 ReportDraft just exported."""

        try:
            relative = exported.resolve(strict=True).relative_to(self._data_dir)
        except (OSError, ValueError) as error:
            raise ReportUnavailable("REPORT_PATH_OUTSIDE_DATA_DIR") from error
        if (
            len(relative.parts) != 3
            or relative.parts[0] != "reports"
            or re.fullmatch(r"F-[0-9]{3,}\.md", relative.name) is None
        ):
            return None
        current = [
            report
            for report in self._source.list_current(relative.parts[1])
            if self._display_id(report) == relative.stem
        ]
        if len(current) != 1 or not isinstance(
            current[0].content, BilingualReportContent
        ):
            return None
        report = current[0]
        expected_identity = _report_identity(report)
        if exported.resolve(strict=True) != self._destination(report).resolve(
            strict=True
        ):
            raise ReportUnavailable("STALE_REPORT")
        bundle = self._data_dir / relative.parent / relative.stem
        manifest_path = bundle / "manifest.json"
        archive_path = bundle / "bundle.zip"
        try:
            if (
                manifest_path.resolve(strict=True) != manifest_path
                or archive_path.resolve(strict=True) != archive_path
            ):
                raise ReportUnavailable("BUNDLE_PATH_UNSAFE")
            raw_manifest = _read_small_regular(manifest_path, MAX_BUNDLE_MANIFEST_BYTES)
            manifest = parse_bundle_manifest(
                raw_manifest, finding_ref=report.draft.finding_ref
            )
            if (manifest.analysis_id, manifest.display_id) != (
                report.analysis_id,
                relative.stem,
            ):
                raise ReportUnavailable("BUNDLE_SCOPE_MISMATCH")
            expected_files = self._bundle_files(report, display_id=relative.stem)
            expected_by_path = {
                item.path: (
                    item.media_type,
                    len(item.body),
                    hashlib.sha256(item.body).hexdigest(),
                )
                for item in expected_files
            }
            manifest_by_path = {
                item.path: (item.media_type, item.size, item.sha256)
                for item in manifest.files
            }
            if (
                len(expected_by_path) != len(expected_files)
                or expected_by_path != manifest_by_path
            ):
                raise ReportUnavailable("STALE_REPORT")
            disk_archive = _read_small_regular(archive_path, MAX_BUNDLE_ARCHIVE_BYTES)
            digest = hashlib.sha256(disk_archive).hexdigest()
            archive_ref = StoredDataRef(
                stored_data_id=StoredDataId(digest),
                data_kind="artifact",
                content_hash=digest,
                workspace_id=report.draft.finding_ref.workspace_id,
                commit_id=report.draft.finding_ref.commit_id,
                record_id=None,
            )
            if (
                read_bundle_archive(manifest, archive_ref, self._source.read_artifact)
                != disk_archive
            ):
                raise ReportUnavailable("BUNDLE_ARCHIVE_INVALID")
            if _report_identity(self._source.get_current(report.finding_id)) != (
                expected_identity
            ):
                raise ReportUnavailable("STALE_REPORT")
        except ReportUnavailable:
            raise
        except (OSError, ValueError) as error:
            raise ReportUnavailable("BUNDLE_UNAVAILABLE") from error
        return (relative.parent / relative.stem / "bundle.zip").as_posix()

    def _publish_bundle(self, report: CurrentReport, *, display_id: str) -> None:
        from sastsimi.reporting.bundle_files import publish_bundle

        if not isinstance(report.content, BilingualReportContent):
            return
        files = self._bundle_files(report, display_id=display_id)
        publish_bundle(
            root=self._data_dir,
            analysis_id=report.analysis_id,
            display_id=display_id,
            finding_ref=report.draft.finding_ref,
            files=files,
            put_artifact=lambda body, media_type: self._source.put_artifact(
                report.draft.finding_ref, body, media_type
            ),
        )

    def _bundle_files(
        self, report: CurrentReport, *, display_id: str
    ) -> tuple[BundleFile, ...]:
        if not isinstance(report.content, BilingualReportContent):
            raise ReportUnavailable("REPORT_BUNDLE_NOT_AVAILABLE")
        candidate_ref = report.poc_candidate.content_ref
        poc = report.poc_text.encode("utf-8")
        if (
            hashlib.sha256(poc).hexdigest() != candidate_ref.content_hash
            or report.poc.candidate_digest != candidate_ref.content_hash
        ):
            raise ReportUnavailable("REPORT_POC_SOURCE_MISMATCH")
        if self._source.read_artifact(candidate_ref) != poc:
            raise ReportUnavailable("REPORT_POC_SOURCE_MISMATCH")
        if (report.stdout_bytes is None) != (report.stdout_ref is None) or (
            report.stderr_bytes is None
        ) != (report.stderr_ref is None):
            raise ReportUnavailable("REPORT_OUTPUT_SOURCE_MISSING")
        source_refs = [
            ("finding", report.draft.finding_ref),
            ("poc", candidate_ref),
            ("verification", report.draft.verification_result_ref),
            ("technical", report.draft.technical_review_ref),
            ("scope", report.draft.rule_scope_impact_review_ref),
        ]
        for name, ref in (("stdout", report.stdout_ref), ("stderr", report.stderr_ref)):
            if ref is not None:
                source_refs.append((name, ref))
        allowed_locations = tuple(
            location
            for claim in (
                *report.verification.supporting_evidence,
                *report.verification.counter_evidence,
            )
            for location in claim.code_locations
        )
        facts = BundleFacts(
            analysis_id=report.analysis_id,
            display_id=display_id,
            finding_id=report.finding_id,
            repository=report.repository_url or "Needs review",
            tested_commit=str(report.draft.finding_ref.commit_id),
            cwe=str(report.cwe.primary) if report.cwe.primary is not None else None,
            ecosystem=None,
            package_name=None,
            affected_versions=None,
            patched_versions=None,
            severity=None,
            technical_status=report.technical.status,
            scope_status=report.rule_scope.review_status,
            report_permission=report.rule_scope.report_permission,
            execution_command=shlex.join(
                (
                    report.execution_command.executable,
                    *report.execution_command.arguments,
                )
            ),
            exit_code=report.execution_exit_code,
            poc_language="shell",
            poc_original_sha256=candidate_ref.content_hash,
            source_refs=tuple(source_refs),
            allowed_locations=allowed_locations,
        )
        return render_bundle_files(
            facts,
            report.content,
            poc=poc,
            stdout=report.stdout_bytes,
            stderr=report.stderr_bytes,
        )

    def _destination(self, report: CurrentReport) -> Path:
        for value in (report.analysis_id, report.finding_id):
            if (
                _SAFE_PATH_SEGMENT.fullmatch(value) is None
                or value in _WINDOWS_RESERVED_STEMS
            ):
                raise ReportUnavailable("UNSAFE_REPORT_PATH_ID")
        expected_root = self._data_dir / "reports"
        root = expected_root.resolve()
        if root != expected_root or root.parent != self._data_dir:
            raise ReportUnavailable("UNSAFE_REPORT_PATH_ROOT")
        expected_parent = root / report.analysis_id
        parent = expected_parent.resolve()
        if parent != expected_parent or parent.parent != root:
            raise ReportUnavailable("UNSAFE_REPORT_PATH_ID")
        return parent / f"{self._display_id(report)}.md"

    def _display_id(self, report: CurrentReport) -> str:
        return self._display_ids.get_or_allocate(
            report.analysis_id,
            report.draft.finding_ref,
        )


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


def render_markdown(report: CurrentReport, *, display_id: str | None = None) -> str:
    """Render existing record values without creating new security claims."""

    validate_redaction_authority(report)
    prose = (
        report.content.ko
        if isinstance(report.content, BilingualReportContent)
        else report.content
    )
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
    visible_id = display_id or report.finding_id
    lines = [
        f"# {prose.title}",
        "",
        "### Summary",
        "",
        "- 현재 상태: `DRAFTED / CURRENT`",
        f"- 실행 목적: `{report.purpose}`",
        *(
            ["- 운영 준비 상태: `NOT_PRODUCTION_READY`"]
            if report.purpose == "LOCAL_EVALUATION"
            else []
        ),
        f"- final Verification 판정: `{report.verification.verdict}`",
        "",
        "**취약점 요약**",
        "",
        prose.summary,
        "",
        "### Details",
        "",
        "**CWE 분류**",
        "",
        f"- Primary: `{report.cwe.primary or 'UNCLASSIFIED'}`",
        f"- Alternatives: {_inline(report.cwe.alternatives)}",
        f"- Taxonomy: `{report.cwe.taxonomy_version}`",
        f"- 근거: {report.cwe.rationale}",
        "",
        "**영향받는 코드 위치**",
        "",
        *_location_lines(locations),
        "",
        "**source → propagation → sink 흐름**",
        "",
        prose.details,
        "",
        "**정적 분석 근거**",
        "",
        *_claim_lines(static_claims),
        f"- Finding evidence refs: {_refs(report.finding.evidence_refs)}",
        "",
        "**Pro·Con 검증 근거와 최종 판단 이유**",
        "",
        "**Pro**",
        "",
        *_claim_lines(pro),
        "",
        "**Con**",
        "",
        *_claim_lines(con),
        "",
        f"- 최종 판단 이유: {report.verification.verdict_rationale}",
        "",
        "**동적 재현 결과**",
        "",
        f"- 목적: `{report.dynamic.purpose}`",
        f"- 실행 상태: `{report.dynamic.status}`",
        f"- 가설 결과: `{report.dynamic.hypothesis_outcome}`",
        f"- 가설 연결 설명: {report.dynamic.hypothesis_linkage}",
        f"- 관찰 refs: {_refs(report.dynamic.observation_refs)}",
        "",
        "### PoC",
        "",
        f"- validated PoC ref: `{report.draft.poc_ref.record_id}`",
        f"- candidate digest: `{report.poc.candidate_digest}`",
        f"- validated at: `{report.poc.validated_at.isoformat()}`",
        f"- AgentLog ref: `{report.poc.agent_log_ref.record_id}`",
        f"- 실제 실행 action_id: `{report.poc.execution_action_id}`",
        f"- 실제 실행 command digest: `{report.execution_command.command_digest}`",
        "",
        "**실제 실행 방법**",
        "",
        *_indented(_execution_method(report.execution_command)),
        "",
        "**validated PoC candidate 내용**",
        "",
        *_indented(report.poc_text),
        "",
        "### Impact",
        "",
        f"- 정책상 보안 영향: `{report.rule_scope.security_impact}`",
        "- 제한사항: "
        + _inline((*report.draft.limitations, *report.dynamic.limitations)),
        "- 제약: "
        + _inline(tuple(item.statement for item in report.draft.restrictions)),
        "",
        "**Gate 결과**",
        "",
        f"- Technical Gate: `{report.technical.status}` — {report.technical.rationale}",
        f"- Rule Scope Gate: `{report.rule_scope.review_status}`",
        f"- rule / scope / testing: `{report.rule_scope.rule_compliance}` / "
        f"`{report.rule_scope.scope_compliance}` / "
        f"`{report.rule_scope.testing_restriction_compliance}`",
        f"- report permission: `{report.rule_scope.report_permission}`",
        f"- 정책 검토 이유: {_inline(report.rule_scope.reasons)}",
        "",
        "**사람이 추가로 확인해야 할 내용**",
        "",
        f"- 미해결 조건: {_inline(report.draft.unresolved_conditions)}",
        f"- 권고 사항: {prose.recommendation}",
        "",
        "**생성 및 식별 정보**",
        "",
        f"- 생성 시각: `{report.draft.meta.created_at.isoformat()}`",
        f"- analysis_id: `{report.analysis_id}`",
        f"- hypothesis_id: `{report.hypothesis_id}`",
        f"- finding_id: `{report.finding_id}`",
        f"- 보고서 표시 번호: `{visible_id}`",
        f"- ReportDraft record_id: `{report.draft.meta.record_id}`",
        "",
    ]
    rendered = "\n".join(lines)
    try:
        assert_safe_provider_text(rendered.encode("utf-8"))
        _assert_terminal_safe(rendered)
    except ValueError as error:
        raise ReportUnavailable("REPORT_REDACTION_NOT_PROVEN") from error
    return rendered


def _assert_terminal_safe(value: str) -> None:
    """Reject terminal control sequences while preserving Markdown whitespace."""

    if any(
        (ord(character) < 0x20 and character not in {"\n", "\t"})
        or 0x7F <= ord(character) <= 0x9F
        for character in value
    ):
        raise ValueError("REPORT_TERMINAL_CONTROL_FORBIDDEN")


def _report_identity(report: CurrentReport) -> tuple[object, ...]:
    """Exact immutable inputs whose change makes an export stale."""

    records = (
        report.draft,
        report.finding,
        report.verification,
        report.cwe,
        report.technical,
        report.rule_scope,
        report.dynamic,
        report.poc,
        report.poc_candidate,
        report.agent_log,
        report.execution_command,
        report.content,
        report.report_action,
        report.report_decision,
    )
    return tuple(
        record.model_dump(mode="python", warnings=False) for record in records
    ) + (
        report.poc_text,
        report.purpose,
        report.repository_url,
        report.stdout_bytes,
        report.stderr_bytes,
        report.stdout_ref,
        report.stderr_ref,
        report.execution_exit_code,
    )


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


def _execution_method(command: SandboxCommandRecord) -> str:
    """Render exact safe argv, naming only the fixed internal candidate path."""

    arguments = tuple(
        "<validated-poc-candidate>" if value == POC_RUNTIME_PATH else value
        for value in command.arguments
    )
    argv = shlex.join((command.executable, *arguments))
    return f"working_directory={command.working_directory}\ncommand={argv}"


def _atomic_write(
    path: Path, data: bytes, assert_still_current: Callable[[], None]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        assert_still_current()
        os.replace(temporary, path)
        _sync_directory(path.parent)
        if path.read_bytes() != data:
            raise ReportUnavailable("REPORT_EXPORT_WRITE_FAILED")
        try:
            assert_still_current()
        except Exception:
            path.unlink(missing_ok=True)
            _sync_directory(path.parent)
            raise
    finally:
        temporary.unlink(missing_ok=True)


def _read_small_regular(path: Path, limit: int) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_file_attributes", 0)) & 0x400
        or before.st_size > limit
    ):
        raise ReportUnavailable("BUNDLE_PATH_UNSAFE")
    with path.open("rb") as stream:
        current = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (
            current.st_dev,
            current.st_ino,
        ) or current.st_size > limit:
            raise ReportUnavailable("BUNDLE_PATH_UNSAFE")
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise ReportUnavailable("BUNDLE_FILE_TOO_LARGE")
    return result


def _sync_directory(path: Path) -> None:
    """Durably publish a directory update where the platform supports it."""

    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _atomic_write_report(
    path: Path,
    analysis_id: str,
    data: bytes,
    data_dir_identity: tuple[int, int, int] | None,
    assert_still_current: Callable[[], None],
) -> None:
    if data_dir_identity is None:
        raise ReportUnavailable("UNSAFE_REPORT_PATH")
    if os.name == "nt":
        with _locked_windows_directory(
            path.parent.parent.parent, expected_identity=data_dir_identity
        ):
            with _locked_windows_directory(path.parent.parent):
                with _guarded_windows_replace_directory(path.parent):
                    _atomic_write(path, data, assert_still_current)
        return
    _atomic_write_report_posix(
        path, analysis_id, data, data_dir_identity, assert_still_current
    )


def _atomic_write_report_posix(
    path: Path,
    analysis_id: str,
    data: bytes,
    data_dir_identity: tuple[int, int, int],
    assert_still_current: Callable[[], None],
) -> None:
    data_dir = path.parent.parent.parent
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise ReportUnavailable("UNSAFE_REPORT_PATH")
    directory_flags = os.O_RDONLY | directory_flag | nofollow_flag
    try:
        data_dir_fd = os.open(data_dir, directory_flags)
    except OSError as error:
        raise ReportUnavailable("UNSAFE_REPORT_PATH") from error
    try:
        if _directory_identity(os.fstat(data_dir_fd)) != data_dir_identity:
            raise ReportUnavailable("UNSAFE_REPORT_PATH")
        try:
            os.mkdir("reports", mode=0o700, dir_fd=data_dir_fd)
        except FileExistsError:
            pass
        root_fd = os.open("reports", directory_flags, dir_fd=data_dir_fd)
        try:
            root_identity = _directory_identity(os.fstat(root_fd))
            try:
                try:
                    os.mkdir(analysis_id, mode=0o700, dir_fd=root_fd)
                except FileExistsError:
                    pass
                parent_fd = os.open(analysis_id, directory_flags, dir_fd=root_fd)
                try:
                    parent_identity = _directory_identity(os.fstat(parent_fd))
                    temporary = f".{path.name}.{uuid4().hex}.tmp"
                    descriptor = os.open(
                        temporary,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=parent_fd,
                    )
                    try:
                        with os.fdopen(descriptor, "w+b", closefd=False) as stream:
                            stream.write(data)
                            stream.flush()
                            os.fsync(descriptor)
                            assert_still_current()
                            os.replace(
                                temporary,
                                path.name,
                                src_dir_fd=parent_fd,
                                dst_dir_fd=parent_fd,
                            )
                            os.fsync(parent_fd)
                            stream.seek(0)
                            if stream.read() != data:
                                raise ReportUnavailable("REPORT_EXPORT_WRITE_FAILED")
                            try:
                                assert_still_current()
                            except Exception:
                                os.unlink(path.name, dir_fd=parent_fd)
                                os.fsync(parent_fd)
                                raise
                        if (
                            _directory_identity(
                                os.stat(data_dir, follow_symlinks=False)
                            )
                            != data_dir_identity
                            or _directory_identity(
                                os.stat(
                                    "reports",
                                    dir_fd=data_dir_fd,
                                    follow_symlinks=False,
                                )
                            )
                            != root_identity
                            or _directory_identity(
                                os.stat(
                                    analysis_id,
                                    dir_fd=root_fd,
                                    follow_symlinks=False,
                                )
                            )
                            != parent_identity
                        ):
                            raise ReportUnavailable("UNSAFE_REPORT_PATH")
                    finally:
                        os.close(descriptor)
                        try:
                            os.unlink(temporary, dir_fd=parent_fd)
                        except FileNotFoundError:
                            pass
                finally:
                    os.close(parent_fd)
            except OSError as error:
                raise ReportUnavailable("UNSAFE_REPORT_PATH") from error
        finally:
            os.close(root_fd)
    except OSError as error:
        raise ReportUnavailable("UNSAFE_REPORT_PATH") from error
    finally:
        os.close(data_dir_fd)


__all__ = [
    "CurrentReport",
    "CurrentReportSource",
    "ReportMarkdownService",
    "ReportUnavailable",
    "render_markdown",
]
