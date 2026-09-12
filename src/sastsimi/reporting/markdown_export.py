"""Fail-closed rendering and atomic export of current report drafts."""

from __future__ import annotations

import os
import re
import shlex
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
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
    POC_RUNTIME_PATH,
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
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import Finding, ReportContent, ReportDraft
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import EvidenceClaim, VerificationResult
from sastsimi.storage.artifact_store import sync_directory

_SAFE_PATH_SEGMENT = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}\Z")
_WINDOWS_RESERVED_STEMS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


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
    def list_current(self) -> tuple[CurrentReport, ...]: ...

    def get_current(self, finding_id: str) -> CurrentReport: ...


class ReportMarkdownService:
    """Render only current exact records; never infer new vulnerability facts."""

    def __init__(self, data_dir: Path, source: CurrentReportSource) -> None:
        self._data_dir = data_dir.resolve()
        self._data_dir_identity = _capture_directory_identity(self._data_dir)
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
        _atomic_write_report(
            destination,
            report.analysis_id,
            markdown.encode("utf-8"),
            self._data_dir_identity,
        )
        return destination

    def _destination(self, report: CurrentReport) -> Path:
        for value in (report.analysis_id, report.finding_id):
            if (
                _SAFE_PATH_SEGMENT.fullmatch(value) is None
                or value in _WINDOWS_RESERVED_STEMS
            ):
                raise ReportUnavailable("UNSAFE_REPORT_PATH_ID")
        expected_root = RuntimePaths(self._data_dir).reports
        root = expected_root.resolve()
        if root != expected_root or root.parent != self._data_dir:
            raise ReportUnavailable("UNSAFE_REPORT_PATH_ROOT")
        expected_parent = root / report.analysis_id
        parent = expected_parent.resolve()
        if parent != expected_parent or parent.parent != root:
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
        f"- AgentLog ref: `{report.poc.agent_log_ref.record_id}`",
        f"- 실제 실행 action_id: `{report.poc.execution_action_id}`",
        f"- 실제 실행 command digest: `{report.execution_command.command_digest}`",
        "",
        "### 실제 실행 방법",
        "",
        *_indented(_execution_method(report.execution_command)),
        "",
        "### validated PoC candidate 내용",
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


def _execution_method(command: SandboxCommandRecord) -> str:
    """Render exact safe argv, naming only the fixed internal candidate path."""

    arguments = tuple(
        "<validated-poc-candidate>" if value == POC_RUNTIME_PATH else value
        for value in command.arguments
    )
    argv = shlex.join((command.executable, *arguments))
    return f"working_directory={command.working_directory}\ncommand={argv}"


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


def _directory_identity(info: os.stat_result) -> tuple[int, int, int]:
    if not stat.S_ISDIR(info.st_mode):
        raise ReportUnavailable("UNSAFE_REPORT_PATH")
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _capture_directory_identity(path: Path) -> tuple[int, int, int] | None:
    try:
        return _directory_identity(os.stat(path, follow_symlinks=False))
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ReportUnavailable("UNSAFE_REPORT_PATH") from error


def _atomic_write_report(
    path: Path,
    analysis_id: str,
    data: bytes,
    data_dir_identity: tuple[int, int, int] | None,
) -> None:
    if data_dir_identity is None:
        raise ReportUnavailable("UNSAFE_REPORT_PATH")
    if os.name == "nt":
        with _locked_windows_directory(
            path.parent.parent.parent, expected_identity=data_dir_identity
        ):
            with _locked_windows_directory(path.parent.parent):
                with _guarded_windows_replace_directory(path.parent):
                    _atomic_write(path, data)
        return
    _atomic_write_report_posix(path, analysis_id, data, data_dir_identity)


def _atomic_write_report_posix(
    path: Path,
    analysis_id: str,
    data: bytes,
    data_dir_identity: tuple[int, int, int],
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


class _WindowsFunction(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *args: object) -> int | None: ...


class _Kernel32(Protocol):
    CreateFileW: _WindowsFunction
    CloseHandle: _WindowsFunction


def _platform_attribute(owner: object, name: str) -> object:
    return getattr(owner, name)


@contextmanager
def _locked_windows_directory(
    path: Path,
    *,
    expected_identity: tuple[int, int, int] | None = None,
    allow_write_sharing: bool = False,
) -> Iterator[None]:
    import ctypes
    import msvcrt

    try:
        path.mkdir(exist_ok=True)
    except OSError as error:
        raise ReportUnavailable("UNSAFE_REPORT_PATH") from error
    load_library = cast(Callable[..., object], _platform_attribute(ctypes, "WinDLL"))
    kernel32 = cast(_Kernel32, load_library("kernel32", use_last_error=True))
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    generic_read = 0x80000000
    share_read = 0x00000001
    share_mode = share_read | (0x00000002 if allow_write_sharing else 0)
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    handle = create_file(
        str(path),
        generic_read,
        share_mode,
        None,
        open_existing,
        file_flag_backup_semantics | file_flag_open_reparse_point,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or handle == invalid_handle:
        get_last_error = cast(
            Callable[[], int], _platform_attribute(ctypes, "get_last_error")
        )
        raise ReportUnavailable("UNSAFE_REPORT_PATH") from OSError(
            get_last_error(), "REPORT_DIRECTORY_OPEN_FAILED", str(path)
        )
    descriptor: int | None = None
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY)
        information = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(information.st_mode)
            or int(getattr(information, "st_file_attributes", 0))
            & _FILE_ATTRIBUTE_REPARSE_POINT
            or int(getattr(information, "st_reparse_tag", 0)) != 0
            or (
                expected_identity is not None
                and _directory_identity(information) != expected_identity
            )
        ):
            raise ReportUnavailable("UNSAFE_REPORT_PATH")
        yield
    finally:
        if descriptor is None:
            close_handle(handle)
        else:
            os.close(descriptor)


@contextmanager
def _guarded_windows_replace_directory(path: Path) -> Iterator[None]:
    """Keep the directory non-empty while replacement needs write sharing."""

    guard_path = path / f".report-export-{uuid4().hex}.guard"
    guard = None
    with _locked_windows_directory(path):
        try:
            guard = guard_path.open("xb")
        except OSError as error:
            raise ReportUnavailable("UNSAFE_REPORT_PATH") from error
    try:
        with _locked_windows_directory(path, allow_write_sharing=True):
            yield
    finally:
        if guard is not None:
            guard.close()
        try:
            guard_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ReportUnavailable("UNSAFE_REPORT_PATH") from error


__all__ = [
    "CurrentReport",
    "CurrentReportSource",
    "ReportMarkdownService",
    "ReportUnavailable",
    "render_markdown",
]
