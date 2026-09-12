"""Human-readable report rendering is current-only and fail-closed."""

import os
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import sastsimi.reporting.markdown_export as markdown_export
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
    POC_RUNTIME_PATH,
    AgentLog,
    AgentLogEvent,
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
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import Finding, ReportContent, ReportDraft
from sastsimi.contracts.verification import EvidenceClaim, VerificationResult
from sastsimi.reporting.markdown_export import (
    CurrentReport,
    ReportMarkdownService,
    ReportUnavailable,
)
from sastsimi.storage.report_export import SQLiteCurrentReportSource


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
            agent_log_ref=ref("agent_log", "agent-log-1"),
            candidate_digest="b" * 64,
            execution_action_id="execute",
            validated_at=now,
        ),
        poc_candidate=PoCCandidate.model_construct(),
        agent_log=AgentLog.model_construct(),
        execution_command=SandboxCommandRecord.model_construct(
            executable="/bin/sh",
            arguments=(POC_RUNTIME_PATH,),
            working_directory="/workspace",
            command_digest="c" * 64,
        ),
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
    assert "- AgentLog ref: `agent-log-1`" in markdown
    assert "- 실제 실행 action_id: `execute`" in markdown
    assert "### 실제 실행 방법" in markdown
    assert "command=/bin/sh '<validated-poc-candidate>'" in markdown
    assert "### validated PoC candidate 내용" in markdown
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


def test_markdown_export_rejects_reports_root_symlink_escape(tmp_path: Path) -> None:
    report = current_report()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-reports"
    outside.mkdir()
    link = tmp_path / "reports"
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            check=True,
            capture_output=True,
        )
    else:
        link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReportUnavailable, match="UNSAFE_REPORT_PATH"):
        ReportMarkdownService(tmp_path, Source(report)).export(report.finding_id)

    assert not (outside / report.analysis_id / f"{report.finding_id}.md").exists()


def test_markdown_export_rejects_analysis_directory_symlink_escape(
    tmp_path: Path,
) -> None:
    report = current_report()
    outside = tmp_path / "outside-analysis"
    outside.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    link = reports / report.analysis_id
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            check=True,
            capture_output=True,
        )
    else:
        link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReportUnavailable, match="UNSAFE_REPORT_PATH"):
        ReportMarkdownService(tmp_path, Source(report)).export(report.finding_id)

    assert not (outside / f"{report.finding_id}.md").exists()


@pytest.mark.parametrize(
    ("analysis_id", "finding_id"),
    (
        ("Analysis-1", "finding-1"),
        ("analysis-1", "Finding-1"),
        ("con", "finding-1"),
        ("analysis-1", "nul"),
        ("a" * 129, "finding-1"),
        ("analysis-1", "f" * 129),
        ("analysis.", "finding-1"),
    ),
)
def test_markdown_export_rejects_noncanonical_filesystem_ids(
    tmp_path: Path, analysis_id: str, finding_id: str
) -> None:
    report = current_report()
    draft_meta = SimpleNamespace(
        analysis_id=analysis_id,
        hypothesis_id=report.draft.meta.hypothesis_id,
        record_id=report.draft.meta.record_id,
        created_at=report.draft.meta.created_at,
    )
    unsafe = replace(
        report,
        draft=report.draft.model_copy(update={"meta": draft_meta}),
        finding=report.finding.model_copy(
            update={"meta": SimpleNamespace(record_id=finding_id)}
        ),
    )

    with pytest.raises(ReportUnavailable, match="UNSAFE_REPORT_PATH_ID"):
        ReportMarkdownService(tmp_path, Source(unsafe)).export(finding_id)


def test_markdown_export_does_not_follow_directory_swap_during_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = current_report()
    service = ReportMarkdownService(tmp_path, Source(report))
    parent = tmp_path / "reports" / report.analysis_id
    parent.mkdir(parents=True)
    backup = tmp_path / "analysis-backup"
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / f"{report.finding_id}.md"
    victim.write_text("victim", encoding="utf-8")
    real_replace = os.replace
    swapped = False
    blocked = False

    def racing_replace(
        source: str | os.PathLike[str],
        destination: str | os.PathLike[str],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal blocked, swapped
        if not swapped and not blocked:
            try:
                parent.rename(backup)
            except OSError:
                blocked = True
            else:
                swapped = True
                if os.name == "nt":
                    subprocess.run(
                        ["cmd", "/c", "mklink", "/J", str(parent), str(outside)],
                        check=True,
                        capture_output=True,
                    )
                else:
                    parent.symlink_to(outside, target_is_directory=True)
                if src_dir_fd is None and dst_dir_fd is None:
                    source_name = Path(source).name
                    real_replace(backup / source_name, outside / source_name)
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(os, "replace", racing_replace)
    try:
        if os.name == "nt":
            exported = service.export(report.finding_id)
            assert blocked
            assert exported.read_text(encoding="utf-8") == service.show(
                report.finding_id
            )
        else:
            with pytest.raises(ReportUnavailable, match="UNSAFE_REPORT_PATH"):
                service.export(report.finding_id)
            assert swapped
        assert victim.read_text(encoding="utf-8") == "victim"
    finally:
        monkeypatch.undo()
        if parent.is_symlink() or (
            hasattr(parent, "is_junction") and parent.is_junction()
        ):
            if os.name == "nt":
                parent.rmdir()
            else:
                parent.unlink()
        if backup.exists() and not parent.exists():
            backup.rename(parent)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory sharing contract")
def test_windows_directory_lock_rejects_competing_write_handle(
    tmp_path: Path,
) -> None:
    import ctypes

    directory = tmp_path / "locked"
    directory.mkdir()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
    invalid_handle = ctypes.c_void_p(-1).value

    with markdown_export._locked_windows_directory(directory):
        ctypes.set_last_error(0)
        competing_handle = create_file(
            str(directory),
            0x40000000,  # GENERIC_WRITE
            0x00000001 | 0x00000002 | 0x00000004,
            None,
            3,  # OPEN_EXISTING
            0x02000000 | 0x00200000,
            None,
        )
        error = ctypes.get_last_error()
        if competing_handle not in (None, invalid_handle):
            close_handle(competing_handle)

    assert competing_handle in (None, invalid_handle)
    assert error == 32  # ERROR_SHARING_VIOLATION


def test_markdown_export_rejects_data_dir_swap_before_directory_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = current_report()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    service = ReportMarkdownService(data_dir, Source(report))
    backup = tmp_path / "data-backup"
    outside = tmp_path / "outside-data"
    outside_parent = outside / "reports" / report.analysis_id
    outside_parent.mkdir(parents=True)
    victim = outside_parent / f"{report.finding_id}.md"
    victim.write_text("victim", encoding="utf-8")
    real_write = markdown_export._atomic_write_report

    def racing_write(*args: object, **kwargs: object) -> None:
        data_dir.rename(backup)
        if os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(data_dir), str(outside)],
                check=True,
                capture_output=True,
            )
        else:
            data_dir.symlink_to(outside, target_is_directory=True)
        real_write(*args, **kwargs)

    monkeypatch.setattr(markdown_export, "_atomic_write_report", racing_write)
    try:
        with pytest.raises(ReportUnavailable, match="UNSAFE_REPORT_PATH"):
            service.export(report.finding_id)
        assert victim.read_text(encoding="utf-8") == "victim"
    finally:
        monkeypatch.undo()
        if data_dir.is_symlink() or (
            hasattr(data_dir, "is_junction") and data_dir.is_junction()
        ):
            if os.name == "nt":
                data_dir.rmdir()
            else:
                data_dir.unlink()


def test_markdown_export_rejects_replaced_data_dir_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = current_report()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    service = ReportMarkdownService(data_dir, Source(report))
    backup = tmp_path / "data-backup"
    victim = data_dir / "reports" / report.analysis_id / f"{report.finding_id}.md"
    real_write = markdown_export._atomic_write_report

    def racing_write(*args: object, **kwargs: object) -> None:
        data_dir.rename(backup)
        victim.parent.mkdir(parents=True)
        victim.write_text("victim", encoding="utf-8")
        real_write(*args, **kwargs)

    monkeypatch.setattr(markdown_export, "_atomic_write_report", racing_write)

    with pytest.raises(ReportUnavailable, match="UNSAFE_REPORT_PATH"):
        service.export(report.finding_id)
    assert victim.read_text(encoding="utf-8") == "victim"


def test_current_report_requires_exact_execution_log_and_command() -> None:
    assert "agent_log" in CurrentReport.__dataclass_fields__
    assert "execution_command" in CurrentReport.__dataclass_fields__


def test_report_source_rejects_execution_command_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_ref = ref("dynamic_reproduction_request", "request-1")
    log_ref = ref("agent_log", "agent-log-1")
    candidate_ref = ref("poc_candidate", "candidate-1")
    command_ref = ref("sandbox_command_record", "command-1")
    environment_ref = ref("sandbox_environment", "environment-1")
    recipe_ref = ref("environment_recipe", "recipe-1")
    execution_meta = SimpleNamespace(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
        attempt_id="attempt-1",
    )
    execution = AgentLogEvent.model_construct(
        event_type="POC_EXECUTION_FINISHED",
        action_id="execute",
        poc_candidate_ref=candidate_ref,
        command_ref=command_ref,
        command_digest="c" * 64,
        environment_ref=environment_ref,
        environment_recipe_ref=recipe_ref,
        exit_code=0,
        timed_out=False,
    )
    log = AgentLog.model_construct(
        meta=execution_meta,
        request_ref=request_ref,
        events=(execution,),
    )
    command = SandboxCommandRecord.model_construct(
        meta=execution_meta,
        request_ref=request_ref,
        action_id="execute",
        command_digest="d" * 64,
        environment_ref=environment_ref,
        environment_recipe_ref=recipe_ref,
    )
    result = DynamicReproductionResult.model_construct(
        meta=execution_meta,
        request_ref=request_ref,
        agent_log_ref=log_ref,
        environment_ref=environment_ref,
        environment_recipe_ref=recipe_ref,
        poc_candidate_ref=candidate_ref,
    )
    poc = PoCBundle.model_construct(
        meta=execution_meta,
        request_ref=request_ref,
        agent_log_ref=log_ref,
        execution_action_id="execute",
        candidate_ref=candidate_ref,
        environment_ref=environment_ref,
        environment_recipe_ref=recipe_ref,
    )
    source = object.__new__(SQLiteCurrentReportSource)
    values = {log_ref: log, command_ref: command}
    monkeypatch.setattr(source, "_exact", lambda value, _expected: values[value])

    with pytest.raises(ReportUnavailable, match="REPORT_POC_EXECUTION_INVALID"):
        source._poc_execution(
            result,
            poc,
            PoCCandidate.model_construct(),
            (),
        )
