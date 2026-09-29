"""Small public command façade; detailed legacy commands remain available."""

from __future__ import annotations

from typing import TextIO

from sastsimi.interfaces.cli.output import emit_data
from sastsimi.ports.public_commands import PublicCommandApplication


class PublicCommandUnavailable(RuntimeError):
    pass


def _emit_static_coverage(stream: TextIO, data: dict[str, object]) -> None:
    state = data.get("static_coverage_status")
    if state is None:
        return
    if state == "PENDING":
        stream.write("정적 검사 범위: 기록 대기 중\n")
        return
    expected = data.get("static_coverage_expected")
    verified = data.get("static_coverage_verified")
    gaps = data.get("static_coverage_gap_count")
    if (
        state != "AVAILABLE"
        or type(expected) is not int
        or type(verified) is not int
        or type(gaps) is not int
    ):
        stream.write("정적 검사 범위: 확인 불가 (완료 보장 아님)\n")
        return
    stream.write(f"정적 검사 파일·규칙: 검증 {verified}/{expected} · 미검증 {gaps}\n")
    categories = (
        ("미검증 파일·규칙", "static_coverage_gap", ("path", "rule_id", "reason")),
        ("스캔 불가 경로", "static_coverage_unavailable_path", ("path", "reason")),
        ("지원되지 않는 제품 파일", "static_coverage_unsupported", ("path", "reason")),
        ("테스트 제외", "static_excluded_test_file", ("path", "reason")),
        ("범위 밖 제품 코드", "static_out_of_scope_product", ("path", "reason")),
    )
    for label, prefix, fields in categories:
        count = data.get(f"{prefix}_count")
        if type(count) is not int:
            stream.write(f"{label}: 기록 없음(확인 불가)\n")
            continue
        stream.write(f"{label}: {count}개\n")
        preview = data.get(f"{prefix}_preview")
        rows = preview[:20] if isinstance(preview, (list, tuple)) else ()
        shown = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            values = [row.get(field) for field in fields]
            if not all(isinstance(value, str) for value in values):
                continue
            stream.write("  " + " · ".join(str(value) for value in values) + "\n")
            shown += 1
        omitted = max(0, count - shown)
        if omitted:
            stream.write(f"  … 외 {omitted}개\n")


def emit_public(
    output_format: str,
    stream: TextIO,
    *,
    command: str,
    data: dict[str, object],
) -> None:
    if output_format == "json":
        emit_data(output_format, stream, command=command, data=data)
        return
    if command == "analyze":
        stream.write(
            "분석이 시작되었습니다.\n\n"
            f"분석 ID: {data.get('analysis_id', '-')}\n"
            f"대상: {data.get('repository', '-')}\n"
            f"Commit: {data.get('commit', '-')}\n"
            f"현재 단계: {data.get('current_stage', '준비 중')}\n"
            f"대시보드: {data.get('dashboard_url', '-')}\n"
        )
        _emit_static_coverage(stream, data)
        return
    stream.write(f"분석 ID: {data.get('analysis_id', '-')}\n")
    if "status" in data:
        stream.write(f"상태: {data['status']}\n")
    if "percent" in data:
        stream.write(f"진행률: {data['percent']}%\n")
    if "current_stage" in data:
        stream.write(f"현재 단계: {data['current_stage']}\n")
    _emit_static_coverage(stream, data)
    candidate_total = data.get("candidate_total_count")
    if type(candidate_total) is int:
        raw_decisions = data.get("candidate_decision_counts")
        decisions = raw_decisions if isinstance(raw_decisions, dict) else {}
        labels = (
            ("INCLUDE", "포함"),
            ("EXCLUDE", "제외"),
            ("UNDECIDED", "미확정"),
            ("PENDING", "대기"),
            ("ERROR", "오류"),
        )
        summary = " · ".join(
            f"{label} {decisions.get(status, 0)}" for status, label in labels
        )
        stream.write(f"후보: 총 {candidate_total}개 · {summary}\n")
        stream.write(
            "심층 분석: "
            f"진행 {data.get('deep_analysis_running_count', 0)} · "
            f"완료 {data.get('deep_analysis_completed_count', 0)} · "
            f"대기 {data.get('deep_analysis_pending_count', 0)}\n"
        )
    if type(data.get("hypothesis_count")) is int:
        stream.write(f"가설: {data['hypothesis_count']}개\n")
    attempt_number = data.get("attempt_number")
    attempt_limit = data.get("attempt_limit")
    if (
        isinstance(attempt_number, int)
        and isinstance(attempt_limit, int)
        and (attempt_number > 1 or data.get("error_code") == "RECOVERY_EXHAUSTED")
    ):
        stream.write(f"복구 시도: {attempt_number}/{attempt_limit}\n")
    if data.get("error_code"):
        stream.write(f"오류: {data['error_code']}\n")
    if command == "resume" and data.get("resume_skipped_reason") == (
        "ANALYSIS_ALREADY_RUNNING"
    ):
        stream.write(
            "이미 다른 프로세스가 이 분석을 실행 중이어서 재개를 건너뛰었습니다.\n"
        )
        return
    if "finding_count" in data:
        stream.write(f"Finding: {data['finding_count']}개\n")
    if data.get("status") == "PAUSED":
        if data.get("resume_action") == "RESUME_INTERRUPTED":
            stream.write(
                "이전 실행이 중단됐습니다. 저장된 작업부터 재개하세요:\n\n"
                f"sastsimi resume {data.get('analysis_id', '')}\n"
            )
        elif data.get("resume_action") == "INCREASE_BUDGET_AND_RESUME":
            stream.write(
                "사용량 한도를 올린 뒤 이어서 실행하세요:\n\n"
                f"sastsimi resume {data.get('analysis_id', '')}\n"
            )
        elif data.get("resume_action") == "CHECK_USAGE_TELEMETRY":
            stream.write(
                "사용량 정보가 없어 중단됐습니다. 공급자 사용량과 한도 설정을 "
                "확인한 뒤 재개하세요.\n"
            )
        return
    if data.get("status") in {"BLOCKED", "FAILED"}:
        if data.get("error_code") == "RECOVERY_EXHAUSTED":
            stream.write("자동 복구 한도에 도달해 수동 검토가 필요합니다.\n")
            return
        stream.write(
            "앞 단계를 다시 실행하지 않고 이어서 실행하려면:\n\n"
            f"sastsimi resume {data.get('analysis_id', '')}\n"
        )


def unavailable() -> PublicCommandApplication:
    raise PublicCommandUnavailable("SIMPLE_RUNTIME_APPLICATION_UNAVAILABLE")


__all__ = [
    "PublicCommandApplication",
    "PublicCommandUnavailable",
    "emit_public",
    "unavailable",
]
