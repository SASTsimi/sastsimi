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


def _emit_v2_phase_counts(stream: TextIO, data: dict[str, object]) -> None:
    if data.get("percentage_kind") != "known_checkpoint_fraction":
        return
    stream.write(
        "이 비율은 현재 알려진 checkpoint 기준이며 비용·시간·저장소 전체 커버리지를 "
        "뜻하지 않습니다.\n"
    )
    phases = data.get("phase_counts")
    if not isinstance(phases, dict):
        stream.write("보안 surface: coverage 확인 불가\n")
        return
    for key, label in (
        ("static", "정적 단계"),
        ("triage", "후보 선별"),
        ("candidate_deep", "후보 심층 처리"),
        ("verification", "가설 검증"),
    ):
        values = phases.get(key)
        if (
            isinstance(values, dict)
            and type(values.get("completed")) is int
            and type(values.get("known")) is int
        ):
            stream.write(f"{label}: {values['completed']}/{values['known']}\n")
    poc = phases.get("poc")
    if (
        isinstance(poc, dict)
        and type(poc.get("attempted")) is int
        and type(poc.get("completed")) is int
    ):
        stream.write(f"PoC 시도: {poc['attempted']}건 · 완료 {poc['completed']}건\n")
    surface = phases.get("surface")
    if not isinstance(surface, dict) or type(surface.get("total")) is not int:
        stream.write("보안 surface: coverage 확인 불가\n")
        return
    total = surface["total"]
    if all(
        type(surface.get(key)) is int
        for key in ("covered", "uncovered", "insufficient")
    ):
        stream.write(
            f"보안 surface: 검토 근거 충족 {surface['covered']}/{total} · "
            f"미검토 {surface['uncovered']} · 근거 부족 {surface['insufficient']}\n"
        )
        if surface["uncovered"] or surface["insufficient"]:
            stream.write("부분 분석: 보안 surface 검토 범위가 남아 있습니다.\n")
    else:
        recorded_contexts = surface.get("recorded_contexts")
        if type(recorded_contexts) is int:
            recorded_surfaces = surface.get("recorded_surfaces")
            if type(recorded_surfaces) is int:
                stream.write(
                    "보안 surface: context가 저장된 surface "
                    f"{recorded_surfaces}/{total}개 · 저장된 context "
                    f"{recorded_contexts}건 (확장 포함) · coverage 확인 전\n"
                )
            else:
                stream.write(
                    f"보안 surface: 저장된 context {recorded_contexts}건 · "
                    f"인덱스 {total}개 · coverage 확인 전\n"
                )
        else:
            stream.write("보안 surface: coverage 확인 불가\n")


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
        label = (
            "현재 알려진 checkpoint 비율"
            if data.get("percentage_kind") == "known_checkpoint_fraction"
            else "진행률"
        )
        stream.write(f"{label}: {data['percent']}%\n")
    if "current_stage" in data:
        stream.write(f"현재 단계: {data['current_stage']}\n")
    _emit_static_coverage(stream, data)
    _emit_v2_phase_counts(stream, data)
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
    if type(data.get("finding_group_count")) is int:
        stream.write(f"표시 묶음: {data['finding_group_count']}개\n")
    if type(data.get("finding_group_undetermined_count")) is int:
        stream.write(f"묶음 미확정: {data['finding_group_undetermined_count']}개\n")
    if data.get("status") == "PAUSED":
        if data.get("resume_action") == "REVALIDATE_POC":
            stream.write(
                "이전 PoC 결과를 현재 기준으로 재검증해야 합니다. "
                "저장된 단계부터 재개하세요:\n\n"
                f"sastsimi resume {data.get('analysis_id', '')}\n"
            )
        elif data.get("resume_action") == "RESUME_INTERRUPTED":
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
        if data.get("error_code") in {
            "CODEX_CALL_IN_FLIGHT_UNRESOLVED",
            "CODEX_PROCESS_CLEANUP_UNCONFIRMED",
        }:
            stream.write(
                "Codex 호출 또는 프로세스 정리 상태를 확인할 수 없어 차단되었습니다. "
                "호출과 프로세스를 확실히 연결할 기록이 없어 운영자의 수동 검토가 "
                "필요합니다. 현재 CLI에는 종료 확인 명령이 없으며 "
                "resume을 반복해도 재개되지 않습니다.\n"
            )
            return
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
