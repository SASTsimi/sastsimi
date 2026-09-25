"""Small public command façade; detailed legacy commands remain available."""

from __future__ import annotations

from typing import TextIO

from sastsimi.interfaces.cli.output import emit_data
from sastsimi.ports.public_commands import PublicCommandApplication


class PublicCommandUnavailable(RuntimeError):
    pass


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
        return
    stream.write(f"분석 ID: {data.get('analysis_id', '-')}\n")
    if "status" in data:
        stream.write(f"상태: {data['status']}\n")
    if "percent" in data:
        stream.write(f"진행률: {data['percent']}%\n")
    if "current_stage" in data:
        stream.write(f"현재 단계: {data['current_stage']}\n")
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
    if "finding_count" in data:
        stream.write(f"Finding: {data['finding_count']}개\n")
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
