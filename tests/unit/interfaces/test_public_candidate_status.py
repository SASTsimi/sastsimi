from __future__ import annotations

from io import StringIO

import pytest

from sastsimi.interfaces.cli.public import emit_public


def test_text_status_shows_candidate_pipeline_counts_without_conflating_findings() -> (
    None
):
    output = StringIO()
    emit_public(
        "text",
        output,
        command="status",
        data={
            "analysis_id": "A-012",
            "status": "PAUSED",
            "percent": 61,
            "candidate_total_count": 7,
            "candidate_decision_counts": {
                "INCLUDE": 2,
                "EXCLUDE": 1,
                "UNDECIDED": 1,
                "PENDING": 2,
                "ERROR": 1,
            },
            "deep_analysis_running_count": 1,
            "deep_analysis_completed_count": 1,
            "deep_analysis_pending_count": 1,
            "hypothesis_count": 3,
            "finding_count": 1,
            "resume_action": "INCREASE_BUDGET_AND_RESUME",
            "error_code": "LLM_TOKEN_BUDGET_EXHAUSTED",
        },
    )

    rendered = output.getvalue()
    assert "후보: 총 7개" in rendered
    assert "포함 2" in rendered
    assert "제외 1" in rendered
    assert "미확정 1" in rendered
    assert "대기 2" in rendered
    assert "오류 1" in rendered
    assert "심층 분석: 진행 1 · 완료 1 · 대기 1" in rendered
    assert "가설: 3개" in rendered
    assert "Finding: 1개" in rendered
    assert "한도를 올린 뒤" in rendered
    assert "앞 단계를 다시 실행하지 않고" not in rendered


def test_legacy_text_status_does_not_claim_zero_candidates() -> None:
    output = StringIO()
    emit_public(
        "text",
        output,
        command="status",
        data={"analysis_id": "A-001", "status": "RUNNING", "percent": 20},
    )

    assert "후보:" not in output.getvalue()


def test_text_paused_without_usage_shows_telemetry_action() -> None:
    output = StringIO()
    emit_public(
        "text",
        output,
        command="status",
        data={
            "analysis_id": "A-001",
            "status": "PAUSED",
            "percent": 15,
            "error_code": "LLM_COST_USAGE_UNAVAILABLE",
            "resume_action": "CHECK_USAGE_TELEMETRY",
        },
    )

    assert "사용량 정보" in output.getvalue()
    assert "한도를 올린 뒤" not in output.getvalue()


def test_text_interrupted_run_explains_resume_without_budget_advice() -> None:
    output = StringIO()
    emit_public(
        "text",
        output,
        command="status",
        data={
            "analysis_id": "A-007",
            "status": "PAUSED",
            "error_code": "INTERRUPTED_RESUME_REQUIRED",
            "resume_action": "RESUME_INTERRUPTED",
        },
    )

    rendered = output.getvalue()
    assert "오류: INTERRUPTED_RESUME_REQUIRED" in rendered
    assert "sastsimi resume A-007" in rendered
    assert "예산" not in rendered


@pytest.mark.parametrize(
    "error_code",
    ("CODEX_CALL_IN_FLIGHT_UNRESOLVED", "CODEX_PROCESS_CLEANUP_UNCONFIRMED"),
)
def test_text_unconfirmed_codex_cleanup_requires_manual_review(
    error_code: str,
) -> None:
    output = StringIO()
    emit_public(
        "text",
        output,
        command="status",
        data={
            "analysis_id": "A-001",
            "status": "BLOCKED",
            "error_code": error_code,
            "resume_action": "MANUAL_CODEX_CLEANUP_REVIEW",
        },
    )

    rendered = output.getvalue()
    assert "수동 검토" in rendered
    assert "CLI에는" in rendered
    assert "확인 명령이 없" in rendered
    assert "종료 확인을 기록한 뒤" not in rendered
    assert "sastsimi resume A-001" not in rendered


def test_text_status_shows_bounded_static_scope_categories() -> None:
    output = StringIO()
    gaps = [
        {"path": f"pkg/file_{index}.py", "rule_id": "rule.eval", "reason": "scan_gap"}
        for index in range(21)
    ]
    emit_public(
        "text",
        output,
        command="status",
        data={
            "analysis_id": "A-012",
            "status": "PARTIAL",
            "static_coverage_status": "AVAILABLE",
            "static_coverage_verified": 1,
            "static_coverage_expected": 22,
            "static_coverage_gap_count": 21,
            "static_coverage_gap_preview": gaps,
            "static_coverage_unavailable_path_count": 1,
            "static_coverage_unavailable_path_preview": [
                {"path": "pkg/unavailable.py", "reason": "scanner_failed"}
            ],
            "static_coverage_unsupported_count": 1,
            "static_coverage_unsupported_preview": [
                {"path": "pkg/unsupported.py", "reason": "no_applicable_rule"}
            ],
            "static_excluded_test_file_count": 1,
            "static_excluded_test_file_preview": [
                {"path": "tests/test_app.py", "reason": "test-directory:tests"}
            ],
            "static_out_of_scope_product_count": 1,
            "static_out_of_scope_product_preview": [
                {"path": "web/app.ts", "reason": "non_python_product_source"}
            ],
        },
    )

    rendered = output.getvalue()
    assert "정적 검사 파일·규칙: 검증 1/22 · 미검증 21" in rendered
    assert "pkg/file_0.py · rule.eval · scan_gap" in rendered
    assert "pkg/file_19.py · rule.eval · scan_gap" in rendered
    assert "pkg/file_20.py" not in rendered
    assert "외 1개" in rendered
    assert "pkg/unavailable.py · scanner_failed" in rendered
    assert "pkg/unsupported.py · no_applicable_rule" in rendered
    assert "tests/test_app.py · test-directory:tests" in rendered
    assert "web/app.ts · non_python_product_source" in rendered


def test_text_status_never_calls_missing_coverage_complete() -> None:
    output = StringIO()
    emit_public(
        "text",
        output,
        command="status",
        data={
            "analysis_id": "A-001",
            "status": "COMPLETE",
            "static_coverage_status": "UNAVAILABLE",
            "static_coverage_expected": None,
            "static_coverage_verified": None,
        },
    )

    rendered = output.getvalue()
    assert "정적 검사 범위: 확인 불가" in rendered
    assert "검증 0/0" not in rendered
