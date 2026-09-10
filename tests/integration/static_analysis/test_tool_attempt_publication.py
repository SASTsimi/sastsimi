from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.contracts.static import ToolRunResult
from sastsimi.orchestration.static_external_runner import StaticExternalRunner
from sastsimi.orchestration.static_publication import StaticAttemptPublisher
from sastsimi.ports.dto import CandidateRule, ProcessReceipt


@pytest.mark.parametrize(
    ("result_status", "gap_code", "expected"),
    (
        ("SUCCEEDED", None, ("SUCCEEDED", "COMPLETED")),
        ("PARTIAL", "STATIC_COVERAGE_MISSING", ("PARTIAL", "PARTIAL")),
        ("FAILED", "STATIC_TOOL_FAILED", ("FAILED", "STATIC_TOOL_FAILED")),
        ("SKIPPED", "STATIC_NOT_APPLICABLE", ("PARTIAL", "NOT_APPLICABLE")),
        ("SKIPPED", "STATIC_TOOL_CANCELLED", ("CANCELLED", "CALLER_CANCELLED")),
        ("PARTIAL", "STATIC_TOOL_CANCELLED", ("CANCELLED", "CALLER_CANCELLED")),
    ),
)
def test_publisher_owns_closed_result_work_mapping(
    result_status: str, gap_code: str | None, expected: tuple[str, str]
) -> None:
    gaps = () if gap_code is None else (SimpleNamespace(code=gap_code),)
    result = cast(ToolRunResult, SimpleNamespace(status=result_status, gaps=gaps))

    assert StaticAttemptPublisher._terminal_mapping(result) == expected


def test_publisher_rejects_cancellation_disguised_as_failure() -> None:
    result = cast(
        ToolRunResult,
        SimpleNamespace(
            status="FAILED", gaps=(SimpleNamespace(code="STATIC_TOOL_CANCELLED"),)
        ),
    )

    with pytest.raises(ValueError, match="STATIC_TOOL_STATUS_INVALID"):
        StaticAttemptPublisher._terminal_mapping(result)


def test_rule_catalog_must_be_exact_and_complete() -> None:
    rules = (CandidateRule("R1", "SELECTED", "EXECUTED", 0, None, None),)

    with pytest.raises(ValueError, match="RULE_CATALOG_CLOSURE_MISMATCH"):
        StaticAttemptPublisher._validate_rule_catalog(rules, ("R1", "R2"))


def test_tool_process_receipts_bind_exact_action_attempt_and_order() -> None:
    receipt = ProcessReceipt(
        action_id="action",
        invocation_id="attempt-batch-0",
        command_kind="opengrep-batch-0",
        attempt_id="attempt",
        command_fingerprint="a" * 64,
        outcome="SUCCEEDED",
        return_code=0,
        stdout_name="stdout.bin",
        stdout_size=2,
        stdout_sha256="b" * 64,
        stderr_name="stderr.bin",
        stderr_size=0,
        stderr_sha256="c" * 64,
        elapsed_ms=1,
    )

    assert StaticExternalRunner._validate_tool_process_receipts(
        "action", "attempt", (receipt,)
    ) == (receipt,)

    with pytest.raises(ValueError, match="STATIC_PROCESS_RECEIPT_INVALID"):
        StaticExternalRunner._validate_tool_process_receipts(
            "other", "attempt", (receipt,)
        )


@pytest.mark.parametrize(
    ("status", "rules"),
    (
        (
            "SUCCEEDED",
            (CandidateRule("R1", "SELECTED", "NOT_EXECUTED", None, "OTHER", None),),
        ),
        (
            "SKIPPED",
            (CandidateRule("R1", "SELECTED", "EXECUTED", 0, None, None),),
        ),
    ),
)
def test_rule_catalog_rejects_illegal_terminal_telemetry(
    status: str, rules: tuple[CandidateRule, ...]
) -> None:
    with pytest.raises(ValueError, match="RULE_CATALOG_CLOSURE_MISMATCH"):
        StaticAttemptPublisher._validate_rule_catalog(rules, ("R1",), status)
