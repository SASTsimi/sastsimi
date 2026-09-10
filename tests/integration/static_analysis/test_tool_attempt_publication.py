from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.contracts.static import ToolRunResult
from sastsimi.orchestration.static_publication import StaticAttemptPublisher


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
    result = cast(
        ToolRunResult, SimpleNamespace(status=result_status, gaps=gaps)
    )

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
