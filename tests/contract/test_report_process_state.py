"""Report draft lifecycle state remains exact and report-only."""

import pytest
from pydantic import ValidationError

from sastsimi.contracts.reporting import ReportProcessState
from tests.contract.domain.fixtures import meta, ref, wire


def state(**changes: object) -> ReportProcessState:
    value: dict[str, object] = dict(
        meta=meta("report_process_state", hypothesis="h1", attempt=None),
        status="NOT_REQUESTED",
        report_draft_ref=None,
        started_at=None,
        finished_at=None,
        elapsed_ms=0,
    )
    value.update(changes)
    return wire(ReportProcessState, value)


def test_report_process_state_accepts_not_requested_and_drafted() -> None:
    assert state().status == "NOT_REQUESTED"

    drafted = state(
        status="DRAFTED",
        report_draft_ref=ref("report_draft"),
        started_at="2026-09-08T00:00:00Z",
        finished_at="2026-09-08T00:00:01Z",
        elapsed_ms=1000,
    )

    assert drafted.report_draft_ref is not None


@pytest.mark.parametrize(
    "changes",
    (
        {"report_draft_ref": ref("report_draft")},
        {
            "status": "DRAFTED",
            "started_at": "2026-09-08T00:00:00Z",
            "finished_at": "2026-09-08T00:00:01Z",
            "elapsed_ms": 1000,
        },
        {
            "status": "FAILED",
            "report_draft_ref": ref("report_draft"),
            "started_at": "2026-09-08T00:00:00Z",
            "finished_at": "2026-09-08T00:00:01Z",
            "elapsed_ms": 1000,
        },
        {"status": "FAILED"},
    ),
)
def test_report_process_state_rejects_ambiguous_terminal_shapes(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        state(**changes)
