"""Public read seam for persisted ReportDraft records."""

from typing import Protocol

from sastsimi.contracts.reporting import ReportDraft
from sastsimi.ports.dto import Record


class CurrentRecordQuery(Protocol):
    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]: ...


def persisted_report_drafts(
    queries: CurrentRecordQuery, analysis_id: str
) -> tuple[ReportDraft, ...]:
    return tuple(
        item
        for item in queries.current_records(analysis_id, "report_draft")
        if isinstance(item, ReportDraft)
    )
