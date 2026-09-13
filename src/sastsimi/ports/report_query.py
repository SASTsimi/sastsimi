"""Public read seam for current ReportDraft records."""

from typing import Protocol

from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.reporting import ReportDraft, ReportProcessState

from .dto import Record


class CurrentReportRecordQuery(Protocol):
    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]: ...


def current_report_drafts(
    queries: CurrentReportRecordQuery, analysis_id: str
) -> tuple[ReportDraft, ...]:
    """Return only drafts selected by the exact current process-state pointer."""

    current_refs = {
        item.report_draft_ref
        for item in queries.current_records(analysis_id, "report_process_state")
        if isinstance(item, ReportProcessState)
        and item.status == "DRAFTED"
        and item.report_draft_ref is not None
    }
    return tuple(
        item
        for item in queries.current_records(analysis_id, "report_draft")
        if isinstance(item, ReportDraft)
        and isinstance((item_ref := reference(item)), StoredDataRef)
        and item_ref in current_refs
    )


__all__ = ["CurrentReportRecordQuery", "current_report_drafts"]
