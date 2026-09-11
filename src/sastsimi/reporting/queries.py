"""Public read seam for persisted ReportDraft records."""

from typing import Protocol

from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.reporting import ReportDraft, ReportProcessState
from sastsimi.ports.dto import Record


class CurrentRecordQuery(Protocol):
    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]: ...


def persisted_report_drafts(
    queries: CurrentRecordQuery, analysis_id: str
) -> tuple[ReportDraft, ...]:
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
