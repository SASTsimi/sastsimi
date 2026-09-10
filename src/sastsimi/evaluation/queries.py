"""Persisted analysis-result queries behind the evaluation package seam."""

from typing import Protocol

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.ports.dto import Record


class PublishedRecords(Protocol):
    def published_records(self, analysis_id: str) -> tuple[Record, ...]: ...


def persisted_analysis_result(
    queries: PublishedRecords, analysis_id: str
) -> AnalysisRunResult | None:
    """Return the latest committed result without synthesizing terminal state."""
    results = tuple(
        item
        for item in queries.published_records(analysis_id)
        if isinstance(item, AnalysisRunResult)
    )
    return results[-1] if results else None
