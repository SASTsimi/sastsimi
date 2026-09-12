"""Production application decorator that materializes current Markdown reports."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.ports.scheduler import (
    AnalysisApplicationPort,
    AnalysisStatusView,
    RunOutcome,
)


class CurrentReportExportPort(Protocol):
    def summaries(self, analysis_id: str) -> tuple[Mapping[str, str], ...]: ...

    def export(self, finding_id: str) -> Path: ...


class ReportingAnalysisApplication:
    """Export reports after terminal closure without changing domain verdicts."""

    def __init__(
        self,
        application: AnalysisApplicationPort,
        reports: CurrentReportExportPort,
    ) -> None:
        self._application = application
        self._reports = reports

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        outcome = await self._application.run(request)
        self._export_if_terminal(outcome)
        return outcome

    def status(self, analysis_id: str) -> AnalysisStatusView:
        return self._application.status(analysis_id)

    async def cancel(self, analysis_id: str) -> AnalysisStatusView:
        return await self._application.cancel(analysis_id)

    async def resume(self, analysis_id: str) -> RunOutcome:
        outcome = await self._application.resume(analysis_id)
        self._export_if_terminal(outcome)
        return outcome

    def result(self, analysis_id: str) -> AnalysisRunResult:
        return self._application.result(analysis_id)

    async def shutdown(self) -> None:
        """Release the wrapped scope-owned worker tasks."""

        shutdown = getattr(self._application, "shutdown", None)
        if shutdown is None:
            raise ValueError("PRODUCTION_SHUTDOWN_UNAVAILABLE")
        await shutdown()

    def _export_if_terminal(self, outcome: RunOutcome) -> None:
        if outcome.disposition != "TERMINAL":
            return
        seen: set[str] = set()
        for summary in self._reports.summaries(outcome.analysis_id):
            if summary.get("analysis_id") != outcome.analysis_id:
                raise ValueError("REPORT_SCOPE_MISMATCH")
            finding_id = summary.get("finding_id")
            if not finding_id or finding_id in seen:
                raise ValueError("REPORT_IDENTITY_INVALID")
            seen.add(finding_id)
            self._reports.export(finding_id)


__all__ = ["CurrentReportExportPort", "ReportingAnalysisApplication"]
