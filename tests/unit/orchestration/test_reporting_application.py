from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import ProgramId
from sastsimi.orchestration.reporting_application import ReportingAnalysisApplication
from sastsimi.ports.scheduler import AnalysisApplicationPort, RunOutcome


class _Application:
    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        del request
        return RunOutcome("analysis-1", "TERMINAL", None)

    def status(self, analysis_id: str) -> object:
        raise AssertionError(analysis_id)

    async def cancel(self, analysis_id: str) -> object:
        raise AssertionError(analysis_id)

    async def resume(self, analysis_id: str) -> RunOutcome:
        return RunOutcome(analysis_id, "BLOCKED", None)

    def result(self, analysis_id: str) -> object:
        raise AssertionError(analysis_id)


class _Reports:
    def __init__(self) -> None:
        self.exported: list[str] = []

    def summaries(self, analysis_id: str) -> tuple[dict[str, str], ...]:
        assert analysis_id == "analysis-1"
        return (
            {"analysis_id": analysis_id, "finding_id": "finding-1"},
            {"analysis_id": analysis_id, "finding_id": "finding-2"},
        )

    def export(self, finding_id: str) -> Path:
        self.exported.append(finding_id)
        return Path(f"{finding_id}.md")


def _request() -> AnalysisStartRequest:
    return AnalysisStartRequest(
        repository_ref="https://example.invalid/repository.git",
        requested_git_ref="a" * 40,
        program_id=ProgramId("program"),
        purpose=Purpose.PRODUCTION,
    )


@pytest.mark.asyncio
async def test_terminal_run_exports_every_current_markdown_report() -> None:
    reports = _Reports()
    application = ReportingAnalysisApplication(
        cast(AnalysisApplicationPort, _Application()), reports
    )

    outcome = await application.run(_request())

    assert outcome.disposition == "TERMINAL"
    assert reports.exported == ["finding-1", "finding-2"]


@pytest.mark.asyncio
async def test_blocked_resume_never_exports_partial_report() -> None:
    reports = _Reports()
    application = ReportingAnalysisApplication(
        cast(AnalysisApplicationPort, _Application()), reports
    )

    outcome = await application.resume("analysis-1")

    assert outcome.disposition == "BLOCKED"
    assert reports.exported == []
