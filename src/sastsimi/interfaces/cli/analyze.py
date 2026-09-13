"""Fail-closed production analysis command boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.interfaces.cli.run import project
from sastsimi.ports.scheduler import AnalysisStatusView, RunOutcome


class ProductionAnalyzeUnavailable(RuntimeError):
    """Fail-closed production unavailability with one safe public reason code."""

    def __init__(self, reason_code: str = "PRODUCTION_ANALYZE_UNAVAILABLE") -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reason_code) is None:
            reason_code = "PRODUCTION_ANALYZE_UNAVAILABLE"
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ProductionAnalyzeRequest:
    """Exact operator inputs passed untouched to the production composition."""

    data_dir: Path
    repository: str
    commit: str
    profile: Path


class ProductionAnalyzeEntrypoint(Protocol):
    """Narrow seam implemented by the complete T14 production composition."""

    async def __call__(self, request: ProductionAnalyzeRequest) -> RunOutcome: ...


class ProductionQueryEntrypoint(Protocol):
    """Read-only seam usable without restarting or resuming work."""

    def status(self, analysis_id: str) -> AnalysisStatusView: ...

    def result(self, analysis_id: str) -> AnalysisRunResult: ...


async def run(
    entrypoint: ProductionAnalyzeEntrypoint | None,
    request: ProductionAnalyzeRequest,
) -> dict[str, object]:
    if entrypoint is None:
        raise ProductionAnalyzeUnavailable()
    return project(await entrypoint(request))


__all__ = [
    "ProductionAnalyzeEntrypoint",
    "ProductionAnalyzeRequest",
    "ProductionAnalyzeUnavailable",
    "ProductionQueryEntrypoint",
    "run",
]
