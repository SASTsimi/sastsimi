"""Fail-closed production analysis command boundary."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.interfaces.cli.run import project
from sastsimi.ports.scheduler import AnalysisStatusView, RunOutcome


class ProductionAnalyzeUnavailable(RuntimeError):
    """The production composition root was not explicitly installed."""


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
        raise ProductionAnalyzeUnavailable
    return project(await entrypoint(request))


__all__ = [
    "ProductionAnalyzeEntrypoint",
    "ProductionAnalyzeRequest",
    "ProductionAnalyzeUnavailable",
    "ProductionQueryEntrypoint",
    "run",
]
