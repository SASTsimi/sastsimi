"""Fail-closed production analysis command boundary."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.run import project
from sastsimi.ports.production_analysis import (
    ProductionAnalyzeUnavailable as ProductionAnalyzeUnavailable,
)
from sastsimi.ports.scheduler import AnalysisStatusView, RunOutcome


@dataclass(frozen=True, slots=True)
class ProductionAnalyzeRequest:
    """Exact operator inputs passed untouched to the production composition."""

    data_dir: Path
    repository: str
    commit: str
    profile: Path


@dataclass(frozen=True, slots=True)
class ProductionAnalyzeCommandResult:
    """Safe projection paired with the process exit code for this run."""

    code: ExitCode
    data: dict[str, object]


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
) -> ProductionAnalyzeCommandResult:
    if entrypoint is None:
        raise ProductionAnalyzeUnavailable()
    outcome = await entrypoint(request)
    exit_code = {
        "TERMINAL": ExitCode.OK,
        "BLOCKED": ExitCode.BLOCKED,
        "FAILED": ExitCode.RUN_FAILED,
        "CANCELLED": ExitCode.RUN_CANCELLED,
    }[outcome.disposition]
    return ProductionAnalyzeCommandResult(code=exit_code, data=project(outcome))


__all__ = [
    "ProductionAnalyzeEntrypoint",
    "ProductionAnalyzeCommandResult",
    "ProductionAnalyzeRequest",
    "ProductionAnalyzeUnavailable",
    "ProductionQueryEntrypoint",
    "run",
]
