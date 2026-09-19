"""Explicit, non-production local evaluation command boundary."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from sastsimi.interfaces.cli.exit_codes import ExitCode


class LocalEvaluationUnavailable(RuntimeError):
    """The explicit local-evaluation composition cannot be built safely."""

    def __init__(self, reason_code: str = "LOCAL_EVALUATION_UNAVAILABLE") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class LocalEvaluationAnalyzeRequest:
    """Exact repository, revision, and credential-free combined profile input."""

    data_dir: Path
    repository: str
    commit: str
    profile: Path


@dataclass(frozen=True, slots=True)
class LocalEvaluationCommandResult:
    code: ExitCode
    data: dict[str, object]


class _ResultReference(Protocol):
    @property
    def record_id(self) -> object: ...


class LocalEvaluationRunOutcome(Protocol):
    @property
    def analysis_id(self) -> str: ...

    @property
    def disposition(
        self,
    ) -> Literal["TERMINAL", "BLOCKED", "FAILED", "CANCELLED"]: ...

    @property
    def result_ref(self) -> _ResultReference | None: ...


class LocalEvaluationAnalyzeEntrypoint(Protocol):
    async def __call__(
        self, request: LocalEvaluationAnalyzeRequest
    ) -> LocalEvaluationRunOutcome: ...


async def run(
    entrypoint: LocalEvaluationAnalyzeEntrypoint | None,
    request: LocalEvaluationAnalyzeRequest,
) -> LocalEvaluationCommandResult:
    if entrypoint is None:
        raise LocalEvaluationUnavailable()
    outcome = await entrypoint(request)
    exit_code = {
        "TERMINAL": ExitCode.OK,
        "BLOCKED": ExitCode.BLOCKED,
        "FAILED": ExitCode.RUN_FAILED,
        "CANCELLED": ExitCode.RUN_CANCELLED,
    }[outcome.disposition]
    data: dict[str, object] = {
        "analysis_id": outcome.analysis_id,
        "status": outcome.disposition,
        "result_record_id": str(outcome.result_ref.record_id)
        if outcome.result_ref is not None
        else None,
        "purpose": "LOCAL_EVALUATION",
        "production_ready": False,
    }
    return LocalEvaluationCommandResult(code=exit_code, data=data)


__all__ = [
    "LocalEvaluationAnalyzeEntrypoint",
    "LocalEvaluationAnalyzeRequest",
    "LocalEvaluationCommandResult",
    "LocalEvaluationRunOutcome",
    "LocalEvaluationUnavailable",
    "run",
]
