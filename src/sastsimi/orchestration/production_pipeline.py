"""Production run composition over public schedulers and domain services."""

from __future__ import annotations

from typing import Protocol

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.work import WorkType
from sastsimi.ports.scheduler import (
    HandlerRegistryPort,
    RunDisposition,
    RunOutcome,
    WorkSchedulerPort,
)

from .result_aggregation import ResultAggregationPort
from .run_initialization import RunInitializationService


class AnalysisFinalizerPort(Protocol):
    """Trusted sole publisher of a terminal AnalysisRunResult."""

    def finalize(self, result: AnalysisRunResult) -> RunStoredDataRef: ...


class ProductionPipeline:
    """Drive the two budget-pinning phases and publish only terminal closure."""

    def __init__(
        self,
        *,
        handlers: HandlerRegistryPort,
        initializer: RunInitializationService,
        scheduler: WorkSchedulerPort,
        aggregator: ResultAggregationPort,
        finalizer: AnalysisFinalizerPort,
        required_work_types: tuple[WorkType, ...] = tuple(WorkType),
    ) -> None:
        self.handlers = handlers
        self._initializer = initializer
        self._scheduler = scheduler
        self._aggregator = aggregator
        self._finalizer = finalizer
        self._required_work_types = required_work_types

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        # Validate before allocating an analysis ID or writing run state.
        self.handlers.validate_complete(self._required_work_types)
        initialized = self._initializer.start(request)
        bootstrap = await self._scheduler.drain(initialized.analysis_id)
        self._validate_scheduler_outcome(bootstrap, initialized.analysis_id)
        if bootstrap.disposition == "BLOCKED":
            return bootstrap
        if bootstrap.disposition == "TERMINAL":
            self._initializer.bind_workspace_and_seed(initialized)
            outcome = await self._scheduler.drain(initialized.analysis_id)
            self._validate_scheduler_outcome(outcome, initialized.analysis_id)
            if outcome.disposition == "BLOCKED":
                return outcome
        else:
            outcome = bootstrap

        candidate = self._aggregator.build(
            request,
            initialized.analysis_id,
            outcome.disposition,
        )
        result_ref = self._finalizer.finalize(candidate)
        disposition: RunDisposition = (
            "CANCELLED"
            if candidate.status == "CANCELLED"
            else "FAILED"
            if candidate.status == "FAILED"
            else "TERMINAL"
        )
        return RunOutcome(initialized.analysis_id, disposition, result_ref)

    @staticmethod
    def _validate_scheduler_outcome(outcome: RunOutcome, analysis_id: str) -> None:
        if outcome.analysis_id != analysis_id or outcome.result_ref is not None:
            raise ValueError("SCHEDULER_OUTCOME_AUTHORITY_VIOLATION")


__all__ = ["AnalysisFinalizerPort", "ProductionPipeline"]
