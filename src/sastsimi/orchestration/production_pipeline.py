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
        analysis_id = self.start(request)
        return await self.continue_run(analysis_id)

    def start(self, request: AnalysisStartRequest) -> str:
        """Validate and durably start one run without retaining request memory."""

        # Validate before allocating an analysis ID or writing run state.
        self.handlers.validate_complete(self._required_work_types)
        initialized = self._initializer.start(request)
        return initialized.analysis_id

    async def continue_run(self, analysis_id: str) -> RunOutcome:
        """Continue any durable phase and publish exactly one terminal result."""

        self.handlers.validate_complete(self._required_work_types)
        state = self._initializer.current_state(analysis_id)
        if state.status != "RUNNING":
            if state.analysis_result_ref is None:
                raise ValueError("TERMINAL_ANALYSIS_RESULT_REQUIRED")
            return RunOutcome(
                analysis_id,
                self._terminal_disposition(state.status),
                state.analysis_result_ref,
            )

        self._initializer.ensure_workspace_work(analysis_id)
        outcome = await self._scheduler.drain(analysis_id)
        self._validate_scheduler_outcome(outcome, analysis_id)
        if outcome.disposition == "BLOCKED":
            return outcome

        if self._initializer.ensure_post_workspace_seeded(analysis_id):
            outcome = await self._scheduler.drain(analysis_id)
            self._validate_scheduler_outcome(outcome, analysis_id)
            if outcome.disposition == "BLOCKED":
                return outcome

        candidate = self._aggregator.build(
            analysis_id,
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
        return RunOutcome(analysis_id, disposition, result_ref)

    @staticmethod
    def _terminal_disposition(status: str) -> RunDisposition:
        if status == "CANCELLED":
            return "CANCELLED"
        if status == "FAILED":
            return "FAILED"
        if status in {"COMPLETE", "PARTIAL"}:
            return "TERMINAL"
        raise ValueError("ANALYSIS_STATUS_INVALID")

    @staticmethod
    def _validate_scheduler_outcome(outcome: RunOutcome, analysis_id: str) -> None:
        if outcome.analysis_id != analysis_id or outcome.result_ref is not None:
            raise ValueError("SCHEDULER_OUTCOME_AUTHORITY_VIOLATION")


__all__ = ["AnalysisFinalizerPort", "ProductionPipeline"]
