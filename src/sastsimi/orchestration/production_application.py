"""Fail-closed composition of one scope-bound production analysis application."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol, runtime_checkable

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.work import WorkType
from sastsimi.ports.clock import Clock
from sastsimi.ports.scheduler import (
    AnalysisStatusView,
    RunControlPort,
    RunOutcome,
    SchedulerStorePort,
)
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.runtime.cancellation_service import CancellationService
from sastsimi.runtime.run_control import BlockedWorkResumePort, ProductionRunControl
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.worker_pool import WorkerPool

from .production_handlers import ProductionHandlerRegistry
from .production_pipeline import ProductionPipeline
from .result_aggregation import ResultAggregationPort
from .run_initialization import RunInitializationService
from .run_scope_plan import PlannedRunScope


class WorkerSettingsPort(Protocol):
    @property
    def max_workers(self) -> int: ...

    @property
    def lease_ms(self) -> int: ...

    @property
    def heartbeat_ms(self) -> int: ...

    @property
    def poll_ms(self) -> int: ...


class TimeoutSettingsPort(Protocol):
    @property
    def shutdown_ms(self) -> int: ...


class ProductionApplicationProfile(Protocol):
    """Configuration values used by transport composition, not domain logic."""

    @property
    def program_id(self) -> str: ...

    @property
    def host_id(self) -> str: ...

    @property
    def worker(self) -> WorkerSettingsPort: ...

    @property
    def timeouts(self) -> TimeoutSettingsPort: ...


class ProductionReadinessPort(Protocol):
    """Revalidate every exact capability without selecting a fallback.

    The checker is the trusted bridge to the configuration registries. It must
    prove the current ACTIVE run profile belongs to ``scope.analysis_id`` and
    revalidate all Provider, prompt, Git, static-tool, and Sandbox capabilities
    required by the selected production profile.
    """

    def require_ready(
        self,
        *,
        request: AnalysisStartRequest,
        scope: PlannedRunScope,
        profile: ProductionApplicationProfile,
    ) -> None: ...


@runtime_checkable
class BoundArtifactStorePort(Protocol):
    workspace_id: WorkspaceId | None
    commit_id: CommitId | None


@dataclass(frozen=True, slots=True)
class ProductionApplication:
    """One immutable run scope and its concrete production transport services."""

    request: AnalysisStartRequest
    scope: PlannedRunScope
    profile: ProductionApplicationProfile
    runtime: RuntimeServices
    handlers: ProductionHandlerRegistry
    worker: WorkerPool
    pipeline: ProductionPipeline
    control: ProductionRunControl
    readiness: ProductionReadinessPort

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        canonical = _canonical_request(request, self.scope, self.profile)
        if canonical != self.request:
            raise ValueError("PRODUCTION_REQUEST_SCOPE_MISMATCH")
        _require_runtime_scope(self.runtime, self.scope)
        # A profile or executable can be retired after composition. Revalidate
        # immediately before ProductionRunControl can allocate durable state.
        self.readiness.require_ready(
            request=canonical,
            scope=self.scope,
            profile=self.profile,
        )
        outcome = await self.control.run(canonical)
        if outcome.analysis_id != str(self.scope.analysis_id):
            raise ValueError("PRODUCTION_ANALYSIS_SCOPE_MISMATCH")
        return outcome

    def status(self, analysis_id: str) -> AnalysisStatusView:
        self._require_analysis(analysis_id)
        return self.control.status(analysis_id)

    async def cancel(self, analysis_id: str) -> AnalysisStatusView:
        self._require_analysis(analysis_id)
        return await self.control.cancel(analysis_id)

    async def resume(self, analysis_id: str) -> RunOutcome:
        self._require_analysis(analysis_id)
        _require_runtime_scope(self.runtime, self.scope)
        self.readiness.require_ready(
            request=self.request,
            scope=self.scope,
            profile=self.profile,
        )
        return await self.control.resume(analysis_id)

    def result(self, analysis_id: str) -> AnalysisRunResult:
        self._require_analysis(analysis_id)
        return self.control.result(analysis_id)

    async def shutdown(self) -> None:
        await self.worker.shutdown()

    def _require_analysis(self, analysis_id: str) -> None:
        if analysis_id != str(self.scope.analysis_id):
            raise ValueError("PRODUCTION_ANALYSIS_SCOPE_MISMATCH")


def build_production_application(
    *,
    request: AnalysisStartRequest,
    scope: PlannedRunScope,
    profile: ProductionApplicationProfile,
    runtime: RuntimeServices,
    handlers: Iterable[tuple[WorkType, WorkHandler]],
    initializer: RunInitializationService,
    aggregator: ResultAggregationPort,
    scheduler_store: SchedulerStorePort,
    controls: RunControlPort,
    cancellation: CancellationService,
    resumer: BlockedWorkResumePort,
    clock: Clock,
    readiness: ProductionReadinessPort,
) -> ProductionApplication:
    """Wire existing services only after all exact production inputs validate."""

    canonical = _canonical_request(request, scope, profile)
    _require_runtime_scope(runtime, scope)

    registry = ProductionHandlerRegistry(handlers)
    registry.validate_complete(tuple(WorkType))
    readiness.require_ready(request=canonical, scope=scope, profile=profile)

    worker = WorkerPool(
        scheduler=scheduler_store,
        run_control=controls,
        registry=registry,
        works=runtime.work,
        clock=clock,
        worker_id=f"{profile.host_id}:{scope.analysis_id}",
        max_workers=profile.worker.max_workers,
        lease_duration=timedelta(milliseconds=profile.worker.lease_ms),
        heartbeat_interval=profile.worker.heartbeat_ms / 1_000,
        poll_interval=profile.worker.poll_ms / 1_000,
    )
    pipeline = ProductionPipeline(
        handlers=registry,
        initializer=initializer,
        scheduler=worker,
        aggregator=aggregator,
        finalizer=runtime.finalization,
    )
    control = ProductionRunControl(
        lifecycle=pipeline,
        scheduler_store=scheduler_store,
        controls=controls,
        cancellation=cancellation,
        recovery=runtime.recovery,
        runs=runtime.budget_registry,
        records=runtime.unit_of_work.records,
        resumer=resumer,
        shutdown_timeout_seconds=profile.timeouts.shutdown_ms / 1_000,
    )
    return ProductionApplication(
        request=canonical,
        scope=scope,
        profile=profile,
        runtime=runtime,
        handlers=registry,
        worker=worker,
        pipeline=pipeline,
        control=control,
        readiness=readiness,
    )


def _canonical_request(
    request: AnalysisStartRequest,
    scope: PlannedRunScope,
    profile: ProductionApplicationProfile,
) -> AnalysisStartRequest:
    commit = request.requested_git_ref.lower()
    if (
        request.purpose != Purpose.PRODUCTION
        or str(request.repository_ref) != scope.repository_ref
        or commit != str(scope.commit_id)
        or str(request.program_id) != profile.program_id
    ):
        raise ValueError("PRODUCTION_REQUEST_SCOPE_MISMATCH")
    return request.model_copy(update={"requested_git_ref": commit})


def _require_runtime_scope(runtime: RuntimeServices, scope: PlannedRunScope) -> None:
    artifacts = runtime.unit_of_work.artifacts
    if (
        not isinstance(artifacts, BoundArtifactStorePort)
        or artifacts.workspace_id != scope.workspace_id
        or artifacts.commit_id != scope.commit_id
    ):
        raise ValueError("PRODUCTION_RUNTIME_SCOPE_MISMATCH")


__all__ = [
    "BoundArtifactStorePort",
    "ProductionApplication",
    "ProductionApplicationProfile",
    "ProductionReadinessPort",
    "TimeoutSettingsPort",
    "WorkerSettingsPort",
    "build_production_application",
]
