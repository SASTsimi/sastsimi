"""Purpose-locked analysis application shared by production and local evaluation."""

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


class AnalysisApplicationProfile(Protocol):
    """Transport settings; authority and purpose remain outside this profile."""

    @property
    def program_id(self) -> str: ...

    @property
    def host_id(self) -> str: ...

    @property
    def worker(self) -> WorkerSettingsPort: ...

    @property
    def timeouts(self) -> TimeoutSettingsPort: ...


class AnalysisReadinessPort(Protocol):
    """Revalidate exact capabilities selected by the enclosing composition."""

    def require_ready(
        self,
        *,
        request: AnalysisStartRequest,
        scope: PlannedRunScope,
        profile: AnalysisApplicationProfile,
    ) -> None: ...


@runtime_checkable
class BoundArtifactStorePort(Protocol):
    workspace_id: WorkspaceId | None
    commit_id: CommitId | None


@dataclass(frozen=True, slots=True)
class AnalysisApplication:
    """One immutable run whose accepted purpose is fixed at composition time."""

    request: AnalysisStartRequest
    scope: PlannedRunScope
    profile: AnalysisApplicationProfile
    runtime: RuntimeServices
    handlers: ProductionHandlerRegistry
    worker: WorkerPool
    pipeline: ProductionPipeline
    control: ProductionRunControl
    readiness: AnalysisReadinessPort
    expected_purpose: Purpose
    error_namespace: str = "ANALYSIS"

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        canonical = canonical_request(
            request,
            self.scope,
            self.profile,
            expected_purpose=self.expected_purpose,
            error_namespace=self.error_namespace,
        )
        if canonical != self.request:
            raise ValueError(f"{self.error_namespace}_REQUEST_SCOPE_MISMATCH")
        require_runtime_scope(
            self.runtime,
            self.scope,
            error_namespace=self.error_namespace,
        )
        self.readiness.require_ready(
            request=canonical,
            scope=self.scope,
            profile=self.profile,
        )
        outcome = await self.control.run(canonical)
        if outcome.analysis_id != str(self.scope.analysis_id):
            raise ValueError(f"{self.error_namespace}_ANALYSIS_SCOPE_MISMATCH")
        return outcome

    def status(self, analysis_id: str) -> AnalysisStatusView:
        self._require_analysis(analysis_id)
        return self.control.status(analysis_id)

    async def cancel(self, analysis_id: str) -> AnalysisStatusView:
        self._require_analysis(analysis_id)
        return await self.control.cancel(analysis_id)

    async def resume(self, analysis_id: str) -> RunOutcome:
        self._require_analysis(analysis_id)
        require_runtime_scope(
            self.runtime,
            self.scope,
            error_namespace=self.error_namespace,
        )
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
            raise ValueError(f"{self.error_namespace}_ANALYSIS_SCOPE_MISMATCH")


def build_analysis_application(
    *,
    expected_purpose: Purpose,
    request: AnalysisStartRequest,
    scope: PlannedRunScope,
    profile: AnalysisApplicationProfile,
    runtime: RuntimeServices,
    handlers: Iterable[tuple[WorkType, WorkHandler]],
    initializer: RunInitializationService,
    aggregator: ResultAggregationPort,
    scheduler_store: SchedulerStorePort,
    controls: RunControlPort,
    cancellation: CancellationService,
    resumer: BlockedWorkResumePort,
    clock: Clock,
    readiness: AnalysisReadinessPort,
    application_type: type[AnalysisApplication] = AnalysisApplication,
    error_namespace: str = "ANALYSIS",
) -> AnalysisApplication:
    """Build the shared engine while locking its accepted purpose."""

    canonical = canonical_request(
        request,
        scope,
        profile,
        expected_purpose=expected_purpose,
        error_namespace=error_namespace,
    )
    require_runtime_scope(runtime, scope, error_namespace=error_namespace)

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
    return application_type(
        request=canonical,
        scope=scope,
        profile=profile,
        runtime=runtime,
        handlers=registry,
        worker=worker,
        pipeline=pipeline,
        control=control,
        readiness=readiness,
        expected_purpose=expected_purpose,
        error_namespace=error_namespace,
    )


def canonical_request(
    request: AnalysisStartRequest,
    scope: PlannedRunScope,
    profile: AnalysisApplicationProfile,
    *,
    expected_purpose: Purpose,
    error_namespace: str = "ANALYSIS",
) -> AnalysisStartRequest:
    commit = request.requested_git_ref.lower()
    if (
        request.purpose != expected_purpose
        or str(request.repository_ref) != scope.repository_ref
        or commit != str(scope.commit_id)
        or str(request.program_id) != profile.program_id
    ):
        raise ValueError(f"{error_namespace}_REQUEST_SCOPE_MISMATCH")
    return request.model_copy(update={"requested_git_ref": commit})


def require_runtime_scope(
    runtime: RuntimeServices,
    scope: PlannedRunScope,
    *,
    error_namespace: str = "ANALYSIS",
) -> None:
    artifacts = runtime.unit_of_work.artifacts
    if (
        not isinstance(artifacts, BoundArtifactStorePort)
        or artifacts.workspace_id != scope.workspace_id
        or artifacts.commit_id != scope.commit_id
    ):
        raise ValueError(f"{error_namespace}_RUNTIME_SCOPE_MISMATCH")


__all__ = [
    "AnalysisApplication",
    "AnalysisApplicationProfile",
    "AnalysisReadinessPort",
    "BoundArtifactStorePort",
    "TimeoutSettingsPort",
    "WorkerSettingsPort",
    "build_analysis_application",
    "canonical_request",
    "require_runtime_scope",
]
