"""Production-only wrapper around the purpose-neutral analysis engine."""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.work import WorkType
from sastsimi.orchestration.analysis_application import (
    AnalysisApplication,
    AnalysisApplicationProfile,
    AnalysisReadinessPort,
    BoundArtifactStorePort,
    TimeoutSettingsPort,
    WorkerSettingsPort,
    build_analysis_application,
)
from sastsimi.ports.clock import Clock
from sastsimi.ports.scheduler import RunControlPort, SchedulerStorePort
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.runtime.cancellation_service import CancellationService
from sastsimi.runtime.run_control import BlockedWorkResumePort
from sastsimi.runtime.services import RuntimeServices

from .result_aggregation import ResultAggregationPort
from .run_initialization import RunInitializationService
from .run_scope_plan import PlannedRunScope

ProductionApplicationProfile = AnalysisApplicationProfile
ProductionReadinessPort = AnalysisReadinessPort


class ProductionApplication(AnalysisApplication):
    """Analysis engine whose public builder permanently locks PRODUCTION."""


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
    """Build only a PRODUCTION application; callers cannot select purpose."""

    return cast(
        ProductionApplication,
        build_analysis_application(
            expected_purpose=Purpose.PRODUCTION,
            request=request,
            scope=scope,
            profile=profile,
            runtime=runtime,
            handlers=handlers,
            initializer=initializer,
            aggregator=aggregator,
            scheduler_store=scheduler_store,
            controls=controls,
            cancellation=cancellation,
            resumer=resumer,
            clock=clock,
            readiness=readiness,
            application_type=ProductionApplication,
            error_namespace="PRODUCTION",
        ),
    )


__all__ = [
    "BoundArtifactStorePort",
    "ProductionApplication",
    "ProductionApplicationProfile",
    "ProductionReadinessPort",
    "TimeoutSettingsPort",
    "WorkerSettingsPort",
    "build_production_application",
]
