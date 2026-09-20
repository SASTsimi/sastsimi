from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import AnalysisId, CommitId, ProgramId, WorkspaceId
from sastsimi.contracts.work import WorkType
from sastsimi.orchestration.analysis_application import (
    AnalysisApplicationProfile,
    build_analysis_application,
)
from sastsimi.orchestration.result_aggregation import ResultAggregationPort
from sastsimi.orchestration.run_initialization import RunInitializationService
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.clock import Clock
from sastsimi.ports.scheduler import RunControlPort, SchedulerStorePort
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.runtime.cancellation_service import CancellationService
from sastsimi.runtime.run_control import BlockedWorkResumePort
from sastsimi.runtime.services import RuntimeServices


class _Handler:
    async def execute(self, context: object) -> object:
        raise AssertionError(context)


class _Works:
    def require_failure_recorder(self) -> None:
        return None


class _Readiness:
    def __init__(self) -> None:
        self.purposes: list[Purpose] = []

    def require_ready(
        self,
        *,
        request: AnalysisStartRequest,
        scope: PlannedRunScope,
        profile: AnalysisApplicationProfile,
    ) -> None:
        assert str(request.program_id) == profile.program_id
        assert request.requested_git_ref == str(scope.commit_id)
        self.purposes.append(request.purpose)


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("analysis"),
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("a" * 40),
        repository_ref="https://example.invalid/repository.git",
    )


def _profile() -> AnalysisApplicationProfile:
    return cast(
        AnalysisApplicationProfile,
        SimpleNamespace(
            program_id="program",
            host_id="local-host",
            worker=SimpleNamespace(
                max_workers=1,
                lease_ms=30_000,
                heartbeat_ms=5_000,
                poll_ms=10,
            ),
            timeouts=SimpleNamespace(shutdown_ms=5_000),
        ),
    )


def _runtime(scope: PlannedRunScope) -> RuntimeServices:
    return cast(
        RuntimeServices,
        SimpleNamespace(
            work=_Works(),
            recovery=object(),
            budget_registry=object(),
            unit_of_work=SimpleNamespace(
                records=object(),
                artifacts=SimpleNamespace(
                    workspace_id=scope.workspace_id,
                    commit_id=scope.commit_id,
                ),
            ),
            finalization=object(),
        ),
    )


def _handlers() -> dict[WorkType, WorkHandler]:
    return {kind: cast(WorkHandler, _Handler()) for kind in WorkType}


def _build(purpose: Purpose) -> tuple[object, _Readiness]:
    scope = _scope()
    readiness = _Readiness()
    request = AnalysisStartRequest(
        repository_ref=scope.repository_ref,
        requested_git_ref=str(scope.commit_id).upper(),
        program_id=ProgramId("program"),
        purpose=purpose,
    )
    application = build_analysis_application(
        expected_purpose=purpose,
        request=request,
        scope=scope,
        profile=_profile(),
        runtime=_runtime(scope),
        handlers=_handlers().items(),
        initializer=cast(RunInitializationService, object()),
        aggregator=cast(ResultAggregationPort, object()),
        scheduler_store=cast(SchedulerStorePort, object()),
        controls=cast(RunControlPort, object()),
        cancellation=cast(CancellationService, object()),
        resumer=cast(BlockedWorkResumePort, object()),
        clock=cast(Clock, object()),
        readiness=readiness,
    )
    return application, readiness


def test_local_evaluation_uses_shared_engine_without_production_relabeling() -> None:
    application, readiness = _build(Purpose.LOCAL_EVALUATION)

    assert application.request.purpose == Purpose.LOCAL_EVALUATION
    assert application.request.requested_git_ref == "a" * 40
    assert readiness.purposes == [Purpose.LOCAL_EVALUATION]


def test_shared_engine_rejects_a_request_with_a_different_purpose() -> None:
    scope = _scope()
    readiness = _Readiness()
    request = AnalysisStartRequest(
        repository_ref=scope.repository_ref,
        requested_git_ref=str(scope.commit_id),
        program_id=ProgramId("program"),
        purpose=Purpose.LOCAL_EVALUATION,
    )

    with pytest.raises(ValueError, match="ANALYSIS_REQUEST_SCOPE_MISMATCH"):
        build_analysis_application(
            expected_purpose=Purpose.PRODUCTION,
            request=request,
            scope=scope,
            profile=_profile(),
            runtime=_runtime(scope),
            handlers=_handlers().items(),
            initializer=cast(RunInitializationService, object()),
            aggregator=cast(ResultAggregationPort, object()),
            scheduler_store=cast(SchedulerStorePort, object()),
            controls=cast(RunControlPort, object()),
            cancellation=cast(CancellationService, object()),
            resumer=cast(BlockedWorkResumePort, object()),
            clock=cast(Clock, object()),
            readiness=readiness,
        )


# mypy: disable-error-code="attr-defined"
