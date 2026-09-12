from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import AnalysisId, CommitId, ProgramId, WorkspaceId
from sastsimi.contracts.work import WorkType
from sastsimi.orchestration.production_application import (
    ProductionApplication,
    ProductionApplicationProfile,
    ProductionReadinessPort,
    build_production_application,
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

COMMIT = CommitId("a" * 40)


class _Handler:
    async def execute(self, context: object) -> object:
        raise AssertionError(context)


class _Works:
    def __init__(self) -> None:
        self.checked = 0

    def require_failure_recorder(self) -> None:
        self.checked += 1


class _Readiness:
    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.calls = 0

    def require_ready(
        self,
        *,
        request: AnalysisStartRequest,
        scope: PlannedRunScope,
        profile: ProductionApplicationProfile,
    ) -> None:
        self.calls += 1
        assert request.requested_git_ref == str(scope.commit_id)
        assert str(request.program_id) == profile.program_id
        if not self.available:
            raise LookupError("CAPABILITY_ROUTE_NOT_ACTIVE")


def _profile() -> ProductionProfile:
    return ProductionProfile.model_validate(
        {
            "schema_version": 1,
            "program_id": "program",
            "host_id": "local-host",
            "workspace_root": Path("C:/sastsimi-workspaces"),
            "taxonomy_version": "CWE-4.17",
            "worker": {
                "max_workers": 4,
                "lease_ms": 30_000,
                "heartbeat_ms": 5_000,
                "poll_ms": 10,
            },
            "timeouts": {
                "workspace_ms": 120_000,
                "static_tool_ms": 300_000,
                "llm_ms": 120_000,
                "sandbox_ms": 600_000,
                "shutdown_ms": 5_000,
            },
            "tools": {
                "git": "git",
                "python": "python",
                "codeql": "codeql",
                "opengrep": "opengrep",
                "docker": "docker",
            },
            "policy": {
                "program_namespace": "example",
                "external_program_id": "program",
                "source_version": "2026-09-13",
                "official_endpoint": "https://security.example.test/policy",
                "publisher": "example",
                "parser_name": "default",
                "parser_version": "1.0.0",
                "freshness_ttl_seconds": 3600,
                "timeout_seconds": 30,
                "max_response_bytes": 1_048_576,
                "allowed_content_types": ["text/html"],
            },
            "providers": [
                {
                    "provider_profile_key": "provider",
                    "product": "OPENAI_API",
                    "environment": "PERSONAL_LOCAL",
                    "client_name": "openai-python",
                    "client_version": "1",
                    "credential_ref": {"reference": "env:OPENAI_API_KEY"},
                }
            ],
            "llm_routes": [
                {
                    "role": "HYPOTHESIS",
                    "task_kind": "GENERATE_INITIAL",
                    "provider_profile_key": "provider",
                    "model": "configured-model",
                    "prompt_key": "hypothesis.production-v1",
                }
            ],
        }
    )


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("analysis"),
        workspace_id=WorkspaceId("workspace"),
        commit_id=COMMIT,
        repository_ref="https://example.invalid/repository.git",
    )


def _request() -> AnalysisStartRequest:
    return AnalysisStartRequest(
        repository_ref="https://example.invalid/repository.git",
        requested_git_ref=str(COMMIT),
        program_id=ProgramId("program"),
        purpose=Purpose.PRODUCTION,
    )


def _runtime(scope: PlannedRunScope, works: _Works) -> RuntimeServices:
    artifacts = SimpleNamespace(
        workspace_id=scope.workspace_id,
        commit_id=scope.commit_id,
    )
    return cast(
        RuntimeServices,
        SimpleNamespace(
            work=works,
            recovery=object(),
            budget_registry=object(),
            unit_of_work=SimpleNamespace(records=object(), artifacts=artifacts),
            finalization=object(),
        ),
    )


def _handlers() -> dict[WorkType, WorkHandler]:
    return {kind: cast(WorkHandler, _Handler()) for kind in WorkType}


def _build(
    readiness: ProductionReadinessPort,
    *,
    handlers: dict[WorkType, WorkHandler] | None = None,
) -> tuple[ProductionApplication, _Works]:
    scope = _scope()
    works = _Works()
    application = build_production_application(
        request=_request(),
        scope=scope,
        profile=_profile(),
        runtime=_runtime(scope, works),
        handlers=(handlers or _handlers()).items(),
        initializer=cast(RunInitializationService, object()),
        aggregator=cast(ResultAggregationPort, object()),
        scheduler_store=cast(SchedulerStorePort, object()),
        controls=cast(RunControlPort, object()),
        cancellation=cast(CancellationService, object()),
        resumer=cast(BlockedWorkResumePort, object()),
        clock=cast(Clock, object()),
        readiness=readiness,
    )
    return application, works


def test_builds_one_scope_bound_application_from_complete_production_handlers() -> None:
    readiness = _Readiness()
    scope = _scope()
    handlers = _handlers()

    application, works = _build(readiness, handlers=handlers)

    assert application.request == _request()
    assert application.scope == scope
    assert application.profile == _profile()
    assert tuple(application.handlers.resolve(kind) for kind in WorkType) == tuple(
        handlers.values()
    )
    assert application.pipeline.handlers is application.handlers
    assert application.worker.active_task_count == 0
    assert readiness.calls == 1
    assert works.checked == 1


def test_missing_capability_fails_before_application_or_run_state_exists() -> None:
    readiness = _Readiness(available=False)

    with pytest.raises(LookupError, match="CAPABILITY_ROUTE_NOT_ACTIVE"):
        _build(readiness)

    assert readiness.calls == 1
