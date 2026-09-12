from __future__ import annotations

import shutil
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from sastsimi.bootstrap import upgrade_database
from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    ProgramId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.work import WorkType
from sastsimi.orchestration.production_application import ProductionApplication
from sastsimi.orchestration.production_call_authority import AnalysisApprovedRoute
from sastsimi.orchestration.production_composition import (
    ConcreteProductionApplicationFactory,
    InstalledProductionServices,
    ProductionCapabilityResolver,
    ProductionInstallationContext,
    ResolvedProductionCapabilities,
)
from sastsimi.orchestration.run_initialization import PostWorkspaceSeederPort
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.scheduler import CancellationObservation, CancellationTarget
from sastsimi.prompts.production import (
    REQUIRED_PRODUCTION_PROMPT_ROUTES,
    ApprovedProductionRoute,
)
from sastsimi.runtime.work_service import HandlerFailureRecorder

COMMIT = CommitId("a" * 40)


class _Handler:
    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        raise AssertionError(f"handler must not run while composing: {context}")


class _Seeder:
    def ensure_initial(self, *args: object, **kwargs: object) -> tuple[object, ...]:
        del args, kwargs
        return ()


class _Readiness:
    def __init__(self) -> None:
        self.calls = 0

    def require_ready(self, **values: object) -> None:
        assert set(values) == {"request", "scope", "profile"}
        self.calls += 1


class _Cancellation:
    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        raise AssertionError(f"nothing may be cancelled during composition: {target}")


class _Provider:
    async def invoke(self, request: object, decision_ref: object) -> object:
        raise AssertionError(
            f"provider must not run while composing: {request}, {decision_ref}"
        )

    async def cancel(self, invocation_id: str) -> object:
        raise AssertionError(
            f"provider must not cancel while composing: {invocation_id}"
        )

    async def probe(self, profile: object) -> object:
        raise AssertionError(f"provider must not probe while composing: {profile}")


class _FailureRecorder:
    def record_handler_failure(self, context: WorkContext, reason_code: str) -> object:
        raise AssertionError(
            f"handler must not fail while composing: {context}, {reason_code}"
        )


class _Capabilities(ProductionCapabilityResolver):
    def __init__(self) -> None:
        self.resolve_calls = 0
        self.install_calls = 0
        self.readiness = _Readiness()

    def resolve(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ResolvedProductionCapabilities:
        del data_dir
        assert request.requested_git_ref == str(scope.commit_id)
        assert profile.host_id == "host-one"
        self.resolve_calls += 1
        policy = RunStoredDataRef(
            stored_data_id=StoredDataId("workspace-policy"),
            data_kind="artifact",
            content_hash="b" * 64,
            analysis_id=scope.analysis_id,
            record_id=None,
        )
        git = HostConfigurationRef(
            stored_data_id=StoredDataId("git-capability"),
            data_kind="runtime_capability_profile",
            content_hash="c" * 64,
            host_id=profile.host_id,
            publication_analysis_id=scope.analysis_id,
            publication_workspace_id=scope.workspace_id,
            publication_commit_id=scope.commit_id,
            record_id=RecordId("git-capability-record"),
        )
        provider = StoredDataRef(
            stored_data_id=StoredDataId("provider-profile"),
            data_kind="provider_profile",
            content_hash="d" * 64,
            workspace_id=scope.workspace_id,
            commit_id=scope.commit_id,
            record_id=RecordId("provider-profile-record"),
        )
        approved_routes = tuple(
            AnalysisApprovedRoute(
                analysis_id=str(scope.analysis_id),
                route=route,
                approval=ApprovedProductionRoute(
                    active_prompt_ref=_code_ref(
                        scope, f"active-{index}", "prompt_registry_entry"
                    ),
                    evaluation_prompt_ref=_code_ref(
                        scope, f"evaluation-{index}", "prompt_registry_entry"
                    ),
                    quality_evaluation_ref=_code_ref(
                        scope,
                        f"recommendation-{index}",
                        "evaluation_recommendation",
                    ),
                    provider_profile_ref=provider,
                ),
            )
            for index, route in enumerate(profile.llm_routes, start=1)
        )
        return ResolvedProductionCapabilities(
            llm_adapters=cast(
                Mapping[tuple[StoredDataRef, str], LLMProviderAdapter],
                {(provider, "operator-selected-model"): _Provider()},
            ),
            approved_llm_routes=approved_routes,
            workspace_dependency_refs=cast(tuple[RecordRef, ...], (policy, git)),
            handler_failure_recorder=cast(
                HandlerFailureRecorder, _FailureRecorder()
            ),
            install=self._install,
        )

    def _install(
        self, context: ProductionInstallationContext
    ) -> InstalledProductionServices:
        self.install_calls += 1
        artifacts = context.runtime.unit_of_work.artifacts
        assert getattr(artifacts, "workspace_id", None) == WorkspaceId("workspace-one")
        assert getattr(artifacts, "commit_id", None) == COMMIT
        assert context.profiles.identity_ref(RequesterRole.RECOVERY)
        assert len(context.approved_llm_routes) == len(
            REQUIRED_PRODUCTION_PROMPT_ROUTES
        )
        return InstalledProductionServices(
            handlers=tuple((kind, _Handler()) for kind in WorkType),
            seeder=cast(PostWorkspaceSeederPort, _Seeder()),
            readiness=self.readiness,
            external_cancellation=_Cancellation(),
        )


class _MissingRouteCapabilities(_Capabilities):
    def resolve(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ResolvedProductionCapabilities:
        resolved = super().resolve(
            data_dir=data_dir,
            request=request,
            profile=profile,
            scope=scope,
        )
        return replace(
            resolved,
            approved_llm_routes=resolved.approved_llm_routes[:-1],
        )


def _profile() -> ProductionProfile:
    return ProductionProfile.model_validate(
        {
            "schema_version": 1,
            "program_id": "program-one",
            "host_id": "host-one",
            "workspace_root": "C:/sastsimi/workspaces",
            "taxonomy_version": "CWE-4.17",
            "worker": {
                "max_workers": 2,
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
            "workspace_limits": {
                "max_git_bytes": 1_073_741_824,
                "max_checkout_bytes": 2_147_483_648,
                "max_file_count": 100_000,
                "min_free_bytes": 536_870_912,
            },
            "budget": {
                "profile_key": "operator-default",
                "approval_key": "security-approved-v1",
                "approved_by": "security-team",
                "pricing_revision": "pricing-v1",
                "currency": "USD",
                "max_analysis_elapsed_ms": 3_600_000,
                "max_total_cost_minor_units": 100_000,
                "max_total_work": 1_000,
                "max_total_llm_calls": 500,
                "max_total_retries": 100,
                "max_parallel_work": 8,
                "work_timeout_ms": 600_000,
                "max_attempts_per_work": 3,
                "max_calls_per_work": 10,
                "max_items_per_work": 1_000,
                "max_verification_elapsed_ms": 900_000,
                "max_work_per_verification": 100,
                "max_llm_calls_per_verification": 50,
                "max_retries_per_work": 3,
                "max_parallel_evidence_calls": 2,
                "max_dynamic_attempts": 3,
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
                "external_program_id": "program-one",
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
                    "provider_profile_key": "provider-one",
                    "product": "OPENAI_API",
                    "environment": "PERSONAL_LOCAL",
                    "client_name": "openai-python",
                    "client_version": "2",
                    "credential_ref": {"reference": "env:OPENAI_API_KEY"},
                }
            ],
            "llm_routes": [
                {
                    "role": route.role,
                    "task_kind": route.task_kind,
                    "provider_profile_key": "provider-one",
                    "model": "operator-selected-model",
                    "prompt_key": f"{route.role.lower()}.{route.task_kind.lower()}",
                }
                for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
            ],
        }
    )


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("analysis-one"),
        workspace_id=WorkspaceId("workspace-one"),
        commit_id=COMMIT,
        repository_ref="https://example.invalid/repository.git",
    )


def _request() -> AnalysisStartRequest:
    return AnalysisStartRequest(
        repository_ref=_scope().repository_ref,
        requested_git_ref=str(COMMIT),
        program_id=ProgramId("program-one"),
        purpose=Purpose.PRODUCTION,
    )


def _code_ref(
    scope: PlannedRunScope, stored_data_id: str, data_kind: str
) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(stored_data_id),
        data_kind=data_kind,
        content_hash=(stored_data_id.encode().hex() + "0" * 64)[:64],
        workspace_id=scope.workspace_id,
        commit_id=scope.commit_id,
        record_id=RecordId(f"{stored_data_id}-record"),
    )


@contextmanager
def _writable_data_dir() -> Iterator[Path]:
    """Avoid Windows pytest temp ACLs while preserving per-test isolation."""

    data_dir = Path.cwd() / f".factory-test-{uuid4()}"
    try:
        yield data_dir
    finally:
        if data_dir.exists():
            shutil.rmtree(data_dir)


def test_factory_builds_sqlite_foundation_and_complete_handler_application() -> None:
    with _writable_data_dir() as data_dir:
        upgrade_database(data_dir)
        capabilities = _Capabilities()

        application = ConcreteProductionApplicationFactory(capabilities).build(
            data_dir=data_dir,
            request=_request(),
            profile=_profile(),
            scope=_scope(),
        )

        assert isinstance(application, ProductionApplication)
        assert application.scope == _scope()
        assert capabilities.resolve_calls == 1
        assert capabilities.install_calls == 1
        assert capabilities.readiness.calls == 1
        assert tuple(application.handlers.resolve(kind) for kind in WorkType)


def test_factory_without_exact_capability_resolver_fails_before_creating_state(
) -> None:
    from sastsimi.interfaces.cli.analyze import ProductionAnalyzeUnavailable

    with _writable_data_dir() as data_dir:
        with pytest.raises(
            ProductionAnalyzeUnavailable,
            match="PRODUCTION_CAPABILITY_RESOLVER_REQUIRED",
        ):
            ConcreteProductionApplicationFactory().build(
                data_dir=data_dir,
                request=_request(),
                profile=_profile(),
                scope=_scope(),
            )

        assert not data_dir.exists()


def test_factory_rejects_incomplete_exact_llm_route_graph_before_installing() -> None:
    from sastsimi.interfaces.cli.analyze import ProductionAnalyzeUnavailable

    with _writable_data_dir() as data_dir:
        capabilities = _MissingRouteCapabilities()
        with pytest.raises(
            ProductionAnalyzeUnavailable,
            match="PRODUCTION_LLM_ROUTE_APPROVAL_INCOMPLETE",
        ):
            ConcreteProductionApplicationFactory(capabilities).build(
                data_dir=data_dir,
                request=_request(),
                profile=_profile(),
                scope=_scope(),
            )

        assert capabilities.resolve_calls == 1
        assert capabilities.install_calls == 0
        assert not data_dir.exists()
