from __future__ import annotations

import shutil
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from sastsimi.bootstrap import upgrade_database
from sastsimi.composition.local_evaluation_composition import (
    ConcreteLocalEvaluationApplicationFactory,
    InstalledLocalEvaluationServices,
    LocalEvaluationCapabilityResolver,
    LocalEvaluationCompositionUnavailable,
    LocalEvaluationInstallationContext,
    ResolvedLocalEvaluationCapabilities,
)
from sastsimi.config.local_evaluation_profile import LocalEvaluationProfile
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
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.work import WorkType
from sastsimi.orchestration.analysis_application import AnalysisApplication
from sastsimi.orchestration.production_operator_profiles import (
    LocalEvaluationOperatorProfiles,
)
from sastsimi.orchestration.reporting_application import ReportingAnalysisApplication
from sastsimi.orchestration.run_initialization import PostWorkspaceSeederPort
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.scheduler import CancellationObservation, CancellationTarget
from sastsimi.ports.trusted_evidence import UnprovenEvidence
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
        request = values["request"]
        assert isinstance(request, AnalysisStartRequest)
        assert request.purpose == Purpose.LOCAL_EVALUATION
        self.calls += 1


class _Cancellation:
    async def prepare(
        self, targets: tuple[CancellationTarget, ...]
    ) -> tuple[CancellationTarget, ...]:
        return targets

    def validate_inventory(
        self, analysis_id: str, targets: tuple[CancellationTarget, ...]
    ) -> None:
        del analysis_id, targets

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        raise AssertionError(f"nothing may be cancelled while composing: {target}")


class _Provider:
    async def invoke(self, request: object) -> object:
        raise AssertionError(f"provider must not run while composing: {request}")

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


class _Capabilities(LocalEvaluationCapabilityResolver):
    def __init__(self) -> None:
        self.resolve_calls = 0
        self.install_calls = 0
        self.readiness = _Readiness()

    def resolve(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> ResolvedLocalEvaluationCapabilities:
        del data_dir
        assert request.purpose == Purpose.LOCAL_EVALUATION
        assert profile.purpose == "LOCAL_EVALUATION"
        self.resolve_calls += 1
        policy = RunStoredDataRef(
            stored_data_id=StoredDataId("policy"),
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
        return ResolvedLocalEvaluationCapabilities(
            llm_adapters=cast(
                Mapping[tuple[StoredDataRef, str], LLMProviderAdapter],
                {(provider, profile.codex.model): _Provider()},
            ),
            workspace_dependency_refs=(policy, git),
            handler_failure_recorder=cast(HandlerFailureRecorder, _FailureRecorder()),
            install=self._install,
            configuration_evidence=UnprovenEvidence(),
        )

    def _install(
        self, context: LocalEvaluationInstallationContext
    ) -> InstalledLocalEvaluationServices:
        self.install_calls += 1
        assert isinstance(context.profiles, LocalEvaluationOperatorProfiles)
        assert context.request.purpose == Purpose.LOCAL_EVALUATION
        assert context.scope == _scope()
        assert (
            getattr(context.runtime.unit_of_work.artifacts, "workspace_id", None)
            == _scope().workspace_id
        )
        return InstalledLocalEvaluationServices(
            handlers=tuple((kind, _Handler()) for kind in WorkType),
            seeder=cast(PostWorkspaceSeederPort, _Seeder()),
            readiness=self.readiness,
            external_cancellation=_Cancellation(),
        )


def _profile() -> LocalEvaluationProfile:
    root = Path.cwd().resolve()
    return LocalEvaluationProfile.model_validate(
        {
            "schema_version": 1,
            "program_id": "program-one",
            "host_id": "host-one",
            "workspace_root": str(root / ".local-evaluation-workspaces"),
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
                "profile_key": "local-default",
                "pricing_revision": "local-unpriced-v1",
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
            "codeql_container": {
                "schema_version": 1,
                "image": "example/codeql@sha256:" + "e" * 64,
                "expected_codeql_version": "2.23.1",
                "database_registry_root": str(root / ".codeql-databases"),
                "query_pack_root": str(root / ".codeql-queries"),
                "query_pack_sha256": "f" * 64,
                "database_provider_key": "local-codeql-db",
                "database_provider_revision": "1",
                "database_provider_evidence_sha256": "1" * 64,
                "database_limit_bytes": 1_000_000,
                "output_limit_bytes": 1_000_000,
                "pids_limit": 64,
                "memory_limit_bytes": 1_000_000_000,
                "nano_cpus": 1_000_000_000,
                "container_uid": 1000,
                "container_gid": 1000,
            },
            "capabilities": {
                "git_profile_key": "git-local",
                "python_runtime_profile_key": "python-runtime-local",
                "python_ast_profile_key": "python-ast-local",
                "opengrep_profile_key": "opengrep-local",
                "codeql_profile_key": "codeql-local",
            },
            "codex": {
                "provider_profile_key": "codex-local",
                "executable_path": str(root / ".tools" / "codex"),
                "executable_sha256": "2" * 64,
                "codex_home": str(root / ".credentials" / "codex-home"),
                "client_version": "0.152.1",
                "model": "operator-selected-model",
            },
        }
    )


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("analysis-local"),
        workspace_id=WorkspaceId("workspace-local"),
        commit_id=COMMIT,
        repository_ref="https://example.invalid/repository.git",
    )


def _request(purpose: Purpose = Purpose.LOCAL_EVALUATION) -> AnalysisStartRequest:
    return AnalysisStartRequest(
        repository_ref=_scope().repository_ref,
        requested_git_ref=str(COMMIT),
        program_id=ProgramId("program-one"),
        purpose=purpose,
    )


@contextmanager
def _writable_data_dir() -> Iterator[Path]:
    data_dir = Path.cwd() / f".local-factory-test-{uuid4()}"
    try:
        yield data_dir
    finally:
        if data_dir.exists():
            shutil.rmtree(data_dir)


def test_factory_builds_local_runtime_with_injected_capability_closure() -> None:
    with _writable_data_dir() as data_dir:
        upgrade_database(data_dir)
        capabilities = _Capabilities()

        application = ConcreteLocalEvaluationApplicationFactory(capabilities).build(
            data_dir=data_dir,
            request=_request(),
            profile=_profile(),
            scope=_scope(),
        )

        assert isinstance(application, ReportingAnalysisApplication)
        core = application.application
        assert isinstance(core, AnalysisApplication)
        assert core.expected_purpose == Purpose.LOCAL_EVALUATION
        assert core.scope == _scope()
        assert capabilities.resolve_calls == 1
        assert capabilities.install_calls == 1
        assert capabilities.readiness.calls == 1
        assert tuple(core.handlers.resolve(kind) for kind in WorkType)


def test_factory_rejects_production_request_before_capability_resolution() -> None:
    capabilities = _Capabilities()
    with _writable_data_dir() as data_dir:
        with pytest.raises(
            LocalEvaluationCompositionUnavailable,
            match="LOCAL_EVALUATION_REQUEST_SCOPE_MISMATCH",
        ):
            ConcreteLocalEvaluationApplicationFactory(capabilities).build(
                data_dir=data_dir,
                request=_request(Purpose.PRODUCTION),
                profile=_profile(),
                scope=_scope(),
            )

        assert capabilities.resolve_calls == 0
        assert not data_dir.exists()


def test_factory_requires_an_explicit_capability_resolver() -> None:
    with _writable_data_dir() as data_dir:
        with pytest.raises(
            LocalEvaluationCompositionUnavailable,
            match="LOCAL_EVALUATION_CAPABILITY_RESOLVER_REQUIRED",
        ):
            ConcreteLocalEvaluationApplicationFactory().build(
                data_dir=data_dir,
                request=_request(),
                profile=_profile(),
                scope=_scope(),
            )

        assert not data_dir.exists()
