from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.composition.production_composition import ProductionInstallationContext
from sastsimi.composition.production_t08_builder import (
    ProductionT08Inputs,
    StaticAdapterBuildContext,
    build_production_t08_feature,
)
from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.capabilities import (
    CapabilityArchitecture,
    CapabilityKind,
    CapabilityLanguage,
    CapabilityOperatingSystem,
    CapabilityOperation,
    RuntimeCapabilityProfile,
    RuntimeCapabilitySelection,
    StaticToolCapabilitySelection,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.orchestration.production_capabilities import production_profile_hash
from sastsimi.orchestration.production_operator_profiles import (
    ProductionOperatorProfiles,
)
from sastsimi.orchestration.production_provisioning import (
    StaticAnalysisProvisioning,
    StaticRouteProvisioning,
    WorkspaceStorageProvisioning,
)
from sastsimi.orchestration.repository_profile_handler import (
    RepositoryProfileWorkHandler,
)
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.orchestration.static_work_handlers import (
    ContextRetrievalWorkHandler,
    RepositoryProfileFanoutWorkHandler,
    StaticNormalizationWorkHandler,
    StaticPostWorkspaceSeeder,
    StaticToolWorkHandler,
)
from sastsimi.orchestration.workspace_prep_handler import WorkspacePrepWorkHandler
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import (
    CancellationResult,
    MonotonicActionDeadline,
    StaticCapabilityObservation,
    StaticToolObservation,
    StaticToolRequest,
)
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.production_analysis import ProductionAnalyzeUnavailable
from sastsimi.ports.scheduler import SchedulerStorePort
from sastsimi.ports.static_tool import StaticProcessAdapter
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.contract.domain.fixtures import meta
from tests.integration.orchestration.test_production_composition import (
    _profile as production_profile,
)


class _Configuration:
    def __init__(
        self,
        profiles: Mapping[
            HostConfigurationRef,
            RuntimeCapabilityProfile | StaticToolProfile,
        ],
    ) -> None:
        self._profiles = profiles

    def resolve_pinned_active_profile(
        self, profile_ref: HostConfigurationRef
    ) -> RuntimeCapabilityProfile | StaticToolProfile:
        return self._profiles[profile_ref]

    def resolve_static_tool_profile_ref(
        self, profile_ref: StoredDataRef | HostConfigurationRef
    ) -> StaticToolProfile:
        profile = self._profiles[cast(HostConfigurationRef, profile_ref)]
        if not isinstance(profile, StaticToolProfile):
            raise LookupError(profile_ref)
        return profile

    def resolve_active_capability(
        self,
        *,
        capability_kind: CapabilityKind,
        language: CapabilityLanguage,
        operation: CapabilityOperation,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> RuntimeCapabilitySelection:
        raise LookupError(
            (capability_kind, language, operation, operating_system, architecture)
        )

    def resolve_active_static_tool(
        self,
        *,
        adapter_key: str,
        language: CapabilityLanguage,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> StaticToolCapabilitySelection:
        raise LookupError((adapter_key, language, operating_system, architecture))


class _ProcessAdapter:
    def __init__(self, executable: Path) -> None:
        self.executable = executable

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        raise AssertionError((profile, deadline))

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        raise AssertionError((request, workspace_root, profile, deadline))

    async def cancel(self, attempt_id: str) -> CancellationResult:
        raise AssertionError(attempt_id)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _host_ref(kind: str, key: str) -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId(key),
        data_kind=kind,
        content_hash="a" * 64,
        host_id="host-one",
        publication_analysis_id=AnalysisId("a1"),
        publication_workspace_id=WorkspaceId("ws1"),
        publication_commit_id=CommitId("c1"),
        record_id=RecordId(key),
    )


def _profile_meta(kind: str) -> dict[str, object]:
    values = meta(kind, hypothesis=None, attempt=None)
    values["created_at"] = datetime(2026, 9, 13, tzinfo=UTC)
    return values


def _git_profile(git: Path) -> RuntimeCapabilityProfile:
    return RuntimeCapabilityProfile.model_validate(
        {
            "meta": _profile_meta("runtime_capability_profile"),
            "host_id": "host-one",
            "profile_key": "git-production",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "capability_kind": "GIT",
            "subject_key": git.stem,
            "expected_version": "approved-version",
            "subject_sha256": _digest(git.read_bytes()),
            "operating_system": "windows" if os.name == "nt" else "linux",
            "architecture": "x86_64",
            "languages": ("ANY",),
            "operations": ("CLONE", "CHECKOUT"),
            "capability_evidence_ref": _host_ref(
                "tool_capability_evidence", "git-evidence"
            ),
        }
    )


def _ast_profile(executable: Path) -> StaticToolProfile:
    return StaticToolProfile.model_validate(
        {
            "meta": _profile_meta("static_tool_profile"),
            "host_id": "host-one",
            "profile_key": "ast-production",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": "PYTHON_AST",
            "tool_name": "AST",
            "tool_kind": "STRUCTURE",
            "executable_key": "python",
            "executable_sha256": _digest(executable.read_bytes()),
            "expected_version": "approved-version",
            "capability_evidence_ref": _host_ref(
                "tool_capability_evidence", "ast-evidence"
            ),
            "probe_timeout_ms": 1_000,
            "run_timeout_ms": 1_000,
            "stdout_limit_bytes": 1_024,
            "stderr_limit_bytes": 1_024,
            "max_attempt_output_bytes": 4_096,
            "max_output_file_bytes": 2_048,
            "max_artifact_read_bytes": 2_048,
        }
    )


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("a1"),
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        repository_ref="https://example.invalid/repository.git",
    )


def _budget_ref(name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(name),
        data_kind="work_budget_profile",
        content_hash="b" * 64,
        workspace_id=_scope().workspace_id,
        commit_id=_scope().commit_id,
        record_id=RecordId(name),
    )


def _context(
    root: Path,
    profile: ProductionProfile,
    configuration: _Configuration,
) -> ProductionInstallationContext:
    artifact_store = LocalArtifactStore(
        root / "artifacts", _scope().workspace_id, _scope().commit_id
    )
    runtime = cast(
        RuntimeServices,
        SimpleNamespace(
            configuration=configuration,
            unit_of_work=SimpleNamespace(artifacts=artifact_store),
        ),
    )
    runner = cast(WorkflowRunner, SimpleNamespace(runtime=runtime))
    identities: Mapping[RequesterRole, BudgetScopeRef] = {
        role: _budget_ref(f"identity-{role.value.lower()}") for role in RequesterRole
    }
    return ProductionInstallationContext(
        data_dir=root,
        request=cast(AnalysisStartRequest, None),
        profile=profile,
        scope=_scope(),
        clock=cast(Clock, None),
        ids=cast(IdGenerator, None),
        profiles=cast(ProductionOperatorProfiles, None),
        role_identity_refs=identities,
        approved_llm_routes=(),
        budget_binding_ref=_budget_ref("binding"),
        runtime=runtime,
        scheduler_store=cast(SchedulerStorePort, None),
        runner=runner,
    )


def _inputs(
    profile: ProductionProfile,
    git: Path,
    git_profile: RuntimeCapabilityProfile,
    ast_profile: StaticToolProfile,
    *,
    corrupt_evidence: bool = False,
) -> ProductionT08Inputs:
    storage_evidence = b"approved quota boundary"
    analysis_config = b'{"schema_version":1}'
    storage_digest = _digest(storage_evidence)
    config_digest = _digest(analysis_config)
    profile_hash = production_profile_hash(profile)
    workspace = WorkspaceStorageProvisioning(
        schema_version=1,
        slot="WORKSPACE_STORAGE",
        profile_hash=profile_hash,
        analysis_id="a1",
        workspace_id="ws1",
        commit_id="c1",
        record_refs=(),
        evidence_sha256=(storage_digest,),
        backend="SQLITE_RECORDS_AND_CAS",
        root_relative="workspaces",
        capacity_bytes=1_000_000,
        backend_key="production-quota",
        enforcement_evidence_sha256=storage_digest,
    )
    static = StaticAnalysisProvisioning(
        schema_version=1,
        slot="STATIC_ANALYSIS",
        profile_hash=profile_hash,
        analysis_id="a1",
        workspace_id="ws1",
        commit_id="c1",
        record_refs=(),
        evidence_sha256=(config_digest,),
        enabled_tools=("AST",),
        routes=(
            StaticRouteProvisioning(
                tool="AST",
                adapter_key="PYTHON_AST",
                executable_slot="PYTHON_RUNTIME",
                decoder_key="PYTHON_AST_JSON_V1",
                analysis_config_sha256=config_digest,
            ),
        ),
    )
    evidence = {
        storage_digest: b"changed evidence" if corrupt_evidence else storage_evidence,
        config_digest: analysis_config,
    }

    def adapters(
        context: StaticAdapterBuildContext,
    ) -> Mapping[str, StaticProcessAdapter]:
        assert context.routes["AST"].tool_profile_ref == reference(ast_profile)
        return {"PYTHON_AST": _ProcessAdapter(git)}

    return ProductionT08Inputs(
        workspace=workspace,
        static=static,
        git_clone_profile_ref=cast(HostConfigurationRef, reference(git_profile)),
        git_checkout_profile_ref=cast(HostConfigurationRef, reference(git_profile)),
        static_profile_refs={"AST": cast(HostConfigurationRef, reference(ast_profile))},
        evidence=evidence,
        rule_closures={},
        git_executable=git,
        build_static_adapters=adapters,
        static_process_receipts=lambda _action, _attempt: None,
        static_cancellation_observation=lambda _request, _profile: None,
        static_dispatch_state=lambda _action: None,
        static_attempt_dispatch=lambda _attempt: None,
        workspace_timeout_ms=1_000,
        repository_profile_timeout_ms=1_000,
        allow_local_repository=True,
    )


def test_builder_installs_exact_five_stage_real_t08_graph(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    git_name = shutil.which("git")
    assert git_name is not None
    git = Path(git_name).resolve(strict=True)
    profile = production_profile()
    git_profile = _git_profile(git)
    ast_profile = _ast_profile(git)
    configuration = _Configuration(
        {
            cast(HostConfigurationRef, reference(git_profile)): git_profile,
            cast(HostConfigurationRef, reference(ast_profile)): ast_profile,
        }
    )

    feature = build_production_t08_feature(
        _context(root, profile, configuration),
        _inputs(profile, git, git_profile, ast_profile),
    )

    assert isinstance(feature.workspace_prep, WorkspacePrepWorkHandler)
    assert isinstance(feature.repository_profile, RepositoryProfileFanoutWorkHandler)
    assert isinstance(feature.static_tool, StaticToolWorkHandler)
    assert isinstance(feature.static_normalize, StaticNormalizationWorkHandler)
    assert isinstance(feature.context_retrieval, ContextRetrievalWorkHandler)
    assert isinstance(feature.seeder, StaticPostWorkspaceSeeder)
    assert isinstance(feature.repository_profile.handler, RepositoryProfileWorkHandler)


def test_builder_rejects_required_codeql_before_custom_adapter_factory(
    tmp_path: Path,
) -> None:
    git_name = shutil.which("git")
    assert git_name is not None
    git = Path(git_name).resolve(strict=True)
    profile = production_profile()
    git_profile = _git_profile(git)
    ast_profile = _ast_profile(git)
    inputs = _inputs(profile, git, git_profile, ast_profile)
    inputs = replace(
        inputs,
        static=inputs.static.model_copy(update={"enabled_tools": ("AST", "CODEQL")}),
    )
    context = _context(tmp_path, profile, _Configuration({}))
    before = set(tmp_path.rglob("*"))
    with pytest.raises(
        ProductionAnalyzeUnavailable,
        match="PRODUCTION_CODEQL_SAFE_PREREQUISITES_UNAVAILABLE",
    ):
        build_production_t08_feature(context, inputs)
    assert set(tmp_path.rglob("*")) == before


def test_builder_rejects_stale_approved_evidence_before_install(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    git_name = shutil.which("git")
    assert git_name is not None
    git = Path(git_name).resolve(strict=True)
    profile = production_profile()
    git_profile = _git_profile(git)
    ast_profile = _ast_profile(git)
    configuration = _Configuration(
        {
            cast(HostConfigurationRef, reference(git_profile)): git_profile,
            cast(HostConfigurationRef, reference(ast_profile)): ast_profile,
        }
    )

    with pytest.raises(ValueError, match="PRODUCTION_T08_EVIDENCE_STALE"):
        build_production_t08_feature(
            _context(root, profile, configuration),
            _inputs(
                profile,
                git,
                git_profile,
                ast_profile,
                corrupt_evidence=True,
            ),
        )
