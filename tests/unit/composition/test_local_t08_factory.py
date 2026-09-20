from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.composition.local_evaluation_composition import (
    LocalEvaluationInstallationContext,
)
from sastsimi.composition.local_t08_factory import (
    LocalEvaluationT08Capabilities,
    build_local_evaluation_t08,
    prepare_local_evaluation_t08_inputs,
)
from sastsimi.config.local_evaluation_profile import LocalEvaluationProfile
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
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
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.orchestration.static_work_handlers import (
    ContextRetrievalWorkHandler,
    RepositoryProfileFanoutWorkHandler,
    StaticNormalizationWorkHandler,
    StaticPostWorkspaceSeeder,
    StaticToolWorkHandler,
)
from sastsimi.orchestration.workspace_prep_handler import WorkspacePrepWorkHandler
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.contract.domain.fixtures import meta

ROOT = Path(__file__).parents[3]
MATERIALS = ROOT / "config" / "static-analysis" / "candidate-v1"
COMMIT = CommitId("1" * 40)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _host_ref(kind: str, key: str) -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId(key),
        data_kind=kind,
        content_hash="a" * 64,
        host_id="host-one",
        publication_analysis_id=AnalysisId("capability-publication"),
        publication_workspace_id=WorkspaceId("capability-workspace"),
        publication_commit_id=CommitId("2" * 40),
        record_id=RecordId(key),
    )


def _record_meta(kind: str, key: str) -> dict[str, object]:
    value = meta(kind, hypothesis=None, attempt=None)
    value.update(
        record_id=key,
        logical_record_id=f"logical-{key}",
        created_at=datetime(2026, 9, 20, tzinfo=UTC),
    )
    return cast(dict[str, object], value)


def _git_profile(executable: Path) -> RuntimeCapabilityProfile:
    return RuntimeCapabilityProfile.model_validate(
        {
            "meta": _record_meta("runtime_capability_profile", "git-profile"),
            "host_id": "host-one",
            "profile_key": "git-local",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "capability_kind": "GIT",
            "subject_key": executable.stem,
            "expected_version": "2.0.0",
            "subject_sha256": _digest(executable),
            "operating_system": "windows" if os.name == "nt" else "linux",
            "architecture": "x86_64",
            "languages": ("ANY",),
            "operations": ("CLONE", "CHECKOUT"),
            "capability_evidence_ref": _host_ref(
                "tool_capability_evidence", "git-evidence"
            ),
        }
    )


def _static_profile(
    executable: Path,
    *,
    adapter: str,
    profile_key: str,
    query_pack_sha256: str,
    codeql: dict[str, object],
) -> StaticToolProfile:
    tool = {"PYTHON_AST": "AST", "OPENGREP": "OPENGREP", "CODEQL": "CODEQL"}[adapter]
    values: dict[str, object] = {
        "meta": _record_meta("static_tool_profile", f"{adapter.lower()}-profile"),
        "host_id": "host-one",
        "profile_key": profile_key,
        "purpose": "PRODUCTION",
        "status": "ACTIVE",
        "adapter_key": adapter,
        "tool_name": tool,
        "tool_kind": "STRUCTURE" if adapter == "PYTHON_AST" else "RULE_BASED",
        "executable_key": (
            "python"
            if adapter == "PYTHON_AST"
            else "opengrep"
            if adapter == "OPENGREP"
            else "docker"
        ),
        "executable_sha256": _digest(executable),
        "expected_version": (
            str(codeql["expected_codeql_version"]) if adapter == "CODEQL" else "1.0.0"
        ),
        "capability_evidence_ref": _host_ref(
            "tool_capability_evidence", f"{adapter.lower()}-evidence"
        ),
        "probe_timeout_ms": 1_000,
        "run_timeout_ms": 10_000,
        "stdout_limit_bytes": 1_000_000,
        "stderr_limit_bytes": 1_000_000,
        "max_attempt_output_bytes": (
            cast(int, codeql["output_limit_bytes"])
            if adapter == "CODEQL"
            else 1_000_000
        ),
        "max_output_file_bytes": 1_000_000,
        "max_artifact_read_bytes": 1_000_000,
    }
    if adapter == "CODEQL":
        image_digest = str(codeql["image"]).split("@", 1)[1]
        boundary_values = {
            "image_digest": image_digest,
            "user": f"{codeql['container_uid']}:{codeql['container_gid']}",
            "pids_limit": codeql["pids_limit"],
            "memory_limit_bytes": codeql["memory_limit_bytes"],
            "nano_cpus": codeql["nano_cpus"],
            "database_limit_bytes": codeql["database_limit_bytes"],
            "output_limit_bytes": codeql["output_limit_bytes"],
        }
        values["codeql_boundary"] = {
            "quota_backend_key": "CONTAINER_TMPFS_CAP_PLUS_ONE",
            "quota_enforcement_identity_sha256": content_hash(boundary_values),
            "database_limit_bytes": codeql["database_limit_bytes"],
            "execution_limit_bytes": codeql["output_limit_bytes"],
            "database_provider_key": codeql["database_provider_key"],
            "database_provider_revision": codeql["database_provider_revision"],
            "database_provider_evidence_sha256": codeql[
                "database_provider_evidence_sha256"
            ],
            "image_digest": image_digest,
            "expected_codeql_version": codeql["expected_codeql_version"],
            "query_pack_sha256": query_pack_sha256,
            "container_user": boundary_values["user"],
            "pids_limit": codeql["pids_limit"],
            "memory_limit_bytes": codeql["memory_limit_bytes"],
            "nano_cpus": codeql["nano_cpus"],
            "supported_languages": ("PYTHON",),
            "prebuilt_database_only": True,
        }
    return StaticToolProfile.model_validate(values)


class _Configuration:
    def __init__(self, values: dict[HostConfigurationRef, object]) -> None:
        self.values = values

    def resolve_pinned_active_profile(
        self, profile_ref: HostConfigurationRef
    ) -> object:
        return self.values[profile_ref]


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("analysis-local"),
        workspace_id=WorkspaceId("workspace-local"),
        commit_id=COMMIT,
        repository_ref="https://example.invalid/repository.git",
    )


def _budget_ref(key: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(key),
        data_kind="work_budget_profile",
        content_hash="b" * 64,
        workspace_id=_scope().workspace_id,
        commit_id=_scope().commit_id,
        record_id=RecordId(key),
    )


def _profile(root: Path, query_digest: str) -> LocalEvaluationProfile:
    return LocalEvaluationProfile.model_validate(
        {
            "schema_version": 1,
            "program_id": "program-one",
            "host_id": "host-one",
            "workspace_root": str(root / "workspaces"),
            "allow_local_repository": True,
            "taxonomy_version": "CWE-4.18",
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
                "max_git_bytes": 1_000_000,
                "max_checkout_bytes": 2_000_000,
                "max_file_count": 1_000,
                "min_free_bytes": 500_000,
            },
            "budget": {
                "profile_key": "local-budget",
                "pricing_revision": "unpriced-v1",
                "currency": "USD",
                "max_analysis_elapsed_ms": 3_600_000,
                "max_total_cost_minor_units": 100_000,
                "max_total_work": 100,
                "max_total_llm_calls": 50,
                "max_total_retries": 10,
                "max_parallel_work": 4,
                "work_timeout_ms": 600_000,
                "max_attempts_per_work": 3,
                "max_calls_per_work": 10,
                "max_items_per_work": 100,
                "max_verification_elapsed_ms": 900_000,
                "max_work_per_verification": 50,
                "max_llm_calls_per_verification": 20,
                "max_retries_per_work": 3,
                "max_parallel_evidence_calls": 2,
                "max_dynamic_attempts": 3,
            },
            "codeql_container": {
                "schema_version": 1,
                "image": "example/codeql@sha256:" + "e" * 64,
                "expected_codeql_version": "2.27.0",
                "database_registry_root": str(root / "codeql-databases"),
                "query_pack_root": str(MATERIALS / "codeql"),
                "query_pack_sha256": query_digest,
                "database_provider_key": "local-codeql-db",
                "database_provider_revision": "1",
                "database_provider_evidence_sha256": "d" * 64,
                "database_limit_bytes": 4_000_000,
                "output_limit_bytes": 2_000_000,
                "pids_limit": 64,
                "memory_limit_bytes": 536_870_912,
                "nano_cpus": 500_000_000,
                "container_uid": 65532,
                "container_gid": 65532,
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
                "executable_path": str(root / "bin" / "codex"),
                "executable_sha256": "c" * 64,
                "codex_home": str(root / "codex-home"),
                "client_version": "0.152.1",
                "model": "configured-model",
            },
        }
    )


def _fixture(
    root: Path, query_digest: str
) -> tuple[
    LocalEvaluationInstallationContext,
    LocalEvaluationT08Capabilities,
    _Configuration,
]:
    git_name = shutil.which("git")
    python_name = shutil.which("python") or shutil.which("python3")
    assert git_name is not None and python_name is not None
    git = Path(git_name).resolve(strict=True)
    executable = Path(python_name).resolve(strict=True)
    profile = _profile(root, query_digest)
    git_profile = _git_profile(git)
    codeql_values = profile.codeql_container.model_dump(mode="python")
    static_profiles = {
        "AST": _static_profile(
            executable,
            adapter="PYTHON_AST",
            profile_key="python-ast-local",
            query_pack_sha256=query_digest,
            codeql=codeql_values,
        ),
        "OPENGREP": _static_profile(
            executable,
            adapter="OPENGREP",
            profile_key="opengrep-local",
            query_pack_sha256=query_digest,
            codeql=codeql_values,
        ),
        "CODEQL": _static_profile(
            executable,
            adapter="CODEQL",
            profile_key="codeql-local",
            query_pack_sha256=query_digest,
            codeql=codeql_values,
        ),
    }
    values: dict[HostConfigurationRef, object] = {
        cast(HostConfigurationRef, reference(git_profile)): git_profile,
        **{
            cast(HostConfigurationRef, reference(value)): value
            for value in static_profiles.values()
        },
    }
    configuration = _Configuration(values)
    artifacts = LocalArtifactStore(
        root / "artifacts", _scope().workspace_id, _scope().commit_id
    )
    runtime = cast(
        RuntimeServices,
        SimpleNamespace(
            configuration=configuration,
            unit_of_work=SimpleNamespace(artifacts=artifacts, records=object()),
        ),
    )
    identities: dict[RequesterRole, BudgetScopeRef] = {
        role: _budget_ref(f"identity-{role.value.lower()}") for role in RequesterRole
    }
    context = LocalEvaluationInstallationContext(
        data_dir=root,
        request=cast(AnalysisStartRequest, None),
        profile=profile,
        scope=_scope(),
        clock=cast(object, None),
        ids=cast(object, None),
        profiles=cast(object, None),
        role_identity_refs=identities,
        budget_binding_ref=_budget_ref("binding"),
        runtime=runtime,
        scheduler_store=cast(object, None),
        runner=cast(WorkflowRunner, SimpleNamespace(runtime=runtime)),
    )
    capabilities = LocalEvaluationT08Capabilities(
        git_profile_ref=cast(HostConfigurationRef, reference(git_profile)),
        python_ast_profile_ref=cast(
            HostConfigurationRef, reference(static_profiles["AST"])
        ),
        opengrep_profile_ref=cast(
            HostConfigurationRef, reference(static_profiles["OPENGREP"])
        ),
        codeql_profile_ref=cast(
            HostConfigurationRef, reference(static_profiles["CODEQL"])
        ),
        git_executable=git,
        python_ast_executable=executable,
        opengrep_executable=executable,
        codeql_executable=executable,
        python_ast_worker=ROOT
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py",
        candidate_material_root=MATERIALS,
    )
    return context, capabilities, configuration


def test_builds_exact_local_workspace_and_three_tool_t08_graph(tmp_path: Path) -> None:
    from sastsimi.composition.local_static_materials import (
        load_local_candidate_static_materials,
    )

    query_digest = load_local_candidate_static_materials(
        MATERIALS
    ).codeql_query_pack_sha256
    context, capabilities, _configuration = _fixture(tmp_path, query_digest)

    inputs = prepare_local_evaluation_t08_inputs(context, capabilities)
    feature = build_local_evaluation_t08(context, capabilities)

    assert inputs.workspace.profile_hash == content_hash(
        context.profile.model_dump(mode="json")
    )
    assert inputs.workspace.root_relative == "workspaces"
    assert inputs.workspace.capacity_bytes == 3_500_000
    assert inputs.static.enabled_tools == ("AST", "OPENGREP", "CODEQL")
    assert tuple(route.tool for route in inputs.static.routes) == (
        "AST",
        "OPENGREP",
        "CODEQL",
    )
    assert set(inputs.static_profile_refs) == {"AST", "OPENGREP", "CODEQL"}
    assert all(digest in inputs.evidence for digest in inputs.static.evidence_sha256)
    assert callable(inputs.static_process_receipts)
    assert callable(inputs.static_attempt_dispatch)
    assert isinstance(feature.workspace_prep, WorkspacePrepWorkHandler)
    assert isinstance(feature.repository_profile, RepositoryProfileFanoutWorkHandler)
    assert isinstance(feature.static_tool, StaticToolWorkHandler)
    assert isinstance(feature.static_normalize, StaticNormalizationWorkHandler)
    assert isinstance(feature.context_retrieval, ContextRetrievalWorkHandler)
    assert isinstance(feature.seeder, StaticPostWorkspaceSeeder)


def test_rejects_codeql_query_pack_digest_drift_before_build(tmp_path: Path) -> None:
    context, capabilities, _configuration = _fixture(tmp_path, "f" * 64)

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_CODEQL_QUERY_PACK_STALE"):
        prepare_local_evaluation_t08_inputs(context, capabilities)


def test_rejects_a_profile_ref_that_is_no_longer_current(tmp_path: Path) -> None:
    from sastsimi.composition.local_static_materials import (
        load_local_candidate_static_materials,
    )

    query_digest = load_local_candidate_static_materials(
        MATERIALS
    ).codeql_query_pack_sha256
    context, capabilities, configuration = _fixture(tmp_path, query_digest)
    current = cast(
        StaticToolProfile,
        configuration.values[capabilities.python_ast_profile_ref],
    )
    replacement = current.model_copy(
        update={
            "meta": current.meta.model_copy(
                update={
                    "record_id": RecordId("python-ast-new"),
                    "revision_number": 2,
                    "previous_record_id": current.meta.record_id,
                }
            )
        }
    )
    configuration.values[capabilities.python_ast_profile_ref] = replacement

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_STATIC_PROFILE_STALE"):
        prepare_local_evaluation_t08_inputs(context, capabilities)


def test_rejects_codeql_profile_that_can_combine_two_languages(
    tmp_path: Path,
) -> None:
    from sastsimi.composition.local_static_materials import (
        load_local_candidate_static_materials,
    )

    query_digest = load_local_candidate_static_materials(
        MATERIALS
    ).codeql_query_pack_sha256
    context, capabilities, configuration = _fixture(tmp_path, query_digest)
    current = cast(
        StaticToolProfile,
        configuration.values[capabilities.codeql_profile_ref],
    )
    assert current.codeql_boundary is not None
    replacement = current.model_copy(
        update={
            "codeql_boundary": current.codeql_boundary.model_copy(
                update={"supported_languages": ("PYTHON", "JAVASCRIPT")}
            )
        }
    )
    replacement_ref = cast(HostConfigurationRef, reference(replacement))
    configuration.values = {
        ref: value
        for ref, value in configuration.values.items()
        if ref != capabilities.codeql_profile_ref
    } | {replacement_ref: replacement}
    capabilities = replace(capabilities, codeql_profile_ref=replacement_ref)

    with pytest.raises(
        ValueError, match="LOCAL_EVALUATION_CODEQL_PYTHON_ONLY_REQUIRED"
    ):
        prepare_local_evaluation_t08_inputs(context, capabilities)


# mypy: disable-error-code="arg-type"
