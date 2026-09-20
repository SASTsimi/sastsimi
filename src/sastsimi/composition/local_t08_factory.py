"""Exact LOCAL_EVALUATION composition for repository and static analysis.

This module translates one explicit local profile plus currently approved host
capability references into the existing hardened T08 graph.  It does not
discover executables, downgrade CodeQL, or turn candidate materials into a
Production approval.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Literal, cast

from sastsimi.composition.local_evaluation_composition import (
    LocalEvaluationInstallationContext,
)
from sastsimi.composition.local_static_materials import (
    LocalStaticMaterialSet,
    load_local_candidate_static_materials,
)
from sastsimi.composition.production_bootstrap_runtime import (
    ProductionStaticRuntimeFactory,
)
from sastsimi.composition.production_feature_installer import T08ProductionFeature
from sastsimi.composition.production_static_adapters import (
    ProductionStaticAdapterFactory,
)
from sastsimi.composition.production_t08_builder import (
    ProductionT08Inputs,
    build_local_evaluation_t08_feature,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.refs import HostConfigurationRef, reference
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.orchestration.production_context import ProductionInstallationContext
from sastsimi.orchestration.production_provisioning import (
    StaticAdapterKey,
    StaticAnalysisProvisioning,
    StaticDecoderKey,
    StaticRouteProvisioning,
    WorkspaceStorageProvisioning,
)
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.static_analysis.codeql_adapter import digest_path
from sastsimi.storage.context_lineage import ContextLineageReader
from sastsimi.storage.repositories import SQLiteRecordStore

_BACKEND_KEY = "local-evaluation-sqlite-cas-v1"


@dataclass(frozen=True, slots=True)
class LocalEvaluationT08Capabilities:
    """Exact approved references and executable files for one local T08 run."""

    git_profile_ref: HostConfigurationRef
    python_ast_profile_ref: HostConfigurationRef
    opengrep_profile_ref: HostConfigurationRef
    codeql_profile_ref: HostConfigurationRef
    git_executable: Path
    python_ast_executable: Path
    opengrep_executable: Path
    codeql_executable: Path
    python_ast_worker: Path
    candidate_material_root: Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _workspace_relative(context: LocalEvaluationInstallationContext) -> str:
    data_root = context.data_dir.resolve(strict=False)
    workspace_root = context.profile.workspace_root.resolve(strict=False)
    try:
        relative = workspace_root.relative_to(data_root)
    except ValueError:
        raise ValueError("LOCAL_EVALUATION_WORKSPACE_ROOT_OUTSIDE_DATA_DIR") from None
    value = PurePosixPath(relative.as_posix())
    if value.as_posix() in {"", "."} or any(
        part in {"", ".", ".."} for part in value.parts
    ):
        raise ValueError("LOCAL_EVALUATION_WORKSPACE_ROOT_INVALID")
    return value.as_posix()


def _current_profiles(
    context: LocalEvaluationInstallationContext,
    capabilities: LocalEvaluationT08Capabilities,
) -> tuple[RuntimeCapabilityProfile, dict[str, StaticToolProfile]]:
    resolver = cast(
        ProductionCapabilityResolverPort, context.runtime.configuration
    )
    try:
        git = resolver.resolve_pinned_active_profile(capabilities.git_profile_ref)
        static = {
            "AST": resolver.resolve_pinned_active_profile(
                capabilities.python_ast_profile_ref
            ),
            "OPENGREP": resolver.resolve_pinned_active_profile(
                capabilities.opengrep_profile_ref
            ),
            "CODEQL": resolver.resolve_pinned_active_profile(
                capabilities.codeql_profile_ref
            ),
        }
    except (LookupError, TypeError, ValueError):
        raise ValueError("LOCAL_EVALUATION_CAPABILITY_REF_NOT_CURRENT") from None

    if (
        not isinstance(git, RuntimeCapabilityProfile)
        or reference(git) != capabilities.git_profile_ref
        or git.host_id != context.profile.host_id
        or git.profile_key != context.profile.capabilities.git_profile_key
        or git.status != "ACTIVE"
        or git.capability_kind != "GIT"
        or not {"CLONE", "CHECKOUT"} <= set(git.operations)
    ):
        raise ValueError("LOCAL_EVALUATION_GIT_PROFILE_STALE")

    expected = {
        "AST": (
            capabilities.python_ast_profile_ref,
            "PYTHON_AST",
            context.profile.capabilities.python_ast_profile_key,
        ),
        "OPENGREP": (
            capabilities.opengrep_profile_ref,
            "OPENGREP",
            context.profile.capabilities.opengrep_profile_key,
        ),
        "CODEQL": (
            capabilities.codeql_profile_ref,
            "CODEQL",
            context.profile.capabilities.codeql_profile_key,
        ),
    }
    resolved: dict[str, StaticToolProfile] = {}
    for tool, (expected_ref, adapter_key, profile_key) in expected.items():
        value = static[tool]
        if (
            not isinstance(value, StaticToolProfile)
            or reference(value) != expected_ref
            or value.host_id != context.profile.host_id
            or value.profile_key != profile_key
            or value.status != "ACTIVE"
            or value.purpose != "PRODUCTION"
            or value.adapter_key != adapter_key
        ):
            raise ValueError("LOCAL_EVALUATION_STATIC_PROFILE_STALE")
        resolved[tool] = value
    codeql = resolved["CODEQL"]
    if (
        codeql.codeql_boundary is None
        or codeql.codeql_boundary.supported_languages != ("PYTHON",)
    ):
        raise ValueError("LOCAL_EVALUATION_CODEQL_PYTHON_ONLY_REQUIRED")
    return git, resolved


def _workspace_provisioning(
    context: LocalEvaluationInstallationContext,
    *,
    profile_hash: str,
) -> tuple[WorkspaceStorageProvisioning, dict[str, bytes]]:
    relative = _workspace_relative(context)
    limits = context.profile.workspace_limits
    capacity = (
        limits.max_git_bytes
        + limits.max_checkout_bytes
        + limits.min_free_bytes
    )
    payload = canonical_bytes(
        {
            "kind": "local_evaluation_workspace_boundary",
            "schema_version": 1,
            "profile_hash": profile_hash,
            "root_relative": relative,
            "capacity_bytes": capacity,
            "max_git_bytes": limits.max_git_bytes,
            "max_checkout_bytes": limits.max_checkout_bytes,
            "max_file_count": limits.max_file_count,
            "min_free_bytes": limits.min_free_bytes,
        }
    )
    digest = hashlib.sha256(payload).hexdigest()
    scope = context.scope
    return (
        WorkspaceStorageProvisioning(
            schema_version=1,
            slot="WORKSPACE_STORAGE",
            profile_hash=profile_hash,
            analysis_id=str(scope.analysis_id),
            workspace_id=str(scope.workspace_id),
            commit_id=str(scope.commit_id),
            record_refs=(),
            evidence_sha256=(digest,),
            backend="SQLITE_RECORDS_AND_CAS",
            root_relative=relative,
            capacity_bytes=capacity,
            backend_key=_BACKEND_KEY,
            enforcement_evidence_sha256=digest,
        ),
        {digest: payload},
    )


def _static_provisioning(
    context: LocalEvaluationInstallationContext,
    materials: LocalStaticMaterialSet,
    *,
    profile_hash: str,
) -> StaticAnalysisProvisioning:
    routes: list[StaticRouteProvisioning] = []
    for tool in materials.enabled_tools:
        digests = materials.route_digests[tool]
        rules = (None, None, None) if tool == "AST" else digests[1:]
        routes.append(
            StaticRouteProvisioning(
                tool=tool,
                adapter_key=cast(StaticAdapterKey, {
                    "AST": "PYTHON_AST",
                    "OPENGREP": "OPENGREP",
                    "CODEQL": "CODEQL",
                }[tool]),
                executable_slot=cast(Literal["PYTHON_RUNTIME", "CODEQL", "OPENGREP"], {
                    "AST": "PYTHON_RUNTIME",
                    "OPENGREP": "OPENGREP",
                    "CODEQL": "CODEQL",
                }[tool]),
                decoder_key=cast(StaticDecoderKey, {
                    "AST": "PYTHON_AST_JSON_V1",
                    "OPENGREP": "OPENGREP_JSON_V1",
                    "CODEQL": "CODEQL_SARIF_V1",
                }[tool]),
                analysis_config_sha256=materials.analysis_config_sha256,
                rule_catalog_sha256=rules[0],
                rule_selection_sha256=rules[1],
                rule_mapping_sha256=rules[2],
            )
        )
    scope = context.scope
    return StaticAnalysisProvisioning(
        schema_version=1,
        slot="STATIC_ANALYSIS",
        profile_hash=profile_hash,
        analysis_id=str(scope.analysis_id),
        workspace_id=str(scope.workspace_id),
        commit_id=str(scope.commit_id),
        record_refs=(),
        evidence_sha256=tuple(materials.evidence),
        enabled_tools=materials.enabled_tools,
        routes=tuple(routes),
    )


def _require_query_pack(
    context: LocalEvaluationInstallationContext,
    materials: LocalStaticMaterialSet,
) -> None:
    configured = context.profile.codeql_container
    try:
        actual = digest_path(configured.query_pack_root)
    except (OSError, ValueError):
        raise ValueError("LOCAL_EVALUATION_CODEQL_QUERY_PACK_STALE") from None
    if (
        materials.codeql_query_pack_sha256 != configured.query_pack_sha256
        or actual != configured.query_pack_sha256
    ):
        raise ValueError("LOCAL_EVALUATION_CODEQL_QUERY_PACK_STALE")


def prepare_local_evaluation_t08_inputs(
    context: LocalEvaluationInstallationContext,
    capabilities: LocalEvaluationT08Capabilities,
) -> ProductionT08Inputs:
    """Validate exact local inputs and prepare the shared hardened T08 builder."""

    materials = load_local_candidate_static_materials(
        capabilities.candidate_material_root
    )
    _require_query_pack(context, materials)
    _current_profiles(context, capabilities)
    profile_hash = content_hash(context.profile.model_dump(mode="json"))
    workspace, workspace_evidence = _workspace_provisioning(
        context, profile_hash=profile_hash
    )
    static = _static_provisioning(context, materials, profile_hash=profile_hash)
    try:
        worker = capabilities.python_ast_worker.resolve(strict=True)
    except OSError:
        raise ValueError("LOCAL_EVALUATION_PYTHON_AST_WORKER_MISSING") from None
    if not worker.is_file():
        raise ValueError("LOCAL_EVALUATION_PYTHON_AST_WORKER_MISSING")

    ports = ProductionStaticRuntimeFactory()(
        cast(ProductionInstallationContext, context)
    )
    adapter_factory = ProductionStaticAdapterFactory(
        executables={
            "PYTHON_AST": capabilities.python_ast_executable,
            "OPENGREP": capabilities.opengrep_executable,
            "CODEQL": capabilities.codeql_executable,
        },
        python_ast_worker=worker,
        python_ast_worker_sha256=_sha256(worker),
        codeql_container_config=context.profile.codeql_container,
    )
    evidence = dict(materials.evidence)
    evidence.update(workspace_evidence)
    records = cast(SQLiteRecordStore, context.runtime.unit_of_work.records)
    return ProductionT08Inputs(
        workspace=workspace,
        static=static,
        git_clone_profile_ref=capabilities.git_profile_ref,
        git_checkout_profile_ref=capabilities.git_profile_ref,
        static_profile_refs={
            "AST": capabilities.python_ast_profile_ref,
            "OPENGREP": capabilities.opengrep_profile_ref,
            "CODEQL": capabilities.codeql_profile_ref,
        },
        evidence=MappingProxyType(evidence),
        rule_closures=materials.rule_closures,
        git_executable=capabilities.git_executable,
        build_static_adapters=adapter_factory,
        static_process_receipts=ports.process_receipts,
        static_cancellation_observation=ports.cancellation_observation,
        static_dispatch_state=ports.dispatch_state,
        static_attempt_dispatch=ports.attempt_dispatch,
        workspace_timeout_ms=context.profile.timeouts.workspace_ms,
        repository_profile_timeout_ms=context.profile.timeouts.static_tool_ms,
        allow_local_repository=context.profile.allow_local_repository,
        lineage_reader=ContextLineageReader(records),
    )


def build_local_evaluation_t08(
    context: LocalEvaluationInstallationContext,
    capabilities: LocalEvaluationT08Capabilities,
) -> T08ProductionFeature:
    """Build the real local T08 graph without Production approval claims."""

    return build_local_evaluation_t08_feature(
        context,
        prepare_local_evaluation_t08_inputs(context, capabilities),
    )


__all__ = [
    "LocalEvaluationT08Capabilities",
    "build_local_evaluation_t08",
    "prepare_local_evaluation_t08_inputs",
]
