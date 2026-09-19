from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.composition.local_dynamic_composition import (
    LocalSharedDockerTargetResolver,
    build_local_shared_dynamic_feature,
)
from sastsimi.composition.production_dynamic_feature_builder import (
    ProductionDynamicAuthorizationResolver,
)
from sastsimi.composition.production_feature_installer import (
    DynamicProductionFeature,
)
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId


def _context(tmp_path: Path) -> Any:
    return SimpleNamespace(
        data_dir=tmp_path / "runtime-data",
        request=SimpleNamespace(purpose=Purpose.LOCAL_EVALUATION),
        profile=SimpleNamespace(
            purpose="LOCAL_EVALUATION",
            production_ready=False,
            host_id="local-host",
            codeql_container=SimpleNamespace(container_user="65532:65532"),
        ),
        scope=SimpleNamespace(
            analysis_id=AnalysisId("analysis"),
            workspace_id=WorkspaceId("workspace"),
            commit_id=CommitId("c" * 40),
        ),
        runner=cast(Any, object()),
        runtime=SimpleNamespace(
            unit_of_work=SimpleNamespace(records=cast(Any, object())),
            queries=cast(Any, object()),
            budget_registry=SimpleNamespace(current_state=cast(Any, object())),
            validator=cast(Any, object()),
        ),
        role_identity_refs={
            # The builder must pass through the run's existing local identity.
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION: object()
        },
    )


def _sandbox() -> SandboxProfile:
    return SandboxProfile.model_construct(
        cpu_limit_millicores=1_000,
        memory_limit_bytes=1_073_741_824,
        disk_limit_bytes=2_147_483_648,
        pid_limit=256,
        max_requested_execution_ms=600_000,
    )


def test_builds_local_dynamic_feature_for_the_current_shared_daemon(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "docker.exe"
    executable.write_bytes(b"local docker cli")
    workspace = tmp_path / "repository"
    workspace.mkdir()

    feature = build_local_shared_dynamic_feature(
        context=_context(tmp_path),
        sandbox_profile=_sandbox(),
        docker_executable=executable,
        docker_host="npipe:////./pipe/docker_engine",
        workspace_root_for=lambda _work: workspace,
        max_execute_turns=6,
    )

    assert isinstance(feature, DynamicProductionFeature)
    assert isinstance(
        feature.sandbox_authorization, ProductionDynamicAuthorizationResolver
    )
    assert feature.max_execute_turns == 6
    assert feature.resource_journal_path == (
        tmp_path / "runtime-data" / "local-dynamic" / "analysis" / "resources.json"
    )
    assert feature.docker_profile_ref.data_kind == "local_shared_docker_target"
    target = feature.docker_target_resolver.resolve_current(feature.docker_profile_ref)
    assert target.executable == executable.resolve()
    assert target.daemon_target == "npipe:////./pipe/docker_engine"
    assert target.subject_sha256 == hashlib.sha256(b"local docker cli").hexdigest()
    assert target.external_build_disk_limit_bytes == _sandbox().disk_limit_bytes
    assert feature.sandbox_authorization.container_user == "65532:65532"


def test_local_target_rejects_an_executable_changed_after_composition(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "docker.exe"
    executable.write_bytes(b"original docker cli")
    workspace = tmp_path / "repository"
    workspace.mkdir()
    feature = build_local_shared_dynamic_feature(
        context=_context(tmp_path),
        sandbox_profile=_sandbox(),
        docker_executable=executable,
        docker_host="npipe:////./pipe/docker_engine",
        workspace_root_for=lambda _work: workspace,
    )
    resolver = cast(LocalSharedDockerTargetResolver, feature.docker_target_resolver)
    target = resolver.resolve_current(feature.docker_profile_ref)
    executable.write_bytes(b"replaced docker cli")

    with pytest.raises(ValueError, match="LOCAL_DOCKER_TARGET_CHANGED"):
        resolver.require_current(target)


def test_local_dynamic_composition_cannot_be_used_for_production(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "docker.exe"
    executable.write_bytes(b"local docker cli")
    context = _context(tmp_path)
    context.request.purpose = Purpose.PRODUCTION

    with pytest.raises(ValueError, match="LOCAL_DYNAMIC_PURPOSE_REQUIRED"):
        build_local_shared_dynamic_feature(
            context=context,
            sandbox_profile=_sandbox(),
            docker_executable=executable,
            docker_host="npipe:////./pipe/docker_engine",
            workspace_root_for=lambda _work: tmp_path,
        )
