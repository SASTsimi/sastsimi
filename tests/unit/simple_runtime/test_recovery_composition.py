from __future__ import annotations

import hashlib
from pathlib import Path

from sastsimi.composition import simple_runtime_composition as composition
from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    SimpleToolBinding,
    UserConfig,
)
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.models import CheckpointIdentity


def _config(tmp_path: Path) -> UserConfig:
    return UserConfig(
        data_dir=tmp_path / "data",
        profile_path=tmp_path / "profile.toml",
        auth_mode="API_KEY",
        provider="openai",
        model="configured-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        enabled_tools=("DOCKER",),
        detected_versions={"docker": "test"},
        setup_ready=True,
    )


def _profile(tmp_path: Path) -> SimpleExecutionProfile:
    executable = tmp_path / "docker.exe"
    executable.write_bytes(b"docker")
    return SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="configured-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=tmp_path / "data",
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        tools={
            "docker": SimpleToolBinding(
                executable_path=executable,
                version="test",
                executable_sha256=hashlib.sha256(b"docker").hexdigest(),
            )
        },
    )


def _ref(identity: CheckpointIdentity, name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{name}"),
        data_kind=name,
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId(identity.workspace_id),
        commit_id=CommitId(identity.commit_id),
        record_id=None,
    )


def test_composition_injects_identity_scoped_recovery_into_app_and_runner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    created: list[CheckpointIdentity] = []

    class Coordinator:
        def __init__(self, *, client, artifacts) -> None:
            del client
            self.identity = artifacts.identity
            created.append(self.identity)

    monkeypatch.setattr(composition, "SimpleRecoveryCoordinator", Coordinator)
    application = composition.build_analysis_application(
        _config(tmp_path),
        _profile(tmp_path),
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref(identity, "profile"),
        static_bundle_ref=_ref(identity, "bundle"),
        workspace_path=tmp_path / "workspace",
    )

    app_recovery = application._recovery_factory(identity)
    runner = application._runner_factory(application._store, identity, static)

    assert app_recovery.identity == identity
    assert runner.recovery.identity == identity
    assert created == [identity, identity]
