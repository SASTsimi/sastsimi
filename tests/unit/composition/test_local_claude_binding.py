from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sastsimi.composition.local_claude_binding import build_local_claude_binding
from sastsimi.config.local_evaluation_profile import LocalClaudeSubscriptionSettings
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    OpaqueId,
    WorkspaceId,
)
from sastsimi.contracts.refs import reference
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.providers.claude_subscription import _CHILD_ENVIRONMENT_ALLOWLIST
from sastsimi.storage.artifact_store import LocalArtifactStore


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"local-claude-{kind.__name__.lower()}-{self.value}")


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 21, tzinfo=UTC)

    def monotonic_ms(self) -> int:
        return 0


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("analysis-local"),
        workspace_id=WorkspaceId("workspace-local"),
        commit_id=CommitId("a" * 40),
        repository_ref="https://example.invalid/project.git",
    )


def _settings(tmp_path: Path) -> LocalClaudeSubscriptionSettings:
    executable = tmp_path / "bin" / "claude"
    executable.parent.mkdir()
    executable.write_bytes(b"official-claude-code-test-binary")
    claude_config_dir = tmp_path / "claude-home"
    claude_config_dir.mkdir()
    return LocalClaudeSubscriptionSettings(
        provider_profile_key="claude-local",
        executable_path=executable.resolve(),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        claude_config_dir=claude_config_dir.resolve(),
        client_version="2.1.197",
        model="configured-model",
    )


def test_builds_exact_experimental_binding_without_production_approval(
    tmp_path: Path,
) -> None:
    scope = _scope()
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts",
        workspace_id=scope.workspace_id,
        commit_id=scope.commit_id,
    )

    result = build_local_claude_binding(
        settings=_settings(tmp_path),
        scope=scope,
        artifacts=artifacts,
        ids=_Ids(),
        clock=_Clock(),
    )

    assert result.provider.support_status == "EXPERIMENTAL"
    assert result.provider.provider == "ANTHROPIC"
    assert result.provider.product == "CLAUDE_CODE"
    assert result.provider.transport == "CLAUDE_CODE_CLIENT"
    assert result.provider.auth_mode == "SUBSCRIPTION_LOGIN"
    assert result.provider.credential_source == "OFFICIAL_CLIENT_SESSION"
    assert result.provider.validation_evidence_ref == reference(result.validation)
    assert result.client.verification_evidence_ref == reference(result.validation)
    assert result.provider.client_execution_profile_ref == reference(result.client)
    assert result.validation.tests == ()
    assert result.binding.provider_validation_evidence is None
    with artifacts.open_verified(result.client.network_policy_ref) as stream:
        assert b"OFFICIAL_CLAUDE_SERVICE_ONLY" in stream.read()


def test_declared_environment_allowlist_matches_the_adapter_constant(
    tmp_path: Path,
) -> None:
    scope = _scope()
    result = build_local_claude_binding(
        settings=_settings(tmp_path),
        scope=scope,
        artifacts=LocalArtifactStore(
            tmp_path / "artifacts",
            workspace_id=scope.workspace_id,
            commit_id=scope.commit_id,
        ),
        ids=_Ids(),
        clock=_Clock(),
    )

    assert (
        tuple(result.client.environment_variable_allowlist)
        == _CHILD_ENVIRONMENT_ALLOWLIST
    )
    assert "ANTHROPIC_API_KEY" not in _CHILD_ENVIRONMENT_ALLOWLIST
    assert "ANTHROPIC_AUTH_TOKEN" not in _CHILD_ENVIRONMENT_ALLOWLIST
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in _CHILD_ENVIRONMENT_ALLOWLIST


def test_rejects_executable_changed_after_profile_load(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.executable_path.write_bytes(b"changed")
    scope = _scope()

    with pytest.raises(ValueError, match="LOCAL_CLAUDE_EXECUTABLE_MISMATCH"):
        build_local_claude_binding(
            settings=settings,
            scope=scope,
            artifacts=LocalArtifactStore(
                tmp_path / "artifacts",
                workspace_id=scope.workspace_id,
                commit_id=scope.commit_id,
            ),
            ids=_Ids(),
            clock=_Clock(),
        )
