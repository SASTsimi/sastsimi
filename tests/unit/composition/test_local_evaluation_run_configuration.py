from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sastsimi.composition.local_evaluation_run_configuration import (
    build_local_evaluation_run_configuration,
)
from sastsimi.config.local_evaluation_profile import LocalEvaluationProfile
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.runtime.system_support import UUIDIds
from sastsimi.static_analysis.workspace_storage import decode_workspace_storage_policy
from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.unit.config.test_local_evaluation_profile import _profile_text


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 20, tzinfo=UTC)

    def monotonic_ms(self) -> int:
        return 1


def test_builds_exact_local_playbook_sandbox_and_workspace_policy(
    tmp_path: Path,
) -> None:
    profile = LocalEvaluationProfile.model_validate(
        __import__("tomllib").loads(_profile_text(tmp_path))
    )
    scope = PlannedRunScope(
        analysis_id=AnalysisId("analysis-a"),
        workspace_id=WorkspaceId("workspace-a"),
        commit_id=CommitId("a" * 40),
        repository_ref="https://example.invalid/repository.git",
    )
    artifacts = LocalArtifactStore(
        tmp_path / "data" / "artifacts", scope.workspace_id, scope.commit_id
    )

    result = build_local_evaluation_run_configuration(
        profile=profile,
        scope=scope,
        artifacts=artifacts,
        ids=UUIDIds(),
        clock=_Clock(),
    )

    assert result.playbook.scope == "COMMON"
    assert result.playbook_policy.common_playbook_ref == result.playbook_ref
    assert result.playbook_policy.type_playbooks == ()
    assert result.sandbox_profile.network_mode == "DEFAULT_DENY"
    assert result.sandbox_profile.allowed_egress_refs == ()
    assert result.workspace_policy_ref.analysis_id == scope.analysis_id
    with artifacts.open_verified(result.workspace_policy_ref) as stream:
        policy = decode_workspace_storage_policy(
            result.workspace_policy_ref, stream.read(), str(scope.analysis_id)
        )
    assert policy.max_git_bytes == profile.workspace_limits.max_git_bytes
    assert policy.max_checkout_bytes == profile.workspace_limits.max_checkout_bytes
    assert policy.max_file_count == profile.workspace_limits.max_file_count
    assert policy.min_free_bytes == profile.workspace_limits.min_free_bytes
