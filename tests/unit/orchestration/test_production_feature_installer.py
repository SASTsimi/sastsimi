from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.bootstrap import T11Services
from sastsimi.composition.production_composition import (
    ProductionCapabilityUnavailable,
)
from sastsimi.composition.production_feature_installer import (
    CombinedPostWorkspaceSeeder,
    CurrentRepositoryProfileT11Resolver,
    ExactProductionReadiness,
)
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    LogicalRecordId,
    RecordId,
    StoredDataId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, RepositoryProfile
from sastsimi.contracts.work import WorkExecutionState


class _Seeder:
    def __init__(self, work_id: str) -> None:
        self.work_id = work_id
        self.calls = 0

    def ensure_initial(
        self,
        request: AnalysisStartRequest,
        state: AnalysisRunState,
        binding_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]:
        del request, state, binding_ref
        self.calls += 1
        return (WorkExecutionState.model_construct(work_id=WorkId(self.work_id)),)


class _Records:
    def __init__(self, profile: RepositoryProfile) -> None:
        self.profile = profile

    def get_exact(self, ref: object) -> object:
        return self.profile if ref == reference(self.profile) else None


class _Queries:
    def __init__(self, values: tuple[object, ...]) -> None:
        self.values = values

    def current_records(self, _analysis_id: str, _kind: str) -> tuple[object, ...]:
        return self.values


class _Locator:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = 0

    def root_for(self, _workspace: CodeWorkspace) -> Path:
        self.calls += 1
        return self.root


def _run_meta() -> RunMeta:
    return RunMeta(
        record_id=RecordId("workspace-record"),
        logical_record_id=LogicalRecordId("workspace-record"),
        record_type="code_workspace",
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=datetime(2026, 9, 13, tzinfo=UTC),
        analysis_id=AnalysisId("analysis"),
    )


def _profile() -> RepositoryProfile:
    workspace_ref = RunStoredDataRef(
        stored_data_id=StoredDataId("workspace-record"),
        data_kind="code_workspace",
        content_hash="a" * 64,
        analysis_id=AnalysisId("analysis"),
        record_id=RecordId("workspace-record"),
    )
    decision_ref = StoredDataRef(
        stored_data_id=StoredDataId("decision-record"),
        data_kind="action_decision",
        content_hash="b" * 64,
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("c" * 40),
        record_id=RecordId("decision-record"),
    )
    return RepositoryProfile(
        meta=RecordMeta(
            record_id=RecordId("profile-record"),
            logical_record_id=LogicalRecordId("profile-record"),
            record_type=RepositoryProfile.KIND,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=datetime(2026, 9, 13, tzinfo=UTC),
            analysis_id=AnalysisId("analysis"),
            workspace_id=WorkspaceId("workspace"),
            commit_id=CommitId("c" * 40),
            hypothesis_id=None,
            attempt_id=AttemptId("attempt"),
        ),
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("c" * 40),
        workspace_ref=workspace_ref,
        action_decision_ref=decision_ref,
        manifest_hash=content_hash(()),
        tracked_files=(),
        languages=(),
        frameworks=(),
        config_files=(),
        execution_hints=(),
        gaps=(),
        errors=(),
        status="READY",
        confirmation_reasons=(),
    )


def _workspace() -> CodeWorkspace:
    return CodeWorkspace(
        meta=_run_meta(),
        workspace_id=WorkspaceId("workspace"),
        analysis_id=AnalysisId("analysis"),
        repository_url="https://example.invalid/repository.git",
        commit_id=CommitId("c" * 40),
        status="READY",
    )


def test_combined_seeder_starts_static_and_official_policy_once() -> None:
    static = _Seeder("repository-profile")
    policy = _Seeder("official-policy")

    seeded = CombinedPostWorkspaceSeeder(static, policy).ensure_initial(
        AnalysisStartRequest.model_construct(),
        AnalysisRunState.model_construct(),
        StoredDataRef.model_construct(),
    )

    assert tuple(item.work_id for item in seeded) == (
        WorkId("repository-profile"),
        WorkId("official-policy"),
    )
    assert static.calls == policy.calls == 1


def test_readiness_fails_closed_when_exact_commit_changes() -> None:
    checked: list[str] = []
    readiness = ExactProductionReadiness(
        "analysis", "workspace", "commit-a", (lambda: checked.append("ok"),)
    )

    with pytest.raises(
        ProductionCapabilityUnavailable, match="PRODUCTION_SCOPE_CHANGED"
    ):
        readiness.require_ready(
            request=object(),
            profile=object(),
            scope=SimpleNamespace(
                analysis_id="analysis", workspace_id="workspace", commit_id="commit-b"
            ),
        )

    assert checked == []


def test_t11_is_built_lazily_from_current_profile_and_exact_checkout() -> None:
    profile = _profile()
    root = Path.cwd()
    locator = _Locator(root)
    built: list[tuple[RepositoryProfile, Path]] = []
    service = cast(T11Services, object())

    def build(found: RepositoryProfile, found_root: Path) -> T11Services:
        built.append((found, found_root))
        return service

    resolver = CurrentRepositoryProfileT11Resolver(
        records=cast(Any, _Records(profile)),
        queries=cast(Any, _Queries((profile,))),
        workspace_for=lambda _work: _workspace(),
        workspace_locator=cast(Any, locator),
        build=build,
    )
    work = WorkExecutionState.model_construct(meta=profile.meta)

    assert resolver(work) is service
    assert resolver(work) is service
    assert built == [(profile, root.resolve())]
    assert locator.calls == 2


def test_t11_fails_closed_before_build_when_current_profile_is_missing() -> None:
    profile = _profile()
    built: list[object] = []
    resolver = CurrentRepositoryProfileT11Resolver(
        records=cast(Any, _Records(profile)),
        queries=cast(Any, _Queries(())),
        workspace_for=lambda _work: _workspace(),
        workspace_locator=cast(Any, _Locator(Path.cwd())),
        build=lambda found, root: cast(T11Services, built.append((found, root))),
    )
    work = WorkExecutionState.model_construct(meta=profile.meta)

    with pytest.raises(ValueError, match="CURRENT_REPOSITORY_PROFILE_REQUIRED"):
        resolver(work)

    assert built == []
