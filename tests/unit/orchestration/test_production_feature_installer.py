from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.bootstrap import T11Services
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, RepositoryProfile
from sastsimi.orchestration.production_composition import (
    ProductionCapabilityUnavailable,
)
from sastsimi.orchestration.production_feature_installer import (
    CombinedPostWorkspaceSeeder,
    CurrentRepositoryProfileT11Resolver,
    ExactProductionReadiness,
)


class _Seeder:
    def __init__(self, work_id: str) -> None:
        self.work_id = work_id
        self.calls = 0

    def ensure_initial(self, *_args: object) -> tuple[object, ...]:
        self.calls += 1
        return (SimpleNamespace(work_id=self.work_id),)


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
        record_id="workspace-record",
        logical_record_id="workspace-record",
        record_type="code_workspace",
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=datetime(2026, 9, 13, tzinfo=UTC),
        analysis_id="analysis",
    )


def _profile() -> RepositoryProfile:
    workspace_ref = RunStoredDataRef(
        stored_data_id="workspace-record",
        data_kind="code_workspace",
        content_hash="a" * 64,
        analysis_id="analysis",
        record_id="workspace-record",
    )
    decision_ref = StoredDataRef(
        stored_data_id="decision-record",
        data_kind="action_decision",
        content_hash="b" * 64,
        workspace_id="workspace",
        commit_id="c" * 40,
        record_id="decision-record",
    )
    return RepositoryProfile(
        meta=RecordMeta(
            record_id="profile-record",
            logical_record_id="profile-record",
            record_type=RepositoryProfile.KIND,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=datetime(2026, 9, 13, tzinfo=UTC),
            analysis_id="analysis",
            workspace_id="workspace",
            commit_id="c" * 40,
            hypothesis_id=None,
            attempt_id="attempt",
        ),
        workspace_id="workspace",
        commit_id="c" * 40,
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
        workspace_id="workspace",
        analysis_id="analysis",
        repository_url="https://example.invalid/repository.git",
        commit_id="c" * 40,
        status="READY",
    )


def test_combined_seeder_starts_static_and_official_policy_once() -> None:
    static = _Seeder("repository-profile")
    policy = _Seeder("official-policy")

    seeded = CombinedPostWorkspaceSeeder(static, policy).ensure_initial(
        object(), object(), object()
    )

    assert tuple(item.work_id for item in seeded) == (
        "repository-profile",
        "official-policy",
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
    resolver = CurrentRepositoryProfileT11Resolver(
        records=cast(Any, _Records(profile)),
        queries=cast(Any, _Queries((profile,))),
        workspace_for=lambda _work: _workspace(),
        workspace_locator=cast(Any, locator),
        build=lambda found, found_root: (
            built.append((found, found_root)) or service
        ),
    )
    work = cast(
        Any,
        SimpleNamespace(meta=profile.meta),
    )

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
        build=lambda found, root: cast(
            T11Services, built.append((found, root))
        ),
    )
    work = cast(
        Any,
        SimpleNamespace(meta=profile.meta),
    )

    with pytest.raises(ValueError, match="CURRENT_REPOSITORY_PROFILE_REQUIRED"):
        resolver(work)

    assert built == []
