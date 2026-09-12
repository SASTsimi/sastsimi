"""Repository profiling reaches durable storage through the public handler."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, RepositoryProfile
from sastsimi.orchestration.fake_setup import FakeSetupDependencies, FakeSetupStages
from sastsimi.orchestration.repository_profile_handler import RepositoryProfileHandler
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    ProcessReceipt,
    RepositoryPreparation,
    TrackedFile,
)
from sastsimi.runtime.fake_support import ANALYSIS_ID
from sastsimi.static_analysis.repository_profile import RepositoryProfiler


def _tracked(root: Path, path: str, raw: bytes) -> TrackedFile:
    target = root.joinpath(*path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return TrackedFile(path, "100644", blob, len(raw))


class _Guard:
    calls = 0

    async def assert_preparation_unchanged(
        self,
        outcome: RepositoryPreparation,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        assert outcome.status == "READY"
        assert deadline.action_id == "profile"
        assert attempt_id
        assert check_id in {
            "repository-profile-before",
            "repository-profile-after",
        }
        self.calls += 1
        return ()


@pytest.mark.asyncio
async def test_handler_publishes_profile_closed_over_ready_workspace(
    tmp_path: Path,
) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    scenario = cast(Any, pipeline)._scenario
    setup = FakeSetupStages(
        FakeSetupDependencies(
            data_dir=tmp_path,
            runtime_builder=scenario.runtime_builder,
            database_upgrader=scenario.database_upgrader,
            provider_invoke=scenario.provider_invoke,
            provider_probe=scenario.provider_probe,
            policy_fetch=scenario.policy_fetch,
            clock=scenario.clock,
            ids=scenario.ids,
            evidence=scenario.evidence,
            records=scenario.records,
        )
    )
    scope, _, orchestrator = setup._bootstrap()
    assert setup.runtime is not None and setup.runner is not None
    state = setup.runtime.budget_registry.current_state(str(ANALYSIS_ID))
    assert isinstance(state.workspace_ref, RunStoredDataRef)
    workspace = setup.runtime.unit_of_work.records.get_exact(state.workspace_ref)
    assert isinstance(workspace, CodeWorkspace)
    workspace_ref = reference(workspace)
    assert isinstance(workspace_ref, RunStoredDataRef)

    root = tmp_path / "fake-workspace"
    tracked = (
        _tracked(root, "src/app.py", b"from fastapi import FastAPI\n"),
        _tracked(
            root,
            "pyproject.toml",
            b'[project]\nname="demo"\ndependencies=["fastapi"]\n',
        ),
    )
    preparation = RepositoryPreparation(
        analysis_id=str(workspace.analysis_id),
        workspace_id=str(workspace.workspace_id),
        repository_url=workspace.repository_url,
        requested_ref="fake",
        status="READY",
        resolved_commit_id=str(workspace.commit_id),
        root=root,
        tracked_files=tracked,
        gaps=(),
        errors=(),
        lease_id=root.name,
    )
    work = setup.runner.start(
        scope,
        setup._record_meta("repository_profile"),
        "REPOSITORY_PROFILE",
        "ANALYSIS",
        str(workspace.analysis_id),
        orchestrator,
        inputs=(workspace_ref,),
    )
    guard = _Guard()
    published = await RepositoryProfileHandler(
        setup.runner,
        RepositoryProfiler(),
        guard,
    ).execute(
        work=work,
        identity=setup.evidence.identity(RequesterRole.STATIC_ANALYSIS),
        workspace=workspace,
        workspace_ref=workspace_ref,
        preparation=preparation,
        deadline=MonotonicActionDeadline("profile", 0, 10**12),
    )

    assert published.work.status == "SUCCEEDED"
    assert published.profile.status == "READY"
    assert published.profile_ref == reference(published.profile)
    assert guard.calls == 2
    stored = setup.runtime.unit_of_work.records.get_exact(published.profile_ref)
    assert isinstance(stored, RepositoryProfile)
    assert stored == published.profile
