"""Crash recovery for append-only repository workspace publication."""

from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.ids import WorkspaceId
from sastsimi.orchestration.static_publication import WorkspacePreparationPublisher
from sastsimi.ports.dto import RepositoryPreparation
from sastsimi.storage.intermediate_publication import IntermediatePublicationService
from tests.integration.static_analysis.test_repository_prepare import prepared


class SimulatedCrash(BaseException):
    pass


def test_preparing_publication_crash_is_atomic_and_retryable(tmp_path: Path) -> None:
    _, runtime, runner, work, identity, _, _ = prepared(tmp_path)
    publisher = WorkspacePreparationPublisher(runner, identity)
    store = cast(IntermediatePublicationService, runtime.intermediate.store)

    def crash(stage: str) -> None:
        if stage == "before_commit":
            raise SimulatedCrash(stage)

    store.checkpoint = crash
    with pytest.raises(SimulatedCrash):
        publisher.begin(
            work,
            "https://example.invalid/team/repo.git",
            WorkspaceId("workspace"),
        )
    assert runtime.budget_registry.current_state("a1").workspace_ref is None
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"

    store.checkpoint = lambda _stage: None
    replayed = publisher.begin(
        runtime.work.get(str(work.work_id)),
        "https://example.invalid/team/repo.git",
        WorkspaceId("workspace"),
    )
    assert replayed.workspace.status == "PREPARING"
    assert (
        runtime.budget_registry.current_state("a1").workspace_ref
        == replayed.workspace_ref
    )


def test_terminal_prepared_journal_replay_converges_workspace_and_run_state(
    tmp_path: Path,
) -> None:
    _, runtime, runner, work, identity, _, _ = prepared(tmp_path)
    publisher = WorkspacePreparationPublisher(runner, identity)
    started = publisher.begin(
        work, "https://example.invalid/team/repo.git", WorkspaceId("workspace")
    )
    store = cast(IntermediatePublicationService, runtime.intermediate.store)

    def crash(stage: str) -> None:
        if stage == "PREPARED":
            raise SimulatedCrash(stage)

    store.transitions.checkpoint = crash
    with pytest.raises(SimulatedCrash):
        publisher.finish(
            started.work,
            started,
            RepositoryPreparation(
                analysis_id="a1",
                workspace_id="workspace",
                repository_url="https://example.invalid/team/repo.git",
                requested_ref="main",
                status="READY",
                resolved_commit_id="a" * 40,
                root=tmp_path / "lease",
                tracked_files=(),
                gaps=(),
                errors=(),
            ),
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"

    store.transitions.checkpoint = lambda _stage: None
    store.transitions.recover_prepared()
    recovered = runtime.work.get(str(work.work_id))
    state = runtime.budget_registry.current_state("a1")
    assert recovered.status == "SUCCEEDED"
    assert recovered.output_refs == (state.workspace_ref,)
    assert str(state.commit_id) == "a" * 40
