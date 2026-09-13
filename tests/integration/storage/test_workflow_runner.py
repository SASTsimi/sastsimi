"""A workflow runner must use persistent authorization and usage accounting."""

from pathlib import Path

import pytest
from sqlalchemy import func, select

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.work import TransitionCommit
from sastsimi.storage import models
from tests.integration.runtime_support import Harness


def test_workspace_work_accepts_only_well_formed_run_artifact_input(
    tmp_path: Path,
) -> None:
    """Broad unresolved-ref bypass would let an unverified policy reach Git."""
    from sastsimi.runtime.workflow_runner import WorkflowRunner

    h = Harness(tmp_path)
    execution = h.execution(max_work=10)
    assert execution.approval_ref is not None
    h.evidence.identities[execution.approval_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    scope = h.pin_execution(runtime.budget_registry, execution)
    raw = canonical_bytes(
        {
            "kind": "workspace_storage_policy",
            "schema_version": "1.0",
            "max_git_bytes": 10,
            "max_checkout_bytes": 20,
            "max_file_count": 2,
            "min_free_bytes": 30,
        }
    )
    policy_ref = runtime.unit_of_work.artifacts.commit_run(
        runtime.unit_of_work.artifacts.stage_bytes(raw, "application/json"),
        execution.meta.analysis_id,
    )
    runner = WorkflowRunner(runtime, h.clock, h.ids)
    running = runner.start(
        scope,
        execution.meta,
        "WORKSPACE_PREP",
        "ANALYSIS",
        "a1",
        execution.approval_ref,
        inputs=(policy_ref,),
    )
    assert running.input_refs == (policy_ref,)

    for wrong in (
        policy_ref.model_copy(update={"data_kind": "other"}),
        policy_ref.model_copy(update={"stored_data_id": "f" * 64}),
        policy_ref.model_copy(update={"analysis_id": "other"}),
        RunStoredDataRef(
            stored_data_id=StoredDataId("e" * 64),
            data_kind="artifact",
            content_hash="e" * 64,
            analysis_id=AnalysisId("a1"),
            record_id=None,
        ),
    ):
        with pytest.raises((LookupError, ValueError)):
            runner.start(
                scope,
                execution.meta,
                "WORKSPACE_PREP",
                "ANALYSIS",
                "a1",
                execution.approval_ref,
                inputs=(wrong,),
            )


@pytest.mark.asyncio
async def test_workspace_external_dispatch_and_usage_survive_runner(
    tmp_path: Path,
) -> None:
    from sastsimi.runtime import workflow_runner

    h = Harness(tmp_path)
    execution = h.execution(max_work=10)
    assert execution.approval_ref is not None
    h.evidence.identities[execution.approval_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    scope = h.pin_execution(runtime.budget_registry, execution)
    runner = workflow_runner.WorkflowRunner(runtime, h.clock, h.ids)
    running = runner.start(
        scope,
        execution.meta,
        "WORKSPACE_PREP",
        "ANALYSIS",
        "a1",
        execution.approval_ref,
    )
    h.evidence.identities[execution.approval_ref] = RequesterRole.REPOSITORY_LOADER
    from sastsimi.orchestration.static_publication import WorkspacePreparationPublisher
    from sastsimi.ports.dto import RepositoryPreparation

    publisher = WorkspacePreparationPublisher(runner, execution.approval_ref)
    preparing = publisher.begin(
        running, "https://example.invalid/fake", WorkspaceId("w1")
    )
    running = preparing.work

    async def external() -> str:
        return "fake-workspace-output"

    result = await runner.external(
        running,
        scope,
        execution.approval_ref,
        "REPOSITORY_LOADER",
        "RUN_TOOL",
        external,
        tool_name="fake-repository-loader",
        file_paths=("fixture.py",),
        input_refs=(preparing.workspace_ref,),
        requested_units=runner.units(elapsed_ms=1, cost_minor_units=1),
        actual_units=runner.units(elapsed_ms=1, cost_minor_units=1),
    )
    assert result == "fake-workspace-output"
    with h.database.engine.connect() as connection:
        dispatch = (
            connection.execute(select(models.external_dispatches)).mappings().one()
        )
        assert dispatch["dispatched_at"] is not None
        assert dispatch["returned_at"] is not None
        assert (
            connection.execute(
                select(func.count()).select_from(models.budget_ledger_entries)
            ).scalar_one()
            == 3
        )
    remaining = runtime.budget.remaining(scope, "a1")
    assert remaining.active_reservation_count == 0
    assert remaining.available_units.work_count == 9
    completed = publisher.finish(
        running,
        preparing,
        RepositoryPreparation(
            analysis_id="a1",
            workspace_id="w1",
            repository_url="https://example.invalid/fake",
            requested_ref="main",
            status="READY",
            resolved_commit_id="c1",
            root=tmp_path / "fixture-workspace",
            tracked_files=(),
            gaps=(),
            errors=(),
        ),
    ).work
    assert completed.status == "SUCCEEDED"
    assert completed.last_transition_commit_ref is not None
    committed = runtime.unit_of_work.records.get_exact(
        completed.last_transition_commit_ref
    )
    assert isinstance(committed, TransitionCommit)
    assert committed.state == "COMMITTED"
    assert (
        runtime.budget_registry.current_state("a1").workspace_ref
        == completed.output_refs[0]
    )


@pytest.mark.asyncio
async def test_denied_external_call_releases_unused_reservation(tmp_path: Path) -> None:
    from sastsimi.runtime.workflow_runner import WorkflowRunner

    h = Harness(tmp_path)
    execution = h.execution(max_work=10)
    assert execution.approval_ref is not None
    h.evidence.identities[execution.approval_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    scope = h.pin_execution(runtime.budget_registry, execution)
    runner = WorkflowRunner(runtime, h.clock, h.ids)
    running = runner.start(
        scope,
        execution.meta,
        "WORKSPACE_PREP",
        "ANALYSIS",
        "a1",
        execution.approval_ref,
    )

    async def forbidden() -> None:
        pytest.fail("Unauthorized external operation was invoked")

    with pytest.raises(ValueError, match="ACTION_DENIED"):
        await runner.external(
            running,
            scope,
            execution.approval_ref,
            "REPOSITORY_LOADER",
            "RUN_TOOL",
            forbidden,
            tool_name="fake",
            file_paths=("fixture.py",),
            requested_units=runner.units(elapsed_ms=1, cost_minor_units=1),
            actual_units=runner.units(elapsed_ms=1, cost_minor_units=1),
        )
    assert runtime.budget.remaining(scope, "a1").active_reservation_count == 0
    with h.database.engine.connect() as connection:
        assert (
            connection.execute(
                select(func.count()).select_from(models.external_dispatches)
            ).scalar_one()
            == 0
        )
