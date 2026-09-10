"""A workflow runner must use persistent authorization and usage accounting."""

from pathlib import Path

import pytest
from sqlalchemy import func, select

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.work import TransitionCommit
from sastsimi.storage import models
from tests.integration.runtime_support import Harness


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
    from sastsimi.contracts.canonical_json import canonical_bytes
    from sastsimi.contracts.static import CodeWorkspace

    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            dict(
                meta=runner.metadata(running.meta, "code_workspace"),
                workspace_id="w1",
                analysis_id="a1",
                repository_url="https://example.invalid/fake",
                commit_id="c1",
                status="READY",
            )
        )
    )
    completed = runner.complete(
        running,
        execution.approval_ref,
        "REPOSITORY_LOADER",
        (workspace,),
    )
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
