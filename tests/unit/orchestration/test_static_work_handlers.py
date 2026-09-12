"""Focused production tests for the T14 static claimed-work adapters."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.contracts.static import RepositorySelectedTool, RepositoryTrackedFile
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState, WorkType
from sastsimi.orchestration.static_work_handlers import (
    StaticToolCall,
    StaticToolWorkHandler,
    require_current_work_context,
    resolve_static_tool_recovery_action,
    selected_static_paths,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.runtime.workflow_runner import WorkflowRunner
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref


def _context() -> WorkContext:
    inputs = ()
    work_meta = RecordMeta.model_validate_json(
        canonical_bytes(meta("work_execution_state", attempt=None))
    )
    work = WorkExecutionState.model_validate_json(
        canonical_bytes(
            {
                "meta": work_meta,
                "work_id": "static-work",
                "parent_work_ref": None,
                "work_type": "STATIC_TOOL",
                "subject_type": "ANALYSIS",
                "subject_id": "a1",
                "work_generation": 1,
                "status": "RUNNING",
                "state_version": 3,
                "last_transition_ref": ref("state_transition"),
                "last_transition_commit_ref": ref("transition_commit"),
                "active_attempt_id": "attempt-current",
                "input_hash": content_hash(inputs),
                "dedupe_key": "d" * 64,
                "trigger_primitive_ref": None,
                "input_refs": inputs,
                "output_refs": (),
                "gap_ids": (),
                "error_ids": (),
                "waiting_for": (),
                "stop_reason": None,
                "started_at": "2026-09-13T00:00:00Z",
                "finished_at": None,
                "elapsed_ms": 0,
            }
        )
    )
    attempt = WorkAttempt.model_validate_json(
        canonical_bytes(
            {
                "meta": work_meta.model_copy(update={"attempt_id": "attempt-current"}),
                "work_id": work.work_id,
                "attempt_id": "attempt-current",
                "attempt_number": 1,
                "trigger": "INITIAL",
                "input_hash": work.input_hash,
                "status": "RUNNING",
                "output_refs": (),
                "gap_ids": (),
                "error_ids": (),
                "started_at": "2026-09-13T00:00:00Z",
                "finished_at": None,
                "elapsed_ms": 0,
            }
        )
    )
    return WorkContext(work, attempt)


def _runner(context: WorkContext, *, stale: bool = False) -> WorkflowRunner:
    current = (
        context.work.model_copy(update={"state_version": 4}) if stale else context.work
    )
    runtime = SimpleNamespace(
        work=SimpleNamespace(
            get=lambda _work_id: current,
            store=SimpleNamespace(
                attempts_for_work=lambda _work_id: (context.attempt,)
            ),
        )
    )
    return cast(WorkflowRunner, SimpleNamespace(runtime=runtime))


def _action(context: WorkContext, action_id: str, *, attempt_id: str) -> ActionRequest:
    action = make("ActionRequest", "action_request")
    action.update(
        meta=meta("action_request", hypothesis=None, attempt=attempt_id),
        action_id=action_id,
        requested_by="STATIC_ANALYSIS",
        requester_identity_ref=make("ActionRequest", "action_request")[
            "requester_identity_ref"
        ],
        action_type="RUN_TOOL",
        work_ref=reference(context.work).model_dump(mode="json"),
        expected_state_version=context.work.state_version,
        input_refs=(),
        tool_name="AST",
        file_paths=("src/app.py",),
    )
    return ActionRequest.model_validate_json(canonical_bytes(action))


def _recovery_runner(
    context: WorkContext, actions: tuple[ActionRequest, ...]
) -> tuple[WorkflowRunner, list[WorkExecutionState]]:
    blocked: list[WorkExecutionState] = []
    runtime = SimpleNamespace(
        work=SimpleNamespace(
            get=lambda _work_id: context.work,
            store=SimpleNamespace(
                attempts_for_work=lambda _work_id: (context.attempt,)
            ),
        ),
        queries=SimpleNamespace(published_records=lambda _analysis_id: actions),
        recovery=SimpleNamespace(
            recovery=SimpleNamespace(block_uncertain=lambda work: blocked.append(work))
        ),
    )
    return cast(WorkflowRunner, SimpleNamespace(runtime=runtime)), blocked


def test_selected_static_paths_follow_only_the_selected_language() -> None:
    tracked = tuple(
        RepositoryTrackedFile.model_validate(
            {
                "git_path": path,
                "git_mode": "100644",
                "blob_id": key * 40,
                "content_sha256": key * 64,
                "size_bytes": 1,
            }
        )
        for path, key in (
            ("src/app.py", "a"),
            ("src/app.js", "b"),
            ("README.md", "c"),
        )
    )
    tool = RepositorySelectedTool.model_validate_json(
        canonical_bytes(
            {
                "adapter_key": "CODEQL",
                "operation": "ANALYZE",
                "tool_profile_ref": {
                    "stored_data_id": "profile-s1",
                    "data_kind": "static_tool_profile",
                    "record_id": "profile-r1",
                    "content_hash": "d" * 64,
                    "host_id": "host-a",
                    "publication_analysis_id": "published-analysis",
                    "publication_workspace_id": "published-workspace",
                    "publication_commit_id": "published-commit",
                },
                "languages": ("PYTHON", "JAVASCRIPT"),
            }
        )
    )

    assert selected_static_paths(tracked, tool) == (
        "src/app.js",
        "src/app.py",
    )


def test_claimed_adapter_rejects_a_stale_work_revision() -> None:
    context = _context()
    action = _action(context, "static-action-current", attempt_id="attempt-current")
    identity = RunStoredDataRef.model_validate(action.requester_identity_ref)

    require_current_work_context(context, _runner(context), WorkType.STATIC_TOOL)
    with pytest.raises(ValueError, match="WORK_CONTEXT_NOT_CURRENT"):
        require_current_work_context(
            context, _runner(context, stale=True), WorkType.STATIC_TOOL
        )
    with pytest.raises(ValueError, match="WORK_CONTEXT_NOT_CURRENT"):
        resolve_static_tool_recovery_action(
            _runner(context, stale=True),
            context,
            requester_identity_ref=identity,
            tool_name="AST",
            file_paths=("src/app.py",),
        )


def test_static_recovery_resolver_reuses_the_exact_current_attempt_action() -> None:
    context = _context()
    action = _action(context, "static-action-current", attempt_id="attempt-current")
    runner, blocked = _recovery_runner(context, (action,))
    identity = RunStoredDataRef.model_validate(action.requester_identity_ref)

    recovered = resolve_static_tool_recovery_action(
        runner,
        context,
        requester_identity_ref=identity,
        tool_name="AST",
        file_paths=("src/app.py",),
    )

    assert recovered == action
    assert blocked == []


@pytest.mark.parametrize("failure", ("duplicate", "cross-attempt"))
def test_static_recovery_resolver_blocks_ambiguous_attempt_closure(
    failure: str,
) -> None:
    context = _context()
    current = _action(context, "static-action-current", attempt_id="attempt-current")
    actions = (
        (
            current,
            _action(
                context, "static-action-duplicate", attempt_id="attempt-current"
            ),
        )
        if failure == "duplicate"
        else (_action(context, "static-action-stale", attempt_id="attempt-stale"),)
    )
    runner, blocked = _recovery_runner(context, actions)
    identity = RunStoredDataRef.model_validate(current.requester_identity_ref)

    with pytest.raises(ValueError, match="STATIC_TOOL_RECOVERY_AMBIGUOUS"):
        resolve_static_tool_recovery_action(
            runner,
            context,
            requester_identity_ref=identity,
            tool_name="AST",
            file_paths=("src/app.py",),
        )

    assert blocked == [context.work]


@pytest.mark.asyncio
async def test_static_tool_handler_routes_recovery_without_running_again() -> None:
    context = _context()
    request = cast(Any, SimpleNamespace())
    selected = cast(RepositorySelectedTool, SimpleNamespace())
    calls: list[str] = []

    class Tools:
        async def run(self, _request: object) -> None:
            calls.append("run")

        async def recover(self, _request: object) -> None:
            calls.append("recover")

    terminal = context.work.model_copy(
        update={"status": "SUCCEEDED", "active_attempt_id": None}
    )
    graph = cast(
        Any,
        SimpleNamespace(
            runner=SimpleNamespace(
                runtime=SimpleNamespace(
                    work=SimpleNamespace(get=lambda _work_id: terminal)
                )
            ),
            ensure_normalization=lambda _work: None,
        ),
    )
    handler = StaticToolWorkHandler(
        cast(Any, Tools()),
        cast(Any, lambda _context: StaticToolCall(request, selected, recover=True)),
        graph,
    )

    await handler.execute(context)

    assert calls == ["recover"]
