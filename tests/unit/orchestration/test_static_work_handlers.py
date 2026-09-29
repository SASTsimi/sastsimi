"""Focused production tests for the T14 static claimed-work adapters."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import (
    CodeWorkspace,
    RepositoryExecutionSelection,
    RepositoryProfile,
    RepositorySelectedTool,
    RepositoryTrackedFile,
    StaticToolProfile,
)
from sastsimi.contracts.work import (
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.orchestration.static_work_handlers import (
    StaticProductionGraph,
    StaticToolCall,
    StaticToolRoute,
    StaticToolWorkHandler,
    require_current_work_context,
    resolve_static_tool_recovery_action,
    selected_static_paths,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.file_scope import StaticFileScope
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


@pytest.mark.parametrize("scope_is_broad", [False, True])
def test_selected_static_paths_follow_only_python_product_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope_is_broad: bool,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('app')\n", encoding="utf-8")
    (source / "app.js").write_text("console.log('app')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("docs\n", encoding="utf-8")
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

    if scope_is_broad:
        monkeypatch.setattr(
            "sastsimi.orchestration.static_work_handlers.build_static_file_scope",
            lambda _root, _tracked: StaticFileScope(
                selected_paths=("src/app.js", "src/app.py", "README.md"),
                fingerprint="f" * 64,
            ),
        )

    assert selected_static_paths(tracked, tool, workspace_root=tmp_path) == (
        "src/app.py",
    )


def test_selected_static_paths_excludes_tests_before_creating_tool_actions(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('app')\n", encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text(
        "def test_app():\n    assert True\n", encoding="utf-8"
    )
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
        for path, key in (("src/app.py", "a"), ("tests/test_app.py", "b"))
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
                "languages": ("PYTHON",),
            }
        )
    )

    assert selected_static_paths(tracked, tool, workspace_root=tmp_path) == (
        "src/app.py",
    )


@pytest.mark.parametrize("python_is_product", [True, False])
def test_python_product_scope_skips_non_python_paths_without_stalling_fanout(
    tmp_path: Path,
    python_is_product: bool,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    javascript_path = "src/app.js"
    python_path = "src/app.py" if python_is_product else "tests/test_only.py"
    (tmp_path / javascript_path).write_text("console.log('app')\n", encoding="utf-8")
    (tmp_path / python_path).write_text(
        "print('app')\n"
        if python_is_product
        else "def test_only():\n    assert True\n",
        encoding="utf-8",
    )
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
        for path, key in sorted(((javascript_path, "a"), (python_path, "b")))
    )
    workspace_data = make("CodeWorkspace")
    workspace_data.update(status="READY", commit_id="c1")
    workspace = CodeWorkspace.model_validate_json(canonical_bytes(workspace_data))
    workspace_ref = RunStoredDataRef.model_validate(reference(workspace))
    repository_data = make("RepositoryProfile")
    repository_data.update(
        workspace_ref=workspace_ref,
        tracked_files=tracked,
        manifest_hash=content_hash(
            tuple(item.model_dump(mode="json") for item in tracked)
        ),
        languages=(
            {"name": "PYTHON", "evidence_paths": (python_path,)},
            {"name": "JAVASCRIPT", "evidence_paths": (javascript_path,)},
        ),
    )
    repository = RepositoryProfile.model_validate_json(canonical_bytes(repository_data))
    repository_ref = StoredDataRef.model_validate(reference(repository))

    def profile(adapter: str, key: str) -> StaticToolProfile:
        data = make("StaticToolProfile")
        data["meta"].update(record_id=f"static_tool_profile-{key}")
        data.update(
            host_id="host1",
            profile_key=key,
            purpose="PRODUCTION",
            status="ACTIVE",
            adapter_key=adapter,
            tool_name="AST" if adapter == "PYTHON_AST" else "OPENGREP",
            tool_kind="STRUCTURE" if adapter == "PYTHON_AST" else "RULE_BASED",
            executable_sha256="a" * 64,
            capability_evidence_ref={
                **make("RepositoryExecutionSelection")["git_clone_profile_ref"],
                "data_kind": "tool_capability_evidence",
            },
        )
        return StaticToolProfile.model_validate_json(canonical_bytes(data))

    python_profile = profile("PYTHON_AST", "python")
    js_profile = profile("OPENGREP", "javascript")
    python_ref = HostConfigurationRef.model_validate(reference(python_profile))
    js_ref = HostConfigurationRef.model_validate(reference(js_profile))
    selected = (
        RepositorySelectedTool.model_validate(
            {
                "adapter_key": "PYTHON_AST",
                "operation": "PARSE",
                "tool_profile_ref": python_ref,
                "languages": ("PYTHON",),
            }
        ),
        RepositorySelectedTool.model_validate(
            {
                "adapter_key": "OPENGREP",
                "operation": "ANALYZE",
                "tool_profile_ref": js_ref,
                "languages": ("PYTHON", "JAVASCRIPT"),
            }
        ),
    )
    selection_data = make("RepositoryExecutionSelection")
    selection_data.update(
        status="READY",
        repository_profile_ref=repository_ref,
        languages=("PYTHON", "JAVASCRIPT"),
        selected_tools=selected,
        errors=(),
        gaps=tuple(
            {
                **make("DataGap"),
                "gap_id": f"missing-codeql-{language.lower()}",
                "code": f"NO_ACTIVE_STATIC_CAPABILITY:CODEQL:{language}",
            }
            for language in ("PYTHON", "JAVASCRIPT")
        ),
    )
    selection = RepositoryExecutionSelection.model_validate_json(
        canonical_bytes(selection_data)
    )
    selection_ref = StoredDataRef.model_validate(reference(selection))
    profile_work = _context().work.model_copy(
        update={
            "work_type": WorkType.REPOSITORY_PROFILE,
            "status": WorkStatus.SUCCEEDED,
            "input_refs": (workspace_ref,),
            "output_refs": (repository_ref, selection_ref),
        }
    )
    works: dict[str, WorkExecutionState] = {str(profile_work.work_id): profile_work}
    enqueued: list[WorkExecutionState] = []
    records = {
        workspace_ref: workspace,
        repository_ref: repository,
        selection_ref: selection,
    }
    profiles = {python_ref: python_profile, js_ref: js_profile}

    def ensure_enqueue(
        _scope: StoredDataRef,
        work_meta: RecordMeta,
        work_type: WorkType,
        _subject_type: object,
        _subject_id: str,
        _requester: object,
        *,
        stable_key: str,
        inputs: tuple[object, ...],
    ) -> WorkExecutionState:
        work = profile_work.model_copy(
            update={
                "meta": work_meta,
                "work_id": "stable-" + content_hash(stable_key)[:32],
                "work_type": work_type,
                "status": WorkStatus.PENDING,
                "input_refs": inputs,
                "output_refs": (),
                "dedupe_key": content_hash([stable_key, inputs]),
            }
        )
        enqueued.append(work)
        works[str(work.work_id)] = work
        return work

    budget_ref = StoredDataRef.model_validate(ref("budget_binding"))
    runtime = SimpleNamespace(
        work=SimpleNamespace(get=lambda work_id: works[work_id]),
        unit_of_work=SimpleNamespace(
            records=SimpleNamespace(get_exact=lambda exact_ref: records[exact_ref])
        ),
        configuration=SimpleNamespace(
            resolve_static_tool_profile_ref=lambda exact_ref: profiles[exact_ref]
        ),
        budget_registry=SimpleNamespace(
            current_state=lambda _analysis_id: SimpleNamespace(
                budget_binding_ref=budget_ref,
                workspace_id=repository.workspace_id,
                commit_id=repository.commit_id,
            )
        ),
    )
    runner = cast(
        WorkflowRunner,
        SimpleNamespace(
            runtime=runtime,
            metadata=lambda _source, _kind: RecordMeta.model_validate_json(
                canonical_bytes(
                    meta("work_execution_state", hypothesis=None, attempt=None)
                )
            ).model_dump(),
            ensure_enqueue=ensure_enqueue,
        ),
    )
    config_ref = StoredDataRef.model_validate(
        ref("static_analysis_config", record=False)
    )
    graph = StaticProductionGraph(
        runner=runner,
        work_query=cast(
            Any,
            SimpleNamespace(work_for_run=lambda _analysis_id: tuple(works.values())),
        ),
        requester_identity_ref=budget_ref,
        routes=(
            StaticToolRoute(python_ref, config_ref, None),
            StaticToolRoute(
                js_ref,
                config_ref,
                StoredDataRef.model_validate(ref("rule_catalog")),
                ("rule-1",),
            ),
        ),
        workspace_locator=cast(
            Any, SimpleNamespace(root_for=lambda _workspace: tmp_path)
        ),
    )

    assert selected_static_paths(tracked, selected[0], workspace_root=tmp_path) == (
        (python_path,) if python_is_product else ()
    )
    assert selected_static_paths(tracked, selected[1], workspace_root=tmp_path) == (
        (python_path,) if python_is_product else ()
    )
    if not python_is_product:
        with pytest.raises(ValueError, match="STATIC_PRODUCT_SOURCE_EMPTY"):
            graph.ensure_static_tools(
                profile_work=profile_work,
                repository=repository,
                repository_ref=repository_ref,
                selection=selection,
                selection_ref=selection_ref,
            )
        assert enqueued == []
        return
    children = graph.ensure_static_tools(
        profile_work=profile_work,
        repository=repository,
        repository_ref=repository_ref,
        selection=selection,
        selection_ref=selection_ref,
    )
    assert len(children) == 2
    assert python_ref in children[0].input_refs
    assert js_ref in children[1].input_refs
    completed = tuple(
        child.model_copy(
            update={
                "status": WorkStatus.SUCCEEDED,
                "output_refs": (StoredDataRef.model_validate(ref("tool_run_result")),),
            }
        )
        for child in children
    )
    for item in completed:
        works[str(item.work_id)] = item
    normalized = graph.ensure_normalization(completed[1])
    assert normalized is not None
    assert normalized.work_type == WorkType.STATIC_NORMALIZE
    legacy_normalization_key = "static-normalize:" + selection_ref.content_hash
    assert str(normalized.work_id) != (
        "stable-" + content_hash(legacy_normalization_key)[:32]
    )
    assert all(item.work_type != WorkType.STATIC_TOOL for item in enqueued[2:])

    legacy_key = f"static-tool:{selection_ref.content_hash}:{js_ref.content_hash}"
    legacy = completed[1].model_copy(
        update={
            "work_id": "stable-" + content_hash(legacy_key)[:32],
            "dedupe_key": content_hash([legacy_key, completed[1].input_refs]),
        }
    )
    works[str(legacy.work_id)] = legacy
    with pytest.raises(ValueError, match="STATIC_SCOPE_CHANGED_NEW_ANALYSIS_REQUIRED"):
        graph.ensure_static_tools(
            profile_work=profile_work,
            repository=repository,
            repository_ref=repository_ref,
            selection=selection,
            selection_ref=selection_ref,
        )
    with pytest.raises(ValueError, match="STATIC_SCOPE_CHANGED_NEW_ANALYSIS_REQUIRED"):
        graph.ensure_normalization(legacy)


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
            _action(context, "static-action-duplicate", attempt_id="attempt-current"),
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
