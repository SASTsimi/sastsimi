"""File-oriented candidate batching does not inherit raw DB page boundaries."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TypedDict

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.call_path_facts import build_python_call_path_index
from sastsimi.simple_runtime.candidate_batches import (
    CandidateBatch,
    CandidateContextOverflow,
    iter_candidate_batches,
)
from sastsimi.simple_runtime.candidates import CandidateOrigin, StaticCandidate
from sastsimi.simple_runtime.file_context import (
    build_file_context,
    restrict_file_context_to_candidates,
)
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _BatchArguments(TypedDict):
    artifacts: SimpleArtifactRepository
    ast_summary: Mapping[str, object]
    workspace: Path
    max_prompt_bytes: int


def _fixture(
    tmp_path: Path,
    *,
    count: int,
    excerpt_size: int = 24,
    source_text: str | None = None,
) -> tuple[
    SimpleCheckpointStore,
    CheckpointIdentity,
    SimpleArtifactRepository,
    Path,
    dict[str, object],
    tuple[str, ...],
]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        source_text or "def route(value):\n" + "    evaluate(value)\n" * count,
        encoding="utf-8",
    )
    identity = CheckpointIdentity(
        analysis_id="batch-analysis",
        workspace_id="batch-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    raw_ref = artifacts.put_json({"kind": "fixture-raw"})
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=100_000
    )
    candidates = tuple(
        StaticCandidate(
            candidate_id=f"C-{index:04d}",
            kind="HINT",
            path="app.py",
            line=index + 2,
            end_line=index + 2,
            evidence_ref=raw_ref,
            origins=(
                CandidateOrigin(
                    engine="opengrep",
                    rule_id="python.eval",
                    artifact_ref=raw_ref,
                    result_index=index,
                ),
            ),
            evidence_key=f"evidence-{index}",
            summary="sink",
            evidence_excerpt="x" * excerpt_size,
        )
        for index in range(count)
    )
    store.upsert_candidate_page(identity, "scope-batch", raw_ref, 0, count, candidates)
    for candidate in candidates:
        store.save_candidate_decision(
            identity,
            "scope-batch",
            candidate.candidate_id,
            "INCLUDE",
            "fixture review",
        )
    return (
        store,
        identity,
        artifacts,
        workspace,
        summary,
        tuple(candidate.candidate_id for candidate in candidates),
    )


def test_file_batch_spans_database_pages(tmp_path: Path) -> None:
    store, identity, artifacts, workspace, summary, expected_ids = _fixture(
        tmp_path, count=40
    )
    batches = tuple(
        iter_candidate_batches(
            store,
            identity,
            "scope-batch",
            artifacts=artifacts,
            ast_summary=summary,
            workspace=workspace,
            max_prompt_bytes=12_000,
            db_page_size=32,
        )
    )
    emitted = tuple(
        candidate_id for batch in batches for candidate_id in batch.candidate_ids
    )
    assert set(emitted) == set(expected_ids)
    assert len(emitted) == 40
    assert all(batch.path == "app.py" for batch in batches)
    assert all(batch.prompt_bytes <= 12_000 for batch in batches)


def test_context_overflow_splits_without_loss(tmp_path: Path) -> None:
    store, identity, artifacts, workspace, summary, expected_ids = _fixture(
        tmp_path, count=8, excerpt_size=600
    )

    def build() -> tuple[CandidateBatch, ...]:
        return tuple(
            iter_candidate_batches(
                store,
                identity,
                "scope-batch",
                artifacts=artifacts,
                ast_summary=summary,
                workspace=workspace,
                max_prompt_bytes=7_500,
                db_page_size=3,
            )
        )

    first = build()
    second = build()
    emitted = tuple(
        candidate_id for batch in first for candidate_id in batch.candidate_ids
    )
    assert len(first) > 1
    assert emitted == expected_ids
    assert all(batch.prompt_bytes <= 7_500 for batch in first)
    assert [(batch.batch_id, batch.shared_context_ref) for batch in first] == [
        (batch.batch_id, batch.shared_context_ref) for batch in second
    ]


def test_single_oversized_candidate_is_explicit_error(tmp_path: Path) -> None:
    store, identity, artifacts, workspace, summary, expected_ids = _fixture(
        tmp_path, count=1, excerpt_size=10_000
    )
    with pytest.raises(CandidateContextOverflow) as error:
        tuple(
            iter_candidate_batches(
                store,
                identity,
                "scope-batch",
                artifacts=artifacts,
                ast_summary=summary,
                workspace=workspace,
                max_prompt_bytes=1_500,
            )
        )
    assert error.value.candidate_ids == expected_ids


def test_shared_context_is_focused_and_keeps_full_ast_reference(tmp_path: Path) -> None:
    store, identity, artifacts, workspace, summary, _ = _fixture(tmp_path, count=8)
    candidate = store.list_candidates(identity, "scope-batch", limit=1)[0]
    first_ref = build_file_context(
        artifacts, summary, workspace, "app.py", (candidate,)
    )
    second_ref = build_file_context(
        artifacts, summary, workspace, "app.py", (candidate,)
    )
    assert first_ref == second_ref
    context = json.loads(artifacts.read(first_ref))
    assert context["source_status"] == "AVAILABLE"
    assert context["source_line_count"] == 9
    assert context["omitted_source_line_count"] > 0
    assert context["ast_file_ref"] is not None
    assert context["ast_total_count"] >= len(context["ast_facts"])
    assert context["ast_omitted_count"] == context["ast_total_count"] - len(
        context["ast_facts"]
    )


def test_candidate_line_range_beyond_source_is_bounded(tmp_path: Path) -> None:
    store, identity, artifacts, workspace, summary, _ = _fixture(tmp_path, count=1)
    candidate = store.list_candidates(identity, "scope-batch", limit=1)[0]
    altered = candidate.model_copy(update={"end_line": 10_000_000})
    context_ref = build_file_context(
        artifacts, summary, workspace, "app.py", (altered,)
    )
    context = json.loads(artifacts.read(context_ref))
    assert len(context["source_lines"]) == 2
    assert context["requested_lines_outside_source"][0]["requested_end"] == 10_000_001


def test_context_v2_keeps_bounded_syntax_route_evidence(tmp_path: Path) -> None:
    store, identity, artifacts, workspace, summary, _ = _fixture(
        tmp_path,
        count=1,
        source_text=(
            "@app.post('/run')\ndef route(value):\n    return evaluate(value)\n"
        ),
    )
    batches = tuple(
        iter_candidate_batches(
            store,
            identity,
            "scope-batch",
            artifacts=artifacts,
            ast_summary=summary,
            workspace=workspace,
            max_prompt_bytes=16_384,
            context_version=2,
        )
    )

    context = json.loads(artifacts.read(batches[0].shared_context_ref))
    assert context["kind"] == "simple_candidate_file_context_v2"
    path = context["candidate_call_paths"][0]
    assert path["status"] == "AVAILABLE"
    assert [
        (step["role"], step["line"])
        for step in path["paths"][0]["steps"]
        if step["role"] in {"ROUTE_ENTRY", "CALL", "SINK"}
    ] == [
        ("ROUTE_ENTRY", 1),
        ("SINK", 2),
    ]
    assert {row["line"] for row in context["source_lines"]} >= {1, 2, 3}


def test_context_v2_keeps_local_handler_source_before_call_path_sink(
    tmp_path: Path,
) -> None:
    """A short route handler keeps its nearby request construction context.

    The call path is only syntactic reachability, but the Agent must see the
    handler's local request-read statement in order to assess attacker control.
    """

    source = (
        "@app.post('/students')\n"
        "async def create_student(request):\n"
        "    data = await request.post()\n"
        "    name = data['name']\n"
        "    return await save(name)\n\n"
        "async def save(name):\n"
        "    query = f\"SELECT * FROM students WHERE name = '{name}'\"\n"
        "    return await conn.execute(query)\n"
    )
    store, identity, artifacts, workspace, summary, _ = _fixture(
        tmp_path, count=1, source_text=source
    )
    candidate = store.list_candidates(identity, "scope-batch", limit=1)[0].model_copy(
        update={"line": 9, "end_line": 9}
    )
    index = build_python_call_path_index(workspace, ("app.py",))

    context_ref = build_file_context(
        artifacts,
        summary,
        workspace,
        "app.py",
        (candidate,),
        call_path_index=index,
    )
    context = json.loads(artifacts.read(context_ref))

    assert context["kind"] == "simple_candidate_file_context_v2"
    assert {row["line"] for row in context["source_lines"]} >= {2, 3, 4, 5, 8, 9}
    path = context["candidate_call_paths"][0]["paths"][0]
    assert {step["role"] for step in path["steps"]} >= {
        "HANDLER_DEFINITION",
        "REQUEST_CONTEXT",
        "CALL",
        "SINK",
    }
    assert ("HANDLER_DEFINITION", 2) in {
        (step["role"], step["line"]) for step in path["steps"]
    }
    assert ("REQUEST_CONTEXT", 3) in {
        (step["role"], step["line"]) for step in path["steps"]
    }


def test_context_v2_source_hint_includes_bounded_downstream_callee(
    tmp_path: Path,
) -> None:
    """An input hint must not hide the statically called sink implementation."""

    source = (
        "@app.post('/find')\n"
        "async def find(request):\n"
        "    query = await request.json()\n"
        "    return query_users(query)\n\n"
        "def query_users(query):\n"
        "    users = db.users\n"
        "    return users.find(query)\n"
    )
    store, identity, artifacts, workspace, summary, _ = _fixture(
        tmp_path, count=1, source_text=source
    )
    candidate = store.list_candidates(identity, "scope-batch", limit=1)[0].model_copy(
        update={"line": 3, "end_line": 3, "kind": "HINT"}
    )
    context_ref = build_file_context(
        artifacts,
        summary,
        workspace,
        "app.py",
        (candidate,),
        call_path_index=build_python_call_path_index(workspace, ("app.py",)),
        include_downstream=True,
    )
    context = json.loads(artifacts.read(context_ref))

    assert {row["line"] for row in context["source_lines"]} >= {3, 4, 6, 7, 8}
    downstream = [
        path
        for path in context["candidate_call_paths"][0]["paths"]
        if path["kind"] == "candidate_downstream_context_v1"
    ]
    assert len(downstream) == 1
    assert downstream[0]["assurance"] == "SYNTACTIC_REACHABILITY"
    assert ("CALL", "app.py", 4) in {
        (step["role"], step["path"], step["line"]) for step in downstream[0]["steps"]
    }
    from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap

    _primary, allowed = DirectHypothesisBootstrap._candidate_evidence_locations(
        context, "app.py", candidate.candidate_id
    )
    assert ("app.py", 8) in allowed


def test_candidate_context_v3_does_not_change_legacy_v2_batch_hash(
    tmp_path: Path,
) -> None:
    source = (
        "@app.post('/find')\n"
        "def find(request):\n"
        "    query = request.get_json()\n"
        "    return lookup(query)\n\n"
        "def lookup(query):\n"
        "    return db.users.find(query)\n"
    )
    store, identity, artifacts, workspace, summary, _ = _fixture(
        tmp_path, count=1, source_text=source
    )
    arguments: _BatchArguments = {
        "artifacts": artifacts,
        "ast_summary": summary,
        "workspace": workspace,
        "max_prompt_bytes": 16_384,
    }
    old = tuple(
        iter_candidate_batches(
            store, identity, "scope-batch", context_version=2, **arguments
        )
    )
    new = tuple(
        iter_candidate_batches(
            store, identity, "scope-batch", context_version=3, **arguments
        )
    )
    old_context = json.loads(artifacts.read(old[0].shared_context_ref))
    new_context = json.loads(artifacts.read(new[0].shared_context_ref))
    assert all(
        path["kind"] != "candidate_downstream_context_v1"
        for path in old_context["candidate_call_paths"][0]["paths"]
    )
    assert any(
        path["kind"] == "candidate_downstream_context_v1"
        for path in new_context["candidate_call_paths"][0]["paths"]
    )
    assert old[0].batch_id != new[0].batch_id


def test_candidate_context_v4_preserves_v3_and_adds_local_sink_context(
    tmp_path: Path,
) -> None:
    source = (
        "@app.post('/create')\n"
        "async def create(request):\n"
        "    name = await request.text()\n"
        "    q = \"INSERT INTO students VALUES ('%s')\" % name\n"
        "    async with db.cursor() as cur:\n"
        "        await cur.execute(q)\n"
    )
    store, identity, artifacts, workspace, summary, _ = _fixture(
        tmp_path, count=1, source_text=source
    )
    arguments: _BatchArguments = {
        "artifacts": artifacts,
        "ast_summary": summary,
        "workspace": workspace,
        "max_prompt_bytes": 16_384,
    }
    version3 = tuple(
        iter_candidate_batches(
            store, identity, "scope-batch", context_version=3, **arguments
        )
    )
    version4 = tuple(
        iter_candidate_batches(
            store, identity, "scope-batch", context_version=4, **arguments
        )
    )
    old_context = json.loads(artifacts.read(version3[0].shared_context_ref))
    new_context = json.loads(artifacts.read(version4[0].shared_context_ref))
    assert not any(
        path["kind"] == "candidate_enclosing_context_v1"
        for path in old_context["candidate_call_paths"][0]["paths"]
    )
    assert any(
        path["kind"] == "candidate_enclosing_context_v1"
        for path in new_context["candidate_call_paths"][0]["paths"]
    )
    assert {row["line"] for row in new_context["source_lines"]} >= {4, 6}
    assert version3[0].batch_id != version4[0].batch_id


def test_context_v2_slice_keeps_cross_file_handler_request_context(
    tmp_path: Path,
) -> None:
    """Retry slicing preserves route handler input context across files."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "sqli"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "routes.py").write_text(
        "from sqli import views\n"
        "app.router.add_route('POST', '/students', views.students)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "from sqli.dao.student import Student\n\n"
        "async def students(request):\n"
        "    data = await request.post()\n"
        "    return await Student.create(data['name'])\n\n"
        "async def unrelated(request):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    dao = package / "dao"
    dao.mkdir()
    (dao / "__init__.py").write_text("", encoding="utf-8")
    (dao / "student.py").write_text(
        "class Student:\n"
        "    @classmethod\n"
        "    async def create(cls, name):\n"
        "        return await connection.execute(name)\n",
        encoding="utf-8",
    )
    identity = CheckpointIdentity(
        analysis_id="context-analysis",
        workspace_id="context-workspace",
        commit_id="b" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    tracked = (
        "sqli/__init__.py",
        "sqli/routes.py",
        "sqli/views.py",
        "sqli/dao/__init__.py",
        "sqli/dao/student.py",
    )
    summary = collect_python_ast(
        workspace, tracked, artifacts, max_source_bytes=100_000
    )
    evidence_ref = artifacts.put_json({"kind": "fixture-raw"})
    candidate = StaticCandidate(
        candidate_id="C-DVPWA",
        kind="HINT",
        path="sqli/dao/student.py",
        line=4,
        end_line=4,
        evidence_ref=evidence_ref,
        origins=(
            CandidateOrigin(
                engine="opengrep",
                rule_id="python.sql",
                artifact_ref=evidence_ref,
                result_index=0,
            ),
        ),
        evidence_key="fixture-sql",
    )
    context_ref = build_file_context(
        artifacts,
        summary,
        workspace,
        candidate.path,
        (candidate,),
        call_path_index=build_python_call_path_index(workspace, tracked),
    )
    context = json.loads(artifacts.read(context_ref))
    restricted = restrict_file_context_to_candidates(context, (candidate.candidate_id,))

    for payload in (context, restricted):
        related_files = payload["related_source_files"]
        assert isinstance(related_files, list)
        related = {item["path"]: item for item in related_files}
        assert {row["line"] for row in related["sqli/views.py"]["source_lines"]} >= {
            3,
            4,
            5,
        }
        assert 7 not in {
            row["line"] for row in related["sqli/views.py"]["source_lines"]
        }


@pytest.mark.parametrize(
    ("related_failure", "expected_gap"),
    [
        ("missing", "RELATED_SOURCE_UNSAFE_OR_MISSING:routes.py"),
        ("oversized", "RELATED_SOURCE_TOO_LARGE:routes.py"),
        ("truncated", "RELATED_SOURCE_LOCATION_UNAVAILABLE:routes.py"),
    ],
)
def test_unavailable_related_source_does_not_block_other_candidate_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    related_failure: str,
    expected_gap: str,
) -> None:
    """Stale optional route evidence must not invalidate a file's candidate batch."""

    store, identity, artifacts, workspace, summary, _ = _fixture(
        tmp_path,
        count=2,
        source_text=(
            "def routed(value):\n    return eval(value)\n\n"
            "def local(value):\n    return eval(value)\n"
        ),
    )
    route_file = workspace / "routes.py"
    route_source = (
        "from app import routed\napp.add_url_rule('/run', view_func=routed)\n"
    )
    route_file.write_text(route_source, encoding="utf-8")
    summary = collect_python_ast(
        workspace, ("app.py", "routes.py"), artifacts, max_source_bytes=100_000
    )
    candidates = store.list_candidates(identity, "scope-batch", limit=2)
    routed = candidates[0].model_copy(update={"line": 2, "end_line": 2})
    local = candidates[1].model_copy(update={"line": 5, "end_line": 5})
    index = build_python_call_path_index(workspace, ("app.py", "routes.py"))
    route_found = False
    for path in index.for_candidate(routed).paths:
        steps = path["steps"]
        assert isinstance(steps, list)
        route_found = route_found or any(step["path"] == "routes.py" for step in steps)
    assert route_found
    if related_failure == "missing":
        route_file.unlink()
    elif related_failure == "oversized":
        from sastsimi.simple_runtime import file_context

        monkeypatch.setattr(file_context, "MAX_CONTEXT_SOURCE_BYTES", 128)
        route_file.write_text(route_source + "#" * 256, encoding="utf-8")
    else:
        route_file.write_text("from app import routed\n", encoding="utf-8")

    ref = build_file_context(
        artifacts,
        summary,
        workspace,
        "app.py",
        (routed, local),
        call_path_index=index,
    )
    context = json.loads(artifacts.read(ref))
    by_id = {row["candidate_id"]: row for row in context["candidate_call_paths"]}
    assert by_id[routed.candidate_id]["status"] == "PARTIAL"
    assert expected_gap in by_id[routed.candidate_id]["gaps"]
    assert all(
        step["path"] != "routes.py"
        for path in by_id[routed.candidate_id]["paths"]
        for step in path["steps"]
    )
    assert not any(
        gap.startswith("RELATED_SOURCE_") for gap in by_id[local.candidate_id]["gaps"]
    )
    assert context["related_source_files"] == []
    from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap

    primary, allowed = DirectHypothesisBootstrap._candidate_evidence_locations(
        context, "app.py", routed.candidate_id
    )
    assert 2 in primary
    assert ("routes.py", 2) not in allowed
