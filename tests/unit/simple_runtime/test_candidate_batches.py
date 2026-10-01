"""File-oriented candidate batching does not inherit raw DB page boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.candidate_batches import (
    CandidateContextOverflow,
    iter_candidate_batches,
)
from sastsimi.simple_runtime.candidates import CandidateOrigin, StaticCandidate
from sastsimi.simple_runtime.file_context import build_file_context
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _fixture(
    tmp_path: Path,
    *,
    count: int,
    excerpt_size: int = 24,
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
        "def route(value):\n" + "    evaluate(value)\n" * count,
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

    def build() -> tuple[object, ...]:
        return tuple(
            iter_candidate_batches(
                store,
                identity,
                "scope-batch",
                artifacts=artifacts,
                ast_summary=summary,
                workspace=workspace,
                max_prompt_bytes=3_500,
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
    assert all(batch.prompt_bytes <= 3_500 for batch in first)
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
