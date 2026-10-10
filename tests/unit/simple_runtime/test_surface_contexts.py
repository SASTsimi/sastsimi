"""Targeted surface context preserves exact, bounded review evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime import application, surface_contexts
from sastsimi.simple_runtime.application import SimpleAnalysisApplication
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.attack_surfaces import (
    AttackSurface,
    SurfaceCoverage,
    SurfaceIndex,
)
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_contexts import (
    SurfaceContext,
    expanded_surface_contexts,
    iter_uncovered_surface_contexts,
    reuse_saved_expanded_surface_contexts,
)


def _setup(
    tmp_path: Path, source: str, *, surface_line: int = 3
) -> tuple[
    SurfaceIndex,
    SurfaceCoverage,
    SimpleArtifactRepository,
    dict[str, object],
    Path,
]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(source, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="surface-context-analysis",
        workspace_id="surface-context-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    ast_summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=3 * 1024 * 1024
    )
    raw_ref = artifacts.put_json({"kind": "static-evidence"})
    surface = AttackSurface(
        surface_id="S-auth",
        type="AUTHORIZATION",
        path="app.py",
        symbol="check_permission",
        line=surface_line,
        linked_candidate_ids=("C-1",),
        evidence_refs=(raw_ref,),
        detector="AST_CALL",
    )
    covered = replace(surface, surface_id="S-covered", coverage_status="COVERED")
    index = SurfaceIndex(
        scope_fingerprint="scope-1",
        static_bundle_hash="b" * 64,
        ast_manifest_hash="c" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="d" * 64,
        candidate_count=1,
        surfaces=(surface, covered),
        static_gaps=(),
    )
    coverage = SurfaceCoverage(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        surfaces=index.surfaces,
        static_gaps=(),
    )
    return index, coverage, artifacts, ast_summary, workspace


def _contexts(
    fixture: tuple[
        SurfaceIndex,
        SurfaceCoverage,
        SimpleArtifactRepository,
        dict[str, object],
        Path,
    ],
    *,
    budget_bytes: int = 4096,
) -> tuple[SurfaceContext, ...]:
    index, coverage, artifacts, ast_summary, workspace = fixture
    return tuple(
        iter_uncovered_surface_contexts(
            index,
            coverage,
            budget_bytes,
            artifacts=artifacts,
            ast_summary=ast_summary,
            workspace=workspace,
        )
    )


def test_only_uncovered_or_insufficient_surfaces_get_stable_redacted_context(
    tmp_path: Path,
) -> None:
    source = (
        "def route(user):\n"
        "    value = user.name\n"
        "    check_permission(value)\n"
        "    return value\n" + ("\n" * 12) + "def unrelated():\n" + "    return 1\n"
    )
    fixture = _setup(tmp_path, source)
    first = _contexts(fixture)
    replay = _contexts(fixture)

    assert len(first) == 1
    assert [item.surface_id for item in first] == ["S-auth"]
    assert first[0].context_id == replay[0].context_id
    assert first[0].context_ref == replay[0].context_ref
    assert first[0].context_hash == first[0].context_ref.content_hash
    payload = json.loads(fixture[2].read(first[0].context_ref))
    assert payload["kind"] == "simple_surface_context_v1"
    assert payload["surface_id"] == "S-auth"
    assert payload["scope_fingerprint"] == "scope-1"
    assert any(
        "check_permission(value)" in row["text"] for row in payload["source_lines"]
    )
    assert any(fact["name"] == "check_permission" for fact in payload["ast_facts"])
    assert payload["omitted_source_line_count"] >= 1
    assert first[0].prompt_bytes == len(fixture[2].read(first[0].context_ref))


def test_long_nearby_context_splits_into_complete_numbered_parts(
    tmp_path: Path,
) -> None:
    lines = [
        "def route(value):",
        *[f"    item_{i} = '{str(i) * 360}'" for i in range(7)],
    ]
    lines.append("    check_permission(value)")
    fixture = _setup(tmp_path, "\n".join(lines) + "\n", surface_line=8)

    contexts = _contexts(fixture, budget_bytes=2400)
    payloads = [json.loads(fixture[2].read(item.context_ref)) for item in contexts]

    assert len(contexts) > 1
    assert [item.part_index for item in contexts] == list(range(len(contexts)))
    assert all(item.part_count == len(contexts) for item in contexts)
    assert all(item.prompt_bytes <= 2400 for item in contexts)
    assert len({item.context_id for item in contexts}) == len(contexts)
    sent_lines = [row for payload in payloads for row in payload["source_lines"]]
    assert len(sent_lines) == len({row["line"] for row in sent_lines})
    assert {row["line"] for row in sent_lines} >= {3, 4, 5, 6, 7, 8}
    assert all(row["text"] == lines[row["line"] - 1] for row in sent_lines)


def test_single_line_exceeding_budget_is_explicitly_unavailable(tmp_path: Path) -> None:
    giant = "    check_permission('" + "x" * 5000 + "')"
    fixture = _setup(tmp_path, "def route():\n    pass\n" + giant + "\n")

    contexts = _contexts(fixture, budget_bytes=2400)
    payloads = [json.loads(fixture[2].read(item.context_ref)) for item in contexts]

    assert contexts
    assert all(item.prompt_bytes <= 2400 for item in contexts)
    assert all(
        giant not in fixture[2].read(item.context_ref).decode() for item in contexts
    )
    assert any(
        row["line"] == 3 and row["reason"] == "SOURCE_LINE_TOO_LARGE"
        for payload in payloads
        for row in payload["unavailable_source_lines"]
    )
    assert all(payload["source_status"] == "PARTIAL" for payload in payloads)
    assert all(
        item.source_unavailable_reason == "SOURCE_LINE_TOO_LARGE" for item in contexts
    )
    assert any(
        item.omitted_source_line_count is not None
        and item.omitted_source_line_count >= 1
        for item in contexts
    )


def test_surface_location_outside_readable_file_is_explicit_gap(tmp_path: Path) -> None:
    fixture = _setup(
        tmp_path, "def route():\n    check_permission()\n", surface_line=90
    )

    contexts = _contexts(fixture)
    payload = json.loads(fixture[2].read(contexts[0].context_ref))

    assert payload["source_status"] == "UNAVAILABLE"
    assert payload["source_unavailable_reason"] == "SURFACE_LOCATION_BEYOND_SOURCE"
    assert contexts[0].source_unavailable_reason == "SURFACE_LOCATION_BEYOND_SOURCE"
    assert payload["source_lines"] == []


def test_index_and_coverage_scope_mismatch_is_rejected(tmp_path: Path) -> None:
    fixture = _setup(tmp_path, "def route():\n    pass\n    check_permission()\n")
    index, coverage, artifacts, ast_summary, workspace = fixture

    with pytest.raises(ValueError, match="SURFACE_CONTEXT_SCOPE_MISMATCH"):
        tuple(
            iter_uncovered_surface_contexts(
                index,
                replace(coverage, static_bundle_hash="wrong"),
                4096,
                artifacts=artifacts,
                ast_summary=ast_summary,
                workspace=workspace,
            )
        )


def test_candidate_inventory_revision_changes_context_identity(tmp_path: Path) -> None:
    fixture = _setup(tmp_path, "def route():\n    pass\n    check_permission()\n")
    first = _contexts(fixture)[0]
    index, coverage, artifacts, ast_summary, workspace = fixture
    revised = (
        replace(index, candidate_inventory_hash="e" * 64),
        replace(coverage, candidate_inventory_hash="e" * 64),
        artifacts,
        ast_summary,
        workspace,
    )

    second = _contexts(revised)[0]

    assert first.context_id != second.context_id
    assert first.context_hash != second.context_hash


def test_inconclusive_coverage_does_not_change_same_source_context(
    tmp_path: Path,
) -> None:
    fixture = _setup(tmp_path, "def route():\n    pass\n    check_permission()\n")
    first = _contexts(fixture)[0]
    index, coverage, artifacts, ast_summary, workspace = fixture
    inconclusive = replace(
        coverage,
        surfaces=(
            replace(coverage.surfaces[0], coverage_status="INSUFFICIENT"),
            coverage.surfaces[1],
        ),
    )

    second = _contexts((index, inconclusive, artifacts, ast_summary, workspace))[0]

    assert first.context_id == second.context_id
    assert first.context_hash == second.context_hash


def test_too_large_file_is_not_reported_as_inspected_source(tmp_path: Path) -> None:
    source = "def route():\n    check_permission()\n" + ("# padding\n" * 240_000)
    fixture = _setup(tmp_path, source, surface_line=2)

    contexts = _contexts(fixture)
    payload = json.loads(fixture[2].read(contexts[0].context_ref))

    assert contexts[0].source_unavailable_reason == "SOURCE_TOO_LARGE"
    assert payload["source_status"] == "UNAVAILABLE"
    assert payload["source_lines"] == []
    assert payload["source_unavailable_reason"] == "SOURCE_TOO_LARGE"


def test_unsafe_source_path_fails_instead_of_reading_host_file(tmp_path: Path) -> None:
    fixture = _setup(tmp_path, "def route():\n    pass\n    check_permission()\n")
    index, coverage, artifacts, ast_summary, workspace = fixture
    unsafe = replace(index.surfaces[0], path="../secret.py")
    index = replace(index, surfaces=(unsafe,))
    coverage = replace(coverage, surfaces=(unsafe,))

    with pytest.raises(ValueError, match="CANDIDATE_CONTEXT_SOURCE_UNSAFE_OR_MISSING"):
        tuple(
            iter_uncovered_surface_contexts(
                index,
                coverage,
                4096,
                artifacts=artifacts,
                ast_summary=ast_summary,
                workspace=workspace,
            )
        )


def test_enclosing_function_changes_context(tmp_path: Path) -> None:
    source = (
        "def route(value):\n"
        "    normalized = helper(value)\n"
        + "    # spacer\n" * 20
        + "    check_permission(normalized)\n"
        + "def helper(value):\n"
        + "    return value.strip()\n"
    )
    fixture = _setup(tmp_path, source, surface_line=23)
    index, _coverage, artifacts, summary, workspace = fixture
    first = _contexts(fixture)[0]
    expanded = expanded_surface_contexts(
        index,
        index.surfaces[0],
        artifacts=artifacts,
        ast_summary=summary,
        workspace=workspace,
    )
    first_payload = json.loads(artifacts.read(first.context_ref))
    expanded_payload = json.loads(artifacts.read(expanded[0].context_ref))

    assert first_payload["kind"] == "simple_surface_context_v1"
    assert all(row["line"] != 2 for row in first_payload["source_lines"])
    assert expanded_payload["kind"] == "simple_surface_context_v2"
    assert {2, 23, 24, 25} <= {row["line"] for row in expanded_payload["source_lines"]}
    assert expanded[0].context_id != first.context_id


def test_expansion_stays_within_budget_and_splits(tmp_path: Path) -> None:
    source = "def route(value):\n" + "    # " + "x" * 110 + "\n" * 1
    source += "    # filler\n" * 110 + "    check_permission(value)\n"
    fixture = _setup(tmp_path, source, surface_line=113)
    index, _coverage, artifacts, summary, workspace = fixture

    expanded = expanded_surface_contexts(
        index,
        index.surfaces[0],
        artifacts=artifacts,
        ast_summary=summary,
        workspace=workspace,
        budget_bytes=2400,
    )
    assert len(expanded) > 1
    assert all(item.prompt_bytes <= 2400 for item in expanded)
    assert [item.part_index for item in expanded] == list(range(len(expanded)))
    assert all(item.part_count == len(expanded) for item in expanded)
    assert all(
        any(
            row["line"] == 113
            for row in json.loads(artifacts.read(item.context_ref))["source_lines"]
        )
        for item in expanded
    )


def test_oversized_line_and_external_file_remain_insufficient(tmp_path: Path) -> None:
    giant = "    check_permission('" + "x" * 70_000 + "')"
    fixture = _setup(tmp_path, "def route():\n" + giant + "\n", surface_line=2)
    index, _coverage, artifacts, summary, workspace = fixture

    expanded = expanded_surface_contexts(
        index,
        index.surfaces[0],
        artifacts=artifacts,
        ast_summary=summary,
        workspace=workspace,
    )
    payload = json.loads(artifacts.read(expanded[0].context_ref))
    assert payload["source_status"] == "PARTIAL"
    assert {"line": 2, "reason": "SOURCE_LINE_TOO_LARGE"} in payload[
        "unavailable_source_lines"
    ]
    assert giant not in artifacts.read(expanded[0].context_ref).decode()

    external_root = tmp_path / "external"
    external_root.mkdir()
    external_fixture = _setup(
        external_root,
        "def route(value):\n    return super().eval(value)\n",
        surface_line=2,
    )
    other_index, _coverage, other_artifacts, other_summary, other_workspace = (
        external_fixture
    )
    external_surface = replace(other_index.surfaces[0], symbol="super().eval")
    other_index = replace(
        other_index,
        surfaces=(external_surface, *other_index.surfaces[1:]),
    )
    external = expanded_surface_contexts(
        other_index,
        external_surface,
        artifacts=other_artifacts,
        ast_summary=other_summary,
        workspace=other_workspace,
    )
    external_payload = json.loads(other_artifacts.read(external[0].context_ref))
    assert external_payload["unavailable_implementation"] == (
        "CALL_RESULT_IMPLEMENTATION_NOT_IN_SAME_FILE"
    )


def test_expansion_redacts_secrets(tmp_path: Path) -> None:
    secret = "sk-1234567890abcdefgh"
    source = f'def route(value):\n    token = "{secret}"\n    check_permission(value)\n'
    fixture = _setup(tmp_path, source)
    index, _coverage, artifacts, summary, workspace = fixture

    expanded = expanded_surface_contexts(
        index,
        index.surfaces[0],
        artifacts=artifacts,
        ast_summary=summary,
        workspace=workspace,
    )
    raw = artifacts.read(expanded[0].context_ref)
    assert secret.encode() not in raw
    assert b"REDACTED" in raw


def test_old_checkpoint_context_set_unchanged(tmp_path: Path) -> None:
    fixture = _setup(
        tmp_path,
        "def route(value):\n"
        + "    # earlier\n" * 20
        + "    check_permission(value)\n",
        surface_line=22,
    )
    index, _coverage, artifacts, _summary, _workspace = fixture
    context = _contexts(fixture)[0]
    result_ref = artifacts.put_json({"kind": "old-result"})
    record = SurfaceExplorationProgressRecord(
        surface_id=context.surface_id,
        context_id=context.context_id,
        static_bundle_hash=index.static_bundle_hash,
        index_hash="e" * 64,
        context_hash=context.context_hash,
        source_sha256=context.source_sha256,
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        result_ref=result_ref,
        hypothesis_ids=(),
        proposal_version=1,
    )
    assert (context.omitted_source_line_count or 0) > 0
    assert not SimpleAnalysisApplication._surface_expansion_needed(
        index,
        (context,),
        {(context.surface_id, context.context_id): record},
    )


def test_v2_expands_an_omitted_hypothesis_context_missing_review_parts(
    tmp_path: Path,
) -> None:
    fixture = _setup(
        tmp_path,
        "def route(value):\n"
        + "    # earlier\n" * 20
        + "    check_permission(value)\n",
        surface_line=22,
    )
    index, _coverage, artifacts, _summary, _workspace = fixture
    context = _contexts(fixture)[0]
    partial_ref = artifacts.put_json(
        {"kind": "surface-result", "reviewed_parts": ["SENSITIVE_OPERATION"]}
    )
    partial = SurfaceExplorationProgressRecord(
        surface_id=context.surface_id,
        context_id=context.context_id,
        static_bundle_hash=index.static_bundle_hash,
        index_hash="e" * 64,
        context_hash=context.context_hash,
        source_sha256=context.source_sha256,
        status="HYPOTHESES",
        result_ref=partial_ref,
        hypothesis_ids=(),
        proposal_version=1,
    )
    complete_ref = artifacts.put_json(
        {
            "kind": "surface-result",
            "reviewed_parts": [
                "ENTRY",
                "SENSITIVE_OPERATION",
                "TRUST_BOUNDARY",
            ],
        }
    )
    complete = replace(partial, result_ref=complete_ref)
    version_two = replace(index, index_version=2)

    assert (context.omitted_source_line_count or 0) > 0
    assert SimpleAnalysisApplication._surface_expansion_needed(
        version_two,
        (context,),
        {(context.surface_id, context.context_id): partial},
        artifacts=artifacts,
    )
    assert not SimpleAnalysisApplication._surface_expansion_needed(
        version_two,
        (context,),
        {(context.surface_id, context.context_id): complete},
        artifacts=artifacts,
    )


@dataclass(frozen=True)
class _SavedV2:
    index: SurfaceIndex
    artifacts: SimpleArtifactRepository
    summary: dict[str, object]
    first: tuple[SurfaceContext, ...]
    expanded: tuple[SurfaceContext, ...]
    progress: dict[tuple[str, str], SurfaceExplorationProgressRecord]
    workspace: Path
    index_hash: str


def _saved_v2(tmp_path: Path) -> _SavedV2:
    source = (
        "def route(value):\n" + "    # filler\n" * 110 + "    check_permission(value)\n"
    )
    index, coverage, artifacts, summary, workspace = _setup(
        tmp_path, source, surface_line=112
    )
    index = replace(
        index,
        index_version=2,
        ast_source_hashes=(
            ("app.py", hashlib.sha256((workspace / "app.py").read_bytes()).hexdigest()),
        ),
    )
    first = tuple(
        iter_uncovered_surface_contexts(
            index,
            coverage,
            2400,
            artifacts=artifacts,
            ast_summary=summary,
            workspace=workspace,
        )
    )
    expanded = expanded_surface_contexts(
        index,
        index.surfaces[0],
        artifacts=artifacts,
        ast_summary=summary,
        workspace=workspace,
        budget_bytes=2400,
    )
    assert len(expanded) > 1
    index_ref = artifacts.put_json(index.to_json())
    result_ref = artifacts.put_json({"kind": "saved-result"})
    progress = {
        (context.surface_id, context.context_id): SurfaceExplorationProgressRecord(
            surface_id=context.surface_id,
            context_id=context.context_id,
            static_bundle_hash=index.static_bundle_hash,
            index_hash=index_ref.content_hash,
            context_hash=context.context_hash,
            source_sha256=context.source_sha256,
            status="NO_HYPOTHESIS",
            result_ref=result_ref,
            hypothesis_ids=(),
            proposal_version=2,
        )
        for context in expanded
    }
    return _SavedV2(
        index=index,
        artifacts=artifacts,
        summary=summary,
        first=first,
        expanded=expanded,
        progress=progress,
        workspace=workspace,
        index_hash=index_ref.content_hash,
    )


def _reuse_saved_v2(
    saved: _SavedV2,
    *,
    progress: dict[tuple[str, str], SurfaceExplorationProgressRecord] | None = None,
    index: SurfaceIndex | None = None,
) -> tuple[SurfaceContext, ...] | None:
    current_index = index or saved.index
    return reuse_saved_expanded_surface_contexts(
        current_index,
        current_index.surfaces[0],
        saved.first,
        saved.progress if progress is None else progress,
        artifacts=saved.artifacts,
        ast_summary=saved.summary,
        workspace=saved.workspace,
        index_hash=saved.index_hash,
        budget_bytes=2400,
    )


def test_complete_saved_v2_parts_reuse_exact_context_without_rebuilding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = _saved_v2(tmp_path)
    monkeypatch.setattr(
        surface_contexts,
        "_surface_payload",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("saved context was rebuilt")
        ),
    )

    actual = _reuse_saved_v2(saved)
    assert actual == saved.expanded


def test_saved_v2_context_is_not_reused_after_source_changes(tmp_path: Path) -> None:
    saved = _saved_v2(tmp_path)
    with (saved.workspace / "app.py").open("a", encoding="utf-8") as stream:
        stream.write("# changed after the first context was built\n")

    assert _reuse_saved_v2(saved) is None


def test_changed_source_takes_existing_block_path(tmp_path: Path) -> None:
    saved = _saved_v2(tmp_path)
    with (saved.workspace / "app.py").open("a", encoding="utf-8") as stream:
        stream.write("# changed after the saved context\n")

    with pytest.raises(ValueError, match="SURFACE_CONTEXT_SOURCE_CHANGED"):
        SimpleAnalysisApplication._second_look_contexts(
            saved.index,
            saved.index.surfaces[0],
            saved.first,
            saved.progress,
            artifacts=saved.artifacts,
            ast_summary=saved.summary,
            workspace=saved.workspace,
            index_hash=saved.index_hash,
        )


def test_application_replays_saved_second_look_idempotently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = _saved_v2(tmp_path)

    def no_rebuild(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("completed second look was rendered again")

    monkeypatch.setattr(application, "expanded_surface_contexts", no_rebuild)
    for _ in range(2):
        assert (
            SimpleAnalysisApplication._second_look_contexts(
                saved.index,
                saved.index.surfaces[0],
                saved.first,
                saved.progress,
                artifacts=saved.artifacts,
                ast_summary=saved.summary,
                workspace=saved.workspace,
                index_hash=saved.index_hash,
            )
            == saved.expanded
        )


def test_missing_saved_part_uses_existing_renderer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = _saved_v2(tmp_path)
    partial = dict(saved.progress)
    partial.pop((saved.expanded[-1].surface_id, saved.expanded[-1].context_id))
    rendered: list[bool] = []

    def render(*_args: object, **_kwargs: object) -> tuple[SurfaceContext, ...]:
        rendered.append(True)
        return saved.expanded

    monkeypatch.setattr(application, "expanded_surface_contexts", render)
    assert (
        SimpleAnalysisApplication._second_look_contexts(
            saved.index,
            saved.index.surfaces[0],
            saved.first,
            partial,
            artifacts=saved.artifacts,
            ast_summary=saved.summary,
            workspace=saved.workspace,
            index_hash=saved.index_hash,
        )
        == saved.expanded
    )
    assert rendered == [True]


def test_saved_v2_rejects_progress_key_mismatch(tmp_path: Path) -> None:
    saved = _saved_v2(tmp_path)
    progress = dict(saved.progress)
    key, record = next(iter(progress.items()))
    del progress[key]
    progress[(key[0], "f" * 64)] = record

    assert _reuse_saved_v2(saved, progress=progress) is None


def test_saved_v2_rejects_changed_record_scope_version_or_reference(
    tmp_path: Path,
) -> None:
    saved = _saved_v2(tmp_path)
    key, original = next(iter(saved.progress.items()))
    mismatches = (
        replace(original, static_bundle_hash="c" * 64),
        replace(original, index_hash="d" * 64),
        replace(original, source_sha256="e" * 64),
        replace(original, proposal_version=3),
        replace(original, context_hash="f" * 64),
    )
    for mismatch in mismatches:
        progress = dict(saved.progress)
        progress[key] = mismatch
        assert _reuse_saved_v2(saved, progress=progress) is None, mismatch

    forged_id = "f" * 64
    progress = dict(saved.progress)
    del progress[key]
    progress[(key[0], forged_id)] = replace(original, context_id=forged_id)
    assert _reuse_saved_v2(saved, progress=progress) is None
    assert (
        _reuse_saved_v2(
            saved, index=replace(saved.index, scope_fingerprint="changed-scope")
        )
        is None
    )


def test_saved_v2_rejects_corrupted_cas_bytes(tmp_path: Path) -> None:
    saved = _saved_v2(tmp_path)
    context = saved.expanded[0]
    saved.artifacts.artifacts.path_for(context.context_hash).write_bytes(b"corrupted")
    assert _reuse_saved_v2(saved) is None


def test_saved_v2_rejects_forged_payload_metadata(tmp_path: Path) -> None:
    saved = _saved_v2(tmp_path)
    context = saved.expanded[0]
    payload = json.loads(saved.artifacts.read(context.context_ref))
    payload["static_evidence_refs"] = []
    forged_ref = saved.artifacts.put_json(payload)
    forged_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v2",
                "scope_fingerprint": saved.index.scope_fingerprint,
                "surface_id": context.surface_id,
                "part_index": context.part_index,
                "context_hash": forged_ref.content_hash,
            }
        )
    ).hexdigest()
    key = (context.surface_id, context.context_id)
    original = saved.progress[key]
    progress = dict(saved.progress)
    del progress[key]
    progress[(context.surface_id, forged_id)] = replace(
        original,
        context_id=forged_id,
        context_hash=forged_ref.content_hash,
    )
    assert _reuse_saved_v2(saved, progress=progress) is None
