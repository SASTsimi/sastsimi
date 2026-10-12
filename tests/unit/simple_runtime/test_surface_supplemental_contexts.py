"""Saved v2 surface facts receive exact, bounded source-line supplements."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.file_context import (
    PreparedFileContext,
    prepare_file_context,
)
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.surface_contexts import (
    SurfaceContext,
    SurfaceContextOverflow,
    _surface_payload,
)
from sastsimi.simple_runtime.surface_supplemental_contexts import (
    build_surface_context_supplements,
)


def _rows(payload: dict[str, object], field: str) -> list[dict[str, object]]:
    value = payload[field]
    assert isinstance(value, list)
    assert all(isinstance(row, dict) for row in value)
    return cast(list[dict[str, object]], value)


def _saved_v2_fixture(
    tmp_path: Path,
    *,
    source: str,
    first_fact_count: int,
    surface_line: int = 2,
) -> tuple[
    SurfaceIndex,
    AttackSurface,
    PreparedFileContext,
    tuple[tuple[SurfaceContext, dict[str, object]], ...],
]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(source, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="surface-supplement-test",
        workspace_id="surface-supplement-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=3 * 1024 * 1024
    )
    prepared = prepare_file_context(artifacts, summary, workspace, "app.py")
    evidence = artifacts.put_json({"kind": "static-evidence"})
    surface = AttackSurface(
        surface_id="S-auth",
        type="AUTHORIZATION",
        path="app.py",
        symbol="check_permission",
        line=surface_line,
        linked_candidate_ids=("C-1",),
        evidence_refs=(evidence,),
        detector="AST_CALL",
    )
    index = SurfaceIndex(
        scope_fingerprint="scope-1",
        static_bundle_hash="b" * 64,
        ast_manifest_hash="c" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="d" * 64,
        candidate_count=1,
        surfaces=(surface,),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=(("app.py", prepared.source_sha256 or ""),),
    )
    all_source = [
        {"line": line, "text": text}
        for line, text in enumerate(prepared.source_lines, start=1)
    ]
    anchor_source = [all_source[surface_line - 1]]
    fact_parts = (
        list(prepared.ast_facts[:first_fact_count]),
        list(prepared.ast_facts[first_fact_count:]),
    )
    source_parts = (all_source, anchor_source)
    saved: list[tuple[SurfaceContext, dict[str, object]]] = []
    for part_index in range(2):
        payload = _surface_payload(
            index,
            surface,
            prepared,
            source_parts[part_index],
            fact_parts[part_index],
            [],
            [],
            source_window_count=len(all_source),
            ast_nearby_count=len(prepared.ast_facts),
            part_index=part_index,
            part_count=2,
        )
        payload["kind"] = "simple_surface_context_v2"
        payload["selection_scope"] = "FULL_FILE"
        payload["selected_source_line_count"] = len(all_source)
        payload["unavailable_implementation"] = None
        omitted_source_count = payload["omitted_source_line_count"]
        omitted_ast_count = payload["omitted_ast_fact_count"]
        assert omitted_source_count is None or isinstance(omitted_source_count, int)
        assert omitted_ast_count is None or isinstance(omitted_ast_count, int)
        ref = artifacts.put_json(payload)
        context_id = hashlib.sha256(
            canonical_bytes(
                {
                    "kind": "simple_surface_context_id_v2",
                    "scope_fingerprint": index.scope_fingerprint,
                    "surface_id": surface.surface_id,
                    "part_index": part_index,
                    "context_hash": ref.content_hash,
                }
            )
        ).hexdigest()
        saved.append(
            (
                SurfaceContext(
                    surface_id=surface.surface_id,
                    context_id=context_id,
                    context_hash=ref.content_hash,
                    context_ref=ref,
                    part_index=part_index,
                    part_count=2,
                    prompt_bytes=len(canonical_bytes(payload)),
                    source_sha256=prepared.source_sha256,
                    source_unavailable_reason=None,
                    ast_unavailable_reason=None,
                    omitted_source_line_count=omitted_source_count,
                    omitted_ast_fact_count=omitted_ast_count,
                ),
                payload,
            )
        )
    return index, surface, prepared, tuple(saved)


def test_616_line_saved_v2_ast_only_second_part_gets_source_paired_supplements(
    tmp_path: Path,
) -> None:
    source = (
        "def route(value):\n"
        + "".join(
            "    check_permission(value)\n"
            if number % 3 == 0
            else "    # " + "x" * 40 + "\n"
            for number in range(614)
        )
        + "    check_permission(value)\n"
    )
    index, surface, prepared, saved = _saved_v2_fixture(
        tmp_path, source=source, first_fact_count=174
    )
    assert len(prepared.source_lines) == 616
    assert len(prepared.ast_facts) > 174
    assert all(context.prompt_bytes <= 64 * 1024 for context, _ in saved), [
        context.prompt_bytes for context, _ in saved
    ]
    second_source_lines = {row["line"] for row in _rows(saved[1][1], "source_lines")}
    orphan_facts = [
        fact
        for fact in _rows(saved[1][1], "ast_facts")
        if fact["line"] not in second_source_lines
    ]
    assert orphan_facts

    supplements = build_surface_context_supplements(index, surface, prepared, saved)

    assert supplements
    assert all(item.prompt_bytes <= 64 * 1024 for item in supplements)
    assert all(
        item.payload["kind"] == "simple_surface_context_v3" for item in supplements
    )
    assert all(
        item.payload["parent_v2_context_id"] == saved[1][0].context_id
        and item.payload["parent_v2_context_hash"] == saved[1][0].context_hash
        for item in supplements
    )
    assert all(
        {fact["line"] for fact in _rows(item.payload, "ast_facts")}
        <= {row["line"] for row in _rows(item.payload, "source_lines")}
        for item in supplements
    )
    assert all(
        item.payload["source_window_line_count"]
        == len({row["line"] for row in _rows(item.payload, "source_lines")})
        and item.payload["ast_nearby_count"] == len(_rows(item.payload, "ast_facts"))
        for item in supplements
    )
    assert sorted(canonical_bytes(fact) for fact in orphan_facts) == sorted(
        canonical_bytes(fact)
        for item in supplements
        for fact in _rows(item.payload, "ast_facts")
    )
    assert [(item.context_id, item.context_hash) for item in supplements] == [
        (item.context_id, item.context_hash)
        for item in build_surface_context_supplements(index, surface, prepared, saved)
    ]


def test_supplement_rejects_changed_commit_source_and_ast_cas(tmp_path: Path) -> None:
    fixture = _saved_v2_fixture(
        tmp_path,
        source="def route(value):\n    check_permission(value)\n    helper(value)\n",
        first_fact_count=1,
    )
    index, surface, prepared, saved = fixture

    with pytest.raises(ValueError, match="SURFACE_SUPPLEMENT_SCOPE_MISMATCH"):
        build_surface_context_supplements(
            replace(index, commit_id="f" * 40), surface, prepared, saved
        )
    with pytest.raises(ValueError, match="SURFACE_SUPPLEMENT_SCOPE_MISMATCH"):
        build_surface_context_supplements(
            index, replace(surface, path="different.py"), prepared, saved
        )
    with pytest.raises(ValueError, match="SURFACE_SUPPLEMENT_SOURCE_MISMATCH"):
        build_surface_context_supplements(
            replace(index, ast_source_hashes=(("app.py", "f" * 64),)),
            surface,
            prepared,
            saved,
        )
    assert prepared.ast_file_ref is not None
    changed_ast_ref = StoredDataRef.model_validate(
        {
            **prepared.ast_file_ref.model_dump(mode="json"),
            "stored_data_id": "f" * 64,
            "content_hash": "f" * 64,
        }
    )
    with pytest.raises(ValueError, match="SURFACE_SUPPLEMENT_.*MISMATCH"):
        build_surface_context_supplements(
            index, surface, replace(prepared, ast_file_ref=changed_ast_ref), saved
        )


def test_supplement_preserves_parent_unavailable_implementation(tmp_path: Path) -> None:
    index, surface, prepared, original = _saved_v2_fixture(
        tmp_path,
        source="def route(value):\n    check_permission(value)\n    helper(value)\n",
        first_fact_count=1,
    )
    saved = list(original)
    parent, raw_payload = saved[1]
    payload = dict(raw_payload)
    reason = "CALL_RESULT_IMPLEMENTATION_NOT_IN_SAME_FILE"
    payload["unavailable_implementation"] = reason
    artifacts = SimpleArtifactRepository(
        tmp_path / "data",
        CheckpointIdentity(
            analysis_id="surface-supplement-test",
            workspace_id=index.workspace_id,
            commit_id=index.commit_id,
            hypothesis_id=None,
        ),
    )
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v2",
                "scope_fingerprint": index.scope_fingerprint,
                "surface_id": surface.surface_id,
                "part_index": parent.part_index,
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    saved[1] = (
        replace(
            parent,
            context_id=context_id,
            context_hash=ref.content_hash,
            context_ref=ref,
            prompt_bytes=len(canonical_bytes(payload)),
        ),
        payload,
    )

    supplements = build_surface_context_supplements(index, surface, prepared, saved)

    assert supplements
    assert all(
        item.payload["unavailable_implementation"] == reason for item in supplements
    )


def test_supplement_fails_closed_when_source_fact_pair_cannot_fit(
    tmp_path: Path,
) -> None:
    source = (
        "def route(value):\n"
        "    check_permission('" + "x" * 6_000 + "')\n"
        "    helper(value)\n"
    )
    index, surface, prepared, saved = _saved_v2_fixture(
        tmp_path, source=source, first_fact_count=1, surface_line=3
    )
    assert all(context.prompt_bytes <= 8 * 1024 for context, _ in saved), [
        context.prompt_bytes for context, _ in saved
    ]

    with pytest.raises(SurfaceContextOverflow):
        build_surface_context_supplements(
            index, surface, prepared, saved, budget_bytes=8 * 1024
        )
