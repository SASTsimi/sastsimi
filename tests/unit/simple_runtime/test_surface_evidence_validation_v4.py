"""V4 review claims must resolve to one pinned source-bound graph path."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMClient
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from sastsimi.simple_runtime.surface_evidence_validation_v4 import (
    validate_v4_context_payload,
    validate_v4_response,
)
from tests.unit.simple_runtime.test_surface_proposal import (
    _Client,
    _reply,
    _review,
)

_SOURCE = (
    "@app.route('/run')\n"
    "def route(value):\n"
    "    value = request.args['value']\n"
    "    return dangerous(value)\n"
)
_SURFACE = "surface-review-001"
_SOURCE_SHA = hashlib.sha256(_SOURCE.encode()).hexdigest()


def _graph() -> dict[str, object]:
    lines = [
        {
            "line_id": f"line-{line}",
            "path": "app.py",
            "line": line,
            "text": text,
            "source_sha256": _SOURCE_SHA,
        }
        for line, text in enumerate(_SOURCE.splitlines(), 1)
    ]
    nodes = [
        {"node_id": "node-entry", "role": "ROUTE_ENTRY", "path": "app.py", "line": 1},
        {
            "node_id": "node-boundary",
            "role": "REQUEST_CONTEXT",
            "path": "app.py",
            "line": 3,
        },
        {"node_id": "node-sink", "role": "SINK", "path": "app.py", "line": 4},
    ]
    edges = [
        {
            "edge_id": "edge-entry",
            "type": "ENTRY",
            "from_node_id": "node-entry",
            "to_node_id": "node-boundary",
            "graph_path_id": "path-real",
        },
        {
            "edge_id": "edge-sink",
            "type": "SENSITIVE_OPERATION",
            "from_node_id": "node-boundary",
            "to_node_id": "node-sink",
            "graph_path_id": "path-real",
        },
    ]
    return {
        "kind": "simple_surface_evidence_graph_v4",
        "anchor": {"surface_id": _SURFACE, "path": "app.py", "line": 4},
        "scope_fingerprint": "scope-surface",
        "index_hash": "c" * 64,
        "ast_manifest_hash": "d" * 64,
        "source_files": [{"path": "app.py", "source_sha256": _SOURCE_SHA}],
        "source_lines": lines,
        "ast_facts": [],
        "nodes": nodes,
        "edges": edges,
        "paths": [
            {
                "path_id": "path-real",
                "kind": "call_path_v1",
                "provenance": "python_syntax",
                "assurance": "SYNTACTIC_REACHABILITY",
                "steps": nodes,
                "edge_ids": ["edge-entry", "edge-sink"],
            }
        ],
        "gaps": [],
    }


def _fixture(
    tmp_path: Path,
    *,
    graph: dict[str, object] | None = None,
    part_count: int = 1,
    unavailable_item_count: int = 0,
    visible_categories: frozenset[str] | None = None,
) -> tuple[
    DirectHypothesisBootstrap,
    _Client,
    CheckpointIdentity,
    StaticBootstrapResult,
    SurfaceContext,
    SimpleArtifactRepository,
    dict[str, object],
    dict[str, object],
]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text(_SOURCE, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-v4",
        workspace_id="workspace-v4",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    bundle_ref = artifacts.put_json({"kind": "simple_static_fact_bundle"})
    static = StaticBootstrapResult(
        repository_profile_ref=bundle_ref,
        static_bundle_ref=bundle_ref,
        workspace_path=workspace,
    )
    graph_payload = graph or _graph()
    graph_ref = artifacts.put_json(graph_payload)
    items: list[dict[str, object]] = []
    for category in (
        "source_files",
        "source_lines",
        "ast_facts",
        "nodes",
        "edges",
        "paths",
        "gaps",
    ):
        if visible_categories is not None and category not in visible_categories:
            continue
        for ordinal, value in enumerate(
            cast(list[dict[str, object]], graph_payload[category])
        ):
            items.append({"category": category, "ordinal": ordinal, "value": value})
    payload: dict[str, object] = {
        "kind": "simple_surface_context_v4",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": "default",
        "scope_fingerprint": "scope-surface",
        "static_bundle_hash": bundle_ref.content_hash,
        "ast_manifest_hash": "d" * 64,
        "surface_index_hash": "c" * 64,
        "scope_certificate_hash": "e" * 64,
        "surface_id": _SURFACE,
        "surface_type": "CODE_EXECUTION",
        "path": "app.py",
        "line": 4,
        "source_sha256": _SOURCE_SHA,
        "graph_hash": graph_ref.content_hash,
        "parent_progress_hash": "f" * 64,
        "plan_binding_hash": "1" * 64,
        "reader_revision": "source-bound-v4-1",
        "part_index": 0,
        "part_count": part_count,
        "unavailable_item_count": unavailable_item_count,
        "items": items,
    }
    context_ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v4",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": _SURFACE,
                "part_index": 0,
                "context_hash": context_ref.content_hash,
            }
        )
    ).hexdigest()
    context = SurfaceContext(
        surface_id=_SURFACE,
        context_id=context_id,
        context_hash=context_ref.content_hash,
        context_ref=context_ref,
        part_index=0,
        part_count=part_count,
        prompt_bytes=len(artifacts.read(context_ref)),
        source_sha256=_SOURCE_SHA,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=0,
        omitted_ast_fact_count=0,
    )
    client = _Client([])
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda _identity, _artifacts: cast(SimpleLLMClient, client),
    )
    return (
        bootstrap,
        client,
        identity,
        static,
        context,
        artifacts,
        payload,
        graph_payload,
    )


def _review_v4(
    context: SurfaceContext,
    *,
    path_ids: tuple[str, str, str] = ("path-real", "path-real", "path-real"),
) -> list[dict[str, object]]:
    return [
        {
            "part": part,
            "location": f"app.py:{line}",
            "context_hash": context.context_hash,
            "source_sha256": _SOURCE_SHA,
            "graph_path_id": path_id,
            "edge_ids": edges,
            "explanation": f"Visible {part.lower()} line.",
        }
        for part, line, edges, path_id in (
            ("ENTRY", 1, ["edge-entry"], path_ids[0]),
            ("TRUST_BOUNDARY", 3, ["edge-entry", "edge-sink"], path_ids[1]),
            ("SENSITIVE_OPERATION", 4, ["edge-sink"], path_ids[2]),
        )
    ]


def test_verified_three_roles_on_one_graph_path_is_accepted(tmp_path: Path) -> None:
    _, _, _, _, context, _, payload, graph = _fixture(tmp_path)
    reply = _reply(
        context.context_id,
        status="NO_HYPOTHESIS",
        review_evidence=cast(Any, _review_v4(context)),
    )

    result = validate_v4_response(reply, context, payload, graph)

    assert result.status == "NO_HYPOTHESIS"
    assert result.reviewed_parts == {
        "ENTRY",
        "SENSITIVE_OPERATION",
        "TRUST_BOUNDARY",
    }
    assert len(result.verified_roles) == 3
    assert {row["graph_path_id"] for row in result.verified_roles} == {"path-real"}
    assert result.evidence_locations == ("app.py:1", "app.py:3", "app.py:4")


def test_split_insufficient_parts_preserve_graph_bound_roles_for_aggregation(
    tmp_path: Path,
) -> None:
    """No-seed slice status must not discard independently verified route roles."""

    _, _, _, static, base, artifacts, payload, graph = _fixture(tmp_path, part_count=2)
    items = cast(list[dict[str, object]], payload["items"])
    first_items = [
        item
        for item in items
        if not (
            item["category"] == "source_lines"
            and cast(dict[str, object], item["value"])["line"] == 4
        )
    ]
    second_items = [item for item in items if item not in first_items]

    def make_part(
        index: int, part_items: list[dict[str, object]]
    ) -> tuple[SurfaceContext, dict[str, object]]:
        part_payload = {**payload, "part_index": index, "items": part_items}
        part_ref = artifacts.put_json(part_payload)
        part_id = hashlib.sha256(
            canonical_bytes(
                {
                    "kind": "simple_surface_context_id_v4",
                    "plan_binding_hash": part_payload["plan_binding_hash"],
                    "surface_id": base.surface_id,
                    "part_index": index,
                    "context_hash": part_ref.content_hash,
                }
            )
        ).hexdigest()
        part = replace(
            base,
            context_id=part_id,
            context_hash=part_ref.content_hash,
            context_ref=part_ref,
            part_index=index,
            prompt_bytes=len(artifacts.read(part_ref)),
        )
        validate_v4_context_payload(
            part, part_payload, static.static_bundle_ref.content_hash
        )
        return part, part_payload

    first, first_payload = make_part(0, first_items)
    second, second_payload = make_part(1, second_items)
    first_reply = _reply(
        first.context_id,
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        review_evidence=cast(Any, _review_v4(first)[:2]),
    )
    second_reply = _reply(
        second.context_id,
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        review_evidence=cast(Any, _review_v4(second)[2:]),
    )

    first_checked = validate_v4_response(first_reply, first, first_payload, graph)
    second_checked = validate_v4_response(second_reply, second, second_payload, graph)

    assert first_checked.reviewed_parts == second_checked.reviewed_parts == frozenset()
    assert {
        cast(str, row["part"])
        for checked in (first_checked, second_checked)
        for row in checked.verified_roles
    } == {"ENTRY", "TRUST_BOUNDARY", "SENSITIVE_OPERATION"}
    assert {
        row["graph_path_id"]
        for checked in (first_checked, second_checked)
        for row in checked.verified_roles
    } == {"path-real"}


@pytest.mark.parametrize("mutation", ("invented_line", "wrong_sha", "decoy_path"))
def test_invented_line_wrong_source_hash_and_cross_file_decoy_rejected(
    tmp_path: Path, mutation: str
) -> None:
    _, _, _, _, context, _, payload, graph = _fixture(tmp_path)
    review = _review_v4(context)
    if mutation == "invented_line":
        review[0]["location"] = "app.py:99"
    elif mutation == "wrong_sha":
        review[0]["source_sha256"] = "0" * 64
    else:
        review[0]["graph_path_id"] = "path-decoy"
    reply = _reply(
        context.context_id,
        status="NO_HYPOTHESIS",
        review_evidence=cast(Any, review),
    )

    with pytest.raises(ValueError, match="HYPOTHESIS_SURFACE"):
        validate_v4_response(reply, context, payload, graph)


def test_roles_from_unrelated_paths_do_not_combine(tmp_path: Path) -> None:
    graph = _graph()
    paths = cast(list[dict[str, object]], graph["paths"])
    decoy = {**paths[0], "path_id": "path-decoy"}
    paths.append(decoy)
    edges = cast(list[dict[str, object]], graph["edges"])
    edges.extend(
        {**edge, "edge_id": f"decoy-{edge['edge_id']}", "graph_path_id": "path-decoy"}
        for edge in list(edges)
    )
    decoy["edge_ids"] = ["decoy-edge-entry", "decoy-edge-sink"]
    _, _, _, _, context, _, payload, bound_graph = _fixture(tmp_path, graph=graph)
    review = _review_v4(context, path_ids=("path-real", "path-decoy", "path-real"))
    review[1]["edge_ids"] = ["decoy-edge-entry", "decoy-edge-sink"]
    reply = _reply(
        context.context_id,
        status="NO_HYPOTHESIS",
        review_evidence=cast(Any, review),
    )

    result = validate_v4_response(reply, context, payload, bound_graph)

    assert len(result.verified_roles) == 3
    assert result.reviewed_parts == frozenset()


def test_incomplete_context_cannot_return_no_hypothesis(tmp_path: Path) -> None:
    _, _, _, _, context, _, payload, graph = _fixture(
        tmp_path, part_count=2, unavailable_item_count=1
    )
    reply = _reply(
        context.context_id,
        status="NO_HYPOTHESIS",
        review_evidence=cast(Any, _review_v4(context)),
    )

    with pytest.raises(ValueError, match="HYPOTHESIS_SURFACE_SOURCE_INCOMPLETE"):
        validate_v4_response(reply, context, payload, graph)


def test_single_part_missing_graph_rows_cannot_return_no_hypothesis(
    tmp_path: Path,
) -> None:
    _, _, _, _, context, _, payload, graph = _fixture(
        tmp_path, visible_categories=frozenset({"source_lines"})
    )
    reply = _reply(
        context.context_id,
        status="NO_HYPOTHESIS",
        review_evidence=cast(Any, _review_v4(context)),
    )

    with pytest.raises(ValueError, match="HYPOTHESIS_SURFACE_SOURCE_INCOMPLETE"):
        validate_v4_response(reply, context, payload, graph)


@pytest.mark.asyncio
async def test_invalid_json_schema_and_edge_retries_are_bounded(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, artifacts, _, _ = _fixture(tmp_path)
    invalid = _reply(
        context.context_id,
        status="NO_HYPOTHESIS",
        review_evidence=cast(Any, _review_v4(context)),
    )
    cast(list[dict[str, object]], invalid["review_evidence"])[0]["edge_ids"] = [
        "invented-edge"
    ]
    client.replies.extend([{"unexpected": True}, invalid])

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_OUTPUT_INVALID"
    assert len(client.requests) == 2
    assert len(result.evidence_refs) >= 2
    assert all(
        request["schema"]["properties"]["review_evidence"]["items"]["required"]
        == [
            "part",
            "location",
            "context_hash",
            "source_sha256",
            "graph_path_id",
            "edge_ids",
            "explanation",
        ]
        for request in client.requests
    )
    assert any(
        json.loads(artifacts.read(ref)).get("kind")
        == "simple_surface_hypothesis_result_v4"
        for ref in result.evidence_refs
    )


@pytest.mark.asyncio
async def test_v4_prompt_supplies_compact_path_directory_for_line_only_part(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _, _, _ = _fixture(
        tmp_path,
        visible_categories=frozenset({"source_lines"}),
        part_count=2,
    )
    client.replies.append(
        _reply(
            context.context_id,
            status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        )
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert len(client.requests) == 1
    prompt = client.requests[0]["prompt"]
    assert b"<GRAPH_REVIEW_DIRECTORY>" in prompt
    assert b"path-real" in prompt
    assert b"edge-entry" in prompt
    assert b"</GRAPH_REVIEW_DIRECTORY>" in prompt


@pytest.mark.asyncio
async def test_v3_response_schema_remains_unchanged(tmp_path: Path) -> None:
    from tests.unit.simple_runtime.test_surface_proposal import _fixture as v1_fixture

    bootstrap, client, identity, static, context, _ = v1_fixture(tmp_path)
    client.replies.append(
        _reply(
            context.context_id,
            status="NO_HYPOTHESIS",
            review_evidence=_review("ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"),
        )
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert len(client.requests) == 1
    assert client.requests[0]["schema"]["properties"]["review_evidence"]["items"][
        "required"
    ] == ["part", "location", "explanation"]
