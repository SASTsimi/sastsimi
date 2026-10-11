"""The Hypothesis Agent v5 adapter saves only source-bound graph reviews."""

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
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    SurfaceProposalResult,
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMClient
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from tests.unit.simple_runtime.test_surface_enrichment_v5 import (
    _case as _planner_case,
)
from tests.unit.simple_runtime.test_surface_enrichment_v5 import (
    _prepare as _planner_prepare,
)
from tests.unit.simple_runtime.test_surface_evidence_validation_v4 import (
    _fixture as _v4_fixture,
)
from tests.unit.simple_runtime.test_surface_evidence_validation_v4 import (
    _review_v4,
)
from tests.unit.simple_runtime.test_surface_proposal import _Client, _reply


def _v5_fixture(
    tmp_path: Path, *, bad_graph: bool = False
) -> tuple[
    DirectHypothesisBootstrap,
    _Client,
    CheckpointIdentity,
    StaticBootstrapResult,
    SurfaceContext,
    SimpleArtifactRepository,
]:
    bootstrap, client, identity, static, old, artifacts, old_payload, graph = (
        _v4_fixture(tmp_path)
    )
    graph = {**graph, "kind": "simple_surface_evidence_graph_v5"}
    graph["scope_fingerprint"] = "f" * 64
    graph["operational_routes"] = [{"good_path": "private answer"}] if bad_graph else []
    graph_ref = artifacts.put_json(graph)
    payload = {
        **old_payload,
        "kind": "simple_surface_context_v5",
        "scope_fingerprint": "f" * 64,
        "graph_hash": graph_ref.content_hash,
        "reader_revision": "source-bound-v5-1",
        "items": [
            {"category": category, "ordinal": ordinal, "value": value}
            for category in (
                "source_files",
                "source_lines",
                "ast_facts",
                "nodes",
                "edges",
                "paths",
                "operational_routes",
                "gaps",
            )
            for ordinal, value in enumerate(
                cast(list[dict[str, object]], graph[category])
            )
        ],
    }
    context_ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v5",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": old.surface_id,
                "part_index": old.part_index,
                "context_hash": context_ref.content_hash,
            }
        )
    ).hexdigest()
    context = replace(
        old,
        context_id=context_id,
        context_hash=context_ref.content_hash,
        context_ref=context_ref,
        prompt_bytes=len(artifacts.read(context_ref)),
    )
    return bootstrap, client, identity, static, context, artifacts


@pytest.mark.asyncio
async def test_v5_adapter_saves_exact_validated_graph_review(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, artifacts = _v5_fixture(tmp_path)
    client.replies.append(
        _reply(
            context.context_id,
            status="NO_HYPOTHESIS",
            review_evidence=cast(Any, _review_v4(context)),
        )
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.reviewed_parts == {"ENTRY", "TRUST_BOUNDARY", "SENSITIVE_OPERATION"}
    assert len(client.requests) == 1
    request = client.requests[0]
    assert b"<GRAPH_REVIEW_DIRECTORY>" in request["prompt"]
    assert b"path-real" in request["prompt"]
    required = request["schema"]["properties"]["review_evidence"]["items"]["required"]
    assert required == [
        "part",
        "location",
        "context_hash",
        "source_sha256",
        "graph_path_id",
        "edge_ids",
        "explanation",
    ]
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["kind"] == "simple_surface_hypothesis_result_v5"
    assert saved["validation_status"] == "VALID"
    assert saved["verified_path_id"] == "path-real"
    assert len(saved["verified_roles"]) == 3
    assert saved["graph_ref"]["content_hash"] == saved["graph_hash"]
    assert saved["reviewed_parts"] == sorted(result.reviewed_parts)
    assert saved["response"]["context_id"] == context.context_id


@pytest.mark.asyncio
async def test_v5_adapter_retries_bad_edge_then_fails_closed(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, artifacts = _v5_fixture(tmp_path)
    invalid = _reply(
        context.context_id,
        status="NO_HYPOTHESIS",
        review_evidence=cast(Any, _review_v4(context)),
    )
    cast(list[dict[str, object]], invalid["review_evidence"])[2]["edge_ids"] = [
        "edge-entry"
    ]
    client.replies.extend([invalid, invalid])

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_OUTPUT_INVALID"
    assert len(client.requests) == 2
    assert any(
        json.loads(artifacts.read(ref)).get("kind")
        == "simple_surface_hypothesis_result_v5"
        for ref in result.evidence_refs
    )


@pytest.mark.asyncio
async def test_v5_adapter_rejects_answer_key_field_before_llm(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, _ = _v5_fixture(
        tmp_path, bad_graph=True
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_CONTEXT_INVALID"
    assert client.requests == []


@pytest.mark.asyncio
async def test_v5_adapter_accepts_actual_planner_part(tmp_path: Path) -> None:
    case = _planner_case(tmp_path)
    _, parts = _planner_prepare(case)
    assert len(parts) == 1
    part = parts[0]
    identity = case["identity"]
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    graph = case["graphs"][part.surface_id]
    graph_ref = artifacts.put_json(graph)
    assert graph_ref.content_hash == part.payload["graph_hash"]
    context_ref = artifacts.put_json(part.payload)
    assert context_ref.content_hash == part.context_hash
    static_ref = artifacts.put_json({"kind": "static-bundle"})
    static = StaticBootstrapResult(
        repository_profile_ref=static_ref,
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )
    context = SurfaceContext(
        surface_id=part.surface_id,
        context_id=part.context_id,
        context_hash=part.context_hash,
        context_ref=context_ref,
        part_index=part.part_index,
        part_count=part.part_count,
        prompt_bytes=len(artifacts.read(context_ref)),
        source_sha256=part.source_sha256,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=0,
        omitted_ast_fact_count=0,
    )
    client = _Client(
        [
            {
                "surface_id": part.surface_id,
                "context_id": part.context_id,
                "status": "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
                "reason": "No connected route, request and sink path is visible.",
                "hypotheses": [],
                "review_evidence": [],
            }
        ]
    )
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "artifacts",
        client_factory=lambda _identity, _artifacts: cast(SimpleLLMClient, client),
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["kind"] == "simple_surface_hypothesis_result_v5"
    assert saved["validation_status"] == "VALID"
    assert saved["graph_hash"] == graph_ref.content_hash
    assert saved["verified_path_id"] is None
