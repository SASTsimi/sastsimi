"""The v8 Hypothesis Agent asks for source/control anchors, never fake sinks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    SurfaceProposalResult,
)
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.provider import SimpleLLMClient
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from tests.unit.simple_runtime.test_surface_enrichment_v8 import (
    _graph,
    _response,
    _wrapper,
)
from tests.unit.simple_runtime.test_surface_proposal import _Client


def test_v8_schema_requests_only_role_specific_anchor_and_allows_local_edges() -> None:
    schema = DirectHypothesisBootstrap._surface_schema(
        "surface-1",
        "context-1",
        version=8,
        context_hash="a" * 64,
        eligible_review_parts=frozenset({"ANCHOR"}),
    )

    review = schema["properties"]["review_evidence"]["items"]
    assert review["properties"]["part"]["enum"] == ["ANCHOR"]
    assert review["properties"]["edge_ids"]["minItems"] == 0
    assert review["properties"]["context_hash"]["enum"] == ["a" * 64]


def _run_v8_proposal(
    tmp_path: Path,
    graph: dict[str, object],
    *,
    local_only: bool,
    provide_response: bool,
) -> tuple[SurfaceProposalResult, dict[str, object], _Client]:
    wrapper = _wrapper(graph, local_only=local_only)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    graph_ref = artifacts.put_json(graph)
    static_ref = artifacts.put_json({"kind": "static-bundle"})
    context_payload = wrapper["context_payload"]
    assert isinstance(context_payload, dict)
    payload = dict(context_payload)
    payload["graph_hash"] = graph_ref.content_hash
    payload["static_bundle_hash"] = static_ref.content_hash
    payload["reader_revision"] = "source-bound-v5-1"
    context_ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v8",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": payload["surface_id"],
                "part_index": 0,
                "context_hash": context_ref.content_hash,
            }
        )
    ).hexdigest()
    wrapper.update(
        context_payload=payload,
        context_hash=context_ref.content_hash,
        context_id=context_id,
    )
    context = SurfaceContext(
        surface_id="surface-1",
        context_id=context_id,
        context_hash=context_ref.content_hash,
        context_ref=context_ref,
        part_index=0,
        part_count=1,
        prompt_bytes=len(artifacts.read(context_ref)),
        source_sha256="a" * 64,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=0,
        omitted_ast_fact_count=0,
    )
    static = StaticBootstrapResult(
        repository_profile_ref=static_ref,
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )
    client = _Client(
        [_response(wrapper, local_only=local_only)] if provide_response else []
    )
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda *_: cast(SimpleLLMClient, client),
    )
    operation = bootstrap.propose_surface(identity, static, context)
    try:
        operation.send(None)
    except StopIteration as completed:
        result = completed.value
    else:
        raise AssertionError("The local fake client must complete synchronously")
    finally:
        operation.close()

    assert isinstance(result, SurfaceProposalResult)
    return result, json.loads(artifacts.read(result.result_ref)), client


def test_v8_local_anchor_proposal_records_actual_proof_without_fake_sink(
    tmp_path: Path,
) -> None:
    graph = _graph()
    graph["paths"] = []
    graph["nodes"] = []
    graph["edges"] = []
    result, saved, client = _run_v8_proposal(
        tmp_path, graph, local_only=True, provide_response=True
    )

    assert result.status == "NO_HYPOTHESIS"
    assert result.reviewed_parts == frozenset({"ANCHOR"})
    assert saved["proof_level"] == "LOCAL_ONLY"
    assert saved["verified_path_id"] is None
    verified_roles = saved["verified_roles"]
    assert isinstance(verified_roles, list)
    assert all(isinstance(row, dict) for row in verified_roles)
    assert [row["part"] for row in verified_roles] == ["ANCHOR"]
    assert client.requests
    assert b"SENSITIVE_OPERATION" not in client.requests[0]["prompt"]
    assert client.requests[0]["schema"]["properties"]["review_evidence"]["items"][
        "properties"
    ]["part"]["enum"] == ["ANCHOR"]


def test_v8_missing_ast_short_circuits_as_insufficient_without_llm(
    tmp_path: Path,
) -> None:
    graph = _graph()
    graph["ast_facts"] = []
    result, saved, client = _run_v8_proposal(
        tmp_path, graph, local_only=False, provide_response=False
    )

    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert result.reviewed_parts == frozenset()
    assert saved["proof_level"] == "INSUFFICIENT"
    assert saved["reason"] == "ANCHOR_AST_UNAVAILABLE"
    assert saved["resolution_source"] == "PINNED_GRAPH_GAPS"
    assert client.requests == []
