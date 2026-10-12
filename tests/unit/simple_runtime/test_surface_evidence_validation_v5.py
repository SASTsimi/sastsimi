"""The Hypothesis Agent v5 adapter saves only source-bound graph reviews."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    SurfaceProposalResult,
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMClient
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
    validate_v5_context,
    validate_v5_response,
)
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
from tests.unit.simple_runtime.test_surface_proposal import (
    _Client,
    _proposal,
    _reply,
)


def _v5_fixture(
    tmp_path: Path,
    *,
    bad_graph: bool = False,
    proof_revision: str | None = None,
    blocking_gaps: object | None = None,
    graph_gaps: list[dict[str, str]] | None = None,
    successor_fields: dict[str, object] | None = None,
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
    if proof_revision is not None:
        graph["proof_semantics_revision"] = proof_revision
    if blocking_gaps is not None:
        paths = cast(list[dict[str, object]], graph["paths"])
        paths[0] = {**paths[0], "blocking_gaps": blocking_gaps}
    if graph_gaps is not None:
        graph["gaps"] = graph_gaps
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
        **(successor_fields or {}),
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


_SUCCESSOR_FIELDS: dict[str, object] = {
    "prior_v3_coverage_hash": "a" * 64,
    "prior_v5_plan_hash": "b" * 64,
    "graph_semantics_revision": "v5-source-bound-3",
}


def _saved_v5_wrapper(
    context: SurfaceContext, artifacts: SimpleArtifactRepository
) -> dict[str, object]:
    payload = json.loads(artifacts.read(context.context_ref))
    graph_hash = cast(str, payload["graph_hash"])
    graph_ref = context.context_ref.model_copy(
        update={"stored_data_id": graph_hash, "content_hash": graph_hash}
    )
    return {
        "context_payload": payload,
        "graph_payload": json.loads(artifacts.read(graph_ref)),
        "context_hash": context.context_hash,
        "context_id": context.context_id,
    }


def _propose_without_event_loop(
    bootstrap: DirectHypothesisBootstrap,
    identity: CheckpointIdentity,
    static: StaticBootstrapResult,
    context: SurfaceContext,
) -> SurfaceProposalResult | StageFailure:
    operation = bootstrap.propose_surface(identity, static, context)
    try:
        operation.send(None)
    except StopIteration as completed:
        return cast(SurfaceProposalResult | StageFailure, completed.value)
    finally:
        operation.close()
    raise AssertionError("test client unexpectedly suspended")


def test_v5_rev3_positive_path_accepts_unrelated_gap(tmp_path: Path) -> None:
    _, _, _, _, context, artifacts = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=[],
        graph_gaps=[{"path": "other.py", "reason": "UNRELATED_DYNAMIC_DISPATCH"}],
    )
    response = _reply(
        context.context_id,
        status="HYPOTHESES",
        hypotheses=[_proposal("app.py:4")],
        review_evidence=cast(Any, _review_v4(context)),
    )

    checked = validate_v5_response(_saved_v5_wrapper(context, artifacts), response)

    assert checked.verified_path_id == "path-real"
    assert checked.reviewed_parts == {"ENTRY", "TRUST_BOUNDARY", "SENSITIVE_OPERATION"}


def test_v5_rev3_without_clear_path_records_insufficient_without_llm(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _ = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=["SOURCE_BOUND_PATH_UNPROVEN"],
        graph_gaps=[],
    )

    result = _propose_without_event_loop(bootstrap, identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert client.requests == []


@pytest.mark.parametrize("blocking_gaps", ["PATH_SOURCE_UNAVAILABLE", [17], [""]])
def test_v5_rev3_rejects_malformed_path_gap_attribution(
    tmp_path: Path, blocking_gaps: object
) -> None:
    _, _, _, _, context, artifacts = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=blocking_gaps,
    )

    with pytest.raises(ValueError, match="V5_GRAPH_INVALID"):
        validate_v5_context(_saved_v5_wrapper(context, artifacts))


def test_v5_successor_context_validation_requires_pinned_parent_pair(
    tmp_path: Path,
) -> None:
    _, _, _, _, context, artifacts = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=[],
        successor_fields={
            "prior_v3_coverage_hash": "a" * 64,
            "graph_semantics_revision": "v5-source-bound-3",
        },
    )

    with pytest.raises(ValueError, match="V5_CONTEXT_INVALID"):
        validate_v5_context(_saved_v5_wrapper(context, artifacts))


def test_v5_rev3_verified_path_can_be_reviewed_with_unrelated_graph_gap(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, artifacts = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=[],
        graph_gaps=[{"path": "other.py", "reason": "UNRELATED_DYNAMIC_DISPATCH"}],
    )
    client.replies.append(
        _reply(
            context.context_id,
            status="HYPOTHESES",
            hypotheses=[_proposal("app.py:4")],
            review_evidence=cast(Any, _review_v4(context)),
        )
    )

    result = _propose_without_event_loop(bootstrap, identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.status == "HYPOTHESES"
    assert result.reviewed_parts == {"ENTRY", "TRUST_BOUNDARY", "SENSITIVE_OPERATION"}
    assert len(client.requests) == 1
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["verified_path_id"] == "path-real"
    assert saved["validation_status"] == "VALID"


def test_v5_rev3_no_hypothesis_requires_gap_free_whole_graph(tmp_path: Path) -> None:
    _, _, _, _, context, artifacts = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=[],
        graph_gaps=[{"path": "other.py", "reason": "UNRELATED_DYNAMIC_DISPATCH"}],
    )
    response = _reply(
        context.context_id,
        status="NO_HYPOTHESIS",
        review_evidence=cast(Any, _review_v4(context)),
    )

    with pytest.raises(ValueError, match="V5_SOURCE_INCOMPLETE"):
        validate_v5_response(_saved_v5_wrapper(context, artifacts), response)


def test_v5_successor_normal_review_saves_v6_result_kind(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, artifacts = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=[],
        successor_fields=_SUCCESSOR_FIELDS,
    )
    client.replies.append(
        _reply(
            context.context_id,
            status="NO_HYPOTHESIS",
            review_evidence=cast(Any, _review_v4(context)),
        )
    )

    result = _propose_without_event_loop(bootstrap, identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["kind"] == "simple_surface_hypothesis_result_v6"
    assert saved["verified_path_id"] == "path-real"
    assert len(client.requests) == 1


def test_v5_successor_gap_shortcut_saves_v6_result_kind(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, artifacts = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=["PATH_SOURCE_UNAVAILABLE"],
        graph_gaps=[{"path": "app.py", "reason": "PATH_SOURCE_UNAVAILABLE"}],
        successor_fields=_SUCCESSOR_FIELDS,
    )

    result = _propose_without_event_loop(bootstrap, identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["kind"] == "simple_surface_hypothesis_result_v6"
    assert saved["resolution_source"] == "PINNED_GRAPH_GAPS"
    assert client.requests == []


def test_v5_successor_missing_parent_hash_rejects_context(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, _ = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=[],
        successor_fields={"prior_v3_coverage_hash": "a" * 64},
    )

    result = _propose_without_event_loop(bootstrap, identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_CONTEXT_INVALID"
    assert client.requests == []


@pytest.mark.parametrize(
    "successor_fields",
    [
        {**_SUCCESSOR_FIELDS, "prior_v5_plan_hash": "B" * 64},
        {**_SUCCESSOR_FIELDS, "graph_semantics_revision": "v5-source-bound-2"},
    ],
)
def test_v5_successor_malformed_binding_rejects_context(
    tmp_path: Path, successor_fields: dict[str, object]
) -> None:
    bootstrap, client, identity, static, context, _ = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=[],
        successor_fields=successor_fields,
    )

    result = _propose_without_event_loop(bootstrap, identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_CONTEXT_INVALID"
    assert client.requests == []


def test_v5_legacy_context_still_saves_v5_result_kind(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, artifacts = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-2",
    )
    client.replies.append(
        _reply(
            context.context_id,
            status="NO_HYPOTHESIS",
            review_evidence=cast(Any, _review_v4(context)),
        )
    )

    result = _propose_without_event_loop(bootstrap, identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["kind"] == "simple_surface_hypothesis_result_v5"
    assert saved["verified_path_id"] == "path-real"


@pytest.mark.parametrize("blocking_gaps", [None, ["PATH_SOURCE_UNAVAILABLE"]])
def test_v5_rev3_gap_without_clean_path_stays_insufficient(
    tmp_path: Path, blocking_gaps: list[str] | None
) -> None:
    bootstrap, client, identity, static, context, _ = _v5_fixture(
        tmp_path,
        proof_revision="v5-source-bound-3",
        blocking_gaps=blocking_gaps,
        graph_gaps=[{"path": "app.py", "reason": "PATH_SOURCE_UNAVAILABLE"}],
    )
    client.replies.append(
        _reply(
            context.context_id,
            status="HYPOTHESES",
            hypotheses=[_proposal("app.py:4")],
            review_evidence=cast(Any, _review_v4(context)),
        )
    )

    result = _propose_without_event_loop(bootstrap, identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert client.requests == []


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


@pytest.mark.asyncio
async def test_v5_graph_gaps_checkpoint_insufficient_without_positive_agent_output(
    tmp_path: Path,
) -> None:
    """A pinned graph gap must not become a positive claim or block the next part."""

    case = _planner_case(tmp_path)
    graph = next(iter(case["graphs"].values()))
    graph["gaps"].append({"reason": "DYNAMIC_DISPATCH_UNRESOLVED"})
    _, parts = _planner_prepare(case)
    part = parts[0]
    graph = case["graphs"][part.surface_id]
    assert graph["gaps"]
    identity = case["identity"]
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    graph_ref = artifacts.put_json(graph)
    context_ref = artifacts.put_json(part.payload)
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
            _reply(context.context_id, status="HYPOTHESES"),
            _reply(context.context_id, status="HYPOTHESES"),
        ]
    )
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "artifacts",
        client_factory=lambda _identity, _artifacts: cast(SimpleLLMClient, client),
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert result.seeds == ()
    assert result.reviewed_parts == frozenset()
    assert result.evidence_locations == ()
    assert client.requests == []
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["resolution_source"] == "PINNED_GRAPH_GAPS"
    assert saved["validation_status"] == "VALID"
    assert saved["response"]["hypotheses"] == []
    assert saved["response"]["review_evidence"] == []
    SimpleAnalysisApplication._surface_result_valid(
        artifacts,
        context,
        result.status,
        result.result_ref,
        static_ref.content_hash,
        analysis_id=identity.analysis_id,
        expected_seed_ids=(),
        expected_reviewed_parts=frozenset(),
        expected_locations=(),
    )
    store = SimpleCheckpointStore(tmp_path / "checkpoint.sqlite3")
    store.commit_surface_exploration(
        identity,
        case["index"].scope_fingerprint,
        context.surface_id,
        context.context_id,
        static_bundle_hash=static_ref.content_hash,
        index_hash=case["index_ref"].content_hash,
        context_hash=context.context_hash,
        source_sha256=context.source_sha256,
        status=result.status,
        result_ref=result.result_ref,
        registrations=(),
        proposal_version=5,
    )
    progress = store.list_surface_exploration_progress(
        identity, case["index"].scope_fingerprint
    )
    assert progress[(context.surface_id, context.context_id)].status == result.status
    assert progress[(context.surface_id, context.context_id)].hypothesis_ids == ()
    assert graph_ref.content_hash == saved["graph_hash"]
