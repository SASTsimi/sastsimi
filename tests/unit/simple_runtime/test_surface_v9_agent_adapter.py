"""The existing Hypothesis Agent can review bounded v9 parts safely."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    SurfaceProposalResult,
)
from sastsimi.simple_runtime.models import StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMClient
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from tests.unit.simple_runtime.test_surface_evidence_validation_v9 import (
    _case,
    _response,
)
from tests.unit.simple_runtime.test_surface_proposal import _Client, _proposal


def _bootstrap(
    tmp_path: Path, replies: list[dict[str, object]]
) -> tuple[DirectHypothesisBootstrap, _Client, StaticBootstrapResult]:
    context, _payload, identity = _case(tmp_path)
    client = _Client(replies)
    static_ref = _ref(identity, "b" * 64)
    static = StaticBootstrapResult(
        repository_profile_ref=static_ref,
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda _identity, _artifacts: cast(SimpleLLMClient, client),
    )
    assert context.context_ref.content_hash == context.context_hash
    return bootstrap, client, static


@pytest.mark.asyncio
async def test_v9_agent_saves_exact_review_fields_for_coverage(tmp_path: Path) -> None:
    context, payload, identity = _case(tmp_path)
    bootstrap, client, static = _bootstrap(tmp_path, [_response(context, payload)])

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.status == "NO_HYPOTHESIS"
    assert result.reviewed_parts == frozenset({"ENTRY", "TRUST_BOUNDARY", "ANCHOR"})
    assert len(client.requests) == 1
    assert client.requests[0]["agent_name"] == "hypothesis_surface"
    assert client.requests[0]["schema"]["properties"]["part_id"]["enum"] == ["part-1"]
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["kind"] == "simple_surface_hypothesis_result_v9"
    assert saved["part_id"] == "part-1"
    assert saved["review_complete"] is True
    assert saved["reviewed_path_ids"] == ["path-a"]
    part = cast(dict[str, object], payload["context_part"])
    assert saved["content_sha256"] == part["content_sha256"]
    assert {(row["path_id"], row["role"]) for row in saved["role_citations"]} == {
        ("path-a", "ENTRY"),
        ("path-a", "TRUST_BOUNDARY"),
        ("path-a", "ANCHOR"),
    }


@pytest.mark.asyncio
async def test_v9_agent_repairs_missing_role_once_then_accepts_review(
    tmp_path: Path,
) -> None:
    context, payload, identity = _case(tmp_path)
    invalid = _response(context, payload)
    evidence = cast(list[object], invalid["review_evidence"])
    invalid["review_evidence"] = evidence[:-1]
    bootstrap, client, static = _bootstrap(
        tmp_path, [invalid, _response(context, payload)]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.status == "NO_HYPOTHESIS"
    assert len(client.requests) == 2
    assert b"V9_REVIEW_INCOMPLETE" in client.requests[1]["prompt"]


@pytest.mark.asyncio
async def test_v9_agent_fails_after_bounded_invalid_replies(tmp_path: Path) -> None:
    context, payload, identity = _case(tmp_path)
    invalid = _response(context, payload)
    invalid["review_evidence"] = []
    bootstrap, client, static = _bootstrap(tmp_path, [invalid, invalid])

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_OUTPUT_INVALID"
    assert len(client.requests) == 2
    assert result.evidence_refs


@pytest.mark.asyncio
async def test_v9_agent_never_calls_llm_for_tampered_context(tmp_path: Path) -> None:
    context, payload, identity = _case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    payload["plan_binding_hash"] = "7" * 64
    tampered_ref = artifacts.put_json(payload)
    from dataclasses import replace

    tampered = replace(context, context_ref=tampered_ref)
    bootstrap, client, static = _bootstrap(tmp_path, [])

    result = await bootstrap.propose_surface(identity, static, tampered)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_CONTEXT_INVALID"
    assert client.requests == []


@pytest.mark.asyncio
async def test_v9_agent_fails_closed_when_response_cannot_be_redacted(
    tmp_path: Path,
) -> None:
    context, payload, identity = _case(tmp_path)
    reply = _response(context, payload)
    nested = "reviewed local source"
    for _ in range(24):
        nested = json.dumps({"wrap": nested})
    reply["reason"] = nested
    bootstrap, client, static = _bootstrap(tmp_path, [reply])

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_OUTPUT_UNSAFE"
    assert len(client.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("complete_review", [True, False])
async def test_v9_hypothesis_uses_existing_qualification_and_keeps_seed(
    tmp_path: Path, complete_review: bool
) -> None:
    context, payload, identity = _case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    excerpt = "def route():\n    value = request.args['x']\n    return eval(value)"
    source_hash = hashlib.sha256((excerpt + "\n").encode()).hexdigest()
    part = dict(cast(dict[str, object], payload["context_part"]))
    part.update(
        source_sha256=source_hash,
        content_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
    )
    payload["context_part"] = part
    payload["source_excerpt"] = excerpt
    role_directory = cast(list[dict[str, object]], payload["role_directory"])
    payload["role_directory"] = [
        {**item, "source_sha256": source_hash} for item in role_directory
    ]
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v9",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": context.surface_id,
                "part_id": part["part_id"],
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    context = replace(
        context,
        context_ref=ref,
        context_hash=ref.content_hash,
        context_id=context_id,
        source_sha256=source_hash,
        prompt_bytes=len(artifacts.read(ref)),
    )
    reply = _response(context, payload)
    reply["status"] = "HYPOTHESES"
    reply["hypotheses"] = [_proposal("app.py:3")]
    if not complete_review:
        reply["reviewed_path_ids"] = []
        reply["review_evidence"] = []
    bootstrap, _client, static = _bootstrap(tmp_path, [reply])

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, SurfaceProposalResult)
    assert result.status == "HYPOTHESES"
    assert len(result.seeds) == 1
    saved = json.loads(artifacts.read(result.result_ref))
    assert saved["review_complete"] is complete_review
    assert saved["seed_ids"] == [result.seeds[0].hypothesis_id]
    assert result.reviewed_parts == (
        frozenset({"ENTRY", "TRUST_BOUNDARY", "ANCHOR"})
        if complete_review
        else frozenset()
    )
