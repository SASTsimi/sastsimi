"""The real Hypothesis Agent must accept pinned v3 surface supplements."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import StageFailure
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from tests.unit.simple_runtime.test_surface_proposal import (
    _fixture,
    _proposal,
    _reply,
    _review,
)


def _v3_context(
    artifacts: SimpleArtifactRepository,
    original: SurfaceContext,
    *,
    unavailable_implementation: str | None = None,
) -> SurfaceContext:
    payload = json.loads(artifacts.read(original.context_ref))
    payload.update(
        kind="simple_surface_context_v3",
        selection_scope="SAVED_V2_AST_SOURCE_SUPPLEMENT",
        parent_v2_context_id="saved-v2-part",
        parent_v2_context_hash="b" * 64,
        parent_v2_part_index=1,
        surface_index_hash="c" * 64,
        unavailable_ast_facts=[],
        unavailable_implementation=unavailable_implementation,
    )
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v3",
                "scope_fingerprint": payload["scope_fingerprint"],
                "surface_id": original.surface_id,
                "parent_v2_context_id": payload["parent_v2_context_id"],
                "part_index": original.part_index,
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    return replace(
        original,
        context_id=context_id,
        context_hash=ref.content_hash,
        context_ref=ref,
        prompt_bytes=len(artifacts.read(ref)),
    )


@pytest.mark.asyncio
async def test_real_surface_agent_records_distinct_v3_result_and_prompt(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, original, artifacts = _fixture(tmp_path)
    context = _v3_context(artifacts, original)
    client.replies.append(
        _reply(
            context.context_id,
            status="NO_HYPOTHESIS",
            review_evidence=_review("ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"),
        )
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "NO_HYPOTHESIS"
    assert json.loads(artifacts.read(result.result_ref))["kind"] == (
        "simple_surface_hypothesis_result_v3"
    )
    assert client.requests[0]["agent_name"] == "hypothesis_surface"


@pytest.mark.asyncio
async def test_real_surface_agent_preserves_grounded_v3_seed(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, original, artifacts = _fixture(tmp_path)
    context = _v3_context(artifacts, original)
    client.replies.append(
        _reply(
            context.context_id,
            status="HYPOTHESES",
            hypotheses=[_proposal()],
            review_evidence=_review("ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"),
        )
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "HYPOTHESES"
    assert len(result.seeds) == 1
    proposal = json.loads(artifacts.read(result.seeds[0].proposal_ref))
    assert proposal["context_id"] == context.context_id
    assert json.loads(artifacts.read(result.result_ref))["seed_ids"] == [
        result.seeds[0].hypothesis_id
    ]


@pytest.mark.asyncio
async def test_v3_context_id_cannot_be_rebound_to_another_parent(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, original, artifacts = _fixture(tmp_path)
    context = _v3_context(artifacts, original)
    payload = json.loads(artifacts.read(context.context_ref))
    payload["parent_v2_context_id"] = "different-saved-part"
    changed_ref = artifacts.put_json(payload)
    changed = replace(
        context,
        context_ref=changed_ref,
        context_hash=changed_ref.content_hash,
        prompt_bytes=len(artifacts.read(changed_ref)),
    )

    result = await bootstrap.propose_surface(identity, static, changed)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_CONTEXT_INVALID"
    assert not client.requests


@pytest.mark.asyncio
async def test_v3_missing_implementation_cannot_prove_no_hypothesis(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, original, artifacts = _fixture(tmp_path)
    context = _v3_context(
        artifacts,
        original,
        unavailable_implementation="CALL_RESULT_IMPLEMENTATION_NOT_IN_SAME_FILE",
    )
    client.replies.extend(
        [
            _reply(context.context_id, status="NO_HYPOTHESIS"),
            _reply(context.context_id, status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert result.reviewed_parts == frozenset()
    assert len(client.requests) == 2
