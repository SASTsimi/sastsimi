"""Targeted Hypothesis Agent reviews remain bound to visible surface context."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult, SimpleLLMClient
from sastsimi.simple_runtime.surface_contexts import SurfaceContext

_SURFACE_ID = "surface-review-001"
_SOURCE = "def route(value):\n    evaluate(value)\n"


class _Client:
    def __init__(self, replies: list[dict[str, object]]) -> None:
        self.replies = replies
        self.requests: list[dict[str, Any]] = []

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult:
        del invocation_id
        self.requests.append(
            {
                "prompt": prompt,
                "schema": output_schema,
                "timeout_ms": timeout_ms,
                "agent_name": agent_name,
                "owner": owner,
                "prompt_bytes": prompt_bytes,
            }
        )
        return SimpleLLMCallResult(
            value=cast(dict[str, JsonValue], self.replies.pop(0)),
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _proposal(location: str = "app.py:2") -> dict[str, object]:
    return {
        "title": "Possible unsafe evaluation",
        "vulnerability_type": "CODE_INJECTION",
        "summary": "A caller-controlled value may reach evaluate.",
        "code_locations": [location],
        "source": "route value",
        "sink": "evaluate(value)",
        "rationale": "The route forwards the argument to evaluation.",
        "qualification": {
            "attacker_control": "POSSIBLE",
            "sensitive_operation": "YES",
            "reachability": "POSSIBLE",
            "trust_boundary": "caller to evaluator",
            "controls": "UNKNOWN",
            "preconditions": "route can be called by an untrusted caller",
            "evidence_locations": [location],
        },
    }


def _review(*parts: str) -> list[dict[str, str]]:
    return [
        {
            "part": part,
            "location": "app.py:2" if part == "SENSITIVE_OPERATION" else "app.py:1",
            "explanation": f"Visible code supports {part.lower()} review",
        }
        for part in parts
    ]


def _reply(
    context_id: str,
    *,
    status: str,
    hypotheses: list[dict[str, object]] | None = None,
    review_evidence: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "surface_id": _SURFACE_ID,
        "context_id": context_id,
        "status": status,
        "reason": "Visible source was reviewed for this surface.",
        "hypotheses": hypotheses or [],
        "review_evidence": review_evidence or [],
    }


def _fixture(
    tmp_path: Path,
    *,
    source_status: str = "AVAILABLE",
    unavailable_source_lines: list[dict[str, object]] | None = None,
) -> tuple[
    DirectHypothesisBootstrap,
    _Client,
    CheckpointIdentity,
    StaticBootstrapResult,
    SurfaceContext,
    SimpleArtifactRepository,
]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text(_SOURCE, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-surface",
        workspace_id="workspace-surface",
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
    payload: dict[str, Any] = {
        "kind": "simple_surface_context_v1",
        "scope_fingerprint": "scope-surface",
        "static_bundle_hash": bundle_ref.content_hash,
        "ast_manifest_hash": "c" * 64,
        "surface_id": _SURFACE_ID,
        "surface_type": "CODE_EXECUTION",
        "path": "app.py",
        "symbol": "route",
        "line": 2,
        "detector": "test-detector",
        "flow_identity": None,
        "source_sha256": hashlib.sha256(_SOURCE.encode()).hexdigest(),
        "source_status": source_status,
        "source_unavailable_reason": (
            "SOURCE_TOO_LARGE"
            if source_status == "UNAVAILABLE"
            else "SOURCE_LINE_TOO_LARGE"
            if source_status == "PARTIAL"
            else None
        ),
        "source_line_count": 2 if source_status != "UNAVAILABLE" else None,
        "source_lines": (
            (
                [{"line": 1, "text": "def route(value):"}]
                if source_status == "AVAILABLE"
                else []
            )
            + [{"line": 2, "text": "    evaluate(value)"}]
            if source_status == "AVAILABLE" or source_status == "PARTIAL"
            else []
        ),
        "unavailable_source_lines": (
            unavailable_source_lines
            if unavailable_source_lines is not None
            else [{"line": 1, "reason": "SOURCE_LINE_TOO_LARGE"}]
            if source_status == "PARTIAL"
            else []
        ),
        "ast_facts": [],
        "part_index": 0,
        "part_count": 1,
    }
    context_ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v1",
                "scope_fingerprint": "scope-surface",
                "surface_id": _SURFACE_ID,
                "part_index": 0,
                "context_hash": context_ref.content_hash,
            }
        )
    ).hexdigest()
    context = SurfaceContext(
        surface_id=_SURFACE_ID,
        context_id=context_id,
        context_hash=context_ref.content_hash,
        context_ref=context_ref,
        part_index=0,
        part_count=1,
        prompt_bytes=len(artifacts.read(context_ref)),
        source_sha256=payload["source_sha256"],
        source_unavailable_reason=payload["source_unavailable_reason"],
        ast_unavailable_reason=None,
        omitted_source_line_count=(
            0
            if source_status == "AVAILABLE"
            else 1
            if source_status == "PARTIAL"
            else None
        ),
        omitted_ast_fact_count=0,
    )
    client = _Client([])
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda _identity, _artifacts: cast(SimpleLLMClient, client),
    )
    return bootstrap, client, identity, static, context, artifacts


def _as_part(
    artifacts: SimpleArtifactRepository,
    context: SurfaceContext,
    *,
    part_index: int,
    part_count: int,
) -> SurfaceContext:
    payload = json.loads(artifacts.read(context.context_ref))
    payload["part_index"] = part_index
    payload["part_count"] = part_count
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v1",
                "scope_fingerprint": payload["scope_fingerprint"],
                "surface_id": context.surface_id,
                "part_index": part_index,
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    return replace(
        context,
        context_ref=ref,
        context_hash=ref.content_hash,
        context_id=context_id,
        part_index=part_index,
        part_count=part_count,
        prompt_bytes=len(artifacts.read(ref)),
    )


def _as_v2(
    artifacts: SimpleArtifactRepository, context: SurfaceContext
) -> SurfaceContext:
    payload = json.loads(artifacts.read(context.context_ref))
    payload["kind"] = "simple_surface_context_v2"
    payload["selection_scope"] = "ENCLOSING_DEFINITION"
    payload["selected_source_line_count"] = 2
    payload["unavailable_implementation"] = None
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v2",
                "scope_fingerprint": payload["scope_fingerprint"],
                "surface_id": context.surface_id,
                "part_index": context.part_index,
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    return replace(
        context,
        context_ref=ref,
        context_hash=ref.content_hash,
        context_id=context_id,
        prompt_bytes=len(artifacts.read(ref)),
    )


@pytest.mark.asyncio
async def test_v1_and_v2_proposals_require_exact_source_location(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, artifacts = _fixture(tmp_path)
    expanded = _as_v2(artifacts, context)
    client.replies.extend(
        [
            _reply(
                expanded.context_id,
                status="HYPOTHESES",
                hypotheses=[_proposal("other.py:2")],
            ),
            _reply(expanded.context_id, status="HYPOTHESES", hypotheses=[_proposal()]),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, expanded)

    assert not isinstance(result, StageFailure)
    assert len(client.requests) == 2
    assert result.status == "HYPOTHESES"
    assert json.loads(artifacts.read(result.result_ref))["kind"] == (
        "simple_surface_hypothesis_result_v2"
    )


@pytest.mark.asyncio
async def test_second_look_cannot_rule_out_external_implementation(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, artifacts = _fixture(tmp_path)
    expanded = _as_v2(artifacts, context)
    payload = json.loads(artifacts.read(expanded.context_ref))
    payload["unavailable_implementation"] = (
        "CALL_RESULT_IMPLEMENTATION_NOT_IN_SAME_FILE"
    )
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v2",
                "scope_fingerprint": payload["scope_fingerprint"],
                "surface_id": expanded.surface_id,
                "part_index": expanded.part_index,
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    expanded = replace(
        expanded,
        context_ref=ref,
        context_hash=ref.content_hash,
        context_id=context_id,
        prompt_bytes=len(artifacts.read(ref)),
    )
    client.replies.extend(
        [
            _reply(expanded.context_id, status="NO_HYPOTHESIS"),
            _reply(expanded.context_id, status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, expanded)

    assert not isinstance(result, StageFailure)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert len(client.requests) == 2


@pytest.mark.asyncio
async def test_surface_hypothesis_is_bound_to_exact_visible_evidence(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, artifacts = _fixture(tmp_path)
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
    assert result.surface_id == _SURFACE_ID
    assert result.context_id == context.context_id
    assert result.reviewed_parts == frozenset(
        {"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"}
    )
    assert set(result.evidence_locations) == {"app.py:1", "app.py:2"}
    assert len(result.seeds) == 1
    assert client.requests[0]["agent_name"] == "hypothesis_surface"
    assert client.requests[0]["owner"].surface_id == _SURFACE_ID
    assert client.requests[0]["owner"].context_id == context.context_id
    proposal = json.loads(artifacts.read(result.seeds[0].proposal_ref))
    recorded = json.loads(artifacts.read(result.result_ref))
    assert proposal["surface_id"] == _SURFACE_ID
    assert proposal["context_id"] == context.context_id
    assert recorded["seed_ids"] == [result.seeds[0].hypothesis_id]
    assert recorded["reviewed_parts"] == [
        "ENTRY",
        "SENSITIVE_OPERATION",
        "TRUST_BOUNDARY",
    ]


@pytest.mark.asyncio
async def test_surface_no_hypothesis_preserves_review_evidence(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(tmp_path)
    client.replies.append(
        _reply(
            context.context_id,
            status="NO_HYPOTHESIS",
            review_evidence=_review("SENSITIVE_OPERATION"),
        )
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "NO_HYPOTHESIS"
    assert result.seeds == ()
    assert result.reviewed_parts == frozenset({"SENSITIVE_OPERATION"})


@pytest.mark.asyncio
async def test_surface_review_retries_when_indexed_line_is_not_cited(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(tmp_path)
    nearby_only = [
        {
            "part": part,
            "location": "app.py:1",
            "explanation": "Nearby code was reviewed",
        }
        for part in ("ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY")
    ]
    client.replies.extend(
        [
            _reply(
                context.context_id,
                status="NO_HYPOTHESIS",
                review_evidence=nearby_only,
            ),
            _reply(
                context.context_id,
                status="NO_HYPOTHESIS",
                review_evidence=_review(
                    "ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"
                ),
            ),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "NO_HYPOTHESIS"
    assert len(client.requests) == 2
    assert b"app.py:2" in client.requests[1]["prompt"]
    assert "app.py:2" in result.evidence_locations


@pytest.mark.asyncio
async def test_v1_context_part_without_indexed_line_does_not_demand_it(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, artifacts = _fixture(tmp_path)
    payload = json.loads(artifacts.read(context.context_ref))
    payload["source_lines"] = [{"line": 1, "text": "def route(value):"}]
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v1",
                "scope_fingerprint": payload["scope_fingerprint"],
                "surface_id": context.surface_id,
                "part_index": 0,
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    context = replace(
        context,
        context_ref=ref,
        context_hash=ref.content_hash,
        context_id=context_id,
        prompt_bytes=len(artifacts.read(ref)),
    )
    client.replies.append(
        _reply(
            context.context_id,
            status="NO_HYPOTHESIS",
            review_evidence=[
                {
                    "part": part,
                    "location": "app.py:1",
                    "explanation": "Visible part reviewed",
                }
                for part in ("ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY")
            ],
        )
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "NO_HYPOTHESIS"
    assert result.evidence_locations == ("app.py:1",)
    assert len(client.requests) == 1


@pytest.mark.asyncio
async def test_repeated_missing_anchor_keeps_hypothesis_but_not_coverage(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, artifacts = _fixture(tmp_path)
    nearby_only = [
        {"part": part, "location": "app.py:1", "explanation": "Nearby code reviewed"}
        for part in ("ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY")
    ]
    client.replies.extend(
        [
            _reply(
                context.context_id,
                status="HYPOTHESES",
                hypotheses=[_proposal()],
                review_evidence=nearby_only,
            )
            for _ in range(2)
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "HYPOTHESES"
    assert len(result.seeds) == 1
    assert result.reviewed_parts == frozenset()
    assert result.evidence_locations == ()
    assert len(client.requests) == 2
    stored = json.loads(artifacts.read(result.result_ref))
    assert stored["validation_status"] == "PARTIAL_REVIEW"


@pytest.mark.asyncio
async def test_identical_proposal_in_two_parts_has_distinct_durable_seed_ids(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, artifacts = _fixture(tmp_path)
    first_context = _as_part(artifacts, context, part_index=0, part_count=2)
    second_context = _as_part(artifacts, context, part_index=1, part_count=2)
    client.replies.extend(
        [
            _reply(
                first_context.context_id, status="HYPOTHESES", hypotheses=[_proposal()]
            ),
            _reply(
                second_context.context_id, status="HYPOTHESES", hypotheses=[_proposal()]
            ),
        ]
    )

    first = await bootstrap.propose_surface(identity, static, first_context)
    second = await bootstrap.propose_surface(identity, static, second_context)

    assert not isinstance(first, StageFailure)
    assert not isinstance(second, StageFailure)
    assert len(first.seeds) == len(second.seeds) == 1
    assert first.seeds[0].hypothesis_id != second.seeds[0].hypothesis_id
    assert first.seeds[0].proposal_ref != second.seeds[0].proposal_ref


@pytest.mark.asyncio
async def test_surface_invalid_location_retries_then_preserves_valid_result(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(tmp_path)
    client.replies.extend(
        [
            _reply(
                context.context_id,
                status="HYPOTHESES",
                hypotheses=[_proposal("app.py:3")],
            ),
            _reply(
                context.context_id,
                status="HYPOTHESES",
                hypotheses=[_proposal()],
                review_evidence=_review("SENSITIVE_OPERATION"),
            ),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert len(result.seeds) == 1
    assert len(client.requests) == 2
    assert b"HYPOTHESIS_SURFACE_LOCATION_INVALID" in client.requests[1]["prompt"]


@pytest.mark.asyncio
async def test_surface_ungrounded_attacker_control_gets_specific_repair_feedback(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, artifacts = _fixture(tmp_path)
    ungrounded = _proposal()
    qualification = cast(dict[str, object], ungrounded["qualification"])
    qualification["attacker_control"] = "UNKNOWN"
    client.replies.extend(
        [
            _reply(
                context.context_id,
                status="HYPOTHESES",
                hypotheses=[ungrounded],
            ),
            _reply(
                context.context_id,
                status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            ),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert result.seeds == ()
    assert result.reviewed_parts == frozenset()
    assert len(client.requests) == 2
    assert b"qualification.attacker_control" in client.requests[1]["prompt"]
    assert b"YES or POSSIBLE" in client.requests[1]["prompt"]
    recorded = json.loads(artifacts.read(result.result_ref))
    assert recorded["validation_status"] == "VALID"


@pytest.mark.asyncio
async def test_surface_ungrounded_sensitive_operation_is_not_misdiagnosed(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(tmp_path)
    ungrounded = _proposal()
    qualification = cast(dict[str, object], ungrounded["qualification"])
    qualification["sensitive_operation"] = "UNKNOWN"
    client.replies.extend(
        [
            _reply(
                context.context_id,
                status="HYPOTHESES",
                hypotheses=[ungrounded],
            ),
            _reply(
                context.context_id,
                status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            ),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert b"qualification.sensitive_operation" in client.requests[1]["prompt"]
    assert b"qualification.attacker_control" in client.requests[1]["prompt"]


@pytest.mark.asyncio
async def test_surface_blocking_control_gets_allowed_repair_values(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(tmp_path)
    ungrounded = _proposal()
    qualification = cast(dict[str, object], ungrounded["qualification"])
    qualification["controls"] = "PROVEN_BLOCKING"
    client.replies.extend(
        [
            _reply(
                context.context_id,
                status="HYPOTHESES",
                hypotheses=[ungrounded],
            ),
            _reply(
                context.context_id,
                status="NO_HYPOTHESIS",
            ),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "NO_HYPOTHESIS"
    assert len(client.requests) == 2
    assert (
        b"qualification.controls NONE, POSSIBLE, or UNKNOWN"
        in (client.requests[1]["prompt"])
    )


@pytest.mark.asyncio
async def test_surface_invalid_output_fails_after_bounded_retry(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, artifacts = _fixture(tmp_path)
    client.replies.extend(
        [
            _reply(
                context.context_id,
                status="HYPOTHESES",
                hypotheses=[_proposal("other.py:2")],
            ),
            _reply(
                context.context_id,
                status="HYPOTHESES",
                hypotheses=[_proposal("app.py:3")],
            ),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_OUTPUT_INVALID"
    assert len(client.requests) == 2
    assert len(result.evidence_refs) >= 2
    assert any(
        json.loads(artifacts.read(ref)).get("validation_status") == "INVALID"
        for ref in result.evidence_refs
    )


@pytest.mark.asyncio
async def test_unavailable_surface_cannot_be_false_negative(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(
        tmp_path, source_status="UNAVAILABLE"
    )
    client.replies.extend(
        [
            _reply(context.context_id, status="NO_HYPOTHESIS"),
            _reply(
                context.context_id,
                status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            ),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert result.reviewed_parts == frozenset()
    assert len(client.requests) == 2


@pytest.mark.asyncio
async def test_partial_surface_keeps_grounded_seed_but_not_coverage(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(
        tmp_path, source_status="PARTIAL"
    )
    client.replies.append(
        _reply(
            context.context_id,
            status="HYPOTHESES",
            hypotheses=[_proposal()],
            review_evidence=_review("SENSITIVE_OPERATION"),
        )
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "HYPOTHESES"
    assert len(result.seeds) == 1
    assert result.reviewed_parts == frozenset()
    assert result.evidence_locations == ()


@pytest.mark.asyncio
async def test_partial_surface_cannot_be_false_negative(tmp_path: Path) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(
        tmp_path, source_status="PARTIAL"
    )
    client.replies.extend(
        [
            _reply(context.context_id, status="NO_HYPOTHESIS"),
            _reply(
                context.context_id,
                status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            ),
        ]
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert not isinstance(result, StageFailure)
    assert result.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert result.reviewed_parts == frozenset()
    assert len(client.requests) == 2


@pytest.mark.asyncio
async def test_surface_context_identity_mismatch_fails_before_llm(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, context, _ = _fixture(tmp_path)
    context = SurfaceContext(
        surface_id=context.surface_id,
        context_id="wrong-context-id",
        context_hash=context.context_hash,
        context_ref=context.context_ref,
        part_index=context.part_index,
        part_count=context.part_count,
        prompt_bytes=context.prompt_bytes,
        source_sha256=context.source_sha256,
        source_unavailable_reason=context.source_unavailable_reason,
        ast_unavailable_reason=context.ast_unavailable_reason,
        omitted_source_line_count=context.omitted_source_line_count,
        omitted_ast_fact_count=context.omitted_ast_fact_count,
    )

    result = await bootstrap.propose_surface(identity, static, context)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURFACE_CONTEXT_INVALID"
    assert client.requests == []
