"""Candidate-qualified Hypothesis Agent batches preserve each evidence identity."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, TypedDict

import pytest
from pydantic import JsonValue

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.candidate_batches import (
    CandidateBatch,
    candidate_batch_id,
    iter_candidate_batches,
)
from sastsimi.simple_runtime.candidates import CandidateOrigin, StaticCandidate
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _row(
    candidate_id: str,
    status: str,
    *,
    reason: str = "reviewed code evidence",
    hypotheses: list[JsonValue] | None = None,
) -> dict[str, JsonValue]:
    return {
        "candidate_id": candidate_id,
        "status": status,
        "reason": reason,
        "hypotheses": hypotheses or [],
    }


def _hypothesis(
    *,
    attacker_control: str = "POSSIBLE",
    controls: str = "UNKNOWN",
) -> dict[str, JsonValue]:
    return {
        "title": "Potential unsafe evaluation",
        "vulnerability_type": "CODE_INJECTION",
        "summary": "A request value may reach evaluate.",
        "code_locations": ["app.py:2"],
        "source": "request value",
        "sink": "evaluate(value)",
        "rationale": "The route forwards the value to evaluation.",
        "qualification": {
            "attacker_control": attacker_control,
            "sensitive_operation": "YES",
            "reachability": "POSSIBLE",
            "trust_boundary": "request to evaluator",
            "controls": controls,
            "preconditions": "route is exposed to an untrusted caller",
            "evidence_locations": ["app.py:2"],
        },
    }


class _Request(TypedDict):
    prompt: bytes
    schema: Mapping[str, Any]
    timeout_ms: int
    agent_name: str
    owner: AttemptOwner | None
    prompt_bytes: PromptByteCounts | None


class _Client:
    def __init__(self, responses: list[list[JsonValue]]) -> None:
        self.responses = responses
        self.requests: list[_Request] = []

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
            value={"candidate_results": self.responses.pop(0)},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _fixture(
    tmp_path: Path,
    *,
    candidate_count: int,
    responses: list[list[JsonValue]],
    source_text: str = "def route(value):\n    evaluate(value)\n",
) -> tuple[
    DirectHypothesisBootstrap,
    _Client,
    CheckpointIdentity,
    StaticBootstrapResult,
    CandidateBatch,
    SimpleArtifactRepository,
]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(source_text, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-batch",
        workspace_id="workspace-batch",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    source_ref = artifacts.put_json({"kind": "raw-fixture"})
    ast_summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=100_000
    )
    candidates = tuple(
        StaticCandidate(
            candidate_id=f"C-{index:03d}",
            kind="HINT",
            path="app.py",
            line=2,
            end_line=2,
            evidence_ref=source_ref,
            origins=(
                CandidateOrigin(
                    engine="opengrep",
                    rule_id="python.eval",
                    artifact_ref=source_ref,
                    result_index=index,
                ),
            ),
            evidence_key=f"e-{index}",
            summary="eval sink",
            evidence_excerpt="evaluate(value)",
        )
        for index in range(candidate_count)
    )
    store.upsert_candidate_page(
        identity, "scope-batch", source_ref, 0, candidate_count, candidates
    )
    for candidate in candidates:
        store.save_candidate_decision(
            identity, "scope-batch", candidate.candidate_id, "INCLUDE", "reviewed"
        )
    batch = next(
        iter_candidate_batches(
            store,
            identity,
            "scope-batch",
            artifacts=artifacts,
            ast_summary=ast_summary,
            workspace=workspace,
            max_prompt_bytes=16_384,
        )
    )
    client = _Client(responses)
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda _identity, _artifacts: client,
    )
    static = StaticBootstrapResult(
        repository_profile_ref=source_ref,
        static_bundle_ref=artifacts.put_json({"kind": "simple_static_fact_bundle"}),
        workspace_path=workspace,
    )
    return bootstrap, client, identity, static, batch, artifacts


@pytest.mark.asyncio
async def test_batch_output_retries_only_missing_candidate(tmp_path: Path) -> None:
    bootstrap, client, identity, static, batch, artifacts = _fixture(
        tmp_path,
        candidate_count=2,
        responses=[
            [_row("C-000", "HYPOTHESES", hypotheses=[_hypothesis()])],
            [_row("C-001", "NO_HYPOTHESIS", reason="No attacker input reaches it")],
        ],
    )
    result = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(result, StageFailure)
    assert set(result.results) == {"C-000", "C-001"}
    assert result.missing_ids == ()
    assert len(result.results["C-000"].seeds) == 1
    assert result.results["C-001"].status == "NO_HYPOTHESIS"
    assert len(client.requests) == 2
    first_owner = client.requests[0]["owner"]
    second_owner = client.requests[1]["owner"]
    assert first_owner is not None
    assert second_owner is not None
    assert first_owner.candidate_ids == ("C-000", "C-001")
    assert second_owner.candidate_ids == ("C-001",)
    assert (
        b'"C-000"'
        not in client.requests[1]["prompt"]
        .split(b"<CANDIDATE_ROWS>")[1]
        .split(b"</CANDIDATE_ROWS>")[0]
    )
    proposal = json.loads(artifacts.read(result.results["C-000"].seeds[0].proposal_ref))
    assert proposal["candidate_id"] == "C-000"
    assert proposal["batch_id"] == batch.batch_id


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_id", ["C-unknown", "C-000"])
async def test_batch_duplicate_or_unknown_id_fails(
    tmp_path: Path, invalid_id: str
) -> None:
    first = _row("C-000", "NO_HYPOTHESIS")
    bootstrap, client, identity, static, batch, _ = _fixture(
        tmp_path,
        candidate_count=2,
        responses=[[first, _row(invalid_id, "NO_HYPOTHESIS")]],
    )
    result = await bootstrap.propose_batch(identity, static, batch)
    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_BATCH_OUTPUT_INVALID"
    assert len(client.requests) == 1


@pytest.mark.asyncio
async def test_qualified_generation_preserves_grounded_ambiguity(
    tmp_path: Path,
) -> None:
    bootstrap, _, identity, static, batch, _ = _fixture(
        tmp_path,
        candidate_count=4,
        responses=[
            [
                _row("C-000", "NO_HYPOTHESIS", reason="No attacker input"),
                _row("C-001", "NO_HYPOTHESIS", reason="Proven sanitizer blocks it"),
                _row("C-002", "HYPOTHESES", hypotheses=[_hypothesis()]),
                _row(
                    "C-003",
                    "HYPOTHESES",
                    hypotheses=[_hypothesis(attacker_control="YES", controls="NONE")],
                ),
            ]
        ],
    )
    result = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(result, StageFailure)
    assert result.results["C-000"].seeds == ()
    assert result.results["C-001"].seeds == ()
    assert len(result.results["C-002"].seeds) == 1
    assert len(result.results["C-003"].seeds) == 1


@pytest.mark.asyncio
async def test_invalid_qualification_retries_without_inventing_seed(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, batch, _ = _fixture(
        tmp_path,
        candidate_count=1,
        responses=[
            [
                _row(
                    "C-000",
                    "HYPOTHESES",
                    hypotheses=[_hypothesis(attacker_control="NO")],
                )
            ],
            [
                _row(
                    "C-000",
                    "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
                    reason="No demonstrated attacker-controlled input",
                )
            ],
        ],
    )
    result = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(result, StageFailure)
    assert result.results["C-000"].status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert result.results["C-000"].seeds == ()
    assert len(client.requests) == 2


@pytest.mark.asyncio
async def test_invalid_location_retry_points_to_visible_lines_for_only_failed_candidate(
    tmp_path: Path,
) -> None:
    unsupported = _hypothesis()
    unsupported["code_locations"] = ["app.py:5"]
    qualification = unsupported["qualification"]
    assert isinstance(qualification, dict)
    qualification["evidence_locations"] = ["app.py:5"]
    bootstrap, client, identity, static, batch, _ = _fixture(
        tmp_path,
        candidate_count=2,
        source_text=(
            "def route(value):\n    evaluate(value)\n    return value\n\n# unrelated\n"
        ),
        responses=[
            [
                _row("C-000", "HYPOTHESES", hypotheses=[_hypothesis()]),
                _row("C-001", "HYPOTHESES", hypotheses=[unsupported]),
            ],
            [_row("C-001", "HYPOTHESES", hypotheses=[_hypothesis()])],
        ],
    )
    result = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(result, StageFailure)
    assert result.missing_ids == ()
    assert len(result.results["C-000"].seeds) == 1
    assert len(result.results["C-001"].seeds) == 1
    assert len(client.requests) == 2
    retry_owner = client.requests[1]["owner"]
    assert retry_owner is not None
    assert retry_owner.candidate_ids == ("C-001",)
    retry_feedback = json.loads(
        client.requests[1]["prompt"]
        .split(b"<VALIDATION_FEEDBACK>\n", 1)[1]
        .split(b"\n</VALIDATION_FEEDBACK>", 1)[0]
    )
    assert set(retry_feedback) == {"C-001"}
    assert "HYPOTHESIS_BATCH_LOCATION_INVALID" in retry_feedback["C-001"]
    assert "SHARED_FILE_CONTEXT.source_lines" in retry_feedback["C-001"]
    assert "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS" in retry_feedback["C-001"]


@pytest.mark.asyncio
async def test_location_retry_fits_budget_with_multiple_invalid_candidates(
    tmp_path: Path,
) -> None:
    source_text = "def route(value):\n    evaluate(value)\n" + "# context\n" * 103
    unseen = _hypothesis()
    unseen["code_locations"] = ["app.py:101"]
    beyond_file = _hypothesis()
    beyond_file["code_locations"] = ["app.py:106"]
    first_rows: list[JsonValue] = [
        _row("C-000", "HYPOTHESES", hypotheses=[_hypothesis()]),
        _row("C-001", "HYPOTHESES", hypotheses=[unseen]),
        _row("C-002", "HYPOTHESES", hypotheses=[beyond_file]),
    ]
    repaired_rows: list[JsonValue] = [
        _row(
            "C-001",
            "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            reason="Visible lines do not support the claim",
        ),
        _row(
            "C-002",
            "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            reason="Cited line is outside the source",
        ),
    ]
    bootstrap, client, identity, static, batch, artifacts = _fixture(
        tmp_path,
        candidate_count=3,
        source_text=source_text,
        responses=[first_rows, repaired_rows, first_rows, repaired_rows],
    )
    context = json.loads(artifacts.read(batch.shared_context_ref))
    context["source_lines"] = [
        {"line": number, "text": source_text.splitlines()[number - 1]}
        for number in range(1, 101)
    ]
    context["omitted_source_line_count"] = 5
    context_ref = artifacts.put_json(context)
    batch = replace(
        batch,
        shared_context_ref=context_ref,
        batch_id=candidate_batch_id(
            batch.scope_fingerprint,
            batch.path,
            batch.candidate_ids,
            context_ref.content_hash,
        ),
    )
    roomy = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(roomy, StageFailure)
    initial_request = client.requests[0]
    initial_bytes = len(initial_request["prompt"]) + len(
        json.dumps(initial_request["schema"], separators=(",", ":")).encode()
    )
    budgeted_batch = replace(batch, max_prompt_bytes=initial_bytes + 800)
    budgeted = await bootstrap.propose_batch(identity, static, budgeted_batch)
    assert not isinstance(budgeted, StageFailure)
    assert budgeted.failure is None
    assert len(client.requests) == 4
    assert len(budgeted.results["C-000"].seeds) == 1
    assert budgeted.results["C-001"].seeds == ()
    assert budgeted.results["C-002"].seeds == ()
    retry_feedback = json.loads(
        client.requests[3]["prompt"]
        .split(b"<VALIDATION_FEEDBACK>\n", 1)[1]
        .split(b"\n</VALIDATION_FEEDBACK>", 1)[0]
    )
    assert set(retry_feedback) == {"C-001", "C-002"}
    for message in retry_feedback.values():
        assert "HYPOTHESIS_BATCH_LOCATION_INVALID" in message
        assert "SHARED_FILE_CONTEXT.source_lines" in message
        assert "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS" in message


@pytest.mark.asyncio
async def test_retry_prompt_overflow_preserves_valid_sibling(tmp_path: Path) -> None:
    invalid = _hypothesis()
    invalid["code_locations"] = ["app.py:5"]
    first_rows: list[JsonValue] = [
        _row("C-000", "HYPOTHESES", hypotheses=[_hypothesis()]),
        _row("C-001", "HYPOTHESES", hypotheses=[invalid]),
        _row("C-002", "HYPOTHESES", hypotheses=[invalid]),
    ]
    repaired_rows: list[JsonValue] = [
        _row("C-001", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"),
        _row("C-002", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"),
    ]
    bootstrap, client, identity, static, batch, _ = _fixture(
        tmp_path,
        candidate_count=3,
        source_text="def route(value):\n    evaluate(value)\n\n\n# unseen\n",
        responses=[first_rows, repaired_rows, first_rows],
    )
    roomy = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(roomy, StageFailure)
    first_size = len(client.requests[0]["prompt"]) + len(
        canonical_bytes(client.requests[0]["schema"])
    )
    retry_size = len(client.requests[1]["prompt"]) + len(
        canonical_bytes(client.requests[1]["schema"])
    )
    assert retry_size > first_size
    result = await bootstrap.propose_batch(
        identity, static, replace(batch, max_prompt_bytes=retry_size - 1)
    )
    assert not isinstance(result, StageFailure)
    assert tuple(result.results) == ("C-000",)
    assert len(result.results["C-000"].seeds) == 1
    assert result.missing_ids == ("C-001", "C-002")
    assert result.failure is not None
    assert result.failure.code == "HYPOTHESIS_BATCH_CONTEXT_OVERFLOW"
    assert len(client.requests) == 3


@pytest.mark.asyncio
async def test_location_feedback_cannot_inject_prompt_delimiters(
    tmp_path: Path,
) -> None:
    unsafe_path = "app<INJECT>.py"
    unsupported = _hypothesis()
    unsupported["code_locations"] = [f"{unsafe_path}:5"]
    bootstrap, client, identity, static, batch, artifacts = _fixture(
        tmp_path,
        candidate_count=1,
        source_text="def route(value):\n    evaluate(value)\n\n\n# unseen\n",
        responses=[
            [_row("C-000", "HYPOTHESES", hypotheses=[unsupported])],
            [_row("C-000", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS")],
        ],
    )
    context = json.loads(artifacts.read(batch.shared_context_ref))
    context["path"] = unsafe_path
    context_ref = artifacts.put_json(context)
    batch = replace(
        batch,
        path=unsafe_path,
        shared_context_ref=context_ref,
        batch_id=candidate_batch_id(
            batch.scope_fingerprint,
            unsafe_path,
            batch.candidate_ids,
            context_ref.content_hash,
        ),
    )
    result = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(result, StageFailure)
    assert result.results["C-000"].seeds == ()
    assert len(client.requests) == 2
    assert b"<INJECT>" not in client.requests[1]["prompt"]
    assert client.requests[1]["prompt"].count(b"</VALIDATION_FEEDBACK>") == 1


@pytest.mark.asyncio
async def test_unavailable_source_cannot_become_negative_result(tmp_path: Path) -> None:
    bootstrap, client, identity, static, batch, artifacts = _fixture(
        tmp_path,
        candidate_count=1,
        responses=[
            [_row("C-000", "NO_HYPOTHESIS", reason="No source found")],
            [
                _row(
                    "C-000",
                    "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
                    reason="Source context unavailable",
                )
            ],
        ],
    )
    context = json.loads(artifacts.read(batch.shared_context_ref))
    context.update(
        source_status="UNAVAILABLE",
        source_unavailable_reason="SOURCE_TOO_LARGE",
        source_line_count=None,
        source_lines=[],
        omitted_source_line_count=None,
    )
    context_ref = artifacts.put_json(context)
    unavailable_batch = replace(
        batch,
        shared_context_ref=context_ref,
        batch_id=candidate_batch_id(
            batch.scope_fingerprint,
            batch.path,
            batch.candidate_ids,
            context_ref.content_hash,
        ),
    )
    result = await bootstrap.propose_batch(identity, static, unavailable_batch)
    assert not isinstance(result, StageFailure)
    assert result.results["C-000"].status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert len(client.requests) == 2


@pytest.mark.asyncio
async def test_batch_hypothesis_ids_ignore_response_order(tmp_path: Path) -> None:
    first_rows: list[JsonValue] = [
        _row("C-000", "HYPOTHESES", hypotheses=[_hypothesis()]),
        _row("C-001", "HYPOTHESES", hypotheses=[_hypothesis()]),
    ]
    bootstrap, client, identity, static, batch, _ = _fixture(
        tmp_path, candidate_count=2, responses=[first_rows, list(reversed(first_rows))]
    )
    first = await bootstrap.propose_batch(identity, static, batch)
    second = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(first, StageFailure)
    assert not isinstance(second, StageFailure)
    assert {
        candidate_id: outcome.seeds[0].hypothesis_id
        for candidate_id, outcome in first.results.items()
    } == {
        candidate_id: outcome.seeds[0].hypothesis_id
        for candidate_id, outcome in second.results.items()
    }
    assert len(client.requests) == 2


@pytest.mark.asyncio
async def test_exhausted_repair_keeps_valid_sibling_and_names_missing_id(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, batch, _ = _fixture(
        tmp_path,
        candidate_count=2,
        responses=[
            [_row("C-000", "HYPOTHESES", hypotheses=[_hypothesis()])],
            [],
        ],
    )
    result = await bootstrap.propose_batch(identity, static, batch)
    assert not isinstance(result, StageFailure)
    assert tuple(result.results) == ("C-000",)
    assert len(result.results["C-000"].seeds) == 1
    assert result.missing_ids == ("C-001",)
    assert result.failure is not None
    assert result.failure.code == "HYPOTHESIS_BATCH_OUTPUT_INVALID"
    assert len(client.requests) == 2


@pytest.mark.asyncio
async def test_forged_batch_identity_is_rejected_before_llm(tmp_path: Path) -> None:
    bootstrap, client, identity, static, batch, _ = _fixture(
        tmp_path,
        candidate_count=1,
        responses=[[_row("C-000", "NO_HYPOTHESIS")]],
    )
    result = await bootstrap.propose_batch(
        identity, static, replace(batch, batch_id="f" * 64)
    )
    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_BATCH_CONTEXT_INVALID"
    assert client.requests == []


@pytest.mark.asyncio
async def test_resume_subset_keeps_full_batch_identity_but_requests_only_missing(
    tmp_path: Path,
) -> None:
    bootstrap, client, identity, static, batch, _ = _fixture(
        tmp_path,
        candidate_count=2,
        responses=[[_row("C-001", "NO_HYPOTHESIS")]],
    )
    result = await bootstrap.propose_batch(
        identity, static, batch, requested_ids=("C-001",)
    )
    assert not isinstance(result, StageFailure)
    assert tuple(result.results) == ("C-001",)
    owner = client.requests[0]["owner"]
    assert owner is not None
    assert owner.candidate_ids == ("C-001",)
    assert owner.batch_id == batch.batch_id
