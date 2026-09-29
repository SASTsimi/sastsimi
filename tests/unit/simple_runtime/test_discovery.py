from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest

from sastsimi.simple_runtime.discovery import CandidateDiscovery
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult


@dataclass(frozen=True)
class _Origin:
    engine: str = "opengrep"
    rule_id: str = "rule"
    result_index: int = 0


@dataclass(frozen=True)
class _Candidate:
    candidate_id: str
    kind: str = "HINT"
    path: str = "app.py"
    line: int = 1
    end_line: int = 1
    summary: str = "untrusted input"
    evidence_excerpt: str = "request.args"
    flow_trace: tuple[str, ...] | dict[str, str | int] = ()
    origins: tuple[_Origin, ...] = (_Origin(),)
    evidence_ref: Any = None
    decision: str = "PENDING"


class _Store:
    def __init__(self, items: list[_Candidate]) -> None:
        self.items = {item.candidate_id: item for item in items}
        self.decisions: dict[str, str] = {}
        self.reasons: dict[str, str] = {}

    def list_candidates(
        self,
        _identity: object,
        _scope: str,
        *,
        status: str = "PENDING",
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[_Candidate, ...]:
        return tuple(
            item
            for key, item in sorted(self.items.items())
            if self.decisions.get(key, "PENDING") == status
            and (after_id is None or key > after_id)
        )[:limit]

    def save_candidate_decision(
        self,
        _identity: object,
        _scope: str,
        candidate_id: str,
        decision: str,
        reason: str,
        evidence_refs: tuple[object, ...] = (),
        attempt_ref: object = None,
    ) -> None:
        del evidence_refs, attempt_ref
        self.decisions[candidate_id] = decision
        self.reasons[candidate_id] = reason

    def candidate_counts(self, _identity: object, _scope: str) -> dict[str, int]:
        out = {
            key: 0 for key in ("PENDING", "INCLUDE", "EXCLUDE", "UNDECIDED", "ERROR")
        }
        for key in self.items:
            out[self.decisions.get(key, "PENDING")] += 1
        return out


@pytest.mark.asyncio
async def test_fatal_provider_failure_stops_after_first_batch() -> None:
    store = _Store([_Candidate(f"candidate-{i:02d}") for i in range(16)])
    client = _Client(fatal_code="AUTH_REQUIRED")
    outcome = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=client, batch_size=8
    ).run(_identity(), "scope")

    assert outcome.status == "ERROR"
    assert outcome.error_code == "AUTH_REQUIRED"
    assert outcome.counts["ERROR"] == 8
    assert outcome.counts["PENDING"] == 8
    assert len(client.calls) == 1


class _Artifacts:
    def __init__(self) -> None:
        self.values: list[object] = []

    def put_json(self, value: object) -> None:
        self.values.append(value)
        return None


class _Client:
    def __init__(
        self,
        *,
        invalid_once: bool = False,
        invalid_failure_once: bool = False,
        max_items: int = 10,
        budget: bool = False,
        fatal_code: str | None = None,
    ) -> None:
        self.invalid_once = invalid_once
        self.invalid_failure_once = invalid_failure_once
        self.max_items = max_items
        self.budget = budget
        self.fatal_code = fatal_code
        self.calls: list[bytes] = []
        self.batch_sizes: list[int] = []

    def budget_failure(self) -> StageFailure | None:
        if self.budget:
            return StageFailure(
                code="LLM_TOKEN_BUDGET_EXHAUSTED",
                retryable=False,
                safe_message="budget",
            )
        return None

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult | StageFailure:
        del output_schema, timeout_ms
        assert agent_name == "discovery"
        self.calls.append(prompt)
        if self.fatal_code is not None:
            return StageFailure(
                code=self.fatal_code, retryable=False, safe_message="fatal"
            )
        rows = json.loads(prompt.split(b"<CANDIDATES>")[1].split(b"</CANDIDATES>")[0])
        self.batch_sizes.append(len(rows))
        if len(rows) > self.max_items:
            return StageFailure(
                code="CONTEXT_LIMIT_EXCEEDED",
                retryable=False,
                safe_message="context",
            )
        if self.invalid_once and len(self.calls) == 1:
            return _result({"decisions": [{"candidate_id": "wrong"}]})
        if self.invalid_failure_once and len(self.calls) == 1:
            return StageFailure(
                code="INVALID_OUTPUT", retryable=False, safe_message="invalid JSON"
            )
        return _result(
            {
                "decisions": [
                    {
                        "candidate_id": row["candidate_id"],
                        "status": "INCLUDE",
                        "reason": "input reaches a sensitive operation",
                        "evidence": "request.args",
                    }
                    for row in rows
                ]
            }
        )


def _result(value: dict[str, Any]) -> SimpleLLMCallResult:
    return SimpleLLMCallResult(
        value=value, prompt_digest="a" * 64, output_digest="b" * 64
    )


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


@pytest.mark.asyncio
async def test_reviews_all_six_hundred_candidates_in_bounded_batches() -> None:
    store = _Store([_Candidate(f"candidate-{i:04d}") for i in range(600)])
    client = _Client()
    outcome = await CandidateDiscovery(
        store=store,
        artifacts=_Artifacts(),
        client=client,
        batch_size=8,
    ).run(_identity(), "scope")

    assert outcome.status == "COMPLETE"
    assert outcome.counts["INCLUDE"] == 600
    assert outcome.counts["PENDING"] == 0
    assert len(client.calls) == 75
    assert max(client.batch_sizes) == 8


@pytest.mark.asyncio
async def test_resume_retries_prior_error_once_without_looping() -> None:
    store = _Store([_Candidate("candidate-1")])
    first = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=_Client(max_items=0)
    ).run(_identity(), "scope")
    assert first.status == "ERROR"
    assert store.decisions["candidate-1"] == "ERROR"

    second = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=_Client()
    ).run(_identity(), "scope", retry_errors=True)
    assert second.status == "COMPLETE"
    assert store.decisions["candidate-1"] == "INCLUDE"


@pytest.mark.asyncio
async def test_invalid_ids_retry_with_schema_and_error() -> None:
    store = _Store([_Candidate("candidate-1")])
    client = _Client(invalid_once=True)
    outcome = await CandidateDiscovery(
        store=store,
        artifacts=_Artifacts(),
        client=client,
        batch_size=8,
    ).run(_identity(), "scope")

    assert outcome.status == "COMPLETE"
    assert store.decisions["candidate-1"] == "INCLUDE"
    assert len(client.calls) == 2
    assert b"<VALIDATION_ERROR>" in client.calls[1]
    assert b"<REQUIRED_SCHEMA>" in client.calls[1]


@pytest.mark.asyncio
async def test_provider_invalid_json_gets_bounded_schema_retry() -> None:
    store = _Store([_Candidate("candidate-1")])
    client = _Client(invalid_failure_once=True)
    outcome = await CandidateDiscovery(
        store=store,
        artifacts=_Artifacts(),
        client=client,
    ).run(_identity(), "scope")

    assert outcome.status == "COMPLETE"
    assert len(client.calls) == 2
    assert b"<VALIDATION_ERROR>" in client.calls[1]


@pytest.mark.asyncio
async def test_context_limit_splits_without_dropping_candidates() -> None:
    store = _Store([_Candidate(f"candidate-{i}") for i in range(4)])
    client = _Client(max_items=2)
    outcome = await CandidateDiscovery(
        store=store,
        artifacts=_Artifacts(),
        client=client,
        batch_size=4,
    ).run(_identity(), "scope")

    assert outcome.status == "COMPLETE"
    assert outcome.counts["INCLUDE"] == 4
    assert client.batch_sizes == [4, 2, 2]


@pytest.mark.asyncio
async def test_unchanged_exhausted_budget_keeps_candidates_pending_without_call() -> (
    None
):
    store = _Store([_Candidate("candidate-1")])
    client = _Client(budget=True)
    reviewer = CandidateDiscovery(
        store=store,
        artifacts=_Artifacts(),
        client=client,
    )
    first = await reviewer.run(_identity(), "scope")
    second = await reviewer.run(_identity(), "scope")

    assert first.status == second.status == "PAUSED"
    assert first.error_code == "LLM_TOKEN_BUDGET_EXHAUSTED"
    assert store.candidate_counts(_identity(), "scope")["PENDING"] == 1
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_code", ["LLM_COST_USAGE_UNAVAILABLE", "LLM_TOKEN_USAGE_UNAVAILABLE"]
)
@pytest.mark.parametrize("failure_source", ["precheck", "call"])
async def test_unmeasured_usage_pauses_without_turning_candidates_into_errors(
    failure_code: str, failure_source: str
) -> None:
    class UnmeasuredClient(_Client):
        def budget_failure(self) -> StageFailure | None:
            if failure_source == "precheck" or self.calls:
                return StageFailure(
                    code=failure_code,
                    retryable=False,
                    safe_message="usage unavailable",
                )
            return None

    store = _Store([_Candidate("candidate-1")])
    client = UnmeasuredClient(
        fatal_code=failure_code if failure_source == "call" else None
    )
    reviewer = CandidateDiscovery(store=store, artifacts=_Artifacts(), client=client)

    first = await reviewer.run(_identity(), "scope")
    resumed = await reviewer.run(_identity(), "scope")

    assert first.status == resumed.status == "PAUSED"
    assert first.error_code == resumed.error_code == failure_code
    assert first.counts["PENDING"] == resumed.counts["PENDING"] == 1
    assert first.counts["ERROR"] == resumed.counts["ERROR"] == 0
    assert len(client.calls) == (0 if failure_source == "precheck" else 1)


@pytest.mark.asyncio
async def test_oversized_single_candidate_is_error_and_next_candidate_runs() -> None:
    store = _Store(
        [
            _Candidate("candidate-1", evidence_excerpt="x" * 4000),
            _Candidate("candidate-2"),
        ]
    )
    client = _Client()
    outcome = await CandidateDiscovery(
        store=store,
        artifacts=_Artifacts(),
        client=client,
        batch_size=2,
        max_prompt_bytes=1000,
    ).run(_identity(), "scope")

    assert outcome.status == "ERROR"
    assert store.decisions == {"candidate-1": "ERROR", "candidate-2": "INCLUDE"}
    assert outcome.counts["PENDING"] == 0


@pytest.mark.asyncio
async def test_discovery_redacts_candidate_evidence_before_provider_call() -> None:
    secret = "sk-abcdefgh12345678"
    candidate = _Candidate(
        "candidate-1",
        evidence_excerpt=f"api_key={secret}",
        flow_trace={"access_token": secret, "path": "app.py", "line": 1},
    )
    store = _Store([candidate])
    client = _Client()

    outcome = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=client
    ).run(_identity(), "scope")

    assert outcome.status == "COMPLETE"
    assert len(client.calls) == 1
    assert secret.encode() not in client.calls[0]
    rows = json.loads(
        client.calls[0].split(b"<CANDIDATES>", 1)[1].split(b"</CANDIDATES>", 1)[0]
    )
    assert rows[0]["evidence_excerpt"] == "[REDACTED:CREDENTIAL]"
    assert rows[0]["flow_trace"]["access_token"] == "[REDACTED:CREDENTIAL]"
    assert (rows[0]["path"], rows[0]["line"]) == ("app.py", 1)
    assert store.items[candidate.candidate_id] == candidate


@pytest.mark.asyncio
async def test_discovery_redaction_failure_is_durable_without_provider_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_redaction(_data: bytes) -> None:
        raise ValueError("PROMPT_REDACTION_FAILED")

    monkeypatch.setattr(
        "sastsimi.simple_runtime.discovery.redact_projected_json",
        fail_redaction,
        raising=False,
    )
    store = _Store([_Candidate("candidate-1")])
    client = _Client()

    outcome = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=client
    ).run(_identity(), "scope")

    assert outcome.status == "ERROR"
    assert outcome.error_code == "DISCOVERY_INPUT_REDACTION_FAILED"
    assert store.decisions == {"candidate-1": "ERROR"}
    assert client.calls == []
