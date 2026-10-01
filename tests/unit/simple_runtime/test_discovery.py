from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
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
    decision_evidence_refs: tuple[StoredDataRef, ...] = ()
    decision_attempt_ref: StoredDataRef | None = None


class _Store:
    def __init__(self, items: list[_Candidate]) -> None:
        self.items = {item.candidate_id: item for item in items}
        self.decisions: dict[str, str] = {
            item.candidate_id: item.decision
            for item in items
            if item.decision != "PENDING"
        }
        self.reasons: dict[str, str] = {}
        self.evidence_refs: dict[str, tuple[StoredDataRef, ...]] = {
            item.candidate_id: item.decision_evidence_refs for item in items
        }
        self.attempt_refs: dict[str, StoredDataRef | None] = {
            item.candidate_id: item.decision_attempt_ref for item in items
        }

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
            replace(
                item,
                decision=self.decisions.get(key, "PENDING"),
                decision_evidence_refs=self.evidence_refs.get(key, ()),
                decision_attempt_ref=self.attempt_refs.get(key),
            )
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
        evidence_refs: tuple[StoredDataRef, ...] = (),
        attempt_ref: StoredDataRef | None = None,
    ) -> None:
        self.decisions[candidate_id] = decision
        self.reasons[candidate_id] = reason
        self.evidence_refs[candidate_id] = evidence_refs
        self.attempt_refs[candidate_id] = attempt_ref

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
        fatal_refs: tuple[StoredDataRef, ...] = (),
    ) -> None:
        self.invalid_once = invalid_once
        self.invalid_failure_once = invalid_failure_once
        self.max_items = max_items
        self.budget = budget
        self.fatal_code = fatal_code
        self.fatal_refs = fatal_refs
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
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult | StageFailure:
        del output_schema, timeout_ms, owner, prompt_bytes, invocation_id
        assert agent_name == "discovery"
        self.calls.append(prompt)
        if self.fatal_code is not None:
            return StageFailure(
                code=self.fatal_code,
                retryable=False,
                safe_message="fatal",
                evidence_refs=self.fatal_refs,
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


def _ref(name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(name),
        data_kind="simple_runtime_artifact",
        content_hash="a" * 64,
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("a" * 40),
        record_id=None,
    )


@pytest.mark.asyncio
async def test_fatal_provider_failure_keeps_checkpoint_and_audit_refs() -> None:
    candidate_ref = _ref("candidate-source")
    request_ref = _ref("provider-request")
    diagnostic_ref = _ref("provider-diagnostic")
    store = _Store([_Candidate("candidate-1", evidence_ref=candidate_ref)])

    outcome = await CandidateDiscovery(
        store=store,
        artifacts=_Artifacts(),
        client=_Client(
            fatal_code="INVALID_CREDENTIAL",
            fatal_refs=(request_ref, diagnostic_ref),
        ),
    ).run(_identity(), "scope")

    assert outcome.status == "ERROR"
    assert outcome.error_code == "INVALID_CREDENTIAL"
    assert outcome.evidence_refs == (request_ref, diagnostic_ref)
    assert store.evidence_refs["candidate-1"] == (
        candidate_ref,
        request_ref,
        diagnostic_ref,
    )
    assert store.attempt_refs["candidate-1"] == diagnostic_ref


@pytest.mark.asyncio
async def test_recovered_provider_failure_keeps_failed_attempt_ref_in_decision() -> (
    None
):
    request_ref = _ref("provider-request")

    class RecoveringClient(_Client):
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
        ) -> SimpleLLMCallResult | StageFailure:
            if not self.calls:
                self.calls.append(prompt)
                return StageFailure(
                    code="TIMED_OUT",
                    retryable=True,
                    safe_message="timed out",
                    evidence_refs=(request_ref,),
                )
            return await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
                owner=owner,
                prompt_bytes=prompt_bytes,
                invocation_id=invocation_id,
            )

    store = _Store([_Candidate("candidate-1")])
    outcome = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=RecoveringClient()
    ).run(_identity(), "scope")

    assert outcome.status == "COMPLETE"
    assert store.decisions["candidate-1"] == "INCLUDE"
    assert request_ref in store.evidence_refs["candidate-1"]


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
async def test_resume_error_keeps_prior_decision_and_attempt_refs() -> None:
    source_ref = _ref("candidate-source")
    prior_diagnostic = _ref("prior-diagnostic")
    prior_attempt = _ref("prior-attempt")
    current_diagnostic = _ref("current-diagnostic")
    store = _Store(
        [
            _Candidate(
                "candidate-1",
                evidence_ref=source_ref,
                decision="ERROR",
                decision_evidence_refs=(source_ref, prior_diagnostic),
                decision_attempt_ref=prior_attempt,
            )
        ]
    )

    outcome = await CandidateDiscovery(
        store=store,
        artifacts=_Artifacts(),
        client=_Client(fatal_code="TIMED_OUT", fatal_refs=(current_diagnostic,)),
    ).run(_identity(), "scope", retry_errors=True)

    assert outcome.status == "ERROR"
    assert store.evidence_refs["candidate-1"] == (
        source_ref,
        prior_diagnostic,
        prior_attempt,
        current_diagnostic,
    )
    assert store.attempt_refs["candidate-1"] == current_diagnostic


@pytest.mark.asyncio
async def test_resume_success_keeps_prior_failure_refs() -> None:
    source_ref = _ref("candidate-source")
    prior_diagnostic = _ref("prior-diagnostic")
    prior_attempt = _ref("prior-attempt")
    store = _Store(
        [
            _Candidate(
                "candidate-1",
                evidence_ref=source_ref,
                decision="ERROR",
                decision_evidence_refs=(source_ref, prior_diagnostic),
                decision_attempt_ref=prior_attempt,
            )
        ]
    )

    outcome = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=_Client()
    ).run(_identity(), "scope", retry_errors=True)

    assert outcome.status == "COMPLETE"
    assert store.evidence_refs["candidate-1"] == (
        source_ref,
        prior_diagnostic,
        prior_attempt,
    )
    assert store.attempt_refs["candidate-1"] == prior_attempt


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
async def test_schema_requires_exact_batch_ids_and_decision_count() -> None:
    class CapturingClient(_Client):
        def __init__(self) -> None:
            super().__init__()
            self.schemas: list[Mapping[str, Any]] = []

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
        ) -> SimpleLLMCallResult | StageFailure:
            self.schemas.append(output_schema)
            return await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
                owner=owner,
                prompt_bytes=prompt_bytes,
                invocation_id=invocation_id,
            )

    client = CapturingClient()
    outcome = await CandidateDiscovery(
        store=_Store([_Candidate("candidate-a"), _Candidate("candidate-b")]),
        artifacts=_Artifacts(),
        client=client,
    ).run(_identity(), "scope")

    assert outcome.status == "COMPLETE"
    decisions = client.schemas[0]["properties"]["decisions"]
    assert decisions["minItems"] == decisions["maxItems"] == 2
    assert decisions["items"]["properties"]["candidate_id"]["enum"] == [
        "candidate-a",
        "candidate-b",
    ]


@pytest.mark.asyncio
async def test_exhausted_invalid_batch_splits_and_isolates_bad_singleton() -> None:
    class MalformedIdClient(_Client):
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
        ) -> SimpleLLMCallResult | StageFailure:
            result = await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
                owner=owner,
                prompt_bytes=prompt_bytes,
                invocation_id=invocation_id,
            )
            assert isinstance(result, SimpleLLMCallResult)
            rows = result.value["decisions"]
            assert isinstance(rows, list)
            first_row = rows[0]
            assert isinstance(first_row, dict)
            if len(rows) > 1 or first_row["candidate_id"] == "candidate-bad":
                first_row["candidate_id"] = "malformed-id"
            return result

    store = _Store([_Candidate("candidate-bad"), _Candidate("candidate-good")])
    client = MalformedIdClient()
    outcome = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=client, batch_size=2
    ).run(_identity(), "scope")

    assert outcome.status == "ERROR"
    assert outcome.counts["ERROR"] == 1
    assert outcome.counts["INCLUDE"] == 1
    assert store.decisions == {
        "candidate-bad": "ERROR",
        "candidate-good": "INCLUDE",
    }
    assert client.batch_sizes == [2, 2, 2, 1, 1, 1, 1]


@pytest.mark.asyncio
async def test_provider_invalid_output_splits_and_isolates_bad_singleton() -> None:
    failure_ref = _ref("invalid-output-diagnostic")

    class InvalidOutputClient(_Client):
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
        ) -> SimpleLLMCallResult | StageFailure:
            result = await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
                owner=owner,
                prompt_bytes=prompt_bytes,
                invocation_id=invocation_id,
            )
            rows = json.loads(
                prompt.split(b"<CANDIDATES>")[1].split(b"</CANDIDATES>")[0]
            )
            if len(rows) > 1 or rows[0]["candidate_id"] == "candidate-bad":
                return StageFailure(
                    code="INVALID_OUTPUT",
                    retryable=False,
                    safe_message="schema mismatch",
                    evidence_refs=(failure_ref,),
                )
            return result

    store = _Store([_Candidate("candidate-bad"), _Candidate("candidate-good")])
    client = InvalidOutputClient()
    outcome = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=client, batch_size=2
    ).run(_identity(), "scope")

    assert outcome.status == "ERROR"
    assert store.decisions == {
        "candidate-bad": "ERROR",
        "candidate-good": "INCLUDE",
    }
    assert failure_ref in outcome.evidence_refs
    assert failure_ref in store.evidence_refs["candidate-bad"]
    assert failure_ref in store.evidence_refs["candidate-good"]
    assert store.attempt_refs["candidate-bad"] == failure_ref
    assert client.batch_sizes == [2, 2, 2, 1, 1, 1, 1]


@pytest.mark.asyncio
async def test_timeout_then_invalid_output_splits_without_stale_failure() -> None:
    class MixedFailureClient(_Client):
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
        ) -> SimpleLLMCallResult | StageFailure:
            result = await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
                owner=owner,
                prompt_bytes=prompt_bytes,
                invocation_id=invocation_id,
            )
            rows = json.loads(
                prompt.split(b"<CANDIDATES>")[1].split(b"</CANDIDATES>")[0]
            )
            if len(rows) > 1 and self.batch_sizes.count(2) == 1:
                return StageFailure(
                    code="TIMED_OUT", retryable=True, safe_message="timeout"
                )
            if len(rows) > 1 or rows[0]["candidate_id"] == "candidate-bad":
                return StageFailure(
                    code="INVALID_OUTPUT",
                    retryable=False,
                    safe_message="schema mismatch",
                )
            return result

    store = _Store([_Candidate("candidate-bad"), _Candidate("candidate-good")])
    client = MixedFailureClient()
    outcome = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=client, batch_size=2
    ).run(_identity(), "scope")

    assert outcome.status == "ERROR"
    assert outcome.error_code == "DISCOVERY_CANDIDATE_ERROR"
    assert store.decisions == {
        "candidate-bad": "ERROR",
        "candidate-good": "INCLUDE",
    }
    assert client.batch_sizes == [2, 2, 2, 1, 1, 1, 1]


@pytest.mark.asyncio
async def test_resume_retries_only_isolated_error_without_duplicate_decision() -> None:
    class MalformedOnce(_Client):
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
        ) -> SimpleLLMCallResult | StageFailure:
            result = await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
                owner=owner,
                prompt_bytes=prompt_bytes,
                invocation_id=invocation_id,
            )
            assert isinstance(result, SimpleLLMCallResult)
            rows = result.value["decisions"]
            assert isinstance(rows, list)
            first_row = rows[0]
            assert isinstance(first_row, dict)
            if len(rows) > 1 or first_row["candidate_id"] == "candidate-bad":
                first_row["candidate_id"] = "malformed-id"
            return result

    store = _Store([_Candidate("candidate-bad"), _Candidate("candidate-good")])
    first = await CandidateDiscovery(
        store=store, artifacts=_Artifacts(), client=MalformedOnce(), batch_size=2
    ).run(_identity(), "scope")
    assert first.counts["ERROR"] == 1
    assert first.counts["INCLUDE"] == 1

    artifacts = _Artifacts()
    client = _Client()
    resumed = await CandidateDiscovery(
        store=store, artifacts=artifacts, client=client, batch_size=2
    ).run(_identity(), "scope", retry_errors=True)

    assert resumed.status == "COMPLETE"
    assert resumed.counts["INCLUDE"] == 2
    assert client.batch_sizes == [1]
    assert (
        sum(
            isinstance(value, dict) and value.get("kind") == "simple_discovery_decision"
            for value in artifacts.values
        )
        == 1
    )


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
