"""Safety gates for bounded hypothesis scheduling and billable calls."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.call_queue import (
    RunLimitedClient,
    effective_hypothesis_concurrency,
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult, SimpleOpenAIClient
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-concurrency",
        workspace_id="workspace-concurrency",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


def _client(
    tmp_path: Path,
    inner: SimpleOpenAIClient,
    *,
    max_tokens: int = 1000,
    max_cost_minor_units: int = 1000,
) -> RunLimitedClient:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    return RunLimitedClient(
        inner=inner,
        semaphore=asyncio.Semaphore(4),
        artifacts=artifacts,
        store=SimpleCheckpointStore(artifacts.paths.database),
        model="test-model",
        max_retries=0,
        max_tokens=max_tokens,
        max_cost_minor_units=max_cost_minor_units,
        max_elapsed_seconds=3600,
    )


def _owned(child_id: str) -> AttemptOwner:
    return AttemptOwner(
        analysis_id="analysis-concurrency",
        stage="PRO_CON_DONE",
        hypothesis_id=child_id,
    )


def _priced() -> SimpleLLMCallResult:
    return SimpleLLMCallResult(
        value={"ok": True},
        prompt_digest="a" * 64,
        output_digest="b" * 64,
        input_tokens=5,
        output_tokens=2,
        cost_minor_units=7,
    )


class _PricedAPI(SimpleOpenAIClient):
    def __init__(self) -> None:
        super().__init__(credential_ref="env:NOT_USED", model="test-model")
        self.calls = 0
        self.active = 0
        self.peak = 0

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
        del prompt, output_schema, timeout_ms, agent_name, owner, prompt_bytes
        del invocation_id
        self.calls += 1
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(0.02)
            return _priced()
        finally:
            self.active -= 1


@pytest.mark.parametrize("provider", ["codex", "codex-cli", "claude", "cursor"])
def test_cli_providers_stay_serial_even_with_safety_claims(provider: str) -> None:
    assert (
        effective_hypothesis_concurrency(
            provider,
            4,
            atomic_budget_reservations=True,
            exact_child_claims=True,
        )
        == 1
    )


def test_api_requires_both_explicit_safety_guarantees() -> None:
    assert effective_hypothesis_concurrency("openai", 4) == 1
    assert (
        effective_hypothesis_concurrency("openai", 4, atomic_budget_reservations=True)
        == 1
    )
    assert effective_hypothesis_concurrency("openai", 4, exact_child_claims=True) == 1
    assert (
        effective_hypothesis_concurrency(
            "openai-api",
            4,
            atomic_budget_reservations=True,
            exact_child_claims=True,
        )
        == 4
    )


@pytest.mark.parametrize("configured", [0, 33, True, 1.5])
def test_concurrency_rejects_invalid_configured_bound(configured: Any) -> None:
    with pytest.raises(ValueError, match="HYPOTHESIS_CONCURRENCY_INVALID"):
        effective_hypothesis_concurrency("openai", configured)


@pytest.mark.asyncio
async def test_atomic_claim_prevents_duplicate_child(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "claims.sqlite3")
    identity = _identity()
    results = await asyncio.gather(
        *(
            asyncio.to_thread(store.claim_hypothesis, identity, "H-1", f"turn-{i}")
            for i in range(8)
        )
    )
    assert sum(results) == 1


@pytest.mark.asyncio
async def test_api_queue_serializes_budget_check_and_owned_attempt(
    tmp_path: Path,
) -> None:
    inner = _PricedAPI()
    clients = [
        _client(tmp_path, inner, max_tokens=7, max_cost_minor_units=7) for _ in range(2)
    ]

    results = await asyncio.gather(
        *(
            client.call(
                prompt=b"safe",
                output_schema={},
                timeout_ms=1000,
                owner=_owned(f"H-{index}"),
            )
            for index, client in enumerate(clients)
        )
    )

    assert inner.calls == inner.peak == 1
    assert sum(isinstance(result, SimpleLLMCallResult) for result in results) == 1
    assert sum(isinstance(result, StageFailure) for result in results) == 1
    with sqlite3.connect(clients[0]._store.database_path) as connection:
        rows = connection.execute(
            "SELECT a.status, m.analysis_id, m.stage, m.hypothesis_id "
            "FROM simple_llm_attempts AS a "
            "JOIN simple_llm_attempt_metadata AS m ON m.attempt_id = a.attempt_id"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0] in {
        ("SUCCEEDED", "analysis-concurrency", "PRO_CON_DONE", "H-0"),
        ("SUCCEEDED", "analysis-concurrency", "PRO_CON_DONE", "H-1"),
    }


@pytest.mark.asyncio
async def test_api_cancellation_records_owned_unknown_usage_and_blocks_retry(
    tmp_path: Path,
) -> None:
    entered = asyncio.Event()

    class HangingAPI(_PricedAPI):
        async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
            del kwargs
            self.calls += 1
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    inner = HangingAPI()
    client = _client(tmp_path, inner)
    task = asyncio.create_task(
        client.call(
            prompt=b"safe",
            output_schema={},
            timeout_ms=5000,
            owner=_owned("H-cancelled"),
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    blocked = await client.call(
        prompt=b"safe",
        output_schema={},
        timeout_ms=1000,
        owner=_owned("H-next"),
    )
    assert isinstance(blocked, StageFailure)
    assert blocked.code == "LLM_TOKEN_USAGE_UNAVAILABLE"
    assert inner.calls == 1
    with sqlite3.connect(client._store.database_path) as connection:
        rows = connection.execute(
            "SELECT a.status, m.analysis_id, m.stage, m.hypothesis_id "
            "FROM simple_llm_attempts AS a "
            "JOIN simple_llm_attempt_metadata AS m ON m.attempt_id = a.attempt_id"
        ).fetchall()
    assert rows == [
        ("CANCELLED", "analysis-concurrency", "PRO_CON_DONE", "H-cancelled")
    ]


@pytest.mark.asyncio
async def test_mismatched_owner_is_rejected_before_billable_api_call(
    tmp_path: Path,
) -> None:
    inner = _PricedAPI()
    client = _client(tmp_path, inner)
    other_owner = AttemptOwner(
        analysis_id="different-analysis",
        stage="PRO_CON_DONE",
        hypothesis_id="H-wrong",
    )

    with pytest.raises(ValueError, match="LLM_ATTEMPT_OWNER_INVALID"):
        await client.call(
            prompt=b"safe",
            output_schema={},
            timeout_ms=1000,
            owner=other_owner,
        )

    assert inner.calls == 0
    assert client._store.usage_summary("analysis-concurrency")["calls"] == 0
