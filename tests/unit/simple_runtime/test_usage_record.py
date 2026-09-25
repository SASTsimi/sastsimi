from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.call_queue import RunUsageBudget
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def test_usage_summary_is_durable_idempotent_and_preserves_unknown_cost(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-usage",
        workspace_id="workspace-usage",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    ref = artifacts.put_json({"kind": "attempt"})
    for attempt_id, tokens, cost in (
        ("attempt-1", 100, 75.0),
        ("attempt-2", 310, 50.0),
        ("attempt-3", None, None),
    ):
        store.record_llm_attempt(
            attempt_id=attempt_id,
            analysis_id=identity.analysis_id,
            agent="hypothesis",
            model="test-model",
            attempt_number=1,
            status="SUCCEEDED",
            elapsed_ms=100,
            input_tokens=tokens,
            output_tokens=0,
            cost_cents=cost,
            artifact_ref=ref,
        )
    store.record_llm_attempt(
        attempt_id="attempt-1",
        analysis_id=identity.analysis_id,
        agent="hypothesis",
        model="test-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=100,
        input_tokens=100,
        output_tokens=0,
        cost_cents=75.0,
        artifact_ref=ref,
    )

    summary = SimpleCheckpointStore(store.database_path).usage_summary(
        identity.analysis_id
    )
    assert summary == {
        "calls": 3,
        "input_tokens": 410,
        "output_tokens": 0,
        "cost_minor_units": 125.0,
        "unknown_cost_calls": 1,
    }
    with pytest.raises(ValueError, match="LLM_ATTEMPT_CONFLICT"):
        store.record_llm_attempt(
            attempt_id="attempt-1",
            analysis_id=identity.analysis_id,
            agent="hypothesis",
            model="test-model",
            attempt_number=1,
            status="FAILED",
            elapsed_ms=100,
            input_tokens=100,
            output_tokens=0,
            cost_cents=75.0,
            artifact_ref=ref,
        )


def test_known_usage_ceiling_blocks_next_call(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-budget",
        workspace_id="workspace-budget",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    ref = artifacts.put_json({"kind": "attempt"})
    store.record_llm_attempt(
        attempt_id="charged",
        analysis_id=identity.analysis_id,
        agent="hypothesis",
        model="test",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=100,
        input_tokens=90,
        output_tokens=20,
        cost_cents=10.0,
        artifact_ref=ref,
    )
    budget = RunUsageBudget(
        store=store,
        analysis_id=identity.analysis_id,
        max_tokens=100,
        max_cost_minor_units=100,
        max_elapsed_seconds=3600,
    )
    failure = budget.check()
    assert failure is not None
    assert failure.code == "LLM_TOKEN_BUDGET_EXHAUSTED"
