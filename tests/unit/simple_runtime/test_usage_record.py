from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.call_queue import RunUsageBudget
from sastsimi.simple_runtime.models import CheckpointIdentity, SimpleAnalysisRun
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
        "unknown_token_calls": 1,
        "unlinked_codex_usage_calls": 0,
        "unrecorded_in_flight_codex_calls": 0,
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


def test_attempt_owner_survives_retry_and_legacy_migration(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="owned-attempts",
        workspace_id="workspace-owned",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    ref = artifacts.put_json({"kind": "attempt"})

    def record(
        attempt_id: str,
        *,
        owner: AttemptOwner | None = None,
        retry_of: str | None = None,
        prompt_bytes: PromptByteCounts | None = None,
    ) -> None:
        store.record_llm_attempt(
            attempt_id=attempt_id,
            analysis_id=identity.analysis_id,
            agent="discovery",
            model="fake-model",
            attempt_number=1,
            status="FAILED",
            elapsed_ms=12,
            input_tokens=None,
            output_tokens=None,
            cost_cents=None,
            artifact_ref=ref,
            owner=owner,
            retry_of=retry_of,
            prompt_bytes=prompt_bytes,
        )

    record("legacy")
    owner = AttemptOwner(
        analysis_id=identity.analysis_id,
        stage="DISCOVERY",
        candidate_ids=("C-1",),
        file_path="app/main.py",
        batch_id="batch-1",
    )
    bytes_used = PromptByteCounts(
        raw_source_bytes=3,
        shared_context_bytes=5,
        candidate_specific_bytes=7,
        fixed_prompt_bytes=11,
    )
    record("first", owner=owner, prompt_bytes=bytes_used)
    record("retry", owner=owner, retry_of="first")
    record("first", owner=owner, prompt_bytes=bytes_used)

    with sqlite3.connect(store.database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT a.attempt_id, m.stage, m.candidate_ids_json, m.file_path, "
            "m.batch_id, m.retry_of, m.raw_source_bytes, m.shared_context_bytes, "
            "m.candidate_specific_bytes, m.fixed_prompt_bytes "
            "FROM simple_llm_attempts AS a LEFT JOIN simple_llm_attempt_metadata AS m "
            "ON m.attempt_id = a.attempt_id WHERE a.analysis_id = ? "
            "ORDER BY a.attempt_id",
            (identity.analysis_id,),
        ).fetchall()
    by_id = {row["attempt_id"]: row for row in rows}
    assert by_id["legacy"]["stage"] is None
    assert by_id["first"]["stage"] == "DISCOVERY"
    assert by_id["first"]["candidate_ids_json"] == '["C-1"]'
    assert by_id["first"]["file_path"] == "app/main.py"
    assert by_id["first"]["batch_id"] == "batch-1"
    assert by_id["first"]["raw_source_bytes"] == 3
    assert by_id["first"]["shared_context_bytes"] == 5
    assert by_id["first"]["candidate_specific_bytes"] == 7
    assert by_id["first"]["fixed_prompt_bytes"] == 11
    assert by_id["retry"]["retry_of"] == "first"
    assert len(rows) == 3


def test_usage_summary_reads_legacy_attempt_table_without_codex_tables(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="legacy-usage",
        workspace_id="legacy-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    store.record_llm_attempt(
        attempt_id="legacy-attempt",
        analysis_id=identity.analysis_id,
        agent="hypothesis",
        model="legacy-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=100,
        input_tokens=3,
        output_tokens=2,
        cost_cents=1.0,
        artifact_ref=artifacts.put_json({"kind": "attempt"}),
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TABLE simple_codex_calls")
        connection.execute("DROP TABLE agent_activity_events")
        connection.row_factory = sqlite3.Row
        summary = SimpleCheckpointStore.usage_summary_from_connection(
            connection, identity.analysis_id
        )

    assert summary == {
        "calls": 1,
        "input_tokens": 3,
        "output_tokens": 2,
        "cost_minor_units": 1.0,
        "unknown_cost_calls": 0,
        "unknown_token_calls": 0,
        "unlinked_codex_usage_calls": 0,
        "unrecorded_in_flight_codex_calls": 0,
    }


def test_unrecorded_in_flight_codex_call_counts_as_possible_usage_once(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-in-flight-usage",
        workspace_id="workspace-in-flight-usage",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    assert store.begin_codex_call("unrecorded-call", identity.analysis_id)

    pending = store.usage_summary(identity.analysis_id)
    assert pending == {
        "calls": 1,
        "input_tokens": 0,
        "output_tokens": 0,
        "cost_minor_units": None,
        "unknown_cost_calls": 1,
        "unknown_token_calls": 1,
        "unlinked_codex_usage_calls": 1,
        "unrecorded_in_flight_codex_calls": 1,
    }
    finite = RunUsageBudget(
        store=store,
        analysis_id=identity.analysis_id,
        max_tokens=100,
        max_cost_minor_units=100,
        max_elapsed_seconds=3600,
    )
    assert (failure := finite.check()) is not None
    assert failure.code == "LLM_TOKEN_USAGE_UNAVAILABLE"

    store.record_llm_attempt(
        attempt_id="unrecorded-call",
        analysis_id=identity.analysis_id,
        agent="hypothesis",
        model="codex",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=50,
        input_tokens=5,
        output_tokens=2,
        cost_cents=1.0,
        artifact_ref=artifacts.put_json({"kind": "attempt"}),
    )
    linked = store.usage_summary(identity.analysis_id)
    assert linked["calls"] == 1
    assert linked["input_tokens"] == 5
    assert linked["output_tokens"] == 2
    assert linked["cost_minor_units"] == 1.0
    assert linked["unknown_cost_calls"] == 0
    assert linked["unknown_token_calls"] == 0
    assert linked["unlinked_codex_usage_calls"] == 0
    assert linked["unrecorded_in_flight_codex_calls"] == 0


def test_confirming_unrecorded_codex_call_does_not_double_count_usage(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-confirmed-usage",
        workspace_id="workspace-confirmed-usage",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    store = SimpleCheckpointStore(
        SimpleArtifactRepository(tmp_path, identity).paths.database
    )
    assert store.begin_codex_call("same-call", identity.analysis_id)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_codex_calls SET status = 'CONFIRMED', "
            "resolved_at = ?, confirmation_ref_json = ? "
            "WHERE call_id = ? AND analysis_id = ?",
            (
                datetime.now(UTC).isoformat(),
                '{"confirmation":"recorded"}',
                "same-call",
                identity.analysis_id,
            ),
        )

    confirmed = store.usage_summary(identity.analysis_id)
    assert confirmed["calls"] == 1
    assert confirmed["unknown_token_calls"] == 1
    assert confirmed["unknown_cost_calls"] == 1
    assert confirmed["unlinked_codex_usage_calls"] == 1
    assert confirmed["unrecorded_in_flight_codex_calls"] == 0


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


def test_unlimited_token_budget_keeps_ledger_and_cost_ceiling(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-unlimited-tokens",
        workspace_id="workspace-unlimited-tokens",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    ref = artifacts.put_json({"kind": "attempt"})
    store.record_llm_attempt(
        attempt_id="large",
        analysis_id=identity.analysis_id,
        agent="hypothesis",
        model="test",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=100,
        input_tokens=1_500_000,
        output_tokens=20,
        cost_cents=9.0,
        artifact_ref=ref,
    )
    store.record_llm_attempt(
        attempt_id="unmeasured",
        analysis_id=identity.analysis_id,
        agent="hypothesis",
        model="test",
        attempt_number=2,
        status="TIMED_OUT",
        elapsed_ms=100,
        input_tokens=None,
        output_tokens=None,
        cost_cents=None,
        artifact_ref=ref,
    )
    unlimited = RunUsageBudget(
        store=store,
        analysis_id=identity.analysis_id,
        max_tokens="unlimited",
        max_cost_minor_units=10,
        max_elapsed_seconds="unlimited",
    )
    assert unlimited.check() is None
    assert store.usage_summary(identity.analysis_id)["input_tokens"] == 1_500_000
    cost_limited = RunUsageBudget(
        store=store,
        analysis_id=identity.analysis_id,
        max_tokens="unlimited",
        max_cost_minor_units=9,
        max_elapsed_seconds="unlimited",
    )
    assert (failure := cost_limited.check()) is not None
    assert failure.code == "LLM_COST_BUDGET_EXHAUSTED"


def test_unlimited_elapsed_budget_keeps_cost_ceiling(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-unlimited",
        workspace_id="workspace-unlimited",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    ref = artifacts.put_json({"kind": "attempt"})
    store.record_llm_attempt(
        attempt_id="slow",
        analysis_id=identity.analysis_id,
        agent="hypothesis",
        model="test",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=3_700_000,
        input_tokens=1,
        output_tokens=1,
        cost_cents=9.0,
        artifact_ref=ref,
    )
    budget = RunUsageBudget(
        store=store,
        analysis_id=identity.analysis_id,
        max_tokens=100,
        max_cost_minor_units=10,
        max_elapsed_seconds="unlimited",
    )
    assert budget.check() is None
    limited = RunUsageBudget(
        store=store,
        analysis_id=identity.analysis_id,
        max_tokens=100,
        max_cost_minor_units=9,
        max_elapsed_seconds="unlimited",
    )
    assert (failure := limited.check()) is not None
    assert failure.code == "LLM_COST_BUDGET_EXHAUSTED"


def test_elapsed_budget_uses_durable_llm_attempt_time_not_analysis_age(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-elapsed",
        workspace_id="workspace-elapsed",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            started_at=datetime.now(UTC) - timedelta(days=7),
        )
    )
    ref = artifacts.put_json({"kind": "attempt"})
    store.record_llm_attempt(
        attempt_id="first",
        analysis_id=identity.analysis_id,
        agent="hypothesis",
        model="test",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=499,
        input_tokens=0,
        output_tokens=0,
        cost_cents=None,
        artifact_ref=ref,
    )
    reopened = SimpleCheckpointStore(store.database_path)
    budget = RunUsageBudget(
        store=reopened,
        analysis_id=identity.analysis_id,
        max_tokens=100,
        max_cost_minor_units=100,
        max_elapsed_seconds=1,
    )
    assert budget.check() is None
    reopened.record_llm_attempt(
        attempt_id="second",
        analysis_id=identity.analysis_id,
        agent="verification",
        model="test",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=501,
        input_tokens=0,
        output_tokens=0,
        cost_cents=None,
        artifact_ref=ref,
    )
    assert (failure := budget.check()) is not None
    assert failure.code == "LLM_ELAPSED_BUDGET_EXHAUSTED"
