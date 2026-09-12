"""Policy work, run-local state, and run-neutral cache lifecycle tests."""

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.policy import (
    PolicyCacheRecord,
    PolicyCollectionResult,
    RunPolicyState,
)
from sastsimi.contracts.refs import reference
from sastsimi.ports.policy_runtime import PolicyCacheKey
from sastsimi.storage import models
from sastsimi.storage.policy_runtime import publish_current, validate_cache_head
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


def _begin_policy(tmp_path: Path) -> tuple[Any, ...]:
    h, runtime, runner, existing, *_ = prepared_policy_parser(tmp_path, parallel=2)
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    identity = next(iter(h.evidence.identities))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    started = runner.begin_policy(
        scope,
        existing.meta,
        identity,
        program_id="program",
        source_config_ref=identity,
        parser_name="policy-parser",
        parser_version="1.0.0",
        generation=2,
    )
    return h, runtime, runner, scope, identity, started


def test_policy_begin_atomically_registers_pending_and_preparing(
    tmp_path: Path,
) -> None:
    """Publishing either half alone would expose an untraceable policy run."""
    h, runtime, _, _, _, started = _begin_policy(tmp_path)

    assert started.work.status == "PENDING"
    assert started.state.status == "PREPARING"
    assert started.state.policy_work_ref == reference(started.work)
    run = runtime.budget_registry.current_state("a1")
    assert run.run_policy_state_ref == reference(started.state)
    assert runtime.policy.current_state("a1") == started.state
    with h.database.engine.connect() as connection:
        attempts = connection.execute(
            select(func.count())
            .select_from(models.work_attempts)
            .where(models.work_attempts.c.work_id == str(started.work.work_id))
        ).scalar_one()
    assert attempts == 0


def test_policy_terminal_requires_exact_preparing_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new logical record would bypass stale-state and terminal-freeze guards."""
    h, runtime, runner, scope, identity, started = _begin_policy(tmp_path)
    ready = runner.enqueue_registered(started.work, scope, identity)
    running = runner.activate(ready, scope, identity)
    h.evidence.identities[identity] = RequesterRole.POLICY_COLLECTOR
    wrong_meta = runner.metadata(running.meta, "run_policy_state")
    wrong = RunPolicyState.model_validate_json(
        canonical_bytes(
            started.state.model_dump()
            | dict(
                meta=wrong_meta,
                status="FAILED",
                policy_work_ref=reference(running),
            )
        )
    )
    refs = (h.records.stage_record(wrong),)
    monkeypatch.setattr(h.evidence, "authorized_outputs", lambda action: refs)

    with pytest.raises(ValueError, match="POLICY_STATE_REVISION_MISMATCH"):
        runner.complete(
            running,
            identity,
            "POLICY_COLLECTOR",
            (wrong,),
            status="FAILED",
            error_ids=("policy-failed",),
        )

    assert runtime.policy.current_state("a1") == started.state
    assert runtime.work.get(str(running.work_id)) == running


@pytest.mark.parametrize("terminal_status", ["BLOCKED", "FAILED"])
def test_policy_terminal_successor_replaces_preparing_and_then_freezes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_status: str,
) -> None:
    """Keeping PREPARING current after completion would expose stale policy state."""
    h, runtime, runner, scope, identity, started = _begin_policy(tmp_path)
    ready = runner.enqueue_registered(started.work, scope, identity)
    running = runner.activate(ready, scope, identity)
    h.evidence.identities[identity] = RequesterRole.POLICY_COLLECTOR
    terminal = RunPolicyState.model_validate_json(
        canonical_bytes(
            started.state.model_dump()
            | dict(
                meta=runner.revision_metadata(started.state.meta),
                status=terminal_status,
                policy_work_ref=reference(running),
            )
        )
    )
    refs = (h.records.stage_record(terminal),)
    monkeypatch.setattr(h.evidence, "authorized_outputs", lambda action: refs)

    completed = runner.complete(
        running,
        identity,
        "POLICY_COLLECTOR",
        (terminal,),
        status=terminal_status,
        error_ids=("policy-failed",),
    )

    assert completed.status == terminal_status
    assert runtime.policy.current_state("a1") == terminal
    assert runtime.budget_registry.current_state(
        "a1"
    ).run_policy_state_ref == reference(terminal)
    before = runtime.queries.current_records("a1", "work_execution_state")
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    with pytest.raises(ValueError, match="POLICY_ALREADY_FROZEN"):
        runner.begin_policy(
            scope,
            running.meta,
            identity,
            program_id="program",
            source_config_ref=identity,
            parser_name="policy-parser",
            parser_version="1.0.0",
            generation=3,
        )
    assert runtime.queries.current_records("a1", "work_execution_state") == before
    assert runtime.budget.remaining(scope, "a1").active_reservation_count == 0


def test_policy_cache_uses_exact_cross_run_key_and_head_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Analysis-local lookup or stale sibling publication would reuse wrong policy."""
    h, runtime, runner, scope, identity, started = _begin_policy(tmp_path)
    ready = runner.enqueue_registered(started.work, scope, identity)
    running = runner.activate(ready, scope, identity)
    h.evidence.identities[identity] = RequesterRole.POLICY_COLLECTOR
    now = h.clock.now()
    collection = PolicyCollectionResult.model_validate(
        dict(
            meta=runner.metadata(
                running.meta,
                "policy_collection_result",
                attempt_id=running.active_attempt_id,
            ),
            collection_result_id="absent-policy",
            program_id="program",
            preparation_source="COLLECTED",
            source_cache_ref=None,
            status="ABSENT_CONFIRMED",
            official_source_refs=(scope,),
            parser_result_refs=(scope,),
            policy_record_ref=None,
            gap_ids=("policy-absent",),
            error_ids=(),
            completed_at=now,
        )
    )
    collection_ref = reference(collection)
    key = PolicyCacheKey(
        program_id=started.state.program_id,
        source_config_hash=started.state.source_config_ref.content_hash,
        parser_name=started.state.parser_name,
        parser_version=started.state.parser_version,
        freshness_criterion_hash=scope.content_hash,
    )
    cache = PolicyCacheRecord.model_validate(
        dict(
            meta=runtime.policy.cache_metadata(key, schema_version="1.0.0"),
            source_config_ref=started.state.source_config_ref,
            parser_name=started.state.parser_name,
            parser_version=started.state.parser_version,
            collection_status="ABSENT_CONFIRMED",
            collection_result_ref=collection_ref,
            parser_result_refs=(scope,),
            policy_record_ref=None,
            freshness_criterion_ref=scope,
            freshness_checked_at=now,
            freshness_evidence_refs=(scope,),
            freshness_valid_until=now + timedelta(days=1),
            published_at=now,
        )
    )
    terminal = RunPolicyState.model_validate(
        started.state.model_dump()
        | dict(
            meta=runner.revision_metadata(started.state.meta),
            status="ABSENT",
            preparation_source="COLLECTED",
            policy_work_ref=reference(running),
            policy_cache_ref=reference(cache),
            collection_result_ref=collection_ref,
            freshness_criterion_ref=scope,
            freshness_checked_at=now,
            freshness_evidence_refs=(scope,),
            freshness_valid_until=now + timedelta(days=1),
        )
    )
    outputs = (collection, cache, terminal)
    refs = tuple(h.records.stage_record(value) for value in outputs)
    monkeypatch.setattr(h.evidence, "authorized_outputs", lambda action: refs)
    runner.complete(running, identity, "POLICY_COLLECTOR", outputs)

    assert runtime.policy.current_cache(key) == cache
    miss = PolicyCacheKey(
        program_id=key.program_id,
        source_config_hash="f" * 64,
        parser_name=key.parser_name,
        parser_version=key.parser_version,
        freshness_criterion_hash=key.freshness_criterion_hash,
    )
    assert runtime.policy.current_cache(miss) is None

    newer = PolicyCacheRecord.model_validate(
        cache.model_dump()
        | dict(
            meta=runtime.policy.cache_metadata(
                key,
                schema_version="1.0.0",
                previous=cache,
            )
        )
    )
    stale = PolicyCacheRecord.model_validate(
        cache.model_dump()
        | dict(
            meta=runtime.policy.cache_metadata(
                key,
                schema_version="1.0.0",
                previous=cache,
            )
        )
    )
    with h.database.write() as connection:
        validate_cache_head(connection, newer, exact_key=True)
        newer_ref = h.records.stage(connection, newer)
        h.records.publish(connection, newer_ref)
        publish_current(connection, newer, str(cache.meta.record_id))
    assert runtime.policy.current_cache(key) == newer
    with h.database.engine.connect() as connection:
        with pytest.raises(ValueError, match="policy cache head"):
            validate_cache_head(connection, stale, exact_key=True)
