"""T12 downstream registration stops at READY and never claims an attempt."""

from pathlib import Path

import pytest
from sqlalchemy import func, select

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.work import WorkStatus
from sastsimi.ports.ready_work import ReadyWorkPort
from sastsimi.storage import models
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


def test_enqueue_registers_ready_work_without_creating_attempt(tmp_path: Path) -> None:
    """Calling activate instead of enqueue would create a RUNNING attempt."""
    h, runtime, runner, current, *_ = prepared_policy_parser(tmp_path)
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    identity = next(iter(h.evidence.identities))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION

    ready = runner.enqueue(
        scope,
        current.meta,
        "POLICY_FETCH",
        "ANALYSIS",
        "a1",
        identity,
        generation=2,
    )

    assert isinstance(runner, ReadyWorkPort)
    assert ready.status == WorkStatus.READY
    assert ready.active_attempt_id is None
    assert ready.started_at is None
    with h.database.engine.connect() as connection:
        attempts = connection.execute(
            select(func.count())
            .select_from(models.work_attempts)
            .where(models.work_attempts.c.work_id == str(ready.work_id))
        ).scalar_one()
    assert attempts == 0


def test_enqueue_registered_rejects_non_pending_work(tmp_path: Path) -> None:
    """Accepting READY here would permit duplicate scheduling and state drift."""
    h, runtime, runner, current, *_ = prepared_policy_parser(tmp_path)
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    identity = next(iter(h.evidence.identities))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    ready = runner.enqueue(
        scope,
        current.meta,
        "POLICY_FETCH",
        "ANALYSIS",
        "a1",
        identity,
        generation=2,
    )

    with pytest.raises(ValueError, match="READY_ENQUEUE_REQUIRES_PENDING"):
        runner.enqueue_registered(ready, scope, identity)

    assert runtime.work.get(str(ready.work_id)) == ready


def test_enqueue_registered_rejects_different_budget_scope(tmp_path: Path) -> None:
    """A valid but unrelated budget scope must not authorize READY transition."""
    h, runtime, runner, current, *_ = prepared_policy_parser(tmp_path)
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    identity = next(iter(h.evidence.identities))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    pending = runner.begin_policy(
        scope,
        current.meta,
        identity,
        program_id="program",
        source_config_ref=identity,
        parser_name="policy-parser",
        parser_version="1.0.0",
        generation=2,
    ).work
    wrong_scope = runtime.budget_registry.current_state(
        "a1"
    ).execution_budget_profile_ref

    with pytest.raises(ValueError, match="READY_ENQUEUE_SCOPE_MISMATCH"):
        runner.enqueue_registered(pending, wrong_scope, identity)

    assert runtime.work.get(str(pending.work_id)).status == WorkStatus.PENDING
