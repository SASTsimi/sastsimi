"""T14 startup recovery converges without replaying external effects."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Connection, Table, insert, select, text

from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.storage import models
from sastsimi.storage.recovery_service import RecoveryService
from sastsimi.storage.run_control import RunControlStore
from sastsimi.storage.work_dispatch import WorkDispatchStore
from tests.integration.recovery.test_transitions import SimulatedCrash, completion
from tests.integration.runtime_support import NOW, Harness
from tests.integration.storage.test_work import start_fixture


def _rows(
    connection: Connection, table: Table, *columns: Any
) -> tuple[tuple[object, ...], ...]:
    statement = select(*columns).select_from(table).order_by(*columns)
    return tuple(tuple(row) for row in connection.execute(statement))


def _recovery_snapshot(harness: Harness) -> tuple[object, ...]:
    with harness.database.engine.connect() as connection:
        return (
            _rows(
                connection,
                models.work_states,
                models.work_states.c.work_id,
                models.work_states.c.status,
                models.work_states.c.state_version,
                models.work_states.c.active_attempt_id,
                models.work_states.c.payload,
            ),
            _rows(
                connection,
                models.work_attempts,
                models.work_attempts.c.attempt_id,
                models.work_attempts.c.status,
                models.work_attempts.c.payload,
            ),
            _rows(
                connection,
                models.transition_commits,
                models.transition_commits.c.transition_commit_id,
                models.transition_commits.c.state,
                models.transition_commits.c.payload,
            ),
            _rows(
                connection,
                models.current_records,
                models.current_records.c.logical_record_id,
                models.current_records.c.record_id,
                models.current_records.c.state_version,
            ),
            _rows(
                connection,
                models.external_dispatches,
                models.external_dispatches.c.action_id,
                models.external_dispatches.c.attempt_id,
                models.external_dispatches.c.dispatched_at,
                models.external_dispatches.c.returned_at,
                models.external_dispatches.c.reconciled_at,
            ),
        )


def test_restart_converges_prepared_transition_and_expired_lease(
    tmp_path: Path,
) -> None:
    prepared_harness, prepared_transitions, request = completion(tmp_path / "prepared")

    def crash(checkpoint: str) -> None:
        if checkpoint == "PREPARED":
            raise SimulatedCrash(checkpoint)

    prepared_transitions.checkpoint = crash
    with pytest.raises(SimulatedCrash):
        prepared_transitions.commit(request)
    prepared_transitions.checkpoint = lambda checkpoint: None

    first = RecoveryService(prepared_transitions).recover()
    prepared_snapshot = _recovery_snapshot(prepared_harness)
    second = RecoveryService(prepared_transitions).recover()

    assert first.blocked_work == second.blocked_work == 0
    assert prepared_transitions.works.get("reserve-work").status == "SUCCEEDED"
    assert _recovery_snapshot(prepared_harness) == prepared_snapshot

    lease_harness, lease_transitions, lease_request = completion(tmp_path / "lease")
    with lease_harness.database.write() as connection:
        connection.execute(
            text("UPDATE work_states SET lease_expires_at='2026-09-06T00:00:00+00:00'")
        )

    first = RecoveryService(
        lease_transitions, lease_request.transition.action_decision_ref
    ).recover()
    lease_snapshot = _recovery_snapshot(lease_harness)
    second = RecoveryService(
        lease_transitions, lease_request.transition.action_decision_ref
    ).recover()

    assert first.blocked_work == 1
    assert second.blocked_work == 0
    assert lease_transitions.works.get("reserve-work").stop_reason == "LEASE_EXPIRED"
    assert _recovery_snapshot(lease_harness) == lease_snapshot


@pytest.mark.parametrize("dispatch_attempt", ["at1", "prior-attempt"])
def test_unreturned_dispatch_blocks_without_replay_or_pointer_publication(
    tmp_path: Path, dispatch_attempt: str
) -> None:
    harness, works, attempts, transition, attempt, reservation_ref = start_fixture(
        tmp_path
    )
    running = attempts.start(
        transition,
        attempt,
        reservation_ref,
        "worker",
        NOW + timedelta(seconds=30),
    )
    before_pointers = _rows_from(harness, models.current_records)
    with harness.database.write() as connection:
        connection.execute(
            insert(models.external_dispatches).values(
                action_id="external-call",
                work_id=str(running.work_id),
                attempt_id=dispatch_attempt,
                decision_ref='{"missing":"exact-decision-ref"}',
                reservation_ref='{"missing":"exact-reservation-ref"}',
                prepared_at=NOW.isoformat(),
                dispatched_at=NOW.isoformat(),
                returned_at=None,
                reconciled_at=None,
            )
        )

    from sastsimi.storage.artifact_store import LocalArtifactStore
    from sastsimi.storage.transition_service import TransitionService

    transitions = TransitionService(
        works,
        LocalArtifactStore(tmp_path / "artifacts", WorkspaceId("w1"), CommitId("c1")),
    )
    result = RecoveryService(transitions, transition.action_decision_ref).recover()

    blocked = works.get(str(running.work_id))
    assert result.blocked_work == 1
    assert blocked.status == "BLOCKED"
    assert blocked.stop_reason == "RECOVERY_FAILED"
    assert blocked.waiting_for == ("INPUT",)
    assert blocked.output_refs == ()
    with harness.database.engine.connect() as connection:
        assert connection.execute(
            select(models.external_dispatches.c.action_id)
        ).scalars().all() == ["external-call"]
    after_pointers = _rows_from(harness, models.current_records)
    assert _non_work_pointers(after_pointers) == _non_work_pointers(before_pointers)


def test_precrash_cancel_latch_wins_over_expired_lease_and_scheduling(
    tmp_path: Path,
) -> None:
    harness, works, attempts, transition, attempt, reservation_ref = start_fixture(
        tmp_path / "running"
    )
    running = attempts.start(
        transition,
        attempt,
        reservation_ref,
        "worker",
        NOW + timedelta(seconds=30),
    )
    with harness.database.write() as connection:
        connection.execute(
            text("UPDATE work_states SET lease_expires_at='2026-09-06T00:00:00+00:00'")
        )
    controls = RunControlStore(harness.database, harness.clock)
    controls.request_cancel("a1", "OPERATOR_REQUEST")
    before_recovery = _recovery_snapshot(harness)

    from sastsimi.storage.artifact_store import LocalArtifactStore
    from sastsimi.storage.transition_service import TransitionService

    transitions = TransitionService(
        works,
        LocalArtifactStore(
            tmp_path / "running" / "artifacts", WorkspaceId("w1"), CommitId("c1")
        ),
    )
    report = RecoveryService(transitions, transition.action_decision_ref).recover()

    assert report.blocked_work == 0
    assert works.get(str(running.work_id)) == running
    assert controls.cancel_requested("a1") is True
    assert _recovery_snapshot(harness) == before_recovery

    ready_harness, ready_works, _, _, _, _ = start_fixture(tmp_path / "ready")
    ready = ready_works.get("reserve-work")
    ready_controls = RunControlStore(ready_harness.database, ready_harness.clock)
    ready_controls.request_cancel("a1", "OPERATOR_REQUEST")
    assert (
        WorkDispatchStore(ready_works).try_claim_ready(
            "a1",
            str(ready.work_id),
            ready.state_version,
            "new-worker",
            NOW + timedelta(minutes=1),
        )
        is None
    )
    assert ready_works.get(str(ready.work_id)) == ready


def _rows_from(harness: Harness, table: Table) -> tuple[tuple[object, ...], ...]:
    with harness.database.engine.connect() as connection:
        return _rows(
            connection,
            table,
            table.c.logical_record_id,
            table.c.record_id,
            table.c.state_version,
        )


def _non_work_pointers(
    rows: tuple[tuple[object, ...], ...],
) -> tuple[tuple[object, ...], ...]:
    return tuple(row for row in rows if row[0] != "reserve-work")
