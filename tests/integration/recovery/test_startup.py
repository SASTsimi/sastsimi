from pathlib import Path

import pytest

from tests.integration.recovery.test_transitions import completion


def test_startup_verifies_every_artifact_and_quarantines_unreferenced_files(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.recovery_service import RecoveryService

    h, transitions, request = completion(tmp_path)
    transitions.commit(request)
    orphan = transitions.artifacts.commit(
        transitions.artifacts.stage_bytes(b"orphan", "text/plain")
    )
    recovery = RecoveryService(transitions)
    report = recovery.recover()
    assert report.checked_artifacts == 1
    assert report.quarantined_artifacts == 1
    assert not transitions.artifacts.path_for(orphan.content_hash).exists()
    path = transitions.artifacts.path_for(request.commit.output_refs[0].content_hash)
    path.write_bytes(b"corruption")
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        recovery.recover()
    assert h.database.recovery_failed


def test_record_and_pointer_corruption_blocks_recovery(tmp_path: Path) -> None:
    from sqlalchemy import text

    from sastsimi.storage.recovery_service import RecoveryService

    h, transitions, request = completion(tmp_path)
    transitions.commit(request)
    with h.database.write() as connection:
        connection.execute(
            text(
                "UPDATE current_records SET state_version=99 "
                "WHERE logical_record_id='reserve-work'"
            )
        )
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        RecoveryService(transitions).recover()


def test_expired_external_lease_preserves_unknown_reservation_and_blocks_work(
    tmp_path: Path,
) -> None:
    from sqlalchemy import text

    from sastsimi.storage.recovery_service import RecoveryService

    h, transitions, request = completion(tmp_path)
    with h.database.write() as connection:
        connection.execute(
            text("UPDATE work_states SET lease_expires_at='2026-09-06T00:00:00+00:00'")
        )
    report = RecoveryService(
        transitions, request.transition.action_decision_ref
    ).recover()
    assert report.blocked_work == 1
    work = transitions.works.get("reserve-work")
    assert work.status == "BLOCKED"
    assert work.waiting_for == ("INPUT",)
    assert work.output_refs == ()
    with h.database.engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM budget_reservations WHERE status='RESERVED'")
            ).scalar()
            == 2
        )
