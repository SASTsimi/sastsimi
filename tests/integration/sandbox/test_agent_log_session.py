from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sastsimi.contracts.dynamic import AgentLogEvent
from sastsimi.sandbox.session_manager import ReproductionSessionManager
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import wire
from tests.contract.domain.success_fixture import bound, dynamic_success
from tests.integration.runtime_support import TestClock, TestIds

NOW = datetime(2026, 9, 8, tzinfo=UTC)


def _manager() -> ReproductionSessionManager:
    clock = TestClock()
    clock.wall_time = NOW
    return ReproductionSessionManager(clock=clock, ids=TestIds())


def _agent_event(
    *, event_id: str, sequence: int, event_type: str, action_id: str, seconds: int
) -> AgentLogEvent:
    return wire(
        AgentLogEvent,
        make("AgentLogEvent")
        | {
            "event_id": event_id,
            "sequence": sequence,
            "action_id": action_id,
            "event_type": event_type,
            "actor": "DYNAMIC_REPRODUCTION",
            "safe_message": "Agent lifecycle event",
            "occurred_at": (NOW + timedelta(seconds=seconds)).isoformat(),
        },
    )


def test_log_append_is_ordered_and_idempotent_only_for_identical_event() -> None:
    chain = dynamic_success()
    manager = _manager()
    started = manager.start(request_ref=bound(chain["request"]), meta=chain["log"].meta)
    event = _agent_event(
        event_id="agent-started",
        sequence=2,
        event_type="AGENT_STARTED",
        action_id="agent-call",
        seconds=1,
    )

    current = manager.append(previous=started, event=event)
    replay = manager.append(previous=current, event=event)

    assert replay == current
    assert [item.sequence for item in current.events] == [1, 2]
    assert current.meta.previous_record_id == started.meta.record_id

    changed = _agent_event(
        event_id="agent-started",
        sequence=2,
        event_type="AGENT_STARTED",
        action_id="different-call",
        seconds=1,
    )
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        manager.append(previous=current, event=changed)


def test_log_rejects_stale_revision_skipped_sequence_and_finish_without_start() -> None:
    chain = dynamic_success()
    manager = _manager()
    started = manager.start(request_ref=bound(chain["request"]), meta=chain["log"].meta)
    current = manager.append(
        previous=started,
        event=_agent_event(
            event_id="agent-started",
            sequence=2,
            event_type="AGENT_STARTED",
            action_id="agent-call",
            seconds=1,
        ),
    )

    with pytest.raises(ValueError, match="STALE_RESULT"):
        manager.append(
            previous=started,
            event=_agent_event(
                event_id="other-agent-started",
                sequence=2,
                event_type="AGENT_STARTED",
                action_id="other-agent-call",
                seconds=1,
            ),
        )
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        manager.append(
            previous=current,
            event=_agent_event(
                event_id="skipped",
                sequence=4,
                event_type="AGENT_FINISHED",
                action_id="agent-call",
                seconds=2,
            ),
        )
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        manager.append(
            previous=current,
            event=_agent_event(
                event_id="wrong-finish",
                sequence=3,
                event_type="AGENT_FINISHED",
                action_id="different-call",
                seconds=2,
            ),
        )


def test_log_rejects_event_time_regression() -> None:
    chain = dynamic_success()
    manager = _manager()
    started = manager.start(request_ref=bound(chain["request"]), meta=chain["log"].meta)

    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        manager.append(
            previous=started,
            event=_agent_event(
                event_id="past-event",
                sequence=2,
                event_type="AGENT_STARTED",
                action_id="agent-call",
                seconds=-1,
            ),
        )


def test_log_rejects_a_second_session_start() -> None:
    chain = dynamic_success()
    manager = _manager()
    started = manager.start(request_ref=bound(chain["request"]), meta=chain["log"].meta)

    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        manager.append(
            previous=started,
            event=_agent_event(
                event_id="second-session",
                sequence=2,
                event_type="SESSION_STARTED",
                action_id="second-session",
                seconds=1,
            ),
        )


def test_log_rejects_events_after_session_finish() -> None:
    chain = dynamic_success()
    manager = _manager()
    started = manager.start(request_ref=bound(chain["request"]), meta=chain["log"].meta)
    finished = manager.append(
        previous=started,
        event=_agent_event(
            event_id="session-finished",
            sequence=2,
            event_type="SESSION_FINISHED",
            action_id=str(started.events[0].action_id),
            seconds=1,
        ),
    )

    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        manager.append(
            previous=finished,
            event=_agent_event(
                event_id="late-agent",
                sequence=3,
                event_type="AGENT_STARTED",
                action_id="late-agent",
                seconds=2,
            ),
        )
