from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sastsimi.observability.agent_activity import (
    ActivityKind,
    AgentActivityEvent,
)
from sastsimi.storage.agent_activity import AgentActivityStore


def event(
    kind: ActivityKind,
    *,
    attempt_id: str = "attempt-1",
    sequence: int = 1,
    summary_ko: str = "검증 단계를 확인했습니다.",
) -> AgentActivityEvent:
    return AgentActivityEvent(
        event_id=f"event-{attempt_id}-{sequence}",
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
        stage="VERIFICATION_FINAL_DONE",
        agent_role="Verification Agent",
        attempt_id=attempt_id,
        sequence=sequence,
        kind=kind,
        status="BLOCKED" if kind is ActivityKind.STAGE_BLOCKED else "RUNNING",
        summary_ko=summary_ko,
        started_at=datetime.now(UTC),
    )


def test_retry_events_are_append_only_and_attempt_scoped(tmp_path) -> None:
    store = AgentActivityStore(tmp_path / "sastsimi.sqlite3")
    store.append(event(ActivityKind.STAGE_BLOCKED))
    store.append(
        event(
            ActivityKind.STAGE_STARTED,
            attempt_id="attempt-2",
        )
    )

    values = store.list_analysis("analysis-1", hypothesis_id="hypothesis-1")

    assert [(item.attempt_id, item.kind) for item in values] == [
        ("attempt-1", ActivityKind.STAGE_BLOCKED),
        ("attempt-2", ActivityKind.STAGE_STARTED),
    ]


@pytest.mark.parametrize(
    "unsafe",
    ("token=sk-live-value", r"C:\Users\name\repo", "/home/name/private/repo"),
)
def test_event_rejects_secret_and_host_absolute_path(tmp_path, unsafe: str) -> None:
    store = AgentActivityStore(tmp_path / "sastsimi.sqlite3")

    with pytest.raises(ValueError, match="AGENT_ACTIVITY_UNSAFE"):
        store.append(event(ActivityKind.DECISION_RECORDED, summary_ko=unsafe))


def test_duplicate_event_with_different_content_is_rejected(tmp_path) -> None:
    store = AgentActivityStore(tmp_path / "sastsimi.sqlite3")
    first = event(ActivityKind.STAGE_STARTED)
    store.append(first)

    with pytest.raises(ValueError, match="AGENT_ACTIVITY_EVENT_CONFLICT"):
        store.append(first.model_copy(update={"summary_ko": "다른 내용"}))


# mypy: disable-error-code="no-untyped-def"
