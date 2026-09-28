from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sastsimi.observability.agent_activity import (
    ActivityKind,
    AgentActivityEvent,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
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


def test_old_activity_json_loads_without_metrics() -> None:
    old = event(ActivityKind.STAGE_COMPLETED).model_dump()
    loaded = AgentActivityEvent.model_validate(old)
    assert loaded.substage is None
    assert loaded.metrics == {}


def test_activity_rejects_host_path_in_substage() -> None:
    with pytest.raises(ValueError, match="AGENT_ACTIVITY_UNSAFE"):
        AgentActivityEvent.model_validate(
            {
                **event(ActivityKind.TOOL_COMPLETED).model_dump(),
                "substage": r"C:\Users\name\repo",
            }
        )


def test_activity_metrics_are_bounded_verified_counts() -> None:
    base = event(ActivityKind.TOOL_COMPLETED).model_dump()
    for bad in ({"verified": -1}, {"secret_count": 1}, {"candidates": 1.5}):
        with pytest.raises(ValueError, match="AGENT_ACTIVITY_METRICS_INVALID"):
            AgentActivityEvent.model_validate({**base, "metrics": bad})


def test_stage_completion_counts_candidates_without_confirming_findings(
    tmp_path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    proposal = SimpleArtifactRepository(tmp_path, identity).put_json(
        {"kind": "proposal"}
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(proposal,),
    )
    activity = SimpleCheckpointStore._lifecycle_event(
        checkpoint,
        ActivityKind.STAGE_COMPLETED,
        sequence=1,
        status=StageStatus.SUCCEEDED,
        summary_ko="가설 생성 완료",
        output_refs=(proposal,),
    )
    assert activity.metrics["candidates"] == 1
    assert activity.metrics["artifacts"] == 1
    assert activity.metrics.get("findings", 0) == 0

    finding = checkpoint.model_copy(
        update={
            "identity": identity.model_copy(update={"hypothesis_id": "hypothesis-1"}),
            "stage": SimpleStage.FINDING_DONE,
            "verdict": "TRUE",
            "validated_poc_ref": proposal,
        }
    )
    confirmed = SimpleCheckpointStore._lifecycle_event(
        finding,
        ActivityKind.STAGE_COMPLETED,
        sequence=2,
        status=StageStatus.SUCCEEDED,
        summary_ko="Finding 확정",
        output_refs=(proposal,),
    )
    assert confirmed.metrics["findings"] == 1
    assert confirmed.metrics["artifacts"] == 1
    assert "candidates" not in confirmed.metrics


# mypy: disable-error-code="no-untyped-def"
