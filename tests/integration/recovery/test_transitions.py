import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import StateTransition, TransitionCommit
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.storage.codec import reference
from sastsimi.storage.transition_service import TransitionService
from tests.integration.runtime_support import NOW, Harness, metadata
from tests.integration.storage.test_work import authorization, start_fixture


class SimulatedCrash(BaseException):
    pass


def completion(
    tmp_path: Path, *, authorize_output: bool = True
) -> tuple[Harness, TransitionService, TransitionCommitRequest]:
    from sastsimi.storage.artifact_store import LocalArtifactStore
    from sastsimi.storage.transition_service import TransitionService

    h, works, attempts, transition, attempt, reservation = start_fixture(tmp_path)
    running = attempts.start(
        transition, attempt, reservation, "worker", NOW + timedelta(seconds=30)
    )
    output = CodeWorkspace.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("code_workspace", "result"),
                workspace_id="w1",
                analysis_id="a1",
                repository_url="https://example.invalid/fixture",
                commit_id="c1",
                status="READY",
            )
        )
    )
    output_ref = h.records.stage_record(output)
    decision = authorization(
        h,
        ActionType.SAVE_RESULT if authorize_output else ActionType.CHANGE_WORK_STATE,
        "finish",
        reference(running),
        running.state_version,
        **(
            dict(
                result_kind="code_workspace",
                candidate_result_ref=output_ref.model_dump(mode="json"),
                requested_by="REPOSITORY_LOADER",
            )
            if authorize_output
            else {}
        ),
    )
    change = StateTransition.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("state_transition", "finish-transition"),
                transition_id="finish-transition",
                work_id=str(running.work_id),
                action_decision_ref=decision.model_dump(mode="json"),
                from_status="RUNNING",
                to_status="SUCCEEDED",
                expected_state_version=3,
                new_state_version=4,
                attempt_id="at1",
                cause="COMPLETED",
                output_refs=[output_ref.model_dump(mode="json")],
                gap_ids=[],
                error_ids=[],
                dedupe_key="e" * 64,
                created_at="2026-09-07T00:00:00Z",
            )
        )
    )
    commit = TransitionCommit.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("transition_commit", "commit"),
                transition_commit_id="commit",
                work_id=str(running.work_id),
                transition_ref=reference(change).model_dump(mode="json"),
                expected_state_version=3,
                target_state_version=4,
                attempt_id="at1",
                target_status="SUCCEEDED",
                output_refs=[output_ref.model_dump(mode="json")],
                gap_ids=[],
                error_ids=[],
                state="PREPARED",
                prepared_at="2026-09-07T00:00:00Z",
                committed_at=None,
                abort_reason=None,
            )
        )
    )
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts", WorkspaceId("w1"), CommitId("c1")
    )
    return (
        h,
        TransitionService(works, artifacts),
        TransitionCommitRequest(change, commit, (output,)),
    )


@pytest.mark.parametrize(
    "checkpoint", ["staging", "PREPARED", "CAS", "rename", "transaction_B", "COMMITTED"]
)
def test_crash_checkpoint_recovers_atomic_publication(
    tmp_path: Path, checkpoint: str
) -> None:
    h, service, request = completion(tmp_path)

    def crash(name: str) -> None:
        if name == checkpoint:
            raise SimulatedCrash(name)

    service.checkpoint = crash
    with pytest.raises(SimulatedCrash):
        service.commit(request)
    current = service.works.get("reserve-work")
    if checkpoint != "COMMITTED":
        assert current.status == "RUNNING"
        with pytest.raises(LookupError):
            h.records.get_exact(request.commit.output_refs[0])
    service.checkpoint = lambda name: None
    service.recover_prepared()
    if checkpoint == "staging":
        assert service.works.get("reserve-work").status == "RUNNING"
    else:
        current = service.works.get("reserve-work")
        assert current.status == "SUCCEEDED"
        assert current.state_version == 4
        assert current.output_refs == request.commit.output_refs
        assert current.last_transition_commit_ref is not None
        committed = h.records.get_exact(current.last_transition_commit_ref)
        assert isinstance(committed, TransitionCommit)
        assert committed.state == "COMMITTED"
        assert service.commit(request) == committed


def test_late_result_cannot_change_current_pointer_and_prepared_is_aborted(
    tmp_path: Path,
) -> None:
    h, service, request = completion(tmp_path)

    def crash(name: str) -> None:
        if name == "PREPARED":
            raise SimulatedCrash(name)

    service.checkpoint = crash
    with pytest.raises(SimulatedCrash):
        service.commit(request)
    with h.database.write() as connection:
        connection.execute(
            text("UPDATE work_states SET state_version=4 WHERE work_id='reserve-work'")
        )
    service.checkpoint = lambda name: None
    service.recover_prepared()
    with h.database.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT state FROM transition_commits")).scalar()
            == "ABORTED"
        )
        assert (
            connection.execute(
                text(
                    "SELECT state_version FROM current_records "
                    "WHERE logical_record_id='reserve-work'"
                )
            ).scalar()
            == 3
        )
    with pytest.raises(LookupError):
        h.records.get_exact(request.commit.output_refs[0])
