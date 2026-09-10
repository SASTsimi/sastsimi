import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import WorkAttempt
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.runtime.attempt_service import AttemptService
from sastsimi.runtime.recovery_service import RecoveryService
from sastsimi.runtime.transition_service import TransitionService
from sastsimi.storage.codec import reference
from sastsimi.storage.recovery_service import RecoveryService as SQLiteRecovery
from sastsimi.storage.unit_of_work import SQLiteUnitOfWork
from tests.integration.recovery.test_transitions import completion
from tests.integration.runtime_support import NOW, Harness, metadata
from tests.integration.storage.test_work import start_fixture


def test_save_result_rejects_undeclared_same_owner_candidate(tmp_path: Path) -> None:
    h, adapter, request = completion(tmp_path)
    SQLiteUnitOfWork(h.records, adapter.artifacts, adapter)
    output = request.records[0]
    assert isinstance(output, CodeWorkspace)
    data = output.model_dump(mode="json")
    data["meta"] = metadata("code_workspace", "unrelated")
    extra = CodeWorkspace.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="OUTPUT_BINDING"):
        TransitionService(h.records).commit(
            TransitionCommitRequest(
                request.transition, request.commit, (*request.records, extra)
            )
        )


def test_workspace_publication_updates_exact_analysis_state_atomically(
    tmp_path: Path,
) -> None:
    h, adapter, request = completion(tmp_path)
    SQLiteUnitOfWork(h.records, adapter.artifacts, adapter)
    TransitionService(h.records).commit(request)
    state = adapter.works.validator.budget.registry.current_state("a1")
    assert state.workspace_ref == request.commit.output_refs[0]
    assert str(state.workspace_id) == "w1"
    assert str(state.commit_id) == "c1"


@pytest.mark.parametrize(
    "corruption", ["redirect", "delete", "version", "unjournaled", "missing-work"]
)
def test_domain_pointer_corruption_fails_closed(
    tmp_path: Path, corruption: str
) -> None:
    h, adapter, request = completion(tmp_path)
    SQLiteUnitOfWork(h.records, adapter.artifacts, adapter)
    TransitionService(h.records).commit(request)
    if corruption == "unjournaled":
        candidate = request.records[0]
        assert isinstance(candidate, CodeWorkspace)
        data = candidate.model_dump(mode="json")
        data["meta"].update(
            record_id="unjournaled", revision_number=2, previous_record_id="result"
        )
        h.publish(CodeWorkspace.model_validate_json(json.dumps(data)))
    query = {
        "redirect": "UPDATE current_records SET record_id='start-transition' "
        "WHERE logical_record_id='result'",
        "delete": "DELETE FROM current_records WHERE logical_record_id='result'",
        "version": "UPDATE current_records SET state_version=99 "
        "WHERE logical_record_id='result'",
        "unjournaled": "UPDATE current_records SET record_id='unjournaled', "
        "state_version=2 WHERE logical_record_id='result'",
        "missing-work": (
            "DELETE FROM current_records WHERE logical_record_id='reserve-work'"
        ),
    }[corruption]
    with h.database.write() as connection:
        connection.execute(text(query))
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        RecoveryService(SQLiteRecovery(adapter)).recover()
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        h.records.get_exact(request.commit.output_refs[0])


@pytest.mark.parametrize("status", ["SUCCEEDED", "FAILED"])
def test_start_rejects_terminal_attempt(tmp_path: Path, status: str) -> None:
    h, works, adapter, transition, attempt, reservation = start_fixture(tmp_path)
    data = attempt.model_dump(mode="json")
    data.update(status=status, finished_at="2026-09-07T00:00:00Z")
    if status == "FAILED":
        data["error_ids"] = ["failure"]
    terminal = WorkAttempt.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="ATTEMPT"):
        AttemptService(adapter).start(
            transition, terminal, reservation, "worker", NOW + timedelta(seconds=30)
        )
    assert works.get(str(attempt.work_id)).status == "READY"


def test_superseded_workspace_input_cannot_commit(tmp_path: Path) -> None:
    def workspace_input(h: Harness) -> tuple[RecordRef, ...]:
        workspace = CodeWorkspace.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata("code_workspace", "input-workspace"),
                    workspace_id="w1",
                    analysis_id="a1",
                    repository_url="https://example.invalid/fixture",
                    commit_id="c1",
                    status="READY",
                )
            )
        )
        h.publish(workspace)
        with h.database.write() as connection:
            connection.execute(
                text(
                    "INSERT INTO current_records VALUES "
                    "('input-workspace', 'input-workspace', 1)"
                )
            )
        return (reference(workspace),)

    h, adapter, request = completion(tmp_path, input_factory=workspace_input)
    old = h.records.get_exact(adapter.works.get("reserve-work").input_refs[0])
    assert isinstance(old, CodeWorkspace)
    data = old.model_dump(mode="json")
    data["meta"].update(
        record_id="removed", revision_number=2, previous_record_id="input-workspace"
    )
    data["status"] = "REMOVED"
    h.publish(CodeWorkspace.model_validate_json(json.dumps(data)))
    with h.database.write() as connection:
        connection.execute(
            text(
                "UPDATE current_records SET record_id='removed', state_version=2 "
                "WHERE logical_record_id='input-workspace'"
            )
        )
    SQLiteUnitOfWork(h.records, adapter.artifacts, adapter)
    with pytest.raises(ValueError, match="STALE|STATE_VERSION"):
        TransitionService(h.records).commit(request)
    assert adapter.works.get("reserve-work").status == "RUNNING"
