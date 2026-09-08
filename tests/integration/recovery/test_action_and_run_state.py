import json
from pathlib import Path

import pytest
from sqlalchemy import text

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import StateTransition, TransitionCommit
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.storage.codec import reference
from tests.integration.recovery.test_transitions import completion
from tests.integration.runtime_support import metadata
from tests.integration.storage.test_work import decision_action


def test_public_commit_rechecks_action_only_workspace_input(tmp_path: Path) -> None:
    h, adapter, prepared = completion(tmp_path)
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    workspace = CodeWorkspace.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("code_workspace", "action-workspace"),
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
                "('action-workspace', 'action-workspace', 1)"
            )
        )
    original = h.records.get_exact(
        decision_action(h, prepared.transition.action_decision_ref)
    )
    assert isinstance(original, ActionRequest)
    action = ActionRequest.model_validate(
        original.model_dump()
        | dict(
            meta=original.meta.model_copy(
                update={"record_id": "action-only", "logical_record_id": "action-only"}
            ),
            action_id="action-only",
            input_refs=(reference(workspace),),
            requester_identity_ref=prepared.transition.action_decision_ref,
        )
    )
    h.evidence.identities[action.requester_identity_ref] = (
        RequesterRole.REPOSITORY_LOADER
    )
    approved = runtime.validator.authorize(action)
    assert approved.decision == "ALLOW", approved.check_results
    transition = StateTransition.model_validate(
        prepared.transition.model_dump() | dict(action_decision_ref=reference(approved))
    )
    commit = TransitionCommit.model_validate(
        prepared.commit.model_dump() | dict(transition_ref=reference(transition))
    )
    removed = CodeWorkspace.model_validate(
        workspace.model_dump()
        | dict(
            meta=workspace.meta.model_copy(
                update={
                    "record_id": "removed-action-workspace",
                    "revision_number": 2,
                    "previous_record_id": workspace.meta.record_id,
                }
            ),
            status="REMOVED",
        )
    )
    h.publish(removed)
    with h.database.write() as connection:
        connection.execute(
            text(
                "UPDATE current_records SET record_id='removed-action-workspace', "
                "state_version=2 WHERE logical_record_id='action-workspace'"
            )
        )
    with pytest.raises(ValueError, match="STALE"):
        runtime.transitions.commit(
            TransitionCommitRequest(transition, commit, prepared.records)
        )
    assert adapter.works.get("reserve-work").status == "RUNNING"


@pytest.mark.parametrize("corruption", ["pointer", "projection"])
def test_public_recovery_rejects_detached_analysis_companion(
    tmp_path: Path, corruption: str
) -> None:
    h, adapter, prepared = completion(tmp_path)
    initial = adapter.works.validator.budget.registry.current_state("a1")
    adapter.commit(prepared)
    with h.database.write() as connection:
        if corruption == "pointer":
            connection.execute(
                text("DELETE FROM current_records WHERE logical_record_id=:logical"),
                {"logical": str(initial.meta.logical_record_id)},
            )
        else:
            connection.execute(
                text(
                    "UPDATE analysis_runs SET payload=:payload WHERE analysis_id='a1'"
                ),
                {"payload": initial.model_dump_json()},
            )
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)


def test_public_recovery_rejects_missing_entire_analysis_projection(
    tmp_path: Path,
) -> None:
    h, adapter, prepared = completion(tmp_path)
    adapter.commit(prepared)
    with h.database.write() as connection:
        connection.execute(text("DELETE FROM analysis_runs WHERE analysis_id='a1'"))
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
