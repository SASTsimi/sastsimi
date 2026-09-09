import json
from pathlib import Path

import pytest
from sqlalchemy import text

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.policy import PolicyCollectionResult, RunPolicyState
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import StateTransition, TransitionCommit
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.recovery.test_transitions import completion
from tests.integration.runtime_support import metadata
from tests.integration.storage.test_work import decision_action
from tests.integration.trusted_fixture import FixtureEvidence


class OutputEvidence(FixtureEvidence):
    closure: tuple[RecordRef, ...] = ()

    def authorized_outputs(self, action: ActionRequest) -> tuple[RecordRef, ...] | None:
        return self.closure if str(action.action_id) == "policy-finish" else None


@pytest.mark.parametrize("extra", [False, True, "corrupted"])
def test_public_authorized_policy_companions_are_atomic(
    tmp_path: Path, extra: bool | str
) -> None:
    h, _, original = completion(tmp_path)
    evidence = OutputEvidence()
    evidence.approvals = h.evidence.approvals
    evidence.identities = h.evidence.identities
    collection_data = make("PolicyCollectionResult")
    collection = PolicyCollectionResult.model_validate_json(json.dumps(collection_data))
    state_data = make("RunPolicyState")
    state_data.update(
        status="FAILED",
        preparation_source="COLLECTED",
        policy_cache_ref=None,
        collection_result_ref=reference(collection).model_dump(mode="json"),
        policy_record_ref=None,
    )
    state = RunPolicyState.model_validate_json(json.dumps(state_data))
    outputs = (collection, state)
    evidence.closure = tuple(h.records.stage_record(output) for output in outputs)
    old_action = h.records.get_exact(
        decision_action(h, original.transition.action_decision_ref)
    )
    assert isinstance(old_action, ActionRequest)
    identity = original.transition.action_decision_ref
    evidence.identities[identity] = RequesterRole.POLICY_COLLECTOR
    action_data = old_action.model_dump(mode="json") | dict(
        meta=metadata("action_request", "policy-finish"),
        action_id="policy-finish",
        requested_by="POLICY_COLLECTOR",
        requester_identity_ref=identity.model_dump(mode="json"),
        result_kind="policy_collection_result",
        candidate_result_ref=evidence.closure[0].model_dump(mode="json"),
    )
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=evidence)
    approved = runtime.validator.authorize(
        ActionRequest.model_validate_json(json.dumps(action_data))
    )
    assert approved.decision == "ALLOW", approved.check_results
    if extra == "corrupted":
        with h.database.write() as connection:
            connection.execute(
                text(
                    "UPDATE action_output_closures SET output_refs='[]' "
                    "WHERE action_id='policy-finish'"
                )
            )
    approved_outputs = evidence.closure
    # Host evidence changes after issuance cannot change its durable exact closure.
    evidence.closure = ()
    assert (
        runtime.validator.authorize(
            ActionRequest.model_validate_json(json.dumps(action_data))
        )
        == approved
    )
    records = (*outputs, original.records[0]) if extra is True else outputs
    refs = tuple(reference(record) for record in records)
    transition = StateTransition.model_validate(
        original.transition.model_dump()
        | dict(action_decision_ref=reference(approved), output_refs=refs)
    )
    commit = TransitionCommit.model_validate(
        original.commit.model_dump()
        | dict(transition_ref=reference(transition), output_refs=refs)
    )
    request = TransitionCommitRequest(transition, commit, records)
    if extra:
        with pytest.raises(ValueError, match="OUTPUT_BINDING"):
            runtime.transitions.commit(request)
    else:
        committed = runtime.transitions.commit(request)
        assert committed.output_refs == approved_outputs
        assert runtime.transitions.commit(request) == committed
        for record in outputs:
            assert runtime.unit_of_work.records.get_exact(reference(record)) == record
