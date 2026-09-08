"""Regression cases for the seven Task 4 independent-review findings."""

import json
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError
from test_core_models import action, decision, meta, mutations, ref, work

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    validate_decision_revision,
)
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.work import (
    StateTransition,
    TransitionCommit,
    WorkExecutionState,
    validate_commit_transition,
    validate_transition_context,
)


def scoped_ref(kind: str, code: bool, metadata: dict[str, Any]) -> dict[str, Any]:
    keys = ("workspace_id", "commit_id") if code else ("analysis_id",)
    return ref(kind, code) | {key: metadata[key] for key in keys}


def transition_data(code: bool = True, **scope: Any) -> dict[str, Any]:
    metadata = meta(code, record_type="state_transition", record_id="t1", **scope)
    return dict(
        meta=metadata,
        transition_id="tr1",
        work_id="w1",
        action_decision_ref=scoped_ref("action_decision", code, metadata),
        from_status="READY",
        to_status="CANCELLED",
        expected_state_version=2,
        new_state_version=3,
        attempt_id=None,
        cause="cancel",
        output_refs=[],
        gap_ids=[],
        error_ids=[],
        dedupe_key="b" * 64,
        created_at="2026-09-07T00:00:00Z",
    )


def commit_data(
    transition: StateTransition, code: bool = True, **scope: Any
) -> dict[str, Any]:
    metadata = meta(code, record_type="transition_commit", **scope)
    target = scoped_ref("state_transition", code, metadata) | {
        "record_id": str(transition.meta.record_id),
        "content_hash": content_hash(transition),
    }
    return dict(
        meta=metadata,
        transition_commit_id="tc1",
        work_id="w1",
        transition_ref=target,
        expected_state_version=2,
        target_state_version=3,
        attempt_id=None,
        target_status="CANCELLED",
        output_refs=[],
        gap_ids=[],
        error_ids=[],
        state="PREPARED",
        prepared_at="2026-09-07T00:00:00Z",
        committed_at=None,
        abort_reason=None,
    )


def test_round1_finding_normalize_accepts_rule_scope_parent_and_hypothesis() -> None:
    data = work(
        meta=meta(True, hypothesis_id="h1"),
        work_type="FINDING_NORMALIZE",
        subject_type="HYPOTHESIS",
        subject_id="h1",
        parent_work_ref=ref(code=True),
    )
    assert (
        WorkExecutionState.model_validate_json(json.dumps(data)).parent_work_ref
        is not None
    )
    for change in (
        {"subject_type": "ANALYSIS", "subject_id": "a1"},
        {"parent_work_ref": None},
        {"subject_id": "h2"},
    ):
        with pytest.raises(ValidationError):
            WorkExecutionState.model_validate_json(json.dumps(data | change))


def test_round1_finding_parent_must_be_exact_successful_rule_scope_work() -> None:
    from sastsimi.contracts.work import validate_parent_work

    parent_data = work(
        meta=meta(True, hypothesis_id="h1"),
        work_type="RULE_SCOPE_GATE",
        subject_type="HYPOTHESIS",
        subject_id="h1",
        status="SUCCEEDED",
        state_version=4,
        last_transition_ref=ref("state_transition", True),
        finished_at="2026-09-07T00:00:00Z",
        stop_reason="COMPLETED",
    )
    parent = WorkExecutionState.model_validate_json(json.dumps(parent_data))
    child_data = work(
        meta=meta(True, hypothesis_id="h1"),
        work_id="child",
        work_type="FINDING_NORMALIZE",
        subject_type="HYPOTHESIS",
        subject_id="h1",
        parent_work_ref=ref(code=True) | {"content_hash": content_hash(parent)},
    )
    child = WorkExecutionState.model_validate_json(json.dumps(child_data))
    validate_parent_work(child, parent)
    for changes in (
        {"work_type": "VERIFICATION"},
        {"status": "FAILED", "stop_reason": "FAILED", "error_ids": ["err"]},
    ):
        invalid_parent = WorkExecutionState.model_validate_json(
            json.dumps(parent_data | changes)
        )
        matching_child = WorkExecutionState.model_validate_json(
            json.dumps(
                child_data
                | {
                    "parent_work_ref": ref(code=True)
                    | {"content_hash": content_hash(invalid_parent)}
                }
            )
        )
        with pytest.raises(ValueError):
            validate_parent_work(matching_child, invalid_parent)
    with pytest.raises(ValueError):
        validate_parent_work(
            WorkExecutionState.model_validate_json(
                json.dumps(child_data | {"parent_work_ref": ref(code=True)})
            ),
            parent,
        )


@pytest.mark.parametrize(
    "code,key",
    [
        (False, "analysis_id"),
        (True, "analysis_id"),
        (True, "workspace_id"),
        (True, "commit_id"),
        (True, "hypothesis_id"),
    ],
)
def test_round1_context_and_commit_reject_cross_scope(code: bool, key: str) -> None:
    original = transition_data(code)
    transition = StateTransition.model_validate_json(json.dumps(original))
    state = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=meta(code),
                work_type="STATIC_TOOL" if code else "WORKSPACE_PREP",
                status="READY",
                state_version=2,
                last_transition_ref=ref("state_transition", code),
            )
        )
    )
    validate_transition_context(transition, state)
    validate_commit_transition(
        TransitionCommit.model_validate_json(json.dumps(commit_data(transition, code))),
        transition,
    )
    with pytest.raises(ValueError):
        validate_transition_context(
            StateTransition.model_validate_json(
                json.dumps(transition_data(code, **{key: "other"}))
            ),
            state,
        )
    with pytest.raises(ValueError):
        validate_commit_transition(
            TransitionCommit.model_validate_json(
                json.dumps(commit_data(transition, code, **{key: "other"}))
            ),
            transition,
        )


def test_round1_commit_rejects_wrong_transition_digest() -> None:
    transition = StateTransition.model_validate_json(json.dumps(transition_data()))
    data = commit_data(transition)
    data["transition_ref"]["content_hash"] = "c" * 64
    with pytest.raises(ValueError, match="hash"):
        validate_commit_transition(
            TransitionCommit.model_validate_json(json.dumps(data)), transition
        )


def test_round1_context_rejects_metadata_kind_change() -> None:
    transition = StateTransition.model_validate_json(json.dumps(transition_data(False)))
    state = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=meta(True),
                work_type="STATIC_TOOL",
                status="READY",
                state_version=2,
                last_transition_ref=ref("state_transition", True),
            )
        )
    )
    with pytest.raises(ValueError):
        validate_transition_context(transition, state)
    with pytest.raises(ValueError):
        validate_commit_transition(
            TransitionCommit.model_validate_json(json.dumps(commit_data(transition))),
            transition,
        )


@pytest.mark.parametrize("code", [False, True])
def test_round1_ready_running_requires_new_attempt(code: bool) -> None:
    data = transition_data(code) | {"to_status": "RUNNING"}
    with pytest.raises(ValidationError, match="attempt"):
        StateTransition.model_validate_json(json.dumps(data))
    data["attempt_id"] = "at1"
    if code:
        with pytest.raises(ValidationError, match="attempt"):
            StateTransition.model_validate_json(json.dumps(data))
        data["meta"]["attempt_id"] = "at1"
    assert (
        str(StateTransition.model_validate_json(json.dumps(data)).attempt_id) == "at1"
    )


def restart_data(reason: str) -> dict[str, Any]:
    old_request = ref("dynamic_reproduction_request", True)
    old_profile = ref("sandbox_profile", True)
    new_profile = old_profile | {"record_id": "new-profile", "content_hash": "b" * 64}
    parent_work = ref(code=True)
    dynamic_work = parent_work | {"record_id": "dynamic-work"}
    basis = ref("change_basis", True)
    inputs = [
        ref(kind, True)
        for kind in (
            "hypothesis_process_state",
            "verification_assignment",
            "playbook_policy",
            "verification_playbook",
        )
    ]
    inputs += [parent_work, dynamic_work, old_request, old_profile, basis]
    if reason == "SANDBOX_PROFILE_REVISION_CHANGED":
        inputs.append(new_profile)
    return action(
        meta=meta(True, hypothesis_id="h1"),
        requested_by="VERIFICATION",
        action_type="RESTART_VERIFICATION_GENERATION",
        work_ref=parent_work,
        expected_state_version=2,
        expected_verification_generation=1,
        generation_restart_reason=reason,
        generation_restart_basis_refs=[basis],
        dynamic_request_ref=old_request,
        sandbox_profile_ref=new_profile
        if reason == "SANDBOX_PROFILE_REVISION_CHANGED"
        else old_profile,
        input_refs=inputs,
    )


@pytest.mark.parametrize(
    "reason",
    ["DYNAMIC_REQUEST_REPLACEMENT_REQUIRED", "SANDBOX_PROFILE_REVISION_CHANGED"],
)
def test_round1_restart_accepts_old_request_and_reason_specific_profiles(
    reason: str,
) -> None:
    data = restart_data(reason)
    value = ActionRequest.model_validate_json(json.dumps(data))
    assert (
        str(value.dynamic_request_ref.record_id) == "r1"
        if value.dynamic_request_ref
        else False
    )
    for changed in mutations(
        {"dynamic_request_ref": None},
        {"sandbox_profile_ref": None},
        {"input_refs": []},
        {"generation_restart_basis_refs": [ref("unlisted_basis", True)]},
        {
            "input_refs": data["input_refs"]
            + [ref("dynamic_reproduction_request", True) | {"record_id": "new-request"}]
        },
    ):
        with pytest.raises(ValidationError):
            ActionRequest.model_validate_json(json.dumps(data | changed))


def test_round1_profile_change_requires_distinct_old_and_new_profiles() -> None:
    data = restart_data("SANDBOX_PROFILE_REVISION_CHANGED")
    assert (
        ActionRequest.model_validate_json(json.dumps(data)).sandbox_profile_ref
        is not None
    )
    without_old = [
        item for item in data["input_refs"] if item != ref("sandbox_profile", True)
    ]
    with pytest.raises(ValidationError):
        ActionRequest.model_validate_json(
            json.dumps(data | {"input_refs": without_old})
        )
    with pytest.raises(ValidationError):
        ActionRequest.model_validate_json(
            json.dumps(
                data | {"input_refs": without_old + [data["sandbox_profile_ref"]]}
            )
        )


@pytest.mark.parametrize("role", ["PRO", "CON"])
@pytest.mark.parametrize("session", ["RESUME", "AUTO"])
def test_round1_pro_con_require_new_session(role: str, session: str) -> None:
    data = action(
        meta=meta(True),
        requested_by=role,
        action_type="CALL_LLM",
        work_ref=ref(code=True),
        expected_state_version=1,
        llm_call_spec_ref=ref("llm_call_spec", True),
        provider_profile_ref=ref("provider_profile", True),
        session_mode="NEW",
    )
    ActionRequest.model_validate_json(json.dumps(data))
    with pytest.raises(ValidationError, match="NEW"):
        ActionRequest.model_validate_json(json.dumps(data | {"session_mode": session}))


def test_round1_first_claim_has_no_outcomes() -> None:
    original = ActionDecision.model_validate_json(json.dumps(decision()))
    claimed_data = decision(
        meta=meta(record_id="r2", previous_record_id="r1", revision_number=2),
        use_status="USED",
        used_at="2026-09-07T00:00:01Z",
        outcome_refs=[ref()],
    )
    with pytest.raises(ValueError, match="outcome"):
        validate_decision_revision(
            original, ActionDecision.model_validate_json(json.dumps(claimed_data))
        )
    claim = ActionDecision.model_validate_json(
        json.dumps(claimed_data | {"outcome_refs": []})
    )
    validate_decision_revision(original, claim)
    later = ActionDecision.model_validate_json(
        json.dumps(
            claimed_data
            | {"meta": meta(record_id="r3", previous_record_id="r2", revision_number=3)}
        )
    )
    validate_decision_revision(claim, later)


@pytest.mark.parametrize(
    "hidden", [{"content_hash": "hidden"}, {"amount": 1.5}, {"ignored": "different"}]
)
def test_round1_extra_bearing_models_cannot_hide_members(
    hidden: dict[str, object],
) -> None:
    class External(BaseModel):
        model_config = ConfigDict(extra="allow")
        visible: int

    external = External.model_validate({"visible": 1} | hidden)
    with pytest.raises((TypeError, ValueError)):
        canonical_bytes(external)
    with pytest.raises((TypeError, ValueError)):
        content_hash(external)


def test_round1_contract_subclass_cannot_hide_allowed_extras() -> None:
    class PermissiveContract(ContractModel):
        model_config = ConfigDict(extra="allow")
        visible: int

    with pytest.raises((TypeError, ValueError)):
        content_hash(
            PermissiveContract.model_validate({"visible": 1, "content_hash": "hidden"})
        )


def test_round1_valid_contract_fields_and_nested_refs_remain_hashable() -> None:
    value = ActionRequest.model_validate_json(json.dumps(action()))
    assert canonical_bytes(value) == canonical_bytes(value.model_dump())
    assert content_hash(value) == content_hash(value.model_dump())


@pytest.mark.parametrize(
    "reason",
    ["DYNAMIC_REQUEST_REPLACEMENT_REQUIRED", "SANDBOX_PROFILE_REVISION_CHANGED"],
)
def test_round1_restart_context_fixes_current_request_and_approved_profile(
    reason: str,
) -> None:
    from sastsimi.contracts.actions import validate_generation_restart_context
    from sastsimi.contracts.refs import StoredDataRef

    current_request = StoredDataRef.model_validate_json(
        json.dumps(ref("dynamic_reproduction_request", True))
    )
    current_profile = StoredDataRef.model_validate_json(
        json.dumps(ref("sandbox_profile", True))
    )
    data = restart_data(reason)
    approved = (
        StoredDataRef.model_validate_json(json.dumps(data["sandbox_profile_ref"]))
        if reason == "SANDBOX_PROFILE_REVISION_CHANGED"
        else None
    )
    value = ActionRequest.model_validate_json(json.dumps(data))
    validate_generation_restart_context(
        value,
        current_request_ref=current_request,
        current_profile_ref=current_profile,
        approved_profile_ref=approved,
    )
    other_request = StoredDataRef.model_validate_json(
        json.dumps(
            ref("dynamic_reproduction_request", True) | {"record_id": "another-current"}
        )
    )
    with pytest.raises(ValueError):
        validate_generation_restart_context(
            value,
            current_request_ref=other_request,
            current_profile_ref=current_profile,
            approved_profile_ref=approved,
        )
    if approved is not None:
        uses_old = ActionRequest.model_validate_json(
            json.dumps(data | {"sandbox_profile_ref": ref("sandbox_profile", True)})
        )
        with pytest.raises(ValueError):
            validate_generation_restart_context(
                uses_old,
                current_request_ref=current_request,
                current_profile_ref=current_profile,
                approved_profile_ref=approved,
            )
        with pytest.raises(ValueError):
            validate_generation_restart_context(
                value,
                current_request_ref=current_request,
                current_profile_ref=current_profile,
            )
