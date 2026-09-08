"""Stored canonical prerequisites; the restart action uses public authorization."""

import json
from pathlib import Path
from typing import Any

from sqlalchemy import insert, update

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    EnvironmentRequirements,
    SandboxProfile,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState, VerificationAssignment
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from tests.integration.budget.test_review_capacity import capacity_fixture
from tests.integration.runtime_support import Harness, metadata, units
from tests.integration.storage.test_sandbox_context import make
from tests.integration.trusted_fixture import FixtureEvidence
from tests.unit.contracts.test_core_models import action, ref, work


class RestartEvidence(FixtureEvidence):
    restart_hash: str | None = None
    restart_refs: tuple[BudgetScopeRef, ...] = ()

    def generation_restart_evidence(
        self, request: ActionRequest
    ) -> tuple[BudgetScopeRef, ...] | None:
        return self.restart_refs if content_hash(request) == self.restart_hash else None


def publish_current(h: Harness, record: Any) -> None:
    h.publish(record)
    with h.database.write() as connection:
        connection.execute(
            insert(models.current_records).values(
                logical_record_id=str(record.meta.logical_record_id),
                record_id=str(record.meta.record_id),
                state_version=getattr(
                    record, "state_version", record.meta.revision_number
                ),
            )
        )


def restart_fixture(
    tmp_path: Path, invalid: str | None = None, profile_change: bool = False
) -> tuple[Any, ...]:
    h, _, _ = capacity_fixture(tmp_path, "VERIFICATION")
    evidence = RestartEvidence()
    evidence.approvals = h.evidence.approvals
    h.evidence = evidence
    h.records.evidence = evidence
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=evidence)
    run = runtime.budget_registry.current_state("a1")
    assert run.budget_binding_ref is not None
    profile = SandboxProfile.model_validate_json(json.dumps(make("SandboxProfile")))
    h.publish(profile)
    identity = reference(profile)
    assert isinstance(identity, StoredDataRef)
    evidence.identities[identity] = RequesterRole.VERIFICATION
    assignment_data = make("VerificationAssignment")
    assignment_data.update(
        owner_identity_ref=identity.model_dump(mode="json"),
        status="SUPERSEDED" if invalid == "assignment" else "ACTIVE",
    )
    assignment = VerificationAssignment.model_validate_json(json.dumps(assignment_data))
    publish_current(h, assignment)
    request_data = make("DynamicReproductionRequest")
    request_data.update(
        sandbox_profile_ref=identity.model_dump(mode="json"),
        verification_assignment_ref=reference(assignment).model_dump(mode="json"),
    )
    request = DynamicReproductionRequest.model_validate_json(json.dumps(request_data))
    h.publish(request)

    def running(name: str, kind: str, parent: Any = None) -> WorkExecutionState:
        data = work(
            meta=metadata("work_execution_state", name, code=True)
            | {"hypothesis_id": "h1"},
            work_id=name,
            work_type=kind,
            subject_type="HYPOTHESIS",
            subject_id="h1",
            parent_work_ref=parent,
            status="RUNNING",
            state_version=2,
            last_transition_ref=ref("state_transition", True),
            active_attempt_id=name + "-attempt",
            started_at="2026-09-07T00:00:00Z",
            input_refs=[reference(request).model_dump(mode="json")]
            if kind == "DYNAMIC_REPRO"
            else [],
        )
        value = WorkExecutionState.model_validate_json(json.dumps(data))
        publish_current(h, value)
        attempt = WorkAttempt.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata("work_attempt", name + "-attempt", code=True)
                    | {"hypothesis_id": "h1", "attempt_id": name + "-attempt"},
                    work_id=name,
                    attempt_id=name + "-attempt",
                    attempt_number=1,
                    trigger="INITIAL",
                    input_hash=value.input_hash,
                    status="CANCELLED" if invalid == name + "-attempt" else "RUNNING",
                    output_refs=[],
                    gap_ids=[],
                    error_ids=[],
                    started_at="2026-09-07T00:00:00Z",
                    finished_at="2026-09-07T00:00:00Z"
                    if invalid == name + "-attempt"
                    else None,
                    elapsed_ms=0,
                )
            )
        )
        h.publish(attempt)
        with h.database.write() as connection:
            connection.execute(
                insert(models.work_states).values(
                    work_id=name,
                    analysis_id="a1",
                    registration_key=content_hash(name),
                    status="RUNNING",
                    state_version=2,
                    active_attempt_id=str(value.active_attempt_id),
                    payload=value.model_dump_json(),
                )
            )
            connection.execute(
                insert(models.work_attempts).values(
                    attempt_id=str(attempt.attempt_id),
                    work_id=name,
                    attempt_number=1,
                    status=attempt.status.value,
                    payload=attempt.model_dump_json(),
                )
            )
        return value

    parent = running("verification-parent", "VERIFICATION")
    dynamic = running(
        "dynamic-child", "DYNAMIC_REPRO", reference(parent).model_dump(mode="json")
    )
    if invalid == "dynamic-claim":
        with h.database.write() as connection:
            connection.execute(
                update(models.work_states)
                .where(models.work_states.c.work_id == str(dynamic.work_id))
                .values(active_attempt_id="different-attempt")
            )
    process_data = make("HypothesisProcessState")
    process_data.update(
        status="ASSIGNED" if invalid == "process" else "VERIFYING",
        verification_generation=1,
        verification_assignment_ref=reference(assignment).model_dump(mode="json"),
        verification_work_ref=reference(
            dynamic if invalid == "parent" else parent
        ).model_dump(mode="json"),
    )
    process = HypothesisProcessState.model_validate_json(json.dumps(process_data))
    publish_current(h, process)
    playbook = VerificationPlaybook.model_validate_json(
        json.dumps(make("VerificationPlaybook"))
    )
    publish_current(h, playbook)
    policy_data = make("PlaybookPolicy")
    policy_data["common_playbook_ref"] = reference(playbook).model_dump(mode="json")
    policy = PlaybookPolicy.model_validate_json(json.dumps(policy_data))
    publish_current(h, policy)
    basis = EnvironmentRequirements.model_validate_json(
        json.dumps(make("EnvironmentRequirements"))
    )
    h.publish(basis)
    new_profile = SandboxProfile.model_validate_json(
        json.dumps(
            profile.model_dump(mode="json")
            | {"meta": metadata("sandbox_profile", "new-profile", code=True)}
        )
    )
    h.publish(new_profile)
    chosen_profile = new_profile if profile_change else profile
    inputs = [
        reference(r)
        for r in (
            process,
            assignment,
            parent,
            dynamic,
            request,
            profile,
            policy,
            playbook,
            basis,
        )
    ]
    if profile_change:
        inputs.append(reference(new_profile))
    if invalid == "new-request":
        new_request = DynamicReproductionRequest.model_validate_json(
            json.dumps(
                request.model_dump(mode="json")
                | dict(
                    meta=metadata(
                        "dynamic_reproduction_request", "premature-request", code=True
                    )
                    | {"hypothesis_id": "h1", "attempt_id": "at1"},
                    verification_generation=2,
                )
            )
        )
        h.publish(new_request)
    candidate = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=metadata("action_request", "restart", code=True)
                | {"hypothesis_id": "h1", "attempt_id": str(parent.active_attempt_id)},
                action_id="restart",
                action_type="RESTART_VERIFICATION_GENERATION",
                requested_by="VERIFICATION",
                requester_identity_ref=identity.model_dump(mode="json"),
                work_ref=reference(parent).model_dump(mode="json"),
                expected_state_version=parent.state_version,
                expected_verification_generation=1,
                generation_restart_reason="SANDBOX_PROFILE_REVISION_CHANGED"
                if profile_change
                else "DYNAMIC_REQUEST_REPLACEMENT_REQUIRED",
                generation_restart_basis_refs=[
                    reference(basis).model_dump(mode="json")
                ],
                input_refs=[r.model_dump(mode="json") for r in inputs],
                dynamic_request_ref=reference(request).model_dump(mode="json"),
                sandbox_profile_ref=reference(chosen_profile).model_dump(mode="json"),
            )
        )
    )
    evidence.restart_hash = None if invalid == "evidence" else content_hash(candidate)
    basis_ref, new_profile_ref = reference(basis), reference(new_profile)
    assert isinstance(basis_ref, StoredDataRef) and isinstance(
        new_profile_ref, StoredDataRef
    )
    evidence.restart_refs = (
        (basis_ref, new_profile_ref) if profile_change else (basis_ref,)
    )
    reserved = runtime.budget.reserve(
        BudgetReservationRequest(
            BudgetReservation.model_validate_json(
                json.dumps(
                    dict(
                        meta=metadata(
                            "budget_reservation", "restart-budget", code=True
                        ),
                        reservation_id="restart-budget",
                        budget_binding_ref=run.budget_binding_ref.model_dump(
                            mode="json"
                        ),
                        action_ref=h.records.stage_record(candidate).model_dump(
                            mode="json"
                        ),
                        work_ref=reference(parent).model_dump(mode="json"),
                        requested_units=units(),
                        status="RESERVED",
                        ledger_entry_ref=None,
                        reserved_at="2026-09-07T00:00:00Z",
                        finalized_at=None,
                    )
                )
            )
        )
    )
    return h, runtime, candidate, reserved, process, parent
