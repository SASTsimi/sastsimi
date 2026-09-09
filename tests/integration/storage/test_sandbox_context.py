import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import insert

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
)
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    EnvironmentRequirements,
    ReproductionPlan,
    SandboxProfile,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make as canonical_make
from tests.integration.budget.test_review_capacity import capacity_fixture
from tests.integration.runtime_support import metadata
from tests.unit.contracts.test_core_models import action, ref, work


def make(name: str) -> dict[str, Any]:
    return dict(json.loads(json.dumps(canonical_make(name)).replace('"ws1"', '"w1"')))


@pytest.mark.parametrize(
    "invalid", [None, "plan", "generation", "profile", "lifecycle"]
)
def test_public_sandbox_context_binds_current_plan_and_run_local_profiles(
    tmp_path: Path, invalid: str | None
) -> None:
    h, _, _ = capacity_fixture(tmp_path)
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    run = runtime.budget_registry.current_state("a1")
    assert run.budget_binding_ref is not None
    binding = h.records.get_exact(run.budget_binding_ref)
    assert isinstance(binding, BudgetProfileBinding)
    lifecycle = binding.dynamic_lifecycle_profile_ref
    profile = SandboxProfile.model_validate_json(json.dumps(make("SandboxProfile")))
    profile_ref = h.records.stage_record(profile)
    assert isinstance(profile_ref, StoredDataRef)
    h.publish(profile)
    data = make("DynamicReproductionRequest")
    data["sandbox_profile_ref"] = profile_ref.model_dump(mode="json")
    request = DynamicReproductionRequest.model_validate_json(json.dumps(data))
    request_ref = h.records.stage_record(request)
    h.publish(request)
    requirements_data = make("EnvironmentRequirements")
    requirements_data["request_ref"] = request_ref.model_dump(mode="json")
    requirements = EnvironmentRequirements.model_validate_json(
        json.dumps(requirements_data)
    )
    requirements_ref = h.records.stage_record(requirements)
    plan_data = make("ReproductionPlan")
    plan_data.update(
        request_ref=request_ref.model_dump(mode="json"),
        environment_requirements_ref=requirements_ref.model_dump(mode="json"),
        sandbox_profile_ref=profile_ref.model_dump(mode="json"),
        purpose=request.purpose,
        hypothesis_ref=request.hypothesis_ref.model_dump(mode="json"),
    )
    plan = ReproductionPlan.model_validate_json(json.dumps(plan_data))
    plan_ref = h.records.stage_record(plan)
    process_data = make("HypothesisProcessState")
    process_data.update(
        status="ASSIGNED",
        verification_generation=2 if invalid == "generation" else 1,
        verification_assignment_ref=request.verification_assignment_ref.model_dump(
            mode="json"
        ),
    )
    process = HypothesisProcessState.model_validate_json(json.dumps(process_data))
    target = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=metadata("work_execution_state", "sandbox-work", code=True)
                | {"hypothesis_id": "h1"},
                work_id="sandbox-work",
                work_type="DYNAMIC_REPRO",
                subject_type="HYPOTHESIS",
                subject_id="h1",
                status="RUNNING",
                active_attempt_id="at1",
                state_version=2,
                last_transition_ref=ref("state_transition", True),
                parent_work_ref=ref("work_execution_state", True),
                started_at="2026-09-07T00:00:00Z",
                input_refs=[request_ref.model_dump(mode="json")],
            )
        )
    )
    for record in (requirements, plan, process, target):
        h.publish(record)
        if invalid == "plan" and record == plan:
            continue
        with h.database.write() as connection:
            connection.execute(
                insert(models.current_records).values(
                    logical_record_id=str(record.meta.logical_record_id),
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
    with h.database.write() as connection:
        connection.execute(
            insert(models.work_states).values(
                work_id=str(target.work_id),
                analysis_id="a1",
                registration_key=target.dedupe_key,
                state_version=2,
                status="RUNNING",
                payload=target.model_dump_json(),
            )
        )
    # Configs are pinned exact values, not global current-record projections.
    other_profile = profile.model_copy(
        update={
            "meta": profile.meta.model_copy(
                update={
                    "record_id": RecordId("other-profile"),
                    "logical_record_id": LogicalRecordId("other-profile"),
                }
            )
        }
    )
    other_profile = SandboxProfile.model_validate_json(other_profile.model_dump_json())
    other_profile_ref = h.records.stage_record(other_profile)
    h.publish(other_profile)
    lifecycle_record = h.records.get_exact(lifecycle)
    assert isinstance(lifecycle_record, DynamicReproductionLifecycleProfile)
    other_lifecycle = type(lifecycle_record).model_validate_json(
        lifecycle_record.model_copy(
            update={
                "meta": lifecycle_record.meta.model_copy(
                    update={
                        "record_id": RecordId("other-lifecycle"),
                        "logical_record_id": LogicalRecordId("other-lifecycle"),
                    }
                )
            }
        ).model_dump_json()
    )
    other_lifecycle_ref = h.records.stage_record(other_lifecycle)
    h.publish(other_lifecycle)
    chosen_profile = other_profile_ref if invalid == "profile" else profile_ref
    chosen_lifecycle = other_lifecycle_ref if invalid == "lifecycle" else lifecycle
    h.evidence.identities[profile_ref] = RequesterRole.REPRODUCTION_SETUP_AUTOMATION
    candidate = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=metadata("action_request", "sandbox-action", code=True)
                | {"hypothesis_id": "h1", "attempt_id": "at1"},
                action_id="sandbox-action",
                action_type="RUN_SANDBOX",
                requested_by="REPRODUCTION_SETUP_AUTOMATION",
                requester_identity_ref=profile_ref.model_dump(mode="json"),
                work_ref=reference(target).model_dump(mode="json"),
                expected_state_version=2,
                dynamic_request_ref=request_ref.model_dump(mode="json"),
                reproduction_plan_ref=plan_ref.model_dump(mode="json"),
                sandbox_profile_ref=chosen_profile.model_dump(mode="json"),
                resource_profile_ref=chosen_lifecycle.model_dump(mode="json"),
                run_policy_state_ref=ref("run_policy_state", True),
                input_refs=[
                    r.model_dump(mode="json")
                    for r in (
                        request_ref,
                        requirements_ref,
                        plan_ref,
                        chosen_profile,
                        chosen_lifecycle,
                    )
                ],
            )
        )
    )
    decision = runtime.validator.authorize(candidate)
    state = next(
        check for check in decision.check_results if check.check_type == "STATE"
    )
    assert state.result == ("PASS" if invalid is None else "FAIL"), state.reason_code
    if invalid is None:
        assert {profile_ref, lifecycle}.issubset(decision.checked_config_refs)
