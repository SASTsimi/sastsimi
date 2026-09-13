import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    validate_decision_for_action,
)
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    BudgetReservation,
    BudgetUnits,
    ExecutionBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.ids import AnalysisId, WorkspaceId
from sastsimi.contracts.records import RunMeta, validate_revision
from sastsimi.contracts.work import (
    StateTransition,
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
)


def mutations(*values: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    return values


@pytest.mark.parametrize(
    "status",
    ["PENDING", "READY", "RUNNING", "BLOCKED", "SUCCEEDED", "FAILED", "CANCELLED"],
)
def test_valid_work_states_preserve_lifecycle(status: str) -> None:
    data = work(status=status)
    if status != "PENDING":
        data.update(state_version=2, last_transition_ref=ref("state_transition"))
    if status == "RUNNING":
        data.update(active_attempt_id="at1", started_at="2026-09-07T00:00:00Z")
    elif status == "BLOCKED":
        data.update(waiting_for=["BUDGET"], stop_reason="Budget unavailable")
    elif status in {"SUCCEEDED", "FAILED", "CANCELLED"}:
        data.update(
            finished_at="2026-09-07T00:01:00Z",
            stop_reason="COMPLETED" if status == "SUCCEEDED" else status,
        )
        if status == "FAILED":
            data.update(error_ids=["e1"])
    assert (
        WorkExecutionState.model_validate_json(json.dumps(data)).status.value == status
    )


@pytest.mark.parametrize(
    "kind",
    [
        "READ_CODE",
        "RUN_TOOL",
        "SAVE_RESULT",
        "CALL_LLM",
        "RESTART_VERIFICATION_GENERATION",
        "REQUEST_DYNAMIC_REPRO",
        "RUN_SANDBOX",
    ],
)
def test_valid_action_shapes(kind: str) -> None:
    data = action(
        meta=meta(True),
        action_type=kind,
        work_ref=ref(code=True),
        expected_state_version=1,
    )
    if kind in {"READ_CODE", "RUN_TOOL"}:
        data["file_paths"] = ["src/example.py"]
    if kind == "RUN_TOOL":
        data["tool_name"] = "approved-tool"
    if kind == "SAVE_RESULT":
        data.update(
            result_kind="example_result",
            candidate_result_ref=ref("example_result", True),
        )
    if kind == "CALL_LLM":
        data.update(
            llm_call_spec_ref=ref("llm_call_spec", True),
            provider_profile_ref=ref("provider_profile", True),
            session_mode="NEW",
        )
    if kind == "RESTART_VERIFICATION_GENERATION":
        data.update(
            meta=meta(True, hypothesis_id="h1"),
            requested_by="VERIFICATION",
            expected_verification_generation=1,
            generation_restart_reason="DYNAMIC_REQUEST_REPLACEMENT_REQUIRED",
            generation_restart_basis_refs=[ref("basis", True)],
            dynamic_request_ref=ref("dynamic_reproduction_request", True),
            sandbox_profile_ref=ref("sandbox_profile", True),
            input_refs=[
                ref(name, True)
                for name in (
                    "hypothesis_process_state",
                    "verification_assignment",
                    "work_execution_state",
                    "dynamic_reproduction_request",
                    "sandbox_profile",
                    "playbook_policy",
                    "verification_playbook",
                    "basis",
                )
            ]
            + [ref(code=True) | {"record_id": "dynamic-work"}],
        )
    if kind in {"REQUEST_DYNAMIC_REPRO", "RUN_SANDBOX"}:
        data["dynamic_request_ref"] = ref("dynamic_reproduction_request", True)
    if kind == "RUN_SANDBOX":
        data.update(
            reproduction_plan_ref=ref("reproduction_plan", True),
            sandbox_profile_ref=ref("sandbox_profile", True),
            resource_profile_ref=ref("dynamic_reproduction_lifecycle_profile", True),
            run_policy_state_ref=ref("run_policy_state", True),
            input_refs=[
                ref(name, True)
                for name in [
                    "dynamic_reproduction_request",
                    "reproduction_plan",
                    "sandbox_profile",
                    "dynamic_reproduction_lifecycle_profile",
                    "environment_requirements",
                    "recipe_source",
                ]
            ],
            resource_limits={"memory_limit_bytes": 1024},
        )
    model = ActionRequest.model_validate_json(json.dumps(data))
    assert model.action_type.value == kind
    if model.resource_limits is not None:
        from sastsimi.contracts.canonical_json import canonical_bytes

        assert b'"resource_limits":{"memory_limit_bytes":1024}' in canonical_bytes(
            model
        )


def meta(code: bool = False, **changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = dict(
        record_id="r1",
        logical_record_id="l1",
        record_type="work_execution_state",
        schema_version="1.0.0",
        analysis_id="a1",
        revision_number=1,
        previous_record_id=None,
        created_at="2026-09-07T00:00:00Z",
    )
    if code:
        value.update(
            workspace_id="w1", commit_id="c1", hypothesis_id=None, attempt_id=None
        )
    return value | changes


def ref(kind: str = "work_execution_state", code: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = dict(
        stored_data_id="s1", data_kind=kind, content_hash="a" * 64, record_id="r1"
    )
    return value | (
        dict(workspace_id="w1", commit_id="c1") if code else dict(analysis_id="a1")
    )


def work(**changes: Any) -> dict[str, Any]:
    return (
        dict(
            meta=meta(),
            work_id="w1",
            parent_work_ref=None,
            work_type="WORKSPACE_PREP",
            subject_type="ANALYSIS",
            subject_id="a1",
            work_generation=1,
            status="PENDING",
            state_version=1,
            last_transition_ref=None,
            last_transition_commit_ref=None,
            active_attempt_id=None,
            input_hash="a" * 64,
            dedupe_key="b" * 64,
            trigger_primitive_ref=None,
            input_refs=[],
            output_refs=[],
            gap_ids=[],
            error_ids=[],
            waiting_for=[],
            stop_reason=None,
            started_at=None,
            finished_at=None,
            elapsed_ms=0,
        )
        | changes
    )


def action(**changes: Any) -> dict[str, Any]:
    return (
        dict(
            meta=meta(),
            action_id="ac1",
            requested_by="ORCHESTRATION",
            requester_identity_ref=ref("identity"),
            action_type="REGISTER_WORK",
            work_ref=None,
            expected_state_version=None,
            expected_verification_generation=None,
            generation_restart_reason=None,
            generation_restart_basis_refs=[],
            input_refs=[],
            dynamic_request_ref=None,
            reproduction_plan_ref=None,
            result_kind=None,
            candidate_result_ref=None,
            llm_call_spec_ref=None,
            tool_name=None,
            file_paths=[],
            provider_profile_ref=None,
            session_mode=None,
            sandbox_profile_ref=None,
            resource_profile_ref=None,
            run_policy_state_ref=None,
            image_digest=None,
            network_targets=[],
            resource_limits=None,
            reason="Register work",
            requested_at="2026-09-07T00:00:00Z",
        )
        | changes
    )


def decision(**changes: Any) -> dict[str, Any]:
    checks = ["SCHEMA", "AUTHORITY", "IDENTITY", "REVISION", "STATE", "BUDGET"]
    return (
        dict(
            meta=meta(),
            decision_id="d1",
            action_ref=ref("action_request"),
            decision="ALLOW",
            required_checks=checks,
            check_results=[
                dict(
                    check_type=c, result="PASS", reason_code="OK", safe_message="Passed"
                )
                for c in checks
            ],
            checked_state_version=None,
            checked_config_refs=[],
            valid_until="2026-09-07T00:01:00Z",
            error_ids=[],
            use_status="UNUSED",
            used_at=None,
            expired_at=None,
            expire_reason=None,
            outcome_refs=[],
            decided_at="2026-09-07T00:00:00Z",
        )
        | changes
    )


def test_strict_immutable_ids_and_nulls() -> None:
    assert AnalysisId("opaque") != WorkspaceId("opaque")
    with pytest.raises(ValidationError):
        AnalysisId.model_validate(WorkspaceId("opaque"))
    model = RunMeta.model_validate_json(json.dumps(meta()))
    assert model.model_dump()["previous_record_id"] is None
    with pytest.raises(ValidationError):
        model.analysis_id = AnalysisId("other")
    for changes in mutations(
        dict(revision_number="1"),
        dict(revision_number=True),
        dict(created_at="2026-09-07T00:00:00"),
        dict(unexpected=1),
        dict(revision_number=2),
        dict(previous_record_id="r1"),
    ):
        with pytest.raises(ValidationError):
            RunMeta.model_validate_json(json.dumps(meta(**changes)))
    with pytest.raises(ValidationError):
        WorkExecutionState.model_validate(work())
    assert isinstance(datetime.now(UTC), datetime)


def test_revision_chain_exact_previous_and_scope() -> None:
    first = RunMeta.model_validate_json(json.dumps(meta()))
    next_data = meta(record_id="r2", revision_number=2, previous_record_id="r1")
    validate_revision(first, RunMeta.model_validate_json(json.dumps(next_data)))
    for changes in mutations(
        dict(previous_record_id="wrong"),
        dict(revision_number=3),
        dict(logical_record_id="other"),
        dict(analysis_id="other"),
        dict(created_at="2026-09-06T00:00:00Z"),
    ):
        with pytest.raises(ValueError):
            validate_revision(
                first, RunMeta.model_validate_json(json.dumps(next_data | changes))
            )


@pytest.mark.parametrize(
    "changes",
    [
        dict(state_version=0),
        dict(work_generation=0),
        dict(elapsed_ms=-1),
        dict(status="RUNNING"),
        dict(status="BLOCKED"),
        dict(status="SUCCEEDED"),
        dict(status="FAILED", finished_at="2026-09-07T00:01:00Z", stop_reason="error"),
        dict(
            status="PARTIAL",
            finished_at="2026-09-07T00:01:00Z",
            stop_reason="partial",
            output_refs=[ref()],
        ),
        dict(active_attempt_id="at1"),
        dict(output_refs=[ref()]),
        dict(subject_id="another"),
        dict(trigger_primitive_ref=ref("primitive", True)),
    ],
)
def test_invalid_work_shapes_fail_closed(changes: dict[str, Any]) -> None:
    WorkExecutionState.model_validate_json(json.dumps(work()))
    with pytest.raises(ValidationError):
        WorkExecutionState.model_validate_json(json.dumps(work(**changes)))


def test_attempt_and_transition_rules() -> None:
    data = dict(
        meta=meta(),
        work_id="w1",
        attempt_id="at1",
        attempt_number=1,
        trigger="INITIAL",
        input_hash="a" * 64,
        status="RUNNING",
        output_refs=[],
        gap_ids=[],
        error_ids=[],
        started_at="2026-09-07T00:00:00Z",
        finished_at=None,
        elapsed_ms=0,
    )
    WorkAttempt.model_validate_json(json.dumps(data))
    for changes in mutations(
        dict(attempt_number=0),
        dict(trigger="RETRY"),
        dict(status="FAILED"),
        dict(finished_at="2026-09-07T00:01:00Z"),
        dict(meta=meta(True, attempt_id="other")),
    ):
        with pytest.raises(ValidationError):
            WorkAttempt.model_validate_json(json.dumps(data | changes))
    transition = dict(
        meta=meta(),
        transition_id="tr1",
        work_id="w1",
        action_decision_ref=ref("action_decision"),
        from_status="PENDING",
        to_status="READY",
        expected_state_version=1,
        new_state_version=2,
        attempt_id=None,
        cause="Inputs ready",
        output_refs=[],
        gap_ids=[],
        error_ids=[],
        dedupe_key="b" * 64,
        created_at="2026-09-07T00:00:00Z",
    )
    StateTransition.model_validate_json(json.dumps(transition))
    for changes in mutations(
        dict(new_state_version=3),
        dict(from_status="SUCCEEDED"),
        dict(to_status="PENDING"),
        dict(action_decision_ref=ref("action_decision") | {"record_id": None}),
    ):
        with pytest.raises(ValidationError):
            StateTransition.model_validate_json(json.dumps(transition | changes))
    commit = dict(
        meta=meta(),
        transition_commit_id="tc1",
        work_id="w1",
        transition_ref=ref("state_transition"),
        expected_state_version=1,
        target_state_version=2,
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
    TransitionCommit.model_validate_json(json.dumps(commit))
    for changes in mutations(
        dict(state="COMMITTED"),
        dict(state="ABORTED"),
        dict(target_state_version=4),
        dict(committed_at="2026-09-06T00:00:00Z"),
    ):
        with pytest.raises(ValidationError):
            TransitionCommit.model_validate_json(json.dumps(commit | changes))


@pytest.mark.parametrize(
    "changes",
    [
        dict(reason=" "),
        dict(work_ref=ref()),
        dict(action_type="READ_CODE"),
        dict(action_type="RUN_TOOL"),
        dict(action_type="SAVE_RESULT"),
        dict(action_type="CALL_LLM"),
        dict(action_type="RUN_SANDBOX"),
        dict(action_type="RESTART_VERIFICATION_GENERATION"),
        dict(expected_verification_generation=1),
        dict(tool_name="git"),
        dict(file_paths=["file"]),
        dict(result_kind="anything"),
        dict(network_targets=["host"]),
    ],
)
def test_action_specific_shape(changes: dict[str, Any]) -> None:
    ActionRequest.model_validate_json(json.dumps(action()))
    with pytest.raises(ValidationError):
        ActionRequest.model_validate_json(json.dumps(action(**changes)))


@pytest.mark.parametrize(
    "changes",
    [
        dict(required_checks=["SCHEMA"]),
        dict(check_results=[]),
        dict(use_status="USED"),
        dict(use_status="EXPIRED"),
        dict(decision="DENY"),
        dict(used_at="2026-09-07T00:00:01Z"),
        dict(valid_until="2026-09-06T00:00:00Z"),
        dict(error_ids=["err"]),
        dict(outcome_refs=[ref()]),
    ],
)
def test_decision_consistency(changes: dict[str, Any]) -> None:
    model = ActionDecision.model_validate_json(json.dumps(decision()))
    validate_decision_for_action(model, ActionType.REGISTER_WORK)
    with pytest.raises(ValueError):
        validate_decision_for_action(model, ActionType.READ_CODE)
    with pytest.raises(ValidationError):
        ActionDecision.model_validate_json(json.dumps(decision(**changes)))


def units() -> dict[str, Any]:
    return dict(
        elapsed_ms=0,
        work_count=1,
        llm_call_count=0,
        retry_count=0,
        cost_minor_units=0,
        currency="USD",
    )


def test_budget_nonnegative_approval_binding_and_reservation() -> None:
    for key in [
        "elapsed_ms",
        "work_count",
        "llm_call_count",
        "retry_count",
        "cost_minor_units",
    ]:
        with pytest.raises(ValidationError):
            BudgetUnits.model_validate_json(json.dumps(units() | {key: -1}))
    profile = dict(
        meta=meta(),
        profile_key="approved",
        purpose="PRODUCTION",
        approval_ref=None,
        approved_by=None,
        approved_at=None,
        max_analysis_elapsed_ms=100,
        max_total_cost_minor_units=100,
        currency="USD",
        pricing_revision_ref=ref("pricing"),
        max_total_work=10,
        max_total_llm_calls=10,
        max_total_retries=1,
        max_parallel_work=2,
        status="DRAFT",
    )
    ExecutionBudgetProfile.model_validate_json(json.dumps(profile))
    with pytest.raises(ValidationError):
        ExecutionBudgetProfile.model_validate_json(
            json.dumps(profile | {"status": "ACTIVE"})
        )
    binding = dict(
        meta=meta(True),
        binding_key="full",
        purpose="PRODUCTION",
        execution_budget_profile_ref=ref("execution_budget_profile"),
        work_budget_profile_ref=ref("work_budget_profile", True),
        verification_budget_profile_ref=ref("verification_budget_profile", True),
        dynamic_lifecycle_profile_ref=ref(
            "dynamic_reproduction_lifecycle_profile", True
        ),
        status="DRAFT",
        approval_ref=None,
        approved_by=None,
        approved_at=None,
    )
    BudgetProfileBinding.model_validate_json(json.dumps(binding))
    with pytest.raises(ValidationError):
        BudgetProfileBinding.model_validate_json(
            json.dumps(
                binding
                | {
                    "work_budget_profile_ref": ref("work_budget_profile", True)
                    | {"commit_id": "other"}
                }
            )
        )
    reservation = dict(
        meta=meta(),
        reservation_id="res1",
        budget_binding_ref=ref("execution_budget_profile"),
        action_ref=ref("action_request"),
        work_ref=ref(),
        requested_units=units(),
        status="RESERVED",
        ledger_entry_ref=None,
        reserved_at="2026-09-07T00:00:00Z",
        finalized_at=None,
    )
    BudgetReservation.model_validate_json(json.dumps(reservation))
    for changes in mutations(
        dict(status="COMMITTED"),
        dict(status="RELEASED"),
        dict(ledger_entry_ref=ref("budget_ledger_entry")),
        dict(budget_binding_ref=ref("wrong")),
    ):
        with pytest.raises(ValidationError):
            BudgetReservation.model_validate_json(json.dumps(reservation | changes))


def test_work_budget_deny_unlisted_and_duplicate_limits() -> None:
    limit = dict(
        limit_key="one",
        work_type="STATIC_TOOL",
        operation_kind="STATIC_TOOL",
        agent_role="STATIC_ANALYSIS",
        timeout_ms=100,
        max_attempts=1,
        max_calls_per_work=None,
        max_items_per_work=None,
    )
    profile = dict(
        meta=meta(True),
        profile_key="static",
        purpose="PRODUCTION",
        limits=[limit],
        unlisted_operation="DENY",
        status="DRAFT",
    )
    WorkBudgetProfile.model_validate_json(json.dumps(profile))
    for changes in mutations(
        dict(unlisted_operation="ALLOW"),
        dict(limits=[limit, limit]),
        dict(limits=[limit, limit | {"limit_key": "two"}]),
        dict(meta=meta(True, hypothesis_id="h1")),
        dict(limits=[limit | {"timeout_ms": -1}]),
    ):
        with pytest.raises(ValidationError):
            WorkBudgetProfile.model_validate_json(json.dumps(profile | changes))


def test_alias_declarations_are_not_allowed() -> None:
    from pydantic import Field

    with pytest.raises(TypeError):

        class Aliased(ContractModel):
            name: str = Field(alias="other")


def test_run_profile_permits_canonical_code_scoped_pricing_reference() -> None:
    data = dict(
        meta=meta(),
        profile_key="approved",
        purpose="PRODUCTION",
        approval_ref=ref("approval", True),
        approved_by="R8",
        approved_at="2026-09-07T00:00:00Z",
        max_analysis_elapsed_ms=100,
        max_total_cost_minor_units=100,
        currency="USD",
        pricing_revision_ref=ref("pricing", True),
        max_total_work=10,
        max_total_llm_calls=10,
        max_total_retries=1,
        max_parallel_work=2,
        status="ACTIVE",
    )
    assert (
        ExecutionBudgetProfile.model_validate_json(json.dumps(data)).approved_by == "R8"
    )


def test_python_subject_ids_remain_distinct() -> None:
    model = WorkExecutionState.model_validate_json(json.dumps(work()))
    payload = {name: getattr(model, name) for name in type(model).model_fields}
    assert WorkExecutionState.model_validate(payload).subject_id == AnalysisId("a1")
    with pytest.raises(ValidationError):
        WorkExecutionState.model_validate(payload | {"subject_id": WorkspaceId("a1")})


def test_non_workspace_work_requires_record_metadata() -> None:
    with pytest.raises(ValidationError):
        WorkExecutionState.model_validate_json(
            json.dumps(work(work_type="STATIC_TOOL"))
        )


def test_work_and_attempt_context_invariants() -> None:
    from sastsimi.contracts.work import (
        validate_attempt_context,
        validate_transition_context,
    )

    running_data = work(
        status="RUNNING",
        active_attempt_id="at1",
        state_version=3,
        last_transition_ref=ref("state_transition"),
        started_at="2026-09-07T00:00:00Z",
    )
    running = WorkExecutionState.model_validate_json(json.dumps(running_data))
    attempt_data = dict(
        meta=meta(),
        work_id="w1",
        attempt_id="at1",
        attempt_number=1,
        trigger="INITIAL",
        input_hash="a" * 64,
        status="RUNNING",
        output_refs=[],
        gap_ids=[],
        error_ids=[],
        started_at="2026-09-07T00:00:00Z",
        finished_at=None,
        elapsed_ms=0,
    )
    attempt = WorkAttempt.model_validate_json(json.dumps(attempt_data))
    validate_attempt_context(attempt, running)
    with pytest.raises(ValueError):
        validate_attempt_context(
            WorkAttempt.model_validate_json(
                json.dumps(attempt_data | {"input_hash": "b" * 64})
            ),
            running,
        )
    transition_data = dict(
        meta=meta(),
        transition_id="tr1",
        work_id="w1",
        action_decision_ref=ref("action_decision"),
        from_status="RUNNING",
        to_status="READY",
        expected_state_version=3,
        new_state_version=4,
        attempt_id="at1",
        cause="retry",
        output_refs=[],
        gap_ids=[],
        error_ids=[],
        dedupe_key="b" * 64,
        created_at="2026-09-07T00:00:00Z",
    )
    transition = StateTransition.model_validate_json(json.dumps(transition_data))
    with pytest.raises(ValueError):
        validate_transition_context(transition, running)


def test_valid_decision_lifecycle_and_immutable_revision_fields() -> None:
    from sastsimi.contracts.actions import validate_decision_revision

    first = ActionDecision.model_validate_json(json.dumps(decision()))
    claimed_data = decision(
        meta=meta(record_id="r2", previous_record_id="r1", revision_number=2),
        use_status="USED",
        used_at="2026-09-07T00:00:01Z",
    )
    claimed = ActionDecision.model_validate_json(json.dumps(claimed_data))
    validate_decision_revision(first, claimed)
    outcome_data = claimed_data | dict(
        meta=meta(record_id="r3", previous_record_id="r2", revision_number=3),
        outcome_refs=[ref()],
    )
    outcome = ActionDecision.model_validate_json(json.dumps(outcome_data))
    validate_decision_revision(claimed, outcome)
    with pytest.raises(ValueError):
        validate_decision_revision(
            claimed,
            ActionDecision.model_validate_json(
                json.dumps(outcome_data | {"used_at": "2026-09-07T00:00:02Z"})
            ),
        )
    denied = decision(
        decision="DENY",
        check_results=[
            dict(
                check_type=c,
                result="FAIL" if c == "BUDGET" else "PASS",
                reason_code="denied",
                safe_message="Denied",
            )
            for c in decision()["required_checks"]
        ],
        valid_until=None,
        use_status="NOT_USED",
        error_ids=["err"],
    )
    assert ActionDecision.model_validate_json(json.dumps(denied)).valid_until is None


def test_budget_limit_selection_denies_missing_or_inactive() -> None:
    from sastsimi.contracts.budget import (
        BudgetAgentRole,
        OperationKind,
        select_work_limit,
    )
    from sastsimi.contracts.work import WorkType

    limit = dict(
        limit_key="static",
        work_type="STATIC_TOOL",
        operation_kind="STATIC_TOOL",
        agent_role="STATIC_ANALYSIS",
        timeout_ms=100,
        max_attempts=1,
        max_calls_per_work=None,
        max_items_per_work=None,
    )
    data = dict(
        meta=meta(True),
        profile_key="static",
        purpose="PRODUCTION",
        limits=[limit],
        unlisted_operation="DENY",
        status="ACTIVE",
    )
    profile = WorkBudgetProfile.model_validate_json(json.dumps(data))
    assert (
        select_work_limit(
            profile,
            WorkType.STATIC_TOOL,
            OperationKind.STATIC_TOOL,
            BudgetAgentRole.STATIC_ANALYSIS,
        ).timeout_ms
        == 100
    )
    with pytest.raises(ValueError):
        select_work_limit(
            profile, WorkType.STATIC_TOOL, OperationKind.STATIC_TOOL, None
        )
    with pytest.raises(ValueError):
        select_work_limit(
            WorkBudgetProfile.model_validate_json(
                json.dumps(data | {"status": "DRAFT"})
            ),
            WorkType.STATIC_TOOL,
            OperationKind.STATIC_TOOL,
            BudgetAgentRole.STATIC_ANALYSIS,
        )
