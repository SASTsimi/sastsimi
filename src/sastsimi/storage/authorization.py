"""Derive immutable ActionDecision and check projections from trusted evidence."""

from __future__ import annotations

from contextlib import nullcontext
from datetime import timedelta
from typing import Protocol

from sqlalchemy import Connection, insert, select

from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    CheckType,
)
from sastsimi.contracts.budget import BudgetProfileBinding, BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import DecisionId, ErrorId, LogicalRecordId, RecordId
from sastsimi.contracts.records import RunMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator

from . import models
from .action_context import check_owner
from .action_policy import check_role
from .codec import REF_ADAPTER, reference
from .current_inputs import check_current_input
from .output_closures import derive_outputs
from .repositories import SQLiteRecordStore
from .run_states import get_run
from .stage_policy import check_stage


class AuthorizationContext(Protocol):
    records: SQLiteRecordStore
    clock: Clock
    ids: IdGenerator

    def check_reservation(
        self,
        connection: Connection,
        ref: RecordRef | None,
        action: ActionRequest,
        work: WorkExecutionState,
    ) -> BudgetReservation: ...


def authorize(
    validator: AuthorizationContext,
    action: ActionRequest,
    work: WorkExecutionState | None,
    reservation_ref: RecordRef | None,
    *,
    _connection: Connection | None = None,
) -> ActionDecision:
    records = validator.records
    action = ActionRequest.model_validate(action)
    run_finalization = (
        action.action_type == ActionType.SAVE_RESULT
        and action.result_kind == "analysis_run_result"
        and action.work_ref is None
        and isinstance(action.meta, RunMeta)
    )
    with (
        records.database.write()
        if _connection is None
        else nullcontext(_connection) as connection
    ):
        prior = (
            connection.execute(
                select(models.action_requests).where(
                    models.action_requests.c.action_id == str(action.action_id)
                )
            )
            .mappings()
            .first()
        )
        if prior is not None:
            if REF_ADAPTER.validate_json(prior["request_ref"]) != reference(action):
                raise ValueError("ACTION_IMMUTABLE")
            old = records.resolve(
                connection, REF_ADAPTER.validate_json(prior["decision_ref"])
            )
            assert isinstance(old, ActionDecision)
            return old
        request_ref = records.stage(connection, action)
        records.publish(connection, request_ref)
        if work is None and action.work_ref is not None:
            resolved = records.resolve(connection, action.work_ref)
            work = resolved if isinstance(resolved, WorkExecutionState) else None
        config_refs: list[BudgetScopeRef] = []
        outputs: tuple[RecordRef, ...] = ()
        checks = []
        for kind in sorted(
            REQUIRED_CHECKS[action.action_type], key=lambda value: value.value
        ):
            passed = True
            reason = "OK"
            try:
                if records.database.recovery_failed:
                    raise ValueError("RECOVERY_FAILED")
                if kind == CheckType.AUTHORITY:
                    role = records.evidence.identity_role(action.requester_identity_ref)
                    check_role(action, role)
                elif kind in {CheckType.IDENTITY, CheckType.STATE, CheckType.REVISION}:
                    if run_finalization:
                        state = get_run(connection, str(action.meta.analysis_id))
                        if state.status != "RUNNING":
                            raise ValueError("ANALYSIS_ALREADY_TERMINAL")
                    else:
                        if (
                            work is None
                            or action.meta.analysis_id != work.meta.analysis_id
                        ):
                            raise ValueError("IDENTITY_MISMATCH")
                        check_owner(records, connection, action, work)
                        check_stage(records, connection, action, work)
                        if action.action_type == ActionType.RUN_SANDBOX:
                            assert action.sandbox_profile_ref is not None
                            assert action.resource_profile_ref is not None
                            config_refs.extend(
                                (
                                    action.sandbox_profile_ref,
                                    action.resource_profile_ref,
                                )
                            )
                        if action.work_ref is not None:
                            current_payload = connection.execute(
                                select(models.work_states.c.payload).where(
                                    models.work_states.c.work_id == str(work.work_id)
                                )
                            ).scalar()
                            if (
                                current_payload is None
                                or WorkExecutionState.model_validate_json(
                                    current_payload
                                )
                                != work
                                or action.work_ref != reference(work)
                                or action.expected_state_version != work.state_version
                            ):
                                raise ValueError("STATE_VERSION_CONFLICT")
                        elif (
                            action.action_type != ActionType.REGISTER_WORK
                            or work.status.value != "PENDING"
                        ):
                            raise ValueError("STATE_VERSION_CONFLICT")
                        for ref in action.input_refs:
                            check_current_input(records, connection, ref)
                elif kind == CheckType.BUDGET:
                    if work is None:
                        raise ValueError("BUDGET_UNAVAILABLE")
                    reservation = validator.check_reservation(
                        connection, reservation_ref, action, work
                    )
                    config_refs.append(reservation.budget_binding_ref)
                    scope = records.resolve(connection, reservation.budget_binding_ref)
                    if isinstance(scope, BudgetProfileBinding):
                        config_refs.extend(
                            (
                                scope.work_budget_profile_ref,
                                scope.verification_budget_profile_ref,
                                scope.dynamic_lifecycle_profile_ref,
                            )
                        )
                elif kind == CheckType.SCHEMA:
                    outputs = derive_outputs(records, connection, action)
                else:
                    evidence = records.evidence.action_evidence(action, kind)
                    if evidence is None:
                        raise ValueError(kind.value + "_UNPROVEN")
                    for ref in evidence:
                        records.resolve(connection, ref)
                    config_refs.extend(evidence)
            except (ValueError, LookupError) as error:
                passed, reason = False, str(error)
            checks.append(
                ActionCheck(
                    check_type=kind,
                    result=CheckResult.PASS if passed else CheckResult.FAIL,
                    reason_code=reason,
                    safe_message="Trusted runtime check passed."
                    if passed
                    else "Trusted runtime check failed.",
                )
            )
        allowed = all(check.result == CheckResult.PASS for check in checks)
        record_id = validator.ids.new(RecordId)
        meta = action.meta.model_dump() | dict(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type="action_decision",
            revision_number=1,
            previous_record_id=None,
            created_at=validator.clock.now(),
        )
        decision = ActionDecision.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta,
                    decision_id=validator.ids.new(DecisionId),
                    action_ref=request_ref,
                    decision="ALLOW" if allowed else "DENY",
                    required_checks=tuple(check.check_type for check in checks),
                    check_results=tuple(checks),
                    checked_state_version=work.state_version if work else None,
                    checked_config_refs=tuple(dict.fromkeys(config_refs)),
                    valid_until=validator.clock.now() + timedelta(minutes=1)
                    if allowed
                    else None,
                    error_ids=() if allowed else (validator.ids.new(ErrorId),),
                    use_status="UNUSED" if allowed else "NOT_USED",
                    used_at=None,
                    expired_at=None,
                    expire_reason=None,
                    outcome_refs=(),
                    decided_at=validator.clock.now(),
                )
            )
        )
        decision_ref = records.stage(connection, decision)
        records.publish(connection, decision_ref)
        connection.execute(
            insert(models.action_requests).values(
                action_id=str(action.action_id),
                request_ref=canonical_bytes(request_ref).decode(),
                decision_ref=canonical_bytes(decision_ref).decode(),
            )
        )
        connection.execute(
            insert(models.action_output_closures).values(
                action_id=str(action.action_id),
                decision_ref=canonical_bytes(decision_ref).decode(),
                output_refs=canonical_bytes(outputs).decode(),
                content_hash=content_hash([request_ref, decision_ref, outputs]),
            )
        )
        for check in checks:
            connection.execute(
                insert(models.action_checks).values(
                    action_id=str(action.action_id),
                    check_type=check.check_type.value,
                    payload=canonical_bytes(check).decode(),
                )
            )
        return decision
