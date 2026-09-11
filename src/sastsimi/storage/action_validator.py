"""SQLite state/config checks and atomic single-use action authorization."""

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
    UseStatus,
    validate_decision_for_action,
)
from sastsimi.contracts.budget import BudgetProfileBinding, BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    PromptPayload,
    ProviderProfile,
)
from sastsimi.contracts.llm_closure import llm_action_input_refs
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.storage import models
from sastsimi.storage.codec import encode, reference
from sastsimi.storage.repositories import SQLiteRecordStore

from .action_context import check_owner
from .action_policy import check_role
from .budget_service import BudgetService
from .current_inputs import allowed_workspace_statuses, check_current_input
from .dispatches import mark_dispatched, mark_returned, reject_uncertain
from .records import next_meta
from .stage_policy import check_stage


class RuntimeValidator:
    def mark_dispatched(
        self,
        decision_ref: RecordRef,
        provider_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        from .codec import REF_ADAPTER

        with self.records.database.write() as connection:
            row = (
                connection.execute(
                    select(models.external_dispatches).where(
                        models.external_dispatches.c.decision_ref
                        == canonical_bytes(decision_ref).decode()
                    )
                )
                .mappings()
                .one()
            )
            decision = self.records.resolve(connection, decision_ref)
            if (
                not isinstance(decision, ActionDecision)
                or decision.valid_until is None
                or self.clock.now() > decision.valid_until
            ):
                raise ValueError("ACTION_EXPIRED_OR_DENIED")
            action = self.records.resolve(connection, decision.action_ref)
            assert isinstance(action, ActionRequest)
            payload = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.work_id == row["work_id"]
                )
            ).scalar_one()
            work = WorkExecutionState.model_validate_json(payload)
            if (
                action.action_type == ActionType.READ_CODE
                and work.work_type == "CONTEXT_RETRIEVAL"
            ):
                from .context_policy import require_context_request

                require_context_request(self.records, connection, action, work)
            check_role(
                action,
                self.records.evidence.identity_role(action.requester_identity_ref),
            )
            check_owner(self.records, connection, action, work)
            check_stage(self.records, connection, action, work)
            for ref in (*work.input_refs, *action.input_refs):
                check_current_input(
                    self.records,
                    connection,
                    ref,
                    workspace_statuses=allowed_workspace_statuses(action, work),
                )
            self.check_reservation(
                connection,
                REF_ADAPTER.validate_json(row["reservation_ref"]),
                action,
                work,
                allow_claimed=True,
            )
            mark_dispatched(
                self.records,
                self.clock,
                connection,
                decision_ref,
                provider_request_id,
                idempotency_key,
            )

    def mark_returned(self, decision_ref: RecordRef) -> None:
        mark_returned(self.records, self.clock, decision_ref)

    def authorize(
        self,
        action: ActionRequest,
        work: WorkExecutionState | None = None,
        reservation_ref: RecordRef | None = None,
    ) -> ActionDecision:
        from .authorization import authorize

        return authorize(self, action, work, reservation_ref)

    def claim_external(
        self, work_id: str, decision_ref: RecordRef, reservation_ref: RecordRef | None
    ) -> RecordRef:
        with self.records.database.write() as connection:
            if self.records.database.recovery_failed:
                raise ValueError("RECOVERY_FAILED")
            payload = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.work_id == work_id
                )
            ).scalar_one()
            work = WorkExecutionState.model_validate_json(payload)
            reject_uncertain(connection, work_id)
            if work.status.value != "RUNNING":
                raise ValueError("ATTEMPT_NOT_ACTIVE")
            decision = self.records.resolve(connection, decision_ref)
            if not isinstance(decision, ActionDecision):
                raise ValueError("ACTION_INVALID")
            action = self.records.resolve(connection, decision.action_ref)
            existing = (
                connection.execute(
                    select(models.external_dispatches).where(
                        models.external_dispatches.c.decision_ref
                        == canonical_bytes(decision_ref).decode()
                    )
                )
                .mappings()
                .first()
            )
            if existing is not None:
                if (
                    decision.valid_until is None
                    or self.clock.now() > decision.valid_until
                ):
                    raise ValueError("ACTION_EXPIRED_OR_DENIED")
                if (
                    existing["dispatched_at"] is None
                    and existing["reservation_ref"]
                    == canonical_bytes(reservation_ref).decode()
                    and existing["attempt_id"] == str(work.active_attempt_id)
                ):
                    if not isinstance(action, ActionRequest):
                        raise ValueError("ACTION_INVALID")
                    self.check_reservation(
                        connection, reservation_ref, action, work, allow_claimed=True
                    )
                    payload = connection.execute(
                        select(models.action_decisions.c.payload).where(
                            models.action_decisions.c.action_id
                            == str(action.action_id),
                        )
                    ).scalar_one()
                    return reference(ActionDecision.model_validate_json(payload))
                raise ValueError("ACTION_ALREADY_USED")
            allowed = {
                ActionType.READ_CODE,
                ActionType.RUN_TOOL,
                ActionType.CALL_LLM,
                ActionType.FETCH_POLICY,
                ActionType.RUN_SANDBOX,
                ActionType.CALL_TECHNICAL_GATE,
                ActionType.CALL_RULE_SCOPE_GATE,
                ActionType.CREATE_REPORT_DRAFT,
            }
            if (
                not isinstance(action, ActionRequest)
                or action.action_type not in allowed
            ):
                raise ValueError("ACTION_TYPE_MISMATCH")
            claimed = self.claim(
                connection,
                decision_ref,
                action.action_type,
                work,
                reservation_ref,
                needs_budget=True,
            )
            connection.execute(
                insert(models.external_dispatches).values(
                    action_id=str(action.action_id),
                    work_id=work_id,
                    attempt_id=str(work.active_attempt_id),
                    decision_ref=canonical_bytes(decision_ref).decode(),
                    reservation_ref=canonical_bytes(reservation_ref).decode(),
                    prepared_at=self.clock.now().isoformat(),
                )
            )
            return reference(claimed)

    def __init__(
        self,
        records: SQLiteRecordStore,
        budget: BudgetService,
        clock: Clock,
        ids: IdGenerator,
    ) -> None:
        self.records, self.budget, self.clock, self.ids = records, budget, clock, ids

    def check(
        self,
        connection: Connection,
        decision_ref: RecordRef,
        kind: ActionType,
        work: WorkExecutionState,
        reservation_ref: RecordRef | None = None,
        *,
        needs_budget: bool = False,
    ) -> tuple[ActionDecision, ActionRequest]:
        if self.records.database.recovery_failed:
            raise ValueError("RECOVERY_FAILED")
        decision = self.records.resolve(connection, decision_ref)
        if not isinstance(decision, ActionDecision):
            raise ValueError("ACTION_INVALID")
        action = self.records.resolve(connection, decision.action_ref)
        if not isinstance(action, ActionRequest) or action.action_type != kind:
            raise ValueError("ACTION_TYPE_MISMATCH")
        check_role(
            action, self.records.evidence.identity_role(action.requester_identity_ref)
        )
        check_owner(self.records, connection, action, work)
        check_stage(self.records, connection, action, work)
        issued = connection.execute(
            select(models.action_requests.c.decision_ref).where(
                models.action_requests.c.action_id == str(action.action_id)
            )
        ).scalar()
        from .codec import REF_ADAPTER

        if issued is None or REF_ADAPTER.validate_json(issued) != decision_ref:
            raise ValueError("AUTHORITY_DENIED: decision was not issued by validator")
        validate_decision_for_action(decision, kind)
        if (
            decision.decision != Decision.ALLOW
            or decision.use_status != UseStatus.UNUSED
            or decision.valid_until is None
            or not decision.decided_at <= self.clock.now() <= decision.valid_until
        ):
            raise ValueError("ACTION_EXPIRED_OR_DENIED")
        if connection.execute(
            select(models.action_decisions.c.decision_id).where(
                models.action_decisions.c.action_id == str(action.action_id)
            )
        ).first():
            raise ValueError("ACTION_ALREADY_USED")
        if (
            decision.meta.analysis_id != work.meta.analysis_id
            or action.meta.analysis_id != work.meta.analysis_id
        ):
            raise ValueError("ACTION_ANALYSIS_MISMATCH")
        if action.work_ref is not None and (
            action.work_ref != reference(work)
            or action.expected_state_version != work.state_version
            or decision.checked_state_version != work.state_version
        ):
            raise ValueError("STATE_VERSION_CONFLICT")
        for ref in (*work.input_refs, *action.input_refs):
            check_current_input(
                self.records,
                connection,
                ref,
                workspace_statuses=allowed_workspace_statuses(action, work),
            )
            try:
                resolved = self.records.resolve(connection, ref)
            except LookupError:
                if isinstance(ref, RunStoredDataRef) and ref.record_id is None:
                    if (
                        ref.data_kind != "artifact"
                        or ref.analysis_id != work.meta.analysis_id
                        or str(ref.stored_data_id) != ref.content_hash
                    ):
                        raise ValueError("ACTION_RUN_ARTIFACT_INVALID") from None
                    continue
                if isinstance(ref, StoredDataRef) and ref.record_id is None:
                    continue
                raise
            if (
                getattr(resolved.meta, "analysis_id", work.meta.analysis_id)
                != work.meta.analysis_id
            ):
                raise ValueError("ACTION_INPUT_SCOPE_MISMATCH")
        if needs_budget:
            reservation = self.check_reservation(
                connection, reservation_ref, action, work
            )
            scope = self.records.resolve(connection, reservation.budget_binding_ref)
            if isinstance(scope, BudgetProfileBinding) and any(
                ref not in decision.checked_config_refs
                for ref in (
                    reservation.budget_binding_ref,
                    scope.work_budget_profile_ref,
                )
            ):
                raise ValueError(
                    "BUDGET checked binding/work profile references are required"
                )
        return decision, action

    def check_reservation(
        self,
        connection: Connection,
        ref: RecordRef | None,
        action: ActionRequest,
        work: WorkExecutionState,
        *,
        allow_claimed: bool = False,
    ) -> BudgetReservation:
        if ref is None:
            raise ValueError("BUDGET reservation required")
        reservation = self.records.resolve(connection, ref)
        if not isinstance(reservation, BudgetReservation):
            raise ValueError("BUDGET reservation required")
        if (
            action.action_type == ActionType.REGISTER_WORK
            and reservation.requested_units.work_count < 1
        ):
            raise ValueError("BUDGET reservation must include the new work")
        if (
            action.action_type
            in {
                ActionType.CALL_LLM,
                ActionType.CALL_TECHNICAL_GATE,
                ActionType.CALL_RULE_SCOPE_GATE,
                ActionType.CREATE_REPORT_DRAFT,
            }
            and reservation.requested_units.llm_call_count < 1
        ):
            raise ValueError("BUDGET reservation must include the LLM call")
        row = (
            connection.execute(
                select(models.budget_reservations).where(
                    models.budget_reservations.c.reservation_id
                    == str(reservation.reservation_id)
                )
            )
            .mappings()
            .first()
        )
        if (
            row is None
            or row["status"] != "RESERVED"
            or (row["claimed"] and not allow_claimed)
        ):
            raise ValueError("BUDGET reservation is unavailable or already claimed")
        if (
            reservation.action_ref != reference(action)
            or reservation.work_ref != reference(work)
            or reservation.meta.analysis_id != work.meta.analysis_id
        ):
            raise ValueError("BUDGET reservation action/work mismatch")
        self.budget.registry.execution(
            connection, reservation.budget_binding_ref, str(work.meta.analysis_id)
        )
        self.budget.validate_operation(connection, reservation, work, action)
        return reservation

    def claim(
        self,
        connection: Connection,
        decision_ref: RecordRef,
        kind: ActionType,
        work: WorkExecutionState,
        reservation_ref: RecordRef | None = None,
        *,
        needs_budget: bool = False,
    ) -> ActionDecision:
        decision, action = self.check(
            connection,
            decision_ref,
            kind,
            work,
            reservation_ref,
            needs_budget=needs_budget,
        )
        used = ActionDecision.model_validate(
            decision.model_dump()
            | dict(
                meta=next_meta(decision.meta, self.clock, self.ids),
                use_status=UseStatus.USED,
                used_at=self.clock.now(),
            )
        )
        ref = self.records.stage(connection, used)
        self.records.publish(connection, ref)
        connection.execute(
            insert(models.action_decisions).values(
                decision_id=str(used.decision_id),
                action_id=str(action.action_id),
                payload=encode(used),
            )
        )
        if needs_budget:
            reservation = self.check_reservation(
                connection, reservation_ref, action, work
            )
            connection.execute(
                update(models.budget_reservations)
                .where(
                    models.budget_reservations.c.reservation_id
                    == str(reservation.reservation_id)
                )
                .values(claimed=1)
            )
        return used

    def record_outcome(
        self,
        connection: Connection,
        claimed: ActionDecision,
        outputs: tuple[RecordRef, ...],
    ) -> ActionDecision:
        from sastsimi.contracts.actions import validate_decision_revision

        completed = ActionDecision.model_validate(
            claimed.model_dump()
            | dict(
                meta=next_meta(claimed.meta, self.clock, self.ids),
                outcome_refs=claimed.outcome_refs + outputs,
            )
        )
        validate_decision_revision(claimed, completed)
        self.records.publish(connection, self.records.stage(connection, completed))
        connection.execute(
            update(models.action_decisions)
            .where(models.action_decisions.c.decision_id == str(completed.decision_id))
            .values(payload=encode(completed))
        )
        return completed

    def record_invocation(
        self,
        request: LLMInvocationRequest,
        result: LLMInvocationResult,
        log: LLMInvocationLog,
    ) -> StoredDataRef:
        """Persist normalized provenance and bind it to the used external action."""
        with self.records.database.write() as connection:
            initial = self.records.resolve(connection, request.action_decision_ref)
            if not isinstance(initial, ActionDecision):
                raise ValueError("INVOCATION_ACTION_MISMATCH")
            payload = connection.execute(
                select(models.action_decisions.c.payload).where(
                    models.action_decisions.c.decision_id == str(initial.decision_id)
                )
            ).scalar_one_or_none()
            if payload is None:
                raise ValueError("INVOCATION_ACTION_NOT_USED")
            claimed = ActionDecision.model_validate_json(payload)
            exact_invocation_refs = tuple(
                reference(item) for item in (request, result, log)
            )
            if all(ref in claimed.outcome_refs for ref in exact_invocation_refs):
                for item, item_ref in zip(
                    (request, result, log), exact_invocation_refs, strict=True
                ):
                    if self.records.resolve(connection, item_ref) != item:
                        raise ValueError("INVOCATION_ACTION_MISMATCH")
                replay_ref = reference(log)
                assert isinstance(replay_ref, StoredDataRef)
                return replay_ref
            claimed_ref = reference(claimed)
            action = self.records.resolve(connection, claimed.action_ref)
            spec = self.records.resolve(connection, request.call_spec_ref)
            profile = (
                self.records.resolve(connection, spec.provider_profile_ref)
                if isinstance(spec, LLMCallSpec)
                else None
            )
            prompt_payload = (
                self.records.resolve(connection, spec.prompt_payload_ref)
                if isinstance(spec, LLMCallSpec)
                else None
            )
            expected_action_inputs = (
                llm_action_input_refs(request.call_spec_ref, spec, prompt_payload)
                if isinstance(spec, LLMCallSpec)
                and isinstance(prompt_payload, PromptPayload)
                else ()
            )
            if (
                not isinstance(action, ActionRequest)
                or action.action_type
                not in {
                    ActionType.CALL_LLM,
                    ActionType.CALL_TECHNICAL_GATE,
                    ActionType.CALL_RULE_SCOPE_GATE,
                    ActionType.CREATE_REPORT_DRAFT,
                }
                or action.llm_call_spec_ref != request.call_spec_ref
                or action.provider_profile_ref != request.provider_profile_ref
                or not isinstance(spec, LLMCallSpec)
                or not isinstance(profile, ProviderProfile)
                or request.action_decision_ref != claimed_ref
                or log.action_decision_ref != claimed_ref
                or log.call_spec_ref != request.call_spec_ref
                or log.parsed_output_ref != result.parsed_output_ref
                or tuple(action.input_refs) != expected_action_inputs
            ):
                raise ValueError("INVOCATION_ACTION_MISMATCH")
            request_fields = (
                "llm_call_id",
                "agent_role",
                "task_kind",
                "purpose",
                "provider_profile_ref",
                "model",
                "session_policy",
                "parent_session_ref",
                "context_refs",
                "prompt_registry_entry_ref",
                "prompt_key",
                "prompt_template_ref",
                "prompt_template_version",
                "prompt_payload_ref",
                "execution_limits_ref",
                "retry_policy_ref",
                "tool_policy_ref",
                "redaction_policy_ref",
                "semantic_validator_ref",
                "output_schema_ref",
                "output_schema",
                "token_budget",
                "timeout_ms",
            )
            log_fields = tuple(
                name
                for name in request_fields
                if name not in {"output_schema", "token_budget", "timeout_ms"}
            )
            if any(
                getattr(request, name) != getattr(spec, name) for name in request_fields
            ) or any(getattr(log, name) != getattr(spec, name) for name in log_fields):
                raise ValueError("INVOCATION_CONFIGURATION_MISMATCH")
            if (
                result.llm_call_id != spec.llm_call_id
                or result.purpose != spec.purpose
                or result.model != spec.model
                or result.provider != profile.provider
                or log.provider != profile.provider
                or log.session_ref != result.session_ref
                or log.status != result.status
                or log.usage != result.usage
                or log.safe_error != result.safe_error
                or log.exposed_response_ref != result.response_ref
            ):
                raise ValueError("INVOCATION_RESULT_MISMATCH")
            candidate = None
            if result.status == "SUCCEEDED":
                if (
                    result.parsed_output_ref is None
                    or result.safe_error is not None
                    or log.validation_errors
                ):
                    raise ValueError("INVOCATION_RESULT_MISMATCH")
                candidate = self.records.resolve(
                    connection, result.parsed_output_ref, candidate=True
                )
                from sastsimi.contracts.llm import OutputSchemaSpec

                schema = self.records.resolve(connection, spec.output_schema_ref)
                if (
                    not isinstance(schema, OutputSchemaSpec)
                    or candidate.meta.record_type != schema.result_kind
                ):
                    raise ValueError("INVOCATION_OUTPUT_MISMATCH")
            elif (
                result.parsed_output_ref is not None
                or log.parsed_output_ref is not None
                or result.safe_error is None
                or log.safe_error is None
            ):
                raise ValueError("INVOCATION_RESULT_MISMATCH")
            if action.work_ref is None:
                raise ValueError("INVOCATION_ACTION_MISMATCH")
            work = self.records.resolve(connection, action.work_ref)
            current_payload = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.work_id == str(getattr(work, "work_id", ""))
                )
            ).scalar_one_or_none()
            if (
                current_payload is None
                or WorkExecutionState.model_validate_json(current_payload) != work
                or not isinstance(work, WorkExecutionState)
                or work.status != "RUNNING"
                or claimed.use_status != UseStatus.USED
            ):
                raise ValueError("INVOCATION_SCOPE_MISMATCH")
            if (
                not isinstance(work, WorkExecutionState)
                or any(
                    getattr(item.meta, name, None) != getattr(work.meta, name, None)
                    for item in (
                        (request, result, log, candidate)
                        if candidate is not None
                        else (request, result, log)
                    )
                    for name in (
                        "analysis_id",
                        "workspace_id",
                        "commit_id",
                        "hypothesis_id",
                    )
                )
                or any(
                    getattr(item.meta, "attempt_id", None) != work.active_attempt_id
                    for item in (
                        (request, result, log, candidate)
                        if candidate is not None
                        else (request, result, log)
                    )
                )
                or not isinstance(prompt_payload, PromptPayload)
                or any(
                    getattr(item.meta, name, None) != expected
                    for item in (spec, prompt_payload)
                    for name, expected in (
                        ("analysis_id", work.meta.analysis_id),
                        ("workspace_id", getattr(work.meta, "workspace_id", None)),
                        ("commit_id", getattr(work.meta, "commit_id", None)),
                        ("hypothesis_id", getattr(work.meta, "hypothesis_id", None)),
                        ("attempt_id", work.active_attempt_id),
                    )
                )
            ):
                raise ValueError("INVOCATION_SCOPE_MISMATCH")
            check_stage(self.records, connection, action, work)
            from sastsimi.contracts.policy import PolicyParserResult

            if (
                candidate is not None
                and isinstance(candidate, PolicyParserResult)
                and (
                    spec.agent_role != "POLICY_PARSER"
                    or spec.context_refs != (candidate.source_ref,)
                    or candidate.llm_invocation_ref != reference(request)
                )
            ):
                raise ValueError("INVOCATION_POLICY_SOURCE_MISMATCH")
            invocation_refs: list[StoredDataRef] = []
            for item in (request, result, log):
                item_ref = self.records.stage(connection, item)
                if not isinstance(item_ref, StoredDataRef):
                    raise ValueError("INVOCATION_SCOPE_MISMATCH")
                self.records.publish(connection, item_ref)
                invocation_refs.append(item_ref)
            log_ref = reference(log)
            if not isinstance(log_ref, StoredDataRef):
                raise ValueError("INVOCATION_SCOPE_MISMATCH")
            if (
                connection.execute(
                    select(models.current_records.c.record_id).where(
                        models.current_records.c.logical_record_id
                        == str(log.meta.logical_record_id)
                    )
                ).scalar_one_or_none()
                is None
            ):
                connection.execute(
                    insert(models.current_records).values(
                        logical_record_id=str(log.meta.logical_record_id),
                        record_id=str(log.meta.record_id),
                        state_version=1,
                    )
                )
            self.record_outcome(connection, claimed, tuple(invocation_refs))
            return log_ref
