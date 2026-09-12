"""Rehydrate exact active external cancellation targets from committed rows only."""

from __future__ import annotations

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionDecision, ActionRequest, ActionType
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.dto import Record
from sastsimi.ports.scheduler import CancellationTarget, CancellationTargetKind

from . import models
from .codec import REF_ADAPTER, decode, reference
from .database import Database

_PROVIDER_ACTIONS = frozenset(
    {
        ActionType.CALL_LLM,
        ActionType.CALL_TECHNICAL_GATE,
        ActionType.CALL_RULE_SCOPE_GATE,
        ActionType.CREATE_REPORT_DRAFT,
    }
)
_STATIC_ACTIONS = frozenset(
    {ActionType.READ_CODE, ActionType.RUN_TOOL, ActionType.FETCH_POLICY}
)
_SANDBOX_RESOURCE_KINDS = frozenset(
    {
        "environment_recipe",
        "sandbox_environment",
        "sandbox_command_record",
        "dynamic_reproduction_tool_request",
    }
)


class CancellationTargetStore:
    """Never discovers host resources; only follows exact durable references."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def cancellation_targets(self, analysis_id: str) -> tuple[CancellationTarget, ...]:
        if not analysis_id:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        targets: list[CancellationTarget] = []
        with self._database.engine.connect() as connection:
            rows = connection.execute(
                select(
                    models.external_dispatches,
                    models.work_states.c.payload.label("work_payload"),
                )
                .join(
                    models.work_states,
                    models.work_states.c.work_id
                    == models.external_dispatches.c.work_id,
                )
                .where(
                    models.work_states.c.analysis_id == analysis_id,
                    models.work_states.c.status == "RUNNING",
                    models.external_dispatches.c.dispatched_at.is_not(None),
                    models.external_dispatches.c.returned_at.is_(None),
                    models.external_dispatches.c.reconciled_at.is_(None),
                )
                .order_by(
                    models.external_dispatches.c.work_id,
                    models.external_dispatches.c.action_id,
                )
            ).mappings()
            for row in rows:
                work = WorkExecutionState.model_validate_json(row["work_payload"])
                if work.active_attempt_id is None or row["attempt_id"] != str(
                    work.active_attempt_id
                ):
                    continue
                attempt_payload = connection.execute(
                    select(models.work_attempts.c.payload).where(
                        models.work_attempts.c.attempt_id == row["attempt_id"],
                        models.work_attempts.c.work_id == row["work_id"],
                        models.work_attempts.c.status == "RUNNING",
                    )
                ).scalar_one_or_none()
                if attempt_payload is None:
                    continue
                attempt = WorkAttempt.model_validate_json(attempt_payload)
                if (
                    attempt.input_hash != work.input_hash
                    or attempt.attempt_id != work.active_attempt_id
                ):
                    continue
                issued_ref = REF_ADAPTER.validate_json(row["decision_ref"])
                issued = self._exact(connection, issued_ref)
                if not isinstance(issued, ActionDecision):
                    continue
                action = self._exact(connection, issued.action_ref)
                if not isinstance(action, ActionRequest):
                    continue
                used_payload = connection.execute(
                    select(models.action_decisions.c.payload).where(
                        models.action_decisions.c.action_id == str(action.action_id)
                    )
                ).scalar_one_or_none()
                if used_payload is None:
                    continue
                used = ActionDecision.model_validate_json(used_payload)
                if (
                    used.use_status != "USED"
                    or used.action_ref != reference(action)
                    or action.work_ref != reference(work)
                    or action.expected_state_version != work.state_version
                ):
                    continue
                kind = self._target_kind(action.action_type)
                if kind is None:
                    continue
                if action.llm_call_spec_ref is not None:
                    self._exact(connection, action.llm_call_spec_ref)
                resources = tuple(
                    dict.fromkeys(
                        ref
                        for ref in (
                            *action.input_refs,
                            action.reproduction_plan_ref,
                            action.sandbox_profile_ref,
                            action.resource_profile_ref,
                        )
                        if isinstance(ref, StoredDataRef)
                        and ref.data_kind in _SANDBOX_RESOURCE_KINDS
                        and self._is_exact(connection, ref)
                    )
                )
                targets.append(
                    CancellationTarget(
                        target_kind=kind,
                        work=work,
                        attempt=attempt,
                        action_request_ref=reference(action),
                        action_decision_ref=reference(used),
                        call_spec_ref=action.llm_call_spec_ref,
                        sandbox_resource_refs=resources,
                    )
                )
        return tuple(targets)

    @staticmethod
    def _target_kind(action_type: ActionType) -> CancellationTargetKind | None:
        if action_type in _PROVIDER_ACTIONS:
            return "PROVIDER"
        if action_type in _STATIC_ACTIONS:
            return "STATIC"
        if action_type == ActionType.RUN_SANDBOX:
            return "SANDBOX"
        return None

    @staticmethod
    def _exact(connection: Connection, ref: RecordRef) -> Record:
        if ref.record_id is None:
            raise ValueError("CANCELLATION_TARGET_EXACT_REF_REQUIRED")
        row = (
            connection.execute(
                select(models.records)
                .join(models.record_revisions)
                .where(models.records.c.record_id == str(ref.record_id))
            )
            .mappings()
            .one()
        )
        if REF_ADAPTER.validate_json(row["ref"]) != ref:
            raise ValueError("RECORD_REVISION_MISMATCH: exact cancellation target")
        record = decode(row["kind"], row["payload"])
        if content_hash(record) != ref.content_hash:
            raise ValueError("HASH_MISMATCH")
        return record

    @classmethod
    def _is_exact(cls, connection: Connection, ref: RecordRef) -> bool:
        cls._exact(connection, ref)
        return True


__all__ = ["CancellationTargetStore"]
