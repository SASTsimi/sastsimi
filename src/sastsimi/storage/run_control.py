"""SQLite-backed durable cancellation latch and exact reconciliation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.work import (
    AttemptStatus,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
)
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.scheduler import CancellationObservation, CancellationTarget

from . import models
from .codec import encode
from .database import Database
from .records import next_meta

if TYPE_CHECKING:
    from .work_service import WorkService

_SAFE_REASON = re.compile(r"[A-Z0-9_]{1,64}\Z")
_CLOSED_STATUSES = frozenset({"STOPPED", "ABSENT"})


@dataclass(frozen=True)
class _ObservationResource:
    kind: str
    resource_id: str
    ref: str | None
    tag: str | None = None
    labels: str = "{}"
    lookup_by_name: int = 0


class RunControlStore:
    def __init__(
        self,
        database: Database,
        clock: Clock,
        *,
        works: WorkService | None = None,
        ids: IdGenerator | None = None,
    ) -> None:
        if (works is None) != (ids is None):
            raise ValueError("RUN_CONTROL_RECONCILIATION_CONFIGURATION_INVALID")
        self._database = database
        self._clock = clock
        self._works = works
        self._ids = ids

    def request_cancel(self, analysis_id: str, reason: str) -> None:
        if not analysis_id or _SAFE_REASON.fullmatch(reason) is None:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        with self._database.write() as connection:
            exists = connection.execute(
                select(models.run_controls.c.analysis_id).where(
                    models.run_controls.c.analysis_id == analysis_id
                )
            ).scalar_one_or_none()
            if exists is None:
                connection.execute(
                    insert(models.run_controls).values(
                        analysis_id=analysis_id,
                        cancel_requested_at=self._clock.now().isoformat(),
                        cancel_reason=reason,
                        quiescent_at=None,
                    )
                )

    def cancel_requested(self, analysis_id: str) -> bool:
        if not analysis_id:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        with self._database.engine.connect() as connection:
            return cancel_latched(connection, analysis_id)

    def cancellation_targets(self, analysis_id: str) -> tuple[CancellationTarget, ...]:
        if not analysis_id:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        from .cancellation_targets import CancellationTargetStore

        return CancellationTargetStore(self._database).cancellation_targets(analysis_id)

    def cancellation_observations(
        self, targets: tuple[CancellationTarget, ...]
    ) -> tuple[CancellationObservation | None, ...]:
        if len({str(target.work.meta.analysis_id) for target in targets}) > 1:
            raise ValueError("CANCELLATION_TARGET_SCOPE_MISMATCH")
        with self._database.engine.connect() as connection:
            return self._observations(connection, targets)

    def record_cancellation_observation(
        self, observation: CancellationObservation
    ) -> None:
        self._validate_observation(observation)
        target = observation.target
        analysis_id = str(target.work.meta.analysis_id)
        from .cancellation_targets import CancellationTargetStore

        with self._database.write() as connection:
            if not cancel_latched(connection, analysis_id):
                raise ValueError("CANCELLATION_LATCH_REQUIRED")
            current = CancellationTargetStore(self._database).cancellation_targets(
                analysis_id, _connection=connection
            )
            if target not in current:
                raise ValueError("CANCELLATION_TARGET_NOT_CURRENT")
            existing = self._observations(connection, (target,))[0]
            if existing is not None:
                if existing != observation:
                    raise ValueError("CANCELLATION_OBSERVATION_CONFLICT")
                return
            now = self._clock.now().isoformat()
            for resource in _resources(target):
                connection.execute(
                    insert(models.cancellation_observations).values(
                        **_observation_values(observation, resource),
                        observed_at=now,
                    )
                )

    def reconcile_cancellation(
        self,
        analysis_id: str,
        observations: tuple[CancellationObservation, ...],
    ) -> None:
        if not analysis_id or self._works is None or self._ids is None:
            raise ValueError("RUN_CONTROL_RECONCILIATION_NOT_CONFIGURED")
        if len({str(item.target.work.work_id) for item in observations}) != len(
            observations
        ):
            raise ValueError("DUPLICATE_CANCELLATION_TARGET")
        from .cancellation_targets import CancellationTargetStore

        with self._database.write() as connection:
            if not cancel_latched(connection, analysis_id):
                raise ValueError("CANCELLATION_LATCH_REQUIRED")
            current = CancellationTargetStore(self._database).cancellation_targets(
                analysis_id, _connection=connection
            )
            if tuple(item.target for item in observations) != current:
                raise ValueError("CANCELLATION_TARGET_NOT_CURRENT")
            persisted = self._observations(connection, current)
            if any(
                item is None or item != supplied
                for item, supplied in zip(persisted, observations, strict=True)
            ):
                raise ValueError("CANCELLATION_OBSERVATION_NOT_DURABLE")

            planned: list[
                tuple[CancellationTarget, WorkExecutionState, WorkAttempt]
            ] = []
            for observation in observations:
                self._validate_observation(observation)
                if observation.status == "UNKNOWN":
                    continue
                target = observation.target
                work_row = (
                    connection.execute(
                        select(models.work_states).where(
                            models.work_states.c.analysis_id == analysis_id,
                            models.work_states.c.work_id == str(target.work.work_id),
                        )
                    )
                    .mappings()
                    .one()
                )
                attempt_row = (
                    connection.execute(
                        select(models.work_attempts).where(
                            models.work_attempts.c.work_id == str(target.work.work_id),
                            models.work_attempts.c.attempt_id
                            == str(target.attempt.attempt_id),
                        )
                    )
                    .mappings()
                    .one()
                )
                current_work = WorkExecutionState.model_validate_json(
                    work_row["payload"]
                )
                current_attempt = WorkAttempt.model_validate_json(
                    attempt_row["payload"]
                )
                issued = target.issued_action_decision_ref
                if (
                    current_work != target.work
                    or current_attempt != target.attempt
                    or current_work.status != "RUNNING"
                    or current_attempt.status != "RUNNING"
                    or issued is None
                    or work_row["active_attempt_id"]
                    != str(current_attempt.attempt_id)
                    or work_row["worker_id"] is None
                    or work_row["lease_expires_at"] is None
                ):
                    raise ValueError("CANCELLATION_TARGET_NOT_CURRENT")
                dispatch = (
                    connection.execute(
                        select(models.external_dispatches).where(
                            models.external_dispatches.c.work_id
                            == str(current_work.work_id),
                            models.external_dispatches.c.attempt_id
                            == str(current_attempt.attempt_id),
                            models.external_dispatches.c.decision_ref
                            == canonical_bytes(issued).decode(),
                            models.external_dispatches.c.dispatched_at.is_not(None),
                            models.external_dispatches.c.returned_at.is_(None),
                            models.external_dispatches.c.reconciled_at.is_(None),
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if dispatch is None:
                    raise ValueError("CANCELLATION_DISPATCH_NOT_CURRENT")
                now = self._clock.now()
                cancelled_work = WorkExecutionState.model_validate(
                    current_work.model_dump()
                    | {
                        "meta": next_meta(current_work.meta, self._clock, self._ids),
                        "status": WorkStatus.CANCELLED,
                        "state_version": current_work.state_version + 1,
                        "active_attempt_id": None,
                        "waiting_for": (),
                        "stop_reason": "CANCELLATION_REQUESTED",
                        "finished_at": now,
                    }
                )
                cancelled_attempt = WorkAttempt.model_validate(
                    current_attempt.model_dump()
                    | {
                        "meta": next_meta(
                            current_attempt.meta, self._clock, self._ids
                        ),
                        "status": AttemptStatus.CANCELLED,
                        "finished_at": now,
                    }
                )
                planned.append((target, cancelled_work, cancelled_attempt))

            for target, cancelled_work, cancelled_attempt in planned:
                previous = target.work
                self._works.records.publish(
                    connection,
                    self._works.records.stage(connection, cancelled_attempt),
                )
                attempt_result = connection.execute(
                    update(models.work_attempts)
                    .where(
                        models.work_attempts.c.attempt_id
                        == str(cancelled_attempt.attempt_id),
                        models.work_attempts.c.status == "RUNNING",
                        models.work_attempts.c.payload == encode(target.attempt),
                    )
                    .values(
                        status=cancelled_attempt.status.value,
                        payload=encode(cancelled_attempt),
                    )
                )
                if attempt_result.rowcount != 1:
                    raise ValueError("CANCELLATION_ATTEMPT_CAS_FAILED")
                self._works.save(connection, previous, cancelled_work)
                lease_result = connection.execute(
                    update(models.work_states)
                    .where(
                        models.work_states.c.work_id == str(cancelled_work.work_id),
                        models.work_states.c.status == "CANCELLED",
                        models.work_states.c.state_version
                        == cancelled_work.state_version,
                    )
                    .values(worker_id=None, lease_expires_at=None)
                )
                if lease_result.rowcount != 1:
                    raise ValueError("CANCELLATION_WORK_CAS_FAILED")
                issued = target.issued_action_decision_ref
                assert issued is not None
                dispatch_result = connection.execute(
                    update(models.external_dispatches)
                    .where(
                        models.external_dispatches.c.work_id
                        == str(cancelled_work.work_id),
                        models.external_dispatches.c.attempt_id
                        == str(cancelled_attempt.attempt_id),
                        models.external_dispatches.c.decision_ref
                        == canonical_bytes(issued).decode(),
                        models.external_dispatches.c.dispatched_at.is_not(None),
                        models.external_dispatches.c.returned_at.is_(None),
                        models.external_dispatches.c.reconciled_at.is_(None),
                    )
                    .values(reconciled_at=self._clock.now().isoformat())
                )
                if dispatch_result.rowcount != 1:
                    raise ValueError("CANCELLATION_DISPATCH_CAS_FAILED")

    def mark_quiescent(self, analysis_id: str) -> None:
        if not analysis_id:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        with self._database.write() as connection:
            control = (
                connection.execute(
                    select(models.run_controls).where(
                        models.run_controls.c.analysis_id == analysis_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if control is None:
                raise LookupError("RUN_CONTROL_NOT_FOUND")
            if control["quiescent_at"] is not None:
                return
            work_rows = (
                connection.execute(
                    select(models.work_states).where(
                        models.work_states.c.analysis_id == analysis_id
                    )
                )
                .mappings()
                .all()
            )
            work_ids = tuple(row["work_id"] for row in work_rows)
            if any(
                row["status"] in {"PENDING", "READY", "RUNNING"}
                or row["active_attempt_id"] is not None
                or row["worker_id"] is not None
                or row["lease_expires_at"] is not None
                for row in work_rows
            ):
                raise ValueError("RUN_NOT_QUIESCENT")
            if work_ids and (
                connection.execute(
                    select(models.work_attempts.c.attempt_id).where(
                        models.work_attempts.c.work_id.in_(work_ids),
                        models.work_attempts.c.status == "RUNNING",
                    )
                ).first()
                or connection.execute(
                    select(models.transition_commits.c.transition_commit_id).where(
                        models.transition_commits.c.work_id.in_(work_ids),
                        models.transition_commits.c.state == "PREPARED",
                    )
                ).first()
                or connection.execute(
                    select(models.external_dispatches.c.action_id).where(
                        models.external_dispatches.c.work_id.in_(work_ids),
                        models.external_dispatches.c.dispatched_at.is_not(None),
                        models.external_dispatches.c.returned_at.is_(None),
                        models.external_dispatches.c.reconciled_at.is_(None),
                    )
                ).first()
            ):
                raise ValueError("RUN_NOT_QUIESCENT")
            observations = (
                connection.execute(
                    select(models.cancellation_observations).where(
                        models.cancellation_observations.c.analysis_id == analysis_id
                    )
                )
                .mappings()
                .all()
            )
            if any(row["status"] not in _CLOSED_STATUSES for row in observations):
                raise ValueError("RUN_NOT_QUIESCENT")
            if work_ids:
                dispatches = connection.execute(
                    select(models.external_dispatches).where(
                        models.external_dispatches.c.work_id.in_(work_ids),
                        models.external_dispatches.c.dispatched_at.is_not(None),
                        models.external_dispatches.c.returned_at.is_(None),
                        models.external_dispatches.c.reconciled_at.is_not(None),
                    )
                ).mappings()
                for dispatch in dispatches:
                    if not any(
                        row["work_id"] == dispatch["work_id"]
                        and row["attempt_id"] == dispatch["attempt_id"]
                        and row["issued_decision_ref"] == dispatch["decision_ref"]
                        and row["status"] in _CLOSED_STATUSES
                        for row in observations
                    ):
                        raise ValueError("RUN_NOT_QUIESCENT")
            result = connection.execute(
                update(models.run_controls)
                .where(
                    models.run_controls.c.analysis_id == analysis_id,
                    models.run_controls.c.quiescent_at.is_(None),
                )
                .values(quiescent_at=self._clock.now().isoformat())
            )
            if result.rowcount != 1:
                raise ValueError("RUN_QUIESCENCE_CAS_FAILED")

    @staticmethod
    def _validate_observation(observation: CancellationObservation) -> None:
        if observation.status not in {*_CLOSED_STATUSES, "UNKNOWN"}:
            raise ValueError("CANCELLATION_OBSERVATION_STATUS_INVALID")
        if observation.reason_code is not None and (
            _SAFE_REASON.fullmatch(observation.reason_code) is None
        ):
            raise ValueError("CANCELLATION_OBSERVATION_REASON_INVALID")
        if observation.target.issued_action_decision_ref is None:
            raise ValueError("CANCELLATION_TARGET_ISSUED_DECISION_REQUIRED")

    def _observations(
        self,
        connection: Connection,
        targets: tuple[CancellationTarget, ...],
    ) -> tuple[CancellationObservation | None, ...]:
        result: list[CancellationObservation | None] = []
        for target in targets:
            resources = _resources(target)
            rows = []
            for resource in resources:
                key = _observation_key(target, resource)
                row = (
                    connection.execute(
                        select(models.cancellation_observations).where(
                            models.cancellation_observations.c.observation_key == key
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is not None:
                    candidate = CancellationObservation(
                        target, row["status"], row["reason_code"]
                    )
                    expected = _observation_values(candidate, resource)
                    if any(row[name] != value for name, value in expected.items()):
                        raise ValueError("CANCELLATION_OBSERVATION_SCOPE_MISMATCH")
                rows.append(row)
            present = tuple(row for row in rows if row is not None)
            if not present:
                result.append(None)
                continue
            if len(present) != len(resources):
                raise ValueError("CANCELLATION_OBSERVATION_INCOMPLETE")
            statuses = {(row["status"], row["reason_code"]) for row in present}
            if len(statuses) != 1:
                raise ValueError("CANCELLATION_OBSERVATION_CONFLICT")
            status, reason = statuses.pop()
            observation = CancellationObservation(target, status, reason)
            self._validate_observation(observation)
            result.append(observation)
        return tuple(result)


def _resources(target: CancellationTarget) -> tuple[_ObservationResource, ...]:
    if target.target_kind == "SANDBOX":
        if not target.sandbox_resource_refs:
            raise ValueError("CANCELLATION_SANDBOX_RESOURCE_MISSING")
        return tuple(
            _ObservationResource(
                kind=ref.data_kind,
                resource_id=str(ref.stored_data_id),
                ref=canonical_bytes(ref).decode(),
            )
            for ref in target.sandbox_resource_refs
        )
    if target.target_kind == "PROVIDER":
        if target.call_spec_ref is None:
            raise ValueError("CANCELLATION_CALL_SPEC_NOT_EXACT")
        return (
            _ObservationResource(
                kind="PROVIDER_CALL",
                resource_id=str(target.call_spec_ref.stored_data_id),
                ref=canonical_bytes(target.call_spec_ref).decode(),
            ),
        )
    if target.target_kind == "STATIC":
        return (
            _ObservationResource(
                kind="STATIC_ATTEMPT",
                resource_id=str(target.attempt.attempt_id),
                ref=None,
            ),
        )
    raise ValueError("CANCELLATION_TARGET_KIND_MISMATCH")


def _observation_key(
    target: CancellationTarget, resource: _ObservationResource
) -> str:
    return content_hash(
        [
            "cancellation-observation-v1",
            target.target_kind,
            target.work.meta.analysis_id,
            target.work.work_id,
            target.attempt.attempt_id,
            target.action_request_ref,
            target.issued_action_decision_ref,
            target.action_decision_ref,
            resource.kind,
            resource.resource_id,
            resource.ref,
            resource.tag,
            resource.labels,
            resource.lookup_by_name,
        ]
    )


def _observation_values(
    observation: CancellationObservation, resource: _ObservationResource
) -> dict[str, object]:
    target = observation.target
    issued = target.issued_action_decision_ref
    if issued is None:
        raise ValueError("CANCELLATION_TARGET_ISSUED_DECISION_REQUIRED")
    return {
        "observation_key": _observation_key(target, resource),
        "analysis_id": str(target.work.meta.analysis_id),
        "work_id": str(target.work.work_id),
        "attempt_id": str(target.attempt.attempt_id),
        "action_ref": canonical_bytes(target.action_request_ref).decode(),
        "issued_decision_ref": canonical_bytes(issued).decode(),
        "decision_ref": canonical_bytes(target.action_decision_ref).decode(),
        "target_kind": target.target_kind,
        "resource_kind": resource.kind,
        "resource_id": resource.resource_id,
        "resource_ref": resource.ref,
        "resource_tag": resource.tag,
        "labels": resource.labels,
        "lookup_by_name": resource.lookup_by_name,
        "status": observation.status,
        "reason_code": observation.reason_code,
    }


def cancel_latched(connection: Connection, analysis_id: str) -> bool:
    """Read the durable latch on the caller's transaction snapshot."""
    return (
        connection.execute(
            select(models.run_controls.c.analysis_id).where(
                models.run_controls.c.analysis_id == analysis_id
            )
        ).scalar_one_or_none()
        is not None
    )


def reject_cancelled(connection: Connection, analysis_id: str) -> None:
    if cancel_latched(connection, analysis_id):
        raise ValueError("RUN_CANCELLED")


__all__ = ["RunControlStore", "cancel_latched", "reject_cancelled"]
