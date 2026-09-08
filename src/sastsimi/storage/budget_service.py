"""Atomic ledger; uncertain usage stays reserved across restarts."""

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.actions import ActionRequest, ActionType
from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetProfileBinding,
    BudgetRemaining,
    BudgetReservation,
    BudgetUnits,
    ReservationStatus,
    WorkBudgetProfile,
    select_work_limit,
    validate_reservation_revision,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import BudgetScopeRef
from sastsimi.contracts.work import WorkExecutionState, WorkType
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import (
    BudgetCommitRequest,
    BudgetReleaseRequest,
    BudgetReservationRequest,
)
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.storage import models
from sastsimi.storage.codec import REF_ADAPTER, encode
from sastsimi.storage.repositories import SQLiteRecordStore

from .budget_hierarchy import check_hierarchy
from .budget_limits import EXTERNAL_ACTIONS, operation
from .budget_registry import BudgetProfileRegistry
from .records import next_meta

UNIT_FIELDS = (
    "elapsed_ms",
    "work_count",
    "llm_call_count",
    "retry_count",
    "cost_minor_units",
)


class BudgetService:
    def __init__(
        self,
        records: SQLiteRecordStore,
        registry: BudgetProfileRegistry,
        clock: Clock,
        ids: IdGenerator,
    ) -> None:
        self.records, self.registry, self.clock, self.ids = (
            records,
            registry,
            clock,
            ids,
        )

    def reserve(self, request: BudgetReservationRequest) -> BudgetReservation:
        reservation = BudgetReservation.model_validate(request.reservation)
        with self.records.database.write() as connection:
            table = models.budget_reservations
            existing = (
                connection.execute(
                    select(table).where(
                        table.c.reservation_id == str(reservation.reservation_id)
                    )
                )
                .mappings()
                .first()
            )
            if existing:
                initial = self.records.resolve(
                    connection, REF_ADAPTER.validate_json(existing["initial_ref"])
                )
                if initial != reservation:
                    raise ValueError("Reservation identity mismatch")
                return BudgetReservation.model_validate_json(existing["payload"])
            if reservation.status != ReservationStatus.RESERVED:
                raise ValueError("New reservation must be RESERVED")
            work = self.records.resolve(
                connection, reservation.work_ref, candidate=True
            )
            action = self.records.resolve(
                connection, reservation.action_ref, candidate=True
            )
            if (
                not isinstance(work, WorkExecutionState)
                or work.meta.analysis_id != reservation.meta.analysis_id
                or getattr(action.meta, "analysis_id", None)
                != reservation.meta.analysis_id
            ):
                raise ValueError("BUDGET analysis/work mismatch")
            if not isinstance(action, ActionRequest):
                raise ValueError("BUDGET requires exact action")
            self.records.publish(connection, reservation.action_ref)
            self.validate_operation(connection, reservation, work, action)
            remaining = self.available(
                connection,
                reservation.budget_binding_ref,
                str(reservation.meta.analysis_id),
            )
            if (
                reservation.requested_units.currency
                != remaining.available_units.currency
            ):
                raise ValueError("BUDGET currency unavailable")
            if any(
                getattr(reservation.requested_units, key)
                > getattr(remaining.available_units, key)
                for key in UNIT_FIELDS
            ):
                raise ValueError("BUDGET_EXCEEDED")
            ref = self.records.stage(connection, reservation)
            self.records.publish(connection, ref)
            connection.execute(
                insert(table).values(
                    reservation_id=str(reservation.reservation_id),
                    analysis_id=str(reservation.meta.analysis_id),
                    action_id=str(reservation.action_ref.record_id),
                    status=reservation.status.value,
                    payload=encode(reservation),
                    initial_ref=canonical_bytes(ref).decode(),
                    claimed=0,
                    item_count=self.records.evidence.item_count(action, work),
                )
            )
            return reservation

    def validate_operation(
        self,
        connection: Connection,
        reservation: BudgetReservation,
        work: WorkExecutionState,
        action: ActionRequest,
    ) -> None:
        remaining = self.available(
            connection,
            reservation.budget_binding_ref,
            str(work.meta.analysis_id),
            exclude_reservation=str(reservation.reservation_id),
        )
        if any(
            getattr(reservation.requested_units, key)
            > getattr(remaining.available_units, key)
            for key in UNIT_FIELDS
        ):
            raise ValueError("BUDGET_EXCEEDED: requested capacity no longer fits")
        if action.action_type in {ActionType.REGISTER_WORK, ActionType.START_ATTEMPT}:
            if any(
                getattr(remaining.available_units, key) <= 0
                for key in (
                    "elapsed_ms",
                    "cost_minor_units",
                    "llm_call_count",
                    "work_count",
                )
            ):
                raise ValueError("BUDGET_EXCEEDED: executable capacity exhausted")
        scope = self.records.resolve(connection, reservation.budget_binding_ref)
        if isinstance(scope, BudgetProfileBinding):
            self.registry.validate_binding(connection, scope)
            check_hierarchy(self.records, connection, reservation, work, action, scope)
        if action.action_type in EXTERNAL_ACTIONS:
            execution_profile = self.registry.execution(
                connection, reservation.budget_binding_ref, str(work.meta.analysis_id)
            )
            remaining = self.available(
                connection,
                reservation.budget_binding_ref,
                str(work.meta.analysis_id),
                exclude_reservation=str(reservation.reservation_id),
            )
            applicable = ("elapsed_ms", "cost_minor_units") + (
                ("llm_call_count",)
                if action.action_type
                in {
                    ActionType.CALL_LLM,
                    ActionType.CALL_TECHNICAL_GATE,
                    ActionType.CALL_RULE_SCOPE_GATE,
                    ActionType.CREATE_REPORT_DRAFT,
                }
                else ()
            )
            if any(
                getattr(remaining.available_units, name) <= 0 for name in applicable
            ):
                raise ValueError("BUDGET_EXCEEDED: execution capacity exhausted")
            if not self.records.evidence.pricing(execution_profile) or any(
                getattr(reservation.requested_units, name) <= 0 for name in applicable
            ):
                raise ValueError(
                    "BLOCKED waiting_for=BUDGET: "
                    "positive execution/pricing proof required"
                )
        if work.work_type == WorkType.WORKSPACE_PREP:
            if isinstance(scope, BudgetProfileBinding):
                raise ValueError("BUDGET bootstrap requires run execution profile")
            return
        if not isinstance(scope, BudgetProfileBinding):
            raise ValueError("BUDGET requires full ACTIVE binding")
        profile = self.records.resolve(connection, scope.work_budget_profile_ref)
        assert isinstance(profile, WorkBudgetProfile)
        kind, role = operation(work.work_type, action)
        limit = select_work_limit(profile, work.work_type, kind, role)
        count_items = self.records.evidence.item_count(action, work)
        if limit.max_items_per_work is None or count_items is None or count_items < 0:
            raise ValueError(
                "BLOCKED waiting_for=BUDGET: trusted item admission unavailable"
            )
        if count_items > limit.max_items_per_work:
            raise ValueError("BUDGET_EXCEEDED: work items")
        admitted_items = count_items
        for row in connection.execute(
            select(models.budget_reservations).where(
                models.budget_reservations.c.analysis_id == str(work.meta.analysis_id),
                models.budget_reservations.c.status != "RELEASED",
                models.budget_reservations.c.reservation_id
                != str(reservation.reservation_id),
            )
        ).mappings():
            prior = BudgetReservation.model_validate_json(row["payload"])
            prior_work = self.records.resolve(
                connection, prior.work_ref, candidate=True
            )
            if (
                isinstance(prior_work, WorkExecutionState)
                and prior_work.work_id == work.work_id
            ):
                if row["item_count"] is None:
                    raise ValueError(
                        "BLOCKED waiting_for=BUDGET: item history unproven"
                    )
                admitted_items += row["item_count"]
        if admitted_items > limit.max_items_per_work:
            raise ValueError("BUDGET_EXCEEDED: cumulative work items")
        if action.action_type == ActionType.START_ATTEMPT:
            ceiling = limit.max_attempts
            kinds = {ActionType.START_ATTEMPT}
        elif action.action_type in {
            ActionType.RUN_TOOL,
            ActionType.CALL_LLM,
            ActionType.FETCH_POLICY,
            ActionType.RUN_SANDBOX,
            ActionType.READ_CODE,
            ActionType.CALL_TECHNICAL_GATE,
            ActionType.CALL_RULE_SCOPE_GATE,
            ActionType.CREATE_REPORT_DRAFT,
        }:
            ceiling = limit.max_calls_per_work
            kinds = {
                ActionType.RUN_TOOL,
                ActionType.CALL_LLM,
                ActionType.FETCH_POLICY,
                ActionType.RUN_SANDBOX,
                ActionType.READ_CODE,
                ActionType.CALL_TECHNICAL_GATE,
                ActionType.CALL_RULE_SCOPE_GATE,
                ActionType.CREATE_REPORT_DRAFT,
            }
        else:
            ceiling, kinds = None, set()
        if kinds:
            if ceiling is None:
                raise ValueError("BUDGET unavailable: operation limit is unspecified")
            count = 0
            for payload in connection.execute(
                select(models.budget_reservations.c.payload).where(
                    models.budget_reservations.c.analysis_id
                    == str(work.meta.analysis_id),
                    models.budget_reservations.c.status != "RELEASED",
                )
            ).scalars():
                other = BudgetReservation.model_validate_json(payload)
                if other.reservation_id == reservation.reservation_id:
                    continue
                other_work = self.records.resolve(
                    connection, other.work_ref, candidate=True
                )
                other_action = self.records.resolve(connection, other.action_ref)
                if (
                    isinstance(other_work, WorkExecutionState)
                    and other_work.work_id == work.work_id
                    and isinstance(other_action, ActionRequest)
                    and other_action.action_type in kinds
                ):
                    count += 1
            if count >= ceiling:
                raise ValueError("BUDGET_EXCEEDED: work operation limit")
        if (
            limit.timeout_ms is not None
            and reservation.requested_units.elapsed_ms > limit.timeout_ms
        ):
            raise ValueError("BUDGET_EXCEEDED: work timeout")

    def available(
        self,
        connection: Connection,
        scope: BudgetScopeRef,
        analysis_id: str,
        *,
        exclude_reservation: str | None = None,
    ) -> BudgetRemaining:
        profile = self.registry.execution(connection, scope, analysis_id)
        limits = dict(
            elapsed_ms=profile.max_analysis_elapsed_ms,
            work_count=profile.max_total_work,
            llm_call_count=profile.max_total_llm_calls,
            retry_count=profile.max_total_retries,
            cost_minor_units=profile.max_total_cost_minor_units,
        )
        table = models.budget_reservations
        reservations = [
            BudgetReservation.model_validate_json(payload)
            for payload in connection.execute(
                select(table.c.payload).where(
                    table.c.analysis_id == analysis_id, table.c.status == "RESERVED"
                )
            ).scalars()
        ]
        entries = [
            BudgetLedgerEntry.model_validate_json(payload)
            for payload in connection.execute(
                select(models.budget_ledger_entries.c.payload).where(
                    models.budget_ledger_entries.c.analysis_id == analysis_id
                )
            ).scalars()
        ]
        used = [
            r.requested_units
            for r in reservations
            if str(r.reservation_id) != exclude_reservation
        ] + [entry.actual_units for entry in entries]
        remaining = {
            key: max(0, limit - sum(getattr(units, key) for units in used))
            for key, limit in limits.items()
        }
        return BudgetRemaining(
            budget_binding_ref=scope,
            as_of_sequence=max((entry.sequence for entry in entries), default=0),
            available_units=BudgetUnits.model_validate(
                remaining | dict(currency=profile.currency)
            ),
            active_reservation_count=len(reservations),
        )

    def remaining(
        self, budget_scope_ref: BudgetScopeRef, analysis_id: str
    ) -> BudgetRemaining:
        # A read transaction provides a coherent reservation/ledger snapshot.
        with self.records.database.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN")
            return self.available(connection, budget_scope_ref, analysis_id)

    def commit_usage(self, request: BudgetCommitRequest) -> BudgetLedgerEntry:
        entry = BudgetLedgerEntry.model_validate(request.entry)
        with self.records.database.write() as connection:
            initial = self.records.resolve(connection, entry.reservation_ref)
            if not isinstance(initial, BudgetReservation):
                raise ValueError("Expected exact reservation")
            reservation_id = str(initial.reservation_id)
            table = models.budget_ledger_entries
            old = connection.execute(
                select(table.c.payload).where(table.c.reservation_id == reservation_id)
            ).scalar()
            if old:
                existing = BudgetLedgerEntry.model_validate_json(old)
                if existing != entry:
                    raise ValueError("Duplicate debit differs from committed usage")
                return existing
            row = (
                connection.execute(
                    select(models.budget_reservations).where(
                        models.budget_reservations.c.reservation_id == reservation_id
                    )
                )
                .mappings()
                .one()
            )
            reservation = BudgetReservation.model_validate_json(row["payload"])
            if reservation.status != ReservationStatus.RESERVED:
                raise ValueError("Reservation already finalized")
            for field in ("budget_binding_ref", "action_ref", "work_ref"):
                if getattr(entry, field) != getattr(reservation, field):
                    raise ValueError("Ledger scope mismatch")
            if (
                entry.meta.analysis_id != reservation.meta.analysis_id
                or entry.actual_units.currency != reservation.requested_units.currency
            ):
                raise ValueError("Ledger analysis/currency mismatch")
            remaining = self.available(
                connection, entry.budget_binding_ref, str(entry.meta.analysis_id)
            )
            if entry.sequence != remaining.as_of_sequence + 1:
                raise ValueError("Ledger sequence must be consecutive")
            for usage in entry.usage_refs:
                resolved = self.records.resolve(connection, usage)
                if (
                    getattr(resolved.meta, "analysis_id", None)
                    != entry.meta.analysis_id
                ):
                    raise ValueError("Usage analysis mismatch")
            ref = self.records.stage(connection, entry)
            self.records.publish(connection, ref)
            finalized = BudgetReservation.model_validate(
                reservation.model_dump()
                | dict(
                    meta=next_meta(reservation.meta, self.clock, self.ids),
                    status=ReservationStatus.COMMITTED,
                    finalized_at=self.clock.now(),
                    ledger_entry_ref=ref,
                )
            )
            self.finalize(connection, reservation, finalized)
            connection.execute(
                insert(table).values(
                    ledger_entry_id=str(entry.ledger_entry_id),
                    reservation_id=reservation_id,
                    analysis_id=str(entry.meta.analysis_id),
                    sequence=entry.sequence,
                    payload=encode(entry),
                )
            )
            return entry

    def finalize(
        self,
        connection: Connection,
        previous: BudgetReservation,
        current: BudgetReservation,
    ) -> None:
        validate_reservation_revision(previous, current)
        ref = self.records.stage(connection, current)
        self.records.publish(connection, ref)
        connection.execute(
            update(models.budget_reservations)
            .where(
                models.budget_reservations.c.reservation_id
                == str(current.reservation_id)
            )
            .values(status=current.status.value, payload=encode(current))
        )

    def release(self, request: BudgetReleaseRequest) -> BudgetReservation:
        release = BudgetReservation.model_validate(request.reservation)
        with self.records.database.write() as connection:
            table = models.budget_reservations
            row = (
                connection.execute(
                    select(table).where(
                        table.c.reservation_id == str(release.reservation_id)
                    )
                )
                .mappings()
                .one()
            )
            previous = BudgetReservation.model_validate_json(row["payload"])
            if previous.status != ReservationStatus.RESERVED:
                return previous
            if row["claimed"] or release.status != ReservationStatus.RELEASED:
                raise ValueError("BUDGET: cannot release uncertain or used reservation")
            self.finalize(connection, previous, release)
            return release
