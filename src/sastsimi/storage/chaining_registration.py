"""Durable Chaining cohorts, historical pools, and match reservations."""

from collections.abc import Callable

from pydantic import TypeAdapter
from sqlalchemy import Connection, insert, select, update
from sqlalchemy.exc import IntegrityError

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetReservation,
    BudgetUnits,
    ReservationStatus,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    PrimitiveAdmissionDecision,
    PrimitiveIndexState,
)
from sastsimi.contracts.ids import (
    ActionId,
    LedgerEntryId,
    ReservationId,
    TransitionId,
    WorkId,
)
from sastsimi.contracts.records import RecordMeta, RecordMetadata
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    StoredDataRef,
    require_record_ref,
)
from sastsimi.contracts.work import (
    CommitState,
    StateTransition,
    SubjectType,
    TransitionCommit,
    TransitionTargetStatus,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.chaining import (
    ChainingCohortMember,
    ChainingCohortRegistration,
    ChainingMatchIdentity,
    ChainingPoolHistory,
    PinnedChainingUniverse,
    PrimitiveUpdateOutcome,
)
from sastsimi.ports.dto import BudgetCommitRequest, BudgetReservationRequest

from . import models
from .authorization import authorize
from .codec import REF_ADAPTER, encode, reference
from .committed_outputs import require_committed
from .records import fresh_meta, next_meta
from .repositories import SQLiteRecordStore
from .work_service import WorkService

_STORED_REFS = TypeAdapter(tuple[StoredDataRef, ...])


def _wire(ref: StoredDataRef) -> str:
    return canonical_bytes(ref).decode("utf-8")


def _scope(record: object) -> tuple[str | None, str | None, str | None]:
    meta = record if isinstance(record, RecordMeta) else getattr(record, "meta", None)
    values = (
        getattr(meta, "analysis_id", None),
        getattr(meta, "workspace_id", None),
        getattr(meta, "commit_id", None),
    )
    return (
        str(values[0]) if values[0] is not None else None,
        str(values[1]) if values[1] is not None else None,
        str(values[2]) if values[2] is not None else None,
    )


class ChainingPoolHistoryStore:
    """Read only the immutable pool stored for one exact work revision."""

    def __init__(self, records: SQLiteRecordStore) -> None:
        self.records = records

    def get_for_trigger(self, trigger_work_ref: StoredDataRef) -> ChainingPoolHistory:
        require_record_ref(trigger_work_ref, "work_execution_state")
        with self.records.database.engine.connect() as connection:
            work = self.records.resolve(connection, trigger_work_ref)
            if not isinstance(work, WorkExecutionState):
                raise ValueError("CHAINING_POOL_WORK_MISMATCH")
            current_payload = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.work_id == str(work.work_id)
                )
            ).scalar_one_or_none()
            if current_payload is None:
                raise LookupError("CHAINING_POOL_NOT_FOUND")
            current = WorkExecutionState.model_validate_json(current_payload)
            if reference(current) != trigger_work_ref:
                raise ValueError("CHAINING_POOL_WORK_MISMATCH")
            row = (
                connection.execute(
                    select(models.chaining_work_pools).where(
                        models.chaining_work_pools.c.work_id == str(work.work_id)
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise LookupError("CHAINING_POOL_NOT_FOUND")
            return self._decode_row(connection, row, trigger_work_ref)

    def get_for_primitive(
        self, trigger_primitive_ref: StoredDataRef
    ) -> ChainingPoolHistory:
        require_record_ref(trigger_primitive_ref, "primitive")
        with self.records.database.engine.connect() as connection:
            primitive = self.records.resolve(connection, trigger_primitive_ref)
            if not isinstance(primitive, Primitive):
                raise ValueError("CHAINING_POOL_TRIGGER_MISMATCH")
            rows = (
                connection.execute(
                    select(models.chaining_work_pools).where(
                        models.chaining_work_pools.c.trigger_primitive_ref
                        == _wire(trigger_primitive_ref)
                    )
                )
                .mappings()
                .all()
            )
            if len(rows) != 1:
                raise LookupError("CHAINING_POOL_NOT_FOUND")
            row = rows[0]
            if _scope(primitive) != (
                row["analysis_id"],
                row["workspace_id"],
                row["commit_id"],
            ):
                raise ValueError("CHAINING_POOL_TRIGGER_MISMATCH")
            stored_work_ref = REF_ADAPTER.validate_json(row["trigger_work_ref"])
            if not isinstance(stored_work_ref, StoredDataRef):
                raise ValueError("CHAINING_POOL_REF_KIND")
            return self._decode_row(connection, row, stored_work_ref)

    def _decode_row(
        self,
        connection: Connection,
        row: object,
        trigger_work_ref: StoredDataRef,
    ) -> ChainingPoolHistory:
        from collections.abc import Mapping

        from sastsimi.contracts.canonical_json import content_hash

        if not isinstance(row, Mapping):
            raise ValueError("CHAINING_POOL_INTEGRITY_MISMATCH")
        work = self.records.resolve(connection, trigger_work_ref)
        if (
            not isinstance(work, WorkExecutionState)
            or str(work.work_id) != row["work_id"]
            or work.work_type != WorkType.CHAINING
            or work.work_generation != row["work_generation"]
            or work.input_hash != row["input_hash"]
            or work.input_hash != content_hash(work.input_refs)
        ):
            raise ValueError("CHAINING_POOL_WORK_MISMATCH")
        trigger_ref = REF_ADAPTER.validate_json(row["trigger_primitive_ref"])
        if not isinstance(trigger_ref, StoredDataRef):
            raise ValueError("CHAINING_POOL_REF_KIND")
        index_refs = _STORED_REFS.validate_json(row["index_refs"])
        considered_refs = _STORED_REFS.validate_json(row["considered_primitive_refs"])
        universe = PinnedChainingUniverse(
            trigger_primitive_ref=trigger_ref,
            index_refs=index_refs,
            considered_primitive_refs=considered_refs,
        )
        expected_inputs = (*universe.index_refs, *universe.considered_primitive_refs)
        if (
            row["pool_hash"] != self._pool_hash(universe)
            or _scope(work)
            != (row["analysis_id"], row["workspace_id"], row["commit_id"])
            or work.trigger_primitive_ref != universe.trigger_primitive_ref
            or work.input_refs != expected_inputs
        ):
            raise ValueError("CHAINING_POOL_INTEGRITY_MISMATCH")
        return ChainingPoolHistory(
            trigger_work_ref=trigger_work_ref,
            universe=universe,
        )

    @staticmethod
    def _pool_hash(universe: PinnedChainingUniverse) -> str:
        from sastsimi.contracts.canonical_json import content_hash

        return content_hash(
            [
                universe.trigger_primitive_ref,
                universe.index_refs,
                universe.considered_primitive_refs,
            ]
        )


class ChainingCommittedSourceStore:
    """Reconstruct recovery handoffs from committed records, never pointers."""

    def __init__(self, records: SQLiteRecordStore) -> None:
        self.records = records

    def primitive_update(
        self, source_update_ref: StoredDataRef
    ) -> PrimitiveUpdateOutcome:
        require_record_ref(source_update_ref, "transition_commit")
        with self.records.database.engine.connect() as connection:
            commit = self.records.resolve(connection, source_update_ref)
            if not isinstance(commit, TransitionCommit) or commit.state != "COMMITTED":
                raise ValueError("CHAINING_SOURCE_NOT_COMMITTED")
            payload = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.work_id == str(commit.work_id)
                )
            ).scalar_one_or_none()
            if payload is None:
                raise LookupError("CHAINING_SOURCE_WORK_NOT_FOUND")
            work = WorkExecutionState.model_validate_json(payload)
            work_ref = reference(work)
            if (
                not isinstance(work_ref, StoredDataRef)
                or work.work_type != WorkType.PRIMITIVE_UPDATE
                or work.status != WorkStatus.SUCCEEDED
                or work.last_transition_commit_ref != source_update_ref
                or work.output_refs != commit.output_refs
            ):
                raise ValueError("CHAINING_UPDATE_OUTCOME_MISMATCH")
            outputs = tuple(
                self.records.resolve(connection, output_ref)
                for output_ref in commit.output_refs
            )
            admission_outputs = tuple(
                output
                for output in outputs
                if isinstance(output, PrimitiveAdmissionDecision)
            )
            primitive_outputs = tuple(
                output for output in outputs if isinstance(output, Primitive)
            )
            admissions = tuple(
                value
                for output in admission_outputs
                if isinstance(value := reference(output), StoredDataRef)
            )
            primitive_refs = tuple(
                value
                for output in primitive_outputs
                if isinstance(value := reference(output), StoredDataRef)
            )
            if (
                len(outputs) != len(admission_outputs) + len(primitive_outputs)
                or len(admissions) != len(admission_outputs)
                or len(primitive_refs) != len(primitive_outputs)
            ):
                raise ValueError("CHAINING_UPDATE_OUTCOME_MISMATCH")
            if admissions:
                if (
                    len(admissions) != 1
                    or (
                        primitive_outputs
                        and (
                            admission_outputs[0].decision != "ALLOW"
                            or any(
                                primitive.result is None
                                or primitive.admission_decision_ref != admissions[0]
                                for primitive in primitive_outputs
                            )
                        )
                    )
                    or (
                        not primitive_outputs
                        and admission_outputs[0].decision != "DENY"
                    )
                ):
                    raise ValueError("CHAINING_UPDATE_OUTCOME_MISMATCH")
                admission_ref: StoredDataRef | None = admissions[0]
            else:
                if any(
                    primitive.result is not None
                    or primitive.admission_decision_ref is not None
                    for primitive in primitive_outputs
                ):
                    raise ValueError("CHAINING_UPDATE_OUTCOME_MISMATCH")
                admission_ref = None
            index_ref = self._index_for_update(connection, work, primitive_refs)
            return PrimitiveUpdateOutcome(
                source_work_ref=work_ref,
                transition_commit_ref=source_update_ref,
                admission_decision_ref=admission_ref,
                primitive_refs=primitive_refs,
                primitive_index_ref=index_ref,
            )

    def chaining_result(self, source_result_ref: StoredDataRef) -> ChainingResult:
        require_record_ref(source_result_ref, "chaining_result")
        with self.records.database.engine.connect() as connection:
            result = self.records.resolve(connection, source_result_ref)
            if not isinstance(result, ChainingResult):
                raise ValueError("CHAINING_RESULT_SOURCE_MISMATCH")
            require_committed(self.records, connection, result, WorkType.CHAINING)
            return result

    def _index_for_update(
        self,
        connection: Connection,
        work: WorkExecutionState,
        primitive_refs: tuple[StoredDataRef, ...],
    ) -> StoredDataRef | None:
        if not primitive_refs:
            return None
        matches: list[StoredDataRef] = []
        for wire in connection.execute(
            select(models.records.c.ref)
            .join(
                models.record_revisions,
                models.record_revisions.c.record_id == models.records.c.record_id,
            )
            .where(models.records.c.kind == "primitive_index_state")
        ).scalars():
            candidate_ref = REF_ADAPTER.validate_json(wire)
            if not isinstance(candidate_ref, StoredDataRef):
                continue
            candidate = self.records.resolve(connection, candidate_ref)
            if not isinstance(candidate, PrimitiveIndexState) or _scope(
                candidate
            ) != _scope(work):
                continue
            previous_id = candidate.meta.previous_record_id
            if previous_id is None:
                continue
            previous_wire = connection.execute(
                select(models.records.c.ref)
                .join(
                    models.record_revisions,
                    models.record_revisions.c.record_id == models.records.c.record_id,
                )
                .where(models.records.c.record_id == str(previous_id))
            ).scalar_one_or_none()
            if previous_wire is None:
                continue
            previous_ref = REF_ADAPTER.validate_json(previous_wire)
            previous = self.records.resolve(connection, previous_ref)
            if isinstance(
                previous, PrimitiveIndexState
            ) and candidate.primitive_refs == (
                *previous.primitive_refs,
                *primitive_refs,
            ):
                matches.append(candidate_ref)
        if len(matches) != 1:
            raise ValueError("CHAINING_UPDATE_INDEX_NOT_EXACT")
        return matches[0]


class ChainingCohortStore:
    """Register and reveal one complete sibling cohort in atomic transactions."""

    def __init__(
        self,
        works: WorkService,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.works = works
        self.records = works.records
        self.pools = ChainingPoolHistoryStore(self.records)
        self.checkpoint = checkpoint or (lambda _stage: None)

    def register_pending(
        self,
        *,
        outcome: PrimitiveUpdateOutcome,
        scope: BudgetScopeRef,
        requester_identity_ref: BudgetScopeRef,
        metadata: RecordMetadata,
        generation: int,
    ) -> ChainingCohortRegistration:
        if not isinstance(metadata, RecordMeta) or generation < 1:
            raise ValueError("CHAINING_REGISTRATION_SCOPE_MISMATCH")
        with self.records.database.write() as connection:
            self._validate_outcome(connection, outcome, metadata, generation)
            existing = self._read_registration(
                connection, outcome.transition_commit_ref, required=False
            )
            if existing is not None:
                self._validate_replay(existing, outcome, generation)
                return existing

            index_refs, considered_refs = self._current_universe(
                connection,
                source_index_ref=outcome.primitive_index_ref,
                metadata=metadata,
            )
            if any(ref not in considered_refs for ref in outcome.primitive_refs):
                raise ValueError("CHAINING_UPDATE_INDEX_NOT_CURRENT")

            source_wire = _wire(outcome.transition_commit_ref)
            from sastsimi.contracts.canonical_json import content_hash

            cohort_id = content_hash([outcome.transition_commit_ref])
            connection.execute(
                insert(models.chaining_cohorts).values(
                    cohort_id=cohort_id,
                    source_update_ref=source_wire,
                    analysis_id=str(metadata.analysis_id),
                    workspace_id=str(metadata.workspace_id),
                    commit_id=str(metadata.commit_id),
                    member_count=len(outcome.primitive_refs),
                    status="PENDING",
                )
            )
            members: list[ChainingCohortMember] = []
            for order, trigger_ref in enumerate(outcome.primitive_refs):
                universe = PinnedChainingUniverse(
                    trigger_primitive_ref=trigger_ref,
                    index_refs=index_refs,
                    considered_primitive_refs=considered_refs,
                )
                inputs = (*universe.index_refs, *universe.considered_primitive_refs)
                work = self._pending_work(
                    metadata,
                    generation,
                    trigger_ref,
                    inputs,
                    outcome.transition_commit_ref,
                )
                registered = self._register_one(
                    connection,
                    work,
                    scope,
                    requester_identity_ref,
                )
                work_ref = reference(registered)
                assert isinstance(work_ref, StoredDataRef)
                pool = ChainingPoolHistory(
                    trigger_work_ref=work_ref,
                    universe=universe,
                )
                connection.execute(
                    insert(models.chaining_work_pools).values(
                        work_id=str(work.work_id),
                        cohort_id=cohort_id,
                        member_order=order,
                        analysis_id=str(metadata.analysis_id),
                        workspace_id=str(metadata.workspace_id),
                        commit_id=str(metadata.commit_id),
                        trigger_work_ref=_wire(work_ref),
                        work_generation=work.work_generation,
                        input_hash=work.input_hash,
                        trigger_primitive_ref=_wire(trigger_ref),
                        index_refs=canonical_bytes(universe.index_refs).decode(),
                        considered_primitive_refs=canonical_bytes(
                            universe.considered_primitive_refs
                        ).decode(),
                        pool_hash=self.pools._pool_hash(universe),
                    )
                )
                members.append(ChainingCohortMember(work=registered, pool=pool))
                self.checkpoint("pending_member")
            registration = ChainingCohortRegistration(
                source_update_ref=outcome.transition_commit_ref,
                members=tuple(members),
                status="PENDING",
            )
            self.checkpoint("pending_complete")
            return registration

    def promote_ready(
        self,
        *,
        registration: ChainingCohortRegistration,
        scope: BudgetScopeRef,
        requester_identity_ref: BudgetScopeRef,
    ) -> ChainingCohortRegistration:
        with self.records.database.write() as connection:
            stored = self._read_registration(
                connection, registration.source_update_ref, required=True
            )
            assert stored is not None
            self._require_same_registration(registration, stored)
            if stored.status == "READY":
                return stored
            ready_members: list[ChainingCohortMember] = []
            for member in stored.members:
                if self._registration_scope(connection, member.work) != scope:
                    raise ValueError("CHAINING_COHORT_SCOPE_MISMATCH")
                ready = self._make_ready(
                    connection,
                    member.work,
                    requester_identity_ref,
                )
                ready_ref = reference(ready)
                assert isinstance(ready_ref, StoredDataRef)
                connection.execute(
                    update(models.chaining_work_pools)
                    .where(models.chaining_work_pools.c.work_id == str(ready.work_id))
                    .values(trigger_work_ref=_wire(ready_ref))
                )
                ready_members.append(
                    ChainingCohortMember(
                        work=ready,
                        pool=ChainingPoolHistory(
                            trigger_work_ref=ready_ref,
                            universe=member.pool.universe,
                        ),
                    )
                )
                self.checkpoint("ready_member")
            connection.execute(
                update(models.chaining_cohorts)
                .where(
                    models.chaining_cohorts.c.source_update_ref
                    == _wire(registration.source_update_ref),
                    models.chaining_cohorts.c.status == "PENDING",
                )
                .values(status="READY")
            )
            result = ChainingCohortRegistration(
                source_update_ref=stored.source_update_ref,
                members=tuple(ready_members),
                status="READY",
            )
            self.checkpoint("ready_complete")
            return result

    def _validate_outcome(
        self,
        connection: Connection,
        outcome: PrimitiveUpdateOutcome,
        metadata: RecordMeta,
        generation: int,
    ) -> PrimitiveIndexState:
        if not outcome.primitive_refs or outcome.primitive_index_ref is None:
            raise ValueError("CHAINING_COHORT_EMPTY")
        work = self.records.resolve(connection, outcome.source_work_ref)
        commit = self.records.resolve(connection, outcome.transition_commit_ref)
        index = self.records.resolve(connection, outcome.primitive_index_ref)
        if (
            not isinstance(work, WorkExecutionState)
            or work.work_type != "PRIMITIVE_UPDATE"
            or work.status != WorkStatus.SUCCEEDED
            or work.last_transition_commit_ref != outcome.transition_commit_ref
            or not isinstance(commit, TransitionCommit)
            or commit.state != CommitState.COMMITTED
            or commit.work_id != work.work_id
            or commit.output_refs != work.output_refs
            or not isinstance(index, PrimitiveIndexState)
            or _scope(work) != _scope(index)
            or _scope(work) != _scope(metadata)
        ):
            raise ValueError("CHAINING_UPDATE_OUTCOME_MISMATCH")
        if generation != work.work_generation:
            raise ValueError("CHAINING_UPDATE_GENERATION_MISMATCH")
        expected_outputs = set(outcome.primitive_refs)
        if outcome.admission_decision_ref is not None:
            expected_outputs.add(outcome.admission_decision_ref)
        if set(commit.output_refs) != expected_outputs:
            raise ValueError("CHAINING_UPDATE_OUTCOME_MISMATCH")
        for primitive_ref in outcome.primitive_refs:
            primitive = self.records.resolve(connection, primitive_ref)
            if (
                not isinstance(primitive, Primitive)
                or primitive_ref not in index.primitive_refs
                or _scope(primitive) != _scope(work)
            ):
                raise ValueError("CHAINING_UPDATE_OUTCOME_MISMATCH")
        if outcome.admission_decision_ref is not None:
            self.records.resolve(connection, outcome.admission_decision_ref)
        return index

    def _current_universe(
        self,
        connection: Connection,
        *,
        source_index_ref: StoredDataRef | None,
        metadata: RecordMeta,
    ) -> tuple[tuple[StoredDataRef, ...], tuple[StoredDataRef, ...]]:
        if source_index_ref is None:
            raise ValueError("CHAINING_COHORT_EMPTY")
        scoped: list[tuple[StoredDataRef, PrimitiveIndexState]] = []
        for wire in connection.execute(
            select(models.records.c.ref)
            .join(
                models.current_records,
                models.current_records.c.record_id == models.records.c.record_id,
            )
            .where(models.records.c.kind == "primitive_index_state")
        ).scalars():
            candidate_ref = REF_ADAPTER.validate_json(wire)
            if not isinstance(candidate_ref, StoredDataRef):
                raise ValueError("CHAINING_PINNED_REF_KIND")
            candidate = self.records.resolve(connection, candidate_ref)
            if isinstance(candidate, PrimitiveIndexState) and _scope(
                candidate
            ) == _scope(metadata):
                scoped.append((candidate_ref, candidate))
        scoped.sort(key=lambda item: _wire(item[0]))
        index_refs = tuple(item[0] for item in scoped)
        if source_index_ref not in index_refs:
            raise ValueError("CHAINING_UPDATE_INDEX_NOT_CURRENT")
        hypotheses = tuple(str(item.meta.hypothesis_id) for _, item in scoped)
        if any(item.meta.hypothesis_id is None for _, item in scoped) or len(
            set(hypotheses)
        ) != len(hypotheses):
            raise ValueError("CHAINING_INDEX_SCOPE_CONFLICT")
        considered: dict[bytes, StoredDataRef] = {}
        for _, current_index in scoped:
            for primitive_ref in current_index.primitive_refs:
                primitive = self.records.resolve(connection, primitive_ref)
                if (
                    not isinstance(primitive, Primitive)
                    or _scope(primitive) != _scope(metadata)
                    or primitive.meta.hypothesis_id != current_index.meta.hypothesis_id
                ):
                    raise ValueError("CHAINING_INDEX_PRIMITIVE_MISMATCH")
                considered.setdefault(canonical_bytes(primitive_ref), primitive_ref)
        considered_refs = tuple(considered[key] for key in sorted(considered))
        return index_refs, considered_refs

    def _pending_work(
        self,
        metadata: RecordMeta,
        generation: int,
        trigger_ref: StoredDataRef,
        inputs: tuple[StoredDataRef, ...],
        source_update_ref: StoredDataRef,
    ) -> WorkExecutionState:
        from sastsimi.contracts.canonical_json import content_hash

        work_id = self.works.ids.new(WorkId)
        dedupe = content_hash([source_update_ref, trigger_ref, inputs])
        return WorkExecutionState.model_validate(
            dict(
                meta=fresh_meta(
                    metadata,
                    "work_execution_state",
                    self.works.clock,
                    self.works.ids,
                    attempt_id=None,
                ),
                work_id=work_id,
                parent_work_ref=None,
                work_type=WorkType.CHAINING,
                subject_type=SubjectType.ANALYSIS,
                subject_id=metadata.analysis_id,
                work_generation=generation,
                status=WorkStatus.PENDING,
                state_version=1,
                last_transition_ref=None,
                last_transition_commit_ref=None,
                active_attempt_id=None,
                input_hash=content_hash(inputs),
                dedupe_key=dedupe,
                trigger_primitive_ref=trigger_ref,
                input_refs=inputs,
                output_refs=(),
                gap_ids=(),
                error_ids=(),
                waiting_for=(),
                stop_reason=None,
                started_at=None,
                finished_at=None,
                elapsed_ms=0,
            )
        )

    def _action(
        self,
        work: WorkExecutionState,
        requester_identity_ref: BudgetScopeRef,
        action_type: ActionType,
    ) -> ActionRequest:
        role = self.records.evidence.identity_role(requester_identity_ref)
        if role not in {
            RequesterRole.PRIMITIVE_ADMISSION_RUNTIME,
            RequesterRole.RECOVERY,
        }:
            raise ValueError("AUTHORITY_DENIED: Chaining cohort registrar required")
        return ActionRequest.model_validate(
            dict(
                meta=fresh_meta(
                    work.meta,
                    "action_request",
                    self.works.clock,
                    self.works.ids,
                    attempt_id=None,
                ),
                action_id=self.works.ids.new(ActionId),
                requested_by=role,
                requester_identity_ref=requester_identity_ref,
                action_type=action_type,
                work_ref=None
                if action_type == ActionType.REGISTER_WORK
                else reference(work),
                expected_state_version=None
                if action_type == ActionType.REGISTER_WORK
                else work.state_version,
                expected_verification_generation=None,
                generation_restart_reason=None,
                generation_restart_basis_refs=(),
                input_refs=work.input_refs,
                dynamic_request_ref=None,
                reproduction_plan_ref=None,
                result_kind=None,
                candidate_result_ref=None,
                llm_call_spec_ref=None,
                tool_name=None,
                file_paths=(),
                provider_profile_ref=None,
                session_mode=None,
                sandbox_profile_ref=None,
                resource_profile_ref=None,
                run_policy_state_ref=None,
                image_digest=None,
                network_targets=(),
                resource_limits=None,
                reason="Register or reveal an exact pinned Chaining cohort",
                requested_at=self.works.clock.now(),
            )
        )

    def _register_one(
        self,
        connection: Connection,
        work: WorkExecutionState,
        scope: BudgetScopeRef,
        requester_identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState:
        from sastsimi.contracts.canonical_json import content_hash

        action = self._action(work, requester_identity_ref, ActionType.REGISTER_WORK)
        work_ref = self.records.stage(connection, work)
        action_ref = self.records.stage(connection, action)
        remaining = self.works.validator.budget.available(
            connection, scope, str(work.meta.analysis_id)
        )
        units = BudgetUnits(
            elapsed_ms=0,
            work_count=1,
            llm_call_count=0,
            retry_count=0,
            cost_minor_units=0,
            currency=remaining.available_units.currency,
        )
        reservation = BudgetReservation.model_validate(
            dict(
                meta=fresh_meta(
                    work.meta,
                    "budget_reservation",
                    self.works.clock,
                    self.works.ids,
                    attempt_id=None,
                ),
                reservation_id=self.works.ids.new(ReservationId),
                budget_binding_ref=scope,
                action_ref=action_ref,
                work_ref=work_ref,
                requested_units=units,
                status=ReservationStatus.RESERVED,
                ledger_entry_ref=None,
                reserved_at=self.works.clock.now(),
                finalized_at=None,
            )
        )
        reserved = self.works.validator.budget.reserve(
            BudgetReservationRequest(reservation), _connection=connection
        )
        reservation_ref = reference(reserved)
        decision = authorize(
            self.works.validator,
            action,
            work,
            reservation_ref,
            _connection=connection,
        )
        if decision.decision != "ALLOW":
            raise ValueError("ACTION_DENIED: Chaining cohort registration")
        decision_ref = reference(decision)
        self.works.validator.claim(
            connection,
            decision_ref,
            ActionType.REGISTER_WORK,
            work,
            reservation_ref,
            needs_budget=True,
        )
        self.records.publish(connection, work_ref)
        registration_key = content_hash(
            [
                work.meta.analysis_id,
                work.work_type,
                work.subject_id,
                work.work_generation,
                work.dedupe_key,
            ]
        )
        connection.execute(
            insert(models.work_states).values(
                work_id=str(work.work_id),
                analysis_id=str(work.meta.analysis_id),
                registration_key=registration_key,
                status=work.status.value,
                state_version=work.state_version,
                active_attempt_id=None,
                payload=encode(work),
            )
        )
        self.works.point(connection, work)
        remaining = self.works.validator.budget.available(
            connection, scope, str(work.meta.analysis_id)
        )
        entry = BudgetLedgerEntry.model_validate(
            dict(
                meta=fresh_meta(
                    reservation.meta,
                    "budget_ledger_entry",
                    self.works.clock,
                    self.works.ids,
                ),
                ledger_entry_id=self.works.ids.new(LedgerEntryId),
                reservation_ref=reservation_ref,
                budget_binding_ref=scope,
                action_ref=action_ref,
                work_ref=work_ref,
                actual_units=units,
                usage_refs=(),
                sequence=remaining.as_of_sequence + 1,
                committed_at=self.works.clock.now(),
            )
        )
        self.works.validator.budget.commit_usage(
            BudgetCommitRequest(entry), _connection=connection
        )
        return work

    def _make_ready(
        self,
        connection: Connection,
        work: WorkExecutionState,
        requester_identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState:
        from sastsimi.contracts.canonical_json import content_hash

        action = self._action(
            work, requester_identity_ref, ActionType.CHANGE_WORK_STATE
        )
        decision = authorize(
            self.works.validator,
            action,
            work,
            None,
            _connection=connection,
        )
        if decision.decision != "ALLOW":
            raise ValueError("ACTION_DENIED: Chaining cohort readiness")
        decision_ref = reference(decision)
        self.works.validator.claim(
            connection,
            decision_ref,
            ActionType.CHANGE_WORK_STATE,
            work,
        )
        transition = StateTransition.model_validate(
            dict(
                meta=fresh_meta(
                    work.meta,
                    "state_transition",
                    self.works.clock,
                    self.works.ids,
                    attempt_id=None,
                ),
                transition_id=self.works.ids.new(TransitionId),
                work_id=work.work_id,
                action_decision_ref=decision_ref,
                from_status=work.status,
                to_status=TransitionTargetStatus.READY,
                expected_state_version=work.state_version,
                new_state_version=work.state_version + 1,
                attempt_id=None,
                cause="CHAINING_COHORT_READY",
                output_refs=(),
                gap_ids=(),
                error_ids=(),
                dedupe_key=content_hash([work.work_id, work.state_version, "READY"]),
                created_at=self.works.clock.now(),
            )
        )
        transition_ref = self.records.stage(connection, transition)
        self.records.publish(connection, transition_ref)
        ready = WorkExecutionState.model_validate(
            work.model_dump()
            | dict(
                meta=next_meta(work.meta, self.works.clock, self.works.ids),
                status=WorkStatus.READY,
                state_version=transition.new_state_version,
                last_transition_ref=transition_ref,
                output_refs=(),
                waiting_for=(),
                stop_reason=None,
            )
        )
        self.works.save(connection, work, ready)
        return ready

    def _read_registration(
        self,
        connection: Connection,
        source_update_ref: StoredDataRef,
        *,
        required: bool,
    ) -> ChainingCohortRegistration | None:
        row = (
            connection.execute(
                select(models.chaining_cohorts).where(
                    models.chaining_cohorts.c.source_update_ref
                    == _wire(source_update_ref)
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            if required:
                raise LookupError("CHAINING_COHORT_NOT_FOUND")
            return None
        pool_rows = (
            connection.execute(
                select(models.chaining_work_pools)
                .where(models.chaining_work_pools.c.cohort_id == row["cohort_id"])
                .order_by(models.chaining_work_pools.c.member_order)
            )
            .mappings()
            .all()
        )
        if len(pool_rows) != row["member_count"]:
            raise ValueError("CHAINING_COHORT_PARTIAL_VISIBILITY")
        members = []
        for pool_row in pool_rows:
            work_ref = REF_ADAPTER.validate_json(pool_row["trigger_work_ref"])
            if not isinstance(work_ref, StoredDataRef):
                raise ValueError("CHAINING_POOL_REF_KIND")
            resolved_work = self.records.resolve(connection, work_ref)
            if not isinstance(resolved_work, WorkExecutionState):
                raise ValueError("CHAINING_POOL_WORK_MISMATCH")
            work = resolved_work
            pool = self.pools._decode_row(connection, pool_row, work_ref)
            members.append(ChainingCohortMember(work=work, pool=pool))
        return ChainingCohortRegistration(
            source_update_ref=source_update_ref,
            members=tuple(members),
            status=row["status"],
        )

    def _registration_scope(
        self, connection: Connection, work: WorkExecutionState
    ) -> BudgetScopeRef:
        matches: list[BudgetScopeRef] = []
        for payload in connection.execute(
            select(models.budget_reservations.c.payload).where(
                models.budget_reservations.c.analysis_id == str(work.meta.analysis_id)
            )
        ).scalars():
            reservation = BudgetReservation.model_validate_json(payload)
            candidate = self.records.resolve(
                connection, reservation.work_ref, candidate=True
            )
            action = self.records.resolve(connection, reservation.action_ref)
            if (
                isinstance(candidate, WorkExecutionState)
                and candidate.work_id == work.work_id
                and isinstance(action, ActionRequest)
                and action.action_type == ActionType.REGISTER_WORK
            ):
                matches.append(reservation.budget_binding_ref)
        if len(matches) != 1:
            raise ValueError("CHAINING_COHORT_SCOPE_MISMATCH")
        return matches[0]

    @staticmethod
    def _validate_replay(
        registration: ChainingCohortRegistration,
        outcome: PrimitiveUpdateOutcome,
        generation: int,
    ) -> None:
        first_universe = registration.members[0].pool.universe
        if (
            registration.source_update_ref != outcome.transition_commit_ref
            or tuple(
                member.pool.universe.trigger_primitive_ref
                for member in registration.members
            )
            != outcome.primitive_refs
            or any(
                member.pool.universe.index_refs != first_universe.index_refs
                for member in registration.members
            )
            or any(
                member.pool.universe.considered_primitive_refs
                != first_universe.considered_primitive_refs
                for member in registration.members
            )
            or outcome.primitive_index_ref not in first_universe.index_refs
            or any(
                ref not in first_universe.considered_primitive_refs
                for ref in outcome.primitive_refs
            )
            or any(
                member.work.work_generation != generation
                for member in registration.members
            )
        ):
            raise ValueError("CHAINING_COHORT_REPLAY_MISMATCH")

    @staticmethod
    def _require_same_registration(
        supplied: ChainingCohortRegistration,
        stored: ChainingCohortRegistration,
    ) -> None:
        if supplied.source_update_ref != stored.source_update_ref or tuple(
            str(member.work.work_id) for member in supplied.members
        ) != tuple(str(member.work.work_id) for member in stored.members):
            raise ValueError("CHAINING_COHORT_REPLAY_MISMATCH")


class ChainingMatchReservationStore:
    """A reservation adapter bound to one caller-owned final transaction.

    It deliberately has no standalone database/write entry. The only
    production composition point is ``TransitionService.finish`` after all
    read-only checks, so nested rows and their source result commit or roll
    back together.
    """

    def __init__(self, records: SQLiteRecordStore, connection: Connection) -> None:
        self.records = records
        self.connection = connection

    def reserve_for_result(
        self,
        *,
        source_result_ref: StoredDataRef,
        identities: tuple[ChainingMatchIdentity, ...],
    ) -> None:
        require_record_ref(source_result_ref, "chaining_result")
        source = self.records.resolve(self.connection, source_result_ref)
        if not isinstance(source, ChainingResult) or not isinstance(
            source.meta, RecordMeta
        ):
            raise ValueError("CHAINING_RESERVATION_SOURCE_MISMATCH")
        expected = tuple(
            ChainingMatchIdentity(
                primitive_match_id=str(candidate.primitive_match_id),
                upstream_result_ref=candidate.upstream_result_ref,
                downstream_input_ref=candidate.downstream_input_ref,
                matched_input_id=str(candidate.matched_input_id),
            )
            for candidate in source.primitive_match_candidates
        )
        if identities != expected:
            raise ValueError("CHAINING_RESERVATION_SOURCE_MISMATCH")

        analysis_id = str(source.meta.analysis_id)
        source_wire = _wire(source_result_ref)
        seen_ids: set[str] = set()
        seen_triples: set[tuple[str, str, str]] = set()
        for identity in identities:
            require_record_ref(identity.upstream_result_ref, "primitive")
            require_record_ref(identity.downstream_input_ref, "primitive")
            if any(
                (value.workspace_id, value.commit_id)
                != (source.meta.workspace_id, source.meta.commit_id)
                for value in (
                    identity.upstream_result_ref,
                    identity.downstream_input_ref,
                )
            ):
                raise ValueError("CHAINING_RESERVATION_SCOPE_MISMATCH")
            upstream = _wire(identity.upstream_result_ref)
            downstream = _wire(identity.downstream_input_ref)
            triple = (upstream, downstream, identity.matched_input_id)
            if identity.primitive_match_id in seen_ids or triple in seen_triples:
                raise ValueError("CHAINING_MATCH_DUPLICATE")
            seen_ids.add(identity.primitive_match_id)
            seen_triples.add(triple)
            old = (
                self.connection.execute(
                    select(models.chaining_match_reservations).where(
                        models.chaining_match_reservations.c.analysis_id == analysis_id,
                        models.chaining_match_reservations.c.primitive_match_id
                        == identity.primitive_match_id,
                    )
                )
                .mappings()
                .one_or_none()
            )
            values = dict(
                analysis_id=analysis_id,
                primitive_match_id=identity.primitive_match_id,
                upstream_result_ref=upstream,
                downstream_input_ref=downstream,
                matched_input_id=identity.matched_input_id,
                source_result_ref=source_wire,
            )
            if old is not None:
                if dict(old) != values:
                    raise ValueError("CHAINING_MATCH_DUPLICATE")
                continue
            try:
                self.connection.execute(
                    insert(models.chaining_match_reservations).values(**values)
                )
            except IntegrityError as error:
                raise ValueError("CHAINING_MATCH_DUPLICATE") from error


def reserve_chaining_result_matches(
    records: SQLiteRecordStore,
    connection: Connection,
    result: ChainingResult,
) -> None:
    """Bind the exact trusted result candidates to global reservation rows."""
    result_ref = reference(result)
    if not isinstance(result_ref, StoredDataRef):
        raise ValueError("CHAINING_RESERVATION_SOURCE_MISMATCH")
    identities = tuple(
        ChainingMatchIdentity(
            primitive_match_id=str(candidate.primitive_match_id),
            upstream_result_ref=candidate.upstream_result_ref,
            downstream_input_ref=candidate.downstream_input_ref,
            matched_input_id=str(candidate.matched_input_id),
        )
        for candidate in result.primitive_match_candidates
    )
    ChainingMatchReservationStore(records, connection).reserve_for_result(
        source_result_ref=result_ref,
        identities=identities,
    )
