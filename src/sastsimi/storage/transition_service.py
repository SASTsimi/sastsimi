"""Durable PREPARED journal, repeat CAS, atomic publication and replay."""

import json
from collections.abc import Callable

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.result_registry import validate_result_owner
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import (
    AttemptStatus,
    CommitState,
    StateTransition,
    TransitionCommit,
    WaitingFor,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    validate_commit_transition,
    validate_transition_context,
)
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.codec import REF_ADAPTER, encode, reference

from .current_inputs import check_current_input
from .records import next_meta
from .run_states import get_run, save_run
from .work_service import WorkService


class TransitionService:
    def __init__(
        self,
        works: WorkService,
        artifacts: LocalArtifactStore,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.works, self.artifacts = works, artifacts
        self.checkpoint = checkpoint or (lambda name: None)

    def commit(self, request: TransitionCommitRequest) -> TransitionCommit:
        validate_commit_transition(request.commit, request.transition)
        if request.commit.state != CommitState.PREPARED:
            raise ValueError("Initial journal must be PREPARED")
        records = self.works.records
        refs = tuple(reference(record) for record in request.records)
        if len(set(refs)) != len(refs) or set(refs) != set(request.commit.output_refs):
            raise ValueError("OUTPUT_BINDING_MISMATCH")
        binding = content_hash([request.transition, request.commit, refs])
        table = models.transition_commits
        with records.database.engine.connect() as connection:
            old = (
                connection.execute(
                    select(table).where(
                        table.c.transition_commit_id
                        == str(request.commit.transition_commit_id)
                    )
                )
                .mappings()
                .first()
            )
        if old is not None:
            if old["candidate_binding"] != binding:
                raise ValueError("TRANSITION_BINDING_MISMATCH")
            result = TransitionCommit.model_validate_json(old["payload"])
            if result.state == CommitState.COMMITTED:
                return result
            if result.state == CommitState.ABORTED:
                raise ValueError(
                    "Transition already ABORTED: " + str(result.abort_reason)
                )
            return self.finish(request)
        for record in request.records:
            records.stage_record(record)
            self.artifacts.stage_bytes(encode(record).encode(), "application/json")
        self.checkpoint("staging")
        with records.database.write() as connection:
            self.check(connection, request)
            records.publish(connection, records.stage(connection, request.transition))
            records.publish(connection, records.stage(connection, request.commit))
            wire = dict(
                transition=reference(request.transition),
                commit=reference(request.commit),
                records=refs,
            )
            connection.execute(
                insert(table).values(
                    transition_commit_id=str(request.commit.transition_commit_id),
                    work_id=str(request.commit.work_id),
                    expected_state_version=request.commit.expected_state_version,
                    candidate_binding=binding,
                    state="PREPARED",
                    payload=encode(request.commit),
                    request=canonical_bytes(wire).decode(),
                )
            )
        self.checkpoint("PREPARED")
        try:
            return self.finish(request)
        except (ValueError, LookupError) as error:
            self.abort(request.commit, str(error))
            raise

    def check(
        self, connection: Connection, request: TransitionCommitRequest
    ) -> WorkExecutionState:
        refs = tuple(reference(record) for record in request.records)
        if len(set(refs)) != len(refs) or set(refs) != set(request.commit.output_refs):
            raise ValueError("OUTPUT_BINDING_MISMATCH")
        work = self.works.get(str(request.commit.work_id), connection)
        row = (
            connection.execute(
                select(models.work_states).where(
                    models.work_states.c.work_id == str(work.work_id)
                )
            )
            .mappings()
            .one()
        )
        if row["state_version"] != work.state_version or row["active_attempt_id"] != (
            str(work.active_attempt_id) if work.active_attempt_id else None
        ):
            raise ValueError("STATE_VERSION_CONFLICT")
        validate_transition_context(request.transition, work)
        _, action = self.works.validator.check(
            connection,
            request.transition.action_decision_ref,
            ActionType.SAVE_RESULT
            if request.commit.output_refs
            else ActionType.CHANGE_WORK_STATE,
            work,
        )
        for ref in work.input_refs:
            check_current_input(self.works.records, connection, ref)
        for record in request.records:
            if not isinstance(record, ContractModel):
                raise ValueError("OUTPUT_SCHEMA_MISMATCH")
            if reference(record) != action.candidate_result_ref:
                raise ValueError("OUTPUT_BINDING_MISMATCH")
            validate_result_owner(record.meta.record_type, record, action.requested_by)
            meta = record.meta
            if (
                getattr(meta, "analysis_id", work.meta.analysis_id)
                != work.meta.analysis_id
            ):
                raise ValueError("OUTPUT_ANALYSIS_MISMATCH")
            attempt = getattr(meta, "attempt_id", None)
            if attempt is not None and attempt != work.active_attempt_id:
                raise ValueError("ATTEMPT_NOT_ACTIVE")
        return work

    def finish(self, request: TransitionCommitRequest) -> TransitionCommit:
        records = self.works.records
        with records.database.write() as connection:
            self.check(connection, request)
        self.checkpoint("CAS")
        artifact_refs = []
        for record in request.records:
            staged = self.artifacts.stage_bytes(
                encode(record).encode(), "application/json"
            )
            artifact_refs.append(self.artifacts.promote(staged))
        self.checkpoint("rename")
        with records.database.write() as connection:
            previous = self.check(connection, request)
            claimed = self.works.validator.claim(
                connection,
                request.transition.action_decision_ref,
                ActionType.SAVE_RESULT
                if request.commit.output_refs
                else ActionType.CHANGE_WORK_STATE,
                previous,
            )
            committed = TransitionCommit.model_validate(
                request.commit.model_dump()
                | dict(
                    meta=next_meta(
                        request.commit.meta, self.works.clock, self.works.ids
                    ),
                    state=CommitState.COMMITTED,
                    committed_at=self.works.clock.now(),
                )
            )
            commit_ref = records.stage(connection, committed)
            records.publish(connection, commit_ref)
            for record in request.records:
                records.publish(connection, reference(record))
                self.publish_pointer(connection, reference(record))
                if isinstance(record, CodeWorkspace):
                    state = get_run(connection, str(record.analysis_id))
                    updated_state = AnalysisRunState.model_validate(
                        state.model_dump()
                        | dict(
                            meta=next_meta(
                                state.meta, self.works.clock, self.works.ids
                            ),
                            workspace_ref=reference(record),
                            workspace_id=record.workspace_id,
                            commit_id=record.commit_id,
                        )
                    )
                    save_run(records, connection, updated_state, state)
            self.works.validator.record_outcome(
                connection, claimed, committed.output_refs
            )
            for digest in artifact_refs:
                if not connection.execute(
                    select(models.artifacts.c.content_hash).where(
                        models.artifacts.c.content_hash == digest
                    )
                ).first():
                    connection.execute(
                        insert(models.artifacts).values(
                            content_hash=digest,
                            path="sha256/" + digest[:2] + "/" + digest[2:],
                        )
                    )
            terminal = request.commit.target_status.value != "BLOCKED"
            work = WorkExecutionState.model_validate(
                previous.model_dump()
                | dict(
                    meta=next_meta(previous.meta, self.works.clock, self.works.ids),
                    state_version=committed.target_state_version,
                    status=WorkStatus(committed.target_status.value),
                    active_attempt_id=None,
                    last_transition_ref=committed.transition_ref,
                    last_transition_commit_ref=commit_ref,
                    output_refs=committed.output_refs,
                    gap_ids=committed.gap_ids,
                    error_ids=committed.error_ids,
                    finished_at=self.works.clock.now() if terminal else None,
                    stop_reason=request.transition.cause,
                    waiting_for=() if terminal else (WaitingFor.INPUT,),
                )
            )
            if previous.active_attempt_id is not None:
                payload = connection.execute(
                    select(models.work_attempts.c.payload).where(
                        models.work_attempts.c.attempt_id
                        == str(previous.active_attempt_id)
                    )
                ).scalar_one()
                prior_attempt = WorkAttempt.model_validate_json(payload)
                ended = WorkAttempt.model_validate(
                    prior_attempt.model_dump()
                    | dict(
                        meta=next_meta(
                            prior_attempt.meta, self.works.clock, self.works.ids
                        ),
                        status=AttemptStatus(work.status.value)
                        if terminal
                        else AttemptStatus.CANCELLED,
                        finished_at=self.works.clock.now(),
                        output_refs=work.output_refs,
                        gap_ids=work.gap_ids,
                        error_ids=work.error_ids,
                    )
                )
                records.publish(connection, records.stage(connection, ended))
                connection.execute(
                    update(models.work_attempts)
                    .where(models.work_attempts.c.attempt_id == str(ended.attempt_id))
                    .values(status=ended.status.value, payload=encode(ended))
                )
            self.works.save(connection, previous, work)
            connection.execute(
                update(models.work_states)
                .where(models.work_states.c.work_id == str(work.work_id))
                .values(worker_id=None, lease_expires_at=None)
            )
            connection.execute(
                update(models.transition_commits)
                .where(
                    models.transition_commits.c.transition_commit_id
                    == str(committed.transition_commit_id),
                    models.transition_commits.c.state == "PREPARED",
                )
                .values(state="COMMITTED", payload=encode(committed))
            )
            self.checkpoint("transaction_B")
        self.checkpoint("COMMITTED")
        return committed

    def publish_pointer(self, connection: Connection, ref: RecordRef) -> None:
        record = self.works.records.resolve(connection, ref)
        table = models.current_records
        logical_id = str(record.meta.logical_record_id)
        old = (
            connection.execute(
                select(table).where(table.c.logical_record_id == logical_id)
            )
            .mappings()
            .first()
        )
        if old is None:
            if record.meta.revision_number != 1:
                raise ValueError(
                    "RECORD_REVISION_MISMATCH: missing current predecessor"
                )
            connection.execute(
                insert(table).values(
                    logical_record_id=logical_id,
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
        else:
            if old["record_id"] != str(record.meta.previous_record_id):
                raise ValueError("STALE_RESULT: current record predecessor")
            connection.execute(
                update(table)
                .where(
                    table.c.logical_record_id == logical_id,
                    table.c.state_version == old["state_version"],
                )
                .values(
                    record_id=str(record.meta.record_id),
                    state_version=old["state_version"] + 1,
                )
            )

    def abort(self, prepared: TransitionCommit, reason: str) -> None:
        records = self.works.records
        with records.database.write() as connection:
            state = connection.execute(
                select(models.transition_commits.c.state).where(
                    models.transition_commits.c.transition_commit_id
                    == str(prepared.transition_commit_id)
                )
            ).scalar_one()
            if state != "PREPARED":
                return
            aborted = TransitionCommit.model_validate(
                prepared.model_dump()
                | dict(
                    meta=next_meta(prepared.meta, self.works.clock, self.works.ids),
                    state=CommitState.ABORTED,
                    abort_reason=reason,
                )
            )
            records.publish(connection, records.stage(connection, aborted))
            connection.execute(
                update(models.transition_commits)
                .where(
                    models.transition_commits.c.transition_commit_id
                    == str(aborted.transition_commit_id)
                )
                .values(state="ABORTED", payload=encode(aborted))
            )

    def recover_prepared(self) -> None:
        records = self.works.records
        with records.database.engine.connect() as connection:
            wires = list(
                connection.execute(
                    select(models.transition_commits.c.request).where(
                        models.transition_commits.c.state == "PREPARED"
                    )
                ).scalars()
            )
        for wire in wires:
            data = json.loads(wire)
            with records.database.engine.connect() as connection:
                transition = records.resolve(
                    connection,
                    REF_ADAPTER.validate_python(data["transition"], strict=False),
                )
                prepared = records.resolve(
                    connection,
                    REF_ADAPTER.validate_python(data["commit"], strict=False),
                )
                candidates = tuple(
                    records.resolve(
                        connection,
                        REF_ADAPTER.validate_python(ref, strict=False),
                        candidate=True,
                    )
                    for ref in data["records"]
                )
            assert isinstance(transition, StateTransition) and isinstance(
                prepared, TransitionCommit
            )
            try:
                self.finish(TransitionCommitRequest(transition, prepared, candidates))
            except (ValueError, LookupError) as error:
                self.abort(prepared, str(error))
