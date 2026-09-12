"""Durable PREPARED journal, repeat CAS, atomic publication and replay."""

import json
from collections.abc import Callable

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.hypothesis import VerificationAssignment
from sastsimi.contracts.policy import PolicyCacheRecord, RunPolicyState
from sastsimi.contracts.records import validate_revision
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.reporting import ReportDraft
from sastsimi.contracts.result_registry import validate_result_owner
from sastsimi.contracts.static import (
    CodeContextResponse,
    CodeWorkspace,
    RepositoryProfile,
)
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
from sastsimi.ports.chaining import ChainingLineagePort
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.codec import REF_ADAPTER, decode, encode, reference

from .chaining_projection import validate_chaining_output
from .chaining_registration import reserve_chaining_result_matches
from .context_policy import check_context_response
from .current_inputs import check_current_input
from .dynamic_projection import dynamic_projection
from .finding_projection import finding_index_projection, validate_finding_output
from .hypothesis_projections import hypothesis_projection
from .intermediate_policy import prepublished_output
from .lease_recovery import retire_undispatched, uncertain
from .output_closures import read_outputs
from .primitive_projection import (
    primitive_index_projection,
    validate_primitive_outputs,
)
from .records import next_meta
from .report_projection import report_creation_decision, validate_report_output
from .report_state import report_process_projection
from .run_projections import run_policy_projection
from .run_states import get_run, save_run
from .verification_projection import verification_projection
from .work_service import WorkService

__all__ = ["TransitionService", "reserve_chaining_result_matches"]


def _validate_terminal_workspace(
    connection: Connection,
    work: WorkExecutionState,
    candidate: CodeWorkspace,
    output_count: int,
) -> None:
    if (
        work.work_type.value != "WORKSPACE_PREP"
        or output_count != 1
        or candidate.status not in {"READY", "FAILED"}
        or candidate.meta.revision_number != 2
        or candidate.meta.previous_record_id is None
        or candidate.analysis_id != work.meta.analysis_id
        or (candidate.status == "READY" and candidate.commit_id is None)
    ):
        raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
    row = (
        connection.execute(
            select(models.records.c.kind, models.records.c.payload).where(
                models.records.c.record_id == str(candidate.meta.previous_record_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
    previous = decode(row["kind"], row["payload"])
    if not isinstance(previous, CodeWorkspace) or previous.status != "PREPARING":
        raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
    validate_revision(previous.meta, candidate.meta)
    if (
        previous.workspace_id != candidate.workspace_id
        or previous.analysis_id != candidate.analysis_id
        or previous.repository_url != candidate.repository_url
    ):
        raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
    current_id = connection.execute(
        select(models.current_records.c.record_id).where(
            models.current_records.c.logical_record_id
            == str(candidate.meta.logical_record_id)
        )
    ).scalar_one_or_none()
    state = get_run(connection, str(candidate.analysis_id))
    if current_id != str(previous.meta.record_id) or state.workspace_ref != reference(
        previous
    ):
        raise ValueError("WORKSPACE_LIFECYCLE_INVALID")


def _validate_repository_profile(
    connection: Connection,
    work: WorkExecutionState,
    candidate: RepositoryProfile,
) -> None:
    if (
        work.work_type.value != "REPOSITORY_PROFILE"
        or work.input_refs != (candidate.workspace_ref,)
        or candidate.meta.attempt_id != work.active_attempt_id
    ):
        raise ValueError("REPOSITORY_PROFILE_CLOSURE_MISMATCH")
    row = (
        connection.execute(
            select(models.records.c.kind, models.records.c.payload).where(
                models.records.c.record_id == str(candidate.workspace_ref.record_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ValueError("REPOSITORY_PROFILE_CLOSURE_MISMATCH")
    workspace = decode(row["kind"], row["payload"])
    if (
        not isinstance(workspace, CodeWorkspace)
        or workspace.status != "READY"
        or workspace.commit_id is None
        or reference(workspace) != candidate.workspace_ref
        or workspace.analysis_id != candidate.meta.analysis_id
        or workspace.workspace_id != candidate.workspace_id
        or workspace.commit_id != candidate.commit_id
    ):
        raise ValueError("REPOSITORY_PROFILE_CLOSURE_MISMATCH")


class TransitionService:
    def __init__(
        self,
        works: WorkService,
        artifacts: LocalArtifactStore,
        checkpoint: Callable[[str], None] | None = None,
        chaining_lineage: ChainingLineagePort | None = None,
    ) -> None:
        self.works, self.artifacts = works, artifacts
        self.checkpoint = checkpoint or (lambda name: None)
        self.chaining_lineage = chaining_lineage

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
        if refs and set(refs) != set(
            read_outputs(connection, action, request.transition.action_decision_ref)
        ):
            raise ValueError("OUTPUT_BINDING_MISMATCH")
        for record in request.records:
            if not isinstance(record, ContractModel):
                raise ValueError("OUTPUT_SCHEMA_MISMATCH")
            if isinstance(record, CodeWorkspace):
                _validate_terminal_workspace(
                    connection, work, record, len(request.records)
                )
            if isinstance(record, RepositoryProfile):
                _validate_repository_profile(connection, work, record)
            if isinstance(record, CodeContextResponse):
                check_context_response(self.works.records, connection, work, record)
            if not prepublished_output(
                self.works.records, connection, reference(record), work
            ):
                if record.meta.record_type == "finding":
                    from .action_context import current_process

                    process = current_process(self.works.records, connection, work)
                    if not isinstance(
                        process.verification_assignment_ref, StoredDataRef
                    ):
                        raise ValueError("FINDING_NORMALIZER_AUTHORITY_REQUIRED")
                    assignment = self.works.records.resolve(
                        connection, process.verification_assignment_ref
                    )
                    if not isinstance(
                        action.requester_identity_ref, StoredDataRef
                    ) or not isinstance(assignment, VerificationAssignment):
                        raise ValueError("FINDING_NORMALIZER_AUTHORITY_REQUIRED")
                    validate_result_owner(
                        record.meta.record_type,
                        record,
                        action.requested_by,
                        requester_identity_ref=action.requester_identity_ref,
                        finding_service_identity_ref=(
                            self.works.records.finding_service_identity_ref
                        ),
                        active_assignment_owner_ref=assignment.owner_identity_ref,
                        finding_assignment=assignment,
                        expected_assignment_ref=process.verification_assignment_ref,
                    )
                else:
                    validate_result_owner(
                        record.meta.record_type, record, action.requested_by
                    )
            meta = record.meta
            if (
                getattr(meta, "analysis_id", work.meta.analysis_id)
                != work.meta.analysis_id
            ):
                raise ValueError("OUTPUT_ANALYSIS_MISMATCH")
            attempt = getattr(meta, "attempt_id", None)
            if attempt is not None and attempt != work.active_attempt_id:
                raise ValueError("ATTEMPT_NOT_ACTIVE")
        run_policy_projection(
            self.works, connection, work, request.records, publish=False
        )
        hypothesis_projection(
            self.works, connection, work, request.records, publish=False
        )
        verification_projection(
            self.works, connection, work, request.records, publish=False
        )
        dynamic_projection(
            self.works,
            connection,
            work,
            request.records,
            request.commit.target_status.value,
            publish=False,
        )
        validate_finding_output(self.works, connection, work, request.records)
        validate_primitive_outputs(self.works, connection, work, request.records)
        validate_chaining_output(
            self.works,
            connection,
            work,
            request.records,
            self.chaining_lineage,
        )
        validate_report_output(
            self.works, connection, work, request.records, self.artifacts
        )
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
                if prepublished_output(
                    records, connection, reference(record), previous
                ):
                    continue
                records.publish(connection, reference(record))
                if not isinstance(record, (PolicyCacheRecord, RunPolicyState)):
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
            for chaining_result in (
                record
                for record in request.records
                if isinstance(record, ChainingResult)
            ):
                reserve_chaining_result_matches(records, connection, chaining_result)
            self.works.validator.record_outcome(
                connection, claimed, committed.output_refs
            )
            run_policy_projection(
                self.works, connection, previous, request.records, publish=True
            )
            for projection in hypothesis_projection(
                self.works, connection, previous, request.records, publish=True
            ):
                projection_ref = records.stage(connection, projection)
                records.publish(connection, projection_ref)
                self.publish_pointer(connection, projection_ref)
            for projection in verification_projection(
                self.works, connection, previous, request.records, publish=True
            ):
                projection_ref = records.stage(connection, projection)
                records.publish(connection, projection_ref)
                self.publish_pointer(connection, projection_ref)
            for projection in dynamic_projection(
                self.works,
                connection,
                previous,
                request.records,
                request.commit.target_status.value,
                publish=True,
            ):
                projection_ref = records.stage(connection, projection)
                records.publish(connection, projection_ref)
                self.publish_pointer(connection, projection_ref)
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
            waiting = WaitingFor.INPUT
            action = records.resolve(connection, claimed.action_ref)
            if (
                isinstance(action, ActionRequest)
                and action.requested_by == RequesterRole.RECOVERY
            ):
                if not uncertain(connection, previous):
                    waiting = WaitingFor.RETRY
                    retire_undispatched(
                        connection, self.works.validator.budget, previous
                    )
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
                    waiting_for=() if terminal else (waiting,),
                )
            )
            finding = validate_finding_output(
                self.works, connection, previous, request.records
            )
            if finding is not None:
                index = finding_index_projection(
                    self.works, connection, work, finding, committed
                )
                index_ref = records.stage(connection, index)
                records.publish(connection, index_ref)
                self.publish_pointer(connection, index_ref)
            report_state = report_process_projection(
                self.works, connection, previous, request.records, committed
            )
            if report_state is not None:
                if report_state.report_draft_ref is not None:
                    drafts = tuple(
                        item
                        for item in request.records
                        if isinstance(item, ReportDraft)
                    )
                    if len(drafts) != 1:
                        raise ValueError("REPORT_EXACT_OUTPUT_REQUIRED")
                    create_decision = report_creation_decision(
                        self.works, connection, previous, drafts[0]
                    )
                    self.works.validator.record_outcome(
                        connection, create_decision, (report_state.report_draft_ref,)
                    )
                report_state_ref = records.stage(connection, report_state)
                records.publish(connection, report_state_ref)
                self.publish_pointer(connection, report_state_ref)
            primitive_index = primitive_index_projection(
                self.works,
                connection,
                previous,
                validate_primitive_outputs(
                    self.works, connection, previous, request.records
                ),
            )
            if primitive_index is not None:
                primitive_index_ref = records.stage(connection, primitive_index)
                records.publish(connection, primitive_index_ref)
                self.publish_pointer(connection, primitive_index_ref)
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
