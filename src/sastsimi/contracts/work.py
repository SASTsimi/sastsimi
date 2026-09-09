from enum import StrEnum
from typing import Any, Self

from pydantic import AwareDatetime, ValidationInfo, field_validator, model_validator

from .base import ContractModel, NonEmptyStr, NonNegativeInt, PositiveInt, Sha256
from .canonical_json import content_hash
from .ids import (
    AnalysisId,
    AttemptId,
    ErrorId,
    GapId,
    HypothesisId,
    ProposalId,
    ReportId,
    TransitionCommitId,
    TransitionId,
    WorkId,
)
from .records import RecordMeta, RunMeta
from .refs import (
    BudgetScopeRef,
    PolicyCacheRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    require_record_ref,
    validate_exact_ref,
    validate_ref_scope,
)


class WorkType(StrEnum):
    WORKSPACE_PREP = "WORKSPACE_PREP"
    STATIC_TOOL = "STATIC_TOOL"
    STATIC_NORMALIZE = "STATIC_NORMALIZE"
    HYPOTHESIS_PROPOSAL = "HYPOTHESIS_PROPOSAL"
    CONTEXT_RETRIEVAL = "CONTEXT_RETRIEVAL"
    PRO_EVIDENCE = "PRO_EVIDENCE"
    CON_EVIDENCE = "CON_EVIDENCE"
    VERIFICATION = "VERIFICATION"
    DYNAMIC_REPRO = "DYNAMIC_REPRO"
    PRIMITIVE_UPDATE = "PRIMITIVE_UPDATE"
    CHAINING = "CHAINING"
    CWE_LABEL = "CWE_LABEL"
    POLICY_FETCH = "POLICY_FETCH"
    TECHNICAL_GATE = "TECHNICAL_GATE"
    RULE_SCOPE_GATE = "RULE_SCOPE_GATE"
    FINDING_NORMALIZE = "FINDING_NORMALIZE"
    REPORT_DRAFT = "REPORT_DRAFT"


class WorkStatus(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    BLOCKED = "BLOCKED"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AttemptStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TransitionTargetStatus(StrEnum):
    READY = "READY"
    RUNNING = "RUNNING"
    BLOCKED = "BLOCKED"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CommitTargetStatus(StrEnum):
    BLOCKED = "BLOCKED"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class SubjectType(StrEnum):
    ANALYSIS = "ANALYSIS"
    PROPOSAL = "PROPOSAL"
    HYPOTHESIS = "HYPOTHESIS"
    REPORT = "REPORT"


class AttemptTrigger(StrEnum):
    INITIAL = "INITIAL"
    RETRY = "RETRY"
    RESUME = "RESUME"


class WaitingFor(StrEnum):
    RETRY = "RETRY"
    AUTH = "AUTH"
    APPROVAL = "APPROVAL"
    INPUT = "INPUT"
    BUDGET = "BUDGET"
    DEPENDENCY = "DEPENDENCY"


class CommitState(StrEnum):
    PREPARED = "PREPARED"
    COMMITTED = "COMMITTED"
    ABORTED = "ABORTED"


TERMINAL_WORK_STATUSES = frozenset(
    {WorkStatus.SUCCEEDED, WorkStatus.PARTIAL, WorkStatus.FAILED, WorkStatus.CANCELLED}
)
_ALLOWED_TRANSITIONS = {
    WorkStatus.PENDING: frozenset({WorkStatus.READY, WorkStatus.CANCELLED}),
    WorkStatus.READY: frozenset(
        {WorkStatus.RUNNING, WorkStatus.BLOCKED, WorkStatus.CANCELLED}
    ),
    WorkStatus.RUNNING: frozenset(
        {WorkStatus.READY, WorkStatus.BLOCKED, *TERMINAL_WORK_STATUSES}
    ),
    WorkStatus.BLOCKED: frozenset(
        {WorkStatus.READY, WorkStatus.FAILED, WorkStatus.CANCELLED}
    ),
}


class ScopedRecord(ContractModel):
    meta: RunMeta | RecordMeta

    @model_validator(mode="after")
    def reference_scopes(self) -> Self:
        for name in type(self).model_fields:
            value = getattr(self, name)
            values = value if isinstance(value, tuple) else (value,)
            for ref in values:
                if isinstance(ref, (RunStoredDataRef, StoredDataRef, PolicyCacheRef)):
                    validate_ref_scope(ref, self.meta)
        return self


class WorkExecutionState(ScopedRecord):
    work_id: WorkId
    parent_work_ref: BudgetScopeRef | None
    work_type: WorkType
    subject_type: SubjectType
    subject_id: AnalysisId | ProposalId | HypothesisId | ReportId
    work_generation: PositiveInt
    status: WorkStatus
    state_version: PositiveInt
    last_transition_ref: BudgetScopeRef | None
    last_transition_commit_ref: BudgetScopeRef | None
    active_attempt_id: AttemptId | None
    input_hash: Sha256
    dedupe_key: Sha256
    trigger_primitive_ref: StoredDataRef | None
    input_refs: tuple[RecordRef, ...]
    output_refs: tuple[RecordRef, ...]
    gap_ids: tuple[GapId, ...]
    error_ids: tuple[ErrorId, ...]
    waiting_for: tuple[WaitingFor, ...]
    stop_reason: NonEmptyStr | None
    started_at: AwareDatetime | None
    finished_at: AwareDatetime | None
    elapsed_ms: NonNegativeInt

    @field_validator("subject_id", mode="before")
    @classmethod
    def typed_subject(cls, value: Any, info: ValidationInfo) -> object:
        kinds = {
            SubjectType.ANALYSIS: AnalysisId,
            SubjectType.PROPOSAL: ProposalId,
            SubjectType.HYPOTHESIS: HypothesisId,
            SubjectType.REPORT: ReportId,
        }
        subject_type = info.data.get("subject_type")
        kind = (
            kinds.get(subject_type) if isinstance(subject_type, SubjectType) else None
        )
        return kind.model_validate(value) if kind else value

    @model_validator(mode="after")
    def work_shape(self) -> Self:
        if self.work_type != WorkType.WORKSPACE_PREP and not isinstance(
            self.meta, RecordMeta
        ):
            raise ValueError("Post-workspace work requires RecordMeta")
        if self.work_type == WorkType.WORKSPACE_PREP and isinstance(
            self.meta, RecordMeta
        ):
            raise ValueError("WORKSPACE_PREP must retain RunMeta")
        if isinstance(self.meta, RecordMeta) and self.meta.attempt_id is not None:
            raise ValueError("Work metadata attempt_id must be null")
        if (
            self.subject_type == SubjectType.ANALYSIS
            and self.subject_id != self.meta.analysis_id
        ):
            raise ValueError("Analysis subject mismatch")
        if self.subject_type == SubjectType.HYPOTHESIS and (
            not isinstance(self.meta, RecordMeta)
            or self.subject_id != self.meta.hypothesis_id
        ):
            raise ValueError("Hypothesis subject mismatch")
        if (self.status == WorkStatus.RUNNING) != (self.active_attempt_id is not None):
            raise ValueError("Only RUNNING has an active attempt")
        terminal = self.status in TERMINAL_WORK_STATUSES
        if terminal != (self.finished_at is not None):
            raise ValueError("Only terminal work has finished_at")
        if self.started_at and self.finished_at and self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        if self.status == WorkStatus.RUNNING and self.started_at is None:
            raise ValueError("RUNNING requires started_at")
        if self.status in {WorkStatus.PENDING, WorkStatus.READY} and (
            self.output_refs or self.waiting_for
        ):
            raise ValueError("PENDING/READY require empty outputs and waiting_for")
        if self.status == WorkStatus.BLOCKED:
            if not self.waiting_for or not self.stop_reason:
                raise ValueError("BLOCKED requires waiting_for and stop_reason")
        elif self.waiting_for:
            raise ValueError("Only BLOCKED can wait")
        if terminal and not self.stop_reason:
            raise ValueError("Terminal work requires stop_reason")
        if self.status == WorkStatus.SUCCEEDED and self.stop_reason != "COMPLETED":
            raise ValueError("SUCCEEDED stop_reason must be COMPLETED")
        if self.status == WorkStatus.FAILED and not self.error_ids:
            raise ValueError("FAILED requires error_ids")
        if self.status == WorkStatus.PARTIAL:
            allowed = {
                WorkType.STATIC_TOOL,
                WorkType.STATIC_NORMALIZE,
                WorkType.CONTEXT_RETRIEVAL,
                WorkType.DYNAMIC_REPRO,
            }
            if self.work_type not in allowed or not self.output_refs:
                raise ValueError("PARTIAL requires an eligible work type and outputs")
            if self.work_type != WorkType.DYNAMIC_REPRO and not (
                self.error_ids or self.gap_ids
            ):
                raise ValueError("Static/context PARTIAL requires gaps or errors")
            if self.work_type == WorkType.DYNAMIC_REPRO:
                if len(self.output_refs) != 1:
                    raise ValueError("Dynamic PARTIAL requires one result")
                require_record_ref(self.output_refs[0], "dynamic_reproduction_result")
        for ref, kind in (
            (self.last_transition_ref, "state_transition"),
            (self.last_transition_commit_ref, "transition_commit"),
            (self.parent_work_ref, "work_execution_state"),
        ):
            if ref is not None:
                require_record_ref(ref, kind)
        if self.status == WorkStatus.PENDING:
            if (
                self.state_version != 1
                or self.last_transition_ref is not None
                or self.last_transition_commit_ref is not None
            ):
                raise ValueError("Initial PENDING has version 1 and no transition")
        elif self.last_transition_ref is None or self.state_version < 2:
            raise ValueError(
                "Non-PENDING work requires its transition and advanced version"
            )
        children = {
            WorkType.PRO_EVIDENCE,
            WorkType.CON_EVIDENCE,
            WorkType.DYNAMIC_REPRO,
            WorkType.CWE_LABEL,
            WorkType.FINDING_NORMALIZE,
        }
        if (self.work_type in children) != (self.parent_work_ref is not None):
            raise ValueError("Parent required only for declared child work types")
        if (
            self.work_type == WorkType.FINDING_NORMALIZE
            and self.subject_type != SubjectType.HYPOTHESIS
        ):
            raise ValueError("FINDING_NORMALIZE requires a hypothesis subject")
        if (self.work_type == WorkType.CHAINING) != (
            self.trigger_primitive_ref is not None
        ):
            raise ValueError("Only CHAINING requires trigger_primitive_ref")
        if self.trigger_primitive_ref is not None:
            require_record_ref(self.trigger_primitive_ref, "primitive")
            if (
                self.subject_type != SubjectType.ANALYSIS
                or self.input_refs.count(self.trigger_primitive_ref) != 1
            ):
                raise ValueError(
                    "CHAINING requires analysis subject and one trigger input"
                )
        return self


class WorkAttempt(ScopedRecord):
    work_id: WorkId
    attempt_id: AttemptId
    attempt_number: PositiveInt
    trigger: AttemptTrigger
    input_hash: Sha256
    status: AttemptStatus
    output_refs: tuple[RecordRef, ...]
    gap_ids: tuple[GapId, ...]
    error_ids: tuple[ErrorId, ...]
    started_at: AwareDatetime
    finished_at: AwareDatetime | None
    elapsed_ms: NonNegativeInt

    @model_validator(mode="after")
    def attempt_shape(self) -> Self:
        if (self.attempt_number == 1) != (self.trigger == AttemptTrigger.INITIAL):
            raise ValueError("Only first attempt has INITIAL trigger")
        if (self.status == AttemptStatus.RUNNING) != (self.finished_at is None):
            raise ValueError("Only running attempt has finished_at=null")
        if self.finished_at and self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        if self.status == AttemptStatus.FAILED and not self.error_ids:
            raise ValueError("Failed attempt requires errors")
        _attempt_meta(self.meta, self.attempt_id)
        return self


def _attempt_meta(meta: RunMeta | RecordMeta, attempt_id: AttemptId | None) -> None:
    if isinstance(meta, RecordMeta) and meta.attempt_id != attempt_id:
        raise ValueError("Metadata attempt_id mismatch")


class StateTransition(ScopedRecord):
    transition_id: TransitionId
    work_id: WorkId
    action_decision_ref: BudgetScopeRef
    from_status: WorkStatus
    to_status: TransitionTargetStatus
    expected_state_version: PositiveInt
    new_state_version: PositiveInt
    attempt_id: AttemptId | None
    cause: NonEmptyStr
    output_refs: tuple[RecordRef, ...]
    gap_ids: tuple[GapId, ...]
    error_ids: tuple[ErrorId, ...]
    dedupe_key: Sha256
    created_at: AwareDatetime

    @model_validator(mode="after")
    def transition_shape(self) -> Self:
        if WorkStatus(self.to_status.value) not in _ALLOWED_TRANSITIONS.get(
            self.from_status, frozenset()
        ):
            raise ValueError("STATE_TRANSITION_INVALID")
        if self.new_state_version != self.expected_state_version + 1:
            raise ValueError("State version must increase by exactly one")
        if self.to_status == TransitionTargetStatus.RUNNING and self.attempt_id is None:
            raise ValueError("Starting RUNNING requires the new attempt_id")
        require_record_ref(self.action_decision_ref, "action_decision")
        _attempt_meta(self.meta, self.attempt_id)
        return self


class TransitionCommit(ScopedRecord):
    transition_commit_id: TransitionCommitId
    work_id: WorkId
    transition_ref: BudgetScopeRef
    expected_state_version: PositiveInt
    target_state_version: PositiveInt
    attempt_id: AttemptId | None
    target_status: CommitTargetStatus
    output_refs: tuple[RecordRef, ...]
    gap_ids: tuple[GapId, ...]
    error_ids: tuple[ErrorId, ...]
    state: CommitState
    prepared_at: AwareDatetime
    committed_at: AwareDatetime | None
    abort_reason: NonEmptyStr | None

    @model_validator(mode="after")
    def commit_shape(self) -> Self:
        if self.target_state_version != self.expected_state_version + 1:
            raise ValueError("Target version must increase by exactly one")
        require_record_ref(self.transition_ref, "state_transition")
        _attempt_meta(self.meta, self.attempt_id)
        if (self.state == CommitState.COMMITTED) != (self.committed_at is not None):
            raise ValueError("Only COMMITTED has committed_at")
        if (self.state == CommitState.ABORTED) != (self.abort_reason is not None):
            raise ValueError("Only ABORTED has abort_reason")
        if self.committed_at and self.committed_at < self.prepared_at:
            raise ValueError("committed_at precedes prepared_at")
        return self


def validate_transition_context(
    transition: StateTransition,
    work: WorkExecutionState,
    *,
    retry_trigger: AttemptTrigger | None = None,
) -> None:
    _validate_metadata_scope(transition.meta, work.meta)
    if (
        transition.work_id != work.work_id
        or transition.expected_state_version != work.state_version
        or transition.from_status != work.status
    ):
        raise ValueError(
            "STATE_VERSION_CONFLICT: transition does not match current work"
        )
    if (
        transition.from_status == WorkStatus.RUNNING
        and transition.attempt_id != work.active_attempt_id
    ):
        raise ValueError("ATTEMPT_NOT_ACTIVE")
    if (
        transition.from_status == WorkStatus.RUNNING
        and transition.to_status == TransitionTargetStatus.READY
    ):
        if (
            work.work_type != WorkType.DYNAMIC_REPRO
            or retry_trigger != AttemptTrigger.RETRY
        ):
            raise ValueError("RUNNING -> READY requires dynamic session RETRY")


def validate_attempt_context(
    attempt: WorkAttempt,
    work: WorkExecutionState,
    *,
    previous_attempt: WorkAttempt | None = None,
) -> None:
    if attempt.work_id != work.work_id or attempt.input_hash != work.input_hash:
        raise ValueError("Attempt work/input_hash mismatch")
    if (
        type(attempt.meta) is not type(work.meta)
        or attempt.meta.analysis_id != work.meta.analysis_id
    ):
        raise ValueError("Attempt metadata kind or analysis mismatch")
    if isinstance(attempt.meta, RecordMeta) and isinstance(work.meta, RecordMeta):
        for name in ("workspace_id", "commit_id", "hypothesis_id"):
            if getattr(attempt.meta, name) != getattr(work.meta, name):
                raise ValueError("Attempt workspace/commit/hypothesis mismatch")
    if attempt.status == AttemptStatus.RUNNING and (
        work.status != WorkStatus.RUNNING
        or work.active_attempt_id != attempt.attempt_id
    ):
        raise ValueError("ATTEMPT_NOT_ACTIVE")
    if previous_attempt is not None:
        if (
            previous_attempt.work_id != attempt.work_id
            or previous_attempt.attempt_id == attempt.attempt_id
            or previous_attempt.attempt_number + 1 != attempt.attempt_number
            or previous_attempt.status == AttemptStatus.RUNNING
        ):
            raise ValueError("Previous attempt must be ended and numbering consecutive")


def validate_commit_transition(
    commit: TransitionCommit, transition: StateTransition
) -> None:
    _validate_metadata_scope(commit.meta, transition.meta)
    validate_exact_ref(
        commit.transition_ref,
        transition.meta,
        content_hash(transition),
        analysis_id=commit.meta.analysis_id,
    )
    pairs = (
        (commit.work_id, transition.work_id),
        (commit.expected_state_version, transition.expected_state_version),
        (commit.target_state_version, transition.new_state_version),
        (commit.attempt_id, transition.attempt_id),
        (commit.target_status, transition.to_status),
        (commit.output_refs, transition.output_refs),
        (commit.gap_ids, transition.gap_ids),
        (commit.error_ids, transition.error_ids),
        (commit.transition_ref.record_id, transition.meta.record_id),
    )
    if any(left != right for left, right in pairs):
        raise ValueError("TransitionCommit does not match exact StateTransition")


def _validate_metadata_scope(
    left: RunMeta | RecordMeta, right: RunMeta | RecordMeta
) -> None:
    if type(left) is not type(right) or left.analysis_id != right.analysis_id:
        raise ValueError("Metadata kind or analysis scope mismatch")
    if isinstance(left, RecordMeta) and isinstance(right, RecordMeta):
        if (left.workspace_id, left.commit_id, left.hypothesis_id) != (
            right.workspace_id,
            right.commit_id,
            right.hypothesis_id,
        ):
            raise ValueError("Metadata workspace/commit/hypothesis scope mismatch")


def validate_parent_work(child: WorkExecutionState, parent: WorkExecutionState) -> None:
    """Validate a resolved exact parent; storage still verifies current pointers."""
    if child.parent_work_ref is None:
        raise ValueError("Child work requires its exact parent reference")
    _validate_metadata_scope(child.meta, parent.meta)
    validate_exact_ref(
        child.parent_work_ref,
        parent.meta,
        content_hash(parent),
        analysis_id=child.meta.analysis_id,
    )
    if (
        child.subject_type != parent.subject_type
        or child.subject_id != parent.subject_id
    ):
        raise ValueError("Parent and child hypothesis subjects must match")
    if child.work_type == WorkType.FINDING_NORMALIZE:
        if (
            parent.work_type != WorkType.RULE_SCOPE_GATE
            or parent.status != WorkStatus.SUCCEEDED
        ):
            raise ValueError(
                "FINDING_NORMALIZE requires a successful RULE_SCOPE_GATE parent"
            )
    elif parent.work_type != WorkType.VERIFICATION:
        raise ValueError("Verification child requires a VERIFICATION parent")
