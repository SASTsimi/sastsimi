from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from .base import ContractModel, NonEmptyStr, PositiveInt, SchemaVersion
from .ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    HypothesisId,
    LogicalRecordId,
    ProgramId,
    RecordId,
    WorkspaceId,
)


class RevisionMeta(ContractModel):
    record_id: RecordId
    logical_record_id: LogicalRecordId
    record_type: NonEmptyStr
    schema_version: SchemaVersion
    revision_number: PositiveInt
    previous_record_id: RecordId | None
    created_at: AwareDatetime

    @model_validator(mode="after")
    def revision_shape(self) -> Self:
        if (self.revision_number == 1) != (self.previous_record_id is None):
            raise ValueError("First revision alone must have previous_record_id=null")
        if self.previous_record_id == self.record_id:
            raise ValueError("A revision cannot reference itself")
        return self


class RunMeta(RevisionMeta):
    analysis_id: AnalysisId


class RecordMeta(RunMeta):
    workspace_id: WorkspaceId
    commit_id: CommitId
    hypothesis_id: HypothesisId | None
    attempt_id: AttemptId | None


class PolicyCacheMeta(RevisionMeta):
    record_type: Literal["policy_cache_record"]
    program_id: ProgramId


type RecordMetadata = RunMeta | RecordMeta | PolicyCacheMeta


def validate_revision(previous: RecordMetadata, current: RecordMetadata) -> None:
    """Validate a supplied exact predecessor; storage enforces unique chains."""
    if type(previous) is not type(current):
        raise ValueError("Metadata kind cannot change between revisions")
    immutable = (
        "logical_record_id",
        "record_type",
        "analysis_id",
        "workspace_id",
        "commit_id",
        "hypothesis_id",
        "program_id",
    )
    if any(
        getattr(previous, key, None) != getattr(current, key, None) for key in immutable
    ):
        raise ValueError("Revision identity or scope mismatch")
    if (
        current.previous_record_id != previous.record_id
        or current.record_id == previous.record_id
        or current.revision_number != previous.revision_number + 1
    ):
        raise ValueError(
            "RECORD_REVISION_MISMATCH: exact predecessor and next revision required"
        )
    if current.created_at < previous.created_at:
        raise ValueError("Revision created_at precedes predecessor")
