from typing import Literal

from .base import ContractModel, NonEmptyStr, SchemaVersion, Sha256
from .ids import AnalysisId, CommitId, ProgramId, RecordId, StoredDataId, WorkspaceId
from .records import PolicyCacheMeta, RecordMeta, RecordMetadata, RunMeta


class RunStoredDataRef(ContractModel):
    stored_data_id: StoredDataId
    data_kind: NonEmptyStr
    content_hash: Sha256
    analysis_id: AnalysisId
    record_id: RecordId | None


class StoredDataRef(ContractModel):
    stored_data_id: StoredDataId
    data_kind: NonEmptyStr
    content_hash: Sha256
    workspace_id: WorkspaceId
    commit_id: CommitId
    record_id: RecordId | None


class PolicyCacheRef(ContractModel):
    stored_data_id: StoredDataId
    data_kind: Literal["policy_cache_record"]
    record_id: RecordId
    content_hash: Sha256
    program_id: ProgramId
    schema_version: SchemaVersion


type RecordRef = RunStoredDataRef | StoredDataRef | PolicyCacheRef
type BudgetScopeRef = RunStoredDataRef | StoredDataRef


def require_record_ref(ref: RecordRef, data_kind: str | None = None) -> None:
    if ref.record_id is None:
        raise ValueError("Stored-record reference requires record_id")
    if data_kind is not None and ref.data_kind != data_kind:
        raise ValueError("Reference data_kind mismatch")


def validate_ref_scope(ref: RecordRef, meta: RecordMetadata) -> None:
    """Local scope only. StoredDataRef analysis must be checked after resolving."""
    if isinstance(ref, PolicyCacheRef):
        if isinstance(meta, PolicyCacheMeta) and ref.program_id != meta.program_id:
            raise ValueError("Policy program mismatch")
    elif isinstance(ref, StoredDataRef):
        if isinstance(meta, PolicyCacheMeta):
            raise ValueError("Policy cache cannot carry code-scoped local metadata")
        if isinstance(meta, RecordMeta) and (ref.workspace_id, ref.commit_id) != (
            meta.workspace_id,
            meta.commit_id,
        ):
            raise ValueError("WORKSPACE_MISMATCH")
    elif not isinstance(meta, RunMeta) or ref.analysis_id != meta.analysis_id:
        raise ValueError("Analysis mismatch")


def validate_exact_ref(
    ref: RecordRef,
    meta: RecordMetadata,
    expected_content_hash: str,
    *,
    analysis_id: AnalysisId | None = None,
) -> None:
    require_record_ref(ref, meta.record_type)
    if isinstance(meta, PolicyCacheMeta):
        if (
            not isinstance(ref, PolicyCacheRef)
            or ref.schema_version != meta.schema_version
        ):
            raise ValueError("Policy cache reference kind/schema mismatch")
    else:
        expected_type = (
            StoredDataRef if isinstance(meta, RecordMeta) else RunStoredDataRef
        )
        if not isinstance(ref, expected_type):
            raise ValueError("Record reference kind mismatch")
        if analysis_id is None or meta.analysis_id != analysis_id:
            raise ValueError("Consuming analysis mismatch or missing")
    validate_ref_scope(ref, meta)
    if ref.record_id != meta.record_id or ref.content_hash != expected_content_hash:
        raise ValueError("RECORD_REVISION_MISMATCH: record_id/content_hash mismatch")
