"""Canonical wire conversion and exact reference construction."""

from typing import cast

from pydantic import BaseModel, TypeAdapter

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import StoredDataId
from sastsimi.contracts.records import PolicyCacheMeta, RecordMeta, RunMeta
from sastsimi.contracts.refs import (
    PolicyCacheRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.result_registry import RESULT_REGISTRY
from sastsimi.contracts.schema_export import CORE_SCHEMAS
from sastsimi.ports.dto import Record

REF_ADAPTER: TypeAdapter[RecordRef] = TypeAdapter(RecordRef)


def encode(record: Record) -> str:
    if not isinstance(record, BaseModel):
        raise TypeError("Stored records must be registered contract models")
    payload = canonical_bytes(record).decode("utf-8")
    decode(record.meta.record_type, payload)
    return payload


def decode(kind: str, payload: str) -> Record:
    model = CORE_SCHEMAS.get(kind)
    if kind in RESULT_REGISTRY:
        model = RESULT_REGISTRY[kind].model
    if model is None:
        raise ValueError("Unknown record kind: " + kind)
    record = model.model_validate_json(payload)
    meta = getattr(record, "meta", None)
    if not isinstance(meta, (RunMeta, PolicyCacheMeta)) or meta.record_type != kind:
        raise ValueError("RECORD_KIND_MISMATCH")
    return cast(Record, record)


def reference(record: Record) -> RecordRef:
    common = dict(
        stored_data_id=StoredDataId(str(record.meta.record_id)),
        data_kind=record.meta.record_type,
        content_hash=content_hash(record),
        record_id=record.meta.record_id,
    )
    meta = record.meta
    if isinstance(meta, RecordMeta):
        return StoredDataRef.model_validate(
            common | dict(workspace_id=meta.workspace_id, commit_id=meta.commit_id)
        )
    if isinstance(meta, RunMeta):
        return RunStoredDataRef.model_validate(
            common | dict(analysis_id=meta.analysis_id)
        )
    return PolicyCacheRef.model_validate(
        common | dict(program_id=meta.program_id, schema_version=meta.schema_version)
    )
