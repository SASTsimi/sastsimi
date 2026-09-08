"""Immutable exact output admission, derived only during trusted authorization."""

import json

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.result_registry import validate_result_owner

from . import models
from .codec import REF_ADAPTER, reference
from .repositories import SQLiteRecordStore


def derive_outputs(
    records: SQLiteRecordStore, connection: Connection, action: ActionRequest
) -> tuple[RecordRef, ...]:
    primary = action.candidate_result_ref
    if primary is None:
        return ()
    outputs = records.evidence.authorized_outputs(action)
    if outputs is None:
        outputs = (primary,)
    if primary not in outputs or len(outputs) != len(set(outputs)):
        raise ValueError("OUTPUT_BINDING_MISMATCH")
    for ref in outputs:
        candidate = records.resolve(connection, ref, candidate=True)
        if not isinstance(candidate, ContractModel):
            raise ValueError("OUTPUT_BINDING_MISMATCH: invalid candidate model")
        validate_result_owner(ref.data_kind, candidate, action.requested_by)
    return outputs


def read_outputs(
    connection: Connection, action: ActionRequest, decision_ref: RecordRef
) -> tuple[RecordRef, ...]:
    row = (
        connection.execute(
            select(models.action_output_closures).where(
                models.action_output_closures.c.action_id == str(action.action_id)
            )
        )
        .mappings()
        .first()
    )
    if row is None or row["decision_ref"] != canonical_bytes(decision_ref).decode():
        raise ValueError("OUTPUT_BINDING_MISMATCH: authorization closure missing")
    outputs = tuple(
        REF_ADAPTER.validate_python(ref, strict=False)
        for ref in json.loads(row["output_refs"])
    )
    if row["content_hash"] != content_hash([reference(action), decision_ref, outputs]):
        raise ValueError("OUTPUT_BINDING_MISMATCH: authorization closure hash")
    return outputs
