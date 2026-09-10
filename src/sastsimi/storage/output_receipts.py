"""Read immutable authorization receipts without importing admission policy."""

import json

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.refs import RecordRef

from . import models
from .codec import REF_ADAPTER, reference


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
