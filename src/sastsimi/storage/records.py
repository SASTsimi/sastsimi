"""SQLite adapter: Immutable runtime record revisions with injected IDs and time."""

from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.records import RecordMetadata
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator


def fresh_meta(
    meta: RecordMetadata, kind: str, clock: Clock, ids: IdGenerator, **fields: object
) -> RecordMetadata:
    record_id = ids.new(RecordId)
    return type(meta).model_validate(
        meta.model_dump()
        | dict(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            revision_number=1,
            previous_record_id=None,
            created_at=clock.now(),
        )
        | fields
    )


def next_meta(meta: RecordMetadata, clock: Clock, ids: IdGenerator) -> RecordMetadata:
    return type(meta).model_validate(
        meta.model_dump()
        | dict(
            record_id=ids.new(RecordId),
            previous_record_id=meta.record_id,
            revision_number=meta.revision_number + 1,
            created_at=clock.now(),
        )
    )
