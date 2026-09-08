"""SQLite adapter: Immutable runtime record revisions with injected IDs and time."""

from sastsimi.contracts.ids import RecordId
from sastsimi.contracts.records import RecordMetadata
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator


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
