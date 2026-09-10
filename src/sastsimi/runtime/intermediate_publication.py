"""Owner-specific append-only records inside a continuing work attempt."""

from sastsimi.contracts.refs import RecordRef
from sastsimi.ports.dto import Record
from sastsimi.ports.intermediate_publication import IntermediatePublicationPort


class IntermediatePublicationService:
    def __init__(self, store: IntermediatePublicationPort) -> None:
        self.store = store

    def publish(
        self,
        work_id: str,
        decision_ref: RecordRef,
        records: tuple[Record, ...],
    ) -> tuple[RecordRef, ...]:
        return self.store.publish(work_id, decision_ref, records)
