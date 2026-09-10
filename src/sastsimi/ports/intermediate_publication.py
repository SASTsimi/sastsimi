from typing import Protocol

from sastsimi.contracts.refs import RecordRef

from .dto import Record


class IntermediatePublicationPort(Protocol):
    def publish(
        self,
        work_id: str,
        decision_ref: RecordRef,
        records: tuple[Record, ...],
    ) -> tuple[RecordRef, ...]: ...
