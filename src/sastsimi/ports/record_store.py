from typing import Protocol, runtime_checkable

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import TransitionCommit

from .dto import Record, TransitionCommitRequest


@runtime_checkable
class RecordStore(Protocol):
    """Resolve exact kind/scope/record/hash; never silently read current instead.

    commit_transition owns atomic CAS, output publication and journal integrity.
    Caller supplies its consuming analysis to domain validation after resolution.
    """

    def get_exact(self, ref: RecordRef) -> Record: ...
    def is_revision_descendant(
        self, earlier_ref: RecordRef, later_ref: RecordRef
    ) -> bool: ...
    def stage_record(self, record: Record) -> RecordRef: ...
    def commit_transition(
        self, request: TransitionCommitRequest
    ) -> TransitionCommit: ...
