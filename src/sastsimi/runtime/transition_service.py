"""Runtime publication entry point backed by the RecordStore journal port."""

from typing import Protocol

from sastsimi.contracts.work import TransitionCommit
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.ports.record_store import RecordStore


class TransitionService:
    def __init__(self, records: RecordStore) -> None:
        self.records = records

    def commit(self, request: TransitionCommitRequest) -> TransitionCommit:
        return self.records.commit_transition(request)


class TransitionServicePort(Protocol):
    """The exact `runtime.transitions` surface production code calls.

    `storage.transition_service.TransitionService` (a much larger class)
    structurally satisfies this without inheriting from it - see
    `composition/runtime.py`'s `build_runtime`, which supplies that real
    instance for `RuntimeServices.transitions`. `TransitionService` above
    (`.commit` only) also satisfies it, and stays a separate concrete class
    for the narrow commit-only test doubles that already construct it
    directly.
    """

    def commit(self, request: TransitionCommitRequest) -> TransitionCommit: ...
