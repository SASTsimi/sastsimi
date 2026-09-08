"""Runtime publication entry point backed by the RecordStore journal port."""

from sastsimi.contracts.work import TransitionCommit
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.ports.record_store import RecordStore


class TransitionService:
    def __init__(self, records: RecordStore) -> None:
        self.records = records

    def commit(self, request: TransitionCommitRequest) -> TransitionCommit:
        return self.records.commit_transition(request)
