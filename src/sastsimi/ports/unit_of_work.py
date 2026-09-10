from typing import Protocol, runtime_checkable

from sastsimi.contracts.work import TransitionCommit

from .artifact_store import ArtifactStore
from .dto import TransitionCommitRequest
from .record_store import RecordStore


@runtime_checkable
class UnitOfWork(Protocol):
    records: RecordStore
    artifacts: ArtifactStore

    def commit(self, request: TransitionCommitRequest) -> TransitionCommit: ...
    def rollback(self) -> None: ...
