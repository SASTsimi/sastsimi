"""Public UnitOfWork composition; services own short transactions, not callers."""

from collections.abc import Callable
from typing import Protocol

from sastsimi.contracts.work import TransitionCommit
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.ports.record_store import RecordStore

from .repositories import SQLiteRecordStore


class TransitionWriter(Protocol):
    def commit(self, request: TransitionCommitRequest) -> TransitionCommit: ...


class SQLiteUnitOfWork:
    records: RecordStore
    artifacts: ArtifactStore

    def __init__(
        self,
        records: SQLiteRecordStore,
        artifacts: ArtifactStore,
        transitions: TransitionWriter,
    ) -> None:
        self.records, self.artifacts = records, artifacts
        self._commit: Callable[[TransitionCommitRequest], TransitionCommit] = (
            transitions.commit
        )
        records.transition_writer = self._commit

    def commit(self, request: TransitionCommitRequest) -> TransitionCommit:
        return self._commit(request)

    def rollback(self) -> None:
        # Staging is immutable, invisible and recoverable. No transaction is held
        # by this object, and durable PREPARED journals must survive caller failure.
        return None
