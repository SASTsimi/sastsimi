from typing import BinaryIO, Protocol, runtime_checkable

from sastsimi.contracts.ids import AnalysisId
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef

from .dto import StagedArtifact


@runtime_checkable
class ArtifactStore(Protocol):
    """Commit scoped content; open_verified must verify digest before use."""

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact: ...
    def commit(self, staged: StagedArtifact) -> StoredDataRef: ...
    def commit_run(
        self, staged: StagedArtifact, analysis_id: AnalysisId
    ) -> RunStoredDataRef: ...
    def open_verified(self, ref: StoredDataRef | RunStoredDataRef) -> BinaryIO: ...
