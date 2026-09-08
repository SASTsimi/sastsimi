from typing import BinaryIO, Protocol, runtime_checkable

from sastsimi.contracts.refs import StoredDataRef

from .dto import StagedArtifact


@runtime_checkable
class ArtifactStore(Protocol):
    """Commit scoped content; open_verified must verify digest before use."""

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact: ...
    def commit(self, staged: StagedArtifact) -> StoredDataRef: ...
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...
