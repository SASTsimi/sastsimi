"""Durable local content-addressed files; no database transaction spans file I/O."""

import hashlib
import os
import re
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.dto import StagedArtifact


def sync_directory(path: Path) -> None:
    # Windows does not expose POSIX directory fsync; startup verifies every file.
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class LocalArtifactStore:
    def __init__(
        self, root: Path, workspace_id: WorkspaceId | None, commit_id: CommitId | None
    ) -> None:
        self.root = root.resolve()
        self.paths = RuntimePaths(self.root.parent)
        self.workspace_id = workspace_id
        self.commit_id = commit_id
        for path in (self.paths.staging, self.root / "sha256", self.paths.quarantine):
            path.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("Invalid SHA-256 path")
        return self.root / "sha256" / digest[:2] / digest[2:]

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        if not media_type.strip():
            raise ValueError("Artifact media type is required")
        digest = hashlib.sha256(data).hexdigest()
        path = self.paths.staging / digest
        try:
            with path.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if path.read_bytes() != data:
                raise ValueError("HASH_MISMATCH: staged artifact") from None
        sync_directory(path.parent)
        return StagedArtifact(data, media_type)

    def promote(self, staged: StagedArtifact) -> str:
        digest = hashlib.sha256(staged.data).hexdigest()
        path = self.path_for(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("HASH_MISMATCH: immutable artifact")
        else:
            source = self.paths.staging / digest
            if not source.exists() or source.read_bytes() != staged.data:
                raise ValueError("HASH_MISMATCH: missing or corrupt staging")
            os.replace(source, path)
            sync_directory(path.parent)
        return digest

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        if self.workspace_id is None or self.commit_id is None:
            raise ValueError("Artifact reference requires a bound workspace")
        digest = self.promote(staged)
        return StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id=self.workspace_id,
            commit_id=self.commit_id,
            record_id=None,
        )

    def open_verified(self, ref: StoredDataRef) -> BinaryIO:
        if (ref.workspace_id, ref.commit_id) != (self.workspace_id, self.commit_id):
            raise ValueError("WORKSPACE_MISMATCH")
        if (
            ref.record_id is not None
            or ref.data_kind != "artifact"
            or str(ref.stored_data_id) != ref.content_hash
        ):
            raise ValueError("Artifact reference mismatch")
        data = self.path_for(ref.content_hash).read_bytes()
        if hashlib.sha256(data).hexdigest() != ref.content_hash:
            raise ValueError("HASH_MISMATCH")
        return BytesIO(data)
