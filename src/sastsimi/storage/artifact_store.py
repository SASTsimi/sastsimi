"""Durable local content-addressed files; no database transaction spans file I/O."""

import hashlib
import os
import re
import stat
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.ids import AnalysisId, CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef
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
        self,
        root: Path,
        workspace_id: WorkspaceId | None,
        commit_id: CommitId | None,
        *,
        create_dirs: bool = True,
    ) -> None:
        self.root = root.resolve()
        self.paths = RuntimePaths(self.root.parent)
        self.workspace_id = workspace_id
        self.commit_id = commit_id
        if create_dirs:
            for path in (
                self.paths.staging,
                self.root / "sha256",
                self.paths.quarantine,
            ):
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

    def commit_run(
        self, staged: StagedArtifact, analysis_id: AnalysisId
    ) -> RunStoredDataRef:
        digest = self.promote(staged)
        return RunStoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            analysis_id=analysis_id,
            record_id=None,
        )

    def open_verified(self, ref: StoredDataRef | RunStoredDataRef) -> BinaryIO:
        if isinstance(ref, StoredDataRef) and (ref.workspace_id, ref.commit_id) != (
            self.workspace_id,
            self.commit_id,
        ):
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

    def open_verified_bounded(
        self, ref: StoredDataRef | RunStoredDataRef, max_bytes: int
    ) -> BinaryIO:
        """Verify a small CAS object without reading an oversized file first."""

        if max_bytes < 0:
            raise ValueError("ARTIFACT_SIZE_LIMIT_INVALID")
        if isinstance(ref, StoredDataRef) and (ref.workspace_id, ref.commit_id) != (
            self.workspace_id,
            self.commit_id,
        ):
            raise ValueError("WORKSPACE_MISMATCH")
        if (
            ref.record_id is not None
            or ref.data_kind != "artifact"
            or str(ref.stored_data_id) != ref.content_hash
        ):
            raise ValueError("Artifact reference mismatch")
        path = self.path_for(ref.content_hash)
        if not path.resolve(strict=True).is_relative_to(self.root):
            raise ValueError("ARTIFACT_PATH_UNSAFE")
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size > max_bytes
        ):
            raise ValueError("ARTIFACT_SIZE_OR_TYPE_INVALID")
        with path.open("rb") as stream:
            current = os.fstat(stream.fileno())
            if (
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
                or not stat.S_ISREG(current.st_mode)
                or current.st_size > max_bytes
            ):
                raise ValueError("ARTIFACT_CHANGED")
            data = stream.read(max_bytes + 1)
        if (
            len(data) > max_bytes
            or hashlib.sha256(data).hexdigest() != ref.content_hash
        ):
            raise ValueError("HASH_MISMATCH")
        return BytesIO(data)
