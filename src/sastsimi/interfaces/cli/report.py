"""Human-readable current ReportDraft show/export commands."""

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Protocol, cast

from sastsimi import bootstrap
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.bundle_files import (
    MAX_BUNDLE_ARCHIVE_BYTES,
    MAX_BUNDLE_MANIFEST_BYTES,
    ReportBundleManifest,
    parse_bundle_manifest,
    read_bundle_archive,
)
from sastsimi.storage.artifact_store import LocalArtifactStore


class ReportCommandError(ValueError):
    """A safe, expected report lookup or export failure."""


class ReportService(Protocol):
    """CLI view of the report application service."""

    def summaries(self, analysis_id: str) -> tuple[dict[str, str], ...]: ...

    def show(self, finding_id: str) -> str: ...

    def export(self, finding_id: str) -> Path: ...


def service(data_dir: Path) -> ReportService:
    return cast(ReportService, bootstrap.build_report_markdown_service(data_dir))


def show(data_dir: Path, finding_id: str) -> str:
    try:
        return service(data_dir).show(finding_id)
    except ValueError as error:
        raise ReportCommandError from error


def export(data_dir: Path, finding_id: str) -> Path:
    try:
        return service(data_dir).export(finding_id)
    except ValueError as error:
        raise ReportCommandError from error


def safe_export_reference(data_dir: Path, exported: Path) -> str:
    """Return a data-root-relative report path without disclosing its host path."""

    try:
        root = data_dir.resolve(strict=True)
        relative = exported.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        raise ReportCommandError from None
    if not relative.parts or relative.parts[0] != "reports":
        raise ReportCommandError
    return relative.as_posix()


def _read_small_regular(path: Path, limit: int) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_file_attributes", 0)) & 0x400
        or before.st_size > limit
    ):
        raise ReportCommandError
    with path.open("rb") as stream:
        current = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (
            current.st_dev,
            current.st_ino,
        ) or current.st_size > limit:
            raise ReportCommandError
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise ReportCommandError
    return result


def bundle_reference(data_dir: Path, exported: Path) -> str | None:
    """Return a freshly exported v2 ZIP path only after manifest/CAS validation."""

    relative = Path(safe_export_reference(data_dir, exported))
    if (
        len(relative.parts) != 3
        or re.fullmatch(r"F-[0-9]{3,}\.md", relative.name) is None
    ):
        return None
    root = data_dir.resolve(strict=True)
    bundle_dir = root / "reports" / relative.parts[1] / relative.stem
    manifest_path = bundle_dir / "manifest.json"
    archive_path = bundle_dir / "bundle.zip"
    if not manifest_path.exists() and not archive_path.exists():
        return None
    try:
        if not manifest_path.is_file() or not archive_path.is_file():
            raise ReportCommandError
        if (
            manifest_path.resolve(strict=True) != manifest_path
            or archive_path.resolve(strict=True) != archive_path
        ):
            raise ReportCommandError
        raw_manifest = _read_small_regular(manifest_path, MAX_BUNDLE_MANIFEST_BYTES)
        preliminary = ReportBundleManifest.model_validate_json(raw_manifest)
        manifest = parse_bundle_manifest(
            raw_manifest, finding_ref=preliminary.finding_ref
        )
        if (manifest.analysis_id, manifest.display_id) != (
            relative.parts[1],
            relative.stem,
        ):
            raise ReportCommandError
        disk_archive = _read_small_regular(archive_path, MAX_BUNDLE_ARCHIVE_BYTES)
        digest = hashlib.sha256(disk_archive).hexdigest()
        finding = manifest.finding_ref
        archive_ref = StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id=WorkspaceId(str(finding.workspace_id)),
            commit_id=CommitId(str(finding.commit_id)),
            record_id=None,
        )
        artifacts = LocalArtifactStore(
            RuntimePaths(root).artifacts,
            finding.workspace_id,
            finding.commit_id,
        )
        verified = read_bundle_archive(
            manifest,
            archive_ref,
            lambda ref: artifacts.open_verified_bounded(
                ref, MAX_BUNDLE_ARCHIVE_BYTES
            ).read(),
        )
        if verified != disk_archive:
            raise ReportCommandError
    except (OSError, ValueError) as error:
        raise ReportCommandError from error
    return (relative.parent / relative.stem / "bundle.zip").as_posix()
