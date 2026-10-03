"""Publication is atomic, bounded, path-safe and verified from exact refs."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

import sastsimi.reporting.bundle_files as bundle_files
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.bilingual_bundle import BundleFile
from sastsimi.reporting.bundle_files import (
    parse_bundle_manifest,
    publish_bundle,
    read_bundle_archive,
    read_bundle_file,
)

_MEDIA = {
    "report_en.md": "text/markdown; charset=utf-8",
    "report_kr.md": "text/markdown; charset=utf-8",
    "poc.sh": "text/x-shellscript; charset=utf-8",
    "evidence/provenance.json": "application/json",
}


def _ref(kind: str, digest: str, *, record_id: str | None = None) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": record_id or digest,
            "data_kind": kind,
            "content_hash": digest,
            "workspace_id": "ws-1",
            "commit_id": "a" * 40,
            "record_id": record_id,
        }
    )


class Artifacts:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def put(self, body: bytes, _media_type: str) -> StoredDataRef:
        digest = hashlib.sha256(body).hexdigest()
        self.values[digest] = body
        return _ref("artifact", digest)

    def read(self, ref: StoredDataRef) -> bytes:
        return self.values[ref.content_hash]


def _files(poc: bytes = b"#!/bin/sh\necho safe\n") -> tuple[BundleFile, ...]:
    digest = hashlib.sha256(poc).hexdigest()
    provenance = canonical_bytes(
        {
            "poc": {
                "path": "poc.sh",
                "original_sha256": digest,
                "attachment_sha256": digest,
                "redacted": False,
            }
        }
    )
    bodies = {
        "report_en.md": b"# Example\n",
        "report_kr.md": "# 예시\n".encode(),
        "poc.sh": poc,
        "evidence/provenance.json": provenance,
    }
    return tuple(BundleFile(path, body, _MEDIA[path]) for path, body in bodies.items())


def _publish(
    root: Path, artifacts: Artifacts, files: tuple[BundleFile, ...] | None = None
) -> bundle_files.PublishedBundle:
    return publish_bundle(
        root=root,
        analysis_id="a1",
        display_id="F-002",
        finding_ref=_ref("finding", "b" * 64, record_id="finding-2"),
        files=files or _files(),
        put_artifact=artifacts.put,
    )


def test_manifest_and_archive_cover_exact_curated_members(tmp_path: Path) -> None:
    artifacts = Artifacts()
    published = _publish(tmp_path, artifacts)
    manifest = parse_bundle_manifest(
        artifacts.read(published.manifest_ref),
        finding_ref=_ref("finding", "b" * 64, record_id="finding-2"),
    )
    assert published.bundle_dir == tmp_path / "reports" / "a1" / "F-002"
    assert (published.bundle_dir / "manifest.json").read_bytes() == artifacts.read(
        published.manifest_ref
    )
    assert {item.path for item in manifest.files} == {
        "report_en.md",
        "report_kr.md",
        "poc.sh",
        "evidence/provenance.json",
    }
    for item in manifest.files:
        body, media_type = read_bundle_file(manifest, item.path, artifacts.read)
        assert body == (published.bundle_dir / item.path).read_bytes()
        assert media_type == item.media_type
        assert item.sha256 == hashlib.sha256(body).hexdigest()
        assert item.artifact_ref.content_hash == item.sha256
    archive = read_bundle_archive(manifest, published.archive_ref, artifacts.read)
    assert archive == (published.bundle_dir / "bundle.zip").read_bytes()
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        assert set(zipped.namelist()) == {item.path for item in manifest.files}
        for item in manifest.files:
            assert zipped.read(item.path) == artifacts.read(item.artifact_ref)
    assert _publish(tmp_path, artifacts) == published


def test_validated_shell_poc_survives_manifest_read_and_zip_exactly(
    tmp_path: Path,
) -> None:
    poc = (
        b"#!/bin/sh\nset -eu\n"
        b"fixture=/tmp/sastsimi-fixture\n"
        b"printf 'safe' > \"$fixture\"\n"
    )
    digest = hashlib.sha256(poc).hexdigest()
    artifacts = Artifacts()

    published = _publish(tmp_path, artifacts, _files(poc))
    manifest = parse_bundle_manifest(
        artifacts.read(published.manifest_ref),
        finding_ref=_ref("finding", "b" * 64, record_id="finding-2"),
    )

    assert manifest.poc_original_sha256 == digest
    assert manifest.poc_redacted is False
    assert (published.bundle_dir / "poc.sh").read_bytes() == poc
    body, media_type = read_bundle_file(manifest, "poc.sh", artifacts.read)
    assert body == poc
    assert media_type == _MEDIA["poc.sh"]
    archive = read_bundle_archive(manifest, published.archive_ref, artifacts.read)
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        assert zipped.read("poc.sh") == poc
    poc_entry = next(item for item in manifest.files if item.path == "poc.sh")
    assert poc_entry.sha256 == digest


@pytest.mark.parametrize(
    "poc",
    (
        b"#!/bin/sh\necho /home/alice/private.txt\n",
        b"#!/bin/sh\necho C:\\Users\\Alice\\private.txt\n",
        b"#!/bin/sh\necho /tmp/safe sk-Abcdefghijk99999\n",
        b"#!/bin/sh\nmkdir -p /tmp/sk-ABCDEFGH12345678\n",
        b"#!/bin/sh\necho /usr/local/private.txt\n",
        b"#!/bin/sh\necho /tmp/../var/log/private\n",
    ),
)
def test_publisher_rejects_raw_host_or_secret_shell_poc(
    tmp_path: Path, poc: bytes
) -> None:
    artifacts = Artifacts()

    with pytest.raises(ValueError, match="BUNDLE_FILE_UNSAFE"):
        _publish(tmp_path, artifacts, _files(poc))

    assert artifacts.values == {}
    assert not (tmp_path / "reports" / "a1" / "F-002" / "manifest.json").exists()


def test_published_bundle_rejects_missing_or_modified_files(tmp_path: Path) -> None:
    artifacts = Artifacts()
    published = _publish(tmp_path, artifacts)
    (published.bundle_dir / "poc.sh").write_bytes(b"changed")
    with pytest.raises(ValueError, match="BUNDLE_PUBLISHED_FILE_INVALID"):
        _publish(tmp_path, artifacts)
    (published.bundle_dir / "poc.sh").unlink()
    with pytest.raises(ValueError, match="BUNDLE_PUBLISHED_FILE_INVALID"):
        _publish(tmp_path, artifacts)
    (published.bundle_dir / "poc.sh").write_bytes(_files()[2].body)
    with pytest.raises(ValueError, match="BUNDLE_ALREADY_PUBLISHED"):
        _publish(
            tmp_path,
            artifacts,
            (BundleFile("report_en.md", b"# Different\n", _MEDIA["report_en.md"]),)
            + _files()[1:],
        )


def test_reader_rejects_bad_path_bad_bytes_and_archive_substitution(
    tmp_path: Path,
) -> None:
    artifacts = Artifacts()
    published = _publish(tmp_path, artifacts)
    manifest = parse_bundle_manifest(
        artifacts.read(published.manifest_ref),
        finding_ref=_ref("finding", "b" * 64, record_id="finding-2"),
    )
    for path in ("../poc.sh", "report_fr.md", "manifest.json", "bundle.zip"):
        with pytest.raises(ValueError, match="BUNDLE_FILE_NOT_LISTED"):
            read_bundle_file(manifest, path, artifacts.read)
    with pytest.raises(ValueError, match="BUNDLE_FILE_HASH_MISMATCH"):
        read_bundle_file(manifest, "poc.sh", lambda _ref: b"tampered")
    with pytest.raises(ValueError, match="BUNDLE_ARCHIVE_INVALID"):
        read_bundle_archive(manifest, published.archive_ref, lambda _ref: b"bad zip")


def test_reader_rejects_symlink_mode_even_when_member_bytes_match(
    tmp_path: Path,
) -> None:
    artifacts = Artifacts()
    published = _publish(tmp_path, artifacts)
    manifest = parse_bundle_manifest(
        artifacts.read(published.manifest_ref),
        finding_ref=_ref("finding", "b" * 64, record_id="finding-2"),
    )
    original = artifacts.read(published.archive_ref)
    output = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(original)) as source,
        zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as target,
    ):
        for member in source.infolist():
            info = zipfile.ZipInfo(member.filename, date_time=member.date_time)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = member.create_system
            info.external_attr = (
                (stat.S_IFLNK | 0o777) << 16
                if member.filename == "poc.sh"
                else member.external_attr
            )
            target.writestr(info, source.read(member))
    tampered_ref = artifacts.put(output.getvalue(), "application/zip")

    with pytest.raises(ValueError, match="BUNDLE_ARCHIVE_INVALID"):
        read_bundle_archive(manifest, tampered_ref, artifacts.read)


def test_oversized_and_unsafe_bytes_are_rejected_before_publication(
    tmp_path: Path,
) -> None:
    artifacts = Artifacts()
    too_large = BundleFile(
        "report_en.md",
        b"a" * (bundle_files.MAX_BUNDLE_FILE_BYTES + 1),
        _MEDIA["report_en.md"],
    )
    with pytest.raises(ValueError, match="BUNDLE_FILE_TOO_LARGE"):
        _publish(tmp_path, artifacts, (too_large, *_files()[1:]))
    assert not (tmp_path / "reports" / "a1" / "F-002" / "manifest.json").exists()
    unsafe = BundleFile("poc.sh", b"echo sk-Abcdefghijk99999\n", _MEDIA["poc.sh"])
    with pytest.raises(ValueError, match="BUNDLE_FILE_UNSAFE"):
        _publish(tmp_path, artifacts, (*_files()[:2], unsafe, _files()[3]))


def test_partial_write_never_advertises_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = Artifacts()
    original = bundle_files._write_file
    calls = 0

    def failing_write(
        directory: bundle_files._SafeDirectory, name: str, body: bytes
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk failed")
        original(directory, name, body)

    monkeypatch.setattr(bundle_files, "_write_file", failing_write)
    with pytest.raises(OSError, match="disk failed"):
        _publish(tmp_path, artifacts)
    assert not (tmp_path / "reports" / "a1" / "F-002" / "manifest.json").exists()


def test_symlinked_bundle_directory_cannot_redirect_publication(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    bundle_parent = tmp_path / "reports" / "a1"
    bundle_parent.mkdir(parents=True)
    try:
        os.symlink(outside, bundle_parent / "F-002", target_is_directory=True)
    except (OSError, NotImplementedError):
        if os.name != "nt":
            pytest.skip("Creating a directory symlink is unavailable on this host")
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(bundle_parent / "F-002"), str(outside)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("Creating a directory junction is unavailable on this host")
    with pytest.raises(ValueError, match="BUNDLE_PATH_UNSAFE"):
        _publish(tmp_path, Artifacts())
    assert list(outside.iterdir()) == []
