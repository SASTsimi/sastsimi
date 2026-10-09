"""Operator-provided wheel archives are validated before CAS persistence."""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.offline_wheels import (
    build_wheel_bundle,
    import_wheel_bundle,
    import_wheel_bundle_bytes,
    require_target_compatible_wheels,
)


def _artifacts(tmp_path: Path) -> SimpleArtifactRepository:
    return SimpleArtifactRepository(
        tmp_path / "data",
        CheckpointIdentity(
            analysis_id="wheels-test",
            workspace_id="wheel-workspace",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )


def _wheel_bytes() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("sample_pkg/__init__.py", "")
        archive.writestr(
            "sample_pkg-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nTag: py3-none-any\n",
        )
        archive.writestr(
            "sample_pkg-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: sample-pkg\nVersion: 1.0\n",
        )
    return stream.getvalue()


def _tar_bytes(
    entries: tuple[tuple[str, bytes, bytes], ...],
) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, contents, member_type in entries:
            info = tarfile.TarInfo(name)
            info.type = member_type
            info.size = len(contents) if member_type == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(contents) if info.isfile() else None)
    return stream.getvalue()


def _write_bundle(tmp_path: Path, raw: bytes) -> tuple[Path, str]:
    path = tmp_path / "wheels.tar"
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def test_archive_imports_exact_universal_wheel(tmp_path: Path) -> None:
    name = "sample_pkg-1.0-py3-none-any.whl"
    path, digest = _write_bundle(
        tmp_path, _tar_bytes(((name, _wheel_bytes(), tarfile.REGTYPE),))
    )
    artifacts = _artifacts(tmp_path)

    bundle = import_wheel_bundle(path, digest, artifacts)

    assert bundle.archive_sha256 == digest
    assert bundle.wheel_names == (name,)
    assert artifacts.read(bundle.archive_ref) == path.read_bytes()


def test_resolver_bundle_round_trips_long_wheel_name(tmp_path: Path) -> None:
    name = (
        "charset_normalizer-3.4.4-cp312-cp312-manylinux2014_x86_64."
        "manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"
    )
    assert len(name.encode("ascii")) > 100
    wheel_dir = tmp_path / "downloaded"
    wheel_dir.mkdir()
    (wheel_dir / name).write_bytes(_wheel_bytes())

    raw = build_wheel_bundle(wheel_dir)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
    assert len(members) == 1
    assert members[0].name == name
    assert not members[0].pax_headers

    bundle = import_wheel_bundle_bytes(
        raw,
        _artifacts(tmp_path),
        target_tags=frozenset({"cp312-cp312-manylinux_2_17_x86_64"}),
    )
    assert bundle.wheel_names == (name,)


def test_operator_bundle_rejects_pax_metadata(tmp_path: Path) -> None:
    name = "sample_pkg-1.0-py3-none-any.whl"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo(name)
        member.pax_headers = {"comment": "untrusted"}
        wheel = _wheel_bytes()
        member.size = len(wheel)
        archive.addfile(member, io.BytesIO(wheel))

    with pytest.raises(ValueError, match="WHEEL_ARCHIVE_INVALID") as caught:
        import_wheel_bundle_bytes(stream.getvalue(), _artifacts(tmp_path))
    assert getattr(caught.value, "wheel_archive_reason", None) == "TAR_PAX_METADATA"


def test_invalid_wheel_zip_records_structure_reason(tmp_path: Path) -> None:
    name = "sample_pkg-1.0-py3-none-any.whl"
    raw = _tar_bytes(((name, b"not-a-zip", tarfile.REGTYPE),))

    with pytest.raises(ValueError, match="WHEEL_ARCHIVE_INVALID") as caught:
        import_wheel_bundle_bytes(raw, _artifacts(tmp_path))
    assert (
        getattr(caught.value, "wheel_archive_reason", None)
        == "WHEEL_ZIP_STRUCTURE_INVALID"
    )


def test_archive_rejects_symlink_digest_mismatch_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "sample_pkg-1.0-py3-none-any.whl"
    path, digest = _write_bundle(
        tmp_path, _tar_bytes(((name, _wheel_bytes(), tarfile.REGTYPE),))
    )
    artifacts = _artifacts(tmp_path)
    monkeypatch.setattr(
        artifacts,
        "put_bytes",
        lambda *_args: (_ for _ in ()).throw(AssertionError("unexpected CAS import")),
    )
    with pytest.raises(ValueError, match="WHEEL_ARCHIVE_DIGEST_MISMATCH"):
        import_wheel_bundle(path, "0" * 64, artifacts)
    from sastsimi.simple_runtime import offline_wheels

    monkeypatch.setattr(offline_wheels, "MAX_WHEEL_ARCHIVE_BYTES", 64)
    with pytest.raises(ValueError, match="WHEEL_ARCHIVE_TOO_LARGE"):
        import_wheel_bundle(path, digest, artifacts)
    link = tmp_path / "link.tar"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("Windows symlink creation is unavailable")
    with pytest.raises(ValueError, match="WHEEL_ARCHIVE_NOT_REGULAR"):
        import_wheel_bundle(link, digest, artifacts)


@pytest.mark.parametrize(
    "entries",
    [
        (("../sample_pkg-1.0-py3-none-any.whl", b"x", tarfile.REGTYPE),),
        (("sample_pkg-1.0-py3-none-any.whl", b"", tarfile.SYMTYPE),),
        (("notes.txt", b"x", tarfile.REGTYPE),),
        (
            ("sample_pkg-1.0-py3-none-any.whl", _wheel_bytes(), tarfile.REGTYPE),
            ("SAMPLE_PKG-1.0-py3-none-any.whl", _wheel_bytes(), tarfile.REGTYPE),
        ),
    ],
)
def test_archive_rejects_traversal_links_duplicate_casefold_names_and_non_wheels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entries: tuple[tuple[str, bytes, bytes], ...],
) -> None:
    path, digest = _write_bundle(tmp_path, _tar_bytes(entries))
    artifacts = _artifacts(tmp_path)
    monkeypatch.setattr(
        artifacts,
        "put_bytes",
        lambda *_args: (_ for _ in ()).throw(AssertionError("unexpected CAS import")),
    )
    with pytest.raises(ValueError, match="WHEEL_ARCHIVE_INVALID"):
        import_wheel_bundle(path, digest, artifacts)


def test_linux_target_accepts_matching_and_universal_wheels() -> None:
    require_target_compatible_wheels(
        (
            "sample_pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl",
            "other_pkg-1.0-py3-none-any.whl",
        ),
        frozenset({"cp312-cp312-manylinux_2_17_x86_64"}),
    )


def test_windows_host_does_not_reject_linux_wheel(
    tmp_path: Path,
) -> None:
    name = "sample_pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    path, digest = _write_bundle(
        tmp_path, _tar_bytes(((name, _wheel_bytes(), tarfile.REGTYPE),))
    )

    bundle = import_wheel_bundle(
        path,
        digest,
        _artifacts(tmp_path),
        target_tags=frozenset({"cp312-cp312-manylinux_2_17_x86_64"}),
    )

    assert bundle.wheel_names == (name,)


def test_unknown_target_rejects_platform_wheel() -> None:
    with pytest.raises(ValueError, match="WHEEL_TARGET_INCOMPATIBLE"):
        require_target_compatible_wheels(
            ("sample_pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl",),
            None,
        )
