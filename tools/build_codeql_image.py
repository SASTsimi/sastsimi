"""Verify the pinned local CodeQL bundle, then run one offline Docker build."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

BUNDLE_NAME = "codeql-bundle-linux64.tar.gz"
BUNDLE_SIZE = 686_083_106
BUNDLE_SHA256 = "8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305"
DEFAULT_TAG = "sastsimi/codeql:2.27.0-local"
_TAG = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ROOT = Path(__file__).resolve().parents[1]
_CONTEXT = _ROOT / "docker" / "codeql"
_BUNDLE = _CONTEXT / BUNDLE_NAME


def _error(code: str) -> int:
    print(code, file=sys.stderr)
    return 1


def _regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
        return (
            stat.S_ISREG(info.st_mode)
            and not path.is_symlink()
            and path.resolve(strict=True) == path.absolute()
            and not (int(getattr(info, "st_file_attributes", 0)) & 0x400)
        )
    except OSError:
        return False


def _copy_verified_bundle(destination: Path) -> str | None:
    if not _regular_file(_BUNDLE):
        return "BUNDLE_MISSING_OR_UNTRUSTED"
    try:
        digest = hashlib.sha256()
        copied = 0
        with _BUNDLE.open("rb") as source, destination.open("xb") as target:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != BUNDLE_SIZE:
                return "BUNDLE_SIZE_MISMATCH"
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                copied += len(chunk)
                if copied > BUNDLE_SIZE:
                    return "BUNDLE_SIZE_MISMATCH"
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
            after = os.fstat(source.fileno())
        if (
            copied != BUNDLE_SIZE
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            return "BUNDLE_SIZE_MISMATCH"
    except OSError:
        return "BUNDLE_MISSING_OR_UNTRUSTED"
    if digest.hexdigest() != BUNDLE_SHA256:
        return "BUNDLE_HASH_MISMATCH"
    return None


def _docker_executable() -> Path | None:
    discovered = shutil.which("docker")
    if not discovered:
        return None
    try:
        executable = Path(discovered).resolve(strict=True)
    except OSError:
        return None
    return executable if _regular_file(executable) else None


def _environment() -> dict[str, str]:
    allowed = {
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "HOME",
        "PATH",
        "SYSTEMROOT",
        "USERPROFILE",
        "WINDIR",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=DEFAULT_TAG)
    arguments = parser.parse_args(argv)
    if _TAG.fullmatch(arguments.tag) is None:
        return _error("IMAGE_TAG_INVALID")
    docker = _docker_executable()
    if docker is None:
        return _error("DOCKER_EXECUTABLE_UNAVAILABLE")

    try:
        with tempfile.TemporaryDirectory(prefix="sastsimi-codeql-build-") as raw:
            staging = Path(raw)
            for name in ("Dockerfile", "sastsimi-codeql"):
                source = _CONTEXT / name
                if not _regular_file(source):
                    return _error("IMAGE_CONTEXT_UNTRUSTED")
                shutil.copyfile(source, staging / name)
            bundle_error = _copy_verified_bundle(staging / BUNDLE_NAME)
            if bundle_error is not None:
                return _error(bundle_error)
            completed = subprocess.run(
                (
                    str(docker),
                    "build",
                    "--pull=false",
                    "--network=none",
                    "--tag",
                    arguments.tag,
                    ".",
                ),
                cwd=staging,
                env=_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                check=False,
                timeout=1800,
            )
    except (OSError, subprocess.TimeoutExpired):
        return _error("CODEQL_IMAGE_BUILD_FAILED")
    if completed.returncode != 0:
        return _error("CODEQL_IMAGE_BUILD_FAILED")
    print("CODEQL_IMAGE_BUILD_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
