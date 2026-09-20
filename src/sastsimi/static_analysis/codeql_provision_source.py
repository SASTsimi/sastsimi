"""Prepare a minimal exact tracked source tree for CodeQL provisioning."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.ports.dto import MonotonicActionDeadline, ProcessSpec, TrackedFile
from sastsimi.security.sensitive_paths import DEFAULT_SENSITIVE_PATH_POLICY

from .process import AttemptOutputBudget, SafeProcessRunner
from .repository_loader import _build_manifest

_COMMIT_LENGTHS = frozenset({40, 64})
_MAX_GIT_OUTPUT = 64 * 1024 * 1024
_MAX_GIT_STDERR = 64 * 1024
_GIT_TIMEOUT_NS = 30 * 1_000_000_000
_ATTEMPT_OUTPUT_LIMIT = 2 * _MAX_GIT_OUTPUT + 4 * _MAX_GIT_STDERR
_REPARSE_POINT = 0x400


@dataclass(frozen=True, slots=True)
class PreparedCodeQLSource:
    root: Path
    tracked_manifest_sha256: str


def _trusted(path: Path, *, directory: bool) -> Path:
    try:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError
        info = path.lstat()
        exact = path.resolve(strict=True)
        if (
            exact != path.absolute()
            or int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))
        ):
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("CODEQL_PROVISION_SOURCE_INVALID") from None
    return exact


def _environment() -> dict[str, str]:
    allowed = {
        name.upper(): value
        for name, value in os.environ.items()
        if name.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"} and value
    }
    return allowed | {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }


def _git(
    runner: SafeProcessRunner,
    repository: Path,
    *arguments: str,
) -> bytes:
    started_ns = time.monotonic_ns()
    spec = ProcessSpec(
        invocation_id="codeql-source-git-" + uuid4().hex,
        command_kind="CODEQL_SOURCE_GIT",
        attempt_id=runner.attempt_id,
        argv=(str(runner.executable), "-C", str(repository), *arguments),
        cwd=repository,
        env=tuple(sorted(_environment().items())),
        attempt_output_dir=runner.output_root,
        stdout_limit_bytes=_MAX_GIT_OUTPUT,
        stderr_limit_bytes=_MAX_GIT_STDERR,
        attempt_output_limit_bytes=_ATTEMPT_OUTPUT_LIMIT,
        deadline=MonotonicActionDeadline(
            action_id=runner.action_id,
            started_ns=started_ns,
            expires_ns=started_ns + _GIT_TIMEOUT_NS,
        ),
    )
    try:
        result = asyncio.run(runner.run(spec))
    except (OSError, RuntimeError, TimeoutError, ValueError):
        raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH") from None
    if result.outcome != "SUCCEEDED" or result.stdout_truncated:
        raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH")
    if result.return_code != 0:
        raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH")
    return result.stdout


def _manifest_digest(tracked: tuple[TrackedFile, ...]) -> str:
    return hashlib.sha256(
        canonical_bytes(
            [
                {
                    "git_path": item.git_path,
                    "git_mode": item.git_mode,
                    "blob_id": item.blob_id,
                    "size_bytes": item.size_bytes,
                }
                for item in tracked
            ]
        )
    ).hexdigest()


def _unchanged(runner: SafeProcessRunner, repository: Path) -> None:
    # ``git diff HEAD`` refreshes the index before comparing on Windows,
    # avoiding the racy-stat false positives of a raw ``diff-index`` call.
    _git(runner, repository, "diff", "--quiet", "HEAD", "--")


def _make_container_readable(root: Path) -> None:
    """Allow the fixed non-root CodeQL user to read the private staging tree."""

    if os.name != "posix":
        return
    for candidate in sorted(root.rglob("*")):
        candidate.chmod(0o755 if candidate.is_dir() else 0o444)
    root.chmod(0o755)


def prepare_exact_source(
    *,
    git_executable: Path,
    repository_root: Path,
    commit_id: str,
    destination: Path,
) -> PreparedCodeQLSource:
    """Copy only safe tracked files from one unchanged exact checkout."""

    executable = _trusted(git_executable, directory=False)
    repository = _trusted(repository_root, directory=True)
    target = _trusted(destination, directory=True)
    if (
        len(commit_id) not in _COMMIT_LENGTHS
        or any(character not in "0123456789abcdef" for character in commit_id)
        or any(target.iterdir())
        or repository == target
        or repository in target.parents
        or target in repository.parents
    ):
        raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH")
    action_id = "codeql-source-action-" + uuid4().hex
    attempt_id = "codeql-source-attempt-" + uuid4().hex
    with TemporaryDirectory(
        prefix="sastsimi-codeql-source-process-", dir=target.parent
    ) as output_name:
        output_root = Path(output_name).resolve(strict=True)
        runner = SafeProcessRunner(
            action_id=action_id,
            attempt_id=attempt_id,
            workspace_root=repository,
            output_root=output_root,
            executable=executable,
            output_budget=AttemptOutputBudget(
                attempt_id=attempt_id,
                limit_bytes=_ATTEMPT_OUTPUT_LIMIT,
            ),
        )
        head = _git(runner, repository, "rev-parse", "HEAD")
        try:
            observed = head.decode("ascii", errors="strict").strip().lower()
        except UnicodeDecodeError:
            raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH") from None
        if observed != commit_id:
            raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH")
        _unchanged(runner, repository)
        raw = _git(runner, repository, "ls-files", "--stage", "-z")
        tracked, _gaps = _build_manifest(repository, raw, DEFAULT_SENSITIVE_PATH_POLICY)
        if not tracked:
            raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH")
        for item in tracked:
            source = repository.joinpath(*item.git_path.split("/"))
            destination_file = target.joinpath(*item.git_path.split("/"))
            try:
                before = source.lstat()
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or source.is_symlink()
                    or before.st_size != item.size_bytes
                ):
                    raise ValueError
                destination_file.parent.mkdir(parents=True, exist_ok=True)
                with source.open("rb") as reader, destination_file.open("xb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)
                    writer.flush()
                    os.fsync(writer.fileno())
                after = source.lstat()
                if (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ) or destination_file.stat().st_size != item.size_bytes:
                    raise ValueError
            except (OSError, ValueError):
                raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH") from None
        _unchanged(runner, repository)
        second_raw = _git(runner, repository, "ls-files", "--stage", "-z")
        second, _second_gaps = _build_manifest(
            repository, second_raw, DEFAULT_SENSITIVE_PATH_POLICY
        )
        if second != tracked:
            raise ValueError("CODEQL_PROVISION_SOURCE_MISMATCH")
        _make_container_readable(target)
    return PreparedCodeQLSource(
        root=target,
        tracked_manifest_sha256=_manifest_digest(tracked),
    )


__all__ = ["PreparedCodeQLSource", "prepare_exact_source"]
