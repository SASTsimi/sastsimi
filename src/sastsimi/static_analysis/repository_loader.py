"""Exact, non-executing repository preparation primitives.

This module owns Git ingress/path checks and typed observations only. Durable
authorization, metadata and storage publication remain application concerns.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import string
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, unquote_to_bytes, urlsplit
from urllib.request import url2pathname

from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.static import CodeWorkspace, git_path
from sastsimi.ports.dto import (
    CandidateError,
    CandidateGap,
    CanonicalRepositorySource,
    MonotonicActionDeadline,
    ProcessReceipt,
    ProcessResult,
    ProcessSpec,
    RepositoryPreparation,
    TrackedFile,
    WorkspaceStorageLease,
    WorkspaceStoragePolicy,
)
from sastsimi.ports.workspace import WorkspaceStoragePort

from .process import process_command_fingerprint

_HEX = frozenset(string.hexdigits)


def _git_executable_identity(path: Path) -> tuple[Path, str, str]:
    """Pin one non-linked Git executable to its key and content digest."""

    try:
        if path.is_symlink():
            raise ValueError
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise ValueError
        digest = hashlib.sha256()
        with resolved.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except (OSError, ValueError) as error:
        raise ValueError("GIT_EXECUTABLE_INVALID") from error
    subject_key = resolved.stem.lower()
    if not subject_key:
        raise ValueError("GIT_EXECUTABLE_INVALID")
    return resolved, subject_key, digest.hexdigest()


def _canonical_local_path(path: Path) -> CanonicalRepositorySource:
    try:
        details = path.lstat()
        resolved = path.resolve(strict=True)
        if (
            path.is_symlink()
            or not resolved.is_dir()
            or getattr(details, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError
    except (OSError, ValueError) as error:
        raise ValueError("REPOSITORY_SOURCE_INVALID") from error
    return CanonicalRepositorySource(resolved.as_uri(), "localhost", str(resolved))


def _strict_percent_decode(value: str) -> bytes:
    for index, char in enumerate(value):
        if char == "%" and (
            index + 2 >= len(value)
            or value[index + 1] not in _HEX
            or value[index + 2] not in _HEX
        ):
            raise ValueError("REPOSITORY_SOURCE_INVALID")
    try:
        return unquote_to_bytes(value)
    except (UnicodeError, ValueError) as error:
        raise ValueError("REPOSITORY_SOURCE_INVALID") from error


def _normalize_percent_path(value: str) -> str:
    parts: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "%":
            parts.append("%" + value[index + 1 : index + 3].upper())
            index += 3
        else:
            parts.append(quote(value[index], safe="/-._~"))
            index += 1
    return "".join(parts)


def canonicalize_repository_source(
    submitted: str, *, allow_local_file: bool = False
) -> CanonicalRepositorySource:
    """Return one secret-free repository identity or reject before any sink."""
    if (
        allow_local_file
        and submitted
        and submitted == submitted.strip()
        and not submitted.startswith("-")
        and not submitted.lower().startswith("ext::")
        and "://" not in submitted
        and not re.match(r"^[^/]+@[^/]+:[^/]+$", submitted)
    ):
        return _canonical_local_path(Path(submitted))
    if (
        not submitted
        or submitted != submitted.strip()
        or submitted.startswith("-")
        or submitted.lower().startswith("ext::")
        or "\\" in submitted
        or re.match(r"^[^/]+@[^/]+:[^/]+$", submitted)
    ):
        raise ValueError("REPOSITORY_SOURCE_INVALID")
    try:
        split = urlsplit(submitted)
        port = split.port
    except (UnicodeError, ValueError) as error:
        raise ValueError("REPOSITORY_SOURCE_INVALID") from error
    if split.query or split.fragment or split.username is not None or split.password:
        raise ValueError("REPOSITORY_SOURCE_INVALID")
    if split.scheme == "file":
        if not allow_local_file or split.netloc not in {"", "localhost"}:
            raise ValueError("REPOSITORY_SOURCE_INVALID")
        raw_path = _strict_percent_decode(split.path)
        if any(byte < 32 or byte == 127 for byte in raw_path):
            raise ValueError("REPOSITORY_SOURCE_INVALID")
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("REPOSITORY_SOURCE_INVALID") from error
        if any(part in {"", ".", ".."} for part in Path(path).parts[1:]):
            raise ValueError("REPOSITORY_SOURCE_INVALID")
        return _canonical_local_path(Path(url2pathname(path)))
    if split.scheme.lower() != "https" or not split.hostname or not split.path:
        raise ValueError("REPOSITORY_SOURCE_INVALID")
    try:
        host = split.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("REPOSITORY_SOURCE_INVALID") from error
    raw_path = _strict_percent_decode(split.path)
    if any(byte < 32 or byte == 127 for byte in raw_path):
        raise ValueError("REPOSITORY_SOURCE_INVALID")
    try:
        decoded_path = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("REPOSITORY_SOURCE_INVALID") from error
    if not decoded_path.startswith("/") or any(
        part in {"", ".", ".."} for part in decoded_path.split("/")[1:]
    ):
        raise ValueError("REPOSITORY_SOURCE_INVALID")
    normalized_path = _normalize_percent_path(split.path)
    authority = host if port in {None, 443} else f"{host}:{port}"
    return CanonicalRepositorySource(
        url=f"https://{authority}{normalized_path}",
        host=host,
        repository_path=normalized_path,
    )


def validate_clone_destination(destination: Path, storage_root: Path) -> Path:
    """Require a resolved, existing, empty, non-linked child directory."""
    try:
        root = storage_root.resolve(strict=True)
        if storage_root.is_symlink() or destination.is_symlink():
            raise ValueError
        resolved = destination.resolve(strict=True)
        resolved.relative_to(root)
        if resolved == root or not resolved.is_dir() or any(resolved.iterdir()):
            raise ValueError
    except (OSError, ValueError) as error:
        raise ValueError("WORKSPACE_DESTINATION_INVALID") from error
    return resolved


class RepositoryProcessRunner(Protocol):
    async def run(self, spec: ProcessSpec) -> ProcessResult: ...

    async def cancel(self, attempt_id: str) -> object: ...


type RepositoryProcessRunnerFactory = Callable[
    [WorkspaceStorageLease, MonotonicActionDeadline, Path], RepositoryProcessRunner
]
type GuardProcessRunnerFactory = Callable[
    [Path, MonotonicActionDeadline, str], RepositoryProcessRunner
]


def _repository_environment() -> tuple[tuple[str, str], ...]:
    values = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    for name in ("SystemRoot", "WINDIR", "COMSPEC"):
        if name in os.environ:
            values[name] = os.environ[name]
    return tuple(sorted(values.items()))


def _repository_command_argv(
    command_kind: str,
    *,
    git_executable: Path,
    root: Path,
    repository_url: str,
    requested_ref: str,
    commit_id: str,
) -> tuple[str, ...]:
    hooks_dir = root / ".git" / "sastsimi-empty-hooks"
    commands = {
        "clone": (
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.file.allow="
            + ("always" if repository_url.startswith("file:") else "never"),
            "-c",
            "http.followRedirects=false",
            "clone",
            "--no-checkout",
            "--no-recurse-submodules",
            "--",
            repository_url,
            ".",
        ),
        "resolve": (
            "-C",
            str(root),
            "rev-parse",
            "--verify",
            "--end-of-options",
            requested_ref + "^{commit}",
        ),
        "checkout": (
            "-c",
            f"core.hooksPath={hooks_dir}",
            "-C",
            str(root),
            "checkout",
            "--detach",
            commit_id,
        ),
        "head": ("-C", str(root), "rev-parse", "HEAD"),
        "manifest": ("-C", str(root), "ls-files", "--stage", "-z"),
    }
    try:
        return (str(git_executable), *commands[command_kind])
    except KeyError as error:
        raise ValueError("GIT_COMMAND_INVALID") from error


def _repository_process_spec(
    *,
    command_kind: str,
    attempt_id: str,
    root: Path,
    output_dir: Path,
    deadline: MonotonicActionDeadline,
    argv: tuple[str, ...],
) -> ProcessSpec:
    return ProcessSpec(
        invocation_id=f"{attempt_id}-{command_kind}",
        command_kind=command_kind,
        attempt_id=attempt_id,
        argv=argv,
        cwd=root,
        env=_repository_environment(),
        attempt_output_dir=output_dir,
        stdout_limit_bytes=2 * 1024 * 1024,
        stderr_limit_bytes=64 * 1024,
        attempt_output_limit_bytes=4 * 1024 * 1024,
        deadline=deadline,
    )


def repository_process_specs(
    *,
    git_executable: Path,
    root: Path,
    output_dir: Path,
    deadline: MonotonicActionDeadline,
    attempt_id: str,
    repository_url: str,
    requested_ref: str,
    commit_id: str,
) -> tuple[ProcessSpec, ...]:
    """Rebuild the exact closed repository command sequence for verification."""
    return tuple(
        _repository_process_spec(
            command_kind=command_kind,
            attempt_id=attempt_id,
            root=root,
            output_dir=output_dir,
            deadline=deadline,
            argv=_repository_command_argv(
                command_kind,
                git_executable=git_executable,
                root=root,
                repository_url=repository_url,
                requested_ref=requested_ref,
                commit_id=commit_id,
            ),
        )
        for command_kind in ("clone", "resolve", "checkout", "head", "manifest")
    )


def _gap(code: str, reason: str, path: str | None = None) -> CandidateGap:
    return CandidateGap(
        stage="REPOSITORY",
        code=code,
        reason=reason,
        description="Repository input was omitted from the safe tracked manifest",
        affected_paths=(path,) if path is not None else (),
        affected_languages=(),
        affected_locations=(),
        retryable=False,
    )


def _error(code: str, *, retryable: bool) -> CandidateError:
    return CandidateError(
        stage="REPOSITORY",
        code=code,
        safe_message="Repository preparation could not produce a verified workspace",
        retryable=retryable,
    )


def _build_manifest(
    root: Path, raw: bytes, sensitive_names: frozenset[str]
) -> tuple[tuple[TrackedFile, ...], tuple[CandidateGap, ...]]:
    safe: list[TrackedFile] = []
    gaps: list[CandidateGap] = []
    workspace = root.resolve(strict=True)
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            header, encoded_path = item.split(b"\t", 1)
            mode, blob_id, stage = header.decode("ascii").split(" ")
            path = encoded_path.decode("utf-8")
            if stage != "0":
                raise ValueError
            git_path(path)
        except (UnicodeError, ValueError):
            gaps.append(_gap("UNSAFE_PATH_EXCLUDED", "BLOCKED"))
            continue
        if mode == "120000":
            gaps.append(_gap("SYMLINK_EXCLUDED", "BLOCKED", path))
            continue
        if mode == "160000":
            gaps.append(_gap("SUBMODULE_UNAVAILABLE", "UNSUPPORTED", path))
            continue
        if mode not in {"100644", "100755"}:
            gaps.append(_gap("UNSUPPORTED_FILE_TYPE", "UNSUPPORTED", path))
            continue
        path_object = Path(path)
        if (
            path_object.name.lower() in sensitive_names
            or path_object.suffix.lower()
            in {
                ".pem",
                ".key",
            }
        ):
            gaps.append(_gap("SENSITIVE_PATH_EXCLUDED", "BLOCKED", path))
            continue
        candidate = workspace.joinpath(*path.split("/"))
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(workspace)
            if candidate.is_symlink() or not resolved.is_file():
                raise ValueError
            with resolved.open("rb") as stream:
                prefix = stream.read(200)
        except (OSError, ValueError):
            gaps.append(_gap("WORKSPACE_PATH_UNSAFE", "BLOCKED", path))
            continue
        if prefix.startswith(b"version https://git-lfs.github.com/spec/v1"):
            gaps.append(_gap("LFS_POINTER_ONLY", "UNSUPPORTED", path))
            continue
        safe.append(
            TrackedFile(
                git_path=path,
                git_mode=mode,
                blob_id=blob_id.lower(),
                size_bytes=resolved.stat().st_size,
            )
        )
    return tuple(sorted(safe, key=lambda value: value.git_path)), tuple(
        sorted(gaps, key=lambda value: (value.code, value.affected_paths))
    )


class WorkspaceGuard:
    """Resolve only registered workspaces and detect HEAD/index/tracked drift."""

    def __init__(
        self,
        *,
        roots: dict[str, Path],
        manifests: dict[str, tuple[TrackedFile, ...]],
        process_runner_factory: GuardProcessRunnerFactory,
        git_executable: Path,
        output_dir: Path,
        sensitive_names: frozenset[str] = frozenset(
            {".env", ".env.local", "id_rsa", "id_ed25519"}
        ),
    ) -> None:
        self._roots = dict(roots)
        self._manifests = dict(manifests)
        self._factory = process_runner_factory
        self._git, self._git_subject_key, self._git_sha256 = _git_executable_identity(
            git_executable
        )
        self._output = output_dir.resolve(strict=True)
        self._sensitive_names = sensitive_names

    def _verified_git_executable(self) -> Path:
        current, subject_key, digest = _git_executable_identity(self._git)
        if (
            current != self._git
            or subject_key != self._git_subject_key
            or digest != self._git_sha256
        ):
            raise ValueError("GIT_EXECUTABLE_CHANGED")
        return current

    def verify_git_capability(self, subject_key: str, expected_sha256: str) -> None:
        """Bind guard commands to the executable approved by the exact profile."""

        if subject_key != self._git_subject_key or expected_sha256 != self._git_sha256:
            raise ValueError("GIT_EXECUTABLE_CAPABILITY_MISMATCH")
        self._verified_git_executable()

    def root_for(self, workspace: CodeWorkspace) -> Path:
        if workspace.status != "READY" or workspace.commit_id is None:
            raise ValueError("WORKSPACE_NOT_READY")
        try:
            configured = self._roots[str(workspace.workspace_id)]
            root = configured.resolve(strict=True)
        except (KeyError, OSError) as error:
            raise ValueError("WORKSPACE_ROOT_UNAVAILABLE") from error
        if configured.is_symlink() or not root.is_dir():
            raise ValueError("WORKSPACE_ROOT_UNAVAILABLE")
        return root

    async def assert_unchanged(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        root = self.root_for(workspace)
        return await self._assert_repository_state(
            root,
            str(workspace.commit_id),
            self._manifests.get(str(workspace.workspace_id)),
            deadline,
            require_detached=False,
            attempt_id=attempt_id,
            check_id=check_id,
        )

    async def assert_preparation_unchanged(
        self,
        outcome: RepositoryPreparation,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        if (
            outcome.status != "READY"
            or outcome.root is None
            or outcome.resolved_commit_id is None
        ):
            raise ValueError("WORKSPACE_MUTATED")
        try:
            configured = self._roots[outcome.workspace_id]
            root = configured.resolve(strict=True)
            reported = outcome.root.resolve(strict=True)
        except (KeyError, OSError) as error:
            raise ValueError("WORKSPACE_MUTATED") from error
        if (
            configured.is_symlink()
            or outcome.root.is_symlink()
            or root != reported
            or not root.is_dir()
        ):
            raise ValueError("WORKSPACE_MUTATED")
        return await self._assert_repository_state(
            root,
            outcome.resolved_commit_id,
            outcome.tracked_files,
            deadline,
            require_detached=True,
            attempt_id=attempt_id,
            check_id=check_id,
        )

    def validate_integrity_receipts(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_ids: tuple[str, ...],
        receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        root = self.root_for(workspace)
        if not check_ids or len(set(check_ids)) != len(check_ids):
            raise ValueError("WORKSPACE_PROCESS_RECEIPTS_INVALID")
        expected = tuple(
            spec
            for check_id in check_ids
            for spec, _expect_failure in self._integrity_specs(
                root,
                deadline,
                attempt_id=attempt_id,
                check_id=check_id,
                require_detached=False,
            )
        )
        if len(receipts) != len(expected):
            raise ValueError("WORKSPACE_PROCESS_RECEIPTS_INVALID")
        for receipt, spec in zip(receipts, expected, strict=True):
            if (
                receipt.action_id != deadline.action_id
                or receipt.attempt_id != attempt_id
                or receipt.invocation_id != spec.invocation_id
                or receipt.command_kind != spec.command_kind
                or receipt.command_fingerprint != process_command_fingerprint(spec)
                or receipt.outcome != "SUCCEEDED"
                or receipt.return_code != 0
            ):
                raise ValueError("WORKSPACE_PROCESS_RECEIPTS_INVALID")

    def _integrity_specs(
        self,
        root: Path,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
        require_detached: bool,
    ) -> tuple[tuple[ProcessSpec, bool], ...]:
        if not attempt_id or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", check_id) is None:
            raise ValueError("WORKSPACE_CHECK_IDENTITY_INVALID")
        git_executable = self._verified_git_executable()
        commands: list[tuple[str, tuple[str, ...], bool]] = [
            ("head", ("rev-parse", "HEAD"), False),
        ]
        if require_detached:
            commands.append(("detached", ("symbolic-ref", "-q", "HEAD"), True))
        commands.extend(
            (
                ("worktree", ("diff", "--quiet", "HEAD", "--"), False),
                ("index", ("diff", "--cached", "--quiet", "HEAD", "--"), False),
                ("manifest", ("ls-files", "--stage", "-z"), False),
            )
        )
        return tuple(
            (
                ProcessSpec(
                    invocation_id=(
                        f"{deadline.action_id}:workspace-guard:{check_id}:{name}"
                    ),
                    command_kind=f"guard-{name}",
                    attempt_id=attempt_id,
                    argv=(str(git_executable), "-C", str(root), *argv),
                    cwd=root,
                    env=(
                        ("GIT_CONFIG_GLOBAL", os.devnull),
                        ("GIT_CONFIG_NOSYSTEM", "1"),
                        ("GIT_TERMINAL_PROMPT", "0"),
                    ),
                    attempt_output_dir=self._output,
                    stdout_limit_bytes=2 * 1024 * 1024,
                    stderr_limit_bytes=64 * 1024,
                    attempt_output_limit_bytes=4 * 1024 * 1024,
                    deadline=deadline,
                ),
                expect_failure,
            )
            for name, argv, expect_failure in commands
        )

    def preparation_process_specs(
        self,
        outcome: RepositoryPreparation,
        *,
        action_id: str,
        attempt_id: str,
        deadline: MonotonicActionDeadline,
    ) -> tuple[ProcessSpec, ...]:
        if (
            outcome.status != "READY"
            or outcome.root is None
            or outcome.resolved_commit_id is None
            or deadline.action_id != action_id
        ):
            raise ValueError("WORKSPACE_MUTATED")
        try:
            root = outcome.root.resolve(strict=True)
            source = canonicalize_repository_source(
                outcome.repository_url,
                allow_local_file=outcome.repository_url.startswith("file:"),
            )
        except (OSError, ValueError) as error:
            raise ValueError("WORKSPACE_MUTATED") from error
        if source.url != outcome.repository_url:
            raise ValueError("WORKSPACE_MUTATED")
        return repository_process_specs(
            git_executable=self._git,
            root=root,
            output_dir=self._output,
            deadline=deadline,
            attempt_id=attempt_id,
            repository_url=source.url,
            requested_ref=outcome.requested_ref,
            commit_id=outcome.resolved_commit_id,
        )

    async def _assert_repository_state(
        self,
        root: Path,
        commit_id: str,
        expected_manifest: tuple[TrackedFile, ...] | None,
        deadline: MonotonicActionDeadline,
        *,
        require_detached: bool,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        runner = self._factory(root, deadline, attempt_id)
        receipts: list[ProcessReceipt] = []
        for spec, expect_failure in self._integrity_specs(
            root,
            deadline,
            attempt_id=attempt_id,
            check_id=check_id,
            require_detached=require_detached,
        ):
            result = await runner.run(spec)
            succeeded = result.outcome == "SUCCEEDED" and result.return_code == 0
            if succeeded == expect_failure:
                raise ValueError("WORKSPACE_MUTATED")
            receipts.append(result.receipt)
            if (
                spec.command_kind == "guard-head"
                and result.stdout.decode("ascii").strip().lower() != commit_id
            ):
                raise ValueError("WORKSPACE_MUTATED")
            if spec.command_kind == "guard-manifest":
                manifest, _ = _build_manifest(
                    root, result.stdout, self._sensitive_names
                )
                if manifest != expected_manifest:
                    raise ValueError("WORKSPACE_MUTATED")
        return tuple(receipts)


type RecoveryDeadlineFactory = Callable[[str, str], MonotonicActionDeadline]


class RepositoryRecoveryGuard:
    """Re-resolve a lease, enforce quota, and re-prove exact Git state."""

    def __init__(
        self,
        *,
        storage: WorkspaceStoragePort,
        workspace_guard: WorkspaceGuard,
        deadline_factory: RecoveryDeadlineFactory,
    ) -> None:
        self._storage = storage
        self._workspace_guard = workspace_guard
        self._deadline_factory = deadline_factory

    async def validate(
        self,
        outcome: RepositoryPreparation,
        *,
        action_id: str,
        attempt_id: str,
        process_receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        if outcome.lease_id is None or outcome.root is None:
            raise ValueError("WORKSPACE_MUTATED")
        lease = self._storage.resolve(outcome.lease_id)
        if (
            lease.attempt_id != attempt_id
            or lease.workspace_id != outcome.workspace_id
            or lease.root.resolve(strict=True) != outcome.root.resolve(strict=True)
        ):
            raise ValueError("WORKSPACE_MUTATED")
        self._storage.enforce(lease)
        deadline = self._deadline_factory(action_id, attempt_id)
        if deadline.action_id != action_id:
            raise ValueError("WORKSPACE_MUTATED")
        expected_specs = self._workspace_guard.preparation_process_specs(
            outcome,
            action_id=action_id,
            attempt_id=attempt_id,
            deadline=deadline,
        )
        if len(process_receipts) != len(expected_specs):
            raise ValueError("WORKSPACE_PROCESS_RECEIPTS_INVALID")
        for receipt, spec in zip(process_receipts, expected_specs, strict=True):
            if (
                receipt.action_id != action_id
                or receipt.attempt_id != attempt_id
                or receipt.invocation_id != spec.invocation_id
                or receipt.command_kind != spec.command_kind
                or receipt.command_fingerprint != process_command_fingerprint(spec)
            ):
                raise ValueError("WORKSPACE_PROCESS_RECEIPTS_INVALID")
        await self._workspace_guard.assert_preparation_unchanged(
            outcome,
            deadline,
            attempt_id=attempt_id,
            check_id="recovery-verify",
        )
        self._storage.enforce(lease)

    def verify_git_capability(self, subject_key: str, expected_sha256: str) -> None:
        """Bind recovery checks to the same approved Git executable."""

        self._workspace_guard.verify_git_capability(subject_key, expected_sha256)


class RepositoryLoader:
    """Run a closed Git command sequence and return a non-persisted candidate."""

    def __init__(
        self,
        *,
        storage: WorkspaceStoragePort,
        process_runner_factory: RepositoryProcessRunnerFactory,
        git_executable: Path,
        output_dir: Path,
        allow_local_file: bool = False,
        sensitive_names: frozenset[str] = frozenset(
            {".env", ".env.local", "id_rsa", "id_ed25519"}
        ),
    ) -> None:
        if output_dir.is_symlink() or not output_dir.resolve(strict=True).is_dir():
            raise ValueError("PROCESS_OUTPUT_ROOT_INVALID")
        self.storage = storage
        self.process_runner_factory = process_runner_factory
        (
            self.git_executable,
            self._git_subject_key,
            self._git_sha256,
        ) = _git_executable_identity(git_executable)
        self.output_dir = output_dir.resolve(strict=True)
        self.allow_local_file = allow_local_file
        self.sensitive_names = sensitive_names
        self.process_receipts: tuple[ProcessReceipt, ...] = ()

    def _verified_git_executable(self) -> Path:
        current, subject_key, digest = _git_executable_identity(self.git_executable)
        if (
            current != self.git_executable
            or subject_key != self._git_subject_key
            or digest != self._git_sha256
        ):
            raise ValueError("GIT_EXECUTABLE_CHANGED")
        return current

    def verify_git_capability(self, subject_key: str, expected_sha256: str) -> None:
        """Bind repository commands to the executable approved by the profile."""

        if subject_key != self._git_subject_key or expected_sha256 != self._git_sha256:
            raise ValueError("GIT_EXECUTABLE_CAPABILITY_MISMATCH")
        self._verified_git_executable()

    def _spec(
        self,
        *,
        attempt_id: str,
        invocation: str,
        root: Path,
        output_dir: Path,
        deadline: MonotonicActionDeadline,
        argv: tuple[str, ...],
    ) -> ProcessSpec:
        command_kind = invocation.rsplit("-", 1)[-1]
        return _repository_process_spec(
            command_kind=command_kind,
            attempt_id=attempt_id,
            root=root,
            output_dir=output_dir,
            deadline=deadline,
            argv=(str(self._verified_git_executable()), *argv),
        )

    def _attempt_output_dir(
        self, attempt_id: str, lease: WorkspaceStorageLease
    ) -> Path:
        if not attempt_id:
            raise ValueError("PROCESS_OUTPUT_ROOT_INVALID")
        target = self.output_dir / hashlib.sha256(attempt_id.encode()).hexdigest()[:24]
        try:
            target.mkdir(mode=0o700)
            resolved = target.resolve(strict=True)
            resolved.relative_to(self.output_dir)
            if target.is_symlink() or not resolved.is_dir():
                raise ValueError
            try:
                resolved.relative_to(lease.root.resolve(strict=True))
            except ValueError:
                pass
            else:
                raise ValueError
            return resolved
        except (OSError, ValueError) as error:
            raise ValueError("PROCESS_OUTPUT_ROOT_INVALID") from error

    def _quota(
        self, lease: WorkspaceStorageLease, policy: WorkspaceStoragePolicy
    ) -> None:
        del policy
        try:
            self.storage.enforce(lease)
        except RuntimeError as error:
            raise ValueError(str(error)) from error

    async def _run_with_quota(
        self,
        runner: RepositoryProcessRunner,
        spec: ProcessSpec,
        lease: WorkspaceStorageLease,
        policy: WorkspaceStoragePolicy,
    ) -> ProcessResult:
        process = asyncio.create_task(runner.run(spec))
        try:
            while not process.done():
                await asyncio.sleep(0.005)
                try:
                    self._quota(lease, policy)
                except ValueError:
                    await runner.cancel(spec.attempt_id)
                    return await process
            return await process
        finally:
            if not process.done():
                await runner.cancel(spec.attempt_id)
                await process

    @staticmethod
    def _empty_hooks_dir(lease: WorkspaceStorageLease) -> Path:
        hooks = lease.root / ".git" / "sastsimi-empty-hooks"
        try:
            git_dir = (lease.root / ".git").resolve(strict=True)
            if git_dir.is_symlink() or not git_dir.is_dir():
                raise ValueError
            hooks.mkdir(mode=0o700)
            resolved = hooks.resolve(strict=True)
            resolved.relative_to(git_dir)
            if hooks.is_symlink() or any(resolved.iterdir()):
                raise ValueError
            return resolved
        except (OSError, ValueError) as error:
            raise ValueError("GIT_HOOKS_DIRECTORY_INVALID") from error

    async def prepare(
        self,
        *,
        submitted_source: str,
        requested_ref: str,
        analysis_id: str,
        workspace_id: str,
        attempt_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
        deadline: MonotonicActionDeadline,
    ) -> RepositoryPreparation:
        source = canonicalize_repository_source(
            submitted_source, allow_local_file=self.allow_local_file
        )
        receipts: list[ProcessReceipt] = []
        commit_id: str | None = None
        lease: WorkspaceStorageLease | None = None

        try:
            if (
                not requested_ref
                or len(requested_ref) > 1_024
                or any(ord(char) < 32 or char == "\x7f" for char in requested_ref)
            ):
                raise ValueError("GIT_REF_INVALID")
            lease = self.storage.allocate(
                attempt_id=attempt_id,
                workspace_id=workspace_id,
                policy_ref=policy_ref,
                policy=policy,
            )
            validate_clone_destination(lease.root, lease.root.parent)
            attempt_output_dir = self._attempt_output_dir(attempt_id, lease)
            runner = self.process_runner_factory(lease, deadline, attempt_output_dir)

            async def invoke(name: str, argv: tuple[str, ...]) -> ProcessResult:
                if deadline.remaining_ms(time.monotonic_ns()) == 0:
                    raise ValueError("GIT_COMMAND_FAILED")
                spec = self._spec(
                    attempt_id=attempt_id,
                    invocation=f"{attempt_id}-{name}",
                    root=lease.root,
                    output_dir=attempt_output_dir,
                    deadline=deadline,
                    argv=argv,
                )
                result = await self._run_with_quota(runner, spec, lease, policy)
                receipts.append(result.receipt)
                self._quota(lease, policy)
                if result.outcome != "SUCCEEDED" or result.return_code != 0:
                    raise ValueError("GIT_COMMAND_FAILED")
                if result.stdout_truncated:
                    raise ValueError("GIT_OUTPUT_TRUNCATED")
                return result

            canonical_again = canonicalize_repository_source(
                source.url, allow_local_file=self.allow_local_file
            )
            if canonical_again != source:
                raise ValueError("REPOSITORY_SOURCE_CHANGED")
            await invoke(
                "clone",
                _repository_command_argv(
                    "clone",
                    git_executable=self.git_executable,
                    root=lease.root,
                    repository_url=source.url,
                    requested_ref=requested_ref,
                    commit_id="",
                )[1:],
            )
            self._empty_hooks_dir(lease)
            resolved = await invoke(
                "resolve",
                _repository_command_argv(
                    "resolve",
                    git_executable=self.git_executable,
                    root=lease.root,
                    repository_url=source.url,
                    requested_ref=requested_ref,
                    commit_id="",
                )[1:],
            )
            commit_id = resolved.stdout.decode("ascii").strip()
            if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit_id):
                raise ValueError("GIT_COMMIT_INVALID")
            commit_id = commit_id.lower()
            await invoke(
                "checkout",
                _repository_command_argv(
                    "checkout",
                    git_executable=self.git_executable,
                    root=lease.root,
                    repository_url=source.url,
                    requested_ref=requested_ref,
                    commit_id=commit_id,
                )[1:],
            )
            head = await invoke(
                "head",
                _repository_command_argv(
                    "head",
                    git_executable=self.git_executable,
                    root=lease.root,
                    repository_url=source.url,
                    requested_ref=requested_ref,
                    commit_id=commit_id,
                )[1:],
            )
            if head.stdout.decode("ascii").strip().lower() != commit_id:
                raise ValueError("WORKSPACE_HEAD_MISMATCH")
            listing = await invoke(
                "manifest",
                _repository_command_argv(
                    "manifest",
                    git_executable=self.git_executable,
                    root=lease.root,
                    repository_url=source.url,
                    requested_ref=requested_ref,
                    commit_id=commit_id,
                )[1:],
            )
            files, gaps = self.build_manifest(lease.root, listing.stdout)
            self._quota(lease, policy)
            self.process_receipts = tuple(receipts)
            return RepositoryPreparation(
                analysis_id=analysis_id,
                workspace_id=workspace_id,
                repository_url=source.url,
                requested_ref=requested_ref,
                status="READY",
                resolved_commit_id=commit_id,
                root=lease.root,
                tracked_files=files,
                gaps=gaps,
                errors=(),
                lease_id=lease.lease_id,
            )
        except (OSError, UnicodeError, ValueError):
            self.process_receipts = tuple(receipts)
            if lease is not None:
                self.storage.seal(lease, "PREPARATION_FAILED")
                self.storage.cleanup_or_quarantine(lease)
            return RepositoryPreparation(
                analysis_id=analysis_id,
                workspace_id=workspace_id,
                repository_url=source.url,
                requested_ref=requested_ref,
                status="FAILED",
                resolved_commit_id=commit_id,
                root=lease.root if lease is not None else None,
                tracked_files=(),
                gaps=(),
                errors=(_error("GIT_COMMAND_FAILED", retryable=True),),
                lease_id=None,
            )

    def build_manifest(
        self, root: Path, raw: bytes
    ) -> tuple[tuple[TrackedFile, ...], tuple[CandidateGap, ...]]:
        return _build_manifest(root, raw, self.sensitive_names)
