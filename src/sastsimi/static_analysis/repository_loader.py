"""Exact, non-executing repository preparation primitives.

This module owns Git ingress/path checks and typed observations only. Durable
authorization, metadata and storage publication remain application concerns.
"""

from __future__ import annotations

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

_HEX = frozenset(string.hexdigits)


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
        canonical = Path(url2pathname(path)).resolve(strict=True).as_uri()
        return CanonicalRepositorySource(canonical, "localhost", path)
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
    [WorkspaceStorageLease, MonotonicActionDeadline], RepositoryProcessRunner
]
type GuardProcessRunnerFactory = Callable[
    [Path, MonotonicActionDeadline], RepositoryProcessRunner
]


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
        self._git = git_executable.resolve(strict=True)
        self._output = output_dir.resolve(strict=True)
        self._sensitive_names = sensitive_names

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
        self, workspace: CodeWorkspace, deadline: MonotonicActionDeadline
    ) -> None:
        root = self.root_for(workspace)
        runner = self._factory(root, deadline)

        async def run(name: str, argv: tuple[str, ...]) -> ProcessResult:
            spec = ProcessSpec(
                invocation_id=f"{deadline.action_id}-guard-{name}",
                attempt_id=deadline.action_id,
                argv=(str(self._git), "-C", str(root), *argv),
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
            )
            result = await runner.run(spec)
            if result.outcome != "SUCCEEDED" or result.return_code != 0:
                raise ValueError("WORKSPACE_MUTATED")
            return result

        head = await run("head", ("rev-parse", "HEAD"))
        if head.stdout.decode("ascii").strip().lower() != str(workspace.commit_id):
            raise ValueError("WORKSPACE_MUTATED")
        await run("worktree", ("diff", "--quiet", "HEAD", "--"))
        await run("index", ("diff", "--cached", "--quiet", "HEAD", "--"))
        listing = await run("manifest", ("ls-files", "--stage", "-z"))
        manifest, _ = _build_manifest(root, listing.stdout, self._sensitive_names)
        if manifest != self._manifests.get(str(workspace.workspace_id)):
            raise ValueError("WORKSPACE_MUTATED")


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
        if (
            git_executable.is_symlink()
            or not git_executable.resolve(strict=True).is_file()
        ):
            raise ValueError("GIT_EXECUTABLE_INVALID")
        if output_dir.is_symlink() or not output_dir.resolve(strict=True).is_dir():
            raise ValueError("PROCESS_OUTPUT_ROOT_INVALID")
        self.storage = storage
        self.process_runner_factory = process_runner_factory
        self.git_executable = git_executable.resolve(strict=True)
        self.output_dir = output_dir.resolve(strict=True)
        self.allow_local_file = allow_local_file
        self.sensitive_names = sensitive_names
        self.process_receipts: tuple[ProcessReceipt, ...] = ()

    def _environment(self) -> tuple[tuple[str, str], ...]:
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

    def _spec(
        self,
        *,
        attempt_id: str,
        invocation: str,
        root: Path,
        deadline: MonotonicActionDeadline,
        argv: tuple[str, ...],
    ) -> ProcessSpec:
        return ProcessSpec(
            invocation_id=invocation,
            attempt_id=attempt_id,
            argv=(str(self.git_executable), *argv),
            cwd=root,
            env=self._environment(),
            attempt_output_dir=self.output_dir,
            stdout_limit_bytes=2 * 1024 * 1024,
            stderr_limit_bytes=64 * 1024,
            attempt_output_limit_bytes=4 * 1024 * 1024,
            deadline=deadline,
        )

    def _quota(
        self, lease: WorkspaceStorageLease, policy: WorkspaceStoragePolicy
    ) -> None:
        usage = self.storage.measure(lease)
        reasons = (
            (usage.git_bytes > policy.max_git_bytes, "GIT_BYTES"),
            (usage.checkout_bytes > policy.max_checkout_bytes, "CHECKOUT_BYTES"),
            (usage.file_count > policy.max_file_count, "FILE_COUNT"),
            (usage.free_bytes < policy.min_free_bytes, "FREE_RESERVE"),
        )
        for exceeded, reason in reasons:
            if exceeded:
                self.storage.seal(lease, reason)
                raise ValueError("WORKSPACE_QUOTA_EXCEEDED:" + reason)

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
        runner = self.process_runner_factory(lease, deadline)
        receipts: list[ProcessReceipt] = []
        commit_id: str | None = None

        async def invoke(name: str, argv: tuple[str, ...]) -> ProcessResult:
            if deadline.remaining_ms(time.monotonic_ns()) == 0:
                raise ValueError("GIT_COMMAND_FAILED")
            spec = self._spec(
                attempt_id=attempt_id,
                invocation=f"{attempt_id}-{name}",
                root=lease.root,
                deadline=deadline,
                argv=argv,
            )
            result = await runner.run(spec)
            receipts.append(result.receipt)
            self._quota(lease, policy)
            if result.outcome != "SUCCEEDED" or result.return_code != 0:
                raise ValueError("GIT_COMMAND_FAILED")
            if result.stdout_truncated:
                raise ValueError("GIT_OUTPUT_TRUNCATED")
            return result

        try:
            canonical_again = canonicalize_repository_source(
                source.url, allow_local_file=self.allow_local_file
            )
            if canonical_again != source:
                raise ValueError("REPOSITORY_SOURCE_CHANGED")
            file_protocol = "always" if source.url.startswith("file:") else "never"
            await invoke(
                "clone",
                (
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
                    f"protocol.file.allow={file_protocol}",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    f"core.hooksPath={self.output_dir}",
                    "clone",
                    "--no-checkout",
                    "--no-recurse-submodules",
                    "--",
                    source.url,
                    ".",
                ),
            )
            resolved = await invoke(
                "resolve",
                (
                    "-C",
                    str(lease.root),
                    "rev-parse",
                    "--verify",
                    "--end-of-options",
                    requested_ref + "^{commit}",
                ),
            )
            commit_id = resolved.stdout.decode("ascii").strip()
            if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit_id):
                raise ValueError("GIT_COMMIT_INVALID")
            commit_id = commit_id.lower()
            await invoke(
                "checkout",
                ("-C", str(lease.root), "checkout", "--detach", commit_id),
            )
            head = await invoke("head", ("-C", str(lease.root), "rev-parse", "HEAD"))
            if head.stdout.decode("ascii").strip().lower() != commit_id:
                raise ValueError("WORKSPACE_HEAD_MISMATCH")
            listing = await invoke(
                "manifest", ("-C", str(lease.root), "ls-files", "--stage", "-z")
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
            )
        except (OSError, UnicodeError, ValueError):
            self.process_receipts = tuple(receipts)
            self.storage.seal(lease, "PREPARATION_FAILED")
            self.storage.cleanup_or_quarantine(lease)
            return RepositoryPreparation(
                analysis_id=analysis_id,
                workspace_id=workspace_id,
                repository_url=source.url,
                requested_ref=requested_ref,
                status="FAILED",
                resolved_commit_id=commit_id,
                root=lease.root,
                tracked_files=(),
                gaps=(),
                errors=(_error("GIT_COMMAND_FAILED", retryable=True),),
            )

    def build_manifest(
        self, root: Path, raw: bytes
    ) -> tuple[tuple[TrackedFile, ...], tuple[CandidateGap, ...]]:
        return _build_manifest(root, raw, self.sensitive_names)
