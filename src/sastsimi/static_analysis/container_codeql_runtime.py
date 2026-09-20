"""Async lifecycle for the closed Docker CodeQL boundary.

The runtime owns ordering, validation, bounded output, and exact cleanup.  A
separately injected port owns Docker I/O; this module never starts a subprocess
and never accepts a container identifier supplied by Docker.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol

from .container_codeql import (
    ContainerCodeQLBoundaryError,
    ContainerCodeQLSpec,
    build_container_codeql_create_argv,
    collect_bounded_stdout,
    validate_container_inspect,
    validate_sarif_payload,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_CONTAINER_NAME = re.compile(r"^sastsimi-codeql-[0-9a-f]{24}$")
_DATABASE_TARGET = "/work/database"
_OUTPUT_TARGET = "/work/output"
_DENIAL_CODES = frozenset({"ENOSPC", "EDQUOT"})
_DEFAULT_CLEANUP_TIMEOUT_SECONDS = 5.0


class CodeQLContainerRunStatus(StrEnum):
    """Terminal status emitted without host or daemon error details."""

    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class CodeQLArtifactIdentity:
    """Exact immutable inputs whose identity follows the SARIF result."""

    database_digest: str
    tracked_manifest_digest: str
    query_digest: str

    def __post_init__(self) -> None:
        if any(
            _DIGEST.fullmatch(value) is None
            for value in (
                self.database_digest,
                self.tracked_manifest_digest,
                self.query_digest,
            )
        ):
            raise ValueError("CODEQL_CONTAINER_ARTIFACT_DIGEST_INVALID")


@dataclass(frozen=True, slots=True)
class CodeQLContainerRunResult:
    """Sanitized result of one exact action and attempt."""

    status: CodeQLContainerRunStatus
    raw_sarif: bytes | None
    reason: str | None
    image_digest: str
    database_digest: str
    tracked_manifest_digest: str
    query_digest: str


@dataclass(frozen=True, slots=True)
class ContainerCodeQLProbeRequest:
    """Probe intent; the runtime overwrites attempted sizes from the spec."""

    expected_codeql_version: str
    database_attempted_bytes: int | None = None
    output_attempted_bytes: int | None = None

    def __post_init__(self) -> None:
        if _VERSION.fullmatch(self.expected_codeql_version) is None:
            raise ValueError("CODEQL_CONTAINER_PROBE_VERSION_INVALID")


@dataclass(frozen=True, slots=True)
class TmpfsCapDenialEvidence:
    """Observation from a non-sparse write that attempted exactly cap + 1."""

    target: str
    limit_bytes: int
    attempted_bytes: int
    bytes_written: int
    denial_code: str


@dataclass(frozen=True, slots=True)
class ContainerCodeQLProbeObservation:
    """Raw trusted-port observation validated before capability activation."""

    codeql_version: str
    database: TmpfsCapDenialEvidence
    output: TmpfsCapDenialEvidence


@dataclass(frozen=True, slots=True)
class ContainerCodeQLProbeResult:
    """Sanitized probe result suitable for a capability receipt."""

    status: CodeQLContainerRunStatus
    reason: str | None
    image_digest: str
    codeql_version: str | None


class ContainerCodeQLDockerPort(Protocol):
    """Docker operations required by this runtime.

    ``probe`` must perform real, non-sparse writes of the requested byte counts
    and report the observed short-write/ENOSPC/EDQUOT outcome.  Returning an
    inferred filesystem size is not sufficient evidence.
    """

    async def create(self, argv: tuple[str, ...]) -> None: ...

    async def start(self, container_name: str) -> None: ...

    async def inspect(self, container_name: str) -> Mapping[str, object]: ...

    async def wait(self, container_name: str) -> int: ...

    def logs(self, container_name: str) -> AsyncIterator[bytes]: ...

    async def probe(
        self, container_name: str, request: ContainerCodeQLProbeRequest
    ) -> ContainerCodeQLProbeObservation: ...

    async def remove(self, container_name: str) -> None: ...


def _container_name(argv: tuple[str, ...]) -> str:
    try:
        positions = tuple(
            index for index, value in enumerate(argv) if value == "--name"
        )
        if len(positions) != 1:
            raise ValueError
        name = argv[positions[0] + 1]
        if _CONTAINER_NAME.fullmatch(name) is None:
            raise ValueError
        return name
    except (IndexError, ValueError):
        raise RuntimeError("CODEQL_CONTAINER_COMMAND_INVALID") from None


def _run_result(
    *,
    status: CodeQLContainerRunStatus,
    reason: str | None,
    raw_sarif: bytes | None,
    spec: ContainerCodeQLSpec,
    artifact_identity: CodeQLArtifactIdentity,
) -> CodeQLContainerRunResult:
    return CodeQLContainerRunResult(
        status=status,
        raw_sarif=raw_sarif,
        reason=reason,
        image_digest=spec.image_digest,
        database_digest=artifact_identity.database_digest,
        tracked_manifest_digest=artifact_identity.tracked_manifest_digest,
        query_digest=artifact_identity.query_digest,
    )


async def _bounded_logs(chunks: AsyncIterator[bytes], *, max_bytes: int) -> bytes:
    received: list[bytes] = []
    total = 0
    async for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise ContainerCodeQLBoundaryError("CODEQL_CONTAINER_STDOUT_MALFORMED")
        total += len(chunk)
        if total > max_bytes:
            raise ContainerCodeQLBoundaryError("CODEQL_CONTAINER_STDOUT_LIMIT")
        received.append(chunk)
    return collect_bounded_stdout(received, max_bytes=max_bytes)


def _consume_cleanup_task(task: asyncio.Task[None]) -> None:
    try:
        task.exception()
    except (asyncio.CancelledError, Exception):
        pass


async def _remove_exact(
    port: ContainerCodeQLDockerPort,
    container_name: str,
    *,
    timeout_seconds: float,
) -> str | None:
    removal = asyncio.create_task(port.remove(container_name))
    try:
        done, _pending = await asyncio.wait({removal}, timeout=timeout_seconds)
    except asyncio.CancelledError:
        removal.add_done_callback(_consume_cleanup_task)
        removal.cancel()
        return "CODEQL_CONTAINER_REMOVE_FAILED"
    if not done:
        removal.add_done_callback(_consume_cleanup_task)
        removal.cancel()
        return "CODEQL_CONTAINER_REMOVE_TIMEOUT"
    try:
        removal.result()
    except (asyncio.CancelledError, Exception):
        return "CODEQL_CONTAINER_REMOVE_FAILED"
    return None


async def run_container_codeql(
    *,
    port: ContainerCodeQLDockerPort,
    spec: ContainerCodeQLSpec,
    artifact_identity: CodeQLArtifactIdentity,
    timeout_seconds: float,
    stdout_limit_bytes: int,
    cleanup_timeout_seconds: float = _DEFAULT_CLEANUP_TIMEOUT_SECONDS,
) -> CodeQLContainerRunResult:
    """Execute one CodeQL attempt and accept SARIF only after exact inspection."""

    if timeout_seconds <= 0 or stdout_limit_bytes <= 0 or cleanup_timeout_seconds <= 0:
        raise ValueError("CODEQL_CONTAINER_RUNTIME_LIMIT_INVALID")
    argv = build_container_codeql_create_argv(spec, operation="analyze")
    name = _container_name(argv)
    create_attempted = False
    created = False
    result = _run_result(
        status=CodeQLContainerRunStatus.FAILED,
        reason="CODEQL_CONTAINER_RUNTIME_ERROR",
        raw_sarif=None,
        spec=spec,
        artifact_identity=artifact_identity,
    )
    try:
        async with asyncio.timeout(timeout_seconds):
            create_attempted = True
            await port.create(argv)
            created = True
            inspect_record = await port.inspect(name)
            validate_container_inspect(inspect_record, spec, operation="analyze")
            await port.start(name)
            if await port.wait(name) != 0:
                result = replace(result, reason="CODEQL_CONTAINER_EXIT_NONZERO")
            else:
                output = await _bounded_logs(
                    port.logs(name), max_bytes=stdout_limit_bytes
                )
                sarif = validate_sarif_payload(output, max_bytes=stdout_limit_bytes)
                result = replace(
                    result,
                    status=CodeQLContainerRunStatus.SUCCEEDED,
                    reason=None,
                    raw_sarif=sarif,
                )
    except TimeoutError:
        result = replace(
            result,
            status=CodeQLContainerRunStatus.TIMED_OUT,
            reason="CODEQL_CONTAINER_TIMEOUT",
        )
    except asyncio.CancelledError:
        result = replace(
            result,
            status=CodeQLContainerRunStatus.CANCELLED,
            reason="CODEQL_CONTAINER_CANCELLED",
        )
    except ContainerCodeQLBoundaryError as error:
        result = replace(result, reason=error.code)
    except Exception:
        result = replace(result, reason="CODEQL_CONTAINER_RUNTIME_ERROR")
    cleanup_failure = (
        None
        if not create_attempted
        else await _remove_exact(
            port,
            name,
            timeout_seconds=cleanup_timeout_seconds,
        )
    )
    if created and cleanup_failure is not None:
        return replace(
            result,
            status=CodeQLContainerRunStatus.FAILED,
            reason=cleanup_failure,
            raw_sarif=None,
        )
    return result


def _valid_denial(
    evidence: TmpfsCapDenialEvidence, *, target: str, limit_bytes: int
) -> bool:
    return (
        evidence.target == target
        and type(evidence.limit_bytes) is int
        and evidence.limit_bytes == limit_bytes
        and type(evidence.attempted_bytes) is int
        and evidence.attempted_bytes == limit_bytes + 1
        and type(evidence.bytes_written) is int
        and 0 <= evidence.bytes_written <= limit_bytes
        and evidence.denial_code in _DENIAL_CODES
    )


def _probe_matches(
    observation: ContainerCodeQLProbeObservation,
    *,
    spec: ContainerCodeQLSpec,
    request: ContainerCodeQLProbeRequest,
) -> bool:
    return (
        observation.codeql_version == request.expected_codeql_version
        and _valid_denial(
            observation.database,
            target=_DATABASE_TARGET,
            limit_bytes=spec.database_limit_bytes,
        )
        and _valid_denial(
            observation.output,
            target=_OUTPUT_TARGET,
            limit_bytes=spec.output_limit_bytes,
        )
    )


async def probe_container_codeql_boundary(
    *,
    port: ContainerCodeQLDockerPort,
    spec: ContainerCodeQLSpec,
    request: ContainerCodeQLProbeRequest,
    timeout_seconds: float,
    cleanup_timeout_seconds: float = _DEFAULT_CLEANUP_TIMEOUT_SECONDS,
) -> ContainerCodeQLProbeResult:
    """Prove the pinned version and both destructive tmpfs cap+1 denials."""

    if timeout_seconds <= 0 or cleanup_timeout_seconds <= 0:
        raise ValueError("CODEQL_CONTAINER_RUNTIME_LIMIT_INVALID")
    argv = build_container_codeql_create_argv(spec, operation="probe")
    name = _container_name(argv)
    create_attempted = False
    created = False
    result = ContainerCodeQLProbeResult(
        status=CodeQLContainerRunStatus.FAILED,
        reason="CODEQL_CONTAINER_PROBE_ERROR",
        image_digest=spec.image_digest,
        codeql_version=None,
    )
    effective_request = replace(
        request,
        database_attempted_bytes=spec.database_limit_bytes + 1,
        output_attempted_bytes=spec.output_limit_bytes + 1,
    )
    try:
        async with asyncio.timeout(timeout_seconds):
            create_attempted = True
            await port.create(argv)
            created = True
            inspect_record = await port.inspect(name)
            validate_container_inspect(inspect_record, spec, operation="probe")
            await port.start(name)
            observation = await port.probe(name, effective_request)
            if not _probe_matches(observation, spec=spec, request=effective_request):
                result = replace(result, reason="CODEQL_CONTAINER_PROBE_MISMATCH")
            else:
                result = replace(
                    result,
                    status=CodeQLContainerRunStatus.SUCCEEDED,
                    reason=None,
                    codeql_version=observation.codeql_version,
                )
    except TimeoutError:
        result = replace(
            result,
            status=CodeQLContainerRunStatus.TIMED_OUT,
            reason="CODEQL_CONTAINER_TIMEOUT",
        )
    except asyncio.CancelledError:
        result = replace(
            result,
            status=CodeQLContainerRunStatus.CANCELLED,
            reason="CODEQL_CONTAINER_CANCELLED",
        )
    except ContainerCodeQLBoundaryError as error:
        result = replace(result, reason=error.code)
    except Exception:
        result = replace(result, reason="CODEQL_CONTAINER_PROBE_ERROR")
    cleanup_failure = (
        None
        if not create_attempted
        else await _remove_exact(
            port,
            name,
            timeout_seconds=cleanup_timeout_seconds,
        )
    )
    if created and cleanup_failure is not None:
        return replace(
            result,
            status=CodeQLContainerRunStatus.FAILED,
            reason=cleanup_failure,
            codeql_version=None,
        )
    return result


__all__ = [
    "CodeQLArtifactIdentity",
    "CodeQLContainerRunResult",
    "CodeQLContainerRunStatus",
    "ContainerCodeQLDockerPort",
    "ContainerCodeQLProbeObservation",
    "ContainerCodeQLProbeRequest",
    "ContainerCodeQLProbeResult",
    "TmpfsCapDenialEvidence",
    "probe_container_codeql_boundary",
    "run_container_codeql",
]
