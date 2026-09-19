"""Safe operator functions for CodeQL database provisioning and registration.

Parser wiring deliberately lives elsewhere. Provisioning prepares an exact
tracked source tree and invokes only the pinned, networkless container mode;
registration and inspection never execute repository code.
"""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Callable, Coroutine
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast
from uuid import uuid4

from sastsimi.config.codeql_container import CodeQLContainerRuntimeConfig
from sastsimi.interfaces.cli.capability import CapabilityCommandResult
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.static_analysis.codeql_provision_source import (
    PreparedCodeQLSource,
    prepare_exact_source,
)
from sastsimi.static_analysis.codeql_registry import (
    CodeQLDatabaseIdentity,
    CodeQLLanguage,
    lookup_codeql_database,
    publish_codeql_database,
)
from sastsimi.static_analysis.container_codeql_provision import (
    CodeQLProvisionDockerPort,
    CodeQLProvisionResult,
    CodeQLProvisionStatus,
    ContainerCodeQLProvisionSpec,
    run_codeql_python_provision,
)
from sastsimi.static_analysis.docker_codeql_port import ContainerCodeQLDockerPort

type SourcePreparer = Callable[..., PreparedCodeQLSource]
type DockerPortFactory = Callable[[Path], CodeQLProvisionDockerPort]
type ProvisionRunner = Callable[..., Coroutine[Any, Any, CodeQLProvisionResult]]


def resolve_operator_executable(value: str) -> Path:
    """Resolve one explicit/path-search executable without executing it."""

    candidate = Path(value)
    discovered = (
        str(candidate)
        if candidate.is_absolute() or candidate.parent != Path(".")
        else shutil.which(value)
    )
    try:
        if discovered is None:
            raise ValueError
        submitted = Path(discovered)
        if submitted.is_symlink():
            raise ValueError
        resolved = submitted.resolve(strict=True)
        if not resolved.is_file():
            raise ValueError
        return resolved
    except (OSError, ValueError):
        raise ValueError("CODEQL_OPERATOR_EXECUTABLE_UNAVAILABLE") from None


def run_register(
    *,
    config: CodeQLContainerRuntimeConfig,
    repository_url: str,
    commit_id: str,
    language: str,
    tracked_manifest_sha256: str,
    database_root: Path,
    cancellation_requested: Callable[[], bool] | None = None,
) -> CapabilityCommandResult:
    """Register one exact existing DB without returning local path material."""

    identity = _operator_identity(
        config=config,
        repository_url=repository_url,
        commit_id=commit_id,
        language=language,
        tracked_manifest_sha256=tracked_manifest_sha256,
    )
    if identity is None:
        return _blocked(ExitCode.INPUT_ERROR, "CODEQL_DATABASE_IDENTITY_INVALID")
    try:
        published = publish_codeql_database(
            registry_root=config.database_registry_root,
            database_root=database_root,
            identity=identity,
            cancellation_requested=cancellation_requested,
            max_bytes=config.database_limit_bytes,
        )
    except FileExistsError:
        return _blocked(ExitCode.CONFIG_ERROR, "CODEQL_DATABASE_ALREADY_PUBLISHED")
    except ValueError as error:
        if str(error) == "CODEQL_DATABASE_PROVISION_CANCELLED":
            return _blocked(ExitCode.BLOCKED, "CODEQL_DATABASE_PROVISION_CANCELLED")
        return _blocked(ExitCode.INTEGRITY_ERROR, "CODEQL_DATABASE_REGISTRATION_FAILED")
    except OSError:
        return _blocked(ExitCode.INTEGRITY_ERROR, "CODEQL_DATABASE_REGISTRATION_FAILED")
    return CapabilityCommandResult(
        ExitCode.OK,
        {
            "artifact_key": published.artifact_key,
            "database_digest": published.database_digest,
            "status": "REGISTERED",
        },
    )


def run_inspect(
    *,
    config: CodeQLContainerRuntimeConfig,
    repository_url: str,
    commit_id: str,
    language: str,
    tracked_manifest_sha256: str,
) -> CapabilityCommandResult:
    """Inspect one exact registry identity and return only stable digests."""

    identity = _operator_identity(
        config=config,
        repository_url=repository_url,
        commit_id=commit_id,
        language=language,
        tracked_manifest_sha256=tracked_manifest_sha256,
    )
    if identity is None:
        return _blocked(ExitCode.INPUT_ERROR, "CODEQL_DATABASE_IDENTITY_INVALID")
    try:
        published = lookup_codeql_database(
            registry_root=config.database_registry_root,
            identity=identity,
        )
    except (OSError, ValueError):
        return _blocked(
            ExitCode.INTEGRITY_ERROR, "CODEQL_DATABASE_INTEGRITY_CHECK_FAILED"
        )
    if published is None:
        return _blocked(ExitCode.CAPABILITY_UNSUPPORTED, "CODEQL_DATABASE_NOT_FOUND")
    return CapabilityCommandResult(
        ExitCode.OK,
        {
            "artifact_key": published.artifact_key,
            "database_digest": published.database_digest,
            "status": "AVAILABLE",
        },
    )


def run_provision(
    *,
    config: CodeQLContainerRuntimeConfig,
    repository_url: str,
    commit_id: str,
    language: str,
    repository_root: Path,
    git_executable: Path,
    docker_executable: Path,
    source_preparer: SourcePreparer = prepare_exact_source,
    docker_port_factory: DockerPortFactory = lambda path: ContainerCodeQLDockerPort(
        docker_executable=path
    ),
    provision_runner: ProvisionRunner = run_codeql_python_provision,
) -> CapabilityCommandResult:
    """Create and atomically register one exact Python DB in the pinned image."""

    if language != "python":
        return _blocked(
            ExitCode.CAPABILITY_UNSUPPORTED,
            "CODEQL_PROVISION_LANGUAGE_UNSUPPORTED",
        )
    if config.nano_cpus % 1_000_000 != 0:
        return _blocked(ExitCode.CONFIG_ERROR, "CODEQL_PROVISION_CPU_LIMIT_INVALID")
    try:
        with TemporaryDirectory(prefix="sastsimi-codeql-source-") as source_name:
            with TemporaryDirectory(prefix="sastsimi-codeql-database-") as db_name:
                source_root = Path(source_name).resolve(strict=True)
                database_root = Path(db_name).resolve(strict=True)
                prepared = source_preparer(
                    git_executable=git_executable,
                    repository_root=repository_root,
                    commit_id=commit_id,
                    destination=source_root,
                )
                identity = _operator_identity(
                    config=config,
                    repository_url=repository_url,
                    commit_id=commit_id,
                    language=language,
                    tracked_manifest_sha256=prepared.tracked_manifest_sha256,
                )
                if identity is None or prepared.root != source_root:
                    return _blocked(
                        ExitCode.INPUT_ERROR,
                        "CODEQL_DATABASE_IDENTITY_INVALID",
                    )
                action_id = "codeql-provision-" + uuid4().hex
                attempt_id = "codeql-attempt-" + uuid4().hex
                spec = ContainerCodeQLProvisionSpec(
                    docker_executable=docker_executable,
                    image_digest=config.image.split("@", 1)[1],
                    repository_source=prepared.root,
                    database_destination=database_root,
                    action_id=action_id,
                    attempt_id=attempt_id,
                    user=config.container_user,
                    pids_limit=config.pids_limit,
                    memory_limit_bytes=config.memory_limit_bytes,
                    cpu_limit_millicores=config.nano_cpus // 1_000_000,
                    database_limit_bytes=config.database_limit_bytes,
                )
                outcome: CodeQLProvisionResult = asyncio.run(
                    provision_runner(
                        port=docker_port_factory(docker_executable),
                        spec=spec,
                        timeout_seconds=900,
                    )
                )
                if (
                    outcome.status is not CodeQLProvisionStatus.SUCCEEDED
                    or outcome.database_root != database_root
                ):
                    return _blocked(
                        ExitCode.BLOCKED,
                        outcome.reason or "CODEQL_PROVISION_FAILED",
                    )
                published = publish_codeql_database(
                    registry_root=config.database_registry_root,
                    database_root=database_root,
                    identity=identity,
                    max_bytes=config.database_limit_bytes,
                )
                return CapabilityCommandResult(
                    ExitCode.OK,
                    {
                        "artifact_key": published.artifact_key,
                        "database_digest": published.database_digest,
                        "tracked_manifest_sha256": (
                            prepared.tracked_manifest_sha256
                        ),
                        "status": "REGISTERED",
                    },
                )
    except FileExistsError:
        return _blocked(ExitCode.CONFIG_ERROR, "CODEQL_DATABASE_ALREADY_PUBLISHED")
    except (OSError, TypeError, ValueError):
        return _blocked(ExitCode.INTEGRITY_ERROR, "CODEQL_PROVISION_FAILED")


def _operator_identity(
    *,
    config: CodeQLContainerRuntimeConfig,
    repository_url: str,
    commit_id: str,
    language: str,
    tracked_manifest_sha256: str,
) -> CodeQLDatabaseIdentity | None:
    if not isinstance(config, CodeQLContainerRuntimeConfig):
        return None
    try:
        return CodeQLDatabaseIdentity(
            repository_url=repository_url,
            commit_id=commit_id,
            language=cast(CodeQLLanguage, language),
            tracked_manifest_sha256=tracked_manifest_sha256,
            provider_key=config.database_provider_key,
            provider_revision=config.database_provider_revision,
            provider_evidence_sha256=config.database_provider_evidence_sha256,
        )
    except (TypeError, ValueError):
        return None


def _blocked(code: ExitCode, reason_code: str) -> CapabilityCommandResult:
    return CapabilityCommandResult(
        code,
        {"reason_code": reason_code, "status": "BLOCKED"},
    )


__all__ = [
    "resolve_operator_executable",
    "run_inspect",
    "run_provision",
    "run_register",
]
