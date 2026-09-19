"""Safe operator functions for prebuilt CodeQL database registration.

Parser wiring deliberately lives elsewhere.  These functions do not create a
database, execute CodeQL or repository code, invoke a build tool, or access the
network.  They only publish or inspect an existing controlled database tree.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

from sastsimi.config.codeql_container import CodeQLContainerRuntimeConfig
from sastsimi.interfaces.cli.capability import CapabilityCommandResult
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.static_analysis.codeql_registry import (
    CodeQLDatabaseIdentity,
    CodeQLLanguage,
    lookup_codeql_database,
    publish_codeql_database,
)


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


__all__ = ["run_inspect", "run_register"]
