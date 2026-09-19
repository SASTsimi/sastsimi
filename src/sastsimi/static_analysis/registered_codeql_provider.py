"""Read-only resolution of exact, pre-registered CodeQL databases."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sastsimi.config.codeql_container import CodeQLContainerRuntimeConfig
from sastsimi.static_analysis.codeql_registry import (
    CodeQLDatabaseIdentity,
    PublishedCodeQLDatabase,
    lookup_codeql_database,
)

type CodeQLLanguage = Literal["python", "javascript-typescript"]


class RegisteredCodeQLProviderError(RuntimeError):
    """Stable resolution failure that never includes paths or submitted data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RegisteredCodeQLDatabase:
    """The only database fields exposed to the analysis runtime."""

    database_root: Path
    database_digest: str
    artifact_key: str


class RegisteredCodeQLDatabaseProvider:
    """Resolve an immutable database without provisioning or registry writes."""

    def __init__(self, config: CodeQLContainerRuntimeConfig) -> None:
        self._config = config

    def resolve(
        self,
        *,
        repository_url: str,
        commit_id: str,
        language: CodeQLLanguage,
        tracked_manifest_sha256: str,
    ) -> RegisteredCodeQLDatabase:
        registered = self.resolve_published(
            repository_url=repository_url,
            commit_id=commit_id,
            language=language,
            tracked_manifest_sha256=tracked_manifest_sha256,
        )
        return RegisteredCodeQLDatabase(
            database_root=registered.database_root,
            database_digest=registered.database_digest,
            artifact_key=registered.artifact_key,
        )

    def resolve_published(
        self,
        *,
        repository_url: str,
        commit_id: str,
        language: CodeQLLanguage,
        tracked_manifest_sha256: str,
    ) -> PublishedCodeQLDatabase:
        """Return the exact validated registry record for container execution."""

        try:
            identity = CodeQLDatabaseIdentity(
                repository_url=repository_url,
                commit_id=commit_id,
                language=language,
                tracked_manifest_sha256=tracked_manifest_sha256,
                provider_key=self._config.database_provider_key,
                provider_revision=self._config.database_provider_revision,
                provider_evidence_sha256=(
                    self._config.database_provider_evidence_sha256
                ),
            )
        except (TypeError, ValueError):
            raise RegisteredCodeQLProviderError(
                "REGISTERED_CODEQL_INPUT_INVALID"
            ) from None
        try:
            registered = lookup_codeql_database(
                registry_root=self._config.database_registry_root,
                identity=identity,
            )
        except ValueError as error:
            code = (
                "REGISTERED_CODEQL_REGISTRY_INVALID"
                if str(error) == "CODEQL_DATABASE_REGISTRY_INVALID"
                else "REGISTERED_CODEQL_DATABASE_INVALID"
            )
            raise RegisteredCodeQLProviderError(code) from None
        except Exception:
            raise RegisteredCodeQLProviderError(
                "REGISTERED_CODEQL_DATABASE_INVALID"
            ) from None
        if registered is None:
            raise RegisteredCodeQLProviderError("REGISTERED_CODEQL_DATABASE_NOT_FOUND")
        try:
            registry = self._config.database_registry_root.resolve(strict=True)
            expected_root = registry / registered.artifact_key / "database"
        except OSError:
            raise RegisteredCodeQLProviderError(
                "REGISTERED_CODEQL_REGISTRY_INVALID"
            ) from None
        if (
            registered.database_root != expected_root
            or registered.identity != identity
            or registered.artifact_key != identity.artifact_key
        ):
            raise RegisteredCodeQLProviderError("REGISTERED_CODEQL_DATABASE_INVALID")
        return registered


__all__ = [
    "CodeQLLanguage",
    "RegisteredCodeQLDatabase",
    "RegisteredCodeQLDatabaseProvider",
    "RegisteredCodeQLProviderError",
]
