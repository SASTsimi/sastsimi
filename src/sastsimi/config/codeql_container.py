"""Secret-free runtime configuration for an approved CodeQL container."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Self

from pydantic import field_validator, model_validator

from sastsimi.contracts.base import ContractModel, PositiveInt, Sha256

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_COMPONENT = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_IMAGE_REGISTRY = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?$")
_EXACT_CODEQL_VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
_PROVIDER_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class CodeQLContainerRuntimeConfig(ContractModel):
    """Pinned, resource-bounded inputs for one Docker CodeQL backend.

    Every field is safe to store in TOML. Credentials, tokens, session data,
    environment inheritance, mounts, and network policy deliberately do not
    belong to this model.
    """

    schema_version: Literal[1]
    image: str
    expected_codeql_version: str
    database_registry_root: Path
    query_pack_root: Path
    query_pack_sha256: Sha256
    database_provider_key: str
    database_provider_revision: str
    database_provider_evidence_sha256: Sha256
    database_limit_bytes: PositiveInt
    output_limit_bytes: PositiveInt
    pids_limit: PositiveInt
    memory_limit_bytes: PositiveInt
    nano_cpus: PositiveInt
    container_uid: PositiveInt
    container_gid: PositiveInt

    @field_validator("image")
    @classmethod
    def digest_pinned_image(cls, value: str) -> str:
        if (
            value != value.strip()
            or any(ord(character) < 32 for character in value)
            or value.count("@") != 1
        ):
            raise ValueError("CODEQL_CONTAINER_IMAGE_INVALID")
        name, digest = value.split("@", 1)
        components = name.split("/")
        if (
            not name
            or name.startswith("/")
            or name.endswith("/")
            or "\\" in name
            or "://" in name
            or _IMAGE_DIGEST.fullmatch(digest) is None
            or any(component in {"", ".", ".."} for component in components)
            or ":" in components[-1]
        ):
            raise ValueError("CODEQL_CONTAINER_IMAGE_INVALID")
        if len(components) > 1:
            if _IMAGE_REGISTRY.fullmatch(components[0]) is None:
                raise ValueError("CODEQL_CONTAINER_IMAGE_INVALID")
            components = components[1:]
        if any(
            _IMAGE_COMPONENT.fullmatch(component) is None for component in components
        ):
            raise ValueError("CODEQL_CONTAINER_IMAGE_INVALID")
        return value

    @field_validator("expected_codeql_version")
    @classmethod
    def exact_codeql_version(cls, value: str) -> str:
        if _EXACT_CODEQL_VERSION.fullmatch(value) is None:
            raise ValueError("CODEQL_VERSION_INVALID")
        return value

    @field_validator("database_registry_root", "query_pack_root", mode="before")
    @classmethod
    def absolute_non_root_path(cls, value: object) -> Path:
        if not isinstance(value, (str, Path)):
            raise ValueError("CODEQL_CONTAINER_PATH_INVALID")
        text = str(value)
        path = Path(value)
        if (
            not text
            or text != text.strip()
            or any(ord(character) < 32 for character in text)
            or ".." in path.parts
            or not path.is_absolute()
            or path.parent == path
        ):
            raise ValueError("CODEQL_CONTAINER_PATH_INVALID")
        return path

    @field_validator("database_provider_key", "database_provider_revision")
    @classmethod
    def safe_provider_identity(cls, value: str) -> str:
        if _PROVIDER_IDENTITY.fullmatch(value) is None:
            raise ValueError("CODEQL_PROVIDER_IDENTITY_INVALID")
        return value

    @model_validator(mode="after")
    def disjoint_roots(self) -> Self:
        registry = self.database_registry_root.resolve(strict=False)
        query_pack = self.query_pack_root.resolve(strict=False)
        if (
            registry == query_pack
            or registry in query_pack.parents
            or query_pack in registry.parents
        ):
            raise ValueError("CODEQL_CONTAINER_PATHS_OVERLAP")
        return self

    @property
    def container_user(self) -> str:
        """Return Docker's numeric, explicitly non-root ``uid:gid`` value."""

        return f"{self.container_uid}:{self.container_gid}"


__all__ = ["CodeQLContainerRuntimeConfig"]
