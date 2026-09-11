"""Immutable, code-scoped environment recipe bindings."""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import EnvironmentRecipe, EnvironmentRequirements
from sastsimi.contracts.ids import LogicalRecordId, RecordId, StoredDataId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference

_MAX_RECIPE_INPUT_BYTES = 4 * 1024 * 1024
_KNOWN_RECIPE_NAMES = frozenset(
    {
        "dockerfile",
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "requirements.txt",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
    }
)
_FROM = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE | re.MULTILINE)
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RecipeDockerPort(Protocol):
    async def build(
        self,
        dockerfile: bytes,
        labels: Mapping[str, str],
        *,
        timeout_ms: int,
    ) -> str: ...
    async def inspect_image(self, image: str, *, timeout_ms: int) -> str: ...


@dataclass(frozen=True, slots=True)
class PreparedRecipeSource:
    """Pure, immutable source inspection result; no Docker call has occurred."""

    workspace_root: Path
    request_ref: StoredDataRef
    requirements_ref: StoredDataRef
    meta: RecordMeta
    recipe_source_ref: StoredDataRef
    source_refs: tuple[StoredDataRef, ...]
    source_digest: str
    dockerfile: bytes
    dockerfile_digest: str
    base_image: str

    def __post_init__(self) -> None:
        content = EnvironmentRecipeStore._validated_dockerfile(self.dockerfile)
        if (
            not _SHA256.fullmatch(self.source_digest)
            or self.recipe_source_ref.data_kind != "recipe_source"
            or self.recipe_source_ref.content_hash != self.source_digest
            or hashlib.sha256(self.dockerfile).hexdigest() != self.dockerfile_digest
            or not _SHA256.fullmatch(self.dockerfile_digest)
            or EnvironmentRecipeStore._base_image(content) != self.base_image
        ):
            raise ValueError("RECIPE_SOURCE_BINDING_INVALID")
        if (
            self.recipe_source_ref.workspace_id != self.meta.workspace_id
            or self.recipe_source_ref.commit_id != self.meta.commit_id
            or any(
                ref.workspace_id != self.meta.workspace_id
                or ref.commit_id != self.meta.commit_id
                for ref in self.source_refs
            )
        ):
            raise ValueError("RECIPE_SOURCE_SCOPE_MISMATCH")


def fresh_record_meta(source: RecordMeta, kind: str) -> RecordMeta:
    """Create a runtime-owned immutable record identity in the same scope."""

    record_id = RecordId(f"{kind}-{uuid4().hex}")
    return RecordMeta.model_validate(
        source.model_dump()
        | {
            "record_id": record_id,
            "logical_record_id": LogicalRecordId(str(record_id)),
            "record_type": kind,
            "revision_number": 1,
            "previous_record_id": None,
        }
    )


class EnvironmentRecipeStore:
    """Build once per exact code-scoped recipe source and bind reuse explicitly."""

    def __init__(self) -> None:
        self._baselines: dict[tuple[str, str, str], EnvironmentRecipe] = {}
        self._lock = asyncio.Lock()

    def preflight(
        self,
        *,
        context: Path,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> PreparedRecipeSource:
        """Parse and hash local files without contacting the Docker daemon."""

        dockerfile, source_ref, source_refs, source_digest = self._source(context, meta)
        content = self._validated_dockerfile(dockerfile)
        requirements_ref = reference(requirements)
        if not isinstance(requirements_ref, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        return PreparedRecipeSource(
            workspace_root=context.resolve(strict=True),
            request_ref=request_ref,
            requirements_ref=requirements_ref,
            meta=meta,
            recipe_source_ref=source_ref,
            source_refs=source_refs,
            source_digest=source_digest,
            dockerfile=content.encode("utf-8"),
            dockerfile_digest=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            base_image=self._base_image(content),
        )

    async def build(
        self,
        *,
        docker: RecipeDockerPort,
        source: PreparedRecipeSource,
        labels: Mapping[str, str],
        build_timeout_ms: int,
    ) -> EnvironmentRecipe:
        """Resolve, pin and build only a boundary-approved source."""

        key = (
            str(source.meta.workspace_id),
            str(source.meta.commit_id),
            source.source_digest,
        )
        try:
            await asyncio.wait_for(
                self._lock.acquire(),
                timeout=build_timeout_ms / 1000,
            )
        except TimeoutError as error:
            raise ValueError("RECIPE_LOCK_TIMEOUT") from error
        try:
            baseline = self._baselines.get(key)
            if baseline is not None:
                recipe = EnvironmentRecipe(
                    meta=fresh_record_meta(source.meta, "environment_recipe"),
                    request_ref=source.request_ref,
                    environment_requirements_ref=source.requirements_ref,
                    recipe_source_ref=source.recipe_source_ref,
                    source_refs=source.source_refs,
                    base_image_digest=baseline.base_image_digest,
                    built_image_digest=baseline.built_image_digest,
                    baseline_recipe_ref=self._exact_ref(baseline),
                    build_disposition="REUSED",
                    created_at=source.meta.created_at,
                )
                return recipe

            base_digest = (
                "scratch"
                if source.base_image == "scratch"
                else await docker.inspect_image(
                    source.base_image,
                    timeout_ms=build_timeout_ms,
                )
            )
            trusted_dockerfile = self._pin_base_image(
                source.dockerfile.decode("utf-8"),
                base_image=source.base_image,
                base_digest=base_digest,
            )
            built_digest = await docker.build(
                trusted_dockerfile,
                labels,
                timeout_ms=build_timeout_ms,
            )
            if not _IMAGE_DIGEST.fullmatch(built_digest):
                raise ValueError("BUILT_IMAGE_DIGEST_INVALID")
            recipe = EnvironmentRecipe(
                meta=fresh_record_meta(source.meta, "environment_recipe"),
                request_ref=source.request_ref,
                environment_requirements_ref=source.requirements_ref,
                recipe_source_ref=source.recipe_source_ref,
                source_refs=source.source_refs,
                base_image_digest=base_digest,
                built_image_digest=built_digest,
                baseline_recipe_ref=None,
                build_disposition="BUILT",
                created_at=source.meta.created_at,
            )
            self._baselines[key] = recipe
            return recipe
        finally:
            self._lock.release()

    def bind_existing(
        self,
        *,
        baseline: EnvironmentRecipe,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> EnvironmentRecipe:
        requirements_ref = reference(requirements)
        if not isinstance(requirements_ref, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        return EnvironmentRecipe(
            meta=fresh_record_meta(meta, "environment_recipe"),
            request_ref=baseline.request_ref,
            environment_requirements_ref=requirements_ref,
            recipe_source_ref=baseline.recipe_source_ref,
            source_refs=baseline.source_refs,
            base_image_digest=baseline.base_image_digest,
            built_image_digest=baseline.built_image_digest,
            baseline_recipe_ref=self._exact_ref(baseline),
            build_disposition="REUSED",
            created_at=meta.created_at,
        )

    @staticmethod
    def _exact_ref(record: EnvironmentRecipe) -> StoredDataRef:
        result = reference(record)
        if not isinstance(result, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        return result

    @staticmethod
    def _base_image(content: str) -> str:
        match = _FROM.search(content)
        if match is None:
            raise ValueError("DOCKERFILE_BASE_IMAGE_REQUIRED")
        image = match.group(1)
        if any(character in image for character in "\r\n\0"):
            raise ValueError("DOCKERFILE_BASE_IMAGE_INVALID")
        return image

    @staticmethod
    def _pin_base_image(
        content: str,
        *,
        base_image: str,
        base_digest: str,
    ) -> bytes:
        if base_image == "scratch":
            if base_digest != "scratch":
                raise ValueError("DOCKER_IMAGE_DIGEST_INVALID")
            return content.encode("utf-8")
        if not _IMAGE_DIGEST.fullmatch(base_digest):
            raise ValueError("DOCKER_IMAGE_DIGEST_INVALID")
        match = _FROM.search(content)
        if match is None or match.group(1) != base_image:
            raise ValueError("DOCKERFILE_BASE_IMAGE_INVALID")
        repository = EnvironmentRecipeStore._image_repository(base_image)
        return (
            content[: match.start(1)]
            + f"{repository}@{base_digest}"
            + content[match.end(1) :]
        ).encode("utf-8")

    @staticmethod
    def _image_repository(image: str) -> str:
        repository = image.split("@", maxsplit=1)[0]
        last_slash = repository.rfind("/")
        last_colon = repository.rfind(":")
        if last_colon > last_slash:
            repository = repository[:last_colon]
        if not repository:
            raise ValueError("DOCKERFILE_BASE_IMAGE_INVALID")
        return repository

    @staticmethod
    def _validated_dockerfile(dockerfile: bytes) -> str:
        try:
            content = dockerfile.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("DOCKERFILE_UTF8_REQUIRED") from error
        if "\0" in content or content.startswith("\ufeff"):
            raise ValueError("DOCKERFILE_UTF8_REQUIRED")
        content = EnvironmentRecipeStore._join_continued_lines(content)
        from_count = 0
        for line in content.splitlines():
            stripped = line.lstrip(" \t")
            if not stripped:
                continue
            if stripped.startswith("#"):
                directive = stripped[1:].lstrip(" \t")
                if re.match(r"syntax[ \t]*=", directive, re.IGNORECASE):
                    raise ValueError("DOCKERFILE_REMOTE_FRONTEND_DENIED")
                continue
            parts = re.split(r"[ \t]+", stripped, maxsplit=1)
            instruction = parts[0].upper()
            if instruction == "FROM":
                from_count += 1
            if "--mount" in stripped.casefold():
                raise ValueError("DOCKERFILE_RUN_MOUNT_DENIED")
            nested = (
                re.split(r"[ \t]+", parts[1].lstrip(" \t"), maxsplit=1)[0].upper()
                if instruction == "ONBUILD" and len(parts) == 2
                else None
            )
            if instruction == "VOLUME" or nested == "VOLUME":
                raise ValueError("DOCKERFILE_VOLUME_DENIED")
            if (
                instruction == "RUN" or nested == "RUN"
            ) and "--network" in stripped.casefold():
                raise ValueError("DOCKERFILE_RUN_NETWORK_DENIED")
            denied = instruction if instruction in {"ADD", "COPY"} else nested
            if denied in {"ADD", "COPY"}:
                raise ValueError(f"DOCKERFILE_{denied}_DENIED")
        if from_count != 1:
            raise ValueError("DOCKERFILE_SINGLE_BASE_IMAGE_REQUIRED")
        return content

    @staticmethod
    def _join_continued_lines(content: str) -> str:
        escape = "\\"
        for line in content.splitlines():
            stripped = line.lstrip(" \t")
            if not stripped:
                continue
            if not stripped.startswith("#"):
                break
            directive = stripped[1:].lstrip(" \t")
            match = re.fullmatch(r"escape[ \t]*=[ \t]*([\\`])", directive, re.I)
            if match is not None:
                escape = match.group(1)

        logical: list[str] = []
        pending = ""
        for line in content.splitlines():
            without_trailing_space = line.rstrip(" \t")
            if without_trailing_space.endswith(escape):
                pending += without_trailing_space[:-1]
                continue
            logical.append(pending + line)
            pending = ""
        if pending:
            raise ValueError("DOCKERFILE_CONTINUATION_INVALID")
        return "\n".join(logical) + ("\n" if content.endswith(("\n", "\r")) else "")

    @staticmethod
    def _source(
        context: Path,
        meta: RecordMeta,
    ) -> tuple[bytes, StoredDataRef, tuple[StoredDataRef, ...], str]:
        root = context.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("RECIPE_CONTEXT_REQUIRED")
        dockerfile = root / "Dockerfile"
        if not dockerfile.is_file() or dockerfile.is_symlink():
            raise ValueError("DOCKERFILE_REQUIRED")
        files = tuple(
            sorted(
                (
                    item
                    for item in root.iterdir()
                    if item.is_file()
                    and not item.is_symlink()
                    and (
                        item.name.lower() in _KNOWN_RECIPE_NAMES
                        or item.name.lower().startswith("readme")
                    )
                ),
                key=lambda item: item.name,
            )
        )
        total = 0
        parts: list[tuple[str, str]] = []
        refs: list[StoredDataRef] = []
        dockerfile_bytes: bytes | None = None
        for path in files:
            data = path.read_bytes()
            if path == dockerfile:
                dockerfile_bytes = data
            total += len(data)
            if total > _MAX_RECIPE_INPUT_BYTES:
                raise ValueError("RECIPE_INPUT_LIMIT_EXCEEDED")
            digest = hashlib.sha256(data).hexdigest()
            parts.append((path.name, digest))
            refs.append(
                StoredDataRef(
                    stored_data_id=StoredDataId(f"recipe-input-{digest}"),
                    data_kind="recipe_input",
                    content_hash=digest,
                    workspace_id=meta.workspace_id,
                    commit_id=meta.commit_id,
                    record_id=None,
                )
            )
        source_digest = hashlib.sha256(canonical_bytes(parts)).hexdigest()
        if dockerfile_bytes is None:
            raise ValueError("DOCKERFILE_REQUIRED")
        return (
            dockerfile_bytes,
            StoredDataRef(
                stored_data_id=StoredDataId(f"recipe-source-{source_digest}"),
                data_kind="recipe_source",
                content_hash=source_digest,
                workspace_id=meta.workspace_id,
                commit_id=meta.commit_id,
                record_id=None,
            ),
            tuple(refs),
            source_digest,
        )
