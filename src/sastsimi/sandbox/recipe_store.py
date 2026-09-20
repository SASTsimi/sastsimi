"""Immutable, code-scoped environment recipe bindings."""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, runtime_checkable
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
    DependencyBundle,
    EnvironmentRecipe,
    EnvironmentRecipeSourceManifest,
    EnvironmentRequirements,
)
from sastsimi.contracts.ids import LogicalRecordId, RecordId, StoredDataId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import RepositoryProfile, RepositoryTrackedFile
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dynamic_sandbox import PreparedRecipeSourceView, SandboxRunSpec

_MAX_RECIPE_INPUT_BYTES = 4 * 1024 * 1024
_MAX_BUILD_CONTEXT_BYTES = 64 * 1024 * 1024
_MAX_DEPENDENCY_BUNDLE_FILES = 20_000
_DEPENDENCY_PREFIX = ".sastsimi/dependencies"
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
_SAFE_RUNTIME_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){0,2}$")
_SECRET_FILE_NAMES = frozenset(
    {
        ".npmrc",
        ".pypirc",
        ".netrc",
        "credentials.json",
        "gradle.properties",
        "id_dsa",
        "id_ed25519",
        "id_rsa",
        "service-account.json",
        "settings.xml",
    }
)
_DEPENDENCY_INPUT_KINDS = frozenset(
    {
        "REQUIREMENTS",
        "PYPROJECT",
        "PACKAGE_JSON",
        "PACKAGE_LOCK",
        "YARN_LOCK",
        "PNPM_LOCK",
        "PYTHON_LOCK",
        "PIPFILE",
    }
)


def dependency_input_hash(profile: RepositoryProfile) -> str:
    """Hash exact tracked dependency declarations selected from a profile."""

    paths = {
        item.path
        for item in profile.config_files
        if item.kind in _DEPENDENCY_INPUT_KINDS
    }
    selected = tuple(
        item.model_dump(mode="python")
        for item in profile.tracked_files
        if item.git_path in paths
    )
    return content_hash(selected)


class RecipeDockerPort(Protocol):
    async def build(
        self,
        dockerfile: bytes,
        labels: Mapping[str, str],
        *,
        spec: SandboxRunSpec,
        timeout_ms: int,
    ) -> str: ...
    async def inspect_image(self, image: str, *, timeout_ms: int) -> str: ...


@runtime_checkable
class RecipeContextDockerPort(Protocol):
    async def build_context(
        self,
        context_archive: bytes,
        dockerfile_path: str,
        labels: Mapping[str, str],
        *,
        spec: SandboxRunSpec,
        timeout_ms: int,
    ) -> str: ...


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
    repository_profile_ref: StoredDataRef | None = None
    dependency_bundle_ref: StoredDataRef | None = None
    dependency_manifest_path: str | None = None
    dockerfile_origin: Literal["REPOSITORY", "GENERATED"] = "REPOSITORY"
    dockerfile_path: str = "Dockerfile"
    context_archive: bytes | None = None
    context_digest: str | None = None
    source_manifest: EnvironmentRecipeSourceManifest | None = None

    def __post_init__(self) -> None:
        content = EnvironmentRecipeStore._validated_dockerfile(
            self.dockerfile,
            allow_context_copy=self.context_archive is not None,
        )
        if (
            not _SHA256.fullmatch(self.source_digest)
            or self.recipe_source_ref.data_kind != "recipe_source"
            or self.recipe_source_ref.content_hash != self.source_digest
            or hashlib.sha256(self.dockerfile).hexdigest() != self.dockerfile_digest
            or not _SHA256.fullmatch(self.dockerfile_digest)
            or EnvironmentRecipeStore._base_image(content) != self.base_image
        ):
            raise ValueError("RECIPE_SOURCE_BINDING_INVALID")
        if self.context_archive is None:
            if (
                self.context_digest is not None
                or self.repository_profile_ref is not None
                or self.dependency_bundle_ref is not None
                or self.dependency_manifest_path is not None
                or self.dockerfile_origin != "REPOSITORY"
                or self.dockerfile_path != "Dockerfile"
                or self.source_manifest is not None
            ):
                raise ValueError("RECIPE_CONTEXT_BINDING_INVALID")
        elif (
            self.repository_profile_ref is None
            or self.repository_profile_ref.data_kind != "repository_profile"
            or self.repository_profile_ref.record_id is None
            or self.context_digest is None
            or hashlib.sha256(self.context_archive).hexdigest() != self.context_digest
            or self.repository_profile_ref not in self.source_refs
            or self.source_refs[:1] != (self.repository_profile_ref,)
            or len(self.source_refs)
            != (4 if self.dependency_bundle_ref is not None else 3)
            or any(
                ref.data_kind != "artifact"
                for ref in self.source_refs[
                    2 if self.dependency_bundle_ref is not None else 1 :
                ]
            )
            or {self.dockerfile_digest, self.context_digest}
            != {
                ref.content_hash
                for ref in self.source_refs[
                    2 if self.dependency_bundle_ref is not None else 1 :
                ]
            }
            or self.dockerfile_path.startswith("/")
            or ".." in PurePosixPath(self.dockerfile_path).parts
            or self.source_manifest is None
            or (
                self.dependency_bundle_ref is not None
                and self.dependency_manifest_path is None
            )
        ):
            raise ValueError("RECIPE_CONTEXT_BINDING_INVALID")
        if self.source_manifest is not None and (
            self.source_manifest.repository_profile_ref != self.repository_profile_ref
            or self.source_manifest.dependency_bundle_ref != self.dependency_bundle_ref
            or self.source_manifest.dockerfile_digest != self.dockerfile_digest
            or self.source_manifest.context_digest != self.context_digest
            or self.source_manifest.dockerfile_path != self.dockerfile_path
            or self.source_manifest.dockerfile_origin != self.dockerfile_origin
            or self.source_manifest.dependency_manifest_path
            != self.dependency_manifest_path
            or set(
                (
                    self.source_manifest.repository_profile_ref,
                    self.source_manifest.dockerfile_ref,
                    self.source_manifest.build_context_ref,
                    *(
                        (self.source_manifest.dependency_bundle_ref,)
                        if self.source_manifest.dependency_bundle_ref is not None
                        else ()
                    ),
                )
            )
            != set(self.source_refs)
        ):
            raise ValueError("RECIPE_SOURCE_MANIFEST_MISMATCH")
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

    def __init__(
        self,
        *,
        artifacts: ArtifactStore | None = None,
        allow_repository_build_network: bool = False,
    ) -> None:
        self._baselines: dict[tuple[str, str, str], EnvironmentRecipe] = {}
        self._lock = asyncio.Lock()
        self._artifacts = artifacts
        self._allow_repository_build_network = allow_repository_build_network

    def preflight(
        self,
        *,
        context: Path,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
        repository_profile: RepositoryProfile | None = None,
        dependency_bundle: DependencyBundle | None = None,
    ) -> PreparedRecipeSource:
        """Parse and hash local files without contacting the Docker daemon."""

        if repository_profile is not None:
            return self._repository_source(
                context=context,
                request_ref=request_ref,
                requirements=requirements,
                repository_profile=repository_profile,
                dependency_bundle=dependency_bundle,
                meta=meta,
            )
        if dependency_bundle is not None:
            raise ValueError("DEPENDENCY_BUNDLE_REPOSITORY_PROFILE_REQUIRED")

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
        source: PreparedRecipeSourceView,
        labels: Mapping[str, str],
        build_spec: SandboxRunSpec,
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
                    source_manifest=baseline.source_manifest,
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
            if source.context_archive is None:
                built_digest = await docker.build(
                    trusted_dockerfile,
                    labels,
                    spec=build_spec,
                    timeout_ms=build_timeout_ms,
                )
            else:
                if not isinstance(docker, RecipeContextDockerPort):
                    raise ValueError("DOCKER_CONTEXT_BUILD_UNSUPPORTED")
                archive = self._replace_archive_file(
                    source.context_archive,
                    source.dockerfile_path,
                    trusted_dockerfile,
                )
                built_digest = await docker.build_context(
                    archive,
                    source.dockerfile_path,
                    labels,
                    spec=build_spec,
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
                source_manifest=source.source_manifest,
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
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> EnvironmentRecipe:
        requirements_ref = reference(requirements)
        if not isinstance(requirements_ref, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        if (
            baseline.meta.analysis_id != meta.analysis_id
            or baseline.meta.workspace_id != meta.workspace_id
            or baseline.meta.commit_id != meta.commit_id
            or request_ref.workspace_id != meta.workspace_id
            or request_ref.commit_id != meta.commit_id
            or requirements.request_ref != request_ref
            or requirements.meta.analysis_id != meta.analysis_id
            or requirements.meta.workspace_id != meta.workspace_id
            or requirements.meta.commit_id != meta.commit_id
        ):
            raise ValueError("BASELINE_RECIPE_SCOPE_MISMATCH")
        return EnvironmentRecipe(
            meta=fresh_record_meta(meta, "environment_recipe"),
            request_ref=request_ref,
            environment_requirements_ref=requirements_ref,
            recipe_source_ref=baseline.recipe_source_ref,
            source_refs=baseline.source_refs,
            base_image_digest=baseline.base_image_digest,
            built_image_digest=baseline.built_image_digest,
            baseline_recipe_ref=self._exact_ref(baseline),
            build_disposition="REUSED",
            source_manifest=baseline.source_manifest,
            created_at=meta.created_at,
        )

    def restore_source(
        self,
        recipe: EnvironmentRecipe,
        *,
        workspace_root: Path,
    ) -> PreparedRecipeSource:
        """Restore exact build inputs from a persisted recipe after restart."""

        manifest = recipe.source_manifest
        if manifest is None or self._artifacts is None:
            raise ValueError("RECIPE_SOURCE_MANIFEST_REQUIRED")
        with self._artifacts.open_verified(manifest.dockerfile_ref) as stream:
            dockerfile = stream.read()
        with self._artifacts.open_verified(manifest.build_context_ref) as stream:
            context_archive = stream.read()
        if (
            hashlib.sha256(dockerfile).hexdigest() != manifest.dockerfile_digest
            or hashlib.sha256(context_archive).hexdigest() != manifest.context_digest
        ):
            raise ValueError("RECIPE_SOURCE_MANIFEST_MISMATCH")
        self._replace_archive_file(
            context_archive,
            manifest.dockerfile_path,
            dockerfile,
        )
        return PreparedRecipeSource(
            workspace_root=workspace_root.resolve(strict=False),
            request_ref=recipe.request_ref,
            requirements_ref=recipe.environment_requirements_ref,
            meta=recipe.meta,
            recipe_source_ref=recipe.recipe_source_ref,
            source_refs=recipe.source_refs,
            source_digest=recipe.recipe_source_ref.content_hash,
            dockerfile=dockerfile,
            dockerfile_digest=manifest.dockerfile_digest,
            base_image=self._base_image(dockerfile.decode("utf-8")),
            repository_profile_ref=manifest.repository_profile_ref,
            dependency_bundle_ref=manifest.dependency_bundle_ref,
            dependency_manifest_path=manifest.dependency_manifest_path,
            dockerfile_origin=manifest.dockerfile_origin,
            dockerfile_path=manifest.dockerfile_path,
            context_archive=context_archive,
            context_digest=manifest.context_digest,
            source_manifest=manifest,
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
    def _validated_dockerfile(
        dockerfile: bytes,
        *,
        allow_context_copy: bool = False,
    ) -> str:
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
            if denied == "ADD" or (denied == "COPY" and not allow_context_copy):
                raise ValueError(f"DOCKERFILE_{denied}_DENIED")
            if denied == "COPY" and "--from" in stripped.casefold():
                raise ValueError("DOCKERFILE_EXTERNAL_COPY_DENIED")
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
        try:
            context_details = context.lstat()
            if (
                context.is_symlink()
                or not root.is_dir()
                or getattr(context_details, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError
        except (OSError, ValueError) as error:
            raise ValueError("REPOSITORY_MANIFEST_MISMATCH") from error
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

    def _repository_source(
        self,
        *,
        context: Path,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        repository_profile: RepositoryProfile,
        dependency_bundle: DependencyBundle | None,
        meta: RecordMeta,
    ) -> PreparedRecipeSource:
        root = context.resolve(strict=True)
        profile_ref = reference(repository_profile)
        if not isinstance(profile_ref, StoredDataRef):
            raise ValueError("REPOSITORY_PROFILE_REFERENCE_INVALID")
        expected_manifest = content_hash(
            tuple(
                item.model_dump(mode="python")
                for item in repository_profile.tracked_files
            )
        )
        if (
            repository_profile.status != "READY"
            or repository_profile.manifest_hash != expected_manifest
            or repository_profile.workspace_id != meta.workspace_id
            or repository_profile.commit_id != meta.commit_id
            or repository_profile.meta.analysis_id != meta.analysis_id
            or repository_profile.meta.workspace_id != meta.workspace_id
            or repository_profile.meta.commit_id != meta.commit_id
            or meta.hypothesis_id is None
            or meta.attempt_id is None
        ):
            raise ValueError("REPOSITORY_PROFILE_SCOPE_MISMATCH")

        all_entries: dict[str, tuple[bytes, int]] = {}
        source_refs: list[StoredDataRef] = [profile_ref]
        total = 0
        for item in repository_profile.tracked_files:
            raw = self._read_profile_file(root, item)
            total += len(raw)
            if total > _MAX_BUILD_CONTEXT_BYTES:
                raise ValueError("RECIPE_BUILD_CONTEXT_LIMIT_EXCEEDED")
            all_entries[item.git_path] = (
                raw,
                0o755 if item.git_mode == "100755" else 0o644,
            )

        ignore_patterns = self._dockerignore_patterns(all_entries)
        dockerfiles = {
            item.path
            for item in repository_profile.config_files
            if item.kind == "DOCKERFILE"
        }
        entries: dict[str, tuple[bytes, int]] = {}
        for path, value in all_entries.items():
            ignored = path not in dockerfiles and self._dockerignored(
                path, ignore_patterns
            )
            if ignored:
                continue
            if self._looks_secret(path):
                raise ValueError("REPOSITORY_SECRET_FILE_DENIED")
            entries[path] = value

        bundle_ref: StoredDataRef | None = None
        if dependency_bundle is not None:
            bundle_entries, bundle_ref = self._dependency_bundle_entries(
                bundle=dependency_bundle,
                repository_profile=repository_profile,
                profile_ref=profile_ref,
                request_ref=request_ref,
                meta=meta,
            )
            if any(
                path == _DEPENDENCY_PREFIX or path.startswith(f"{_DEPENDENCY_PREFIX}/")
                for path in entries
            ):
                raise ValueError("DEPENDENCY_BUNDLE_CONTEXT_COLLISION")
            entries.update(bundle_entries)
            source_refs.append(bundle_ref)

        if (
            sum(len(content) for content, _mode in entries.values())
            > _MAX_BUILD_CONTEXT_BYTES
        ):
            raise ValueError("RECIPE_BUILD_CONTEXT_LIMIT_EXCEEDED")

        dockerfile_path, dockerfile, origin, dependency_manifest_path = (
            self._select_dockerfile(
                entries,
                repository_profile,
                requirements,
                dependency_bundle,
            )
        )
        dockerfile = self._validated_dockerfile(
            dockerfile,
            allow_context_copy=True,
        ).encode("utf-8")
        entries[dockerfile_path] = (dockerfile, 0o644)
        archive = self._archive(entries)
        if self._artifacts is None:
            raise ValueError("RECIPE_ARTIFACT_STORE_REQUIRED")
        dockerfile_ref = self._artifacts.commit(
            self._artifacts.stage_bytes(dockerfile, "text/x-dockerfile")
        )
        context_ref = self._artifacts.commit(
            self._artifacts.stage_bytes(archive, "application/x-tar")
        )
        if any(
            (ref.workspace_id, ref.commit_id) != (meta.workspace_id, meta.commit_id)
            for ref in (dockerfile_ref, context_ref)
        ):
            raise ValueError("RECIPE_ARTIFACT_SCOPE_MISMATCH")
        source_refs.extend((dockerfile_ref, context_ref))
        parts = tuple(
            (path, hashlib.sha256(raw).hexdigest())
            for path, (raw, _) in sorted(entries.items())
        )
        source_digest = hashlib.sha256(
            canonical_bytes((profile_ref, bundle_ref, parts))
        ).hexdigest()
        requirements_ref = reference(requirements)
        if not isinstance(requirements_ref, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        recipe_source_ref = StoredDataRef(
            stored_data_id=StoredDataId(f"recipe-source-{source_digest}"),
            data_kind="recipe_source",
            content_hash=source_digest,
            workspace_id=meta.workspace_id,
            commit_id=meta.commit_id,
            record_id=None,
        )
        source_manifest = EnvironmentRecipeSourceManifest(
            repository_profile_ref=profile_ref,
            dockerfile_ref=dockerfile_ref,
            build_context_ref=context_ref,
            dockerfile_path=dockerfile_path,
            dockerfile_origin=origin,
            dockerfile_digest=hashlib.sha256(dockerfile).hexdigest(),
            context_digest=hashlib.sha256(archive).hexdigest(),
            dependency_bundle_ref=bundle_ref,
            dependency_manifest_path=dependency_manifest_path,
        )
        return PreparedRecipeSource(
            workspace_root=root,
            request_ref=request_ref,
            requirements_ref=requirements_ref,
            meta=meta,
            recipe_source_ref=recipe_source_ref,
            source_refs=tuple(source_refs),
            source_digest=source_digest,
            dockerfile=dockerfile,
            dockerfile_digest=hashlib.sha256(dockerfile).hexdigest(),
            base_image=self._base_image(dockerfile.decode("utf-8")),
            repository_profile_ref=profile_ref,
            dependency_bundle_ref=bundle_ref,
            dependency_manifest_path=dependency_manifest_path,
            dockerfile_origin=origin,
            dockerfile_path=dockerfile_path,
            context_archive=archive,
            context_digest=hashlib.sha256(archive).hexdigest(),
            source_manifest=source_manifest,
        )

    def _dependency_bundle_entries(
        self,
        *,
        bundle: DependencyBundle,
        repository_profile: RepositoryProfile,
        profile_ref: StoredDataRef,
        request_ref: StoredDataRef,
        meta: RecordMeta,
    ) -> tuple[dict[str, tuple[bytes, int]], StoredDataRef]:
        if self._artifacts is None:
            raise ValueError("RECIPE_ARTIFACT_STORE_REQUIRED")
        if (
            bundle.request_ref != request_ref
            or bundle.repository_profile_ref != profile_ref
            or bundle.dependency_input_hash != dependency_input_hash(repository_profile)
            or (
                bundle.meta.analysis_id,
                bundle.meta.workspace_id,
                bundle.meta.commit_id,
                bundle.meta.hypothesis_id,
                bundle.meta.attempt_id,
            )
            != (
                meta.analysis_id,
                meta.workspace_id,
                meta.commit_id,
                meta.hypothesis_id,
                meta.attempt_id,
            )
        ):
            raise ValueError("DEPENDENCY_BUNDLE_INPUT_MISMATCH")
        bundle_ref = reference(bundle)
        if not isinstance(bundle_ref, StoredDataRef):
            raise ValueError("DEPENDENCY_BUNDLE_REFERENCE_INVALID")
        try:
            with self._artifacts.open_verified(bundle.archive_ref) as stream:
                archive_bytes = stream.read(_MAX_BUILD_CONTEXT_BYTES + 1)
        except Exception as error:
            raise ValueError("DEPENDENCY_BUNDLE_ARTIFACT_UNAVAILABLE") from error
        if (
            len(archive_bytes) > _MAX_BUILD_CONTEXT_BYTES
            or hashlib.sha256(archive_bytes).hexdigest() != bundle.archive_digest
        ):
            raise ValueError("DEPENDENCY_BUNDLE_DIGEST_MISMATCH")
        entries: dict[str, tuple[bytes, int]] = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
                members = archive.getmembers()
                if not members or len(members) > _MAX_DEPENDENCY_BUNDLE_FILES:
                    raise ValueError
                total = 0
                for member in members:
                    path = member.name.replace("\\", "/")
                    parts = PurePosixPath(path).parts
                    if (
                        not member.isfile()
                        or path.startswith("/")
                        or re.match(r"^[A-Za-z]:", path)
                        or any(part in {"", ".", ".."} for part in parts)
                        or path in entries
                        or self._looks_secret(path)
                        or not self._valid_dependency_path(bundle.ecosystem, path)
                    ):
                        raise ValueError
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ValueError
                    raw = extracted.read(member.size + 1)
                    if len(raw) != member.size:
                        raise ValueError
                    total += len(raw)
                    if total > _MAX_BUILD_CONTEXT_BYTES:
                        raise ValueError
                    prefix = (
                        f"{_DEPENDENCY_PREFIX}/python"
                        if bundle.ecosystem == "PYTHON_WHEELS"
                        else f"{_DEPENDENCY_PREFIX}/npm"
                    )
                    entries[f"{prefix}/{path}"] = (raw, 0o644)
        except (tarfile.TarError, ValueError, OSError) as error:
            raise ValueError("DEPENDENCY_BUNDLE_ARCHIVE_INVALID") from error
        return entries, bundle_ref

    @staticmethod
    def _valid_dependency_path(ecosystem: str, path: str) -> bool:
        if ecosystem == "PYTHON_WHEELS":
            return "/" not in path and path.casefold().endswith(".whl")
        return path.startswith("_cacache/")

    @staticmethod
    def _looks_secret(path: str) -> bool:
        pure = PurePosixPath(path.casefold())
        name = pure.name
        parts = pure.parts
        return (
            name == ".env"
            or name.startswith(".env.")
            or name in _SECRET_FILE_NAMES
            or PurePosixPath(name).suffix in {".key", ".p12", ".pem", ".pfx"}
            or any(
                parts[index : index + 2]
                in {
                    (".aws", "credentials"),
                    (".docker", "config.json"),
                }
                for index in range(max(0, len(parts) - 1))
            )
        )

    @staticmethod
    def _dockerignore_patterns(
        entries: Mapping[str, tuple[bytes, int]],
    ) -> tuple[str, ...]:
        value = entries.get(".dockerignore")
        if value is None:
            return ()
        try:
            content = value[0].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("DOCKERIGNORE_UNSUPPORTED") from error
        patterns: list[str] = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if (
                line.startswith("!")
                or "\\" in line
                or "\0" in line
                or ".." in PurePosixPath(line.lstrip("/")).parts
                or "**" in line
                or any(character in line for character in "?[]")
            ):
                raise ValueError("DOCKERIGNORE_UNSUPPORTED")
            normalized = line.removeprefix("/").removeprefix("./")
            if not normalized:
                raise ValueError("DOCKERIGNORE_UNSUPPORTED")
            patterns.append(normalized)
        return tuple(patterns)

    @staticmethod
    def _dockerignored(path: str, patterns: tuple[str, ...]) -> bool:
        parts = PurePosixPath(path).parts
        for pattern in patterns:
            if pattern.endswith("/"):
                prefix = pattern.rstrip("/")
                if path == prefix or path.startswith(prefix + "/"):
                    return True
            elif "/" in pattern:
                if fnmatch.fnmatchcase(path, pattern):
                    return True
            elif any(fnmatch.fnmatchcase(part, pattern) for part in parts):
                return True
        return False

    @staticmethod
    def _read_profile_file(root: Path, item: RepositoryTrackedFile) -> bytes:
        target = root.joinpath(*item.git_path.split("/"))
        descriptor = -1
        try:
            target.resolve(strict=True).relative_to(root)
            before = target.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != item.size_bytes
                or getattr(before, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError
            flags = (
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(target, flags)
            opened = os.fstat(descriptor)
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_nlink,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_nlink,
            ):
                raise ValueError
            chunks: list[bytes] = []
            remaining = item.size_bytes
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    raise ValueError
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ValueError
            after = target.lstat()
            if (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_nlink,
            ) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_nlink,
            ):
                raise ValueError
            raw = b"".join(chunks)
            framed = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
            digest = hashlib.sha1 if len(item.blob_id) == 40 else hashlib.sha256
            if digest(framed).hexdigest() != item.blob_id:
                raise ValueError
        except (OSError, ValueError) as error:
            raise ValueError("REPOSITORY_MANIFEST_MISMATCH") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return raw

    def _select_dockerfile(
        self,
        entries: Mapping[str, tuple[bytes, int]],
        profile: RepositoryProfile,
        requirements: EnvironmentRequirements,
        dependency_bundle: DependencyBundle | None,
    ) -> tuple[str, bytes, Literal["REPOSITORY", "GENERATED"], str | None]:
        candidates = tuple(
            item.path for item in profile.config_files if item.kind == "DOCKERFILE"
        )
        if candidates:
            selected = "Dockerfile" if "Dockerfile" in candidates else candidates[0]
            if len(candidates) > 1 and "Dockerfile" not in candidates:
                raise ValueError("DOCKERFILE_SELECTION_CONFIRMATION_REQUIRED")
            try:
                dockerfile = entries[selected][0]
            except KeyError as error:
                raise ValueError("REPOSITORY_MANIFEST_MISMATCH") from error
            family = self._repository_family(
                profile,
                requirements=requirements,
                dockerfile=dockerfile,
            )
            self._validate_dependency_bundle_family(dependency_bundle, family)
            dependency_manifest_path = self._dependency_manifest_path(
                entries,
                profile,
                family,
                dockerfile=dockerfile,
            )
            if dependency_bundle is not None:
                self._dependency_install(
                    entries,
                    profile,
                    family,
                    dependency_bundle,
                    dependency_manifest_path=dependency_manifest_path,
                )
                dockerfile = self._inject_offline_dependency_environment(
                    dockerfile,
                    family,
                )
            elif not self._allow_repository_build_network:
                self._dependency_install(
                    entries,
                    profile,
                    family,
                    None,
                    dependency_manifest_path=dependency_manifest_path,
                )
            else:
                dockerfile = self._repair_archived_debian_sources(dockerfile)
            dockerfile = self._ensure_runtime_workspace(dockerfile)
            return selected, dockerfile, "REPOSITORY", dependency_manifest_path

        family = self._repository_family(
            profile,
            requirements=requirements,
            dockerfile=None,
        )
        self._validate_dependency_bundle_family(dependency_bundle, family)
        dependency_manifest_path = self._dependency_manifest_path(
            entries,
            profile,
            family,
            dockerfile=None,
        )
        version = self._runtime_version(requirements, family)
        if version is None:
            raise ValueError("ENVIRONMENT_VERSION_CONFIRMATION_REQUIRED")
        image = (
            f"python:{version}-slim" if family == "PYTHON" else f"node:{version}-slim"
        )
        install = self._dependency_install(
            entries,
            profile,
            family,
            dependency_bundle,
            dependency_manifest_path=dependency_manifest_path,
        )
        dockerfile = (
            f"FROM {image}\n"
            "WORKDIR /workspace\n"
            "COPY . /workspace\n"
            f"{install}"
            'CMD ["sleep", "infinity"]\n'
        ).encode()
        return "Dockerfile", dockerfile, "GENERATED", dependency_manifest_path

    @staticmethod
    def _ensure_runtime_workspace(dockerfile: bytes) -> bytes:
        """Expose a repository image's source root at the runtime contract path."""

        workdirs: list[bytes] = re.findall(
            rb"(?im)^\s*WORKDIR\s+([^\s#]+)\s*$", dockerfile
        )
        if not workdirs:
            copies_to_workspace = re.search(
                rb"(?im)^\s*(?:COPY|ADD)\s+(?:--[^\s]+\s+)*.+\s+/workspace/?\s*$",
                dockerfile,
            )
            if copies_to_workspace is not None:
                return dockerfile.rstrip() + b"\nWORKDIR /workspace\n"
            raise ValueError("DOCKERFILE_WORKDIR_CONFIRMATION_REQUIRED")
        source = workdirs[-1]
        if source == b"/workspace":
            return dockerfile
        if re.fullmatch(rb"/[A-Za-z0-9._/-]+", source) is None:
            raise ValueError("DOCKERFILE_WORKDIR_CONFIRMATION_REQUIRED")
        return (
            dockerfile.rstrip()
            + b"\n\n# SASTSIMI runtime contract: expose baked source at /workspace.\n"
            + b"USER root\n"
            + b"RUN test -d "
            + source
            + b" && test ! -e /workspace && ln -s "
            + source
            + b" /workspace\n"
            + b"WORKDIR /workspace\n"
        )

    @staticmethod
    def _repair_archived_debian_sources(dockerfile: bytes) -> bytes:
        """Keep an opted-in legacy repository recipe buildable without editing code."""

        if (
            b"archive.debian.org/debian" in dockerfile
            or re.search(rb"(?im)^FROM\s+\S*buster(?:\s+AS\s+\S+)?\s*$", dockerfile)
            is None
            or b"apt-get" not in dockerfile
        ):
            return dockerfile
        lines = dockerfile.splitlines(keepends=True)
        marker = (
            b"RUN sed -i "
            b"-e 's|deb.debian.org/debian|archive.debian.org/debian|g' "
            b"-e 's|security.debian.org/debian-security|"
            b"archive.debian.org/debian-security|g' "
            b"-e '/buster-updates/d' /etc/apt/sources.list "
            b"&& printf 'Acquire::Check-Valid-Until \"false\";\\n' "
            b"> /etc/apt/apt.conf.d/99sastsimi-archive\n"
        )
        for index, line in enumerate(lines):
            if line.lstrip().upper().startswith(b"FROM "):
                lines.insert(index + 1, marker)
                return b"".join(lines)
        return dockerfile

    @staticmethod
    def _dependency_install(
        entries: Mapping[str, tuple[bytes, int]],
        profile: RepositoryProfile,
        family: Literal["PYTHON", "NODE"],
        dependency_bundle: DependencyBundle | None,
        *,
        dependency_manifest_path: str | None,
    ) -> str:
        if family == "PYTHON":
            if dependency_manifest_path is not None:
                kind_by_path = {item.path: item.kind for item in profile.config_files}
                kind = kind_by_path.get(dependency_manifest_path)
                if kind == "REQUIREMENTS":
                    if entries[dependency_manifest_path][0].strip():
                        if dependency_bundle is None:
                            raise ValueError("DEPENDENCY_SUPPLY_CONFIRMATION_REQUIRED")
                        return (
                            "COPY .sastsimi/dependencies/python/ "
                            "/opt/sastsimi-dependencies/python/\n"
                            "RUN python -m pip install --no-index "
                            "--find-links=/opt/sastsimi-dependencies/python "
                            f"-r {dependency_manifest_path}\n"
                        )
                    if dependency_bundle is not None:
                        raise ValueError("DEPENDENCY_BUNDLE_NOT_REQUIRED")
                    return ""
                if kind != "PYPROJECT":
                    raise ValueError("DEPENDENCY_FILE_CONFIRMATION_REQUIRED")
                try:
                    project = tomllib.loads(
                        entries[dependency_manifest_path][0].decode("utf-8")
                    )
                except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
                    raise ValueError("DEPENDENCY_FILE_CONFIRMATION_REQUIRED") from error
                declared = project.get("project", {}).get("dependencies", ())
                build_requires = project.get("build-system", {}).get("requires", ())
                if declared or build_requires:
                    if dependency_bundle is None:
                        raise ValueError("DEPENDENCY_SUPPLY_CONFIRMATION_REQUIRED")
                    return (
                        "COPY .sastsimi/dependencies/python/ "
                        "/opt/sastsimi-dependencies/python/\n"
                        "RUN python -m pip install --no-index "
                        "--find-links=/opt/sastsimi-dependencies/python .\n"
                    )
                if dependency_bundle is not None:
                    raise ValueError("DEPENDENCY_BUNDLE_NOT_REQUIRED")
                return ""
            if dependency_bundle is not None:
                raise ValueError("DEPENDENCY_BUNDLE_NOT_REQUIRED")
            return ""

        if dependency_manifest_path is None:
            if dependency_bundle is not None:
                raise ValueError("DEPENDENCY_BUNDLE_NOT_REQUIRED")
            return ""
        try:
            package = json.loads(entries[dependency_manifest_path][0])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("DEPENDENCY_FILE_CONFIRMATION_REQUIRED") from error
        if not isinstance(package, dict):
            raise ValueError("DEPENDENCY_FILE_CONFIRMATION_REQUIRED")
        dependency_fields = (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        )
        if any(package.get(field) for field in dependency_fields) or package.get(
            "workspaces"
        ):
            if dependency_bundle is None:
                raise ValueError("DEPENDENCY_SUPPLY_CONFIRMATION_REQUIRED")
            manifest_parent = str(PurePosixPath(dependency_manifest_path).parent)
            locks = tuple(
                item.path
                for item in profile.config_files
                if item.kind == "PACKAGE_LOCK"
                and item.path in entries
                and str(PurePosixPath(item.path).parent) == manifest_parent
            )
            if len(locks) != 1:
                raise ValueError("DEPENDENCY_LOCK_CONFIRMATION_REQUIRED")
            return (
                "COPY .sastsimi/dependencies/npm/ "
                "/opt/sastsimi-dependencies/npm/\n"
                "RUN npm ci --offline --cache /opt/sastsimi-dependencies/npm "
                "--ignore-scripts\n"
            )
        if dependency_bundle is not None:
            raise ValueError("DEPENDENCY_BUNDLE_NOT_REQUIRED")
        return ""

    @classmethod
    def _repository_family(
        cls,
        profile: RepositoryProfile,
        *,
        requirements: EnvironmentRequirements,
        dockerfile: bytes | None,
    ) -> Literal["PYTHON", "NODE"]:
        required_runtime_families = {
            family
            for item in requirements.items
            if item.required and item.kind == "VERSION"
            for family in (cls._runtime_name_family(item.name),)
            if family is not None
        }
        dockerfile_families = cls._dockerfile_families(dockerfile)
        primary = required_runtime_families | dockerfile_families
        if len(primary) == 1:
            return primary.pop()
        if len(primary) > 1:
            raise ValueError("ENVIRONMENT_BUILD_CONFIRMATION_REQUIRED")

        root_manifest_families = {
            family
            for item in profile.config_files
            if "/" not in item.path
            for family in (cls._config_family(item.kind),)
            if family is not None
        }
        if len(root_manifest_families) == 1:
            return root_manifest_families.pop()
        if len(root_manifest_families) > 1:
            raise ValueError("ENVIRONMENT_BUILD_CONFIRMATION_REQUIRED")

        language_names = {item.name for item in profile.languages}
        language_families: set[Literal["PYTHON", "NODE"]] = set()
        if "PYTHON" in language_names:
            language_families.add("PYTHON")
        if language_names & {"JAVASCRIPT", "TYPESCRIPT"}:
            language_families.add("NODE")
        if len(language_families) == 1:
            return language_families.pop()
        raise ValueError("ENVIRONMENT_BUILD_CONFIRMATION_REQUIRED")

    @staticmethod
    def _runtime_name_family(name: str) -> Literal["PYTHON", "NODE"] | None:
        normalized = name.casefold()
        if normalized in {"python", "python3"}:
            return "PYTHON"
        if normalized in {"node", "nodejs"}:
            return "NODE"
        return None

    @staticmethod
    def _config_family(kind: str) -> Literal["PYTHON", "NODE"] | None:
        if kind in {"REQUIREMENTS", "PYPROJECT", "PYTHON_LOCK", "PIPFILE"}:
            return "PYTHON"
        if kind in {"PACKAGE_JSON", "PACKAGE_LOCK", "YARN_LOCK", "PNPM_LOCK"}:
            return "NODE"
        return None

    @classmethod
    def _dockerfile_families(
        cls,
        dockerfile: bytes | None,
    ) -> set[Literal["PYTHON", "NODE"]]:
        if dockerfile is None:
            return set()
        try:
            content = cls._join_continued_lines(dockerfile.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise ValueError("DOCKERFILE_INVALID_UTF8") from error
        active = "\n".join(
            line for line in content.splitlines() if not line.lstrip().startswith("#")
        ).casefold()
        families: set[Literal["PYTHON", "NODE"]] = set()
        if re.search(r"(?:^|[/\s])python(?::|@|\s)|\b(?:python3?|pip3?)\b", active):
            families.add("PYTHON")
        if re.search(r"(?:^|[/\s])node(?::|@|\s)|\b(?:node|npm|yarn|pnpm)\b", active):
            families.add("NODE")
        return families

    @classmethod
    def _dependency_manifest_path(
        cls,
        entries: Mapping[str, tuple[bytes, int]],
        profile: RepositoryProfile,
        family: Literal["PYTHON", "NODE"],
        *,
        dockerfile: bytes | None,
    ) -> str | None:
        allowed = (
            {"REQUIREMENTS", "PYPROJECT"} if family == "PYTHON" else {"PACKAGE_JSON"}
        )
        candidates = tuple(
            item.path
            for item in profile.config_files
            if item.kind in allowed and item.path in entries
        )
        if not candidates:
            return None
        if dockerfile is not None:
            try:
                content = cls._join_continued_lines(dockerfile.decode("utf-8"))
            except UnicodeDecodeError as error:
                raise ValueError("DOCKERFILE_INVALID_UTF8") from error
            active = "\n".join(
                line
                for line in content.splitlines()
                if not line.lstrip().startswith("#")
            )
            referenced = tuple(
                path
                for path in candidates
                if re.search(
                    rf"(?<![A-Za-z0-9._/-])(?:\./)?{re.escape(path)}"
                    rf"(?![A-Za-z0-9._/-])",
                    active,
                )
            )
            if len(referenced) == 1:
                return referenced[0]
            if len(referenced) > 1:
                raise ValueError("DEPENDENCY_FILE_SELECTION_CONFIRMATION_REQUIRED")
        root_candidates = tuple(path for path in candidates if "/" not in path)
        if len(root_candidates) == 1:
            return root_candidates[0]
        if len(candidates) == 1:
            return candidates[0]
        raise ValueError("DEPENDENCY_FILE_SELECTION_CONFIRMATION_REQUIRED")

    @staticmethod
    def _validate_dependency_bundle_family(
        bundle: DependencyBundle | None,
        family: Literal["PYTHON", "NODE"],
    ) -> None:
        expected = "PYTHON_WHEELS" if family == "PYTHON" else "NPM_CACHE"
        if bundle is not None and bundle.ecosystem != expected:
            raise ValueError("DEPENDENCY_BUNDLE_ECOSYSTEM_MISMATCH")

    @staticmethod
    def _inject_offline_dependency_environment(
        dockerfile: bytes,
        family: Literal["PYTHON", "NODE"],
    ) -> bytes:
        try:
            content = dockerfile.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("DOCKERFILE_INVALID_UTF8") from error
        if family == "PYTHON":
            addition = (
                "ENV PIP_NO_INDEX=1 "
                "PIP_FIND_LINKS=/opt/sastsimi-dependencies/python\n"
                "COPY .sastsimi/dependencies/python/ "
                "/opt/sastsimi-dependencies/python/\n"
            )
        else:
            addition = (
                "ENV npm_config_offline=true "
                "npm_config_cache=/opt/sastsimi-dependencies/npm "
                "npm_config_ignore_scripts=true\n"
                "COPY .sastsimi/dependencies/npm/ /opt/sastsimi-dependencies/npm/\n"
            )
        lines = content.splitlines(keepends=True)
        result: list[str] = []
        injected = False
        for line in lines:
            result.append(line)
            if line.lstrip().upper().startswith("FROM "):
                result.append(addition)
                injected = True
        if not injected:
            raise ValueError("DOCKERFILE_FROM_REQUIRED")
        return "".join(result).encode("utf-8")

    @staticmethod
    def _runtime_version(
        requirements: EnvironmentRequirements,
        family: Literal["PYTHON", "NODE"],
    ) -> str | None:
        names = {"python", "python3"} if family == "PYTHON" else {"node", "nodejs"}
        versions = {
            item.expected
            for item in requirements.items
            if item.kind == "VERSION"
            and item.name.casefold() in names
            and item.required
            and item.expected is not None
        }
        if not versions:
            return None
        if len(versions) != 1:
            raise ValueError("ENVIRONMENT_VERSION_CONFLICT")
        version = versions.pop()
        if not _SAFE_RUNTIME_VERSION.fullmatch(version):
            raise ValueError("ENVIRONMENT_VERSION_CONFIRMATION_REQUIRED")
        return ".".join(version.split(".")[:2])

    @staticmethod
    def _archive(entries: Mapping[str, tuple[bytes, int]]) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(
            fileobj=stream,
            mode="w",
            format=tarfile.PAX_FORMAT,
        ) as archive:
            for path, (raw, mode) in sorted(entries.items()):
                info = tarfile.TarInfo(path)
                info.size = len(raw)
                info.mode = mode
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info, io.BytesIO(raw))
        return stream.getvalue()

    @classmethod
    def _replace_archive_file(
        cls,
        archive_bytes: bytes,
        path: str,
        content: bytes,
    ) -> bytes:
        entries: dict[str, tuple[bytes, int]] = {}
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            for item in archive.getmembers():
                if not item.isfile():
                    raise ValueError("RECIPE_BUILD_CONTEXT_INVALID")
                extracted = archive.extractfile(item)
                if extracted is None:
                    raise ValueError("RECIPE_BUILD_CONTEXT_INVALID")
                entries[item.name] = (extracted.read(), item.mode)
        if path not in entries:
            raise ValueError("RECIPE_DOCKERFILE_MISSING")
        entries[path] = (content, entries[path][1])
        return cls._archive(entries)
