"""Immutable, code-scoped environment recipe bindings."""

from __future__ import annotations

import asyncio
import hashlib
import io
import os
import re
import stat
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, runtime_checkable
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import EnvironmentRecipe, EnvironmentRequirements
from sastsimi.contracts.ids import LogicalRecordId, RecordId, StoredDataId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import RepositoryProfile, RepositoryTrackedFile
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dynamic_sandbox import PreparedRecipeSourceView

_MAX_RECIPE_INPUT_BYTES = 4 * 1024 * 1024
_MAX_BUILD_CONTEXT_BYTES = 64 * 1024 * 1024
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
        "credentials.json",
        "id_dsa",
        "id_ed25519",
        "id_rsa",
        "service-account.json",
    }
)


class RecipeDockerPort(Protocol):
    async def build(
        self,
        dockerfile: bytes,
        labels: Mapping[str, str],
        *,
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
    dockerfile_origin: Literal["REPOSITORY", "GENERATED"] = "REPOSITORY"
    dockerfile_path: str = "Dockerfile"
    context_archive: bytes | None = None
    context_digest: str | None = None

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
                or self.dockerfile_origin != "REPOSITORY"
                or self.dockerfile_path != "Dockerfile"
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
            or len(self.source_refs) != 3
            or any(ref.data_kind != "artifact" for ref in self.source_refs[1:])
            or {self.dockerfile_digest, self.context_digest}
            != {ref.content_hash for ref in self.source_refs[1:]}
            or self.dockerfile_path.startswith("/")
            or ".." in PurePosixPath(self.dockerfile_path).parts
        ):
            raise ValueError("RECIPE_CONTEXT_BINDING_INVALID")
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

    def __init__(self, *, artifacts: ArtifactStore | None = None) -> None:
        self._baselines: dict[tuple[str, str, str], EnvironmentRecipe] = {}
        self._lock = asyncio.Lock()
        self._artifacts = artifacts

    def preflight(
        self,
        *,
        context: Path,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
        repository_profile: RepositoryProfile | None = None,
    ) -> PreparedRecipeSource:
        """Parse and hash local files without contacting the Docker daemon."""

        if repository_profile is not None:
            return self._repository_source(
                context=context,
                request_ref=request_ref,
                requirements=requirements,
                repository_profile=repository_profile,
                meta=meta,
            )

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
            if source.context_archive is None:
                built_digest = await docker.build(
                    trusted_dockerfile,
                    labels,
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

        entries: dict[str, tuple[bytes, int]] = {}
        source_refs: list[StoredDataRef] = [profile_ref]
        total = 0
        for item in repository_profile.tracked_files:
            if self._looks_secret(item.git_path):
                raise ValueError("REPOSITORY_SECRET_FILE_DENIED")
            raw = self._read_profile_file(root, item)
            total += len(raw)
            if total > _MAX_BUILD_CONTEXT_BYTES:
                raise ValueError("RECIPE_BUILD_CONTEXT_LIMIT_EXCEEDED")
            entries[item.git_path] = (
                raw,
                0o755 if item.git_mode == "100755" else 0o644,
            )

        dockerfile_path, dockerfile, origin = self._select_dockerfile(
            entries,
            repository_profile,
            requirements,
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
            canonical_bytes((profile_ref, parts))
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
            dockerfile_origin=origin,
            dockerfile_path=dockerfile_path,
            context_archive=archive,
            context_digest=hashlib.sha256(archive).hexdigest(),
        )

    @staticmethod
    def _looks_secret(path: str) -> bool:
        name = PurePosixPath(path).name.casefold()
        return (
            name == ".env"
            or name.startswith(".env.")
            or name in _SECRET_FILE_NAMES
            or PurePosixPath(name).suffix in {".key", ".p12", ".pem", ".pfx"}
        )

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

    @classmethod
    def _select_dockerfile(
        cls,
        entries: Mapping[str, tuple[bytes, int]],
        profile: RepositoryProfile,
        requirements: EnvironmentRequirements,
    ) -> tuple[str, bytes, Literal["REPOSITORY", "GENERATED"]]:
        candidates = tuple(
            item.path for item in profile.config_files if item.kind == "DOCKERFILE"
        )
        if candidates:
            selected = "Dockerfile" if "Dockerfile" in candidates else candidates[0]
            if len(candidates) > 1 and "Dockerfile" not in candidates:
                raise ValueError("DOCKERFILE_SELECTION_CONFIRMATION_REQUIRED")
            try:
                return selected, entries[selected][0], "REPOSITORY"
            except KeyError as error:
                raise ValueError("REPOSITORY_MANIFEST_MISMATCH") from error

        language_names = {item.name for item in profile.languages}
        family: Literal["PYTHON", "NODE"] | None = (
            "PYTHON"
            if language_names == {"PYTHON"}
            else "NODE"
            if language_names and language_names <= {"JAVASCRIPT", "TYPESCRIPT"}
            else None
        )
        if family is None:
            raise ValueError("ENVIRONMENT_BUILD_CONFIRMATION_REQUIRED")
        version = cls._runtime_version(requirements, family)
        image = (
            f"python:{version or '3.12'}-slim"
            if family == "PYTHON"
            else f"node:{version or '22'}-slim"
        )
        dockerfile = (
            f"FROM {image}\n"
            "WORKDIR /workspace\n"
            "COPY . /workspace\n"
            'CMD ["sleep", "infinity"]\n'
        ).encode()
        return "Dockerfile", dockerfile, "GENERATED"

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
