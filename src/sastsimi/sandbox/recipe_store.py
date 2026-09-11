"""Immutable, code-scoped environment recipe bindings."""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Mapping
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


class RecipeDockerPort(Protocol):
    async def build(self, recipe_source: Path, labels: Mapping[str, str]) -> str: ...
    async def inspect_image(self, image: str) -> str: ...


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

    async def prepare(
        self,
        *,
        docker: RecipeDockerPort,
        context: Path,
        labels: Mapping[str, str],
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> EnvironmentRecipe:
        root, dockerfile, source_ref, source_refs, source_digest = self._source(
            context, meta
        )
        key = (str(meta.workspace_id), str(meta.commit_id), source_digest)
        requirements_ref = reference(requirements)
        if not isinstance(requirements_ref, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        async with self._lock:
            baseline = self._baselines.get(key)
            if baseline is not None:
                recipe = EnvironmentRecipe(
                    meta=fresh_record_meta(meta, "environment_recipe"),
                    request_ref=request_ref,
                    environment_requirements_ref=requirements_ref,
                    recipe_source_ref=source_ref,
                    source_refs=source_refs,
                    base_image_digest=baseline.base_image_digest,
                    built_image_digest=baseline.built_image_digest,
                    baseline_recipe_ref=self._exact_ref(baseline),
                    build_disposition="REUSED",
                    created_at=meta.created_at,
                )
                return recipe

            base_image = self._base_image(dockerfile)
            base_digest = (
                "scratch"
                if base_image == "scratch"
                else await docker.inspect_image(base_image)
            )
            built_digest = await docker.build(root, labels)
            recipe = EnvironmentRecipe(
                meta=fresh_record_meta(meta, "environment_recipe"),
                request_ref=request_ref,
                environment_requirements_ref=requirements_ref,
                recipe_source_ref=source_ref,
                source_refs=source_refs,
                base_image_digest=base_digest,
                built_image_digest=built_digest,
                baseline_recipe_ref=None,
                build_disposition="BUILT",
                created_at=meta.created_at,
            )
            self._baselines[key] = recipe
            return recipe

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
    def _base_image(dockerfile: Path) -> str:
        content = dockerfile.read_text(encoding="utf-8")
        match = _FROM.search(content)
        if match is None:
            raise ValueError("DOCKERFILE_BASE_IMAGE_REQUIRED")
        image = match.group(1)
        if any(character in image for character in "\r\n\0"):
            raise ValueError("DOCKERFILE_BASE_IMAGE_INVALID")
        return image

    @staticmethod
    def _source(
        context: Path,
        meta: RecordMeta,
    ) -> tuple[Path, Path, StoredDataRef, tuple[StoredDataRef, ...], str]:
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
        for path in files:
            data = path.read_bytes()
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
        return root, dockerfile, StoredDataRef(
            stored_data_id=StoredDataId(f"recipe-source-{source_digest}"),
            data_kind="recipe_source",
            content_hash=source_digest,
            workspace_id=meta.workspace_id,
            commit_id=meta.commit_id,
            record_id=None,
        ), tuple(refs), source_digest
