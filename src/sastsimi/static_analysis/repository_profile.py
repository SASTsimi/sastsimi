"""Detect repository facts from the exact verified Git manifest only."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import (
    RepositoryConfigFile,
    RepositoryFramework,
    RepositoryLanguage,
    RepositoryProfile,
    RepositoryTrackedFile,
    StaticToolProfile,
)
from sastsimi.ports.dto import RepositoryPreparation, TrackedFile

_MAX_DETECTION_FILE_BYTES = 2 * 1024 * 1024
_LANGUAGE_SUFFIXES: dict[str, frozenset[str]] = {
    "PYTHON": frozenset({".py", ".pyi"}),
    "JAVASCRIPT": frozenset({".js", ".jsx", ".mjs", ".cjs"}),
    "TYPESCRIPT": frozenset({".ts", ".tsx", ".mts", ".cts"}),
    "JAVA": frozenset({".java"}),
}
_CONFIG_NAMES: dict[str, str] = {
    "requirements.txt": "REQUIREMENTS",
    "pyproject.toml": "PYPROJECT",
    "package.json": "PACKAGE_JSON",
    "dockerfile": "DOCKERFILE",
    "compose.yaml": "DOCKER_COMPOSE",
    "compose.yml": "DOCKER_COMPOSE",
    "docker-compose.yaml": "DOCKER_COMPOSE",
    "docker-compose.yml": "DOCKER_COMPOSE",
    "pom.xml": "MAVEN_POM",
    "build.gradle": "GRADLE",
    "build.gradle.kts": "GRADLE",
}
_FRAMEWORK_DEPENDENCIES: dict[str, frozenset[str]] = {
    "DJANGO": frozenset({"django"}),
    "FASTAPI": frozenset({"fastapi"}),
    "FLASK": frozenset({"flask"}),
    "EXPRESS": frozenset({"express"}),
    "NEXTJS": frozenset({"next"}),
    "NESTJS": frozenset({"@nestjs/core"}),
}


@dataclass(frozen=True)
class ActiveStaticCapability:
    """One capability already verified and activated outside this detector."""

    profile: StaticToolProfile
    supported_languages: tuple[
        Literal["PYTHON", "JAVASCRIPT", "TYPESCRIPT", "JAVA"], ...
    ]

    def __post_init__(self) -> None:
        known = {"PYTHON", "JAVASCRIPT", "TYPESCRIPT", "JAVA"}
        if (
            self.profile.status != "ACTIVE"
            or self.profile.purpose != "PRODUCTION"
            or self.profile.capability_evidence_ref is None
            or not self.supported_languages
            or len(set(self.supported_languages)) != len(self.supported_languages)
            or not set(self.supported_languages) <= known
            or (
                self.profile.adapter_key == "PYTHON_AST"
                and set(self.supported_languages) != {"PYTHON"}
            )
        ):
            raise ValueError("STATIC_CAPABILITY_NOT_ACTIVE")


@dataclass(frozen=True)
class SelectedStaticTool:
    adapter_key: Literal["PYTHON_AST", "CODEQL", "OPENGREP"]
    tool_profile_ref: StoredDataRef
    languages: tuple[str, ...]


@dataclass(frozen=True)
class StaticToolSelection:
    status: Literal["READY", "NEEDS_CONFIRMATION", "BLOCKED"]
    selected_tools: tuple[SelectedStaticTool, ...]
    block_reasons: tuple[str, ...]


def _identity(details: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_size,
        details.st_mtime_ns,
        details.st_nlink,
        getattr(details, "st_file_attributes", 0),
    )


def _read_exact(root: Path, tracked: TrackedFile) -> bytes:
    target = root.joinpath(*tracked.git_path.split("/"))
    descriptor = -1
    try:
        target.resolve(strict=True).relative_to(root)
        before = target.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or getattr(before, "st_file_attributes", 0) & 0x400
            or before.st_size != tracked.size_bytes
            or before.st_size > _MAX_DETECTION_FILE_BYTES
        ):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ValueError
        chunks: list[bytes] = []
        remaining = tracked.size_bytes
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise ValueError
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError
        after = target.lstat()
        raw = b"".join(chunks)
        if _identity(after) != _identity(opened):
            raise ValueError
    except (OSError, ValueError) as error:
        raise ValueError("REPOSITORY_MANIFEST_MISMATCH") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return raw


def _git_blob_id(raw: bytes, expected: str) -> str:
    framed = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    digest = hashlib.sha1 if len(expected) == 40 else hashlib.sha256
    return digest(framed).hexdigest()


def _dependency_name(value: str) -> str:
    text = value.strip().lower()
    if not text:
        return ""
    if text.startswith("@"):
        return text.split()[0]
    for marker in ("[", "<", ">", "=", "!", "~", " ", ";"):
        text = text.split(marker, 1)[0]
    return text.strip().replace("_", "-")


def _toml_dependencies(raw: bytes) -> frozenset[str]:
    parsed = tomllib.loads(raw.decode("utf-8"))
    values: list[str] = []
    project = parsed.get("project")
    if isinstance(project, dict):
        dependencies = project.get("dependencies", ())
        if isinstance(dependencies, list):
            values.extend(item for item in dependencies if isinstance(item, str))
    tool = parsed.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            dependencies = poetry.get("dependencies")
            if isinstance(dependencies, dict):
                values.extend(str(item) for item in dependencies)
    return frozenset(filter(None, (_dependency_name(item) for item in values)))


def _requirements_dependencies(raw: bytes) -> frozenset[str]:
    values = (
        line.split("#", 1)[0]
        for line in raw.decode("utf-8").splitlines()
        if not line.lstrip().startswith(("-", "#"))
    )
    return frozenset(filter(None, (_dependency_name(item) for item in values)))


def _package_json_dependencies(raw: bytes) -> frozenset[str]:
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError
    names: set[str] = set()
    for field in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        values = parsed.get(field, {})
        if not isinstance(values, dict):
            raise ValueError
        names.update(str(name).lower() for name in values)
    return frozenset(names)


class RepositoryProfiler:
    """Produce facts only after every supplied manifest entry still matches Git."""

    def build(
        self,
        preparation: RepositoryPreparation,
        *,
        meta: RecordMeta,
        workspace_ref: RunStoredDataRef,
    ) -> RepositoryProfile:
        if (
            preparation.status != "READY"
            or preparation.root is None
            or preparation.resolved_commit_id is None
            or meta.record_type != "repository_profile"
            or str(meta.analysis_id) != preparation.analysis_id
            or str(meta.workspace_id) != preparation.workspace_id
            or str(meta.commit_id) != preparation.resolved_commit_id
            or meta.hypothesis_id is not None
            or meta.attempt_id is None
            or workspace_ref.analysis_id != meta.analysis_id
            or workspace_ref.data_kind != "code_workspace"
            or workspace_ref.record_id is None
        ):
            raise ValueError("REPOSITORY_PROFILE_INPUT_INVALID")
        configured_root = preparation.root
        try:
            root = configured_root.resolve(strict=True)
            details = configured_root.lstat()
            if (
                configured_root.is_symlink()
                or not root.is_dir()
                or getattr(details, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError
        except (OSError, ValueError) as error:
            raise ValueError("REPOSITORY_MANIFEST_MISMATCH") from error
        paths = tuple(item.git_path for item in preparation.tracked_files)
        if len(set(paths)) != len(paths):
            raise ValueError("REPOSITORY_MANIFEST_MISMATCH")

        raw_files: dict[str, bytes] = {}
        manifest: list[RepositoryTrackedFile] = []
        canonical_tracked = tuple(
            sorted(preparation.tracked_files, key=lambda item: item.git_path)
        )
        for item in canonical_tracked:
            if item.git_mode not in {"100644", "100755"}:
                raise ValueError("REPOSITORY_MANIFEST_MISMATCH")
            raw = _read_exact(root, item)
            if _git_blob_id(raw, item.blob_id) != item.blob_id:
                raise ValueError("REPOSITORY_MANIFEST_MISMATCH")
            raw_files[item.git_path] = raw
            manifest.append(RepositoryTrackedFile.model_validate(asdict(item)))

        language_paths: dict[str, list[str]] = {}
        configs: list[RepositoryConfigFile] = []
        dependencies: dict[str, frozenset[str]] = {}
        confirmations: list[str] = []
        for path, raw in raw_files.items():
            suffix = PurePosixPath(path).suffix.lower()
            for language, suffixes in _LANGUAGE_SUFFIXES.items():
                if suffix in suffixes:
                    language_paths.setdefault(language, []).append(path)
            name = PurePosixPath(path).name.lower()
            kind = _CONFIG_NAMES.get(name)
            if kind is None:
                continue
            configs.append(
                RepositoryConfigFile.model_validate({"path": path, "kind": kind})
            )
            try:
                if kind == "PYPROJECT":
                    dependencies[path] = _toml_dependencies(raw)
                elif kind == "REQUIREMENTS":
                    dependencies[path] = _requirements_dependencies(raw)
                elif kind == "PACKAGE_JSON":
                    dependencies[path] = _package_json_dependencies(raw)
            except (UnicodeError, ValueError):
                confirmations.append("CONFIG_PARSE_FAILED:" + path)

        languages = tuple(
            RepositoryLanguage.model_validate(
                {
                    "name": language,
                    "evidence_paths": tuple(sorted(set(evidence))),
                }
            )
            for language, evidence in sorted(language_paths.items())
        )
        frameworks = tuple(
            RepositoryFramework.model_validate(
                {"name": framework, "evidence_paths": tuple(paths)}
            )
            for framework, names in sorted(_FRAMEWORK_DEPENDENCIES.items())
            if (
                paths := tuple(
                    sorted(
                        path for path, found in dependencies.items() if names & found
                    )
                )
            )
        )
        config_kinds = {item.kind for item in configs}
        has_build_evidence = bool(
            config_kinds
            & {
                "REQUIREMENTS",
                "PYPROJECT",
                "PACKAGE_JSON",
                "DOCKERFILE",
                "MAVEN_POM",
                "GRADLE",
            }
        )
        if not languages:
            confirmations.append("LANGUAGE_UNCONFIRMED")
        if not has_build_evidence:
            confirmations.append("BUILD_UNCONFIRMED")
        reasons = tuple(sorted(set(confirmations)))
        return RepositoryProfile.model_validate(
            {
                "meta": meta,
                "workspace_id": preparation.workspace_id,
                "commit_id": preparation.resolved_commit_id,
                "workspace_ref": workspace_ref,
                "manifest_hash": content_hash(
                    tuple(asdict(item) for item in canonical_tracked)
                ),
                "tracked_files": tuple(manifest),
                "languages": languages,
                "frameworks": frameworks,
                "config_files": tuple(
                    sorted(configs, key=lambda item: (item.kind, item.path))
                ),
                "status": "NEEDS_CONFIRMATION" if reasons else "READY",
                "confirmation_reasons": reasons,
            }
        )


def select_static_tools(
    repository: RepositoryProfile,
    capabilities: tuple[ActiveStaticCapability, ...],
) -> StaticToolSelection:
    """Choose only ACTIVE capabilities that explicitly support detected languages."""
    if repository.status != "READY":
        return StaticToolSelection(
            status="NEEDS_CONFIRMATION",
            selected_tools=(),
            block_reasons=repository.confirmation_reasons,
        )
    detected = {item.name for item in repository.languages}
    selected: list[SelectedStaticTool] = []
    seen_profiles: set[StoredDataRef] = set()
    claimed_routes: set[tuple[str, str]] = set()
    for capability in capabilities:
        supported = tuple(sorted(detected & set(capability.supported_languages)))
        if not supported:
            continue
        profile_ref = reference(capability.profile)
        if not isinstance(profile_ref, StoredDataRef):
            raise ValueError("STATIC_CAPABILITY_SCOPE_INVALID")
        if profile_ref in seen_profiles:
            raise ValueError("DUPLICATE_STATIC_CAPABILITY")
        routes = {(capability.profile.adapter_key, language) for language in supported}
        if claimed_routes & routes:
            return StaticToolSelection(
                status="BLOCKED",
                selected_tools=(),
                block_reasons=("AMBIGUOUS_STATIC_CAPABILITY",),
            )
        seen_profiles.add(profile_ref)
        claimed_routes.update(routes)
        selected.append(
            SelectedStaticTool(
                adapter_key=capability.profile.adapter_key,
                tool_profile_ref=profile_ref,
                languages=supported,
            )
        )
    if not selected:
        return StaticToolSelection(
            status="BLOCKED",
            selected_tools=(),
            block_reasons=("NO_ACTIVE_STATIC_CAPABILITY",),
        )
    covered = {language for item in selected for language in item.languages}
    missing = tuple(sorted(detected - covered))
    if missing:
        return StaticToolSelection(
            status="BLOCKED",
            selected_tools=(),
            block_reasons=tuple("UNSUPPORTED_LANGUAGE:" + item for item in missing),
        )
    return StaticToolSelection(
        status="READY",
        selected_tools=tuple(
            sorted(selected, key=lambda item: (item.adapter_key, item.languages))
        ),
        block_reasons=(),
    )
