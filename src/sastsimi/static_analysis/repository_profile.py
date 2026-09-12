"""Detect repository facts from the exact verified Git manifest only."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tomllib
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.capabilities import (
    CapabilityArchitecture,
    CapabilityLanguage,
    CapabilityOperatingSystem,
    RuntimeCapabilityProfile,
    RuntimeCapabilitySelection,
    StaticToolCapabilitySelection,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import (
    AnalysisError,
    DataGap,
    RepositoryConfigFile,
    RepositoryExecutionHint,
    RepositoryExecutionSelection,
    RepositoryFramework,
    RepositoryLanguage,
    RepositoryProfile,
    RepositoryProfileError,
    RepositoryProfileGap,
    RepositorySelectedTool,
    RepositoryTrackedFile,
    StaticToolProfile,
)
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
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
    "package-lock.json": "PACKAGE_LOCK",
    "npm-shrinkwrap.json": "PACKAGE_LOCK",
    "yarn.lock": "YARN_LOCK",
    "pnpm-lock.yaml": "PNPM_LOCK",
    "poetry.lock": "PYTHON_LOCK",
    "uv.lock": "PYTHON_LOCK",
    "pipfile.lock": "PYTHON_LOCK",
    "pipfile": "PIPFILE",
}
_FRAMEWORK_DEPENDENCIES: dict[str, frozenset[str]] = {
    "DJANGO": frozenset({"django"}),
    "FASTAPI": frozenset({"fastapi"}),
    "FLASK": frozenset({"flask"}),
    "EXPRESS": frozenset({"express"}),
    "NEXTJS": frozenset({"next"}),
    "NESTJS": frozenset({"@nestjs/core"}),
}


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


def _read_exact(
    root: Path,
    tracked: TrackedFile,
    *,
    capture: bool,
) -> tuple[bytes | None, str]:
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
        ):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ValueError
        chunks: list[bytes] | None = (
            [] if capture and tracked.size_bytes <= _MAX_DETECTION_FILE_BYTES else None
        )
        git_digest = hashlib.sha1() if len(tracked.blob_id) == 40 else hashlib.sha256()
        git_digest.update(b"blob " + str(tracked.size_bytes).encode("ascii") + b"\0")
        sha256 = hashlib.sha256()
        remaining = tracked.size_bytes
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise ValueError
            git_digest.update(chunk)
            sha256.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError
        after = target.lstat()
        if _identity(after) != _identity(opened):
            raise ValueError
    except (OSError, ValueError) as error:
        raise ValueError("REPOSITORY_MANIFEST_MISMATCH") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if git_digest.hexdigest() != tracked.blob_id:
        raise ValueError("REPOSITORY_MANIFEST_MISMATCH")
    return (None if chunks is None else b"".join(chunks), sha256.hexdigest())


def _dependency_name(value: str) -> str:
    text = value.strip().lower()
    if not text:
        return ""
    if text.startswith("@"):
        return text.split()[0]
    for marker in ("[", "<", ">", "=", "!", "~", " ", ";"):
        text = text.split(marker, 1)[0]
    return text.strip().replace("_", "-")


def _toml_details(raw: bytes) -> tuple[frozenset[str], tuple[str, ...]]:
    parsed = tomllib.loads(raw.decode("utf-8"))
    values: list[str] = []
    scripts: set[str] = set()
    project = parsed.get("project")
    if isinstance(project, dict):
        dependencies = project.get("dependencies", ())
        if isinstance(dependencies, list):
            values.extend(item for item in dependencies if isinstance(item, str))
        declared_scripts = project.get("scripts")
        if isinstance(declared_scripts, dict):
            scripts.update(str(item) for item in declared_scripts)
    tool = parsed.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            dependencies = poetry.get("dependencies")
            if isinstance(dependencies, dict):
                values.extend(str(item) for item in dependencies)
            declared_scripts = poetry.get("scripts")
            if isinstance(declared_scripts, dict):
                scripts.update(str(item) for item in declared_scripts)
    return (
        frozenset(filter(None, (_dependency_name(item) for item in values))),
        tuple(sorted(scripts)),
    )


def _requirements_dependencies(raw: bytes) -> frozenset[str]:
    values = (
        line.split("#", 1)[0]
        for line in raw.decode("utf-8").splitlines()
        if not line.lstrip().startswith(("-", "#"))
    )
    return frozenset(filter(None, (_dependency_name(item) for item in values)))


def _package_json_details(raw: bytes) -> tuple[frozenset[str], tuple[str, ...]]:
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
    scripts = parsed.get("scripts", {})
    if not isinstance(scripts, dict) or any(
        not isinstance(name, str) or not isinstance(value, str)
        for name, value in scripts.items()
    ):
        raise ValueError
    return frozenset(names), tuple(sorted(scripts))


class RepositoryProfiler:
    """Produce facts only after every supplied manifest entry still matches Git."""

    def build(
        self,
        preparation: RepositoryPreparation,
        *,
        meta: RecordMeta,
        workspace_ref: RunStoredDataRef,
        action_decision_ref: StoredDataRef,
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
            or action_decision_ref.data_kind != "action_decision"
            or action_decision_ref.record_id is None
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

        raw_configs: dict[str, bytes | None] = {}
        manifest: list[RepositoryTrackedFile] = []
        language_paths: dict[str, list[str]] = {}
        configs: list[RepositoryConfigFile] = []
        confirmations: list[str] = []
        canonical_tracked = tuple(
            sorted(preparation.tracked_files, key=lambda item: item.git_path)
        )
        for item in canonical_tracked:
            if item.git_mode not in {"100644", "100755"}:
                raise ValueError("REPOSITORY_MANIFEST_MISMATCH")
            path = item.git_path
            suffix = PurePosixPath(path).suffix.lower()
            for language, suffixes in _LANGUAGE_SUFFIXES.items():
                if suffix in suffixes:
                    language_paths.setdefault(language, []).append(path)
            kind = _CONFIG_NAMES.get(PurePosixPath(path).name.lower())
            raw, sha256 = _read_exact(root, item, capture=kind is not None)
            manifest.append(
                RepositoryTrackedFile.model_validate(
                    asdict(item) | {"content_sha256": sha256}
                )
            )
            if kind is not None:
                configs.append(
                    RepositoryConfigFile.model_validate({"path": path, "kind": kind})
                )
                raw_configs[path] = raw
                if raw is None:
                    confirmations.append("CONFIG_TOO_LARGE:" + path)

        dependencies: dict[str, frozenset[str]] = {}
        execution_hints: list[RepositoryExecutionHint] = []
        for config in configs:
            path, kind = config.path, config.kind
            raw = raw_configs[path]
            if raw is None:
                continue
            try:
                if kind == "PYPROJECT":
                    dependencies[path], scripts = _toml_details(raw)
                    execution_hints.extend(
                        RepositoryExecutionHint(
                            path=path,
                            kind="PYTHON_SCRIPT",
                            name=name,
                        )
                        for name in scripts
                    )
                elif kind == "REQUIREMENTS":
                    dependencies[path] = _requirements_dependencies(raw)
                elif kind == "PACKAGE_JSON":
                    dependencies[path], scripts = _package_json_details(raw)
                    execution_hints.extend(
                        RepositoryExecutionHint(
                            path=path,
                            kind="PACKAGE_SCRIPT",
                            name=name,
                        )
                        for name in scripts
                        if name in {"build", "start"}
                    )
                elif kind == "DOCKERFILE":
                    execution_hints.append(
                        RepositoryExecutionHint(
                            path=path,
                            kind="DOCKERFILE",
                            name="dockerfile",
                        )
                    )
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
        if not languages:
            confirmations.append("LANGUAGE_UNCONFIRMED")
        if not execution_hints:
            confirmations.append("BUILD_OR_START_UNCONFIRMED")
        gaps = tuple(
            RepositoryProfileGap.model_validate(
                {
                    "code": item.code,
                    "reason": item.reason,
                    "description": item.description,
                    "affected_paths": item.affected_paths,
                    "affected_languages": item.affected_languages,
                    "affected_locations": tuple(
                        {
                            "file_path": location.file_path,
                            "start_line": location.start_line,
                            "start_column": location.start_column,
                            "end_line": location.end_line,
                            "end_column": location.end_column,
                        }
                        for location in item.affected_locations
                    ),
                    "retryable": item.retryable,
                }
            )
            for item in preparation.gaps
        )
        errors = tuple(
            RepositoryProfileError.model_validate(
                {
                    "code": item.code,
                    "safe_message": item.safe_message,
                    "retryable": item.retryable,
                }
            )
            for item in preparation.errors
        )
        confirmations.extend("REPOSITORY_GAP:" + item.code for item in gaps)
        confirmations.extend("REPOSITORY_ERROR:" + item.code for item in errors)
        reasons = tuple(sorted(set(confirmations)))
        return RepositoryProfile.model_validate(
            {
                "meta": meta,
                "workspace_id": preparation.workspace_id,
                "commit_id": preparation.resolved_commit_id,
                "workspace_ref": workspace_ref,
                "action_decision_ref": action_decision_ref,
                "manifest_hash": content_hash(
                    tuple(item.model_dump(mode="json") for item in manifest)
                ),
                "tracked_files": tuple(manifest),
                "languages": languages,
                "frameworks": frameworks,
                "config_files": tuple(
                    sorted(configs, key=lambda item: (item.kind, item.path))
                ),
                "execution_hints": tuple(
                    sorted(
                        execution_hints,
                        key=lambda item: (item.path, item.kind, item.name),
                    )
                ),
                "gaps": gaps,
                "errors": errors,
                "status": "NEEDS_CONFIRMATION" if reasons else "READY",
                "confirmation_reasons": reasons,
            }
        )


_STATIC_ROUTES: dict[str, tuple[str, ...]] = {
    "PYTHON": ("PYTHON_AST", "CODEQL", "OPENGREP"),
    "JAVASCRIPT": ("CODEQL", "OPENGREP"),
}


def resolve_git_capability_refs(
    resolver: ProductionCapabilityResolverPort,
    *,
    operating_system: CapabilityOperatingSystem,
    architecture: CapabilityArchitecture,
) -> tuple[HostConfigurationRef, HostConfigurationRef]:
    """Select and immediately revalidate exact Git revisions before clone work."""

    refs: list[HostConfigurationRef] = []
    for operation in ("CLONE", "CHECKOUT"):
        selected = RuntimeCapabilitySelection.model_validate(
            resolver.resolve_active_capability(
                capability_kind="GIT",
                language="ANY",
                operation=operation,
                operating_system=operating_system,
                architecture=architecture,
            )
        )
        pinned = resolver.resolve_pinned_active_profile(selected.profile_ref)
        if (
            not isinstance(pinned, RuntimeCapabilityProfile)
            or pinned != selected.profile
            or reference(pinned) != selected.profile_ref
            or pinned.status != "ACTIVE"
            or pinned.capability_kind != "GIT"
            or operation not in pinned.operations
            or pinned.operating_system != operating_system
            or pinned.architecture != architecture
        ):
            raise ValueError("GIT_CAPABILITY_ROUTE_MISMATCH")
        refs.append(selected.profile_ref)
    return refs[0], refs[1]


class RepositoryExecutionSelector:
    """Resolve production routes only through the trusted host registry."""

    def __init__(
        self,
        resolver: ProductionCapabilityResolverPort,
        *,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> None:
        self._resolver = resolver
        self._operating_system = operating_system
        self._architecture = architecture

    @staticmethod
    def _stable_id(prefix: str, values: object) -> str:
        return f"{prefix}-{content_hash(values)[:24]}"

    @staticmethod
    def _related(repository: RepositoryProfile) -> tuple[str, ...]:
        return (str(repository.meta.record_id),)

    def _gap(
        self,
        repository: RepositoryProfile,
        *,
        code: str,
        description: str,
        languages: tuple[str, ...] = (),
    ) -> DataGap:
        return DataGap.model_validate(
            {
                "gap_id": self._stable_id(
                    "gap", (repository.meta.record_id, code, languages)
                ),
                "stage": "STATIC_ANALYSIS",
                "code": code,
                "reason": "BLOCKED",
                "description": description,
                "affected_paths": (),
                "affected_languages": languages,
                "affected_locations": (),
                "retryable": True,
                "related_record_ids": self._related(repository),
                "created_at": repository.meta.created_at,
            }
        )

    def _error(
        self,
        repository: RepositoryProfile,
        *,
        meta: RecordMeta,
        code: str,
        message: str,
    ) -> AnalysisError:
        return AnalysisError.model_validate(
            {
                "error_id": self._stable_id("error", (repository.meta.record_id, code)),
                "stage": "STATIC_ANALYSIS",
                "code": code,
                "safe_message": message,
                "retryable": False,
                "work_id": None,
                "attempt_id": meta.attempt_id,
                "related_record_ids": self._related(repository),
                "created_at": meta.created_at,
            }
        )

    def _validate_git_ref(
        self, profile_ref: HostConfigurationRef, operation: str
    ) -> None:
        profile = self._resolver.resolve_pinned_active_profile(profile_ref)
        if not isinstance(profile, RuntimeCapabilityProfile):
            raise ValueError("GIT_CAPABILITY_TYPE_MISMATCH")
        profile = RuntimeCapabilityProfile.model_validate_json(
            profile.model_dump_json()
        )
        if (
            reference(profile) != profile_ref
            or profile.status != "ACTIVE"
            or profile.capability_kind != "GIT"
            or operation not in profile.operations
            or profile.operating_system != self._operating_system
            or profile.architecture != self._architecture
        ):
            raise ValueError("GIT_CAPABILITY_ROUTE_MISMATCH")

    def _resolve_static(
        self, adapter_key: str, language: CapabilityLanguage
    ) -> StaticToolCapabilitySelection:
        selected = self._resolver.resolve_active_static_tool(
            adapter_key=adapter_key,
            language=language,
            operating_system=self._operating_system,
            architecture=self._architecture,
        )
        selected = StaticToolCapabilitySelection.model_validate_json(
            selected.model_dump_json()
        )
        try:
            pinned = self._resolver.resolve_pinned_active_profile(selected.profile_ref)
        except LookupError as error:
            raise ValueError("STATIC_CAPABILITY_PIN_MISSING") from error
        operation = "PARSE" if adapter_key == "PYTHON_AST" else "ANALYZE"
        if (
            not isinstance(pinned, StaticToolProfile)
            or pinned != selected.profile
            or reference(pinned) != selected.profile_ref
            or pinned.status != "ACTIVE"
            or pinned.purpose != "PRODUCTION"
            or pinned.adapter_key != adapter_key
            or selected.evidence.host_id != selected.profile_ref.host_id
            or selected.evidence.operating_system != self._operating_system
            or selected.evidence.architecture != self._architecture
            or language not in selected.evidence.languages
            or operation not in selected.evidence.operations
        ):
            raise ValueError("STATIC_CAPABILITY_ROUTE_MISMATCH")
        return selected

    def select(
        self,
        repository: RepositoryProfile,
        *,
        meta: RecordMeta,
        repository_profile_ref: StoredDataRef,
        git_clone_profile_ref: HostConfigurationRef,
        git_checkout_profile_ref: HostConfigurationRef,
    ) -> RepositoryExecutionSelection:
        if (
            meta.record_type != "repository_execution_selection"
            or meta.attempt_id is None
            or repository_profile_ref != reference(repository)
            or repository_profile_ref.data_kind != "repository_profile"
            or repository.meta.analysis_id != meta.analysis_id
            or repository.meta.workspace_id != meta.workspace_id
            or repository.meta.commit_id != meta.commit_id
            or repository.meta.attempt_id != meta.attempt_id
        ):
            raise ValueError("REPOSITORY_EXECUTION_SELECTION_INPUT_INVALID")
        try:
            self._validate_git_ref(git_clone_profile_ref, "CLONE")
            self._validate_git_ref(git_checkout_profile_ref, "CHECKOUT")
        except (LookupError, ValueError):
            failed = self._error(
                repository,
                meta=meta,
                code="CAPABILITY_REGISTRY_MISMATCH",
                message=(
                    "The pinned Git capability no longer matches the trusted registry."
                ),
            )
            return RepositoryExecutionSelection(
                meta=meta,
                repository_profile_ref=repository_profile_ref,
                git_clone_profile_ref=git_clone_profile_ref,
                git_checkout_profile_ref=git_checkout_profile_ref,
                languages=(),
                selected_tools=(),
                gaps=(),
                errors=(failed,),
                status="FAILED",
            )

        if repository.status != "READY":
            confirmation_gaps = tuple(
                self._gap(
                    repository,
                    code=reason,
                    description=(
                        "Repository input requires confirmation before tool selection."
                    ),
                )
                for reason in repository.confirmation_reasons
            )
            return RepositoryExecutionSelection(
                meta=meta,
                repository_profile_ref=repository_profile_ref,
                git_clone_profile_ref=git_clone_profile_ref,
                git_checkout_profile_ref=git_checkout_profile_ref,
                languages=(),
                selected_tools=(),
                gaps=confirmation_gaps,
                errors=(),
                status="BLOCKED",
            )

        detected = tuple(sorted(item.name for item in repository.languages))
        unsupported = tuple(item for item in detected if item not in _STATIC_ROUTES)
        if unsupported:
            unsupported_gaps = tuple(
                self._gap(
                    repository,
                    code="UNSUPPORTED_LANGUAGE",
                    description=(
                        "No production static-tool route is defined for this language."
                    ),
                    languages=(language,),
                )
                for language in unsupported
            )
            return RepositoryExecutionSelection(
                meta=meta,
                repository_profile_ref=repository_profile_ref,
                git_clone_profile_ref=git_clone_profile_ref,
                git_checkout_profile_ref=git_checkout_profile_ref,
                languages=(),
                selected_tools=(),
                gaps=unsupported_gaps,
                errors=(),
                status="BLOCKED",
            )

        supported_languages = cast(
            tuple[Literal["PYTHON", "JAVASCRIPT"], ...], detected
        )
        resolved: list[
            tuple[
                str,
                Literal["PYTHON", "JAVASCRIPT"],
                StaticToolCapabilitySelection,
            ]
        ] = []
        selection_gaps: list[DataGap] = []
        errors: list[AnalysisError] = []
        for language in supported_languages:
            for adapter_key in _STATIC_ROUTES[language]:
                try:
                    selected = self._resolve_static(
                        adapter_key, cast(CapabilityLanguage, language)
                    )
                except LookupError:
                    selection_gaps.append(
                        self._gap(
                            repository,
                            code=f"NO_ACTIVE_STATIC_CAPABILITY:{adapter_key}:{language}",
                            description=(
                                "A required production static-tool route is not active."
                            ),
                            languages=(language,),
                        )
                    )
                except (ValueError, KeyError, TypeError, AttributeError):
                    errors.append(
                        self._error(
                            repository,
                            meta=meta,
                            code="CAPABILITY_REGISTRY_MISMATCH",
                            message=(
                                "The trusted registry returned an inconsistent "
                                "static-tool route."
                            ),
                        )
                    )
                else:
                    resolved.append((adapter_key, language, selected))

        if errors:
            return RepositoryExecutionSelection(
                meta=meta,
                repository_profile_ref=repository_profile_ref,
                git_clone_profile_ref=git_clone_profile_ref,
                git_checkout_profile_ref=git_checkout_profile_ref,
                languages=supported_languages,
                selected_tools=(),
                gaps=(),
                errors=tuple(errors[:1]),
                status="FAILED",
            )
        if selection_gaps:
            return RepositoryExecutionSelection(
                meta=meta,
                repository_profile_ref=repository_profile_ref,
                git_clone_profile_ref=git_clone_profile_ref,
                git_checkout_profile_ref=git_checkout_profile_ref,
                languages=supported_languages,
                selected_tools=(),
                gaps=tuple(selection_gaps),
                errors=(),
                status="BLOCKED",
            )

        grouped: dict[tuple[str, HostConfigurationRef], set[str]] = {}
        for adapter_key, language, selected in resolved:
            grouped.setdefault((adapter_key, selected.profile_ref), set()).add(language)
        tools = tuple(
            RepositorySelectedTool.model_validate(
                {
                    "adapter_key": adapter_key,
                    "operation": "PARSE" if adapter_key == "PYTHON_AST" else "ANALYZE",
                    "tool_profile_ref": profile_ref,
                    "languages": tuple(sorted(languages)),
                }
            )
            for (adapter_key, profile_ref), languages in sorted(
                grouped.items(), key=lambda item: (item[0][0], item[0][1].record_id)
            )
        )
        return RepositoryExecutionSelection(
            meta=meta,
            repository_profile_ref=repository_profile_ref,
            git_clone_profile_ref=git_clone_profile_ref,
            git_checkout_profile_ref=git_checkout_profile_ref,
            languages=supported_languages,
            selected_tools=tools,
            gaps=(),
            errors=(),
            status="READY",
        )


def static_tool_work_inputs(
    selection: RepositoryExecutionSelection,
    selection_ref: StoredDataRef,
    tool: RepositorySelectedTool,
) -> tuple[StoredDataRef, StoredDataRef, HostConfigurationRef]:
    """Return the exact immutable inputs T14 must pin into one child work."""

    if (
        selection.status != "READY"
        or reference(selection) != selection_ref
        or tool not in selection.selected_tools
    ):
        raise ValueError("STATIC_TOOL_CHILD_INPUT_INVALID")
    return (
        selection.repository_profile_ref,
        selection_ref,
        tool.tool_profile_ref,
    )
