"""Small cross-platform Docker CLI path for the local SimpleRuntime."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import weakref
import zipfile
from collections import OrderedDict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from email.parser import BytesParser
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from uuid import uuid4

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)

from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.docker_state import DockerContainerState
from sastsimi.sandbox.docker_adapter import (
    DockerCommandOutcome,
    DockerOperationError,
)
from sastsimi.sandbox.recipe_store import EnvironmentRecipeStore
from sastsimi.static_analysis.file_scope import (
    build_static_file_scope,
    is_test_only_path,
)

from .artifacts import SimpleArtifactRepository
from .models import CheckpointIdentity, SimpleStage, StageCheckpoint
from .offline_wheels import build_wheel_bundle, import_wheel_bundle
from .recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    validate_environment_patch,
)
from .stages import ReproductionEnvironment

_RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_FULL_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_OUTPUT = 1024 * 1024
_MAX_PINNED_CONTEXT_BYTES = 64 * 1024 * 1024
_MAX_PINNED_FILES = 20_000
_AUTO_BUNDLE_DOWNLOAD_TIMEOUT_SECONDS = 300
_PIP_DOWNLOAD_RETRIES = "3"
_PIP_DOWNLOAD_TIMEOUT_SECONDS = "45"
_REPRODUCIBLE_SOURCE_MTIME = 315532800  # 1980-01-01 UTC; wheel ZIP minimum.
_OFFLINE_BASE_IMAGE = "python:3.12-slim"
_EXPLICIT_PYTHON_RUNTIME = re.compile(
    r"python:([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?)\Z", re.IGNORECASE
)
_OFFLINE_BROWSER_SMOKE_MARKER = "SASTSIMI_BROWSER_SMOKE_OK"


_OFFLINE_BROWSER_COMMANDS = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
)
_OFFLINE_BROWSER_SMOKE_SCRIPT = (
    "import json, shutil, subprocess, sys\n"
    "if sys.version_info[:2] != (3, 12): raise SystemExit(3)\n"
    f"marker = {_OFFLINE_BROWSER_SMOKE_MARKER!r}\n"
    "url = 'data:text/html,<html><body>' + marker + '</body></html>'\n"
    f"for name in {_OFFLINE_BROWSER_COMMANDS!r}:\n"
    "    browser = shutil.which(name)\n"
    "    if browser is None: continue\n"
    "    try:\n"
    "        result = subprocess.run(\n"
    "            [browser, '--headless', '--no-sandbox', '--disable-gpu',\n"
    "             '--disable-dev-shm-usage', '--disable-background-networking',\n"
    "             '--no-first-run', '--user-data-dir=/tmp/sastsimi-browser-smoke',\n"
    "             '--dump-dom', url],\n"
    "            capture_output=True, text=True, timeout=25, check=False,\n"
    "        )\n"
    "    except (OSError, subprocess.TimeoutExpired): continue\n"
    "    if result.returncode == 0 and marker in result.stdout:\n"
    "        print(json.dumps({'marker': marker, 'browser_command': browser,\n"
    "                          'python_version': sys.version.split()[0]}))\n"
    "        break\n"
    "else:\n"
    "    raise SystemExit(4)\n"
)
_OFFLINE_PINNED_SOURCE = re.compile(
    r"Source checkout at commit ((?:[0-9a-f]{40}|[0-9a-f]{64})) "
    r"containing (.+\.py)"
)
_OFFLINE_PINNED_SOURCE_FILE_FIRST = re.compile(
    r"Source checkout of (.+\.py) at commit ((?:[0-9a-f]{40}|[0-9a-f]{64}))"
)
_OFFLINE_MISSING = re.compile(
    rb"(?i)(?:no matching distribution found|could not find a version that satisfies|"
    rb"no matching distribution|package.*not found|missing build dependency|"
    rb"ModuleNotFoundError: No module named)"
)
_MISSING_TOP_LEVEL_IMPORT = re.compile(
    r"(?m)^ModuleNotFoundError:\s*(?:No module named\s+)?['\"]?"
    r"([A-Za-z_][A-Za-z0-9_]*)['\"]?\s*$"
)


@contextmanager
def _wheel_download_workspace() -> Iterator[Path]:
    """Make Docker-created wheels host-readable without changing POSIX temp ACLs."""

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="sastsimi-wheel-") as temporary:
            yield Path(temporary).resolve()
        return

    # tempfile.mkdtemp uses an owner-only directory. Docker Desktop can write
    # into that bind mount, but its downloaded wheels then deny the host read.
    # A normal mkdir inherits the user's Temp ACL, which supports both sides.
    parent = Path(tempfile.gettempdir()).resolve()
    root = parent / f"sastsimi-wheel-{uuid4().hex}"
    root.mkdir()
    try:
        yield root
    finally:
        info: os.stat_result | None
        try:
            info = root.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            if (
                root.parent != parent
                or not stat.S_ISDIR(info.st_mode)
                or root.is_symlink()
                or int(getattr(info, "st_file_attributes", 0)) & 0x400
                or root.resolve() != root
            ):
                raise ValueError("POC_AUTO_BUNDLE_WORKSPACE_UNSAFE")
            try:
                shutil.rmtree(root)
            except OSError as error:
                raise ValueError("POC_AUTO_BUNDLE_CLEANUP_FAILED") from error


def offline_recipe_cache_key(
    *,
    archive_sha256: str,
    manifest_sha256: str,
    commit_id: str,
    dockerfile_sha256: str,
    base_image_digest: str,
    network: str,
) -> str:
    """Keep every executable offline-build input in the cache identity."""

    digest = hashlib.sha256(
        canonical_bytes(
            {
                "archive_sha256": archive_sha256,
                "manifest_sha256": manifest_sha256,
                "commit_id": commit_id,
                "dockerfile_sha256": dockerfile_sha256,
                "base_image_digest": base_image_digest,
                "network": network,
            }
        )
    ).hexdigest()
    return f"{archive_sha256}:{digest}"


@dataclass(frozen=True, slots=True)
class OfflineBaseSmoke:
    base_image_digest: str
    browser_command: str
    python_version: str
    smoke_output_digest: str


@dataclass(frozen=True, slots=True)
class _AutoRuntimeObservation:
    base_digest: str
    requested: str | None
    observed: str | None
    operator_configured: bool


_DEPENDENCY_INSTALL = re.compile(
    rb"(?:pip3? install|python -m pip install|npm (?:ci|install)|"
    rb"apt-get install|yarn install|poetry install)",
    re.IGNORECASE,
)


class DockerBuildAttemptsError(DockerOperationError):
    def __init__(
        self,
        error: DockerOperationError,
        attempt_refs: tuple[StoredDataRef, ...],
        recipe_ref: StoredDataRef,
    ) -> None:
        super().__init__(error.code, error.outcome)
        self.attempt_refs = attempt_refs
        self.recipe_ref = recipe_ref


class DependencyBundleResolutionError(DockerOperationError):
    """A resolver failure with an immutable, redacted attempt receipt."""

    def __init__(
        self,
        error: DockerOperationError,
        attempt_refs: tuple[StoredDataRef, ...],
    ) -> None:
        super().__init__(error.code, error.outcome)
        self.attempt_refs = attempt_refs


class ImportSmokeCleanupUnconfirmed(ValueError):
    """An import smoke container could not be proven absent."""


def _foreign_runtime_paths(
    tracked_paths: frozenset[str], target_python_manifest: str | None
) -> frozenset[str]:
    """Return nested Node-only paths outside the selected Python project.

    A generated Python runtime never runs package-manager commands for a
    nested Node project.  Its source and registry credentials must therefore
    never enter the image.  A secret at the selected Python project's own
    boundary remains fail-closed.  This deliberately does not make a mixed
    Python/Node project safe by assumption: a directory that also declares a
    Python manifest or tracked Python source remains in the normal context and
    follows the normal secret-file denial path.
    """

    if target_python_manifest is None:
        return frozenset()
    manifest = PurePosixPath(target_python_manifest)
    if (
        not target_python_manifest
        or manifest.is_absolute()
        or ".." in manifest.parts
        or "\\" in target_python_manifest
        or ":" in target_python_manifest
        or manifest.name not in {"requirements.txt", "pyproject.toml"}
        or target_python_manifest not in tracked_paths
    ):
        return frozenset()
    target_root = manifest.parent
    # These are intentionally broader than the two manifests AUTO can resolve.
    # Their purpose is fail-closed classification: if a nested Node project also
    # advertises *any* conventional Python project metadata, it may be part of
    # the product runtime and must remain subject to the normal secret checks.
    python_project_markers = frozenset(
        {
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
        }
    )
    foreign_roots: set[PurePosixPath] = set()
    for path in tracked_paths:
        parsed = PurePosixPath(path)
        if parsed.name != "package.json":
            continue
        root = parsed.parent
        # A Node project that owns the selected Python manifest's directory
        # (or an ancestor) cannot be omitted as a foreign subtree.
        if target_root.is_relative_to(root):
            continue
        prefix = root.as_posix()
        has_python_manifest = any(
            f"{prefix}/{marker}" in tracked_paths for marker in python_project_markers
        )
        has_python_source = any(
            candidate.startswith(f"{prefix}/") and candidate.casefold().endswith(".py")
            for candidate in tracked_paths
        )
        if not has_python_manifest and not has_python_source:
            foreign_roots.add(root)
    return frozenset(
        path
        for path in tracked_paths
        if any(PurePosixPath(path).is_relative_to(root) for root in foreign_roots)
    )


def build_pinned_context(
    workspace: Path,
    commit_id: str,
    dockerfile: bytes,
    wheels: Mapping[str, bytes],
    *,
    target_python_manifest: str | None = None,
    git_executable: str = "git",
) -> bytes:
    """Build a bounded Docker context from a verified pinned Git snapshot."""

    if _COMMIT_ID.fullmatch(commit_id) is None:
        raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
    root = workspace.resolve(strict=True)

    def git(*args: str) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                (git_executable, "-C", str(root), *args),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("PINNED_CONTEXT_UNAVAILABLE") from error

    def require_unchanged() -> None:
        diff = git("diff", "--quiet", "--no-ext-diff", "--no-textconv", commit_id, "--")
        if diff.returncode == 1:
            raise ValueError("PINNED_CONTEXT_CHANGED")
        if diff.returncode != 0:
            raise ValueError("PINNED_CONTEXT_UNAVAILABLE")

    listed = git("ls-tree", "-r", "-z", commit_id)
    if listed.returncode != 0 or len(listed.stdout) > 16 * 1024 * 1024:
        raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
    index_flags = git("ls-files", "-v", "-z")
    if index_flags.returncode != 0 or any(
        item and not item.startswith(b"H ") for item in index_flags.stdout.split(b"\0")
    ):
        raise ValueError("PINNED_CONTEXT_UNSAFE")
    entries = listed.stdout.split(b"\0")
    if len(entries) > _MAX_PINNED_FILES + 1:
        raise ValueError("PINNED_CONTEXT_TOO_LARGE")
    paths = [entry.split(b"\t", 1)[1] for entry in entries if entry and b"\t" in entry]
    tracked_paths = frozenset(paths)
    try:
        tracked_text_paths = frozenset(path.decode("utf-8") for path in paths)
    except UnicodeError as error:
        raise ValueError("PINNED_CONTEXT_UNSAFE") from error
    omitted_foreign_runtime_paths = _foreign_runtime_paths(
        tracked_text_paths, target_python_manifest
    )

    def in_nested_project(name: str) -> bool:
        for parent in PurePosixPath(name).parents:
            if parent == PurePosixPath("."):
                break
            prefix = f"{parent.as_posix()}/"
            if any(
                f"{prefix}{manifest}".encode() in tracked_paths
                for manifest in (
                    "pyproject.toml",
                    "setup.py",
                    "setup.cfg",
                    "MANIFEST.in",
                    "package.json",
                )
            ):
                return True
        return False

    def flit_package_boundary() -> tuple[str, tuple[str, ...], tuple[str, ...]] | None:
        """Only omit test fixtures proven outside a simple Flit wheel package."""

        if any(path in {b"setup.py", b"setup.cfg", b"MANIFEST.in"} for path in paths):
            return None
        for entry in entries:
            if not entry or not entry.endswith(b"\tpyproject.toml"):
                continue
            try:
                header, _path = entry.split(b"\t", 1)
                mode, kind, object_id = header.split()
            except ValueError:
                return None
            if mode != b"100644" or kind != b"blob":
                return None
            project_blob = git("cat-file", "blob", object_id.decode("ascii"))
            if project_blob.returncode != 0 or len(project_blob.stdout) > 1024 * 1024:
                return None
            try:
                project = tomllib.loads(project_blob.stdout.decode("utf-8"))
            except (UnicodeError, tomllib.TOMLDecodeError):
                return None
            build = project.get("build-system")
            metadata = project.get("project")
            tool = project.get("tool")
            flit = tool.get("flit") if isinstance(tool, dict) else None
            module = flit.get("module") if isinstance(flit, dict) else None
            module_name = module.get("name") if isinstance(module, dict) else None
            if (
                not isinstance(build, dict)
                or build.get("build-backend") != "flit_core.buildapi"
                or not isinstance(metadata, dict)
                or not isinstance(flit, dict)
                or "external-data" in flit
                or "metadata" in flit
                or not isinstance(module_name, str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name) is None
            ):
                return None
            dynamic = metadata.get("dynamic", [])
            if not isinstance(dynamic, list) or any(
                not isinstance(field, str)
                or field in {"readme", "license", "license-files"}
                for field in dynamic
            ):
                return None
            direct_refs: list[str] = []
            readme = metadata.get("readme")
            if isinstance(readme, str):
                direct_refs.append(readme)
            elif isinstance(readme, dict) and isinstance(readme.get("file"), str):
                direct_refs.append(readme["file"])
            elif readme is not None and not (
                isinstance(readme, dict) and isinstance(readme.get("text"), str)
            ):
                return None
            license_value = metadata.get("license")
            if isinstance(license_value, dict):
                if isinstance(license_value.get("file"), str):
                    direct_refs.append(license_value["file"])
                elif not isinstance(license_value.get("text"), str):
                    return None
            elif license_value is not None and not isinstance(license_value, str):
                return None
            license_files = metadata.get("license-files", [])
            if not isinstance(license_files, list) or any(
                not isinstance(pattern, str) for pattern in license_files
            ):
                return None
            for reference in (*direct_refs, *license_files):
                parsed = PurePosixPath(reference)
                if (
                    not reference
                    or parsed.is_absolute()
                    or "\\" in reference
                    or ".." in parsed.parts
                    or (reference in license_files and "**" in parsed.parts)
                ):
                    return None
            for prefix in (f"src/{module_name}", module_name):
                if f"{prefix}/__init__.py".encode() in tracked_paths:
                    return (
                        prefix,
                        tuple(direct_refs),
                        tuple(
                            PurePosixPath(pattern).as_posix()
                            for pattern in license_files
                        ),
                    )
            return None
        return None

    flit_boundary = flit_package_boundary()
    try:
        attributes = subprocess.run(
            (git_executable, "-C", str(root), "check-attr", "-z", "--stdin", "filter"),
            input=b"\0".join(paths) + b"\0",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("PINNED_CONTEXT_UNAVAILABLE") from error
    if attributes.returncode != 0 or len(attributes.stdout) > 16 * 1024 * 1024:
        raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
    fields = attributes.stdout.split(b"\0")
    if any(
        fields[index] not in {b"unspecified", b"unset"}
        for index in range(2, len(fields) - 1, 3)
    ):
        raise ValueError("PINNED_CONTEXT_FILTER_UNSUPPORTED")
    dockerignore: bytes | None = None
    for entry in entries:
        if entry.endswith(b"\t.dockerignore"):
            try:
                header, _path = entry.split(b"\t", 1)
                mode, kind, object_id = header.split()
            except ValueError as error:
                raise ValueError("PINNED_CONTEXT_UNSAFE") from error
            if mode != b"100644" or kind != b"blob":
                raise ValueError("PINNED_CONTEXT_UNSAFE")
            ignored = git("cat-file", "blob", object_id.decode("ascii"))
            if ignored.returncode != 0 or len(ignored.stdout) > 1024 * 1024:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
            dockerignore = ignored.stdout
            break
    ignore_patterns = EnvironmentRecipeStore._dockerignore_patterns(
        {".dockerignore": (dockerignore, 0o644)} if dockerignore is not None else {}
    )
    stream = io.BytesIO()
    names = {"dockerfile", ".dockerignore"}
    total_bytes = len(dockerfile)
    excluded_test_paths: frozenset[str] | None = None

    def add_member(
        archive: tarfile.TarFile, name: str, raw: bytes, mode: int = 0o644
    ) -> None:
        nonlocal total_bytes
        total_bytes += len(raw)
        if total_bytes > _MAX_PINNED_CONTEXT_BYTES:
            raise ValueError("PINNED_CONTEXT_TOO_LARGE")
        info = tarfile.TarInfo(name)
        info.size = len(raw)
        info.mode = mode
        info.mtime = _REPRODUCIBLE_SOURCE_MTIME
        archive.addfile(info, io.BytesIO(raw))

    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        add_member(archive, "Dockerfile", dockerfile)
        for entry in entries:
            if not entry:
                continue
            try:
                header, path_bytes = entry.split(b"\t", 1)
                mode, kind, object_id = header.split()
                name = path_bytes.decode("utf-8", errors="strict")
                parts = PurePosixPath(name).parts
            except (ValueError, UnicodeError) as error:
                raise ValueError("PINNED_CONTEXT_UNSAFE") from error
            if (
                not parts
                or name.startswith("/")
                or "\\" in name
                or ":" in name
                or any(part in {"", ".", ".."} for part in parts)
                or (
                    name.casefold() in names
                    and name not in {"Dockerfile", ".dockerignore"}
                )
                or name == "wheels"
                or name.startswith("wheels/")
            ):
                raise ValueError("PINNED_CONTEXT_UNSAFE")
            if name in {"Dockerfile", ".dockerignore"}:
                continue
            if EnvironmentRecipeStore._dockerignored(name, ignore_patterns):
                continue
            if name in omitted_foreign_runtime_paths:
                # Nested Node-only projects cannot be part of a generated
                # Python runtime.  Excluding the whole subtree prevents both
                # credential leakage and unrelated symlink/build failures.
                continue
            if mode not in {b"100644", b"100755"} or kind != b"blob":
                raise ValueError("PINNED_CONTEXT_UNSAFE")
            if EnvironmentRecipeStore._looks_secret(name):
                if is_test_only_path(root, name):
                    if excluded_test_paths is None:
                        try:
                            tracked = tuple(path.decode("utf-8") for path in paths)
                            scope = build_static_file_scope(root, tracked)
                        except (UnicodeError, ValueError) as error:
                            raise ValueError("PINNED_CONTEXT_UNSAFE") from error
                        excluded_test_paths = frozenset(
                            path for path, _reason in scope.excluded_test_files
                        )
                    if (
                        name in excluded_test_paths
                        and flit_boundary is not None
                        and not name.startswith(f"{flit_boundary[0]}/")
                        and not in_nested_project(name)
                        and all(
                            PurePosixPath(reference).as_posix() != name
                            for reference in flit_boundary[1]
                        )
                        and not any(
                            fnmatchcase(name, pattern) for pattern in flit_boundary[2]
                        )
                    ):
                        # Test-only credentials never enter a product PoC image.
                        continue
                raise ValueError("PINNED_CONTEXT_SECRET_FILE_DENIED")
            target = root.joinpath(*parts)
            try:
                target.resolve(strict=True).relative_to(root)
                if any(
                    parent.is_symlink()
                    for parent in target.parents
                    if parent != root and parent.is_relative_to(root)
                ):
                    raise ValueError("PINNED_CONTEXT_UNSAFE")
                before = target.lstat()
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or getattr(before, "st_file_attributes", 0) & 0x400
                ):
                    raise ValueError("PINNED_CONTEXT_UNSAFE")
            except OSError as error:
                raise ValueError("PINNED_CONTEXT_UNSAFE") from error
            object_name = object_id.decode("ascii", errors="strict")
            size = git("cat-file", "-s", object_name)
            if size.returncode != 0:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
            try:
                blob_size = int(size.stdout.strip())
            except ValueError as error:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE") from error
            if blob_size + total_bytes > _MAX_PINNED_CONTEXT_BYTES:
                raise ValueError("PINNED_CONTEXT_TOO_LARGE")
            content = git("cat-file", "blob", object_name)
            if content.returncode != 0 or len(content.stdout) != blob_size:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
            raw = content.stdout
            add_member(archive, name, raw, 0o755 if mode == b"100755" else 0o644)
            names.add(name.casefold())
        for name, raw in sorted(wheels.items()):
            if (
                not name
                or name != Path(name).name
                or "/" in name
                or "\\" in name
                or not name.endswith(".whl")
            ):
                raise ValueError("WHEEL_ARCHIVE_INVALID")
            add_member(archive, f"wheels/{name}", raw)
    require_unchanged()
    result = stream.getvalue()
    if len(result) > _MAX_PINNED_CONTEXT_BYTES:
        raise ValueError("PINNED_CONTEXT_TOO_LARGE")
    return result


def _verify_context_archive(raw: bytes, dockerfile: bytes) -> None:
    if len(raw) > _MAX_PINNED_CONTEXT_BYTES:
        raise ValueError("PINNED_CONTEXT_TOO_LARGE")
    names: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                name = member.name
                parts = PurePosixPath(name).parts
                if (
                    not member.isfile()
                    or not parts
                    or name.startswith("/")
                    or "\\" in name
                    or ":" in name
                    or any(part in {"", ".", ".."} for part in parts)
                    or name.casefold() in names
                    or len(names) >= _MAX_PINNED_FILES + 1
                ):
                    raise ValueError("PINNED_CONTEXT_UNSAFE")
                total += member.size
                if total > _MAX_PINNED_CONTEXT_BYTES:
                    raise ValueError("PINNED_CONTEXT_TOO_LARGE")
                names.add(name.casefold())
                if name == "Dockerfile":
                    content = archive.extractfile(member)
                    if content is None or content.read() != dockerfile:
                        raise ValueError("PINNED_CONTEXT_UNSAFE")
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ValueError("PINNED_CONTEXT_UNSAFE") from error
    if "dockerfile" not in names:
        raise ValueError("PINNED_CONTEXT_UNSAFE")


class PortableDockerRuntime:
    """Use Docker Desktop or Engine defaults without WSL-specific paths."""

    def __init__(self, profile: SimpleExecutionProfile) -> None:
        try:
            self._executable = profile.tools["docker"].executable_path
        except KeyError:
            raise ValueError("DOCKER_NOT_CONFIGURED") from None
        self._network = "default" if profile.docker_network == "BRIDGE" else "none"
        configured_timeout = profile.max_elapsed_seconds
        self._timeout = max(
            30, 3600 if configured_timeout == "unlimited" else configured_timeout
        )
        self._build_slots = asyncio.Semaphore(profile.max_parallel_builds)
        self._container_slots = asyncio.Semaphore(profile.max_parallel_containers)
        self._container_limit = profile.max_parallel_containers
        self._offline_base_lock = asyncio.Lock()

    async def build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
        context_archive: bytes | None = None,
    ) -> str:
        gate = getattr(self, "_build_slots", None)
        if gate is None:
            return await self._build_or_reuse(
                workspace=workspace,
                dockerfile=dockerfile,
                cache_key=cache_key,
                labels=labels,
                context_archive=context_archive,
            )
        async with gate:
            return await self._build_or_reuse(
                workspace=workspace,
                dockerfile=dockerfile,
                cache_key=cache_key,
                labels=labels,
                context_archive=context_archive,
            )

    async def _build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
        context_archive: bytes | None = None,
    ) -> str:
        builder_name: str | None = None
        if context_archive is not None:
            if self._network != "none":
                raise ValueError("POC_OFFLINE_NETWORK_REQUIRED")
            _verify_context_archive(context_archive, dockerfile)
            builder = await self._run(("buildx", "inspect"), timeout_seconds=30)
            name_match = re.search(
                rb"(?m)^Name:[ \t]*([A-Za-z0-9][A-Za-z0-9_.-]{0,127})[ \t]*$",
                builder.stdout,
            )
            if (
                builder.exit_code != 0
                or builder.timed_out
                or name_match is None
                or re.search(rb"(?m)^Driver:\s*docker\s*$", builder.stdout) is None
            ):
                raise ValueError("POC_OFFLINE_BUILDER_UNSUPPORTED")
            builder_name = name_match.group(1).decode("ascii")
            cache_key += ":" + hashlib.sha256(context_archive).hexdigest()
        recipe_digest = hashlib.sha256(cache_key.encode()).hexdigest()
        tag = f"sastsimi-simple:{recipe_digest[:24]}"
        format_text = (
            '{{index .Config.Labels "sastsimi.offline-recipe-sha256"}}|{{.Id}}'
            if context_archive is not None
            else "{{.Id}}"
        )
        inspected = await self._run(
            ("image", "inspect", "--format", format_text, tag),
            timeout_seconds=30,
        )
        if inspected.exit_code == 0:
            return (
                self._offline_image_digest(inspected.stdout, recipe_digest)
                if context_archive is not None
                else self._image_digest(inspected.stdout)
            )
        args: list[str] = [
            "build",
        ]
        if builder_name is not None:
            args.extend(("--builder", builder_name))
        args.extend(("--pull=false", "--network", self._network))
        build_labels = dict(labels)
        if context_archive is not None:
            build_labels["sastsimi.offline-recipe-sha256"] = recipe_digest
        for key, value in sorted(build_labels.items()):
            args.extend(("--label", f"{key}={value}"))
        args.extend(
            ("--tag", tag, "--file", "Dockerfile", "-")
            if context_archive is not None
            else ("--tag", tag, "--file", "-", str(workspace))
        )
        built = await self._run(
            tuple(args),
            input_bytes=context_archive if context_archive is not None else dockerfile,
            timeout_seconds=self._timeout,
        )
        self._require_success("DOCKER_BUILD_FAILED", built)
        inspected = await self._run(
            ("image", "inspect", "--format", format_text, tag),
            timeout_seconds=30,
        )
        self._require_success("DOCKER_IMAGE_INSPECT_FAILED", inspected)
        return (
            self._offline_image_digest(inspected.stdout, recipe_digest)
            if context_archive is not None
            else self._image_digest(inspected.stdout)
        )

    @staticmethod
    def _offline_image_digest(raw: bytes, recipe_digest: str) -> str:
        try:
            recorded_recipe, image_id = raw.decode("ascii").strip().split("|")
        except (UnicodeError, ValueError) as error:
            raise ValueError("POC_OFFLINE_CACHE_MISMATCH") from error
        if recorded_recipe != recipe_digest:
            raise ValueError("POC_OFFLINE_CACHE_MISMATCH")
        return PortableDockerRuntime._image_digest(image_id.encode("ascii"))

    async def target_wheel_tags(self, base_image: str) -> frozenset[str] | None:
        """Probe only an already-local Linux image, without network or mounts."""

        inspected = await self._run(
            (
                "image",
                "inspect",
                "--format",
                "{{.Os}}|{{.Architecture}}|{{.Id}}",
                base_image,
            ),
            timeout_seconds=30,
        )
        if inspected.exit_code != 0 or inspected.timed_out:
            return None
        try:
            os_name, _arch, image_id = (
                inspected.stdout.decode("ascii").strip().split("|")
            )
        except (UnicodeError, ValueError):
            return None
        if os_name != "linux" or _IMAGE_DIGEST.fullmatch(image_id) is None:
            return None
        probed = await self._run(
            (
                "run",
                "--pull",
                "never",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                "--entrypoint",
                "python",
                image_id,
                "-c",
                "import json; from pip._vendor.packaging import tags; "
                "print(json.dumps([str(tag) for tag in tags.sys_tags()]))",
            ),
            timeout_seconds=60,
        )
        if probed.exit_code != 0 or probed.timed_out:
            return None
        try:
            parsed = json.loads(probed.stdout)
        except (UnicodeError, ValueError):
            return None
        if (
            not isinstance(parsed, list)
            or not parsed
            or len(parsed) > 20_000
            or any(not isinstance(tag, str) or len(tag) > 128 for tag in parsed)
        ):
            return None
        return frozenset(parsed)

    async def _probe_python_version(self, image_digest: str) -> str:
        """Read the interpreter version from a local digest, without network/mounts."""

        if _IMAGE_DIGEST.fullmatch(image_digest) is None:
            raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE")
        probed = await self._run(
            (
                "run",
                "--pull",
                "never",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--user",
                "10001:10001",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "128",
                "--cpus",
                "1",
                "--memory",
                "1g",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=16m,mode=1777",
                "--entrypoint",
                "python",
                image_digest,
                "-c",
                "import sys; "
                "print('.'.join(str(part) for part in sys.version_info[:3]))",
            ),
            timeout_seconds=30,
        )
        if probed.exit_code != 0 or probed.timed_out:
            raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE")
        try:
            version = probed.stdout.decode("ascii").strip()
        except UnicodeError as error:
            raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE") from error
        if re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", version) is None:
            raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE")
        return version

    async def probe_python_import(
        self,
        image_digest: str,
        module: str,
        identity: CheckpointIdentity,
        attempt_id: str,
    ) -> bool:
        """Smoke one built image without network, writable root, or mounts."""

        if (
            _IMAGE_DIGEST.fullmatch(image_digest) is None
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module) is None
        ):
            return False
        owner_labels = self._owner_labels(identity, attempt_id)
        if any(
            _RESOURCE_ID.fullmatch(value) is None for value in owner_labels.values()
        ):
            raise ValueError("POC_IMPORT_SMOKE_OWNER_INVALID")
        labels = {
            **owner_labels,
            "sastsimi.host": socket.gethostname(),
            "sastsimi.pid": str(os.getpid()),
            "sastsimi.purpose": "verified-import-smoke",
        }
        container_name = f"sastsimi-import-smoke-{uuid4().hex}"
        args = (
            "run",
            "--pull",
            "never",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--user",
            "10001:10001",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--cpus",
            "1",
            "--memory",
            "1g",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=16m,mode=1777",
            *(
                part
                for key, value in sorted(labels.items())
                for part in ("--label", f"{key}={value}")
            ),
            "--entrypoint",
            "python",
            image_digest,
            "-I",
            "-c",
            "import importlib; importlib.import_module(" + repr(module) + ")",
        )
        outcome: DockerCommandOutcome | None = None
        cancelled = False
        try:
            outcome = await self._run(args, timeout_seconds=30)
        except asyncio.CancelledError:
            cancelled = True
            raise
        finally:
            cleanup_task = asyncio.create_task(
                self._confirm_import_probe_removed(container_name, outcome)
            )
            cleanup_cancelled = False
            try:
                while True:
                    try:
                        await asyncio.shield(cleanup_task)
                        break
                    except asyncio.CancelledError:
                        cleanup_cancelled = True
                        if cleanup_task.done():
                            break
                cleanup_task.result()
            except ImportSmokeCleanupUnconfirmed:
                raise
            except Exception as cleanup_error:
                if cancelled or cleanup_cancelled:
                    raise asyncio.CancelledError() from cleanup_error
                raise
            if cleanup_cancelled:
                raise asyncio.CancelledError()
        assert outcome is not None
        return outcome.exit_code == 0 and not outcome.timed_out

    async def _confirm_import_probe_removed(
        self, container_name: str, outcome: DockerCommandOutcome | None
    ) -> None:
        try:
            cleanup = await self._run(
                ("rm", "--force", container_name), timeout_seconds=30
            )
            if cleanup.timed_out or (
                cleanup.exit_code != 0 and (outcome is None or outcome.timed_out)
            ):
                raise ImportSmokeCleanupUnconfirmed("POC_IMPORT_SMOKE_CLEANUP_FAILED")
            inspected = await self._run(
                ("container", "inspect", container_name), timeout_seconds=30
            )
            missing = re.fullmatch(
                rb"(?:Error(?: response from daemon)?: )?"
                rb"No such (?:container|object): "
                + re.escape(container_name.encode("ascii")),
                inspected.stderr.strip(),
            )
            if (
                inspected.timed_out
                or inspected.exit_code != 1
                or inspected.stdout.strip() not in {b"", b"[]"}
                or missing is None
            ):
                raise ImportSmokeCleanupUnconfirmed("POC_IMPORT_SMOKE_CLEANUP_FAILED")
        except ImportSmokeCleanupUnconfirmed:
            raise
        except (Exception, asyncio.CancelledError) as error:
            raise ImportSmokeCleanupUnconfirmed(
                "POC_IMPORT_SMOKE_CLEANUP_FAILED"
            ) from error

    async def local_base_image_digest(self, base_image: str) -> str:
        """Require an already-local Linux image; never trigger an implicit pull."""

        inspected = await self._run(
            ("image", "inspect", "--format", "{{.Os}}|{{.Id}}", base_image),
            timeout_seconds=30,
        )
        if inspected.exit_code != 0 or inspected.timed_out:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE")
        try:
            os_name, image_id = inspected.stdout.decode("ascii").strip().split("|")
        except (UnicodeError, ValueError) as error:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE") from error
        if os_name != "linux" or _IMAGE_DIGEST.fullmatch(image_id) is None:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE")
        return image_id

    async def resolve_offline_base(
        self, base_image: str, *, allow_pull: bool
    ) -> tuple[str, str]:
        """Resolve the fixed public base locally, or pull it once in AUTO mode.

        Only the built-in Python base is eligible for a networked pull.  A
        user-supplied image digest remains an explicit, already-local input so
        AUTO mode cannot fetch an arbitrary image named by repository content.
        """

        lock = getattr(self, "_offline_base_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self._offline_base_lock = lock
        async with lock:
            unavailable: ValueError | None = None
            try:
                return await self.local_base_image_digest(base_image), "LOCAL"
            except ValueError as error:
                unavailable = error
                if not allow_pull or base_image != _OFFLINE_BASE_IMAGE:
                    raise
            pulled = await self._run(
                ("image", "pull", _OFFLINE_BASE_IMAGE), timeout_seconds=300
            )
            if pulled.exit_code != 0 or pulled.timed_out:
                assert unavailable is not None
                raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE") from unavailable
            try:
                digest = await self.local_base_image_digest(_OFFLINE_BASE_IMAGE)
            except ValueError as error:
                raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE") from error
            return digest, "AUTO_PULLED"

    async def pin_local_base(self, image_digest: str) -> str:
        """Give the inspected local image an immutable-by-content build reference."""

        if _IMAGE_DIGEST.fullmatch(image_digest) is None:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE")
        tag = f"sastsimi-offline-base:{image_digest.removeprefix('sha256:')}"
        tagged = await self._run(
            ("image", "tag", image_digest, tag), timeout_seconds=30
        )
        if tagged.exit_code != 0 or tagged.timed_out:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE")
        inspected = await self._run(
            ("image", "inspect", "--format", "{{.Id}}", tag),
            timeout_seconds=30,
        )
        if (
            inspected.exit_code != 0
            or inspected.timed_out
            or inspected.stdout.decode("ascii", errors="replace").strip()
            != image_digest
        ):
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        return tag

    async def download_python_wheels(
        self,
        *,
        base_image: str,
        requirements: tuple[str, ...],
        timeout_seconds: int,
    ) -> bytes:
        """Resolve safe PEP 508 requirements without mounting repository source.

        This is the only network-enabled Docker operation in the portable PoC
        path. It downloads binary dependency artifacts into a temporary host
        directory using a digest-pinned local Python image; the resulting PoC
        image and every executed PoC container remain fully offline.
        """

        if self._network != "none":
            raise ValueError("POC_AUTO_BUNDLE_NETWORK_REQUIRED")
        if not re.fullmatch(r"sastsimi-offline-base:[0-9a-f]{64}", base_image):
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE")
        if not requirements or timeout_seconds < 1 or timeout_seconds > 900:
            raise ValueError("POC_AUTO_BUNDLE_REQUIREMENTS_INVALID")
        accepted: list[str] = []
        for raw in requirements:
            if (
                not raw
                or raw != raw.strip()
                or any(char in raw for char in "\r\n\x00\\")
            ):
                raise ValueError("POC_AUTO_BUNDLE_REQUIREMENTS_INVALID")
            try:
                requirement = Requirement(raw)
            except InvalidRequirement as error:
                raise ValueError("POC_AUTO_BUNDLE_REQUIREMENTS_INVALID") from error
            if requirement.url is not None:
                raise ValueError("POC_AUTO_BUNDLE_REQUIREMENTS_INVALID")
            accepted.append(raw)
        if len(accepted) > 512 or len("\n".join(accepted).encode("utf-8")) > 128 * 1024:
            raise ValueError("POC_AUTO_BUNDLE_REQUIREMENTS_INVALID")
        with _wheel_download_workspace() as root:
            if any(char in str(root) for char in ",\x00"):
                raise ValueError("POC_AUTO_BUNDLE_WORKSPACE_UNSAFE")
            requirements_path = root / "requirements.txt"
            output = root / "wheels"
            output.mkdir()
            requirements_path.write_text("\n".join(accepted) + "\n", encoding="utf-8")
            container_name = f"sastsimi-wheel-{uuid4().hex}"
            args = (
                "run",
                "--pull",
                "never",
                "--rm",
                "--name",
                container_name,
                "--network",
                "bridge",
                "--read-only",
                "--user",
                "0:0",
                "--security-opt",
                "no-new-privileges",
                "--cap-drop",
                "ALL",
                "--pids-limit",
                "128",
                "--cpus",
                "1",
                "--memory",
                "1g",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
                "--mount",
                f"type=bind,source={root},target=/bundle",
                "--env",
                "HOME=/tmp",
                "--env",
                "PIP_CONFIG_FILE=/dev/null",
                "--env",
                "PIP_NO_INPUT=1",
                "--env",
                "PIP_DISABLE_PIP_VERSION_CHECK=1",
                "--entrypoint",
                "python",
                base_image,
                "-m",
                "pip",
                "download",
                "--no-cache-dir",
                "--retries",
                _PIP_DOWNLOAD_RETRIES,
                "--timeout",
                _PIP_DOWNLOAD_TIMEOUT_SECONDS,
                "--only-binary=:all:",
                "--dest",
                "/bundle/wheels",
                "--requirement",
                "/bundle/requirements.txt",
            )
            outcome: DockerCommandOutcome | None = None
            try:
                outcome = await self._run(args, timeout_seconds=timeout_seconds)
            finally:
                cleanup = await self._run(
                    ("rm", "--force", container_name), timeout_seconds=30
                )
                if cleanup.timed_out:
                    raise ValueError("POC_AUTO_BUNDLE_CLEANUP_FAILED")
                if cleanup.exit_code != 0 and (outcome is None or outcome.timed_out):
                    # A timed-out Docker client can leave a delayed container
                    # creation request behind. An immediate absence probe is
                    # not sufficient proof after failed removal.
                    raise ValueError("POC_AUTO_BUNDLE_CLEANUP_FAILED")
                inspected = await self._run(
                    ("container", "inspect", container_name), timeout_seconds=30
                )
                missing = re.fullmatch(
                    rb"(?:Error(?: response from daemon)?: )?"
                    rb"No such (?:container|object): "
                    + re.escape(container_name.encode("ascii")),
                    inspected.stderr.strip(),
                )
                if (
                    inspected.timed_out
                    or inspected.exit_code != 1
                    # Docker CLI emits an empty JSON array on stdout even when
                    # inspect fails with "No such container" on stderr.
                    or inspected.stdout.strip() not in {b"", b"[]"}
                    or missing is None
                ):
                    raise ValueError("POC_AUTO_BUNDLE_CLEANUP_FAILED")
            if outcome.exit_code != 0 or outcome.timed_out:
                raise DockerOperationError("POC_AUTO_BUNDLE_DOWNLOAD_FAILED", outcome)
            return build_wheel_bundle(output)

    async def create_container(
        self,
        image_digest: str,
        labels: Mapping[str, str],
    ) -> str:
        gate = getattr(self, "_container_slots", None)
        if gate is None:
            return await self._create_container(image_digest, labels)
        async with gate:
            return await self._create_container(image_digest, labels)

    async def _create_container(
        self, image_digest: str, labels: Mapping[str, str]
    ) -> str:
        if _IMAGE_DIGEST.fullmatch(image_digest) is None:
            raise ValueError("IMAGE_DIGEST_REQUIRED")
        if labels.get("sastsimi.owner") == "simple-runtime":
            analysis_id = labels.get("sastsimi.analysis-id")
            if not analysis_id:
                raise ValueError("DOCKER_OWNER_LABELS_INCOMPLETE")
            active = await self._run(
                (
                    "ps",
                    "--quiet",
                    "--filter",
                    "label=sastsimi.owner=simple-runtime",
                    "--filter",
                    f"label=sastsimi.analysis-id={analysis_id}",
                    "--filter",
                    "status=running",
                ),
                timeout_seconds=30,
            )
            self._require_success("DOCKER_CONTAINER_COUNT_FAILED", active)
            if len(active.stdout) >= _MAX_OUTPUT:
                raise DockerOperationError("DOCKER_CONTAINER_COUNT_TRUNCATED")
            if len(active.stdout.splitlines()) >= getattr(self, "_container_limit", 1):
                raise DockerOperationError("DOCKER_CONTAINER_LIMIT_REACHED")
        args: list[str] = [
            "create",
            "--network",
            "none",
            "--user",
            "10001:10001",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            "256",
            "--cpus",
            "2",
            "--memory",
            "2g",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
            "--env",
            "HOME=/tmp",
        ]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        args.extend(("--entrypoint", "sleep", image_digest, "infinity"))
        created = await self._run(tuple(args), timeout_seconds=60)
        self._require_success("DOCKER_CREATE_FAILED", created)
        container_id = created.stdout.decode("ascii", errors="strict").strip()
        self._require_resource_id(container_id)
        try:
            await self._require_success_call(
                "DOCKER_START_FAILED", ("start", container_id)
            )
        except (DockerOperationError, asyncio.CancelledError):
            if labels.get("sastsimi.owner") == "simple-runtime":
                try:
                    await self._remove_with_expected_labels(container_id, labels)
                except (DockerOperationError, OSError, ValueError):
                    pass
            raise
        return container_id

    async def materialize_poc(
        self,
        container_id: str,
        content: bytes,
        content_digest: str,
    ) -> str:
        self._require_resource_id(container_id)
        if hashlib.sha256(content).hexdigest() != content_digest:
            raise ValueError("POC_CONTENT_DIGEST_MISMATCH")
        path = "/tmp/sastsimi-poc-candidate"
        written = await self._run(
            (
                "exec",
                "-i",
                container_id,
                "sh",
                "-c",
                f"rm -f {path} && cat > {path}",
            ),
            input_bytes=content,
            timeout_seconds=30,
        )
        self._require_success("DOCKER_POC_MATERIALIZATION_FAILED", written)
        await self._require_success_call(
            "DOCKER_POC_PERMISSION_FAILED",
            ("exec", container_id, "chmod", "0500", path),
        )
        return path

    async def execute(
        self,
        container_id: str,
        argv: tuple[str, ...],
        timeout_ms: int,
        *,
        working_directory: str,
    ) -> DockerCommandOutcome:
        self._require_resource_id(container_id)
        if not argv or not working_directory.startswith("/"):
            raise ValueError("DOCKER_EXEC_INPUT_INVALID")
        return await self._run(
            ("exec", "--workdir", working_directory, container_id, *argv),
            timeout_seconds=max(1, timeout_ms // 1000),
        )

    async def inspect(self, container_id: str) -> DockerContainerState:
        self._require_resource_id(container_id)
        outcome = await self._run(("inspect", container_id), timeout_seconds=30)
        self._require_success("DOCKER_INSPECT_FAILED", outcome)
        try:
            item = json.loads(outcome.stdout)[0]
            config = item["Config"]
            host = item["HostConfig"]
            state = item["State"]
            labels = config.get("Labels") or {}
            return DockerContainerState(
                container_id=str(item["Id"]),
                image_digest=str(item["Image"]),
                user=str(config["User"]),
                network_mode=str(host["NetworkMode"]),
                privileged=bool(host["Privileged"]),
                read_only_rootfs=bool(host["ReadonlyRootfs"]),
                running=bool(state["Running"]),
                exit_code=int(state["ExitCode"]),
                health_status=None,
                labels={str(key): str(value) for key, value in labels.items()},
            )
        except (
            IndexError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise DockerOperationError(
                "DOCKER_INSPECT_OUTPUT_INVALID",
                outcome,
            ) from error

    @staticmethod
    def _owner_labels(identity: CheckpointIdentity, attempt_id: str) -> dict[str, str]:
        return {
            "sastsimi.owner": "simple-runtime",
            "sastsimi.analysis-id": identity.analysis_id,
            "sastsimi.workspace-id": identity.workspace_id,
            "sastsimi.commit-id": identity.commit_id,
            "sastsimi.hypothesis-id": identity.hypothesis_id or "analysis",
            "sastsimi.attempt-id": attempt_id,
        }

    async def remove_owned(
        self, container_id: str, identity: CheckpointIdentity, attempt_id: str
    ) -> bool:
        return await self._remove_with_expected_labels(
            container_id, self._owner_labels(identity, attempt_id)
        )

    async def has_owned_attempt_container(
        self, identity: CheckpointIdentity, attempt_id: str
    ) -> bool:
        """Prove absence, or report presence, without modifying any container."""
        if _RESOURCE_ID.fullmatch(attempt_id) is None:
            raise ValueError("DOCKER_ATTEMPT_ID_INVALID")
        expected = self._owner_labels(identity, attempt_id)
        if any(_RESOURCE_ID.fullmatch(value) is None for value in expected.values()):
            raise ValueError("DOCKER_OWNER_LABELS_INVALID")
        args = (
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            *(
                part
                for key, value in expected.items()
                for part in ("--filter", f"label={key}={value}")
            ),
        )
        for attempt in range(3):
            listed = await self._run(args, timeout_seconds=30)
            if listed.exit_code == 0 and not listed.timed_out:
                break
            if attempt < 2:
                await asyncio.sleep(0.25 * (2**attempt))
        self._require_success("DOCKER_OWNED_ATTEMPT_LIST_FAILED", listed)
        if len(listed.stdout) >= _MAX_OUTPUT:
            raise DockerOperationError("DOCKER_OWNED_ATTEMPT_LIST_TRUNCATED", listed)
        found = False
        for raw in listed.stdout.splitlines():
            try:
                container_id = raw.decode("ascii", errors="strict")
            except UnicodeDecodeError as error:
                raise DockerOperationError(
                    "DOCKER_OWNED_ATTEMPT_LIST_INVALID", listed
                ) from error
            if _FULL_CONTAINER_ID.fullmatch(container_id) is None:
                raise DockerOperationError("DOCKER_OWNED_ATTEMPT_LIST_INVALID", listed)
            state = await self.inspect(container_id)
            if state.container_id != container_id or any(
                state.labels.get(key) != value for key, value in expected.items()
            ):
                raise DockerOperationError("DOCKER_OWNED_ATTEMPT_MISMATCH", listed)
            found = True
        return found

    async def _remove_with_expected_labels(
        self, container_id: str, expected: Mapping[str, str]
    ) -> bool:
        state = await self.inspect(container_id)
        if state.container_id != container_id or any(
            state.labels.get(key) != value for key, value in expected.items()
        ):
            return False
        removed = await self._run(("rm", "--force", container_id), timeout_seconds=30)
        self._require_success("DOCKER_OWNED_REMOVE_FAILED", removed)
        return True

    async def sweep_orphans(self) -> tuple[str, ...]:
        for attempt in range(3):
            listed = await self._run(
                (
                    "ps",
                    "--all",
                    "--quiet",
                    "--filter",
                    "label=sastsimi.owner=simple-runtime",
                ),
                timeout_seconds=30,
            )
            if listed.exit_code == 0 and not listed.timed_out:
                break
            if attempt < 2:
                # Only this read-only query is safe to repeat before ownership
                # inspection; create/remove operations retain their own checks.
                await asyncio.sleep(0.25 * (2**attempt))
        self._require_success("DOCKER_OWNED_LIST_FAILED", listed)
        if len(listed.stdout) >= _MAX_OUTPUT:
            raise DockerOperationError("DOCKER_OWNED_LIST_TRUNCATED")
        removed: list[str] = []
        for raw in listed.stdout.splitlines():
            container_id = raw.decode("ascii", errors="strict").strip()
            if _RESOURCE_ID.fullmatch(container_id) is None:
                continue
            try:
                state = await self.inspect(container_id)
            except DockerOperationError:
                continue
            labels = state.labels
            if (
                state.container_id != container_id
                or labels.get("sastsimi.owner") != "simple-runtime"
                or labels.get("sastsimi.host") != socket.gethostname()
            ):
                continue
            try:
                pid = int(labels["sastsimi.pid"])
                identity = CheckpointIdentity(
                    analysis_id=labels["sastsimi.analysis-id"],
                    workspace_id=labels["sastsimi.workspace-id"],
                    commit_id=labels["sastsimi.commit-id"],
                    hypothesis_id=(
                        None
                        if labels["sastsimi.hypothesis-id"] == "analysis"
                        else labels["sastsimi.hypothesis-id"]
                    ),
                )
                attempt_id = labels["sastsimi.attempt-id"]
            except (KeyError, TypeError, ValueError):
                continue
            if pid > 0 and self._pid_known_dead(pid):
                if await self.remove_owned(container_id, identity, attempt_id):
                    removed.append(container_id)
        return tuple(removed)

    @staticmethod
    def _pid_known_dead(pid: int, *, platform_name: str | None = None) -> bool:
        if (platform_name or os.name) != "posix" or pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False

    async def _require_success_call(
        self,
        code: str,
        argv: Sequence[str],
    ) -> None:
        outcome = await self._run(tuple(argv), timeout_seconds=60)
        self._require_success(code, outcome)

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        process = await asyncio.create_subprocess_exec(
            str(self._executable),
            *args,
            stdin=(
                asyncio.subprocess.PIPE
                if input_bytes is not None
                else asyncio.subprocess.DEVNULL
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._environment(),
        )
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_tail = bytearray()
        stderr_tail = bytearray()
        tasks = [
            asyncio.create_task(self._read_output_tail(process.stdout, stdout_tail)),
            asyncio.create_task(self._read_output_tail(process.stderr, stderr_tail)),
            asyncio.create_task(process.wait()),
        ]
        if process.stdin is not None:
            assert input_bytes is not None
            tasks.append(
                asyncio.create_task(self._write_input(process.stdin, input_bytes))
            )
        try:
            _, pending = await asyncio.wait(tasks, timeout=timeout_seconds)
            if pending:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await asyncio.gather(*tasks, return_exceptions=True)
                return DockerCommandOutcome(
                    exit_code=-1,
                    stdout=bytes(stdout_tail),
                    stderr=bytes(stderr_tail),
                    timed_out=True,
                )
            await asyncio.gather(*tasks)
            return DockerCommandOutcome(
                exit_code=process.returncode or 0,
                stdout=bytes(stdout_tail),
                stderr=bytes(stderr_tail),
                timed_out=False,
            )
        except asyncio.CancelledError:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    @staticmethod
    async def _read_output_tail(stream: asyncio.StreamReader, tail: bytearray) -> None:
        while chunk := await stream.read(64 * 1024):
            if len(chunk) >= _MAX_OUTPUT:
                tail[:] = chunk[-_MAX_OUTPUT:]
            else:
                overflow = len(tail) + len(chunk) - _MAX_OUTPUT
                if overflow > 0:
                    del tail[:overflow]
                tail.extend(chunk)

    @staticmethod
    async def _write_input(stream: asyncio.StreamWriter, payload: bytes) -> None:
        try:
            for offset in range(0, len(payload), 64 * 1024):
                stream.write(payload[offset : offset + 64 * 1024])
                await stream.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            stream.close()
            try:
                await stream.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "HOME",
            "USERPROFILE",
            "PROGRAMFILES",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
        }
        return {key: value for key, value in os.environ.items() if key in allowed}

    @staticmethod
    def _require_success(code: str, outcome: DockerCommandOutcome) -> None:
        if outcome.timed_out or outcome.exit_code != 0:
            raise DockerOperationError(code, outcome)

    @staticmethod
    def _require_resource_id(value: str) -> None:
        if _RESOURCE_ID.fullmatch(value) is None:
            raise ValueError("DOCKER_RESOURCE_ID_INVALID")

    @staticmethod
    def _image_digest(raw: bytes) -> str:
        value = raw.decode("ascii", errors="strict").strip()
        if _IMAGE_DIGEST.fullmatch(value) is None:
            raise DockerOperationError("DOCKER_IMAGE_DIGEST_INVALID")
        return value


class PortableContainerFactory:
    def __init__(self, docker: PortableDockerRuntime) -> None:
        self._docker = docker
        self._swept = False

    async def acquire(self, checkpoint: StageCheckpoint) -> str:
        if checkpoint.image_digest is None or checkpoint.attempt_id is None:
            raise ValueError("SIMPLE_DOCKER_CHECKPOINT_INCOMPLETE")
        if not self._swept:
            await self._docker.sweep_orphans()
            self._swept = True
        identity = checkpoint.identity
        return await self._docker.create_container(
            checkpoint.image_digest,
            {
                **self._docker._owner_labels(identity, checkpoint.attempt_id),
                "sastsimi.host": socket.gethostname(),
                "sastsimi.pid": str(os.getpid()),
            },
        )

    async def release(self, checkpoint: StageCheckpoint, container_id: str) -> bool:
        if checkpoint.attempt_id is None:
            return False
        return await self._docker.remove_owned(
            container_id, checkpoint.identity, checkpoint.attempt_id
        )


class AutoWheelBundleCache:
    """Bounded, analysis-scoped archive reuse for one application process."""

    def __init__(
        self, *, max_bytes: int = 128 * 1024 * 1024, max_entries: int = 8
    ) -> None:
        if max_bytes < 1 or max_entries < 1:
            raise ValueError("POC_AUTO_BUNDLE_CACHE_LIMIT_INVALID")
        self._max_bytes = max_bytes
        self._max_entries = max_entries
        self._stored_bytes = 0
        self._entries: OrderedDict[tuple[str, str], tuple[str, bytes]] = OrderedDict()
        # A binding is never a replacement for the exact archive/image CAS.
        # It only carries a requirement independently proven by a pinned
        # source import, a unique wheel provider, and an offline image smoke.
        self._verified_imports: OrderedDict[tuple[str, ...], tuple[str, str]] = (
            OrderedDict()
        )
        self._ambiguous_verified_imports: OrderedDict[tuple[str, ...], None] = (
            OrderedDict()
        )
        self._max_verified_imports = max_entries * 8
        # Waiters keep their lock alive; idle keys do not accumulate forever.
        self._locks: weakref.WeakValueDictionary[tuple[str, str], asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    def get(self, analysis_id: str, content_key: str) -> bytes | None:
        key = (analysis_id, content_key)
        entry = self._entries.get(key)
        if entry is None:
            return None
        digest, archive = entry
        if hashlib.sha256(archive).hexdigest() != digest:
            self._entries.pop(key)
            self._stored_bytes -= len(archive)
            return None
        self._entries.move_to_end(key)
        return archive

    def put(self, analysis_id: str, content_key: str, archive: bytes) -> None:
        if len(archive) > self._max_bytes:
            return
        key = (analysis_id, content_key)
        previous = self._entries.pop(key, None)
        if previous is not None:
            self._stored_bytes -= len(previous[1])
        self._entries[key] = (hashlib.sha256(archive).hexdigest(), archive)
        self._stored_bytes += len(archive)
        while (
            self._stored_bytes > self._max_bytes
            or len(self._entries) > self._max_entries
        ):
            _, (_, evicted) = self._entries.popitem(last=False)
            self._stored_bytes -= len(evicted)

    def lock_for(self, analysis_id: str, content_key: str) -> asyncio.Lock:
        key = (analysis_id, content_key)
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    def verified_imports(self, scope: tuple[str, ...]) -> tuple[str, ...]:
        requirements: list[str] = []
        for _module, requirement, _decision_hash in self.verified_import_bindings(
            scope
        ):
            if requirement not in requirements:
                requirements.append(requirement)
        return tuple(requirements)

    def verified_import_bindings(
        self, scope: tuple[str, ...]
    ) -> tuple[tuple[str, str, str], ...]:
        bindings: list[tuple[str, str, str]] = []
        for key, (requirement, decision_hash) in tuple(self._verified_imports.items()):
            if key[:-1] == scope:
                self._verified_imports.move_to_end(key)
                bindings.append((key[-1], requirement, decision_hash))
        return tuple(bindings)

    def has_verified_import_scope(self, scope: tuple[str, ...]) -> bool:
        return any(key[: len(scope)] == scope for key in self._verified_imports)

    def put_verified_import(
        self,
        scope: tuple[str, ...],
        module: str,
        requirement: str,
        decision_hash: str,
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", decision_hash) is None:
            return
        key = (*scope, module)
        if key in self._ambiguous_verified_imports:
            return
        existing = self._verified_imports.get(key)
        if existing is not None and existing[0] != requirement:
            # Do not let a later observation re-establish a conflicted binding.
            self._verified_imports.pop(key)
            self._ambiguous_verified_imports[key] = None
            while len(self._ambiguous_verified_imports) > self._max_verified_imports:
                self._ambiguous_verified_imports.popitem(last=False)
            return
        self._verified_imports[key] = (requirement, decision_hash)
        self._verified_imports.move_to_end(key)
        while len(self._verified_imports) > self._max_verified_imports:
            self._verified_imports.popitem(last=False)


class DirectEnvironmentPreparer:
    def __init__(
        self,
        *,
        docker: PortableDockerRuntime,
        artifacts: SimpleArtifactRepository,
        workspace: Path,
        wheel_bundle_path: Path | None = None,
        wheel_bundle_sha256: str | None = None,
        offline_base_image_digest: str | None = None,
        # Keep programmatic callers on the legacy path unless the public
        # execution profile explicitly opts them into AUTO.  The profile
        # default is AUTO, but this constructor is also used by focused
        # repair and test adapters that do not provide a full Docker runtime.
        auto_dependency_bundle: bool = False,
        bundle_source: str = "OPERATOR_SUPPLIED",
        bundle_resolution_metadata: Mapping[str, object] | None = None,
        pinned_target_manifest: str | None = None,
        git_executable: str = "git",
        auto_bundle_cache: AutoWheelBundleCache | None = None,
    ) -> None:
        if (
            offline_base_image_digest is not None
            and _IMAGE_DIGEST.fullmatch(offline_base_image_digest) is None
        ):
            raise ValueError("POC_OFFLINE_BASE_IMAGE_DIGEST_INVALID")
        if bundle_source not in {"OPERATOR_SUPPLIED", "AUTO_RESOLVED"}:
            raise ValueError("POC_DEPENDENCY_BUNDLE_SOURCE_INVALID")
        self._docker = docker
        self._artifacts = artifacts
        self._workspace = workspace
        self._wheel_bundle_path = wheel_bundle_path
        self._wheel_bundle_sha256 = wheel_bundle_sha256
        self._offline_base_image_digest = offline_base_image_digest
        self._offline_base_image = offline_base_image_digest or _OFFLINE_BASE_IMAGE
        self._auto_dependency_bundle = auto_dependency_bundle
        self._auto_bundle_cache = auto_bundle_cache or AutoWheelBundleCache()
        self._bundle_source = bundle_source
        self._bundle_resolution_metadata = dict(bundle_resolution_metadata or {})
        self._pinned_target_manifest = pinned_target_manifest
        self._git_executable = git_executable

    async def offline_base_ready(self) -> bool:
        """Probe and pin the configured offline base for the active mode."""

        if self._wheel_bundle_path is None and not self._auto_dependency_bundle:
            return False
        try:
            if self._auto_dependency_bundle:
                digest, _source = await self._resolve_auto_base_digest()
            else:
                digest = await self._docker.local_base_image_digest(
                    self._offline_base_image
                )
            if (
                self._offline_base_image_digest is not None
                and digest != self._offline_base_image_digest
            ):
                return False
            await self._docker.pin_local_base(digest)
        except (OSError, RuntimeError, ValueError):
            return False
        return True

    async def _resolve_auto_base_digest(self) -> tuple[str, str]:
        """Use the resolver only for the public AUTO base on real Docker IO."""

        if isinstance(self._docker, PortableDockerRuntime):
            return await self._docker.resolve_offline_base(
                self._offline_base_image,
                allow_pull=self._offline_base_image_digest is None,
            )
        # Focused unit adapters deliberately provide only the local-image
        # contract. Their behavior remains the same while production uses the
        # explicit pull path above.
        digest = await self._docker.local_base_image_digest(self._offline_base_image)
        return digest, "LOCAL"

    @staticmethod
    def _requested_python_runtime(requirements: tuple[str, ...]) -> str | None:
        requested: str | None = None
        for raw in requirements:
            item = raw.strip()
            match = _EXPLICIT_PYTHON_RUNTIME.fullmatch(item)
            version = (
                match.group(1)
                if match is not None
                else "3.12"
                if item.casefold() == "python 3.12"
                else None
            )
            if version is None:
                if re.match(r"python(?::|\s|[0-9])", item, re.IGNORECASE):
                    raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_INVALID")
                continue
            if requested is not None:
                requested_parts = requested.split(".")
                version_parts = version.split(".")
                common_length = min(len(requested_parts), len(version_parts))
                if requested_parts[:common_length] != version_parts[:common_length]:
                    raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_CONFLICT")
            if requested is None or version.count(".") > requested.count("."):
                requested = version
        return requested

    def _require_configured_python_runtime(self, requested: str | None) -> None:
        if requested is not None and requested != "3.12":
            if self._offline_base_image_digest is None:
                raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_DIGEST_REQUIRED")

    async def _verified_python_runtime_metadata(
        self, requested: str | None, base_digest: str
    ) -> dict[str, str]:
        # AUTO's built-in 3.12 base remains on the existing path.  An
        # operator-configured digest must prove even an explicit 3.12 claim.
        if requested is None or self._offline_base_image_digest is None:
            return {}
        observed = await self._docker._probe_python_version(base_digest)
        return self._observed_python_runtime_metadata(requested, observed)

    @staticmethod
    def _observed_python_runtime_metadata(
        requested: str, observed: str
    ) -> dict[str, str]:
        if re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", observed) is None:
            raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE")
        expected_parts = requested.split(".")
        if observed.split(".")[: len(expected_parts)] != expected_parts:
            raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_MISMATCH")
        return {
            "python_runtime_requirement": requested,
            "python_runtime_observed_version": observed,
        }

    async def preflight_offline_repair(self) -> OfflineBaseSmoke:
        """Prove the configured local image can run the offline browser PoC."""

        if self._offline_base_image_digest is None:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_DIGEST_REQUIRED")
        if self._wheel_bundle_path is None or self._wheel_bundle_sha256 is None:
            raise ValueError("POC_WHEEL_ARCHIVE_PAIR_REQUIRED")
        digest = await self._docker.local_base_image_digest(
            self._offline_base_image_digest
        )
        if digest != self._offline_base_image_digest:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        outcome = await self._docker._run(
            (
                "run",
                "--pull",
                "never",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--user",
                "10001:10001",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "128",
                "--cpus",
                "1",
                "--memory",
                "1g",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
                "--env",
                "HOME=/tmp",
                "--env",
                "XDG_CACHE_HOME=/tmp/cache",
                digest,
                "python",
                "-c",
                _OFFLINE_BROWSER_SMOKE_SCRIPT,
            ),
            timeout_seconds=60,
        )
        if outcome.timed_out or outcome.exit_code != 0:
            raise ValueError("POC_OFFLINE_BASE_SMOKE_FAILED")
        try:
            proof = json.loads(outcome.stdout)
        except (UnicodeError, ValueError) as error:
            raise ValueError("POC_OFFLINE_BASE_SMOKE_FAILED") from error
        if not isinstance(proof, dict):
            raise ValueError("POC_OFFLINE_BASE_SMOKE_FAILED")
        browser = proof.get("browser_command")
        version = proof.get("python_version")
        if (
            proof.get("marker") != _OFFLINE_BROWSER_SMOKE_MARKER
            or not isinstance(browser, str)
            or not browser.startswith("/")
            or PurePosixPath(browser).name not in _OFFLINE_BROWSER_COMMANDS
            or ".." in PurePosixPath(browser).parts
            or not isinstance(version, str)
            or re.fullmatch(r"3\.12\.[0-9]+", version) is None
        ):
            raise ValueError("POC_OFFLINE_BASE_SMOKE_FAILED")
        return OfflineBaseSmoke(
            base_image_digest=digest,
            browser_command=browser,
            python_version=version,
            smoke_output_digest="sha256:" + hashlib.sha256(outcome.stdout).hexdigest(),
        )

    def _require_repair_base_digest(self, checkpoint: StageCheckpoint) -> None:
        if len(checkpoint.recovery_decision_refs) > 64:
            raise ValueError("POC_OFFLINE_REPAIR_EVIDENCE_INVALID")
        for artifact_ref in checkpoint.recovery_decision_refs:
            try:
                with self._artifacts.artifacts.open_verified_bounded(
                    artifact_ref, 64 * 1024
                ) as stream:
                    evidence = json.loads(stream.read())
            except (OSError, UnicodeError, ValueError) as error:
                raise ValueError("POC_OFFLINE_REPAIR_EVIDENCE_INVALID") from error
            if not isinstance(evidence, dict):
                raise ValueError("POC_OFFLINE_REPAIR_EVIDENCE_INVALID")
            if evidence.get("kind") != "simple_offline_environment_repair":
                continue
            if (
                evidence.get("identity") != checkpoint.identity.model_dump(mode="json")
                or evidence.get("new_base_image_digest")
                != self._offline_base_image_digest
            ):
                raise ValueError("POC_OFFLINE_REPAIR_BASE_MISMATCH")

    @property
    def offline_mode(self) -> bool:
        return self._wheel_bundle_path is not None or self._auto_dependency_bundle

    def validate_requirements(
        self, requirements: tuple[str, ...], *, commit_id: str
    ) -> None:
        """Check syntax; pinned source presence stays fail-closed in prepare."""

        if self.offline_mode:
            self._offline_agent_requirements(requirements, commit_id=commit_id)

    async def prepare(
        self,
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
        requirements: tuple[str, ...],
    ) -> ReproductionEnvironment:
        if self._wheel_bundle_path is not None:
            return await self._prepare_offline(checkpoint, prior, requirements)
        if self._auto_dependency_bundle:
            return await self._prepare_auto_bundle(checkpoint, prior, requirements)
        if self._requested_python_runtime(requirements) not in {None, "3.12"}:
            raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_BUNDLE_REQUIRED")
        target_manifest = self._target_manifest_path(prior)
        if (
            target_manifest is None
            and (self._workspace / "pyproject.toml").is_file()
            and self._target_install_layer("pyproject.toml")
        ):
            target_manifest = "pyproject.toml"
        target_install = self._target_install_layer(target_manifest)
        dockerfile_path = self._workspace / "Dockerfile"
        if dockerfile_path.is_file():
            git_install = (
                self._repository_git_install_layer()
                if target_install.startswith(
                    b"RUN python -m pip install --no-cache-dir uv\n"
                )
                else b""
            )
            dockerfile = self._portable_repository_dockerfile(
                dockerfile_path.read_bytes()
            ) + (
                b"\nUSER root\nWORKDIR /workspace\nCOPY . /workspace\n"
                + git_install
                + target_install
                + b"RUN chmod -R a+rX /workspace && mkdir -p /tmp "
                b"&& chmod 1777 /tmp\n"
            )
            source = "REPOSITORY_DOCKERFILE"
        else:
            dockerfile = self._generated_dockerfile(target_manifest)
            source = "GENERATED"
        recovery_patch = self._recovery_patch(checkpoint)
        dockerfile += recovery_patch
        dockerfile_ref = self._artifacts.put_bytes(dockerfile, "text/x-dockerfile")
        labels = PortableDockerRuntime._owner_labels(
            checkpoint.identity, checkpoint.attempt_id or "initial"
        )
        attempt_refs: list[StoredDataRef] = []
        degraded = False
        while True:
            try:
                image_digest = await self._docker.build_or_reuse(
                    workspace=self._workspace,
                    dockerfile=dockerfile,
                    cache_key=(
                        f"{checkpoint.identity.commit_id}:{dockerfile_ref.content_hash}"
                    ),
                    labels=labels,
                )
            except DockerOperationError as error:
                attempt_refs.append(
                    self._build_attempt_ref(
                        checkpoint, source, dockerfile_ref, "FAILED", error
                    )
                )
                if (
                    not degraded
                    and not recovery_patch
                    and not target_install
                    and target_manifest in {None, "requirements.txt", "pyproject.toml"}
                    and self._dependency_install_failed(error, dockerfile)
                ):
                    dockerfile = self._generated_dockerfile(include_dependencies=False)
                    dockerfile_ref = self._artifacts.put_bytes(
                        dockerfile, "text/x-dockerfile"
                    )
                    source = "GENERATED_NO_INSTALL"
                    degraded = True
                    continue
                recipe_ref = self._artifacts.put_json(
                    self._recipe(
                        checkpoint,
                        source,
                        dockerfile_ref,
                        target_manifest,
                        requirements,
                        attempt_refs,
                        degraded,
                        status="BLOCKED",
                    )
                )
                raise DockerBuildAttemptsError(
                    error, tuple(attempt_refs), recipe_ref
                ) from error
            attempt_refs.append(
                self._build_attempt_ref(
                    checkpoint, source, dockerfile_ref, "BUILT", None
                )
            )
            recipe_ref = self._artifacts.put_json(
                self._recipe(
                    checkpoint,
                    source,
                    dockerfile_ref,
                    target_manifest,
                    requirements,
                    attempt_refs,
                    degraded,
                    status="BUILT",
                    image_digest=image_digest,
                )
            )
            return ReproductionEnvironment(recipe_ref, image_digest)

    def _pinned_tree_paths(self, *, commit_id: str) -> frozenset[str]:
        """Validate the checkout and list only paths from its pinned commit.

        AUTO mode may use a bridge-network resolver for public wheels.  It must
        prove that the manifest/Dockerfile selection comes from the immutable
        analysis commit before that networked action begins.  Untracked files
        are deliberately absent from this tree and cannot influence selection.
        """

        if _COMMIT_ID.fullmatch(commit_id) is None:
            raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
        try:
            root = self._workspace.resolve(strict=True)
            diff = subprocess.run(
                (
                    self._git_executable,
                    "-C",
                    str(root),
                    "diff",
                    "--quiet",
                    "--no-ext-diff",
                    "--no-textconv",
                    commit_id,
                    "--",
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
            if diff.returncode == 1:
                raise ValueError("PINNED_CONTEXT_CHANGED")
            if diff.returncode != 0:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
            listed = subprocess.run(
                (
                    self._git_executable,
                    "-C",
                    str(root),
                    "ls-tree",
                    "-r",
                    "-z",
                    commit_id,
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            raise ValueError("PINNED_CONTEXT_UNAVAILABLE") from error
        if listed.returncode != 0 or len(listed.stdout) > 16 * 1024 * 1024:
            raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
        entries = [entry for entry in listed.stdout.split(b"\0") if entry]
        if len(entries) > _MAX_PINNED_FILES:
            raise ValueError("PINNED_CONTEXT_TOO_LARGE")
        paths: set[str] = set()
        for entry in entries:
            try:
                _header, raw_path = entry.split(b"\t", 1)
                path = raw_path.decode("utf-8")
            except (UnicodeDecodeError, ValueError) as error:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE") from error
            pure = PurePosixPath(path)
            if (
                not path
                or pure.is_absolute()
                or ".." in pure.parts
                or "\\" in path
                or "\x00" in path
            ):
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
            paths.add(path)
        return frozenset(paths)

    def _pinned_manifest_bytes(self, path: str, *, commit_id: str) -> bytes:
        pure = PurePosixPath(path)
        if (
            not path
            or pure.is_absolute()
            or ".." in pure.parts
            or "\\" in path
            or ":" in path
            or "\x00" in path
            or pure.name not in {"requirements.txt", "pyproject.toml"}
            or _COMMIT_ID.fullmatch(commit_id) is None
        ):
            raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
        try:
            result = subprocess.run(
                (
                    self._git_executable,
                    "-C",
                    str(self._workspace.resolve(strict=True)),
                    "show",
                    f"{commit_id}:{path}",
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNAVAILABLE") from error
        if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
            raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNAVAILABLE")
        return result.stdout

    def _pinned_dockerfile_bytes(self, *, commit_id: str) -> bytes:
        """Read only the repository's committed default Dockerfile."""

        if _COMMIT_ID.fullmatch(commit_id) is None:
            raise ValueError("POC_AUTO_BUNDLE_DOCKERFILE_UNAVAILABLE")
        try:
            result = subprocess.run(
                (
                    self._git_executable,
                    "-C",
                    str(self._workspace.resolve(strict=True)),
                    "show",
                    f"{commit_id}:Dockerfile",
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("POC_AUTO_BUNDLE_DOCKERFILE_UNAVAILABLE") from error
        if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
            raise ValueError("POC_AUTO_BUNDLE_DOCKERFILE_UNAVAILABLE")
        return result.stdout

    @staticmethod
    def _literal_dockerfile_pip_requirements(dockerfile: bytes) -> tuple[str, ...]:
        """Accept only standalone literal pip-install declarations.

        Repository Dockerfiles are untrusted build instructions.  This parser
        never executes them: it extracts only PEP 508 package literals from a
        small, shell-free subset and leaves OS installers, URLs, files, and
        compound commands out of the generated Python runtime.
        """

        try:
            lines = dockerfile.decode("utf-8").splitlines()
        except UnicodeError:
            return ()
        selected: list[str] = []
        allowed_flags = {
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--no-input",
            "--prefer-binary",
        }
        for raw in lines:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.fullmatch(r"(?i:RUN)\s+(.+)", stripped)
            if match is None:
                continue
            command = match.group(1).strip()
            if command.endswith("\\") or any(
                token in command for token in ("&&", "||", ";", "|", "`", "$", ">", "<")
            ):
                continue
            try:
                words = shlex.split(command, posix=True, comments=False)
            except ValueError:
                continue
            prefixes = (
                ("pip", "install"),
                ("pip3", "install"),
                ("python", "-m", "pip", "install"),
                ("python3", "-m", "pip", "install"),
            )
            prefix = next(
                (value for value in prefixes if tuple(words[: len(value)]) == value),
                None,
            )
            if prefix is None:
                continue
            values = words[len(prefix) :]
            if not values:
                continue
            requirements: list[str] = []
            safe = True
            for value in values:
                if value in allowed_flags:
                    continue
                if value.startswith("-") or any(
                    character in value for character in "\\\r\n\x00"
                ):
                    safe = False
                    break
                try:
                    parsed_requirement = Requirement(value)
                except InvalidRequirement:
                    safe = False
                    break
                if parsed_requirement.url is not None:
                    safe = False
                    break
                requirements.append(str(parsed_requirement))
            if not safe:
                continue
            for parsed_value in requirements:
                if parsed_value not in selected:
                    selected.append(parsed_value)
        return tuple(selected)

    @staticmethod
    def _canonical_offline_requirements(
        requirements: tuple[str, ...],
        source_paths: tuple[str, ...],
        *,
        commit_id: str,
    ) -> tuple[str, ...]:
        """Translate resolved packages back into the existing offline contract."""

        return (
            *(f"pip:{requirement}" for requirement in requirements),
            *(
                f"Source checkout at commit {commit_id} containing {path}"
                for path in source_paths
            ),
        )

    def _auto_bundle_requirements(
        self,
        target_manifest: str,
        manifest: bytes,
        requirements: tuple[str, ...],
        *,
        commit_id: str,
    ) -> tuple[str, ...]:
        extra, _source_paths = self._offline_agent_requirements(
            requirements, commit_id=commit_id
        )
        selected: list[str] = []

        def append(value: str) -> None:
            try:
                parsed = Requirement(value)
            except InvalidRequirement as error:
                raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED") from error
            if parsed.url is not None:
                raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
            normalized = str(parsed)
            if normalized not in selected:
                selected.append(normalized)

        if target_manifest.endswith("requirements.txt"):
            try:
                lines = manifest.decode("utf-8").splitlines()
            except UnicodeError as error:
                raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED") from error
            for raw in lines:
                item = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
                if not item or item.startswith("#"):
                    continue
                if item.startswith("-") or "\\" in item:
                    raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
                append(item)
        else:
            try:
                project = tomllib.loads(manifest.decode("utf-8"))
            except (UnicodeError, tomllib.TOMLDecodeError) as error:
                raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED") from error
            tool = project.get("tool")
            if isinstance(tool, dict) and any(key in tool for key in ("uv", "poetry")):
                raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
            metadata = project.get("project")
            if not isinstance(metadata, dict):
                raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
            dynamic = metadata.get("dynamic", [])
            dependencies = metadata.get("dependencies", [])
            if (
                not isinstance(dynamic, list)
                or "dependencies" in dynamic
                or not isinstance(dependencies, list)
            ):
                raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
            for item in dependencies:
                if not isinstance(item, str):
                    raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
                append(item)
            build = project.get("build-system")
            if isinstance(build, dict):
                build_requires = build.get("requires", [])
                if not isinstance(build_requires, list):
                    raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
                for item in build_requires:
                    if not isinstance(item, str):
                        raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED")
                    append(item)
        for item in extra:
            append(item)
        return tuple(selected)

    @staticmethod
    def _missing_distribution_name(error: DockerOperationError) -> str | None:
        outcome = error.outcome
        if outcome is None or outcome.timed_out:
            return None
        match = re.search(
            rb"No matching distribution found for\s+"
            rb"([A-Za-z0-9][A-Za-z0-9_.-]*)",
            outcome.stderr,
            re.IGNORECASE,
        )
        if match is None:
            return None
        return canonicalize_name(match.group(1).decode("ascii"))

    @staticmethod
    def _matches_agent_requirement_name(raw: str, name: str) -> bool:
        item = raw[4:].strip() if raw.casefold().startswith("pip:") else raw
        try:
            return canonicalize_name(Requirement(item).name) == name
        except InvalidRequirement:
            return False

    def _bound_missing_import(self, checkpoint: StageCheckpoint) -> str | None:
        """Accept only the current RULE import replan bound to execution evidence."""

        if (
            checkpoint.attempt_number < 2
            or checkpoint.recovery_lineage_id is None
            or not checkpoint.recovery_decision_refs
        ):
            return None
        ref = checkpoint.recovery_decision_refs[-1]
        if ref not in checkpoint.input_refs:
            return None
        try:
            record = json.loads(self._artifacts.read_bounded(ref, 64 * 1024))
            if not isinstance(record, dict):
                return None
            original = record.get("original_error")
            decision = record.get("decision")
            if not isinstance(original, dict) or not isinstance(decision, dict):
                return None
            evidence_refs = tuple(
                StoredDataRef.model_validate(item)
                for item in original.get("evidence_refs", ())
            )
            if (
                record.get("kind") != "simple_recovery_decision"
                or record.get("identity") != checkpoint.identity.model_dump(mode="json")
                or record.get("stage") != SimpleStage.POC_EXECUTION_DONE.value
                or record.get("decision_origin") != "RULE"
                or record.get("attempt") != checkpoint.attempt_number - 1
                or not isinstance(record.get("attempt_id"), str)
                or not record["attempt_id"]
                or record["attempt_id"] == checkpoint.attempt_id
                or original.get("code") != "POC_RUNTIME_IMPORT_FAILED"
                or original.get("retryable") is not True
                or decision.get("action") != RecoveryAction.REPLAN_ENVIRONMENT.value
                or decision.get("category") != RecoveryCategory.ENVIRONMENT.value
                or decision.get("environment_patch")
                or not evidence_refs
                or len(evidence_refs) > 16
                or any(item not in checkpoint.input_refs for item in evidence_refs)
            ):
                return None
            execution_bound = False
            for evidence_ref in evidence_refs:
                try:
                    evidence = json.loads(
                        self._artifacts.read_bounded(evidence_ref, 64 * 1024)
                    )
                except (OSError, UnicodeError, ValueError, TypeError, sqlite3.Error):
                    continue
                if (
                    isinstance(evidence, dict)
                    and evidence.get("kind") == "simple_poc_execution"
                    and evidence.get("attempt_id") == record["attempt_id"]
                    and evidence.get("timed_out") is False
                    and type(evidence.get("exit_code")) is int
                    and evidence["exit_code"] != 0
                ):
                    execution_bound = True
                    break
            if not execution_bound:
                return None
            diagnostic = record.get("diagnostic_excerpt")
            if not isinstance(diagnostic, str) or len(diagnostic) > 4096:
                return None
            matches = set(_MISSING_TOP_LEVEL_IMPORT.findall(diagnostic))
            return next(iter(matches)) if len(matches) == 1 else None
        except (OSError, UnicodeError, ValueError, TypeError, sqlite3.Error):
            return None

    def _pinned_source_imports(
        self, module: str, pinned_paths: frozenset[str], *, commit_id: str
    ) -> bool:
        """Prove the missing top-level module appears in bounded pinned code."""

        if _COMMIT_ID.fullmatch(commit_id) is None:
            return False
        try:
            root = self._workspace.resolve(strict=True)
        except OSError:
            return False
        inspected = 0
        total_bytes = 0
        for path in sorted(pinned_paths):
            if not path.endswith(".py"):
                continue
            try:
                if is_test_only_path(root, path):
                    continue
            except ValueError:
                return False
            inspected += 1
            if inspected > 512:
                return False
            candidate = root.joinpath(*PurePosixPath(path).parts)
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                if not candidate.resolve(strict=True).is_relative_to(root):
                    continue
                blob_ref = f"{commit_id}:{path}"
                size_result = subprocess.run(
                    (self._git_executable, "-C", str(root), "cat-file", "-s", blob_ref),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
                if size_result.returncode != 0:
                    return False
                raw_size = size_result.stdout.strip()
                if len(raw_size) > 20 or not raw_size.isdigit():
                    return False
                blob_size = int(raw_size)
                if blob_size > 256 * 1024 or total_bytes + blob_size > 4 * 1024 * 1024:
                    return False
                blob = subprocess.run(
                    (self._git_executable, "-C", str(root), "show", blob_ref),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
                if blob.returncode != 0:
                    return False
                if len(blob.stdout) != blob_size:
                    return False
                total_bytes += blob_size
                tree = ast.parse(blob.stdout, filename=path)
            except (
                OSError,
                UnicodeError,
                SyntaxError,
                ValueError,
                subprocess.TimeoutExpired,
            ):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(
                    alias.name.split(".", 1)[0] == module for alias in node.names
                ):
                    return True
                if isinstance(node, ast.ImportFrom) and (
                    node.level == 0
                    and node.module is not None
                    and node.module.split(".", 1)[0] == module
                ):
                    return True
        return False

    @staticmethod
    def _unique_wheel_provider(
        bundle_raw: bytes, module: str, agent_requirements: tuple[str, ...]
    ) -> str | None:
        """Match one explicit PEP 508 requirement to one wheel exporting module."""

        candidates: list[str] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(bundle_raw), mode="r:*") as archive:
                for member in archive:
                    if not member.isfile() or not member.name.endswith(".whl"):
                        continue
                    wheel_stream = archive.extractfile(member)
                    if wheel_stream is None:
                        return None
                    wheel_bytes = wheel_stream.read()
                    with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as wheel:
                        names = set(wheel.namelist())
                        provides_module = False
                        for name in names:
                            parts = name.split("/")
                            if len(parts) == 1:
                                site_parts = parts
                            elif (
                                len(parts) >= 3
                                and parts[0].endswith(".data")
                                and parts[1] in {"purelib", "platlib"}
                            ):
                                site_parts = parts[2:]
                            else:
                                site_parts = parts
                            leaf = site_parts[-1]
                            native_extension = leaf.endswith((".so", ".pyd"))
                            if (
                                len(site_parts) == 1
                                and (
                                    leaf == f"{module}.py"
                                    or native_extension
                                    and leaf.startswith(f"{module}.")
                                )
                                or len(site_parts) >= 2
                                and site_parts[0] == module
                                and (leaf.endswith(".py") or native_extension)
                            ):
                                provides_module = True
                                break
                        if not provides_module:
                            continue
                        metadata_paths = [
                            name
                            for name in names
                            if name.endswith(".dist-info/METADATA")
                            and name.count("/") == 1
                        ]
                        if len(metadata_paths) != 1:
                            return None
                        metadata_info = wheel.getinfo(metadata_paths[0])
                        if metadata_info.file_size > 64 * 1024:
                            return None
                        metadata = BytesParser().parsebytes(wheel.read(metadata_info))
                        wheel_name, wheel_version, _build, _tags = parse_wheel_filename(
                            member.name
                        )
                        if canonicalize_name(
                            metadata.get("Name", "")
                        ) != canonicalize_name(wheel_name) or metadata.get(
                            "Version"
                        ) != str(wheel_version):
                            return None
                        matched = []
                        for raw in agent_requirements:
                            parsed = Requirement(raw)
                            if (
                                parsed.url is None
                                and not parsed.extras
                                and parsed.marker is None
                                and canonicalize_name(parsed.name) == wheel_name
                                and parsed.specifier.contains(
                                    wheel_version, prereleases=True
                                )
                            ):
                                matched.append(raw)
                        if len(matched) != 1:
                            return None
                        candidates.append(matched[0])
        except (
            OSError,
            ValueError,
            RuntimeError,
            EOFError,
            KeyError,
            tarfile.TarError,
            zipfile.BadZipFile,
            InvalidWheelFilename,
            InvalidRequirement,
        ):
            return None
        return candidates[0] if len(candidates) == 1 else None

    async def _prepare_auto_bundle(
        self,
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
        requirements: tuple[str, ...],
    ) -> ReproductionEnvironment:
        if self._docker._network != "none":
            raise ValueError("POC_AUTO_BUNDLE_NETWORK_REQUIRED")
        requested_runtime = self._requested_python_runtime(requirements)
        self._require_configured_python_runtime(requested_runtime)
        pinned_paths = self._pinned_tree_paths(commit_id=checkpoint.identity.commit_id)
        target_manifest = self._target_manifest_path(prior)
        if target_manifest is not None and target_manifest not in pinned_paths:
            raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNAVAILABLE")
        if target_manifest is None:
            for name in ("requirements.txt", "pyproject.toml"):
                if name in pinned_paths:
                    target_manifest = name
                    break
        manifest: bytes
        input_kind: str
        delegated_requirements = requirements
        dockerfile_input_ref: StoredDataRef | None = None
        protected_requirements: tuple[str, ...] = ()
        provenance_source_path: str | None = None
        provenance_sha256 = "NO_MANIFEST"
        agent_requirements, _agent_source_paths = self._offline_agent_requirements(
            requirements, commit_id=checkpoint.identity.commit_id
        )
        if target_manifest is None:
            extra_requirements, source_paths = self._offline_agent_requirements(
                requirements, commit_id=checkpoint.identity.commit_id
            )
            dockerfile_requirements: tuple[str, ...] = ()
            if "Dockerfile" in pinned_paths:
                pinned_dockerfile = self._pinned_dockerfile_bytes(
                    commit_id=checkpoint.identity.commit_id
                )
                dockerfile_requirements = self._literal_dockerfile_pip_requirements(
                    pinned_dockerfile
                )
                if dockerfile_requirements:
                    dockerfile_input_ref = self._artifacts.put_bytes(
                        pinned_dockerfile, "text/x-dockerfile"
                    )
            requested = tuple(
                dict.fromkeys((*dockerfile_requirements, *extra_requirements))
            )
            protected_requirements = dockerfile_requirements
            if dockerfile_requirements:
                # A Dockerfile is an environment hint, not trusted build code.
                # Its literal package list is resolved once, then installed into
                # the existing offline generated image.  OS packages and service
                # topology remain explicitly out of scope for this derived mode.
                manifest = canonical_bytes(
                    {
                        "kind": "sastsimi_dockerfile_literal_pip_requirements_v1",
                        "dockerfile_sha256": hashlib.sha256(
                            pinned_dockerfile
                        ).hexdigest(),
                        "requirements": requested,
                        "required_source_paths": source_paths,
                    }
                )
                input_kind = "DOCKERFILE_LITERAL_PIP_REQUIREMENTS"
                provenance_source_path = "Dockerfile"
                provenance_sha256 = hashlib.sha256(pinned_dockerfile).hexdigest()
                delegated_requirements = (
                    *((f"python:{requested_runtime}",) if requested_runtime else ()),
                    *self._canonical_offline_requirements(
                        requested,
                        source_paths,
                        commit_id=checkpoint.identity.commit_id,
                    ),
                )
            elif extra_requirements:
                # A PoC can require a small, explicit runtime library even
                # when the target project is intentionally un-packaged.  The
                # canonical input document gives the resolver and cache an
                # auditable identity without inventing a project manifest.
                requested = extra_requirements
                manifest = canonical_bytes(
                    {
                        "kind": "sastsimi_explicit_poc_requirements_v1",
                        "requirements": requested,
                        "required_source_paths": source_paths,
                    }
                )
                input_kind = "EXPLICIT_POC_REQUIREMENTS"
            else:
                # A stdlib-only project has nothing to resolve. Preserve the
                # existing offline build path rather than requiring an otherwise
                # unnecessary packaging manifest.
                scope_prefix = (
                    checkpoint.identity.analysis_id,
                    checkpoint.identity.workspace_id,
                    checkpoint.identity.commit_id,
                    provenance_sha256,
                )
                if not self._auto_bundle_cache.has_verified_import_scope(scope_prefix):
                    return await self._prepare_without_auto_bundle(
                        checkpoint,
                        prior,
                        requirements,
                        target_manifest=target_manifest,
                    )
                requested = ()
                manifest = canonical_bytes(
                    {
                        "kind": "sastsimi_explicit_poc_requirements_v1",
                        "requirements": (),
                        "required_source_paths": (),
                    }
                )
                input_kind = "EXPLICIT_POC_REQUIREMENTS"
        else:
            manifest = self._pinned_manifest_bytes(
                target_manifest, commit_id=checkpoint.identity.commit_id
            )
            requested = self._auto_bundle_requirements(
                target_manifest,
                manifest,
                requirements,
                commit_id=checkpoint.identity.commit_id,
            )
            protected_requirements = self._auto_bundle_requirements(
                target_manifest,
                manifest,
                (),
                commit_id=checkpoint.identity.commit_id,
            )
            input_kind = "TARGET_MANIFEST"
            provenance_source_path = target_manifest
            provenance_sha256 = hashlib.sha256(manifest).hexdigest()
        scope_prefix = (
            checkpoint.identity.analysis_id,
            checkpoint.identity.workspace_id,
            checkpoint.identity.commit_id,
            provenance_sha256,
        )
        if not requested and not self._auto_bundle_cache.has_verified_import_scope(
            scope_prefix
        ):
            # An empty requirements file (or a package with no declared
            # dependencies) does not need a resolver. The normal build stays
            # offline and still fails closed if its packaging metadata needs
            # an unavailable build dependency.
            return await self._prepare_without_auto_bundle(
                checkpoint, prior, requirements, target_manifest=target_manifest
            )
        base_digest, base_source = await self._resolve_auto_base_digest()
        if (
            self._offline_base_image_digest is not None
            and base_digest != self._offline_base_image_digest
        ):
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        runtime_metadata = await self._verified_python_runtime_metadata(
            requested_runtime, base_digest
        )
        import_scope = (
            *scope_prefix,
            base_digest,
            runtime_metadata.get("python_runtime_observed_version")
            or requested_runtime
            or "3.12",
        )
        verified_bindings = self._auto_bundle_cache.verified_import_bindings(
            import_scope
        )
        reused_requirements = tuple(
            dict.fromkeys(requirement for _, requirement, _ in verified_bindings)
        )
        if reused_requirements:
            requested = tuple(dict.fromkeys((*requested, *reused_requirements)))
            delegated_requirements = tuple(
                dict.fromkeys(
                    (
                        *delegated_requirements,
                        *(f"pip:{item}" for item in reused_requirements),
                    )
                )
            )
            # Synthetic AUTO documents describe the effective resolver input.
            # Recomputing them keeps the existing exact wheel CAS truthful.
            if input_kind == "EXPLICIT_POC_REQUIREMENTS":
                manifest = canonical_bytes(
                    {
                        "kind": "sastsimi_explicit_poc_requirements_v1",
                        "requirements": requested,
                        "required_source_paths": source_paths,
                    }
                )
            elif input_kind == "DOCKERFILE_LITERAL_PIP_REQUIREMENTS":
                manifest = canonical_bytes(
                    {
                        "kind": "sastsimi_dockerfile_literal_pip_requirements_v1",
                        "dockerfile_sha256": provenance_sha256,
                        "requirements": requested,
                        "required_source_paths": source_paths,
                    }
                )
        if not requested:
            return await self._prepare_without_auto_bundle(
                checkpoint, prior, requirements, target_manifest=target_manifest
            )
        base_reference = await self._docker.pin_local_base(base_digest)
        # Marker evaluation belongs to the resolver container, not this host.
        # Keep even conditional repository pins protected from Agent omission.
        protected_names = {
            canonicalize_name(Requirement(item).name) for item in protected_requirements
        }
        agent_names = {
            canonicalize_name(Requirement(item).name) for item in agent_requirements
        }
        omitted_agent_requirements: list[str] = []
        omission_attempt_refs: list[StoredDataRef] = []
        while True:
            cache_key = hashlib.sha256(
                canonical_bytes(
                    {
                        "kind": "simple_auto_wheel_bundle_v1",
                        "base_image_digest": base_digest,
                        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                        "requirements": requested,
                    }
                )
            ).hexdigest()
            bundle_raw = self._auto_bundle_cache.get(
                checkpoint.identity.analysis_id, cache_key
            )
            if bundle_raw is not None:
                break
            lock = self._auto_bundle_cache.lock_for(
                checkpoint.identity.analysis_id, cache_key
            )
            async with lock:
                bundle_raw = self._auto_bundle_cache.get(
                    checkpoint.identity.analysis_id, cache_key
                )
                if bundle_raw is not None:
                    break
                try:
                    bundle_raw = await self._docker.download_python_wheels(
                        base_image=base_reference,
                        requirements=requested,
                        timeout_seconds=_AUTO_BUNDLE_DOWNLOAD_TIMEOUT_SECONDS,
                    )
                except DockerOperationError as error:
                    attempt_ref = self._auto_bundle_attempt_ref(
                        checkpoint,
                        base_digest=base_digest,
                        manifest=manifest,
                        requirements=requested,
                        input_kind=input_kind,
                        provenance_source_path=provenance_source_path,
                        protected_requirements=protected_requirements,
                        error=error,
                    )
                    missing_name = self._missing_distribution_name(error)
                    removable = tuple(
                        item
                        for item in requested
                        if missing_name is not None
                        and canonicalize_name(Requirement(item).name) == missing_name
                        and missing_name in agent_names
                        and missing_name not in protected_names
                    )
                    if not removable or len(requested) == len(removable):
                        raise DependencyBundleResolutionError(
                            error, (*omission_attempt_refs, attempt_ref)
                        ) from error
                    assert missing_name is not None
                    omitted_agent_requirements.extend(removable)
                    omission_attempt_refs.append(attempt_ref)
                    requested = tuple(
                        item
                        for item in requested
                        if canonicalize_name(Requirement(item).name) != missing_name
                    )
                    delegated_requirements = tuple(
                        item
                        for item in delegated_requirements
                        if not self._matches_agent_requirement_name(item, missing_name)
                    )
                    continue
                self._auto_bundle_cache.put(
                    checkpoint.identity.analysis_id, cache_key, bundle_raw
                )
                break
        assert bundle_raw is not None
        archive_sha256 = hashlib.sha256(bundle_raw).hexdigest()
        metadata = {
            "dependency_bundle_source": "AUTO_RESOLVED",
            "dependency_resolution_network": "bridge",
            "dependency_resolution_base_image_digest": base_digest,
            "dependency_resolution_base_image_source": base_source,
            "dependency_resolution_manifest_sha256": hashlib.sha256(
                manifest
            ).hexdigest(),
            "dependency_resolution_input_kind": input_kind,
            "dependency_resolution_requirements_sha256": hashlib.sha256(
                canonical_bytes(requested)
            ).hexdigest(),
            "dependency_resolution_requirement_count": len(requested),
            "dependency_resolution_omitted_agent_requirements": (
                omitted_agent_requirements
            ),
            "dependency_resolution_omission_attempt_refs": [
                ref.model_dump(mode="json") for ref in omission_attempt_refs
            ],
        }
        if verified_bindings:
            metadata["dependency_resolution_verified_import_reuse"] = [
                {
                    "module": module,
                    "requirement": requirement,
                    "decision_sha256": decision_hash,
                }
                for module, requirement, decision_hash in verified_bindings
            ]
        if dockerfile_input_ref is not None:
            metadata.update(
                {
                    "dependency_resolution_dockerfile_ref": (
                        dockerfile_input_ref.model_dump(mode="json")
                    ),
                    "dependency_provisioning_input_kind": input_kind,
                    "environment_fidelity": "DERIVED_PYTHON_RUNTIME",
                    "environment_fidelity_reason": (
                        "Only literal Python package requirements from the "
                        "pinned repository Dockerfile were used; OS installers "
                        "and service topology were not replayed."
                    ),
                }
            )
        with tempfile.TemporaryDirectory(prefix="sastsimi-auto-wheel-") as temporary:
            archive_path = Path(temporary) / "bundle.tar"
            archive_path.write_bytes(bundle_raw)
            delegated = DirectEnvironmentPreparer(
                docker=self._docker,
                artifacts=self._artifacts,
                workspace=self._workspace,
                wheel_bundle_path=archive_path,
                wheel_bundle_sha256=archive_sha256,
                offline_base_image_digest=base_digest,
                auto_dependency_bundle=False,
                bundle_source="AUTO_RESOLVED",
                bundle_resolution_metadata=metadata,
                pinned_target_manifest=target_manifest,
                git_executable=self._git_executable,
            )
            environment = await delegated._prepare_offline(
                checkpoint,
                prior,
                delegated_requirements,
                auto_runtime_observation=_AutoRuntimeObservation(
                    base_digest=base_digest,
                    requested=requested_runtime,
                    observed=runtime_metadata.get("python_runtime_observed_version"),
                    operator_configured=self._offline_base_image_digest is not None,
                ),
            )
            missing_import = self._bound_missing_import(checkpoint)
            if missing_import is not None and self._pinned_source_imports(
                missing_import,
                pinned_paths,
                commit_id=checkpoint.identity.commit_id,
            ):
                provider = self._unique_wheel_provider(
                    bundle_raw, missing_import, agent_requirements
                )
                if provider is not None:
                    try:
                        smoke_passed = await self._docker.probe_python_import(
                            environment.image_digest,
                            missing_import,
                            checkpoint.identity,
                            checkpoint.attempt_id or "initial",
                        )
                    except ImportSmokeCleanupUnconfirmed:
                        raise
                    except (DockerOperationError, OSError, RuntimeError, ValueError):
                        smoke_passed = False
                    if smoke_passed:
                        self._auto_bundle_cache.put_verified_import(
                            import_scope,
                            missing_import,
                            provider,
                            checkpoint.recovery_decision_refs[-1].content_hash,
                        )
            return environment

    async def _prepare_without_auto_bundle(
        self,
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
        requirements: tuple[str, ...],
        *,
        target_manifest: str | None,
    ) -> ReproductionEnvironment:
        requested_runtime = self._requested_python_runtime(requirements)
        if requested_runtime is None or (
            requested_runtime == "3.12" and self._offline_base_image_digest is None
        ):
            delegated = DirectEnvironmentPreparer(
                docker=self._docker,
                artifacts=self._artifacts,
                workspace=self._workspace,
                auto_dependency_bundle=False,
                git_executable=self._git_executable,
            )
            return await delegated.prepare(checkpoint, prior, requirements)
        if self._offline_base_image_digest is None or (
            target_manifest is not None
            and PurePosixPath(target_manifest).name != "requirements.txt"
        ):
            raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_BUNDLE_REQUIRED")

        # A stdlib-only target or an empty requirements file needs no wheels.
        if self._docker._network != "none":
            raise ValueError("POC_OFFLINE_NETWORK_REQUIRED")
        self._require_repair_base_digest(checkpoint)
        if self._recovery_patch(checkpoint):
            raise ValueError("POC_OFFLINE_RECOVERY_PATCH_UNSUPPORTED")
        base_digest, _base_source = await self._resolve_auto_base_digest()
        if base_digest != self._offline_base_image_digest:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        runtime_metadata = await self._verified_python_runtime_metadata(
            requested_runtime, base_digest
        )
        base_reference = await self._docker.pin_local_base(base_digest)
        if await self._docker.local_base_image_digest(base_reference) != base_digest:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        dockerfile = (
            f"FROM {base_reference}\n"
            "WORKDIR /workspace\n"
            "COPY . /workspace\n"
            "RUN chmod -R a+rX /workspace && mkdir -p /tmp && chmod 1777 /tmp\n"
            'CMD ["sleep", "infinity"]\n'
        ).encode("ascii")
        context = build_pinned_context(
            self._workspace,
            checkpoint.identity.commit_id,
            dockerfile,
            {},
            target_python_manifest=target_manifest,
            git_executable=self._git_executable,
        )
        _extra_requirements, required_source_paths = self._offline_agent_requirements(
            requirements, commit_id=checkpoint.identity.commit_id
        )
        if target_manifest is not None or required_source_paths:
            with tarfile.open(fileobj=io.BytesIO(context), mode="r:") as archive:
                context_paths = {member.name for member in archive}
                if target_manifest is not None:
                    try:
                        manifest_stream = archive.extractfile(target_manifest)
                    except KeyError as error:
                        raise ValueError("POC_OFFLINE_MANIFEST_EXCLUDED") from error
                    if manifest_stream is None:
                        raise ValueError("POC_OFFLINE_MANIFEST_EXCLUDED")
                    manifest_stream.read()
            if any(path not in context_paths for path in required_source_paths):
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
        dockerfile_ref = self._artifacts.put_bytes(dockerfile, "text/x-dockerfile")
        context_sha256 = hashlib.sha256(context).hexdigest()
        metadata = {
            "base_image_digest": base_digest,
            **runtime_metadata,
            "build_network": "none",
            "context_sha256": context_sha256,
        }
        cache_key = hashlib.sha256(
            canonical_bytes(
                {
                    "kind": "simple_auto_dependency_free_image_v1",
                    "commit_id": checkpoint.identity.commit_id,
                    "dockerfile_sha256": dockerfile_ref.content_hash,
                    "base_image_digest": base_digest,
                    "context_sha256": context_sha256,
                }
            )
        ).hexdigest()
        labels = PortableDockerRuntime._owner_labels(
            checkpoint.identity, checkpoint.attempt_id or "initial"
        )
        source = "GENERATED"
        try:
            image_digest = await self._docker.build_or_reuse(
                workspace=self._workspace,
                dockerfile=dockerfile,
                cache_key=cache_key,
                labels=labels,
                context_archive=context,
            )
        except DockerOperationError as error:
            attempt_refs = [
                self._build_attempt_ref(
                    checkpoint, source, dockerfile_ref, "FAILED", error
                )
            ]
            recipe_ref = self._artifacts.put_json(
                self._recipe(
                    checkpoint,
                    source,
                    dockerfile_ref,
                    target_manifest,
                    requirements,
                    attempt_refs,
                    False,
                    status="BLOCKED",
                    offline=metadata,
                )
            )
            raise DockerBuildAttemptsError(
                error, tuple(attempt_refs), recipe_ref
            ) from error
        if (
            await self._docker.local_base_image_digest(self._offline_base_image)
            != base_digest
            or await self._docker.local_base_image_digest(base_reference) != base_digest
        ):
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        attempt_refs = [
            self._build_attempt_ref(checkpoint, source, dockerfile_ref, "BUILT", None)
        ]
        recipe_ref = self._artifacts.put_json(
            self._recipe(
                checkpoint,
                source,
                dockerfile_ref,
                target_manifest,
                requirements,
                attempt_refs,
                False,
                status="BUILT",
                image_digest=image_digest,
                offline=metadata,
            )
        )
        return ReproductionEnvironment(recipe_ref, image_digest)

    def _auto_bundle_attempt_ref(
        self,
        checkpoint: StageCheckpoint,
        *,
        base_digest: str,
        manifest: bytes,
        requirements: tuple[str, ...],
        input_kind: str,
        provenance_source_path: str | None,
        protected_requirements: tuple[str, ...],
        error: DockerOperationError,
    ) -> StoredDataRef:
        stderr_ref = (
            self._artifacts.put_bytes(error.outcome.stderr, "text/plain")
            if error.outcome is not None
            else None
        )
        stdout_ref = (
            self._artifacts.put_bytes(error.outcome.stdout, "text/plain")
            if error.outcome is not None
            else None
        )
        manifest_sha256 = hashlib.sha256(manifest).hexdigest()
        receipt: dict[str, object] = {
            "kind": "simple_dependency_bundle_attempt",
            "identity": checkpoint.identity.model_dump(mode="json"),
            "attempt_id": checkpoint.attempt_id,
            "status": "FAILED",
            "dependency_bundle_source": "AUTO_RESOLVED",
            "base_image_digest": base_digest,
            "manifest_sha256": manifest_sha256,
            "dependency_resolution_input_kind": input_kind,
            "requirements_sha256": hashlib.sha256(
                canonical_bytes(requirements)
            ).hexdigest(),
            "requirement_count": len(requirements),
            "error_code": error.code,
            "stderr_ref": (
                stderr_ref.model_dump(mode="json") if stderr_ref is not None else None
            ),
            "stdout_ref": (
                stdout_ref.model_dump(mode="json") if stdout_ref is not None else None
            ),
            "timed_out": (
                error.outcome.timed_out if error.outcome is not None else False
            ),
        }
        provenance_requirements = tuple(
            item for item in protected_requirements if Requirement(item).marker is None
        )
        if (
            input_kind in {"TARGET_MANIFEST", "DOCKERFILE_LITERAL_PIP_REQUIREMENTS"}
            and provenance_source_path is not None
            and provenance_requirements
        ):
            # This is derived from the immutable commit input before any Agent
            # extras are appended.  It lets a later terminal gate prove that
            # the unavailable exact pin came from the repository, not a PoC
            # suggestion, without recording the full manifest contents.
            receipt["pinned_requirement_provenance"] = {
                "kind": "simple_pinned_requirement_provenance_v1",
                "source_kind": input_kind,
                "source_path": provenance_source_path,
                "source_sha256": manifest_sha256,
                "requirements": list(provenance_requirements),
            }
        return self._artifacts.put_json(receipt)

    async def _prepare_offline(
        self,
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
        requirements: tuple[str, ...],
        *,
        auto_runtime_observation: _AutoRuntimeObservation | None = None,
    ) -> ReproductionEnvironment:
        if self._docker._network != "none":
            raise ValueError("POC_OFFLINE_NETWORK_REQUIRED")
        if self._wheel_bundle_path is None or self._wheel_bundle_sha256 is None:
            raise ValueError("POC_WHEEL_ARCHIVE_PAIR_REQUIRED")
        requested_runtime = self._requested_python_runtime(requirements)
        self._require_configured_python_runtime(requested_runtime)
        self._require_repair_base_digest(checkpoint)
        if self._recovery_patch(checkpoint):
            raise ValueError("POC_OFFLINE_RECOVERY_PATCH_UNSUPPORTED")
        extra_python_requirements, required_source_paths = (
            self._offline_agent_requirements(
                requirements, commit_id=checkpoint.identity.commit_id
            )
        )
        pinned_paths: frozenset[str] | None = None
        if self._bundle_source == "AUTO_RESOLVED":
            # AUTO selected this path (including None) from the pinned tree
            # before the resolver ran. Do not rediscover it from the checkout.
            target_manifest = self._pinned_target_manifest
            pinned_paths = self._pinned_tree_paths(
                commit_id=checkpoint.identity.commit_id
            )
            if target_manifest is not None and target_manifest not in pinned_paths:
                raise ValueError("POC_AUTO_BUNDLE_MANIFEST_UNAVAILABLE")
        else:
            target_manifest = self._target_manifest_path(prior)
            if target_manifest is None:
                for name in ("requirements.txt", "pyproject.toml"):
                    if (self._workspace / name).is_file():
                        target_manifest = name
                        break
        if target_manifest is None and not extra_python_requirements:
            raise ValueError("POC_OFFLINE_MANIFEST_MISSING")
        if target_manifest is not None:
            manifest_directory = PurePosixPath(target_manifest).parent
            manifest_siblings = (
                manifest_directory / "requirements.txt",
                manifest_directory / "pyproject.toml",
            )
            ambiguous = (
                all(path.as_posix() in pinned_paths for path in manifest_siblings)
                if pinned_paths is not None
                else all(
                    self._workspace.joinpath(*manifest_directory.parts, name).is_file()
                    for name in ("requirements.txt", "pyproject.toml")
                )
            )
            if ambiguous:
                raise ValueError("POC_OFFLINE_MANIFEST_AMBIGUOUS")
        base_digest = await self._docker.local_base_image_digest(
            self._offline_base_image
        )
        if (
            self._offline_base_image_digest is not None
            and base_digest != self._offline_base_image_digest
        ):
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        if auto_runtime_observation is None:
            runtime_metadata = await self._verified_python_runtime_metadata(
                requested_runtime, base_digest
            )
        else:
            if (
                self._bundle_source != "AUTO_RESOLVED"
                or auto_runtime_observation.base_digest != base_digest
                or auto_runtime_observation.requested != requested_runtime
            ):
                raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE")
            if auto_runtime_observation.operator_configured:
                if requested_runtime is None:
                    if auto_runtime_observation.observed is not None:
                        raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE")
                    runtime_metadata = {}
                else:
                    if auto_runtime_observation.observed is None:
                        raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE")
                    runtime_metadata = self._observed_python_runtime_metadata(
                        requested_runtime, auto_runtime_observation.observed
                    )
            else:
                if (
                    requested_runtime not in {None, "3.12"}
                    or auto_runtime_observation.observed is not None
                ):
                    raise ValueError("POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE")
                runtime_metadata = {}
        tags = await self._docker.target_wheel_tags(base_digest)
        base_reference = await self._docker.pin_local_base(base_digest)
        bundle = import_wheel_bundle(
            self._wheel_bundle_path,
            self._wheel_bundle_sha256,
            self._artifacts,
            target_tags=tags,
        )
        wheel_raw = self._artifacts.read(bundle.archive_ref)
        wheels: dict[str, bytes] = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(wheel_raw), mode="r:*") as archive:
                for name in bundle.wheel_names:
                    member = archive.getmember(name)
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError("POC_OFFLINE_WHEEL_ARTIFACT_INVALID")
                    wheels[name] = stream.read()
        except (KeyError, OSError, tarfile.TarError) as error:
            raise ValueError("POC_OFFLINE_WHEEL_ARTIFACT_INVALID") from error
        dockerfile = self._offline_dockerfile(
            target_manifest, base_reference, extra_python_requirements
        )
        if pinned_paths is None:
            pinned_paths = self._pinned_tree_paths(
                commit_id=checkpoint.identity.commit_id
            )
        omitted_foreign_runtime_paths = _foreign_runtime_paths(
            pinned_paths, target_manifest
        )
        context = build_pinned_context(
            self._workspace,
            checkpoint.identity.commit_id,
            dockerfile,
            wheels,
            target_python_manifest=target_manifest,
            git_executable=self._git_executable,
        )
        try:
            with tarfile.open(fileobj=io.BytesIO(context), mode="r:") as archive:
                paths = {member.name for member in archive}
                if target_manifest is not None:
                    manifest_member = archive.getmember(target_manifest)
                    manifest_stream = archive.extractfile(manifest_member)
                    if manifest_stream is None:
                        raise ValueError("POC_OFFLINE_MANIFEST_EXCLUDED")
                    manifest = manifest_stream.read()
                else:
                    manifest = canonical_bytes(
                        {
                            "kind": "sastsimi_explicit_poc_requirements_v1",
                            "requirements": extra_python_requirements,
                            "required_source_paths": required_source_paths,
                        }
                    )
        except KeyError as error:
            raise ValueError("POC_OFFLINE_MANIFEST_EXCLUDED") from error
        if any(path not in paths for path in required_source_paths):
            raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
        if target_manifest is not None:
            self._validate_offline_manifest(target_manifest, manifest, paths)
        dockerfile_ref = self._artifacts.put_bytes(dockerfile, "text/x-dockerfile")
        manifest_sha256 = hashlib.sha256(manifest).hexdigest()
        context_sha256 = hashlib.sha256(context).hexdigest()
        metadata = {
            "wheel_archive_ref": bundle.archive_ref.model_dump(mode="json"),
            "wheel_archive_sha256": bundle.archive_sha256,
            "dependency_bundle_source": self._bundle_source,
            "manifest_sha256": manifest_sha256,
            "dependency_provisioning_input_kind": (
                "TARGET_MANIFEST"
                if target_manifest is not None
                else "EXPLICIT_POC_REQUIREMENTS"
            ),
            "base_image_digest": base_digest,
            **runtime_metadata,
            "build_network": "none",
            "context_sha256": context_sha256,
            "omitted_foreign_runtime_path_count": len(omitted_foreign_runtime_paths),
            "omitted_foreign_runtime_paths_sha256": hashlib.sha256(
                canonical_bytes(tuple(sorted(omitted_foreign_runtime_paths)))
            ).hexdigest(),
            "omitted_foreign_runtime_secret_path_count": sum(
                EnvironmentRecipeStore._looks_secret(path)
                for path in omitted_foreign_runtime_paths
            ),
            "omitted_foreign_runtime_secret_paths_sha256": hashlib.sha256(
                canonical_bytes(
                    tuple(
                        sorted(
                            path
                            for path in omitted_foreign_runtime_paths
                            if EnvironmentRecipeStore._looks_secret(path)
                        )
                    )
                )
            ).hexdigest(),
            **self._bundle_resolution_metadata,
        }
        cache_key = offline_recipe_cache_key(
            archive_sha256=bundle.archive_sha256,
            manifest_sha256=manifest_sha256,
            commit_id=checkpoint.identity.commit_id,
            dockerfile_sha256=dockerfile_ref.content_hash,
            base_image_digest=base_digest,
            network="none",
        )
        labels = PortableDockerRuntime._owner_labels(
            checkpoint.identity, checkpoint.attempt_id or "initial"
        )
        source = "GENERATED_OFFLINE_WHEELS"
        if await self._docker.local_base_image_digest(base_reference) != base_digest:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        try:
            image_digest = await self._docker.build_or_reuse(
                workspace=self._workspace,
                dockerfile=dockerfile,
                cache_key=cache_key,
                labels=labels,
                context_archive=context,
            )
        except DockerOperationError as error:
            if error.outcome is not None and _OFFLINE_MISSING.search(
                error.outcome.stderr + b"\n" + error.outcome.stdout
            ):
                error = DockerOperationError(
                    "POC_OFFLINE_DEPENDENCY_MISSING", error.outcome
                )
            attempt_refs = [
                self._build_attempt_ref(
                    checkpoint, source, dockerfile_ref, "FAILED", error
                )
            ]
            recipe_ref = self._artifacts.put_json(
                self._recipe(
                    checkpoint,
                    source,
                    dockerfile_ref,
                    target_manifest,
                    requirements,
                    attempt_refs,
                    False,
                    status="BLOCKED",
                    offline=metadata,
                )
            )
            raise DockerBuildAttemptsError(
                error, tuple(attempt_refs), recipe_ref
            ) from error
        if (
            await self._docker.local_base_image_digest(self._offline_base_image)
            != base_digest
        ):
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        if await self._docker.local_base_image_digest(base_reference) != base_digest:
            raise ValueError("POC_OFFLINE_BASE_IMAGE_CHANGED")
        attempt_refs = [
            self._build_attempt_ref(checkpoint, source, dockerfile_ref, "BUILT", None)
        ]
        recipe_ref = self._artifacts.put_json(
            self._recipe(
                checkpoint,
                source,
                dockerfile_ref,
                target_manifest,
                requirements,
                attempt_refs,
                False,
                status="BUILT",
                image_digest=image_digest,
                offline=metadata,
            )
        )
        return ReproductionEnvironment(recipe_ref, image_digest)

    @staticmethod
    def _offline_agent_requirements(
        requirements: tuple[str, ...], *, commit_id: str
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        accepted: list[str] = []
        source_paths: list[str] = []
        for raw in requirements:
            item = raw.strip()
            if (
                _EXPLICIT_PYTHON_RUNTIME.fullmatch(item) is not None
                or item.casefold() == "python 3.12"
            ):
                continue
            pinned_source = _OFFLINE_PINNED_SOURCE.fullmatch(item)
            file_first_source = _OFFLINE_PINNED_SOURCE_FILE_FIRST.fullmatch(item)
            if pinned_source is not None or file_first_source is not None:
                if pinned_source is not None:
                    source_commit, source_path = pinned_source.groups()
                else:
                    assert file_first_source is not None
                    source_path, source_commit = file_first_source.groups()
                if (
                    source_commit != commit_id
                    or len(source_path) > 512
                    or source_path != source_path.strip()
                    or source_path.startswith("/")
                    or "\\" in source_path
                    or ":" in source_path
                    or any(ord(char) < 32 or ord(char) == 127 for char in source_path)
                    or any(part in {"", ".", ".."} for part in source_path.split("/"))
                ):
                    raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
                source_paths.append(source_path)
                continue
            explicit_python = item.casefold().startswith("pip:")
            if explicit_python:
                item = item[4:].strip()
            elif not any(
                operator in item
                for operator in ("==", ">=", "<=", "~=", "!=", ">", "<")
            ):
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
            if any(character in item for character in "\r\n\x00\\"):
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
            try:
                parsed = Requirement(item)
            except InvalidRequirement as error:
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED") from error
            if parsed.url is not None:
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
            accepted.append(item)
        return tuple(accepted), tuple(source_paths)

    @staticmethod
    def _offline_dockerfile(
        target_manifest: str | None,
        base_reference: str,
        extra_python_requirements: tuple[str, ...] = (),
    ) -> bytes:
        if target_manifest is not None:
            relative = PurePosixPath(target_manifest)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or any(character in target_manifest for character in "\\\r\n\x00")
                or relative.name not in {"requirements.txt", "pyproject.toml"}
            ):
                raise ValueError("POC_OFFLINE_MANIFEST_UNSUPPORTED")
        elif not extra_python_requirements:
            raise ValueError("POC_OFFLINE_MANIFEST_MISSING")
        if not base_reference.startswith("sastsimi-offline-base:") or not re.fullmatch(
            r"sastsimi-offline-base:[0-9a-f]{64}", base_reference
        ):
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE")
        target_install = ""
        if target_manifest is not None:
            if relative.name == "requirements.txt":
                target = f"-r {shlex.quote('/workspace/' + target_manifest)}"
            else:
                directory = "/workspace"
                if relative.parent != PurePosixPath("."):
                    directory += "/" + relative.parent.as_posix()
                target = shlex.quote(directory)
            target_install = (
                "RUN python -m pip install --no-cache-dir --no-index "
                "--find-links=/opt/sastsimi-wheels --only-binary=:all: "
                f"{target}\n"
            )
        extra_install = (
            "RUN python -m pip install --no-cache-dir --no-index "
            "--find-links=/opt/sastsimi-wheels --only-binary=:all: "
            + " ".join(
                shlex.quote(requirement) for requirement in extra_python_requirements
            )
            + "\n"
            if extra_python_requirements
            else ""
        )
        return (
            f"FROM {base_reference}\n"
            "WORKDIR /workspace\n"
            "COPY wheels/ /opt/sastsimi-wheels/\n"
            "COPY . /workspace\n"
            "RUN find /workspace -type f -exec touch -t 198001020000.00 {} +\n"
            f"{target_install}"
            f"{extra_install}"
            "RUN chmod -R a+rX /workspace && mkdir -p /tmp && chmod 1777 /tmp\n"
            'CMD ["sleep", "infinity"]\n'
        ).encode()

    @staticmethod
    def _validate_offline_manifest(
        path: str, raw: bytes, context_paths: set[str]
    ) -> None:
        def check_requirement(value: str) -> None:
            try:
                requirement = Requirement(value)
            except InvalidRequirement as error:
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED") from error
            if requirement.url is not None:
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")

        if path.endswith("requirements.txt"):
            try:
                lines = raw.decode("utf-8").splitlines()
            except UnicodeError as error:
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED") from error
            for line in lines:
                item = line.strip()
                if not item or item.startswith("#"):
                    continue
                if item.startswith("-") or "\\" in item:
                    raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
                check_requirement(re.split(r"\s+#", item, maxsplit=1)[0])
            return
        try:
            project = tomllib.loads(raw.decode("utf-8"))
        except (UnicodeError, tomllib.TOMLDecodeError) as error:
            raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED") from error
        tool = project.get("tool")
        if (
            str(PurePosixPath(path).parent / "uv.lock") in context_paths
            or isinstance(tool, dict)
            and any(key in tool for key in ("uv", "poetry"))
        ):
            raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
        metadata = project.get("project")
        if not isinstance(metadata, dict):
            raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
        dynamic = metadata.get("dynamic", [])
        if isinstance(dynamic, list) and "dependencies" in dynamic:
            raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
        for section in (metadata.get("dependencies", []),):
            if not isinstance(section, list):
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
            for item in section:
                if not isinstance(item, str):
                    raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
                check_requirement(item)
        build = project.get("build-system")
        if isinstance(build, dict):
            required = build.get("requires", [])
            if not isinstance(required, list):
                raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
            for item in required:
                if not isinstance(item, str):
                    raise ValueError("POC_OFFLINE_REQUIREMENT_UNSUPPORTED")
                check_requirement(item)

    def _build_attempt_ref(
        self,
        checkpoint: StageCheckpoint,
        source: str,
        dockerfile_ref: StoredDataRef,
        status: str,
        error: DockerOperationError | None,
    ) -> StoredDataRef:
        stderr_ref = (
            self._artifacts.put_bytes(error.outcome.stderr, "text/plain")
            if error is not None and error.outcome is not None
            else None
        )
        stdout_ref = (
            self._artifacts.put_bytes(error.outcome.stdout, "text/plain")
            if error is not None and error.outcome is not None
            else None
        )
        return self._artifacts.put_json(
            {
                "kind": "simple_docker_build_attempt",
                "identity": checkpoint.identity.model_dump(mode="json"),
                "attempt_id": checkpoint.attempt_id,
                "dockerfile_source": source,
                "dockerfile_ref": dockerfile_ref.model_dump(mode="json"),
                "status": status,
                "error_code": error.code if error is not None else None,
                "stderr_ref": (
                    stderr_ref.model_dump(mode="json")
                    if stderr_ref is not None
                    else None
                ),
                "stdout_ref": (
                    stdout_ref.model_dump(mode="json")
                    if stdout_ref is not None
                    else None
                ),
                "timed_out": (
                    error.outcome.timed_out
                    if error is not None and error.outcome is not None
                    else False
                ),
            }
        )

    @staticmethod
    def _dependency_install_failed(
        error: DockerOperationError, dockerfile: bytes
    ) -> bool:
        return bool(
            error.code == "DOCKER_BUILD_FAILED"
            and error.outcome is not None
            and not error.outcome.timed_out
            and _DEPENDENCY_INSTALL.search(dockerfile)
            and _DEPENDENCY_INSTALL.search(
                error.outcome.stderr + b"\n" + error.outcome.stdout
            )
        )

    @staticmethod
    def _recipe(
        checkpoint: StageCheckpoint,
        source: str,
        dockerfile_ref: StoredDataRef,
        target_manifest: str | None,
        requirements: tuple[str, ...],
        attempt_refs: list[StoredDataRef],
        degraded: bool,
        *,
        status: str,
        image_digest: str | None = None,
        offline: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "kind": "simple_environment_recipe",
            "analysis_id": checkpoint.identity.analysis_id,
            "workspace_id": checkpoint.identity.workspace_id,
            "commit_id": checkpoint.identity.commit_id,
            "hypothesis_id": checkpoint.identity.hypothesis_id,
            "attempt_id": checkpoint.attempt_id,
            "dockerfile_source": source,
            "dockerfile_ref": dockerfile_ref.model_dump(mode="json"),
            "target_requirements_path": (
                target_manifest
                if target_manifest is not None
                and PurePosixPath(target_manifest).name == "requirements.txt"
                else None
            ),
            "target_manifest_path": target_manifest,
            "requirements": requirements,
            "build_attempt_refs": [ref.model_dump(mode="json") for ref in attempt_refs],
            "degraded": degraded,
            "status": status,
            **(dict(offline) if offline is not None else {}),
            **({"image_digest": image_digest} if image_digest is not None else {}),
        }

    def _built_recovery_dockerfile(
        self, checkpoint: StageCheckpoint, recipe: dict[str, object]
    ) -> bytes | None:
        """Accept only a same-attempt BUILT recipe with a matching build record."""

        identity = checkpoint.identity.model_dump(mode="json")
        attempt_refs = recipe.get("build_attempt_refs")
        if (
            recipe.get("status") != "BUILT"
            or any(recipe.get(key) != identity[key] for key in identity)
            or not isinstance(recipe.get("image_digest"), str)
            or _IMAGE_DIGEST.fullmatch(str(recipe["image_digest"])) is None
            or not isinstance(attempt_refs, list)
        ):
            return None
        try:
            dockerfile_ref = StoredDataRef.model_validate(recipe.get("dockerfile_ref"))
            for raw_ref in attempt_refs:
                attempt_ref = StoredDataRef.model_validate(raw_ref)
                attempt = json.loads(self._artifacts.read(attempt_ref))
                if (
                    isinstance(attempt, dict)
                    and attempt.get("kind") == "simple_docker_build_attempt"
                    and attempt.get("identity") == identity
                    and attempt.get("attempt_id") == recipe.get("attempt_id")
                    and attempt.get("dockerfile_ref")
                    == dockerfile_ref.model_dump(mode="json")
                    and attempt.get("status") == "BUILT"
                    and attempt.get("error_code") is None
                ):
                    return self._artifacts.read(dockerfile_ref)
        except (OSError, TypeError, ValueError):
            return None
        return None

    def _recovery_patch(self, checkpoint: StageCheckpoint) -> bytes:
        decisions: list[tuple[int, StoredDataRef, str]] = []
        seen_decisions: set[StoredDataRef] = set()
        built_patches: set[str] = set()
        bound_recovery_positions: list[int] = []
        for position, ref in enumerate(checkpoint.input_refs):
            try:
                value = json.loads(self._artifacts.read(ref))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and value.get("kind") == (
                "simple_offline_environment_repair"
            ):
                if (
                    ref not in checkpoint.recovery_decision_refs
                    or value.get("identity")
                    != checkpoint.identity.model_dump(mode="json")
                    or value.get("new_base_image_digest")
                    != self._offline_base_image_digest
                ):
                    raise ValueError("POC_OFFLINE_REPAIR_BASE_MISMATCH")
                # A newly pinned base invalidates only patches preceding it.
                decisions.clear()
                seen_decisions.clear()
                built_patches.clear()
                bound_recovery_positions.clear()
                continue
            if isinstance(value, dict) and value.get("kind") == (
                "simple_environment_recipe"
            ):
                dockerfile = self._built_recovery_dockerfile(checkpoint, value)
                if dockerfile is not None:
                    marker = b"\n# SASTSIMI validated recovery patch\n"
                    applied = (
                        dockerfile.split(marker, 1)[1] if marker in dockerfile else b""
                    )
                    built_patches.update(
                        patch
                        for _, _, patch in decisions
                        if b"\n" + patch.encode("utf-8") + b"\n" in b"\n" + applied
                    )
                continue
            if not isinstance(value, dict) or value.get("kind") != (
                "simple_recovery_decision"
            ):
                continue
            decision_identity = CheckpointIdentity.model_validate(value.get("identity"))
            if decision_identity != checkpoint.identity:
                raise ValueError("RECOVERY_DECISION_IDENTITY_MISMATCH")
            decision_value = value.get("decision")
            if not isinstance(decision_value, dict):
                raise ValueError("RECOVERY_DECISION_ARTIFACT_INVALID")
            decision = RecoveryDecision.model_validate_json(
                canonical_bytes(decision_value)
            )
            if decision.action is RecoveryAction.REPLAN_ENVIRONMENT:
                original_error = value.get("original_error")
                if (
                    ref not in checkpoint.recovery_decision_refs
                    or value.get("stage") != SimpleStage.POC_EXECUTION_DONE.value
                    or value.get("decision_origin") != "RULE"
                    or not isinstance(original_error, dict)
                    or original_error.get("code") != "POC_RUNTIME_IMPORT_FAILED"
                    or decision.category is not RecoveryCategory.ENVIRONMENT
                    or decision.environment_patch
                ):
                    raise ValueError("RECOVERY_REPLAN_EVIDENCE_INVALID")
                # The initial-verification Agent supplies the new requirement;
                # earlier independent Dockerfile repairs remain in effect.
                bound_recovery_positions.append(position)
                continue
            if decision.action is not RecoveryAction.REBUILD_ENVIRONMENT:
                continue
            patch = validate_environment_patch(decision.environment_patch)
            if ref not in seen_decisions:
                decisions.append((position, ref, patch))
                seen_decisions.add(ref)
                if ref in checkpoint.recovery_decision_refs:
                    bound_recovery_positions.append(position)
        if not decisions:
            return b""
        for position, ref, patch in decisions:
            if ref in checkpoint.recovery_decision_refs:
                continue
            if patch not in built_patches or not any(
                later > position for later in bound_recovery_positions
            ):
                raise ValueError("RECOVERY_DECISION_REF_UNBOUND")
        current_ref = next(
            (
                ref
                for _, ref, _ in reversed(decisions)
                if ref in checkpoint.recovery_decision_refs
            ),
            None,
        )
        patches = list(
            dict.fromkeys(
                patch
                for _, ref, patch in decisions
                if ref == current_ref or patch in built_patches
            )
        )
        if not patches:
            return b""
        combined = (
            b"\n# SASTSIMI validated recovery patch\n"
            + "\n".join(patches).encode("utf-8")
            + b"\n"
        )
        if len(combined) > 32 * 1024:
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
        return combined

    @staticmethod
    def _portable_repository_dockerfile(dockerfile: bytes) -> bytes:
        """Keep repository Dockerfiles usable after Debian Buster EOL.

        Some real repositories still pin a Buster-based image and exact
        package versions. Debian moved those package indexes to its archive,
        so an otherwise reproducible repository Dockerfile now fails before
        the target application is built. Insert the archive configuration in
        each affected stage while preserving the repository's own build.
        """

        if b"archive.debian.org/debian" in dockerfile:
            return dockerfile
        archive_setup = (
            b"RUN sed -i "
            b"-e 's|deb.debian.org/debian|archive.debian.org/debian|g' "
            b"-e 's|security.debian.org/debian-security|"
            b"archive.debian.org/debian-security|g' "
            b"-e '/buster-updates/d' /etc/apt/sources.list "
            b"&& printf 'Acquire::Check-Valid-Until \"false\";\\n' "
            b"> /etc/apt/apt.conf.d/99archive\n"
        )
        prepared: list[bytes] = []
        for line in dockerfile.splitlines(keepends=True):
            prepared.append(line)
            normalized = line.lstrip().lower()
            if normalized.startswith(b"from ") and b"buster" in normalized:
                prepared.append(archive_setup)
        return b"".join(prepared)

    @staticmethod
    def _repository_git_install_layer() -> bytes:
        """Install Git for uv on supported Linux bases, or fail the build."""

        return (
            b"RUN if ! command -v git >/dev/null 2>&1; then "
            b"if command -v apt-get >/dev/null 2>&1; then "
            b"apt-get update && apt-get install -y --no-install-recommends "
            b"git ca-certificates && rm -rf /var/lib/apt/lists/*; "
            b"elif command -v apk >/dev/null 2>&1; then "
            b"apk add --no-cache git ca-certificates; "
            b"elif command -v dnf >/dev/null 2>&1; then "
            b"dnf install -y git ca-certificates && dnf clean all; "
            b"elif command -v microdnf >/dev/null 2>&1; then "
            b"microdnf install -y git ca-certificates && microdnf clean all; "
            b"elif command -v yum >/dev/null 2>&1; then "
            b"yum install -y git ca-certificates && yum clean all; "
            b"else echo SASTSIMI_GIT_UNAVAILABLE: "
            b"no supported package manager >&2; exit 1; fi; fi\n"
        )

    def _target_manifest_path(
        self,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> str | None:
        pro_con = prior.get(SimpleStage.PRO_CON_DONE)
        if pro_con is None:
            return None
        root = self._workspace.resolve()
        for ref in pro_con.input_refs:
            try:
                value = json.loads(self._artifacts.read(ref))
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or value.get("kind") != (
                "simple_hypothesis_proposal"
            ):
                continue
            proposal = value.get("proposal")
            locations = (
                proposal.get("code_locations") if isinstance(proposal, dict) else None
            )
            if not isinstance(locations, list):
                continue
            for location in locations:
                if not isinstance(location, str):
                    continue
                relative_text, separator, line = location.rpartition(":")
                relative = PurePosixPath(relative_text)
                if (
                    separator != ":"
                    or not line.isdigit()
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or "\\" in relative_text
                ):
                    continue
                candidate_source = root / Path(*relative.parts)
                if candidate_source.is_symlink() or any(
                    parent.is_symlink()
                    for parent in candidate_source.parents
                    if parent.is_relative_to(root)
                ):
                    continue
                try:
                    source = candidate_source.resolve(strict=True)
                except OSError:
                    continue
                if not source.is_relative_to(root):
                    continue
                if not source.is_file() or source.is_symlink():
                    continue
                current = source.parent
                while current.is_relative_to(root):
                    pyproject = current / "pyproject.toml"
                    prefer_uv = False
                    if (
                        (current / "requirements.txt").is_file()
                        and pyproject.is_file()
                        and not pyproject.is_symlink()
                    ):
                        try:
                            prefer_uv = (
                                self._uv_sync_target(
                                    current, self._read_project(pyproject)
                                )
                                is not None
                            )
                        except ValueError as error:
                            if str(error) != "TARGET_MANIFEST_INVALID":
                                raise
                    names = (
                        ("pyproject.toml", "requirements.txt")
                        if prefer_uv
                        else ("requirements.txt", "pyproject.toml")
                    )
                    for name in names:
                        candidate = current / name
                        if (
                            candidate.is_file()
                            and not candidate.is_symlink()
                            and candidate.resolve().is_relative_to(root)
                        ):
                            return candidate.relative_to(root).as_posix()
                    if current == root:
                        break
                    current = current.parent
        return None

    @staticmethod
    def _read_project(path: Path) -> dict[str, object]:
        try:
            return tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            raise ValueError("TARGET_MANIFEST_INVALID") from None

    @staticmethod
    def _uv_config(project: Mapping[str, object]) -> Mapping[str, object]:
        tool = project.get("tool")
        uv = tool.get("uv") if isinstance(tool, dict) else None
        return uv if isinstance(uv, dict) else {}

    @staticmethod
    def _workspace_pattern_matches(relative: PurePosixPath, patterns: object) -> bool:
        if not isinstance(patterns, list):
            return False

        def matches(
            path_parts: tuple[str, ...], pattern_parts: tuple[str, ...]
        ) -> bool:
            if not pattern_parts:
                return not path_parts
            if pattern_parts[0] == "**":
                return (
                    matches(path_parts, pattern_parts[1:])
                    or bool(path_parts)
                    and matches(path_parts[1:], pattern_parts)
                )
            return (
                bool(path_parts)
                and fnmatchcase(path_parts[0], pattern_parts[0])
                and matches(path_parts[1:], pattern_parts[1:])
            )

        for pattern in patterns:
            if not isinstance(pattern, str) or any(
                char in pattern for char in "\r\n\x00\\:"
            ):
                continue
            parsed = PurePosixPath(pattern)
            if parsed.is_absolute() or ".." in parsed.parts:
                continue
            if matches(relative.parts, parsed.parts):
                return True
        return False

    def _uv_sync_target(
        self, project_dir: Path, project: Mapping[str, object]
    ) -> tuple[Path, str | None] | None:
        uv_config = self._uv_config(project)
        if isinstance(uv_config.get("workspace"), dict):
            return project_dir, None

        workspace = self._workspace.resolve()
        for parent in project_dir.parents:
            if not parent.is_relative_to(workspace):
                break
            manifest = parent / "pyproject.toml"
            if not manifest.is_file():
                continue
            if manifest.is_symlink() or not manifest.resolve().is_relative_to(
                workspace
            ):
                raise ValueError("TARGET_MANIFEST_PATH_UNSAFE")
            parent_uv = self._uv_config(self._read_project(manifest))
            workspace_config = parent_uv.get("workspace")
            if not isinstance(workspace_config, dict):
                continue
            relative = PurePosixPath(project_dir.relative_to(parent).as_posix())
            if self._workspace_pattern_matches(
                relative, workspace_config.get("members")
            ) and not self._workspace_pattern_matches(
                relative, workspace_config.get("exclude")
            ):
                metadata = project.get("project")
                name = metadata.get("name") if isinstance(metadata, dict) else None
                if not isinstance(name, str) or not name.strip():
                    raise ValueError("TARGET_MANIFEST_INVALID")
                return parent, name

        sources = uv_config.get("sources")
        if isinstance(sources, dict) and sources:
            return project_dir, None
        lock = project_dir / "uv.lock"
        if lock.is_symlink():
            raise ValueError("TARGET_LOCK_PATH_UNSAFE")
        if lock.is_file():
            return project_dir, None
        return None

    def _target_install_layer(self, manifest_path: str | None) -> bytes:
        if manifest_path is None or manifest_path == "requirements.txt":
            return b""
        if any(char in manifest_path for char in "\r\n\x00\\"):
            raise ValueError("TARGET_MANIFEST_PATH_UNSAFE")
        relative = PurePosixPath(manifest_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("TARGET_MANIFEST_PATH_UNSAFE")
        host_path = self._workspace.joinpath(*relative.parts)
        root = self._workspace.resolve()
        if (
            not host_path.is_file()
            or host_path.is_symlink()
            or not host_path.resolve().is_relative_to(root)
            or any(
                parent.is_symlink()
                for parent in host_path.parents
                if parent.is_relative_to(root)
            )
        ):
            raise ValueError("TARGET_MANIFEST_PATH_UNSAFE")
        absolute = f"/workspace/{manifest_path}"
        if relative.name == "requirements.txt":
            return (
                f"RUN python -m pip install --no-cache-dir -r {shlex.quote(absolute)}\n"
            ).encode()
        if relative.name != "pyproject.toml":
            raise ValueError("TARGET_MANIFEST_UNSUPPORTED")
        project_dir = (
            "/workspace"
            if relative.parent == PurePosixPath(".")
            else f"/workspace/{relative.parent.as_posix()}"
        )
        source_path = (
            f"RUN ln -s {shlex.quote(project_dir)} /opt/sastsimi-target-source\n"
            'ENV PYTHONPATH="/opt/sastsimi-target-source:'
            '/opt/sastsimi-target-source/src:${PYTHONPATH}"\n'
        )
        uv_target = self._uv_sync_target(
            host_path.parent, self._read_project(host_path)
        )
        if uv_target is None:
            if manifest_path == "pyproject.toml":
                return b""
            return (
                "RUN python -m pip install --no-cache-dir "
                f"{shlex.quote(project_dir)}\n"
                f"{source_path}"
            ).encode()
        uv_root, member_name = uv_target
        lock = uv_root / "uv.lock"
        if lock.is_symlink():
            raise ValueError("TARGET_LOCK_PATH_UNSAFE")
        frozen = " --frozen" if lock.is_file() else ""
        uv_root_path = (
            "/workspace"
            if uv_root == root
            else f"/workspace/{uv_root.relative_to(root).as_posix()}"
        )
        member = f" --package {shlex.quote(member_name)}" if member_name else ""
        return (
            "RUN python -m pip install --no-cache-dir uv\n"
            f"RUN cd {shlex.quote(uv_root_path)} && uv sync{member}{frozen} "
            "--no-dev && "
            f"test -x {shlex.quote(uv_root_path + '/.venv/bin/python')} && "
            f"ln -s {shlex.quote(uv_root_path + '/.venv')} "
            "/opt/sastsimi-target-venv\n"
            "ENV VIRTUAL_ENV=/opt/sastsimi-target-venv\n"
            'ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"\n'
            f"{source_path}"
        ).encode()

    def _generated_dockerfile(
        self,
        target_manifest: str | None = None,
        *,
        include_dependencies: bool = True,
    ) -> bytes:
        if not include_dependencies:
            install = ""
            target_manifest = None
        target_install = self._target_install_layer(target_manifest)
        uses_uv = target_install.startswith(
            b"RUN python -m pip install --no-cache-dir uv\n"
        )
        if include_dependencies and uses_uv:
            install = ""
        elif include_dependencies and (self._workspace / "requirements.txt").is_file():
            install = "RUN pip install --no-cache-dir -r requirements.txt"
        elif include_dependencies and (self._workspace / "pyproject.toml").is_file():
            install = (
                ""
                if self._target_install_layer("pyproject.toml")
                else "RUN pip install --no-cache-dir ."
            )
        else:
            install = ""
        git_install = (
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            "git ca-certificates && rm -rf /var/lib/apt/lists/*\n"
            if uses_uv
            else ""
        )
        return (
            "FROM python:3.12-slim\n"
            "WORKDIR /workspace\n"
            "COPY . /workspace\n"
            f"{install}\n"
            f"{git_install}"
            f"{target_install.decode('utf-8')}"
            "RUN chmod -R a+rX /workspace && mkdir -p /tmp && chmod 1777 /tmp\n"
            'CMD ["sleep", "infinity"]\n'
        ).encode()


__all__ = [
    "build_pinned_context",
    "offline_recipe_cache_key",
    "DirectEnvironmentPreparer",
    "PortableContainerFactory",
    "PortableDockerRuntime",
]
