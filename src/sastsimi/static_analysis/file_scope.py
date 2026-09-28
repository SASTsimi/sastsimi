"""Conservative, auditable test-file policy for pinned repository sources."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from sastsimi.contracts.canonical_json import canonical_bytes

_POLICY_VERSION = 1
_TEST_DIRECTORIES = frozenset({"test", "tests", "__test__", "__tests__"})
_PYTHON_TEST_NAME = re.compile(r"(?:test_.+|.+_test)\.py\Z", re.IGNORECASE)
_JS_TEST_NAME = re.compile(
    r".+\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs)\Z", re.IGNORECASE
)
_PYTHON_TEST_CONTENT = re.compile(
    r"(?m)^\s*(?:import\s+(?:pytest|unittest)\b|"
    r"from\s+(?:pytest|unittest)\s+import\b|"
    r"(?:async\s+)?def\s+test_\w+\s*\(|"
    r"class\s+Test\w*\s*\([^\n]*\bTestCase\b)"
)
_JS_TEST_CONTENT = re.compile(
    r"\b(?:from\s*['\"](?:vitest|jest|@jest/globals|mocha)['\"]|"
    r"require\s*\(\s*['\"](?:vitest|jest|@jest/globals|mocha)['\"]\s*\)|"
    r"(?:describe|it|test)\s*\()"
)
_MAX_CONTENT_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class TestExclusion:
    path: str
    reason: str
    status: str = "EXCLUDED_TEST_FILE"


@dataclass(frozen=True, slots=True)
class StaticFileScope:
    all_tracked: tuple[str, ...]
    selected_paths: tuple[str, ...]
    excluded_test_files: tuple[TestExclusion, ...]
    fingerprint: str
    include_tests: bool
    policy_version: int = _POLICY_VERSION


def _validate_tracked_path(path: str) -> None:
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or ":" in path
        or any(ord(char) < 32 for char in path)
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ValueError("STATIC_SCOPE_TRACKED_PATH_INVALID")


def _safe_read(root: Path, relative: str, *, max_bytes: int) -> bytes | None:
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not candidate.is_file() or candidate.is_symlink():
            return None
        with candidate.open("rb") as stream:
            data = stream.read(max_bytes + 1)
        return data if len(data) <= max_bytes else None
    except (OSError, RuntimeError, ValueError):
        return None


def _package_entry_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        result: list[str] = []
        for item in value.values():
            result.extend(_package_entry_values(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_package_entry_values(item))
        return result
    return []


def _declared_entry_paths(
    root: Path, tracked: tuple[str, ...]
) -> tuple[frozenset[str], frozenset[str]]:
    candidates: set[str] = set()
    uncertain_roots: set[str] = set()
    tracked_set = set(tracked)
    for manifest in tracked:
        name = PurePosixPath(manifest).name
        if name not in {"pyproject.toml", "package.json"}:
            continue
        base = PurePosixPath(manifest).parent
        raw = _safe_read(root, manifest, max_bytes=_MAX_CONTENT_BYTES)
        if raw is None:
            uncertain_roots.add(base.as_posix())
            continue
        if name == "pyproject.toml":
            try:
                data = tomllib.loads(raw.decode("utf-8"))
            except (UnicodeError, tomllib.TOMLDecodeError):
                uncertain_roots.add(base.as_posix())
                continue
            project = data.get("project", {})
            tool = data.get("tool", {})
            poetry = tool.get("poetry", {}) if isinstance(tool, dict) else None
            if not isinstance(project, dict) or not isinstance(poetry, dict):
                uncertain_roots.add(base.as_posix())
                continue
            values = _package_entry_values(
                [
                    project.get("scripts", {}),
                    project.get("gui-scripts", {}),
                    poetry.get("scripts", {}),
                ]
            )
            for value in values:
                module = value.split(":", 1)[0].strip()
                if not re.fullmatch(r"[A-Za-z_][\w.]*(?:\.[A-Za-z_]\w*)*", module):
                    continue
                module_path = module.replace(".", "/")
                for prefix in (base, base / "src"):
                    candidates.add((prefix / f"{module_path}.py").as_posix())
                    candidates.add((prefix / module_path / "__init__.py").as_posix())
        else:
            try:
                data = json.loads(raw)
            except (UnicodeError, ValueError):
                uncertain_roots.add(base.as_posix())
                continue
            if not isinstance(data, dict):
                uncertain_roots.add(base.as_posix())
                continue
            for value in _package_entry_values(
                [
                    data.get("main"),
                    data.get("module"),
                    data.get("browser"),
                    data.get("bin"),
                    data.get("exports"),
                ]
            ):
                if not value.startswith("./"):
                    continue
                relative = value[2:]
                if not relative or any(
                    part in {"", ".", ".."} for part in relative.split("/")
                ):
                    continue
                candidates.add((base / relative).as_posix())
    return frozenset(candidates & tracked_set), frozenset(uncertain_roots)


def _under_uncertain_root(path: str, roots: frozenset[str]) -> bool:
    return any(root == "." or path.startswith(root + "/") for root in roots)


def _test_reason(root: Path, path: str) -> str | None:
    parts = PurePosixPath(path).parts
    for component in parts[:-1]:
        if component.casefold() in _TEST_DIRECTORIES:
            return f"test-directory:{component.casefold()}"
    name = parts[-1]
    if _PYTHON_TEST_NAME.fullmatch(name):
        language = "python"
        pattern = _PYTHON_TEST_CONTENT
    elif _JS_TEST_NAME.fullmatch(name):
        language = "javascript-typescript"
        pattern = _JS_TEST_CONTENT
    else:
        return None
    raw = _safe_read(root, path, max_bytes=_MAX_CONTENT_BYTES)
    if raw is None:
        return None
    try:
        contents = raw.decode("utf-8")
    except UnicodeError:
        return None
    return f"test-basename+content:{language}" if pattern.search(contents) else None


def build_static_file_scope(
    workspace: Path, tracked: Sequence[str], *, include_tests: bool
) -> StaticFileScope:
    """Return deterministic selected and excluded paths for one pinned checkout."""

    root = workspace.resolve()
    paths = tuple(sorted(set(tracked)))
    for path in paths:
        _validate_tracked_path(path)
    protected, uncertain_roots = (
        _declared_entry_paths(root, paths)
        if not include_tests
        else (frozenset(), frozenset())
    )
    excluded = tuple(
        TestExclusion(path, reason)
        for path in paths
        if not include_tests
        and path not in protected
        and not _under_uncertain_root(path, uncertain_roots)
        and (reason := _test_reason(root, path)) is not None
    )
    excluded_paths = {item.path for item in excluded}
    selected = tuple(path for path in paths if path not in excluded_paths)
    fingerprint = hashlib.sha256(
        canonical_bytes(
            {
                "policy_version": _POLICY_VERSION,
                "include_tests": include_tests,
                "all_tracked": paths,
                "selected_paths": selected,
                "excluded_test_files": [
                    {"path": item.path, "reason": item.reason} for item in excluded
                ],
            }
        )
    ).hexdigest()
    return StaticFileScope(
        all_tracked=paths,
        selected_paths=selected,
        excluded_test_files=excluded,
        fingerprint=fingerprint,
        include_tests=include_tests,
    )


__all__ = ["StaticFileScope", "TestExclusion", "build_static_file_scope"]
