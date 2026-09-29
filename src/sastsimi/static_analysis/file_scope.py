"""Conservative product-source scope for pinned repository files."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from sastsimi.contracts.canonical_json import canonical_bytes

_POLICY_VERSION = 6
_TEST_DIRECTORIES = frozenset(
    {
        "test",
        "tests",
        "__test__",
        "__tests__",
        "spec",
        "specs",
        "__specs__",
        "e2e",
        "testdata",
        "unit_tests",
        "integration_tests",
        "functional_tests",
        "benchmarks",
        "stress-test",
        "stress_tests",
    }
)
_PYTHON_TEST_NAME = re.compile(r"(?:test_.+|.+_test)\.py\Z", re.IGNORECASE)
_JS_TEST_NAME = re.compile(
    r".+\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)\Z", re.IGNORECASE
)
_SHELL_TEST_NAME = re.compile(r"(?:test_.+|.+_test)\.(?:sh|bash)\Z", re.IGNORECASE)
_TEST_RUNNER_ASSET_NAME = re.compile(
    r"(?:vitest|jest)(?:[.-].+)?\."
    r"(?:css|scss|less|js|jsx|ts|tsx|mjs|cjs|mts|cts)\Z",
    re.IGNORECASE,
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
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_DOCUMENTATION_DIRECTORIES = frozenset(
    {"doc", "docs", "documentation", "example", "examples", "sample", "samples"}
)
_NON_PYTHON_PRODUCT_EXTENSIONS = frozenset(
    {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".vue",
        ".svelte",
        ".astro",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".sc",
        ".cs",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hh",
        ".hpp",
        ".hxx",
        ".swift",
        ".dart",
        ".rb",
        ".php",
        ".ex",
        ".exs",
        ".erl",
        ".hrl",
        ".hs",
        ".ml",
        ".mli",
        ".lua",
        ".pl",
        ".pm",
        ".r",
        ".jl",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".sql",
        ".graphql",
        ".proto",
    }
)


@dataclass(frozen=True, slots=True)
class StaticFileScope:
    selected_paths: tuple[str, ...]
    fingerprint: str
    policy_version: int = _POLICY_VERSION
    excluded_test_files: tuple[tuple[str, str], ...] = ()
    out_of_scope_product_files: tuple[tuple[str, str], ...] = ()


class StaticScopeManifestUnverified(ValueError):
    """A package declaration might point at an otherwise test-like path."""

    retryable = False

    def __init__(self) -> None:
        super().__init__("STATIC_SCOPE_MANIFEST_UNVERIFIED")


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


def _safe_regular_file(root: Path, relative: str) -> Path | None:
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not candidate.is_file() or candidate.is_symlink():
            return None
        return candidate
    except (OSError, RuntimeError, ValueError):
        return None


def _safe_read(root: Path, relative: str, *, max_bytes: int) -> bytes | None:
    candidate = _safe_regular_file(root, relative)
    if candidate is None:
        return None
    try:
        with candidate.open("rb") as stream:
            data = stream.read(max_bytes + 1)
        return data if len(data) <= max_bytes else None
    except (OSError, RuntimeError, ValueError):
        return None


def _safe_test_content_samples(root: Path, relative: str) -> tuple[bytes, ...] | None:
    candidate = _safe_regular_file(root, relative)
    if candidate is None:
        return None
    try:
        with candidate.open("rb") as stream:
            prefix = stream.read(_MAX_CONTENT_BYTES + 1)
            if len(prefix) <= _MAX_CONTENT_BYTES:
                return (prefix,)
            # Keep the preceding byte so the tail cannot invent a word/line
            # boundary in the middle of a production identifier.
            stream.seek(-(_MAX_CONTENT_BYTES + 1), 2)
            suffix = b"x" + stream.read(_MAX_CONTENT_BYTES + 1)
        return (prefix[:_MAX_CONTENT_BYTES], suffix)
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
        if _test_reason(root, manifest) is not None:
            # Test fixture manifests are not deployed package declarations.
            continue
        base = PurePosixPath(manifest).parent
        raw = _safe_read(root, manifest, max_bytes=_MAX_MANIFEST_BYTES)
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
                relative = value[2:] if value.startswith("./") else value
                if (
                    not relative
                    or any(part in {"", ".", ".."} for part in relative.split("/"))
                    or (relative.startswith("/") or "\\" in relative or ":" in relative)
                ):
                    continue
                candidate = (base / relative).as_posix()
                if any(character in relative for character in "*?["):
                    candidates.update(
                        path for path in tracked if fnmatchcase(path, candidate)
                    )
                else:
                    candidates.add(candidate)
    return frozenset(candidates & tracked_set), frozenset(uncertain_roots)


def _under_uncertain_root(path: str, roots: frozenset[str]) -> bool:
    return any(root == "." or path.startswith(root + "/") for root in roots)


def _test_reason(root: Path, path: str) -> str | None:
    parts = PurePosixPath(path).parts
    directories = tuple(component.casefold() for component in parts[:-1])
    for component in directories:
        if component in _TEST_DIRECTORIES:
            return f"test-directory:{component}"
    if any(
        component == "eslint" and "fixtures" in directories[index + 1 :]
        for index, component in enumerate(directories)
    ):
        return "test-directory:eslint-fixtures"
    name = parts[-1]
    if name.casefold() in {"conftest.py", "pytest.ini"}:
        return "test-basename:pytest"
    if _SHELL_TEST_NAME.fullmatch(name):
        return "test-basename:shell"
    if _TEST_RUNNER_ASSET_NAME.fullmatch(name):
        return "test-basename:test-runner"
    if name.endswith("_test.go"):
        return "test-basename:go"
    if _PYTHON_TEST_NAME.fullmatch(name):
        language = "python"
        pattern = _PYTHON_TEST_CONTENT
    elif _JS_TEST_NAME.fullmatch(name):
        language = "javascript-typescript"
        pattern = _JS_TEST_CONTENT
    else:
        return None
    samples = _safe_test_content_samples(root, path)
    if samples is None:
        return None
    for raw in samples:
        try:
            contents = raw.decode("utf-8")
        except UnicodeError:
            if len(samples) == 1:
                return None
            contents = raw.decode("utf-8", errors="ignore")
        if pattern.search(contents):
            return f"test-basename+content:{language}"
    return None


def is_test_only_path(workspace: Path, path: str) -> bool:
    """Apply the shared conservative test-file exclusion to a tracked path."""

    _validate_tracked_path(path)
    return _test_reason(workspace.resolve(), path) is not None


def _is_documentation_path(path: str) -> bool:
    return any(
        component.casefold() in _DOCUMENTATION_DIRECTORIES
        for component in PurePosixPath(path).parts[:-1]
    )


def build_static_file_scope(workspace: Path, tracked: Sequence[str]) -> StaticFileScope:
    """Return only tracked, non-test Python product sources for static analysis."""

    root = workspace.resolve()
    paths = tuple(sorted(set(tracked)))
    for path in paths:
        _validate_tracked_path(path)
    selected_paths: list[str] = []
    excluded_test_files: list[tuple[str, str]] = []
    out_of_scope_product_files: list[tuple[str, str]] = []
    declared_entries, uncertain_roots = _declared_entry_paths(root, paths)
    scope_exceptions: list[tuple[str, str]] = []
    for path in paths:
        extension = Path(path).suffix.lower()
        test_reason = _test_reason(root, path)
        if path in declared_entries and (
            test_reason is not None or _is_documentation_path(path)
        ):
            if extension == ".py":
                selected_paths.append(path)
                scope_exceptions.append((path, "declared_python_entry"))
            elif extension == ".pyi" or extension in _NON_PYTHON_PRODUCT_EXTENSIONS:
                out_of_scope_product_files.append((path, "declared_non_python_entry"))
                scope_exceptions.append((path, "declared_non_python_entry"))
            continue
        if test_reason is not None:
            if _under_uncertain_root(path, uncertain_roots) and (
                extension in {".py", ".pyi"}
                or extension in _NON_PYTHON_PRODUCT_EXTENSIONS
            ):
                out_of_scope_product_files.append(
                    (path, "manifest_unverified_possible_product")
                )
                scope_exceptions.append((path, "manifest_unverified_possible_product"))
            else:
                excluded_test_files.append((path, test_reason))
            continue
        if _is_documentation_path(path):
            continue
        if extension == ".py":
            selected_paths.append(path)
        elif extension == ".pyi":
            out_of_scope_product_files.append((path, "python_stub_not_scanned"))
        elif extension in _NON_PYTHON_PRODUCT_EXTENSIONS:
            out_of_scope_product_files.append((path, "non_python_product_source"))
    selected = tuple(selected_paths)
    scope_identity: dict[str, object] = {
        "policy_version": _POLICY_VERSION,
        "selected_paths": selected,
    }
    if scope_exceptions:
        scope_identity["manifest_scope_exceptions"] = scope_exceptions
    fingerprint = hashlib.sha256(canonical_bytes(scope_identity)).hexdigest()
    return StaticFileScope(
        selected_paths=selected,
        fingerprint=fingerprint,
        excluded_test_files=tuple(excluded_test_files),
        out_of_scope_product_files=tuple(out_of_scope_product_files),
    )


__all__ = [
    "StaticFileScope",
    "StaticScopeManifestUnverified",
    "build_static_file_scope",
    "is_test_only_path",
]
