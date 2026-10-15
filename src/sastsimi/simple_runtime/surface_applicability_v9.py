"""Commit-pinned applicability proofs for optional surface analyzers.

Absence is meaningful only after every indexed Python source has been read,
hash checked, and parsed. A result says nothing about vulnerability absence.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.static_analysis.file_scope import build_static_file_scope

from .attack_surfaces import SurfaceIndex
from .http_route_facts_v5 import _module as _http_module
from .operational_config_v5 import _Gap, _verified_blob, discover_operational_route_maps

AnalyzerName = Literal["stdlib_http", "operational_xml"]
ApplicabilityStatus = Literal["APPLICABLE", "NOT_APPLICABLE", "UNKNOWN"]

_ANALYZERS: tuple[AnalyzerName, ...] = ("stdlib_http", "operational_xml")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SCAN_FILES = 4_000
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SCAN_BYTES = 16 * 1024 * 1024
_MAX_LAUNCHER_BYTES = 32 * 1024
_MAX_TREE_BYTES = 64 * 1024
_MAX_PYTHON_TREE_BYTES = 2 * 1024 * 1024
_MAX_SCOPE_MANIFEST_BYTES = 4 * 1024 * 1024
_DYNAMIC_CALLS = frozenset(
    {
        "builtins.__import__",
        "builtins.eval",
        "builtins.exec",
        "importlib.import_module",
        "importlib.reload",
        "importlib.util.find_spec",
        "importlib.util.module_from_spec",
        "importlib.util.spec_from_file_location",
        "importlib.machinery.SourceFileLoader",
        "pkgutil.get_loader",
        "pkgutil.resolve_name",
        "runpy.run_module",
        "runpy.run_path",
    }
)


@dataclass(frozen=True, slots=True)
class AnalyzerStatusV9:
    analyzer: AnalyzerName
    status: ApplicabilityStatus
    reason_codes: tuple[str, ...]
    source_hashes: tuple[tuple[str, str], ...]

    def to_json(self) -> dict[str, object]:
        return {
            "analyzer": self.analyzer,
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "source_hashes": [
                {"path": path, "source_sha256": digest}
                for path, digest in self.source_hashes
            ],
        }


@dataclass(frozen=True, slots=True)
class AnalyzerApplicabilityV9:
    workspace_id: str
    commit_id: str
    scope_fingerprint: str
    index_hash: str
    analyzers: tuple[AnalyzerStatusV9, ...]

    def status_for(self, analyzer: str) -> ApplicabilityStatus:
        """Return only the requested analyzer's status."""

        for row in self.analyzers:
            if row.analyzer == analyzer:
                return row.status
        raise KeyError(analyzer)

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_surface_analyzer_applicability_v9",
            "workspace_id": self.workspace_id,
            "commit_id": self.commit_id,
            "scope_fingerprint": self.scope_fingerprint,
            "index_hash": self.index_hash,
            "analyzers": [row.to_json() for row in self.analyzers],
        }


@dataclass(frozen=True, slots=True)
class _ScannedSource:
    path: str
    digest: str
    tree: ast.Module


def _row(
    analyzer: AnalyzerName,
    status: ApplicabilityStatus,
    reasons: tuple[str, ...],
    hashes: tuple[tuple[str, str], ...],
) -> AnalyzerStatusV9:
    return AnalyzerStatusV9(analyzer, status, reasons, tuple(sorted(set(hashes))))


def _proof(
    index: SurfaceIndex, rows: tuple[AnalyzerStatusV9, ...]
) -> AnalyzerApplicabilityV9:
    return AnalyzerApplicabilityV9(
        workspace_id=index.workspace_id,
        commit_id=index.commit_id,
        scope_fingerprint=index.scope_fingerprint,
        index_hash=hashlib.sha256(canonical_bytes(index.to_json())).hexdigest(),
        analyzers=rows,
    )


def _all_unknown(
    index: SurfaceIndex,
    reason: str,
    hashes: tuple[tuple[str, str], ...] = (),
) -> AnalyzerApplicabilityV9:
    return _proof(
        index,
        tuple(_row(name, "UNKNOWN", (reason,), hashes) for name in _ANALYZERS),
    )


def _manifest_valid(index: SurfaceIndex) -> bool:
    hashes = index.ast_source_hashes
    return (
        index.index_version == 2
        and bool(hashes)
        and all(
            isinstance(path, str)
            and path.endswith((".py", ".pyi"))
            and isinstance(digest, str)
            and _DIGEST.fullmatch(digest) is not None
            for path, digest in hashes
        )
        and tuple(sorted(hashes)) == hashes
        and len({path for path, _ in hashes}) == len(hashes)
    )


def _scan_sources(
    index: SurfaceIndex, workspace: Path
) -> tuple[tuple[_ScannedSource, ...], tuple[tuple[str, str], ...], str | None]:
    if not _manifest_valid(index):
        return (), (), "SOURCE_MANIFEST_UNAVAILABLE"
    if any(
        gap.path.lower().endswith((".py", ".pyi"))
        or not gap.path
        and gap.reason in {"STATIC_UNAVAILABLE", "UNVERIFIED_PAIRS_UNSPECIFIED"}
        for gap in index.static_gaps
    ):
        return (), (), "PYTHON_STATIC_GAP"
    if len(index.ast_source_hashes) > _MAX_SCAN_FILES:
        return (), (), "SCAN_FILE_LIMIT"
    try:
        pinned_python = _pinned_python_paths(workspace, index.commit_id)
    except ValueError as error:
        return (), (), str(error)
    if pinned_python != tuple(path for path, _ in index.ast_source_hashes):
        return (), (), "SOURCE_MANIFEST_INCOMPLETE"
    scanned: list[_ScannedSource] = []
    verified: list[tuple[str, str]] = []
    total = 0
    for path, expected in index.ast_source_hashes:
        try:
            raw, actual = _verified_blob(
                workspace,
                index.commit_id,
                path,
                _MAX_SOURCE_BYTES,
                oversize_gap="SCAN_BYTE_LIMIT",
            )
        except _Gap as gap:
            return (), tuple(verified), gap.code
        if actual != expected:
            return (), tuple(verified), "SOURCE_HASH_MISMATCH"
        total += len(raw)
        if total > _MAX_SCAN_BYTES:
            return (), tuple(verified), "SCAN_BYTE_LIMIT"
        verified.append((path, actual))
        try:
            tree = ast.parse(raw.decode("utf-8"), filename=path)
        except (SyntaxError, UnicodeError, ValueError, RecursionError):
            return (), tuple(verified), "SOURCE_PARSE_ERROR"
        scanned.append(_ScannedSource(path, actual, tree))
    return tuple(scanned), tuple(verified), None


def _run_pinned_tree_command(
    command: tuple[str, ...],
) -> subprocess.CompletedProcess[bytes]:
    for attempt in range(2):
        try:
            return subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired:
            if attempt == 1:
                raise
    raise AssertionError("unreachable")


def _pinned_python_paths(workspace: Path, commit_id: str) -> tuple[str, ...]:
    """Require the index to cover every in-scope Python product entry."""

    try:
        result = _run_pinned_tree_command(
            (
                "git",
                "-C",
                str(workspace),
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                commit_id,
            )
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("PINNED_TREE_UNAVAILABLE") from error
    raw = result.stdout
    if (
        result.returncode != 0
        or len(raw) > _MAX_PYTHON_TREE_BYTES
        or raw
        and not raw.endswith(b"\0")
    ):
        raise ValueError("PINNED_TREE_UNAVAILABLE")
    try:
        paths = tuple(part.decode("utf-8") for part in raw.split(b"\0") if part)
    except UnicodeError as error:
        raise ValueError("PINNED_TREE_UNAVAILABLE") from error
    try:
        scope = build_static_file_scope(workspace, paths)
    except ValueError as error:
        raise ValueError("PINNED_TREE_UNAVAILABLE") from error
    # The shared classifier ignores declarations under test-only paths. Pin
    # only manifests it actually uses to decide whether a test-like source is
    # deployed; unrelated test fixtures must not invalidate the product proof.
    excluded = {path for path, _ in scope.excluded_test_files}
    for path in paths:
        if (
            Path(path).name in {"pyproject.toml", "package.json"}
            and path not in excluded
        ):
            try:
                _verified_blob(
                    workspace,
                    commit_id,
                    path,
                    _MAX_SCOPE_MANIFEST_BYTES,
                    oversize_gap="SOURCE_MANIFEST_UNAVAILABLE",
                )
            except _Gap as gap:
                raise ValueError(gap.code) from gap
    # Unlike test directories, `test_*.py` is excluded only when its contents
    # look like tests. The checkout cannot be allowed to reclassify a pinned
    # product module into a test and conceal a missing AST source.
    for path, reason in scope.excluded_test_files:
        if reason != "test-basename+content:python":
            continue
        try:
            _verified_blob(workspace, commit_id, path, _MAX_SOURCE_BYTES)
        except _Gap as gap:
            raise ValueError(gap.code) from gap
    python_paths = scope.selected_paths
    if len(python_paths) > _MAX_SCAN_FILES:
        raise ValueError("SCAN_FILE_LIMIT")
    if len(python_paths) != len(set(python_paths)):
        raise ValueError("PINNED_TREE_UNAVAILABLE")
    return python_paths


def _pinned_tree_paths(
    workspace: Path, commit_id: str, names: tuple[str, ...]
) -> tuple[str, ...]:
    """Enumerate exact pinned entries, not worktree glob matches."""

    try:
        result = _run_pinned_tree_command(
            (
                "git",
                "-C",
                str(workspace),
                "--literal-pathspecs",
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                commit_id,
                "--",
                *names,
            )
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("PINNED_TREE_UNAVAILABLE") from error
    if result.returncode != 0 or len(result.stdout) > _MAX_TREE_BYTES:
        raise ValueError("PINNED_TREE_UNAVAILABLE")
    try:
        found = tuple(
            part.decode("utf-8") for part in result.stdout.split(b"\0") if part
        )
    except UnicodeError as error:
        raise ValueError("PINNED_TREE_UNAVAILABLE") from error
    if len(found) != len(set(found)) or not set(found).issubset(names):
        raise ValueError("PINNED_TREE_UNAVAILABLE")
    return tuple(sorted(found))


def _has_dynamic_import(tree: ast.Module) -> bool:
    module_aliases = {
        "builtins": "builtins",
        "importlib": "importlib",
        "pkgutil": "pkgutil",
        "runpy": "runpy",
    }
    importer_names = {"import_module"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in module_aliases:
                    bound = alias.asname or alias.name.split(".")[0]
                    module_aliases[bound] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "builtins",
            "importlib",
            "importlib.machinery",
            "importlib.util",
            "pkgutil",
            "runpy",
        }:
            for alias in node.names:
                if alias.name == "*":
                    return True
                full_name = f"{node.module}.{alias.name}"
                if full_name in _DYNAMIC_CALLS:
                    importer_names.add(alias.asname or alias.name)
                elif full_name == "importlib.util":
                    module_aliases[alias.asname or alias.name] = full_name
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in {
            "__import__",
            "eval",
            "exec",
            *importer_names,
        }:
            return True
        if (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in module_aliases
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value
            in {
                "import_module",
                "run_module",
                "run_path",
            }
        ):
            return True
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name) and parts:
            full_name = ".".join(
                (module_aliases.get(current.id, current.id), *reversed(parts))
            )
            if full_name in _DYNAMIC_CALLS or parts[0] in {
                "exec_module",
                "load_module",
            }:
                return True
    return False


def _mentions_http_handler(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (
            node.module in {"http", "http.server"}
            and any(
                alias.name in {"server", "BaseHTTPRequestHandler", "*"}
                for alias in node.names
            )
        ):
            return True
        if isinstance(node, ast.Import) and any(
            alias.name in {"http", "http.server"} for alias in node.names
        ):
            return True
        if isinstance(node, ast.ClassDef) and any(
            isinstance(base, ast.Name)
            and base.id == "BaseHTTPRequestHandler"
            or isinstance(base, ast.Attribute)
            and base.attr == "BaseHTTPRequestHandler"
            for base in node.bases
        ):
            return True
    return False


def _mentions_xml_parser(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name == "xml" or alias.name.startswith("xml.") for alias in node.names
        ):
            return True
        if isinstance(node, ast.ImportFrom) and (
            node.module == "xml"
            or node.module is not None
            and node.module.startswith("xml.")
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"parse", "iterparse"}
            and any(
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and arg.value.lower().endswith(".xml")
                for arg in node.args
            )
        ):
            return True
    return False


def _http_status(
    scanned: tuple[_ScannedSource, ...],
    hashes: tuple[tuple[str, str], ...],
    workspace: Path,
    commit_id: str,
) -> AnalyzerStatusV9:
    try:
        shadows = _pinned_tree_paths(
            workspace,
            commit_id,
            ("http.py", "http/__init__.py", "http/server.py"),
        )
    except ValueError:
        return _row("stdlib_http", "UNKNOWN", ("PINNED_TREE_UNAVAILABLE",), hashes)
    checkout_shadows = any(
        os.path.lexists(workspace / path)
        for path in ("http.py", "http/__init__.py", "http/server.py")
    )
    triggered = False
    proven = False
    ambiguous = False
    for source in scanned:
        if not _mentions_http_handler(source.tree):
            continue
        triggered = True
        module = _http_module(source.path, source.digest, source.tree)
        proven = proven or bool(module.handler_classes)
        ambiguous = (
            ambiguous
            or bool(module.gaps)
            or not module.handler_classes
            or any(
                isinstance(node, ast.Import)
                and any(alias.name in {"http", "http.server"} for alias in node.names)
                or isinstance(node, ast.ClassDef)
                and any(
                    isinstance(base, ast.Attribute)
                    and base.attr == "BaseHTTPRequestHandler"
                    for base in node.bases
                )
                for node in ast.walk(source.tree)
            )
        )
    if not triggered:
        return _row("stdlib_http", "NOT_APPLICABLE", ("HTTP_HANDLER_ABSENT",), hashes)
    if shadows or checkout_shadows:
        return _row("stdlib_http", "UNKNOWN", ("HTTP_IMPORT_SHADOWED",), hashes)
    if ambiguous:
        return _row(
            "stdlib_http", "UNKNOWN", ("HTTP_HANDLER_BINDING_UNPROVEN",), hashes
        )
    if proven:
        return _row(
            "stdlib_http", "APPLICABLE", ("HTTP_HANDLER_SUBCLASS_PROVEN",), hashes
        )
    return _row("stdlib_http", "UNKNOWN", ("HTTP_HANDLER_BINDING_UNPROVEN",), hashes)


def _xml_status(
    scanned: tuple[_ScannedSource, ...],
    hashes: tuple[tuple[str, str], ...],
    workspace: Path,
    index: SurfaceIndex,
) -> AnalyzerStatusV9:
    try:
        launchers = _pinned_tree_paths(
            workspace, index.commit_id, ("Dockerfile", "Containerfile")
        )
    except ValueError:
        return _row("operational_xml", "UNKNOWN", ("PINNED_TREE_UNAVAILABLE",), hashes)
    supporting: list[tuple[str, str]] = list(hashes)
    for path in launchers:
        try:
            _, digest = _verified_blob(
                workspace,
                index.commit_id,
                path,
                _MAX_LAUNCHER_BYTES,
                oversize_gap="LAUNCHER_BYTE_LIMIT",
            )
        except _Gap as gap:
            return _row("operational_xml", "UNKNOWN", (gap.code,), tuple(supporting))
        supporting.append((path, digest))
    if not any(_mentions_xml_parser(source.tree) for source in scanned):
        return _row(
            "operational_xml",
            "NOT_APPLICABLE",
            ("OPERATIONAL_XML_PARSER_ABSENT",),
            tuple(supporting),
        )
    result = discover_operational_route_maps(
        workspace, index.commit_id, dict(index.ast_source_hashes)
    )
    if not result.bindings or result.gaps:
        return _row(
            "operational_xml",
            "UNKNOWN",
            tuple(sorted(set(result.gaps))) or ("OPERATIONAL_XML_BINDING_UNPROVEN",),
            tuple(supporting),
        )
    for binding in result.bindings:
        supporting.extend(
            (
                (binding.config_path, binding.config_sha256),
                (binding.launcher_path, binding.launcher_sha256),
            )
        )
    return _row(
        "operational_xml",
        "APPLICABLE",
        ("OPERATIONAL_XML_BINDING_PROVEN",),
        tuple(supporting),
    )


def assess_optional_analyzers(
    index: SurfaceIndex, workspace: Path
) -> AnalyzerApplicabilityV9:
    """Classify each optional analyzer from the complete pinned manifest."""

    scanned, hashes, failure = _scan_sources(index, workspace)
    if failure is not None:
        return _all_unknown(index, failure, hashes)
    if any(_has_dynamic_import(source.tree) for source in scanned):
        return _all_unknown(index, "DYNAMIC_IMPORT_UNRESOLVED", hashes)
    return _proof(
        index,
        (
            _http_status(scanned, hashes, workspace, index.commit_id),
            _xml_status(scanned, hashes, workspace, index),
        ),
    )


def validate_analyzer_applicability(
    index: SurfaceIndex, proof: AnalyzerApplicabilityV9, workspace: Path
) -> bool:
    """Recompute the whole proof against the pinned checkout."""

    return isinstance(proof, AnalyzerApplicabilityV9) and proof == (
        assess_optional_analyzers(index, workspace)
    )
