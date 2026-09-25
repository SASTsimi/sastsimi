"""Deterministic, bounded Python entry-point facts for the optional survey."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

_MAX_FILE_BYTES = 512_000
_MAX_ENTRY_POINTS = 10_000
_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "route", "websocket"}


def safe_tracked_file(workspace: Path, path: str) -> Path | None:
    """Resolve a repository-relative tracked path, refusing host paths and escapes."""

    if not path or "\\" in path or "\x00" in path or ":" in path:
        return None
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {"..", "."} for part in pure.parts):
        return None
    root = workspace.resolve()
    try:
        current = root
        for part in pure.parts:
            current = current / part
            if current.is_symlink():
                return None
        candidate = (root / path).resolve(strict=True)
        candidate.relative_to(root)
        if candidate.is_file():
            return candidate
    except (OSError, RuntimeError, ValueError):
        pass
    return None


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _name(node.value)
        return f"{head}.{node.attr}" if head else node.attr
    return ""


def _is_route(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _name(node.func).split(".")[-1] in _ROUTE_METHODS


def extract_flows(workspace: Path, sources: Sequence[str]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for path in sorted(set(sources)):
        if not path.endswith((".py", ".pyi")):
            continue
        candidate = safe_tracked_file(workspace, path)
        if candidate is None:
            excluded.append({"path": path, "reason": "UNSAFE_OR_MISSING"})
            continue
        try:
            raw = candidate.read_bytes()
            if len(raw) > _MAX_FILE_BYTES:
                excluded.append({"path": path, "reason": "TOO_LARGE"})
                continue
            tree = ast.parse(raw.decode("utf-8"), filename=path)
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
            excluded.append({"path": path, "reason": "UNPARSEABLE"})
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            routes = [
                _name(decorator.func)
                for decorator in node.decorator_list
                if isinstance(decorator, ast.Call) and _is_route(decorator)
            ]
            if not routes:
                continue
            calls = sorted(
                {
                    name
                    for child in ast.walk(node)
                    if isinstance(child, ast.Call)
                    if (name := _name(child.func))
                }
            )
            entries.append(
                {
                    "file": path,
                    "line": node.lineno,
                    "function": node.name,
                    "routes": routes,
                    "calls": calls[:128],
                }
            )
            if len(entries) >= _MAX_ENTRY_POINTS:
                return {
                    "kind": "simple_repository_flows",
                    "entry_points": entries,
                    "excluded": excluded,
                    "truncated": True,
                }
    entries.sort(key=lambda item: (item["file"], item["line"], item["function"]))
    return {
        "kind": "simple_repository_flows",
        "entry_points": entries,
        "excluded": excluded,
        "truncated": False,
    }
