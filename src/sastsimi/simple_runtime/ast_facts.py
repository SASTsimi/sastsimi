from __future__ import annotations

import ast
import os
import stat
from collections.abc import Sequence
from pathlib import Path

from .artifacts import SimpleArtifactRepository


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def collect_python_ast(
    workspace: Path,
    tracked: Sequence[str],
    artifacts: SimpleArtifactRepository,
    *,
    max_source_bytes: int,
) -> dict[str, object]:
    """Persist every fact from each safely parsed Python file separately."""

    if max_source_bytes < 1:
        raise ValueError("AST_SOURCE_LIMIT_INVALID")
    root = workspace.resolve(strict=True)
    entries: list[dict[str, object]] = []
    parse_errors: list[str] = []
    oversize_paths: list[str] = []
    fact_count = 0
    for relative in sorted(tracked):
        if not relative.lower().endswith((".py", ".pyi")):
            continue
        path = root / relative
        try:
            before = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(before.st_mode)
                or int(getattr(before, "st_file_attributes", 0)) & 0x400
            ):
                raise OSError("AST_SOURCE_NOT_REGULAR")
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            if resolved != path:
                raise OSError("AST_SOURCE_PATH_REDIRECTED")
            if before.st_size > max_source_bytes:
                oversize_paths.append(relative)
                continue
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                current = os.fstat(stream.fileno())
                if not stat.S_ISREG(current.st_mode) or (
                    before.st_dev,
                    before.st_ino,
                ) != (current.st_dev, current.st_ino):
                    raise OSError("AST_SOURCE_CHANGED")
                raw = stream.read(max_source_bytes + 1)
            if len(raw) > max_source_bytes:
                oversize_paths.append(relative)
                continue
            tree = ast.parse(raw.decode("utf-8"), filename=relative)
        except (OSError, RuntimeError, ValueError, UnicodeError, SyntaxError):
            parse_errors.append(relative)
            continue
        facts: list[dict[str, object]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                facts.append(
                    {
                        "kind": type(node).__name__,
                        "path": relative,
                        "line": node.lineno,
                        "name": node.name,
                    }
                )
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name:
                    facts.append(
                        {
                            "kind": "Call",
                            "path": relative,
                            "line": node.lineno,
                            "name": name,
                        }
                    )
        file_ref = artifacts.put_json(
            {"kind": "simple_python_ast_file_v1", "path": relative, "facts": facts}
        )
        entries.append(
            {
                "path": relative,
                "fact_count": len(facts),
                "ref": file_ref.model_dump(mode="json"),
            }
        )
        fact_count += len(facts)
    manifest_ref = artifacts.put_json(
        {
            "kind": "simple_python_ast_manifest_v1",
            "entries": entries,
            "fact_count": fact_count,
            "parsed_file_count": len(entries),
        }
    )
    return {
        "kind": "simple_python_ast",
        "format_version": 2,
        "manifest_ref": manifest_ref.model_dump(mode="json"),
        "fact_count": fact_count,
        "parsed_file_count": len(entries),
        "parse_errors": parse_errors,
        "parse_error_count": len(parse_errors),
        "oversize_paths": oversize_paths,
        "oversize_count": len(oversize_paths),
        "truncated": False,
    }
