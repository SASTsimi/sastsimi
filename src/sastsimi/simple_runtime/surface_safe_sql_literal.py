"""Fail-closed proof that a pinned Python SQL call uses a fixed literal.

This proves only the shape of one call's SQL argument. It does not prove that
the surrounding route, trust boundary, or every call to the same function is
safe, and it does not itself change surface coverage.
"""

from __future__ import annotations

import ast
import hashlib
import os
import stat
from pathlib import Path

from .ast_facts import _call_name
from .attack_surfaces import AttackSurface
from .facts import safe_tracked_file

_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_SQL_METHODS = frozenset({"execute", "executemany", "executescript", "raw"})


def prove_fixed_sql_literal(
    workspace: Path,
    surface: AttackSurface,
    *,
    source_sha256: str,
    column: int | None = None,
    expected_call_name: str | None = None,
) -> dict[str, object] | None:
    """Return source-bound, SQL-text-free evidence or ``None`` if uncertain.

    ``column`` is optional because older surface indexes store only a line.
    For an AST surface it can identify one of multiple calls on that line.
    For a STATIC_RULE surface it is forbidden: the whole line must have
    exactly one Call, since the surface itself has no pinned column.

    The caller must obtain ``expected_call_name`` from the unique anchor
    Call fact in a verified v4 graph, checking its path, line, source hash,
    and AST artifact hash against the pinned scope. A STATIC_RULE surface's
    ``symbol`` is a rule ID, not the callee. This helper independently checks
    the current file hash and exact AST call, but cannot authenticate the
    caller's graph artifact.
    """

    if (
        surface.type != "SQL_EXECUTION"
        or not surface.path.endswith(".py")
        or type(surface.line) is not int
        or surface.line < 1
        or not isinstance(surface.symbol, str)
        or not surface.symbol
        or not isinstance(expected_call_name, str)
        or not expected_call_name
        or expected_call_name.rsplit(".", 1)[-1] not in _SQL_METHODS
        or (surface.detector == "AST" and surface.symbol != expected_call_name)
        or (surface.detector == "STATIC_RULE" and column is not None)
        or (column is not None and (type(column) is not int or column < 0))
        or not isinstance(source_sha256, str)
        or len(source_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_sha256)
    ):
        return None

    path = safe_tracked_file(workspace, surface.path)
    if path is None:
        return None
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size > _MAX_SOURCE_BYTES
        ):
            return None
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_size > _MAX_SOURCE_BYTES
            ):
                return None
            raw = stream.read(_MAX_SOURCE_BYTES + 1)
        after = path.lstat()
        if (
            len(raw) > _MAX_SOURCE_BYTES
            or path.is_symlink()
            or not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or hashlib.sha256(raw).hexdigest() != source_sha256
        ):
            return None
        tree = ast.parse(raw.decode("utf-8"), filename=surface.path)
    except (
        OSError,
        RuntimeError,
        ValueError,
        UnicodeError,
        SyntaxError,
        RecursionError,
    ):
        return None

    calls_at_location = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and node.lineno == surface.line
        and (column is None or node.col_offset == column)
    ]
    matching = [
        node
        for node in calls_at_location
        if isinstance(node.func, ast.Attribute)
        and _call_name(node.func) == expected_call_name
    ]
    if len(matching) != 1 or (
        column is None and surface.detector != "AST" and len(calls_at_location) != 1
    ):
        return None
    call = matching[0]
    if (
        len(call.args) != 1
        or call.keywords
        or not isinstance(call.args[0], ast.Constant)
        or not isinstance(call.args[0].value, str)
    ):
        return None
    try:
        sql = call.args[0].value.encode("utf-8")
    except UnicodeError:
        return None
    return {
        "kind": "simple_fixed_sql_literal_proof_v1",
        "surface_id": surface.surface_id,
        "path": surface.path,
        "line": call.lineno,
        "column": call.col_offset,
        "symbol": surface.symbol,
        "call_name": expected_call_name,
        "source_sha256": source_sha256,
        "sql_sha256": hashlib.sha256(sql).hexdigest(),
        "sql_byte_count": len(sql),
        "sql_shape": "FIXED_STRING_LITERAL_SINGLE_ARGUMENT",
    }
