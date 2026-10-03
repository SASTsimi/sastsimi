"""Conservative, pinned-source identity for a verified Python Finding.

This is deliberately not a general taint engine. An unsupported or ambiguous
expression has no equality key, so it can never cause an automatic merge.
"""

from __future__ import annotations

import ast
import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


class FlowEvidenceInvalid(ValueError):
    """Pinned source evidence is unsafe or differs from the AST manifest."""


@dataclass(frozen=True)
class FlowAnchor:
    route: str
    function: str
    source_file: str
    source_line: int
    source_access: str
    source_key: str
    def_use_nodes: tuple[str, ...]
    sink_file: str
    sink_line: int
    sink_callee: str
    sink_argument: int
    branch_nodes: tuple[str, ...]
    cwe: str


@dataclass(frozen=True)
class _Definition:
    name: str
    line: int
    value: ast.expr
    branches: tuple[str, ...]


@dataclass(frozen=True)
class _Callsite:
    call: ast.Call
    branches: tuple[str, ...]


@dataclass(frozen=True)
class _Source:
    line: int
    access: str
    key: str
    nodes: tuple[str, ...]


_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_COMMAND_SINKS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
}


def _safe_source(workspace: Path, relative: str, expected_sha256: str) -> bytes | None:
    path_parts = Path(relative).parts
    if (
        not relative
        or not relative.endswith(".py")
        or Path(relative).is_absolute()
        or "\\" in relative
        or ":" in relative
        or ".." in path_parts
        or "." in path_parts
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise FlowEvidenceInvalid("FLOW_SOURCE_PATH_OR_HASH_INVALID")
    try:
        root = workspace.resolve(strict=True)
        path = root / relative
        before = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size > _MAX_SOURCE_BYTES
        ):
            raise FlowEvidenceInvalid("FLOW_SOURCE_UNSAFE")
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if resolved != path:
            raise FlowEvidenceInvalid("FLOW_SOURCE_REDIRECTED")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            current = os.fstat(stream.fileno())
            if not stat.S_ISREG(current.st_mode) or (before.st_dev, before.st_ino) != (
                current.st_dev,
                current.st_ino,
            ):
                raise FlowEvidenceInvalid("FLOW_SOURCE_CHANGED")
            raw = stream.read(_MAX_SOURCE_BYTES + 1)
        if (
            len(raw) > _MAX_SOURCE_BYTES
            or hashlib.sha256(raw).hexdigest() != expected_sha256
        ):
            raise FlowEvidenceInvalid("FLOW_SOURCE_HASH_MISMATCH")
        return raw
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError, ValueError) as error:
        if isinstance(error, FlowEvidenceInvalid):
            raise
        raise FlowEvidenceInvalid("FLOW_SOURCE_UNSAFE") from error


def _name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _route(function: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not decorator.args:
            continue
        method = _name(decorator.func)
        first = decorator.args[0]
        if (
            method
            and method.rsplit(".", 1)[-1]
            in {"route", "get", "post", "put", "delete", "patch"}
            and isinstance(first, ast.Constant)
            and isinstance(first.value, str)
        ):
            return first.value
    return f"function:{function.name}@{function.lineno}"


def _locations(proposal: Mapping[str, object], path: str) -> set[int]:
    values = proposal.get("code_locations")
    if not isinstance(values, list):
        return set()
    result: set[int] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        prefix, separator, number = value.rpartition(":")
        if separator and prefix.replace("\\", "/") == path and number.isdecimal():
            result.add(int(number))
    return result


def _local_expressions(statement: ast.stmt) -> tuple[ast.expr, ...]:
    if isinstance(statement, (ast.Assign, ast.AugAssign)):
        return (statement.value,)
    if isinstance(statement, ast.AnnAssign) and statement.value is not None:
        return (statement.value,)
    if isinstance(statement, (ast.Expr, ast.Return)) and statement.value is not None:
        return (statement.value,)
    if isinstance(statement, ast.Raise) and statement.exc is not None:
        return (statement.exc,)
    return ()


def _scan_statements(
    statements: list[ast.stmt],
    branches: tuple[str, ...],
    definitions: list[_Definition],
    calls: list[_Callsite],
) -> None:
    for statement in statements:
        if isinstance(statement, ast.If):
            _scan_statements(
                statement.body,
                (*branches, f"if:{statement.lineno}:yes"),
                definitions,
                calls,
            )
            _scan_statements(
                statement.orelse,
                (*branches, f"if:{statement.lineno}:no"),
                definitions,
                calls,
            )
            continue
        if isinstance(statement, (ast.Try, ast.TryStar)):
            _scan_statements(
                statement.body,
                (*branches, f"try:{statement.lineno}:body"),
                definitions,
                calls,
            )
            for index, handler in enumerate(statement.handlers):
                _scan_statements(
                    handler.body,
                    (*branches, f"try:{statement.lineno}:except:{index}"),
                    definitions,
                    calls,
                )
            _scan_statements(
                statement.orelse,
                (*branches, f"try:{statement.lineno}:else"),
                definitions,
                calls,
            )
            _scan_statements(
                statement.finalbody,
                (*branches, f"try:{statement.lineno}:finally"),
                definitions,
                calls,
            )
            continue
        if isinstance(
            statement,
            (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Match),
        ):
            # Loop and pattern reaching definitions are not linear.
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for expression in _local_expressions(statement):
            for node in ast.walk(expression):
                if isinstance(node, ast.Call):
                    calls.append(_Callsite(node, branches))
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name):
                definitions.append(
                    _Definition(target.id, statement.lineno, statement.value, branches)
                )
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value
        ):
            definitions.append(
                _Definition(
                    statement.target.id, statement.lineno, statement.value, branches
                )
            )
        elif isinstance(statement, ast.AugAssign) and isinstance(
            statement.target, ast.Name
        ):
            definitions.append(
                _Definition(
                    statement.target.id, statement.lineno, statement.value, branches
                )
            )


def _single_source(items: list[_Source | None]) -> _Source | None:
    sources = [item for item in items if item is not None]
    return sources[0] if len(sources) == 1 else None


def _trace_expression(
    expression: ast.expr,
    definitions: list[_Definition],
    before_line: int,
    branches: tuple[str, ...],
    seen: frozenset[str],
) -> _Source | None:
    if isinstance(expression, ast.Name):
        if expression.id in seen:
            return None
        matching = [
            item
            for item in definitions
            if item.name == expression.id and item.line < before_line
        ]
        if len(matching) != 1 or not set(matching[0].branches).issubset(branches):
            return None
        definition = matching[0]
        source = _trace_expression(
            definition.value,
            definitions,
            definition.line,
            definition.branches,
            seen | {expression.id},
        )
        if source is None:
            return None
        return _Source(
            source.line,
            source.access,
            source.key,
            (*source.nodes, f"{definition.name}@{definition.line}"),
        )
    if isinstance(expression, ast.Call):
        callee = _name(expression.func)
        if callee in {"request.args.get", "request.form.get", "request.headers.get"}:
            if (
                expression.args
                and isinstance(expression.args[0], ast.Constant)
                and isinstance(expression.args[0].value, str)
            ):
                return _Source(
                    expression.lineno,
                    callee.removesuffix(".get"),
                    expression.args[0].value,
                    (),
                )
            return None
        if isinstance(expression.func, ast.Attribute) and expression.func.attr == "get":
            receiver = _trace_expression(
                expression.func.value, definitions, before_line, branches, seen
            )
            if (
                receiver is not None
                and receiver.access == "request.json"
                and receiver.key == ""
                and expression.args
                and isinstance(expression.args[0], ast.Constant)
                and isinstance(expression.args[0].value, str)
            ):
                return _Source(
                    receiver.line,
                    receiver.access,
                    expression.args[0].value,
                    receiver.nodes,
                )
        if callee == "request.get_json":
            return _Source(expression.lineno, "request.json", "", ())
        return None
    if isinstance(expression, ast.Subscript):
        receiver = _trace_expression(
            expression.value, definitions, before_line, branches, seen
        )
        if (
            receiver is not None
            and receiver.access == "request.json"
            and receiver.key == ""
            and isinstance(expression.slice, ast.Constant)
            and isinstance(expression.slice.value, str)
        ):
            return _Source(
                receiver.line, receiver.access, expression.slice.value, receiver.nodes
            )
        return None
    if (
        isinstance(expression, ast.BoolOp)
        and isinstance(expression.op, ast.Or)
        and len(expression.values) == 2
    ):
        if isinstance(expression.values[1], ast.Dict) and not expression.values[1].keys:
            return _trace_expression(
                expression.values[0], definitions, before_line, branches, seen
            )
        return None
    if isinstance(expression, ast.JoinedStr):
        return _single_source(
            [
                _trace_expression(value.value, definitions, before_line, branches, seen)
                for value in expression.values
                if isinstance(value, ast.FormattedValue)
            ]
        )
    if isinstance(expression, ast.BinOp) and isinstance(
        expression.op, (ast.Add, ast.Mod)
    ):
        return _single_source(
            [
                _trace_expression(
                    expression.left, definitions, before_line, branches, seen
                ),
                _trace_expression(
                    expression.right, definitions, before_line, branches, seen
                ),
            ]
        )
    return None


def _trace_agrees(flow_trace: Mapping[str, object] | None, anchor: FlowAnchor) -> bool:
    if flow_trace is None:
        return True
    for end, expected_line in (
        ("source", anchor.source_line),
        ("sink", anchor.sink_line),
    ):
        endpoint = flow_trace.get(end)
        if not isinstance(endpoint, Mapping):
            return False
        if (
            endpoint.get("path") != anchor.source_file
            or endpoint.get("line") != expected_line
        ):
            return False
    return True


def resolve_flow_anchor(
    workspace: Path,
    path: str,
    expected_sha256: str,
    proposal: Mapping[str, object],
    cwe: str,
    flow_trace: Mapping[str, object] | None = None,
) -> FlowAnchor | None:
    """Return an exact key only when one cited sink traces to one request key."""

    raw = _safe_source(workspace, path, expected_sha256)
    if raw is None:
        return None
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=path)
    except (UnicodeError, SyntaxError):
        return None
    cited = _locations(proposal, path)
    if not cited or cwe.upper().replace("_", "-") != "CWE-78":
        return None
    matches: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, _Callsite]] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        definitions: list[_Definition] = []
        calls: list[_Callsite] = []
        _scan_statements(function.body, (), definitions, calls)
        for callsite in calls:
            callee = _name(callsite.call.func)
            if callee in _COMMAND_SINKS and callsite.call.lineno in cited:
                matches.append((function, callsite))
    if len(matches) != 1:
        return None
    function, callsite = matches[0]
    call = callsite.call
    if not call.args:
        return None
    if any(
        isinstance(
            node, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Match)
        )
        and node.lineno < call.lineno
        for node in ast.walk(function)
    ):
        return None
    definitions = []
    _scan_statements(function.body, (), definitions, [])
    source = _trace_expression(
        call.args[0], definitions, call.lineno, callsite.branches, frozenset()
    )
    if source is None or not source.key:
        return None
    callee = _name(call.func)
    if callee is None:
        return None
    anchor = FlowAnchor(
        route=_route(function),
        function=function.name,
        source_file=path,
        source_line=source.line,
        source_access=source.access,
        source_key=source.key,
        def_use_nodes=source.nodes,
        sink_file=path,
        sink_line=call.lineno,
        sink_callee=callee,
        sink_argument=0,
        branch_nodes=callsite.branches,
        cwe="CWE-78",
    )
    return anchor if _trace_agrees(flow_trace, anchor) else None
