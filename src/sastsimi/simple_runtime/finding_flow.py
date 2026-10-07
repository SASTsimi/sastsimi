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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal


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
    trace_nodes: tuple[str, ...] = ()


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
class _ReturnSite:
    value: ast.expr
    line: int
    branches: tuple[str, ...]


@dataclass(frozen=True)
class _Source:
    line: int
    access: str
    key: str
    nodes: tuple[str, ...]


@dataclass(frozen=True)
class _Route:
    path: str
    framework: Literal["flask", "fastapi"]


@dataclass(frozen=True)
class _RequestBinding:
    name: str
    accesses: frozenset[str]
    flask: bool
    parameter_line: int | None = None


_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_FLASK_REQUEST = _RequestBinding(
    "request", frozenset({"args", "form", "headers", "cookies"}), True
)
_FASTAPI_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "trace"}
)
_FLASK_ROUTE_METHODS = frozenset({"route", "get", "post", "put", "delete", "patch"})
_COMMAND_SINKS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
}
_DIRECT_SINKS: dict[str, frozenset[str]] = {
    "CWE-78": frozenset(_COMMAND_SINKS),
    "CWE-79": frozenset({"make_response", "render_template_string"}),
    "CWE-89": frozenset(),  # Receiver name is proven through sqlite3 provenance.
    "CWE-95": frozenset({"eval"}),
    "CWE-918": frozenset({"requests.get", "requests.post"}),
    "CWE-22": frozenset({"open"}),
    "CWE-1336": frozenset({"render_template_string"}),
}
_ONE_HOP_SQL_METHODS = frozenset(
    {"execute", "executemany", "executescript", "execute_fetchall", "execute_insert"}
)


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
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _root_name(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _route(
    tree: ast.Module, function: ast.FunctionDef | ast.AsyncFunctionDef
) -> _Route | None:
    if len(function.decorator_list) != 1:
        return None
    decorator = function.decorator_list[0]
    if not isinstance(decorator, ast.Call) or len(decorator.args) != 1:
        return None
    method = _name(decorator.func)
    receiver = (
        decorator.func.value if isinstance(decorator.func, ast.Attribute) else None
    )
    first = decorator.args[0]
    if (
        method is None
        or not isinstance(receiver, ast.Name)
        or not isinstance(first, ast.Constant)
        or not isinstance(first.value, str)
        or not first.value
    ):
        return None
    route_method = method.rsplit(".", 1)[-1]
    if route_method in _FLASK_ROUTE_METHODS and _direct_app_binding(
        tree, receiver.id, "Flask", "flask", _FLASK_ROUTE_METHODS
    ):
        framework: Literal["flask", "fastapi"] = "flask"
    elif route_method in _FASTAPI_ROUTE_METHODS and _direct_app_binding(
        tree, receiver.id, "FastAPI", "fastapi", _FASTAPI_ROUTE_METHODS
    ):
        framework = "fastapi"
    else:
        return None
    for keyword in decorator.keywords:
        if keyword.arg is None:
            return None
        if keyword.arg == "methods":
            methods = keyword.value
            if (
                not isinstance(methods, (ast.List, ast.Tuple))
                or len(methods.elts) != 1
                or not isinstance(methods.elts[0], ast.Constant)
                or not isinstance(methods.elts[0].value, str)
            ):
                return None
        elif not _literal(keyword.value):
            return None
    return _Route(first.value, framework)


def _direct_app_binding(
    tree: ast.Module,
    receiver: str,
    constructor_name: str,
    import_module: str,
    route_methods: frozenset[str],
    *,
    allow_unrelated_getattr: bool = False,
) -> bool:
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {
            "globals",
            "locals",
            "vars",
            "getattr",
            "setattr",
            "delattr",
            "exec",
            "__import__",
        }
        and not (
            allow_unrelated_getattr
            and node.func.id == "getattr"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id
            not in {receiver, constructor_name, "request", "render_template_string"}
        )
        for node in ast.walk(tree)
    ):
        # Dynamic namespace access can register another path to this handler.
        return False
    constructors = [
        item
        for item in tree.body
        if isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Name)
        and item.targets[0].id == receiver
        and isinstance(item.value, ast.Call)
        and isinstance(item.value.func, ast.Name)
        and item.value.func.id == constructor_name
    ]
    flask_imports = [
        (item.module, alias.name, alias.asname)
        for item in tree.body
        if isinstance(item, ast.ImportFrom)
        for alias in item.names
        if (alias.asname or alias.name) == constructor_name
    ]
    if len(constructors) != 1 or flask_imports != [
        (import_module, constructor_name, None)
    ]:
        return False
    if any(
        isinstance(item, ast.Import)
        and any(
            (alias.asname or alias.name) == constructor_name for alias in item.names
        )
        or isinstance(item, ast.ImportFrom)
        and any(alias.name == "*" for alias in item.names)
        for item in tree.body
    ):
        return False
    constructor = constructors[0]
    if not isinstance(constructor.value, ast.Call):
        return False
    if constructor_name == "FastAPI" and (
        constructor.value.args
        or any(
            keyword.arg is None or not _literal(keyword.value)
            for keyword in constructor.value.keywords
        )
    ):
        return False
    allowed_receiver_refs = {
        id(decorator.func.value)
        for statement in tree.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        for decorator in statement.decorator_list
        if isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and isinstance(decorator.func.value, ast.Name)
        and decorator.func.value.id == receiver
        and decorator.func.attr in route_methods
    }
    allowed_receiver_refs.update(
        id(node.func.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == receiver
        and constructor_name == "Flask"
        and node.func.attr == "run"
    )
    for statement in tree.body:
        if statement is constructor or isinstance(
            statement, (ast.Import, ast.ImportFrom)
        ):
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if statement.name in {receiver, constructor_name}:
                return False
        for node in ast.walk(statement):
            if (
                isinstance(node, ast.Name)
                and node.id == receiver
                and id(node) not in allowed_receiver_refs
            ):
                return False
            if (
                isinstance(node, ast.Name)
                and node.id in {receiver, constructor_name}
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return False
            if isinstance(node, ast.ExceptHandler) and node.name in {
                receiver,
                constructor_name,
            }:
                return False
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
                targets = (
                    node.targets
                    if isinstance(node, (ast.Assign, ast.Delete))
                    else (node.target,)
                )
                if any(_root_name(target) == receiver for target in targets):
                    return False
    return True


def _fastapi_request_binding(
    tree: ast.Module, function: ast.FunctionDef | ast.AsyncFunctionDef
) -> _RequestBinding | None:
    args = function.args
    if (
        args.posonlyargs
        or len(args.args) != 1
        or args.kwonlyargs
        or args.vararg
        or args.kwarg
        or args.defaults
        or args.kw_defaults
    ):
        return None
    parameter = args.args[0]
    if (
        not isinstance(parameter.annotation, ast.Name)
        or parameter.annotation.id != "Request"
    ):
        return None
    imports = [
        (item.module, alias.name, alias.asname)
        for item in tree.body
        if isinstance(item, ast.ImportFrom)
        for alias in item.names
        if (alias.asname or alias.name) == "Request"
    ]
    if imports not in [
        [("fastapi", "Request", None)],
        [("starlette.requests", "Request", None)],
    ]:
        return None
    if any(
        isinstance(item, ast.Import)
        and any((alias.asname or alias.name) == "Request" for alias in item.names)
        or isinstance(item, ast.ImportFrom)
        and any(alias.name == "*" for alias in item.names)
        for item in tree.body
    ):
        return None
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == "Request"
        or isinstance(node, ast.Name)
        and node.id == "Request"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        or isinstance(node, ast.ExceptHandler)
        and node.name == "Request"
        for node in ast.walk(tree)
    ):
        return None
    return _RequestBinding(
        parameter.arg,
        frozenset({"query_params"}),
        False,
    )


def _fastapi_query_binding(
    tree: ast.Module,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    route: str,
    sink_line: int,
) -> _RequestBinding | None:
    args = function.args
    if (
        "{" in route
        or "}" in route
        or args.posonlyargs
        or not args.args
        or args.kwonlyargs
        or args.vararg
        or args.kwarg
        or args.kw_defaults
        or any(not isinstance(default, ast.Constant) for default in args.defaults)
    ):
        return None
    active = [
        parameter
        for parameter in args.args
        if any(
            isinstance(node, ast.Name)
            and node.id == parameter.arg
            and isinstance(node.ctx, ast.Load)
            and node.lineno <= sink_line
            for statement in function.body
            for node in ast.walk(statement)
        )
    ]
    if len(active) != 1:
        return None
    parameter = active[0]
    index = args.args.index(parameter)
    default_index = index - (len(args.args) - len(args.defaults))
    if default_index >= 0:
        default = args.defaults[default_index]
        if not isinstance(default, ast.Constant) or default.value not in (None, ""):
            return None
    annotation = parameter.annotation
    optional_string = (
        isinstance(annotation, ast.Subscript)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id == "Optional"
        and isinstance(annotation.slice, ast.Name)
        and annotation.slice.id == "str"
        and _stable_imports(
            tree,
            function,
            "Optional",
            ("typing", "Optional"),
            require_flask_request=False,
        )
    )
    if (
        not (isinstance(annotation, ast.Name) and annotation.id == "str")
        and not optional_string
        or not _stable_builtin(tree, function, "str", require_flask_request=False)
    ):
        return None
    return _RequestBinding(parameter.arg, frozenset(), False, parameter.lineno)


def _stable_imports(
    tree: ast.Module,
    function: ast.AST,
    sink_root: str,
    sink_binding: tuple[str, str] | None = None,
    *,
    require_flask_request: bool = True,
    allow_unrelated_nested_imports: bool = False,
) -> bool:
    bindings: dict[str, list[tuple[str, str]]] = {sink_root: []}
    if require_flask_request:
        bindings["request"] = []
    for item in tree.body:
        if isinstance(item, ast.Import):
            for alias in item.names:
                bound = alias.asname or alias.name.partition(".")[0]
                if bound in bindings:
                    bindings[bound].append(("import", alias.name))
        elif isinstance(item, ast.ImportFrom):
            for alias in item.names:
                if alias.name == "*":
                    return False
                bound = alias.asname or alias.name
                if bound in bindings:
                    bindings[bound].append((item.module or "", alias.name))
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if item.name in bindings:
                return False
    if (
        require_flask_request
        and bindings["request"] != [("flask", "request")]
        or bindings[sink_root] != [sink_binding or ("import", sink_root)]
    ):
        return False
    if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
        arg.arg in ({"request", sink_root} if require_flask_request else {sink_root})
        for arg in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
            *((function.args.vararg,) if function.args.vararg else ()),
            *((function.args.kwarg,) if function.args.kwarg else ()),
        )
    ):
        return False
    protected = {"request", sink_root} if require_flask_request else {sink_root}
    for statement in tree.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        for node in ast.walk(statement):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if not allow_unrelated_nested_imports:
                    return False
                if isinstance(node, ast.ImportFrom) and any(
                    alias.name == "*" for alias in node.names
                ):
                    return False
                if any(
                    (
                        (alias.asname or alias.name.partition(".")[0])
                        if isinstance(node, ast.Import)
                        else (alias.asname or alias.name)
                    )
                    in protected
                    for alias in node.names
                ):
                    return False
                continue
            if (
                isinstance(node, ast.Name)
                and node.id in protected
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return False
            if isinstance(node, ast.ExceptHandler) and node.name in protected:
                return False
            if isinstance(
                node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)
            ):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else (node.target,)
                )
                if any(_root_name(target) in protected for target in targets):
                    return False
    return True


def _stable_builtin(
    tree: ast.Module,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
    *,
    require_flask_request: bool = True,
) -> bool:
    """Only treat an unshadowed built-in call as an identity-bearing sink."""

    if require_flask_request and not _stable_imports(
        tree, function, "request", ("flask", "request")
    ):
        return False
    if any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for node in ast.walk(tree)
    ):
        return False
    if any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and any((alias.asname or alias.name) == name for alias in node.names)
        for node in ast.walk(tree)
    ):
        return False
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == name
        or isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        or isinstance(node, ast.Attribute)
        and node.attr == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(tree)
    ):
        return False
    return not any(
        arg.arg == name
        for arg in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
            *((function.args.vararg,) if function.args.vararg else ()),
            *((function.args.kwarg,) if function.args.kwarg else ()),
        )
    )


def _sqlite_cursor_setup(
    definitions: list[_Definition],
    call: ast.Call,
    branches: tuple[str, ...],
    tree: ast.Module,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    require_flask_request: bool = True,
) -> set[int] | None:
    """Prove a local cursor came from a directly imported sqlite3 connection."""

    if not isinstance(call.func, ast.Attribute) or not isinstance(
        call.func.value, ast.Name
    ):
        return None
    cursor_name = call.func.value.id
    cursor_definitions = [item for item in definitions if item.name == cursor_name]
    if len(cursor_definitions) != 1:
        return None
    cursor = cursor_definitions[0]
    if (
        cursor.line >= call.lineno
        or not set(cursor.branches).issubset(branches)
        or not isinstance(cursor.value, ast.Call)
        or cursor.value.args
        or cursor.value.keywords
        or not isinstance(cursor.value.func, ast.Attribute)
        or cursor.value.func.attr != "cursor"
        or not isinstance(cursor.value.func.value, ast.Name)
    ):
        return None
    connection_name = cursor.value.func.value.id
    connection_definitions = [
        item for item in definitions if item.name == connection_name
    ]
    if len(connection_definitions) != 1:
        return None
    connection = connection_definitions[0]
    connection_arguments = (
        connection.value.args if isinstance(connection.value, ast.Call) else []
    )
    if (
        connection.line >= cursor.line
        or not set(connection.branches).issubset(cursor.branches)
        or not isinstance(connection.value, ast.Call)
        or _name(connection.value.func) != "sqlite3.connect"
        or len(connection_arguments) != 1
        or not (
            _literal(connection_arguments[0])
            or _stable_module_string(tree, function, connection_arguments[0])
        )
        or any(
            keyword.arg is None or not _literal(keyword.value)
            for keyword in connection.value.keywords
        )
        or not _stable_imports(
            tree, function, "sqlite3", require_flask_request=require_flask_request
        )
    ):
        return None
    return {id(cursor.value), id(connection.value)}


def _stable_module_string(
    tree: ast.Module,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    expression: ast.expr,
) -> bool:
    if not isinstance(expression, ast.Name):
        return False
    name = expression.id
    definitions = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == name
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    ]
    if len(definitions) != 1:
        return False
    if any(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node is not definitions[0].targets[0]
        for node in ast.walk(tree)
    ):
        return False
    if any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and any((alias.asname or alias.name) == name for alias in node.names)
        for node in ast.walk(tree)
    ):
        return False
    return not any(
        arg.arg == name
        for arg in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
            *((function.args.vararg,) if function.args.vararg else ()),
            *((function.args.kwarg,) if function.args.kwarg else ()),
        )
    )


def _unsupported_writes(
    function: ast.FunctionDef | ast.AsyncFunctionDef, sink_line: int
) -> bool:
    if any(
        getattr(node, "lineno", sink_line + 1) <= sink_line
        and (
            isinstance(
                node, (ast.NamedExpr, ast.Delete, ast.Global, ast.Nonlocal, ast.Lambda)
            )
            or isinstance(node, (ast.Import, ast.ImportFrom))
            or isinstance(node, ast.ExceptHandler)
            and node.name is not None
            or isinstance(node, ast.Assign)
            and (len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name))
            or isinstance(node, ast.AnnAssign)
            and not isinstance(node.target, ast.Name)
            or isinstance(node, ast.AugAssign)
        )
        for statement in function.body
        for node in ast.walk(statement)
    ):
        return True
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.lineno <= sink_line
        for statement in function.body
        for node in ast.walk(statement)
    )


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


def _return_sites(
    statements: list[ast.stmt], branches: tuple[str, ...] = ()
) -> list[_ReturnSite]:
    """Collect only returns on linear, branch-labelled paths."""

    sites: list[_ReturnSite] = []
    for statement in statements:
        if isinstance(statement, ast.If):
            sites.extend(
                _return_sites(statement.body, (*branches, f"if:{statement.lineno}:yes"))
            )
            sites.extend(
                _return_sites(
                    statement.orelse, (*branches, f"if:{statement.lineno}:no")
                )
            )
            continue
        if isinstance(statement, (ast.Try, ast.TryStar)):
            sites.extend(
                _return_sites(
                    statement.body, (*branches, f"try:{statement.lineno}:body")
                )
            )
            for index, handler in enumerate(statement.handlers):
                sites.extend(
                    _return_sites(
                        handler.body,
                        (*branches, f"try:{statement.lineno}:except:{index}"),
                    )
                )
            sites.extend(
                _return_sites(
                    statement.orelse, (*branches, f"try:{statement.lineno}:else")
                )
            )
            sites.extend(
                _return_sites(
                    statement.finalbody, (*branches, f"try:{statement.lineno}:finally")
                )
            )
            continue
        if isinstance(
            statement,
            (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Match),
        ):
            continue
        if isinstance(statement, ast.Return) and statement.value is not None:
            sites.append(_ReturnSite(statement.value, statement.lineno, branches))
    return sites


def _literal(value: ast.expr) -> bool:
    if isinstance(value, ast.Constant):
        return True
    if isinstance(value, (ast.Tuple, ast.List)):
        return len(value.elts) <= 32 and all(_literal(item) for item in value.elts)
    if isinstance(value, ast.Dict):
        return (
            len(value.keys) <= 32
            and all(key is not None and _literal(key) for key in value.keys)
            and all(_literal(item) for item in value.values)
        )
    return False


def _trace_expression(
    expression: ast.expr,
    definitions: list[_Definition],
    before_line: int,
    branches: tuple[str, ...],
    seen: frozenset[str],
    *,
    cited_source_lines: frozenset[int] | None = None,
    binding: _RequestBinding = _FLASK_REQUEST,
) -> _Source | None:
    if isinstance(expression, ast.Name):
        if expression.id in seen:
            return None
        matching = [
            item
            for item in definitions
            if item.name == expression.id and item.line < before_line
        ]
        if (
            not matching
            and binding.parameter_line is not None
            and expression.id == binding.name
        ):
            return _Source(binding.parameter_line, "fastapi.query", binding.name, ())
        if len(matching) != 1 or not set(matching[0].branches).issubset(branches):
            return None
        definition = matching[0]
        source = _trace_expression(
            definition.value,
            definitions,
            definition.line,
            definition.branches,
            seen | {expression.id},
            cited_source_lines=cited_source_lines,
            binding=binding,
        )
        if source is None:
            return None
        return _Source(
            source.line,
            source.access,
            source.key,
            (*source.nodes, f"{definition.name}@{definition.line}"),
        )
    if isinstance(expression, ast.Await) and not binding.flask:
        awaited = expression.value
        if (
            isinstance(awaited, ast.Call)
            and _name(awaited.func) == f"{binding.name}.json"
            and not awaited.args
            and not awaited.keywords
        ):
            return _Source(expression.lineno, f"{binding.name}.json", "", ())
        return None
    if isinstance(expression, ast.Call):
        callee = _name(expression.func)
        if callee in {f"{binding.name}.{access}.get" for access in binding.accesses}:
            if (
                expression.args
                and len(expression.args) <= 2
                and (len(expression.args) == 1 or _literal(expression.args[1]))
                and not expression.keywords
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
                expression.func.value,
                definitions,
                before_line,
                branches,
                seen,
                cited_source_lines=cited_source_lines,
                binding=binding,
            )
            if (
                receiver is not None
                and receiver.access
                == ("request.json" if binding.flask else f"{binding.name}.json")
                and receiver.key == ""
                and expression.args
                and len(expression.args) <= 2
                and (len(expression.args) == 1 or _literal(expression.args[1]))
                and not expression.keywords
                and isinstance(expression.args[0], ast.Constant)
                and isinstance(expression.args[0].value, str)
            ):
                return _Source(
                    receiver.line,
                    receiver.access,
                    expression.args[0].value,
                    receiver.nodes,
                )
        if binding.flask and callee == "request.get_json":
            if expression.args or any(
                keyword.arg is None or not _literal(keyword.value)
                for keyword in expression.keywords
            ):
                return None
            return _Source(expression.lineno, "request.json", "", ())
        return None
    if isinstance(expression, ast.Subscript):
        receiver = _trace_expression(
            expression.value,
            definitions,
            before_line,
            branches,
            seen,
            cited_source_lines=cited_source_lines,
            binding=binding,
        )
        if (
            receiver is not None
            and receiver.access
            == ("request.json" if binding.flask else f"{binding.name}.json")
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
                expression.values[0],
                definitions,
                before_line,
                branches,
                seen,
                cited_source_lines=cited_source_lines,
                binding=binding,
            )
        return None
    if isinstance(expression, ast.JoinedStr):
        formatted = [
            value
            for value in expression.values
            if isinstance(value, ast.FormattedValue)
        ]
        if len(formatted) == 1:
            if formatted[0].format_spec is not None:
                return None
            return _trace_expression(
                formatted[0].value,
                definitions,
                before_line,
                branches,
                seen,
                cited_source_lines=cited_source_lines,
                binding=binding,
            )
        if cited_source_lines is None:
            return None
        sources = [
            _trace_expression(
                value.value,
                definitions,
                before_line,
                branches,
                seen,
                cited_source_lines=cited_source_lines,
                binding=binding,
            )
            for value in formatted
            if value.format_spec is None
        ]
        selected = {
            (source.line, source.access, source.key, source.nodes): source
            for source in sources
            if source is not None and source.line in cited_source_lines
        }
        return next(iter(selected.values())) if len(selected) == 1 else None
    if isinstance(expression, ast.BinOp) and isinstance(
        expression.op, (ast.Add, ast.Mod)
    ):
        if _literal(expression.left):
            return _trace_expression(
                expression.right,
                definitions,
                before_line,
                branches,
                seen,
                cited_source_lines=cited_source_lines,
                binding=binding,
            )
        if _literal(expression.right):
            return _trace_expression(
                expression.left,
                definitions,
                before_line,
                branches,
                seen,
                cited_source_lines=cited_source_lines,
                binding=binding,
            )
        return None
    return None


def _request_input_lines(
    tree: ast.AST, binding: _RequestBinding = _FLASK_REQUEST
) -> list[int]:
    if binding.parameter_line is not None:
        return [binding.parameter_line]
    return [
        node.lineno
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Attribute)
            and _name(node)
            in {f"{binding.name}.{access}" for access in binding.accesses}
        )
        or (
            binding.flask
            and isinstance(node, ast.Call)
            and _name(node.func) == "request.get_json"
        )
        or (
            not binding.flask
            and isinstance(node, ast.Call)
            and _name(node.func) == f"{binding.name}.json"
        )
    ]


def _only_supported_request_uses(
    function: ast.AST,
    sink_line: int,
    *,
    source_line: int | None = None,
    binding: _RequestBinding = _FLASK_REQUEST,
) -> bool:
    """Reject extra cookie-controlled branches outside the proven source flow.

    ``request.cookies`` is a client-controlled source when it is the value
    traced to the sink.  It is not safe to silently accept another cookie
    access elsewhere in the function because it can alter the route to that
    sink.  The existing request containers retain their established behavior
    so independently cited SQL fields can still form separate anchors.
    """

    if binding.parameter_line is not None:
        return not any(
            isinstance(node, ast.Name)
            and node.id == binding.name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.lineno <= sink_line
            for node in ast.walk(function)
        )

    parents = {
        id(child): parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(function):
        if (
            not isinstance(node, ast.Name)
            or node.id != binding.name
            or node.lineno > sink_line
        ):
            continue
        parent = parents.get(id(node))
        if (
            not isinstance(parent, ast.Attribute)
            or parent.value is not node
            or parent.attr
            not in (binding.accesses | ({"get_json"} if binding.flask else {"json"}))
        ):
            return False
        if parent.attr == "cookies" and node.lineno != source_line:
            return False
    return True


def _trace_agrees(
    flow_trace: Mapping[str, object] | None,
    anchor: FlowAnchor,
    tree: ast.AST,
    binding: _RequestBinding = _FLASK_REQUEST,
) -> bool:
    if flow_trace is None:
        return True
    request_lines = _request_input_lines(tree, binding)
    if request_lines.count(anchor.source_line) != 1:
        return False
    has_endpoints = "source" in flow_trace or "sink" in flow_trace
    if has_endpoints:
        for end, expected_line in (
            ("source", anchor.source_line),
            ("sink", anchor.sink_line),
        ):
            endpoint = flow_trace.get(end)
            if not isinstance(endpoint, Mapping) or (
                endpoint.get("path") != anchor.source_file
                or endpoint.get("line") != expected_line
            ):
                return False
    if "sarif_steps" not in flow_trace:
        return has_endpoints
    steps = flow_trace["sarif_steps"]
    if isinstance(steps, list) and len(steps) >= 2:
        allowed_lines = {anchor.source_line, anchor.sink_line}
        for node in anchor.def_use_nodes:
            _, separator, number = node.rpartition("@")
            if separator and number.isdecimal():
                allowed_lines.add(int(number))
        for node in anchor.branch_nodes:
            parts = node.split(":")
            if len(parts) >= 2 and parts[1].isdecimal():
                allowed_lines.add(int(parts[1]))
        if not all(
            isinstance(step, Mapping)
            and step.get("path") == anchor.source_file
            and type(step.get("line")) is int
            and step["line"] in allowed_lines
            and (
                "column" not in step
                or type(step["column"]) is int
                and step["column"] > 0
            )
            for step in steps
        ):
            return False
        lines = [int(step["line"]) for step in steps]
        if (
            lines[0] != anchor.source_line
            or lines[-1] != anchor.sink_line
            or any(left > right for left, right in zip(lines, lines[1:], strict=False))
            or any(
                line in request_lines and line != anchor.source_line
                for line in lines[:-1]
            )
        ):
            return False
        return True
    return False


def _direct_effect_is_unambiguous(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    cwe: str,
) -> bool:
    if cwe not in {"CWE-22", "CWE-79"}:
        return True
    parents = {
        id(child): parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }
    parent = parents.get(id(call))
    if cwe == "CWE-79":
        return isinstance(parent, ast.Return) and parent.value is call
    if (
        not isinstance(parent, ast.Attribute)
        or parent.value is not call
        or parent.attr != "read"
    ):
        return False
    reader = parents.get(id(parent))
    if (
        not isinstance(reader, ast.Call)
        or reader.func is not parent
        or reader.args
        or reader.keywords
    ):
        return False
    if len(call.args) > 2 or any(keyword.arg != "mode" for keyword in call.keywords):
        return False
    modes = ([call.args[1]] if len(call.args) == 2 else []) + [
        keyword.value for keyword in call.keywords
    ]
    return len(modes) <= 1 and all(
        isinstance(mode, ast.Constant) and mode.value in {"r", "rb"} for mode in modes
    )


def _direct_html_f_string(expression: ast.expr) -> bool:
    """Recognize one request interpolation returned as a literal HTML f-string."""

    if not isinstance(expression, ast.JoinedStr):
        return False
    formatted = [
        value for value in expression.values if isinstance(value, ast.FormattedValue)
    ]
    return (
        len(formatted) == 1
        and formatted[0].format_spec is None
        and any(
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and "<" in value.value
            and ">" in value.value
            for value in expression.values
        )
    )


def _direct_html_return_anchor(
    tree: ast.Module,
    path: str,
    cited: set[int],
    cwe: str,
    flow_trace: Mapping[str, object] | None,
) -> FlowAnchor | None:
    """Prove a direct HTML return without treating arbitrary returns as sinks."""

    matches: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, _ReturnSite]] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for site in _return_sites(function.body):
            if site.line in cited and _direct_html_f_string(site.value):
                matches.append((function, site))
    if len(matches) != 1:
        return None
    function, site = matches[0]
    route = _route(tree, function)
    if (
        route is None
        or route.framework != "flask"
        or not _stable_imports(tree, function, "request", ("flask", "request"))
        or _unsupported_writes(function, site.line)
    ):
        return None
    definitions: list[_Definition] = []
    try:
        _scan_statements(function.body, (), definitions, [])
        source = _trace_expression(
            site.value,
            definitions,
            site.line,
            site.branches,
            frozenset(),
            cited_source_lines=frozenset(cited),
        )
    except RecursionError:
        return None
    if (
        source is None
        or not source.key
        or _request_input_lines(function).count(source.line) != 1
        or not _only_supported_request_uses(
            function, site.line, source_line=source.line
        )
    ):
        return None
    anchor = FlowAnchor(
        route=route.path,
        function=function.name,
        source_file=path,
        source_line=source.line,
        source_access=source.access,
        source_key=source.key,
        def_use_nodes=source.nodes,
        sink_file=path,
        sink_line=site.line,
        sink_callee="return_html",
        sink_argument=0,
        branch_nodes=site.branches,
        cwe=cwe,
    )
    return anchor if _trace_agrees(flow_trace, anchor, tree) else None


def _one_hop_fastapi_route(
    tree: ast.Module, function: ast.AsyncFunctionDef
) -> tuple[str, str] | None:
    """Identify one cited FastAPI route without assuming its constructor metadata."""

    if len(function.decorator_list) != 1:
        return None
    decorator = function.decorator_list[0]
    if (
        not isinstance(decorator, ast.Call)
        or not isinstance(decorator.func, ast.Attribute)
        or not isinstance(decorator.func.value, ast.Name)
        or decorator.func.attr not in _FASTAPI_ROUTE_METHODS
        or len(decorator.args) != 1
        or not isinstance(decorator.args[0], ast.Constant)
        or not isinstance(decorator.args[0].value, str)
        or not decorator.args[0].value
        or any(
            keyword.arg is None or not _literal(keyword.value)
            for keyword in decorator.keywords
        )
        or not _stable_imports(
            tree,
            function,
            "FastAPI",
            ("fastapi", "FastAPI"),
            require_flask_request=False,
        )
    ):
        return None
    app_name = decorator.func.value.id
    constructors = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == app_name
        and isinstance(statement.value, ast.Call)
        and _name(statement.value.func) == "FastAPI"
    ]
    if len(constructors) != 1 or constructors[0].lineno >= decorator.lineno:
        return None
    if _one_hop_import_binds(tree, app_name):
        return None
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name in {app_name, "FastAPI"}
        for node in ast.walk(tree)
    ):
        return None
    if any(
        isinstance(node, ast.Name)
        and node.id == app_name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node is not constructors[0].targets[0]
        or isinstance(node, ast.Attribute)
        and _root_name(node) == app_name
        and node.attr in _FASTAPI_ROUTE_METHODS
        and isinstance(node.ctx, (ast.Store, ast.Del))
        or isinstance(node, ast.Name)
        and node.id == function.name
        and isinstance(node.ctx, ast.Load)
        for node in ast.walk(tree)
    ):
        return None
    return decorator.func.attr.upper(), decorator.args[0].value


def _one_hop_import_binds(tree: ast.Module, name: str) -> bool:
    return any(
        isinstance(item, ast.Import)
        and any(
            (alias.asname or alias.name.partition(".")[0]) == name
            for alias in item.names
        )
        or isinstance(item, ast.ImportFrom)
        and any((alias.asname or alias.name) == name for alias in item.names)
        for item in tree.body
    )


def _one_hop_unmodelled_control(function: ast.AST, before_line: int) -> bool:
    if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
        isinstance(statement, (ast.Return, ast.Raise))
        and statement.lineno < before_line
        for statement in function.body
    ):
        # A direct exit ends this path; a later AST call is not reachable.
        # An exit inside a conditional branch still leaves other paths open.
        return True
    return any(
        node.lineno <= before_line
        and (
            isinstance(
                node,
                (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Match),
            )
            or isinstance(node, ast.Call)
            and _name(node.func)
            in {"exec", "eval", "globals", "locals", "vars", "setattr", "delattr"}
        )
        for node in ast.walk(function)
        if hasattr(node, "lineno")
    )


def _one_hop_module_dynamic_binding(tree: ast.Module) -> bool:
    return any(
        (
            isinstance(node, ast.Call)
            and _name(node.func)
            in {
                "globals",
                "locals",
                "vars",
                "getattr",
                "setattr",
                "delattr",
                "exec",
                "eval",
            }
        )
        or (
            isinstance(node, ast.Attribute)
            and node.attr in {"__code__", "__defaults__", "__kwdefaults__"}
            and isinstance(node.ctx, (ast.Store, ast.Del))
        )
        for node in ast.walk(tree)
    )


def _one_hop_mutated_object(tree: ast.Module, name: str) -> bool:
    return any(
        isinstance(node, (ast.Attribute, ast.Subscript))
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and _root_name(node) == name
        for node in ast.walk(tree)
    )


def _one_hop_direct_sql_connector(
    tree: ast.Module,
    function: ast.AsyncFunctionDef,
    expression: ast.expr,
) -> bool:
    if (
        not isinstance(expression, ast.Await)
        or not isinstance(expression.value, ast.Call)
        or _name(expression.value.func) != "aiosqlite.connect"
        or any(keyword.arg is None for keyword in expression.value.keywords)
        or any(isinstance(argument, ast.Starred) for argument in expression.value.args)
        or not _stable_imports(tree, function, "aiosqlite", require_flask_request=False)
    ):
        return False
    return not any(
        isinstance(node, ast.Attribute)
        and _root_name(node) == "aiosqlite"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(tree)
    )


def _one_hop_verified_sql_connector(
    tree: ast.Module,
    helper: ast.AsyncFunctionDef,
    expression: ast.expr,
) -> bool:
    if _one_hop_direct_sql_connector(tree, helper, expression):
        return True
    if (
        not isinstance(expression, ast.Await)
        or not isinstance(expression.value, ast.Call)
        or not isinstance(expression.value.func, ast.Name)
        or expression.value.args
        or expression.value.keywords
    ):
        return False
    provider_name = expression.value.func.id
    providers = [
        item
        for item in tree.body
        if isinstance(item, ast.AsyncFunctionDef) and item.name == provider_name
    ]
    if (
        len(providers) != 1
        or len(
            [
                item
                for item in ast.walk(tree)
                if isinstance(
                    item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
                and item.name == provider_name
            ]
        )
        != 1
        or _one_hop_import_binds(tree, provider_name)
        or _one_hop_mutated_object(tree, provider_name)
        or any(
            isinstance(node, ast.Name)
            and node.id == provider_name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(tree)
        )
    ):
        return False
    provider = providers[0]
    if (
        provider.decorator_list
        or provider.args.posonlyargs
        or provider.args.args
        or provider.args.kwonlyargs
        or provider.args.vararg
        or provider.args.kwarg
        or _one_hop_unmodelled_control(
            provider, max(item.lineno for item in provider.body)
        )
    ):
        return False
    if len(provider.body) == 1 and isinstance(provider.body[0], ast.Return):
        value = provider.body[0].value
    elif (
        len(provider.body) == 2
        and isinstance(provider.body[0], ast.Assign)
        and len(provider.body[0].targets) == 1
        and isinstance(provider.body[0].targets[0], ast.Name)
        and isinstance(provider.body[1], ast.Return)
        and isinstance(provider.body[1].value, ast.Name)
        and provider.body[0].targets[0].id == provider.body[1].value.id
    ):
        value = provider.body[0].value
    else:
        return False
    return value is not None and _one_hop_direct_sql_connector(tree, provider, value)


def _one_hop_sql_anchor(
    tree: ast.Module,
    path: str,
    cited: set[int],
    flow_trace: Mapping[str, object] | None,
) -> FlowAnchor | None:
    """Prove only a direct route argument -> one local helper -> execute flow."""

    # An external trace needs its own multi-function step verifier. Do not
    # silently discard a trace that could distinguish two flows.
    if flow_trace is not None or _one_hop_module_dynamic_binding(tree):
        return None
    matched: list[
        tuple[
            ast.AsyncFunctionDef,
            _Callsite,
            ast.AsyncFunctionDef,
            ast.Call,
            tuple[str, ...],
            str,
            str,
        ]
    ] = []
    for route in tree.body:
        if not isinstance(route, ast.AsyncFunctionDef) or route.lineno not in cited:
            continue
        route_identity = _one_hop_fastapi_route(tree, route)
        if route_identity is None:
            continue
        definitions: list[_Definition] = []
        calls: list[_Callsite] = []
        _scan_statements(route.body, (), definitions, calls)
        for callsite in calls:
            call = callsite.call
            if (
                call.lineno not in cited
                or not isinstance(call.func, ast.Name)
                or not call.args
                or len(call.args) != 1
                or any(
                    keyword.arg is None or not _literal(keyword.value)
                    for keyword in call.keywords
                )
                or _unsupported_writes(route, call.lineno)
                or _one_hop_unmodelled_control(route, call.lineno)
            ):
                continue
            helpers = [
                statement
                for statement in tree.body
                if isinstance(statement, ast.AsyncFunctionDef)
                and statement.name == call.func.id
                and not statement.decorator_list
            ]
            if (
                len(helpers) != 1
                or _one_hop_import_binds(tree, call.func.id)
                or sum(
                    isinstance(
                        statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    )
                    and statement.name == call.func.id
                    for statement in ast.walk(tree)
                )
                != 1
            ):
                continue
            helper = helpers[0]
            parameters = helper.args
            if (
                parameters.posonlyargs
                or not parameters.args
                or parameters.kwonlyargs
                or parameters.vararg
                or parameters.kwarg
                or any(not _literal(default) for default in parameters.defaults)
                or any(
                    keyword.arg not in {arg.arg for arg in parameters.args[1:]}
                    for keyword in call.keywords
                )
                or any(
                    isinstance(node, ast.Name)
                    and node.id == helper.name
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    for node in ast.walk(tree)
                )
                or _one_hop_mutated_object(tree, helper.name)
            ):
                continue
            helper_calls: list[_Callsite] = []
            helper_definitions: list[_Definition] = []
            _scan_statements(helper.body, (), helper_definitions, helper_calls)
            sinks = [
                item
                for item in helper_calls
                if isinstance(item.call.func, ast.Attribute)
                and item.call.func.attr == "execute"
            ]
            sql_calls = [
                node
                for node in ast.walk(helper)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _ONE_HOP_SQL_METHODS
            ]
            if (
                len(sinks) != 1
                or len(sql_calls) != 1
                or sql_calls[0] is not sinks[0].call
            ):
                continue
            sink = sinks[0].call
            if (
                any(
                    helper.lineno <= line <= (helper.end_lineno or helper.lineno)
                    for line in cited
                )
                and sink.lineno not in cited
            ):
                continue
            if (
                not isinstance(sink.func, ast.Attribute)
                or not isinstance(sink.func.value, ast.Name)
                or len(sink.args) != 1
                or not isinstance(sink.args[0], ast.Name)
                or sink.args[0].id != parameters.args[0].arg
                or sink.keywords
                or _unsupported_writes(helper, sink.lineno)
                or _one_hop_unmodelled_control(helper, sink.lineno)
                or any(
                    isinstance(node, ast.Name)
                    and node.id == parameters.args[0].arg
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.lineno <= sink.lineno
                    for node in ast.walk(helper)
                )
            ):
                continue
            receiver = sink.func.value.id
            receiver_defs = [
                item
                for item in helper_definitions
                if item.name == receiver and item.line < sink.lineno
            ]
            if (
                len(receiver_defs) != 1
                or not _one_hop_verified_sql_connector(
                    tree, helper, receiver_defs[0].value
                )
                or not set(receiver_defs[0].branches).issubset(sinks[0].branches)
            ):
                continue
            matched.append(
                (route, callsite, helper, sink, sinks[0].branches, *route_identity)
            )
    if len(matched) != 1:
        return None
    route, callsite, helper, sink, helper_branches, method, route_path = matched[0]
    binding = _fastapi_query_binding(tree, route, route_path, callsite.call.lineno)
    if binding is None or not _only_supported_request_uses(
        route, callsite.call.lineno, source_line=binding.parameter_line, binding=binding
    ):
        return None
    definitions = []
    _scan_statements(route.body, (), definitions, [])
    source = _trace_expression(
        callsite.call.args[0],
        definitions,
        callsite.call.lineno,
        callsite.branches,
        frozenset(),
        cited_source_lines=frozenset(cited),
        binding=binding,
    )
    if source is None or source.line != route.lineno or not source.key:
        return None
    return FlowAnchor(
        route=f"{method} {route_path}",
        function=route.name,
        source_file=path,
        source_line=source.line,
        source_access=source.access,
        source_key=source.key,
        def_use_nodes=(
            *source.nodes,
            f"{helper.name}@{callsite.call.lineno}",
            f"{helper.args.args[0].arg}@{helper.lineno}",
        ),
        sink_file=path,
        sink_line=sink.lineno,
        sink_callee=_name(sink.func) or "",
        sink_argument=0,
        branch_nodes=tuple(f"{route.name}:{branch}" for branch in callsite.branches)
        + tuple(f"{helper.name}:{branch}" for branch in helper_branches),
        cwe="CWE-89",
    )


def _single_percent_string(value: ast.expr) -> ast.expr | None:
    """Return the one inserted value of a literal ``%s`` string."""

    if (
        not isinstance(value, ast.BinOp)
        or not isinstance(value.op, ast.Mod)
        or not isinstance(value.left, ast.Constant)
        or not isinstance(value.left.value, str)
    ):
        return None
    template = value.left.value.replace("%%", "")
    if template.count("%s") != 1 or template.count("%") != 1:
        return None
    return value.right


def _flask_module_attributes_stable(tree: ast.Module) -> bool:
    """Do not prove a Flask flow if its imported source or sink is replaced."""

    module_names = {
        alias.asname or "flask"
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "flask"
    }
    protected = {"request", "render_template_string"}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and isinstance(node.value, ast.Name)
            and node.value.id in module_names
            and node.attr in protected
        ):
            return False
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in module_names
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in protected
        ):
            return False
    return True


def _flask_post_ssti_route(tree: ast.Module, function: ast.FunctionDef) -> str | None:
    """Prove one stable Flask POST route without relaxing other flow families."""

    if len(function.decorator_list) != 1:
        return None
    decorator = function.decorator_list[0]
    if (
        not isinstance(decorator, ast.Call)
        or not isinstance(decorator.func, ast.Attribute)
        or decorator.func.attr != "route"
        or not isinstance(decorator.func.value, ast.Name)
        or len(decorator.args) != 1
        or not isinstance(decorator.args[0], ast.Constant)
        or not isinstance(decorator.args[0].value, str)
        or not decorator.args[0].value
        or len(decorator.keywords) != 1
        or decorator.keywords[0].arg != "methods"
    ):
        return None
    methods = decorator.keywords[0].value
    if (
        not isinstance(methods, (ast.List, ast.Tuple))
        or not 1 <= len(methods.elts) <= 2
        or any(
            not isinstance(item, ast.Constant) or not isinstance(item.value, str)
            for item in methods.elts
        )
        or {item.value for item in methods.elts if isinstance(item, ast.Constant)}
        not in ({"POST"}, {"POST", "GET"})
    ):
        return None
    app_name = decorator.func.value.id
    if (
        not _flask_module_attributes_stable(tree)
        or not _direct_app_binding(
            tree,
            app_name,
            "Flask",
            "flask",
            _FLASK_ROUTE_METHODS,
            allow_unrelated_getattr=True,
        )
        or not _stable_imports(
            tree,
            function,
            "render_template_string",
            ("flask", "render_template_string"),
            allow_unrelated_nested_imports=True,
        )
    ):
        return None
    if (
        sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == function.name
            for node in ast.walk(tree)
        )
        != 1
        or _one_hop_import_binds(tree, function.name)
        or any(
            isinstance(node, ast.Name)
            and node.id == function.name
            and isinstance(node.ctx, (ast.Store, ast.Del, ast.Load))
            for node in ast.walk(tree)
        )
    ):
        return None
    return decorator.args[0].value


def _ssti_trace_agrees(
    flow_trace: Mapping[str, object] | None,
    anchor: FlowAnchor,
    tree: ast.Module,
    source_expr: ast.Subscript,
    sink_call: ast.Call,
    source_lines: list[str],
) -> bool:
    """Require every supplied trace identity to match the exact AST flow."""

    if flow_trace is None:
        return True
    if (
        "source_key" in flow_trace
        and flow_trace["source_key"] != anchor.source_key
        or "sink_argument" in flow_trace
        and (
            type(flow_trace["sink_argument"]) is not int
            or flow_trace["sink_argument"] != anchor.sink_argument
        )
    ):
        return False
    for endpoint, node in (("source", source_expr), ("sink", sink_call)):
        location = flow_trace.get(endpoint)
        if (
            isinstance(location, Mapping)
            and "column" in location
            and not _ssti_column_agrees(location["column"], node, source_lines)
        ):
            return False
    steps = flow_trace.get("sarif_steps")
    if isinstance(steps, list) and len(steps) >= 2:
        for position, node in ((steps[0], source_expr), (steps[-1], sink_call)):
            if (
                isinstance(position, Mapping)
                and "column" in position
                and not _ssti_column_agrees(position["column"], node, source_lines)
            ):
                return False
    return _trace_agrees(flow_trace, anchor, tree)


def _ssti_column_agrees(column: object, node: ast.AST, lines: list[str]) -> bool:
    """Compare columns only where Python byte offsets cannot be ambiguous."""

    line = getattr(node, "lineno", None)
    start = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end = getattr(node, "end_col_offset", None)
    if (
        type(column) is not int
        or type(line) is not int
        or type(start) is not int
        or type(end) is not int
        or line != end_line
        or not 1 <= line <= len(lines)
    ):
        return False
    if not lines[line - 1].isascii():
        return False
    return start + 1 <= column < end + 1


def _flask_post_percent_ssti_anchor(
    tree: ast.Module,
    path: str,
    cited: set[int],
    flow_trace: Mapping[str, object] | None,
    source_lines: list[str],
) -> FlowAnchor | None:
    """Prove the exact POST form -> two literal %s strings -> Jinja sink path."""

    matches: list[FlowAnchor] = []
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef) or len(function.body) != 4:
            continue
        route = _flask_post_ssti_route(tree, function)
        if route is None:
            continue
        initial, guard, template_assignment, returned = function.body
        if (
            not isinstance(initial, ast.Assign)
            or len(initial.targets) != 1
            or not isinstance(initial.targets[0], ast.Name)
            or not isinstance(initial.value, ast.Constant)
            or initial.value.value != ""
            or not isinstance(guard, ast.If)
            or guard.orelse
            or len(guard.body) != 1
            or not isinstance(guard.test, ast.Compare)
            or not isinstance(guard.test.left, ast.Attribute)
            or _name(guard.test.left) != "request.method"
            or len(guard.test.ops) != 1
            or not isinstance(guard.test.ops[0], ast.Eq)
            or len(guard.test.comparators) != 1
            or not isinstance(guard.test.comparators[0], ast.Constant)
            or guard.test.comparators[0].value != "POST"
            or not isinstance(guard.body[0], ast.Assign)
            or len(guard.body[0].targets) != 1
            or not isinstance(guard.body[0].targets[0], ast.Name)
            or guard.body[0].targets[0].id != initial.targets[0].id
            or not isinstance(template_assignment, ast.Assign)
            or len(template_assignment.targets) != 1
            or not isinstance(template_assignment.targets[0], ast.Name)
            or template_assignment.targets[0].id == initial.targets[0].id
            or not isinstance(returned, ast.Return)
            or not isinstance(returned.value, ast.Call)
            or _name(returned.value.func) != "render_template_string"
            or len(returned.value.args) != 1
            or returned.value.keywords
            or not isinstance(returned.value.args[0], ast.Name)
            or returned.value.args[0].id != template_assignment.targets[0].id
            or returned.value.lineno not in cited
        ):
            continue
        source_expr = _single_percent_string(guard.body[0].value)
        template_expr = _single_percent_string(template_assignment.value)
        if (
            not isinstance(source_expr, ast.Subscript)
            or _name(source_expr.value) != "request.form"
            or not isinstance(source_expr.slice, ast.Constant)
            or not isinstance(source_expr.slice.value, str)
            or not source_expr.slice.value
            or not isinstance(template_expr, ast.Name)
            or template_expr.id != initial.targets[0].id
        ):
            continue
        anchor = FlowAnchor(
            route=f"POST {route}",
            function=function.name,
            source_file=path,
            source_line=source_expr.lineno,
            source_access="request.form",
            source_key=source_expr.slice.value,
            def_use_nodes=(
                f"{initial.targets[0].id}@{guard.body[0].lineno}",
                f"{template_assignment.targets[0].id}@{template_assignment.lineno}",
            ),
            sink_file=path,
            sink_line=returned.value.lineno,
            sink_callee="render_template_string",
            sink_argument=0,
            branch_nodes=(f"if:{guard.lineno}:yes",),
            cwe="CWE-1336",
        )
        if _ssti_trace_agrees(
            flow_trace, anchor, tree, source_expr, returned.value, source_lines
        ):
            matches.append(anchor)
    return matches[0] if len(matches) == 1 else None


def _flask_cookie_route(tree: ast.Module, function: ast.FunctionDef) -> str | None:
    """Resolve one literal Flask route without changing other flow families."""

    if len(function.decorator_list) != 1:
        return None
    decorator = function.decorator_list[0]
    if (
        not isinstance(decorator, ast.Call)
        or not isinstance(decorator.func, ast.Attribute)
        or not isinstance(decorator.func.value, ast.Name)
        or decorator.func.attr not in _FLASK_ROUTE_METHODS
        or len(decorator.args) != 1
        or not isinstance(decorator.args[0], ast.Constant)
        or not isinstance(decorator.args[0].value, str)
        or not decorator.args[0].value.startswith("/")
    ):
        return None
    if decorator.func.attr == "route":
        if decorator.keywords:
            if len(decorator.keywords) != 1 or decorator.keywords[0].arg != "methods":
                return None
            methods = decorator.keywords[0].value
            if (
                not isinstance(methods, (ast.List, ast.Tuple))
                or not 1 <= len(methods.elts) <= 2
            ):
                return None
            values = [
                item.value
                for item in methods.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            ]
            if (
                len(values) != len(methods.elts)
                or not set(values)
                <= {
                    "GET",
                    "POST",
                }
                or len(set(values)) != len(values)
            ):
                return None
    elif decorator.keywords:
        return None
    if (
        not _flask_module_attributes_stable(tree)
        or not _direct_app_binding(
            tree,
            decorator.func.value.id,
            "Flask",
            "flask",
            _FLASK_ROUTE_METHODS,
            allow_unrelated_getattr=True,
        )
        or sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == function.name
            for node in ast.walk(tree)
        )
        != 1
        or _one_hop_import_binds(tree, function.name)
        or any(
            isinstance(node, ast.Name)
            and node.id == function.name
            and isinstance(node.ctx, (ast.Store, ast.Del, ast.Load))
            for node in ast.walk(tree)
        )
    ):
        return None
    return decorator.args[0].value


def _direct_flask_cookie_pickle_anchor(
    tree: ast.Module,
    path: str,
    cited: set[int],
    flow_trace: Mapping[str, object] | None,
    source_lines: list[str],
) -> FlowAnchor | None:
    """Identify only a literal cookie -> base64 -> pickle.loads expression."""

    # A second path to the module can replace ``pickle.loads`` without
    # assigning through the protected ``pickle`` name. Abstain on dynamic
    # module resolution rather than treating the direct import as proof.
    sys_bindings: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.partition(".")[0] in {"importlib", "builtins"}:
                    return None
                if alias.name == "sys":
                    sys_bindings.add(alias.asname or "sys")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").partition(".")[0] in {"importlib", "builtins"}:
                return None
            if node.module == "sys" and any(
                alias.name == "modules" for alias in node.names
            ):
                return None
    if any(
        isinstance(node, ast.Attribute)
        and node.attr == "modules"
        and isinstance(node.value, ast.Name)
        and node.value.id in sys_bindings
        for node in ast.walk(tree)
    ):
        return None
    pickle_imports = [
        alias
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "pickle"
    ]
    if len(pickle_imports) != 1 or pickle_imports[0].asname is not None:
        return None
    matches: list[FlowAnchor] = []
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        route = _flask_cookie_route(tree, function)
        if (
            route is None
            or not _stable_imports(
                tree,
                function,
                "pickle",
                ("import", "pickle"),
                allow_unrelated_nested_imports=True,
            )
            or not _stable_imports(
                tree,
                function,
                "b64decode",
                ("base64", "b64decode"),
                allow_unrelated_nested_imports=True,
            )
        ):
            continue
        calls: list[_Callsite] = []
        try:
            _scan_statements(function.body, (), [], calls)
        except RecursionError:
            return None
        for callsite in calls:
            call = callsite.call
            if (
                _name(call.func) != "pickle.loads"
                or call.lineno not in cited
                or len(call.args) != 1
                or call.keywords
                or _unsupported_writes(function, call.lineno)
            ):
                continue
            decoder = call.args[0]
            if (
                not isinstance(decoder, ast.Call)
                or _name(decoder.func) != "b64decode"
                or len(decoder.args) != 1
                or decoder.keywords
            ):
                continue
            source = decoder.args[0]
            if (
                not isinstance(source, ast.Subscript)
                or _name(source.value) != "request.cookies"
                or not isinstance(source.slice, ast.Constant)
                or not isinstance(source.slice.value, str)
                or not source.slice.value
            ):
                continue
            anchor = FlowAnchor(
                route=route,
                function=function.name,
                source_file=path,
                source_line=source.lineno,
                source_access="request.cookies",
                source_key=source.slice.value,
                def_use_nodes=(f"b64decode@{decoder.lineno}",),
                sink_file=path,
                sink_line=call.lineno,
                sink_callee="pickle.loads",
                sink_argument=0,
                branch_nodes=callsite.branches,
                cwe="CWE-502",
            )
            if _cookie_pickle_trace_agrees(
                flow_trace, anchor, tree, source, call, source_lines
            ):
                matches.append(anchor)
    return matches[0] if len(matches) == 1 else None


def _cookie_pickle_trace_agrees(
    flow_trace: Mapping[str, object] | None,
    anchor: FlowAnchor,
    tree: ast.Module,
    source: ast.Subscript,
    sink: ast.Call,
    source_lines: list[str],
) -> bool:
    if flow_trace is not None:
        source_endpoint = flow_trace.get("source")
        if (
            isinstance(source_endpoint, Mapping)
            and "source_key" in source_endpoint
            and source_endpoint["source_key"] != anchor.source_key
        ):
            return False
        sink_endpoint = flow_trace.get("sink")
        if isinstance(sink_endpoint, Mapping) and "sink_argument" in sink_endpoint:
            position = sink_endpoint["sink_argument"]
            if not (
                type(position) is int
                and position == anchor.sink_argument
                or isinstance(position, str)
                and position == str(anchor.sink_argument)
            ):
                return False
    return _ssti_trace_agrees(flow_trace, anchor, tree, source, sink, source_lines)


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
        source_text = raw.decode("utf-8")
        tree = ast.parse(source_text, filename=path)
    except (UnicodeError, SyntaxError, RecursionError):
        return None
    cited = _locations(proposal, path)
    normalized_cwe = cwe.upper().replace("_", "-")
    if not cited:
        return None
    if normalized_cwe == "CWE-502":
        return _direct_flask_cookie_pickle_anchor(
            tree, path, cited, flow_trace, source_text.splitlines()
        )
    allowed_sinks = _DIRECT_SINKS.get(normalized_cwe)
    if allowed_sinks is None:
        return None
    if normalized_cwe == "CWE-1336":
        return _flask_post_percent_ssti_anchor(
            tree, path, cited, flow_trace, source_text.splitlines()
        )
    if normalized_cwe == "CWE-89":
        try:
            one_hop = _one_hop_sql_anchor(tree, path, cited, flow_trace)
        except RecursionError:
            return None
        if one_hop is not None:
            return one_hop
    if normalized_cwe == "CWE-79":
        direct_return = _direct_html_return_anchor(
            tree, path, cited, normalized_cwe, flow_trace
        )
        if direct_return is not None:
            return direct_return
    matches: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, _Callsite]] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        definitions: list[_Definition] = []
        calls: list[_Callsite] = []
        try:
            _scan_statements(function.body, (), definitions, calls)
        except RecursionError:
            return None
        for callsite in calls:
            callee = _name(callsite.call.func)
            if (
                callee in allowed_sinks
                or normalized_cwe == "CWE-89"
                and callee is not None
                and callee.endswith(".execute")
            ) and callsite.call.lineno in cited:
                matches.append((function, callsite))
    if len(matches) != 1:
        return None
    function, callsite = matches[0]
    call = callsite.call
    if not call.args:
        return None
    callee = _name(call.func)
    if callee is None:
        return None
    route = _route(tree, function)
    if route is None:
        return None
    binding = (
        _FLASK_REQUEST
        if route.framework == "flask"
        else _fastapi_request_binding(tree, function)
        or _fastapi_query_binding(tree, function, route.path, call.lineno)
    )
    if binding is None:
        return None
    require_flask_request = binding.flask
    sink_root = callee.split(".", 1)[0]
    if normalized_cwe == "CWE-89":
        # A same-named local cursor is not proof of a SQL query. Its exact
        # sqlite3 origin is checked below after collecting definitions.
        stable_sink = True
    elif normalized_cwe in {"CWE-95", "CWE-22"}:
        stable_sink = _stable_builtin(
            tree, function, sink_root, require_flask_request=require_flask_request
        )
    elif normalized_cwe == "CWE-79":
        stable_sink = require_flask_request and _stable_imports(
            tree, function, sink_root, ("flask", sink_root)
        )
    else:
        stable_sink = _stable_imports(
            tree, function, sink_root, require_flask_request=require_flask_request
        )
    if (
        not stable_sink
        or not _direct_effect_is_unambiguous(function, call, normalized_cwe)
        or _unsupported_writes(function, call.lineno)
        or any(not _literal(argument) for argument in call.args[1:])
        or any(
            keyword.arg is None or not _literal(keyword.value)
            for keyword in call.keywords
        )
    ):
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
    try:
        _scan_statements(function.body, (), definitions, [])
        setup_calls: set[int] = set()
        if normalized_cwe == "CWE-89":
            proven_setup = _sqlite_cursor_setup(
                definitions,
                call,
                callsite.branches,
                tree,
                function,
                require_flask_request=require_flask_request,
            )
            if proven_setup is None:
                return None
            setup_calls = proven_setup
        skipped_return_calls = (
            {
                id(child)
                for statement in function.body
                for node in ast.walk(statement)
                if isinstance(node, ast.Return) and node.lineno < call.lineno
                for child in ast.walk(node)
                if isinstance(child, ast.Call)
            }
            if not any(branch.endswith(":finally") for branch in callsite.branches)
            else set()
        )
        awaited_json_calls = {
            id(node.value)
            for node in ast.walk(function)
            if isinstance(node, ast.Await)
            and isinstance(node.value, ast.Call)
            and _name(node.value.func) == f"{binding.name}.json"
            and not node.value.args
            and not node.value.keywords
        }
        for statement in function.body:
            for node in ast.walk(statement):
                if (
                    not isinstance(node, ast.Call)
                    or node is call
                    or id(node) in skipped_return_calls
                    or id(node) in awaited_json_calls
                    or id(node) in setup_calls
                    or node.lineno > call.lineno
                ):
                    continue
                if (
                    normalized_cwe == "CWE-95"
                    and _name(node.func) == "str"
                    and len(node.args) == 1
                    and node.args[0] is call
                    and not node.keywords
                ):
                    continue
                if (
                    normalized_cwe == "CWE-22"
                    and isinstance(node.func, ast.Attribute)
                    and node.func.value is call
                    and node.func.attr == "read"
                    and not node.args
                    and not node.keywords
                ):
                    continue
                if (
                    normalized_cwe == "CWE-89"
                    and isinstance(node.func, ast.Attribute)
                    and node.func.value is call
                    and node.func.attr == "fetchone"
                    and not node.args
                    and not node.keywords
                ):
                    continue
                if (
                    _trace_expression(
                        node,
                        definitions,
                        node.lineno,
                        callsite.branches,
                        frozenset(),
                        binding=binding,
                    )
                    is None
                ):
                    return None
        source = _trace_expression(
            call.args[0],
            definitions,
            call.lineno,
            callsite.branches,
            frozenset(),
            cited_source_lines=frozenset(cited),
            binding=binding,
        )
    except RecursionError:
        return None
    if (
        source is None
        or not source.key
        or _request_input_lines(function, binding).count(source.line) != 1
        or not _only_supported_request_uses(
            function, call.lineno, source_line=source.line, binding=binding
        )
    ):
        return None
    anchor = FlowAnchor(
        route=route.path,
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
        cwe=normalized_cwe,
    )
    if not _trace_agrees(flow_trace, anchor, tree, binding):
        return None
    steps = flow_trace.get("sarif_steps") if flow_trace is not None else None
    if isinstance(steps, list) and len(steps) > 2:
        interior = [
            step for step in steps[1:-1] if step != steps[0] and step != steps[-1]
        ]
        anchor = replace(
            anchor,
            trace_nodes=tuple(
                f"{step['path']}:{step['line']}:{step.get('column', '')}"
                for step in interior
            ),
        )
    return anchor
