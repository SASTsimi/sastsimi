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
                return False
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
    except (UnicodeError, SyntaxError, RecursionError):
        return None
    cited = _locations(proposal, path)
    normalized_cwe = cwe.upper().replace("_", "-")
    allowed_sinks = _DIRECT_SINKS.get(normalized_cwe)
    if not cited or allowed_sinks is None:
        return None
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
