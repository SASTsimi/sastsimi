"""Conservative source-bound evidence for simple Flask HTML response flows.

The caller must supply bytes read from the pinned commit. This helper verifies
their expected SHA-256 and records only syntactic flow and an observed escape
call. A matching source call does not prove the runtime callable or output is
safe, and this helper never decides exploitability or confirmation.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

HtmlFlowClassification = Literal["UNESCAPED_INTERPOLATION", "HTML_ESCAPE_CALL_OBSERVED"]


@dataclass(frozen=True, slots=True)
class FlaskHtmlResponseFlowV9:
    path: str
    source_sha256: str
    route_line: int
    request_line: int
    request_key: str
    interpolation_line: int
    response_line: int
    escape_line: int | None
    classification: HtmlFlowClassification


def _name(node: ast.expr) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _stable_bindings(tree: ast.Module, *, escaped: bool, route_line: int) -> bool:
    needed = {"Flask", "request", "make_response"}
    seen: dict[str, int] = {name: 0 for name in needed}
    app_lines = [
        stmt.lineno
        for stmt in tree.body
        if isinstance(stmt, ast.Assign)
        and any(_name(target) == "app" for target in stmt.targets)
    ]
    if len(app_lines) != 1:
        return False
    html_imports = 0
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                bound = alias.asname or alias.name
                if bound in needed:
                    if stmt.level or stmt.module != "flask" or alias.asname:
                        return False
                    required_before = app_lines[0] if bound == "Flask" else route_line
                    if stmt.lineno >= required_before:
                        return False
                    seen[bound] += 1
                elif bound == "html":
                    return False
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                if bound in needed:
                    return False
                if bound == "html":
                    if (
                        alias.name != "html"
                        or alias.asname
                        or escaped
                        and stmt.lineno >= route_line
                    ):
                        return False
                    html_imports += 1
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if stmt.name in needed | {"html", "app"}:
                return False
    if any(count != 1 for count in seen.values()) or (escaped and html_imports != 1):
        return False
    if html_imports > 1:
        return False
    observed_escape_receivers = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr == "escape"
        and _name(node.value) == "html"
        and isinstance(node.ctx, ast.Load)
    }
    for node in ast.walk(tree):
        # Reflection can replace a binding without spelling a direct assignment.
        # Keep this narrow certificate unavailable when such behavior appears.
        if isinstance(node, ast.Call) and _name(node.func) in {
            "globals",
            "locals",
            "vars",
            "exec",
            "eval",
            "__import__",
            "getattr",
        }:
            return False
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in needed | {"html"}:
                return False
        if (
            escaped
            and isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id == "html"
            and id(node) not in observed_escape_receivers
        ):
            return False
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if _name(node.value) in {
                "Flask",
                "app",
                "html",
                "make_response",
                "request",
            }:
                return False
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "__dict__"
            and _name(node.value)
            in {"app", "Flask", "html", "make_response", "request"}
        ):
            return False
        if (
            escaped
            and isinstance(node, ast.Attribute)
            and node.attr == "modules"
            and _name(node.value) == "sys"
        ):
            return False
        if isinstance(node, ast.Subscript) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            base = node.value
            if (
                isinstance(base, ast.Attribute)
                and base.attr == "__dict__"
                and _name(base.value) in {"app", "html", "make_response", "request"}
            ):
                return False
        if isinstance(node, ast.Call) and _name(node.func) in {"setattr", "delattr"}:
            if node.args and _name(node.args[0]) in {
                "app",
                "Flask",
                "html",
                "make_response",
                "request",
            }:
                return False
    return True


def _handler(tree: ast.Module, route_line: int) -> ast.FunctionDef | None:
    apps = [
        stmt
        for stmt in tree.body
        if isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and _name(stmt.targets[0]) == "app"
    ]
    if len(apps) != 1:
        return None
    app = apps[0]
    if (
        app.lineno >= route_line
        or not isinstance(app.value, ast.Call)
        or _name(app.value.func) != "Flask"
        or len(app.value.args) != 1
        or _name(app.value.args[0]) != "__name__"
        or app.value.keywords
    ):
        return None
    if any(
        isinstance(node, ast.Name)
        and node.id == "app"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node is not apps[0].targets[0]
        for node in ast.walk(tree)
    ):
        return None
    matches = []
    for stmt in tree.body:
        if not isinstance(stmt, ast.FunctionDef) or len(stmt.decorator_list) != 1:
            continue
        dec = stmt.decorator_list[0]
        if (
            isinstance(dec, ast.Call)
            and dec.lineno == route_line
            and isinstance(dec.func, ast.Attribute)
            and _name(dec.func.value) == "app"
            and dec.func.attr == "route"
            and len(dec.args) == 1
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
            and dec.args[0].value.startswith("/")
            and not dec.keywords
            and not stmt.args.posonlyargs
            and not stmt.args.args
            and not stmt.args.kwonlyargs
            and stmt.args.vararg is None
            and stmt.args.kwarg is None
        ):
            matches.append(stmt)
    return matches[0] if len(matches) == 1 else None


def _request_read(stmt: ast.stmt, request_line: int) -> tuple[str, str] | None:
    if (
        not isinstance(stmt, ast.Assign)
        or stmt.lineno != request_line
        or len(stmt.targets) != 1
        or (target := _name(stmt.targets[0])) is None
        or not isinstance(stmt.value, ast.Call)
        or not isinstance(stmt.value.func, ast.Attribute)
        or stmt.value.func.attr != "get"
        or not isinstance(stmt.value.func.value, ast.Attribute)
        or _name(stmt.value.func.value.value) != "request"
        or stmt.value.func.value.attr not in {"args", "form"}
        or not 1 <= len(stmt.value.args) <= 2
        or stmt.value.keywords
        or not isinstance(stmt.value.args[0], ast.Constant)
        or not isinstance(stmt.value.args[0].value, str)
        or not stmt.value.args[0].value
        or (
            len(stmt.value.args) == 2
            and not isinstance(stmt.value.args[1], ast.Constant)
        )
    ):
        return None
    return target, stmt.value.args[0].value


def _escape_assignment(stmt: ast.stmt, source_name: str) -> str | None:
    if (
        not isinstance(stmt, ast.Assign)
        or len(stmt.targets) != 1
        or (target := _name(stmt.targets[0])) is None
        or not isinstance(stmt.value, ast.Call)
        or not isinstance(stmt.value.func, ast.Attribute)
        or _name(stmt.value.func.value) != "html"
        or stmt.value.func.attr != "escape"
        or len(stmt.value.args) != 1
        or _name(stmt.value.args[0]) != source_name
        or any(
            keyword.arg != "quote"
            or not isinstance(keyword.value, ast.Constant)
            or keyword.value.value is not True
            for keyword in stmt.value.keywords
        )
    ):
        return None
    return target


def _interpolation_assignment(stmt: ast.stmt, value_name: str) -> str | None:
    if (
        not isinstance(stmt, ast.Assign)
        or len(stmt.targets) != 1
        or (target := _name(stmt.targets[0])) is None
        or not isinstance(stmt.value, ast.JoinedStr)
    ):
        return None
    formatted = [
        item for item in stmt.value.values if isinstance(item, ast.FormattedValue)
    ]
    if (
        len(formatted) != 1
        or _name(formatted[0].value) != value_name
        or formatted[0].format_spec is not None
        or formatted[0].conversion != -1
        or any(
            not isinstance(item, (ast.Constant, ast.FormattedValue))
            for item in stmt.value.values
        )
    ):
        return None
    return target


def _html_response(stmt: ast.stmt, page_name: str) -> bool:
    if not isinstance(stmt, ast.Return) or not isinstance(stmt.value, ast.Call):
        return False
    call = stmt.value
    if (
        _name(call.func) != "make_response"
        or len(call.args) != 3
        or _name(call.args[0]) != page_name
        or not isinstance(call.args[1], ast.Constant)
        or type(call.args[1].value) is not int
        or not isinstance(call.args[2], ast.Dict)
        or call.keywords
    ):
        return False
    headers = call.args[2]
    if len(headers.keys) != 1:
        return False
    key, value = headers.keys[0], headers.values[0]
    if (
        not isinstance(key, ast.Constant)
        or not isinstance(key.value, str)
        or key.value.casefold() != "content-type"
        or not isinstance(value, ast.Constant)
        or not isinstance(value.value, str)
    ):
        return False
    return value.value.split(";", 1)[0].strip().casefold() == "text/html"


def prove_flask_html_response_flow_v9(
    source: bytes,
    *,
    path: str,
    expected_sha256: str,
    route_line: int,
    request_line: int,
) -> FlaskHtmlResponseFlowV9 | None:
    """Classify one exact, linear Flask HTML response; return None on doubt.

    This is a source-bound navigation certificate, not dataflow completeness,
    runtime binding proof, safety, exploitability, or confirmation. The escape
    classification means a call was observed in this source, not that its
    callable or HTML context is safe. The caller must obtain ``source`` from
    the pinned Git commit.
    """

    if (
        not isinstance(source, bytes)
        or "\\" in path
        or ":" in path
        or path.startswith("/")
        or ".." in PurePosixPath(path).parts
        or not path.endswith(".py")
        or not path
        or type(route_line) is not int
        or type(request_line) is not int
        or route_line < 1
        or request_line <= route_line
        or hashlib.sha256(source).hexdigest() != expected_sha256
    ):
        return None
    try:
        tree = ast.parse(source.decode("utf-8"), filename=path)
    except (UnicodeError, SyntaxError, RecursionError, ValueError):
        return None
    function = _handler(tree, route_line)
    if function is None:
        return None
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)
    if len(body) not in {3, 4}:
        return None
    read = _request_read(body[0], request_line)
    if read is None:
        return None
    source_name, request_key = read
    escape_line: int | None = None
    value_name = source_name
    if len(body) == 4:
        escaped_name = _escape_assignment(body[1], source_name)
        if escaped_name is None or escaped_name == source_name:
            return None
        value_name = escaped_name
        escape_line = body[1].lineno
    page_stmt, response_stmt = body[-2:]
    page_name = _interpolation_assignment(page_stmt, value_name)
    if (
        page_name is None
        or page_name in {source_name, value_name}
        or not _html_response(response_stmt, page_name)
        or not _stable_bindings(
            tree, escaped=escape_line is not None, route_line=route_line
        )
    ):
        return None
    return FlaskHtmlResponseFlowV9(
        path=path,
        source_sha256=expected_sha256,
        route_line=route_line,
        request_line=request_line,
        request_key=request_key,
        interpolation_line=page_stmt.lineno,
        response_line=response_stmt.lineno,
        escape_line=escape_line,
        classification=(
            "HTML_ESCAPE_CALL_OBSERVED"
            if escape_line is not None
            else "UNESCAPED_INTERPOLATION"
        ),
    )
