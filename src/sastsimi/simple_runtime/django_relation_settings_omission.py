"""Pure, fail-closed proof for a generated Django relation-settings omission."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from sastsimi.simple_runtime.django_project_defaults import (
    _django_project_default_false,
)

_PYTHON_HEREDOC = re.compile(
    rb"(?m)^[^\r\n]*\bpython(?:3(?:\.[0-9]+)?)?[ \t]+-[^\r\n]*"
    rb"<<[ \t]*'(?P<tag>[A-Za-z_][A-Za-z_0-9]*)'[ \t]*\r?$"
)


def _python_tree(content: bytes) -> ast.Module | None:
    if not content or len(content) > 1024 * 1024:
        return None
    source = content
    if content.startswith(b"#!/bin/sh"):
        openers = tuple(_PYTHON_HEREDOC.finditer(content))
        if len(openers) != 1:
            return None
        opener = openers[0]
        lines = content[opener.end() :].lstrip(b"\r\n").splitlines(keepends=True)
        ending = next(
            (
                index
                for index, line in enumerate(lines)
                if line.strip(b"\r\n") == opener.group("tag")
            ),
            None,
        )
        if ending is None or any(line.strip() for line in lines[ending + 1 :]):
            return None
        source = b"".join(lines[:ending])
    try:
        return ast.parse(source.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None


def _name(node: ast.AST | None, value: str) -> bool:
    return isinstance(node, ast.Name) and node.id == value


def _attr(node: ast.AST, owner: str, attribute: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and _name(node.value, owner)
        and node.attr == attribute
    )


def _assigned_name(node: ast.Assign, name: str) -> bool:
    return len(node.targets) == 1 and _name(node.targets[0], name)


def _candidate_body(tree: ast.Module) -> tuple[list[ast.stmt], ast.Call] | None:
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "settings", "configure")
    ]
    if len(calls) != 1:
        return None
    configure = calls[0]
    owners: list[ast.Module | ast.FunctionDef] = [
        tree,
        *[node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)],
    ]
    for owner in owners:
        if any(
            isinstance(statement, ast.Expr) and statement.value is configure
            for statement in owner.body
        ):
            return owner.body, configure
    return None


def _literal_collector(tree: ast.Module) -> str | None:
    """Recognize a bounded AST-literal collector, not a settings evaluator."""

    matches: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.body:
            continue
        if not (
            isinstance(node.body[-1], ast.Return)
            and _name(node.body[-1].value, "values")
        ):
            continue
        literal_calls = [
            call
            for call in ast.walk(node)
            if isinstance(call, ast.Call) and _attr(call.func, "ast", "literal_eval")
        ]
        if not 1 <= len(literal_calls) <= 3 or any(
            len(call.args) != 1 for call in literal_calls
        ):
            continue
        if any(
            not (
                _attr(call.args[0], "node", "value")
                or isinstance(call.args[0], ast.Attribute)
                and _attr(call.args[0].value, "node", "value")
                and call.args[0].attr in {"left", "right"}
            )
            for call in literal_calls
        ):
            continue
        if not any(
            isinstance(item, ast.Call) and _attr(item.func, "ast", "parse")
            for item in ast.walk(node)
        ):
            continue
        if any(
            isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name)
            and item.func.id
            in {"eval", "exec", "compile", "setattr", "globals", "locals"}
            for item in ast.walk(node)
        ):
            continue
        if any(
            isinstance(item, ast.Assign)
            and any(
                isinstance(target, ast.Subscript) and _name(target.value, "values")
                for target in item.targets
            )
            and not _name(item.value, "value")
            for item in ast.walk(node)
        ):
            continue
        parents = {
            id(child): parent
            for parent in ast.walk(node)
            for child in ast.iter_child_nodes(parent)
        }
        initializers = [
            item
            for item in ast.walk(node)
            if isinstance(item, ast.Assign)
            and _assigned_name(item, "values")
            and isinstance(item.value, ast.Dict)
            and not item.value.keys
        ]
        if len(initializers) != 1:
            continue
        bounded_values = True
        for item in ast.walk(node):
            if not isinstance(item, ast.Name) or item.id != "values":
                continue
            parent = parents.get(id(item))
            grandparent = parents.get(id(parent)) if parent is not None else None
            if (
                item is initializers[0].targets[0]
                or isinstance(parent, ast.Return)
                and parent.value is item
                or isinstance(parent, ast.Subscript)
                and parent.value is item
                and isinstance(parent.ctx, ast.Store)
                and isinstance(grandparent, ast.Assign)
                and len(grandparent.targets) == 1
                and grandparent.targets[0] is parent
                and _name(grandparent.value, "value")
            ):
                continue
            bounded_values = False
            break
        if not bounded_values:
            continue
        matches.append(node.name)
    return matches[0] if len(matches) == 1 else None


def _project_is_literal_collected(tree: ast.Module, collector: str) -> bool:
    project_writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(_name(target, "project") for target in node.targets)
    ]
    if len(project_writes) != 1:
        return False
    value = project_writes[0].value
    if isinstance(value, ast.Call) and _name(value.func, collector):
        return True
    if not (
        isinstance(value, ast.IfExp)
        and _name(value.test, "candidates")
        and isinstance(value.orelse, ast.Dict)
        and not value.orelse.keys
        and isinstance(value.body, ast.Subscript)
    ):
        return False
    collector_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _name(node.func, collector)
    ]
    return len(collector_calls) == 1 and any(
        isinstance(node, ast.Call)
        and _attr(node.func, "candidates", "append")
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Tuple)
        and any(_name(item, "values") for item in node.args[0].elts)
        for node in ast.walk(tree)
    )


def _path_constructor_is_unshadowed(tree: ast.Module) -> bool:
    imports = [
        alias
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "pathlib"
        for alias in node.names
        if alias.name == "Path" and alias.asname is None
    ]
    if len(imports) != 1:
        return False
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if (
            (
                isinstance(node, ast.Name)
                and node.id == "Path"
                and isinstance(node.ctx, (ast.Store, ast.Del))
            )
            or (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name == "Path"
            )
            or isinstance(node, ast.arg)
            and node.arg == "Path"
        ):
            return False
        if isinstance(node, ast.Name) and node.id == "Path":
            parent = parents.get(id(node))
            if not isinstance(parent, ast.Call) or parent.func is not node:
                return False
        if isinstance(node, ast.ImportFrom):
            if any(
                (alias.asname == "Path" or alias.name == "Path")
                and alias is not imports[0]
                for alias in node.names
            ):
                return False
        if isinstance(node, ast.Import) and any(
            alias.asname == "Path" or alias.name == "Path" for alias in node.names
        ):
            return False
        if isinstance(node, ast.ExceptHandler) and node.name == "Path":
            return False
        if isinstance(node, (ast.Global, ast.Nonlocal)) and "Path" in node.names:
            return False
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id
            in {
                "globals",
                "locals",
                "vars",
                "setattr",
                "delattr",
                "eval",
                "exec",
                "__import__",
            }
        ):
            return False
    return True


def django_relation_project_settings_paths(
    candidate: bytes,
    tracked_paths: set[str],
    *,
    app_name: str,
) -> tuple[str, tuple[str, ...], str | None] | None:
    """Bind a literal project path or a bounded rglob to tracked source paths.

    This is deliberately narrower than Python execution: any path expression or
    selection condition that cannot be proved from the syntax fails closed.
    """

    tree = _python_tree(candidate)
    collector = _literal_collector(tree) if tree is not None else None
    if (
        tree is None
        or collector is None
        or not _project_is_literal_collected(tree, collector)
    ):
        return None
    if not _path_constructor_is_unshadowed(tree):
        return None
    project_writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and _assigned_name(node, "project")
    ]
    if len(project_writes) != 1:
        return None
    project = project_writes[0].value

    def path_value(
        node: ast.expr, *, before: int, seen: frozenset[str] = frozenset()
    ) -> str | None:
        if (
            isinstance(node, ast.Call)
            and _name(node.func, "Path")
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = path_value(node.left, before=before, seen=seen)
            if (
                left is not None
                and isinstance(node.right, ast.Constant)
                and isinstance(node.right.value, str)
            ):
                return left.rstrip("/") + "/" + node.right.value
        if isinstance(node, ast.Name):
            if node.id in seen:
                return None
            assignments = [
                item
                for item in ast.walk(tree)
                if isinstance(item, ast.Assign) and _assigned_name(item, node.id)
            ]
            writes = [
                item
                for item in ast.walk(tree)
                if isinstance(item, ast.Name)
                and item.id == node.id
                and isinstance(item.ctx, (ast.Store, ast.Del))
            ]
            if (
                len(assignments) == 1
                and len(writes) == 1
                and writes[0] is assignments[0].targets[0]
                and assignments[0].lineno < before
            ):
                return path_value(
                    assignments[0].value,
                    before=assignments[0].lineno,
                    seen=seen | {node.id},
                )
        return None

    def relative_path(value: str | None) -> str | None:
        if value is None or "\\" in value:
            return None
        path = PurePosixPath(value)
        if not path.is_absolute() or ".." in path.parts:
            return None
        parts = path.parts
        return (
            "/".join(parts[2:])
            if parts[:2] == ("/", "workspace") and len(parts) > 2
            else None
        )

    if (
        isinstance(project, ast.Call)
        and _name(project.func, collector)
        and len(project.args) == 1
        and not project.keywords
    ):
        path = relative_path(path_value(project.args[0], before=project.lineno))
        if (
            path is None
            or path not in tracked_paths
            or not path.endswith("/settings.py")
        ):
            return None
        return "LITERAL", (path,), None

    if not isinstance(project, ast.IfExp):
        return None
    if not (
        isinstance(project.body, ast.Subscript)
        and isinstance(project.body.value, ast.Subscript)
        and _name(project.body.value.value, "candidates")
        and isinstance(project.body.value.slice, ast.Constant)
        and project.body.value.slice.value == 0
        and isinstance(project.body.slice, ast.Constant)
        and project.body.slice.value == 1
    ):
        return None
    loops = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.For)
        and isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Attribute)
        and node.iter.func.attr == "rglob"
        and len(node.iter.args) == 1
        and isinstance(node.iter.args[0], ast.Constant)
        and node.iter.args[0].value == "settings.py"
    ]
    if len(loops) != 1:
        return None
    loop = loops[0]
    loop_iter = loop.iter
    loop_target = loop.target
    if (
        not isinstance(loop_iter, ast.Call)
        or not isinstance(loop_iter.func, ast.Attribute)
        or not isinstance(loop_target, ast.Name)
    ):
        return None
    if any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id == loop_target.id
        and node is not loop_target
        for node in ast.walk(loop)
    ):
        return None
    root = relative_path(path_value(loop_iter.func.value, before=loop.lineno))
    # A root at /workspace itself is also a valid bounded scan.
    if root is None:
        root_raw = path_value(loop_iter.func.value, before=loop.lineno)
        if root_raw != "/workspace":
            return None
        root = ""
    collector_calls = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call) and _name(item.func, collector)
    ]
    appends = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call) and _attr(item.func, "candidates", "append")
    ]
    if len(collector_calls) != 1 or len(appends) != 1:
        return None
    collected = collector_calls[0]
    append = appends[0]
    if not (
        len(collected.args) == 1
        and _name(collected.args[0], loop_target.id)
        and any(collected is item for item in ast.walk(loop))
        and len(append.args) == 1
        and isinstance(append.args[0], ast.Tuple)
        and len(append.args[0].elts) == 2
        and _name(append.args[0].elts[0], loop_target.id)
        and _name(append.args[0].elts[1], "values")
    ):
        return None
    values = [
        item
        for item in ast.walk(loop)
        if isinstance(item, ast.Assign)
        and _assigned_name(item, "values")
        and item.value is collected
    ]
    apps = [
        item
        for item in ast.walk(loop)
        if isinstance(item, ast.Assign)
        and _assigned_name(item, "apps")
        and isinstance(item.value, ast.Call)
        and _attr(item.value.func, "values", "get")
        and item.value.args
        and isinstance(item.value.args[0], ast.Constant)
        and item.value.args[0].value == "INSTALLED_APPS"
    ]
    filters = [
        item
        for item in ast.walk(loop)
        if isinstance(item, ast.If)
        and isinstance(item.test, ast.BoolOp)
        and isinstance(item.test.op, ast.And)
        and any(
            isinstance(part, ast.Compare)
            and len(part.ops) == 1
            and isinstance(part.ops[0], ast.In)
            and isinstance(part.left, ast.Constant)
            and part.left.value == app_name
            and len(part.comparators) == 1
            and _name(part.comparators[0], "apps")
            for part in item.test.values
        )
        and any(append is child for child in ast.walk(item))
    ]
    if len(values) != 1 or len(apps) != 1 or len(filters) != 1:
        return None
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    initializers = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Assign)
        and _assigned_name(item, "candidates")
        and isinstance(item.value, ast.List)
        and not item.value.elts
    ]
    if len(initializers) != 1 or initializers[0].lineno >= loop.lineno:
        return None
    for item in ast.walk(tree):
        if not isinstance(item, ast.Name) or item.id != "candidates":
            continue
        parent = parents.get(id(item))
        grandparent = parents.get(id(parent)) if parent is not None else None
        if (
            item is initializers[0].targets[0]
            or item is project.test
            or item is project.body.value.value
            or isinstance(parent, ast.Attribute)
            and parent.value is item
            and parent.attr in {"append", "sort"}
            and isinstance(grandparent, ast.Call)
            and grandparent.func is parent
            and (grandparent is append or parent.attr == "sort")
        ):
            continue
        return None
    for item in ast.walk(loop):
        if not isinstance(item, ast.Name) or item.id != "values":
            continue
        parent = parents.get(id(item))
        grandparent = parents.get(id(parent)) if parent is not None else None
        if (
            item is values[0].targets[0]
            or isinstance(parent, ast.Attribute)
            and parent.value is item
            and parent.attr == "get"
            and isinstance(grandparent, ast.Call)
            and grandparent is apps[0].value
            or isinstance(parent, ast.Tuple)
            and parent is append.args[0]
            and item is parent.elts[1]
        ):
            continue
        return None
    if not root and "settings.py" in tracked_paths:
        # The current source-path binding schema only admits nested settings.
        # Do not silently omit a root-level file reached by rglob.
        return None
    reachable = tuple(
        sorted(
            path
            for path in tracked_paths
            if path.endswith("/settings.py")
            and (not root or path.startswith(root.rstrip("/") + "/"))
        )
    )
    return ("DYNAMIC", reachable, root) if reachable else None


def _option_key(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and len(node.args) == 1
        and isinstance(node.args[0], (ast.List, ast.Tuple))
        and all(
            isinstance(item, ast.Constant) and isinstance(item.value, str)
            for item in node.args[0].elts
        )
    ):
        return node.func.value.value.join(
            str(item.value)
            for item in node.args[0].elts
            if isinstance(item, ast.Constant)
        )
    return None


def _project_update(node: ast.Call, flag: str) -> bool:
    if not _attr(node.func, "options", "update") or len(node.args) != 1:
        return False
    arg = node.args[0]
    if not isinstance(arg, ast.DictComp) or len(arg.generators) != 1:
        return False
    generator = arg.generators[0]
    if not (
        isinstance(generator.target, ast.Tuple)
        and [
            _name(item, name)
            for item, name in zip(generator.target.elts, ("key", "value"), strict=False)
        ]
        == [True, True]
        and isinstance(generator.iter, ast.Call)
        and _attr(generator.iter.func, "project", "items")
        and not generator.iter.args
        and any(
            isinstance(item, ast.Call)
            and _attr(item.func, "key", "startswith")
            and len(item.args) == 1
            and isinstance(item.args[0], ast.Constant)
            and isinstance(item.args[0].value, str)
            and flag.startswith(item.args[0].value)
            for condition in generator.ifs
            for item in ast.walk(condition)
        )
    ):
        return False
    return _name(arg.key, "key") and _name(arg.value, "value")


def _bounded_options_uses(
    tree: ast.Module,
    definition: ast.Assign,
    update: ast.Call,
    configure: ast.Call,
    *,
    override: ast.Assign | None = None,
) -> bool:
    """Allow only the known dict construction, project update and configure."""

    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or node.id != "options":
            continue
        parent = parents.get(id(node))
        grandparent = parents.get(id(parent)) if parent is not None else None
        if (
            node is definition.targets[0]
            or isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent is update.func
            and isinstance(grandparent, ast.Call)
            and grandparent is update
            or isinstance(parent, ast.keyword)
            and parent.value is node
            and parent in configure.keywords
            or override is not None
            and isinstance(parent, ast.Subscript)
            and parent.value is node
            and len(override.targets) == 1
            and parent is override.targets[0]
        ):
            continue
        return False
    return True


def _candidate_omits_flag(tree: ast.Module, flag: str) -> bool:
    located = _candidate_body(tree)
    collector = _literal_collector(tree)
    if (
        located is None
        or collector is None
        or not _project_is_literal_collected(tree, collector)
        or not _path_constructor_is_unshadowed(tree)
    ):
        return False
    body, configure = located
    if (
        configure.args
        or len(configure.keywords) != 1
        or configure.keywords[0].arg is not None
        or not _name(configure.keywords[0].value, "options")
    ):
        return False
    configure_line = configure.lineno
    definitions = [
        node
        for node in body
        if isinstance(node, ast.Assign)
        and _assigned_name(node, "options")
        and node.lineno < configure_line
    ]
    if len(definitions) != 1 or not isinstance(definitions[0].value, ast.Call):
        return False
    definition = definitions[0].value
    if (
        not _name(definition.func, "dict")
        or definition.args
        or any(keyword.arg is None for keyword in definition.keywords)
    ):
        return False
    if "INSTALLED_APPS" not in {keyword.arg for keyword in definition.keywords}:
        return False
    if flag in {keyword.arg for keyword in definition.keywords}:
        return False
    updates = [
        node
        for statement in body
        if statement.lineno < configure_line
        for node in ast.walk(statement)
        if isinstance(node, ast.Call) and _attr(node.func, "options", "update")
    ]
    if len(updates) != 1 or not _project_update(updates[0], flag):
        return False
    if not _bounded_options_uses(tree, definitions[0], updates[0], configure):
        return False
    for statement in body:
        if not definitions[0].lineno < statement.lineno < configure_line:
            continue
        for node in ast.walk(statement):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if _name(target, "options"):
                    return False
                if isinstance(target, ast.Subscript) and _name(target.value, "options"):
                    key = _option_key(target.slice)
                    if key is None or key == flag:
                        return False
    return True


def _project_default_off(tree: ast.Module, flag: str, app_name: str) -> bool:
    assignments = {
        target.id: node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    apps = assignments.get("INSTALLED_APPS")
    try:
        installed = ast.literal_eval(apps) if apps is not None else None
    except (ValueError, TypeError, MemoryError, RecursionError):
        return False
    return (
        isinstance(installed, (tuple, list))
        and app_name in installed
        and flag in assignments
        and _django_project_default_false(assignments[flag], flag)
    )


def _app_relation_alias(tree: ast.Module, flag: str) -> tuple[str, str] | None:
    fallback = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and _assigned_name(node, flag)
        and isinstance(node.value, ast.Call)
        and _name(node.value.func, "getattr")
        and len(node.value.args) == 3
        and _name(node.value.args[0], "settings")
        and isinstance(node.value.args[1], ast.Constant)
        and node.value.args[1].value == flag
        and isinstance(node.value.args[2], ast.Constant)
        and node.value.args[2].value is True
    ]
    if len(fallback) != 1:
        return None
    matches: list[tuple[str, str]] = []
    for condition in tree.body:
        if not isinstance(condition, ast.If) or not _name(condition.test, flag):
            continue
        for node in condition.body:
            if not (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and _name(node.value.func, "getattr")
                and len(node.value.args) == 3
                and _name(node.value.args[0], "settings")
                and isinstance(node.value.args[1], ast.Constant)
                and node.value.args[1].value == node.targets[0].id
                and isinstance(node.value.args[2], ast.Constant)
                and isinstance(node.value.args[2].value, str)
            ):
                continue
            alias = node.targets[0].id
            related = node.value.args[2].value
            if re.fullmatch(r"[A-Za-z_]\w*\.[A-Za-z_]\w*", related) is None:
                continue
            if any(
                isinstance(other, ast.Assign)
                and _assigned_name(other, alias)
                and _attr(other.value, "settings", "AUTH_USER_MODEL")
                for other in condition.orelse
            ):
                matches.append((alias, related.split(".", 1)[0]))
    return matches[0] if len(matches) == 1 else None


def _model_uses_alias(tree: ast.Module, app_name: str, alias: str) -> bool:
    imports = {
        imported.asname or imported.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == app_name
        for imported in node.names
        if imported.name == "settings"
    }
    if len(imports) != 1:
        return False
    settings_name = next(iter(imports))
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _name(node.func.value, "models")
        and node.func.attr in {"ForeignKey", "OneToOneField"}
        and bool(node.args)
        and _attr(node.args[0], settings_name, alias)
        for node in ast.walk(tree)
    )


def django_relation_setting_mismatch(
    stderr: bytes,
    stdout: bytes,
    candidate: bytes,
    project_settings: bytes,
    app_settings: bytes,
    models: bytes,
    *,
    app_name: str,
) -> str | None:
    """Return the unique omitted flag only with a pinned source/fixture chain."""

    if (
        len(stderr) > 1024
        or len(stdout) > 4096
        or any(
            len(source) > 128 * 1024
            for source in (project_settings, app_settings, models)
        )
        or re.fullmatch(
            rb"ValueError\r?\nTraceback: [A-Za-z_][A-Za-z_0-9]*"
            rb"(?: > [A-Za-z_][A-Za-z_0-9]*){2,12}\r?\n?",
            stderr,
        )
        is None
        or b"foreign_related_fields" not in stderr
        or b"resolve_related_fields" not in stderr
        or re.search(
            rb"(?i)(?:MIGRATED|REPRODUCED|CONFIRMED|DIRECT_HELPER_COPY)", stdout
        )
        or b"SASTSIMI_POC_INCONCLUSIVE" in stdout
        or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", app_name) is None
    ):
        return None
    candidate_tree = _python_tree(candidate)
    if candidate_tree is None or not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _name(node.func.value, "django")
        and node.func.attr == "setup"
        for node in ast.walk(candidate_tree)
    ):
        return None
    if not any(
        isinstance(node, ast.ImportFrom) and node.module == app_name + ".models"
        for node in ast.walk(candidate_tree)
    ):
        return None
    try:
        project_tree = ast.parse(project_settings.decode("utf-8"))
        app_tree = ast.parse(app_settings.decode("utf-8"))
        models_tree = ast.parse(models.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None
    flags = [
        target.id
        for node in app_tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
        and re.fullmatch(r"[A-Z][A-Z_0-9]*", target.id)
        and _project_default_off(project_tree, target.id, app_name)
        and _candidate_omits_flag(candidate_tree, target.id)
        and (relation := _app_relation_alias(app_tree, target.id)) is not None
        and _model_uses_alias(models_tree, app_name, relation[0])
    ]
    return flags[0] if len(flags) == 1 else None


def django_relation_settings_replay_forbidden(content: bytes, flag: str) -> bool:
    """Require an explicit, final false override before settings.configure."""

    tree = _python_tree(content)
    located = _candidate_body(tree) if tree is not None else None
    if located is None or re.fullmatch(r"[A-Z][A-Z_0-9]*", flag) is None:
        return True
    assert tree is not None
    body, configure = located
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "django.conf"
            and any(
                imported.name == "settings"
                and imported.asname not in {None, "settings"}
                for imported in node.names
            )
        ):
            return True
        if isinstance(node, ast.Attribute) and node.attr == "settings":
            return True
        if isinstance(node, ast.Name) and node.id == "settings":
            parent = parents.get(id(node))
            grandparent = parents.get(id(parent)) if parent is not None else None
            if not (
                isinstance(node.ctx, ast.Load)
                and isinstance(parent, ast.Attribute)
                and parent.value is node
                and isinstance(parent.ctx, ast.Load)
                and parent.attr not in {"__dict__", "_wrapped"}
                and (
                    parent.attr != "configure"
                    or isinstance(grandparent, ast.Call)
                    and grandparent.func is parent
                )
            ):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {
                "setattr",
                "delattr",
                "globals",
                "locals",
                "vars",
                "eval",
                "exec",
                "__import__",
            }:
                return True
            if (
                node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "settings"
            ):
                return True
    if (
        configure.args
        or len(configure.keywords) != 1
        or configure.keywords[0].arg is not None
        or not _name(configure.keywords[0].value, "options")
    ):
        return True
    writes = [
        node
        for statement in body
        if statement.lineno < configure.lineno
        for node in ast.walk(statement)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Subscript)
        and _name(node.targets[0].value, "options")
        and _option_key(node.targets[0].slice) == flag
    ]
    configure_index = next(
        (
            index
            for index, statement in enumerate(body)
            if isinstance(statement, ast.Expr) and statement.value is configure
        ),
        0,
    )
    definitions = [
        node
        for node in body
        if isinstance(node, ast.Assign)
        and _assigned_name(node, "options")
        and node.lineno < configure.lineno
    ]
    updates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _attr(node.func, "options", "update")
        and node.lineno < configure.lineno
    ]
    return not (
        len(writes) == 1
        and len(definitions) == 1
        and len(updates) == 1
        and _bounded_options_uses(
            tree,
            definitions[0],
            updates[0],
            configure,
            override=writes[0],
        )
        and configure_index > 0
        and body[configure_index - 1] is writes[0]
        and isinstance(writes[0].value, ast.Constant)
        and writes[0].value.value is False
        and not any(
            isinstance(node, ast.Call)
            and _attr(node.func, "options", "update")
            and node.lineno > writes[0].lineno
            and node.lineno < configure.lineno
            for node in ast.walk(tree)
        )
    )
