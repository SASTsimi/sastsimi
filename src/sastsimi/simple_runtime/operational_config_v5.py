"""Fail-closed, commit-pinned operational XML route/class bindings.

Only the tags read by the pinned parser are inspected. The resulting value is
an operational mapping with provenance, never a claim that a request reaches a
sink or that an educational XML answer key is evidence.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import posixpath
import re
import shlex
import stat
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .facts import safe_tracked_file
from .retrieval import _read_pinned_blob

_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_ROUTE = re.compile(r"/[A-Za-z0-9_./{}-]{0,255}\Z")
_XML_DECLARATION = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_MAX_PYTHON_BYTES = 256 * 1024
_MAX_LAUNCHER_BYTES = 32 * 1024
_MAX_XML_NODES = 4096
_MAX_XML_RECORDS = 256
_MAX_DISCOVERY_FILES = 256
_MAX_DISCOVERY_BYTES = 4 * 1024 * 1024
_MAX_DISCOVERY_LAUNCHERS = 16
_MAX_DISCOVERY_PAIRS = 64
_MAX_TREE_OUTPUT_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class OperationalRouteBinding:
    route: str
    module_path: str
    class_symbol: str
    config_path: str
    config_sha256: str
    parser_path: str
    parser_sha256: str
    parser_sites: tuple[int, ...]
    target_path: str
    target_sha256: str
    launcher_path: str
    launcher_sha256: str

    def to_json(self) -> dict[str, object]:
        """Project only the contract's operational fields into saved context."""

        return {
            "route": self.route,
            "module_path": self.module_path,
            "class_symbol": self.class_symbol,
            "config_path": self.config_path,
            "config_sha256": self.config_sha256,
            "parser_path": self.parser_path,
            "parser_sha256": self.parser_sha256,
            "parser_sites": list(self.parser_sites),
            "target_path": self.target_path,
            "target_sha256": self.target_sha256,
            "launcher_path": self.launcher_path,
            "launcher_sha256": self.launcher_sha256,
        }


@dataclass(frozen=True, slots=True)
class OperationalRouteMap:
    bindings: tuple[OperationalRouteBinding, ...]
    gaps: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "bindings": [binding.to_json() for binding in self.bindings],
            "gaps": list(self.gaps),
        }


class _Gap(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _safe_repo_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return (
        bool(path)
        and len(path) <= 240
        and not pure.is_absolute()
        and path == pure.as_posix()
        and not any(part in {".", ".."} for part in pure.parts)
        and "\\" not in path
        and ":" not in path
        and "\x00" not in path
        and all(ord(char) >= 32 for char in path)
    )


def _verify_commit(workspace: Path, commit_id: str) -> None:
    if not _COMMIT.fullmatch(commit_id):
        raise _Gap("PINNED_COMMIT_INVALID")
    try:
        result = subprocess.run(
            ("git", "-C", str(workspace), "cat-file", "-t", commit_id),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _Gap("PINNED_COMMIT_INVALID") from error
    if result.returncode != 0 or result.stdout.strip() != b"commit":
        raise _Gap("PINNED_COMMIT_INVALID")


def _verified_blob(
    workspace: Path,
    commit_id: str,
    path: str,
    limit: int,
    *,
    oversize_gap: str = "SOURCE_TOO_LARGE",
) -> tuple[bytes, str]:
    if not _COMMIT.fullmatch(commit_id) or not _safe_repo_path(path):
        raise _Gap("PINNED_BLOB_UNAVAILABLE")
    source = safe_tracked_file(workspace, path)
    if source is None:
        raise _Gap("PINNED_BLOB_UNAVAILABLE")
    pinned, reason = _read_pinned_blob(
        workspace, path, commit=commit_id, git_executable="git", remaining=limit
    )
    if reason == "TOTAL_BUDGET_EXHAUSTED":
        raise _Gap(oversize_gap)
    if reason is not None or pinned is None:
        raise _Gap("PINNED_BLOB_UNAVAILABLE")
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or source.is_symlink():
            raise _Gap("PINNED_BLOB_UNAVAILABLE")
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            current = os.fstat(stream.fileno())
            if not stat.S_ISREG(current.st_mode) or (before.st_dev, before.st_ino) != (
                current.st_dev,
                current.st_ino,
            ):
                raise _Gap("PINNED_BLOB_MISMATCH")
            checkout = stream.read(limit + 1)
    except OSError as error:
        raise _Gap("PINNED_BLOB_UNAVAILABLE") from error
    if len(checkout) > limit:
        raise _Gap(oversize_gap)
    if checkout != pinned:
        raise _Gap("PINNED_BLOB_MISMATCH")
    return pinned, hashlib.sha256(pinned).hexdigest()


def _module_file(module: str) -> str:
    if not module or any(not _IDENTIFIER.fullmatch(p) for p in module.split(".")):
        raise _Gap("DYNAMIC_DISPATCH_UNRESOLVED")
    return module.replace(".", "/") + ".py"


def _expression_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _expression_name(node.value)
        return f"{head}.{node.attr}" if head else None
    return None


def _imported_modules(tree: ast.Module) -> dict[str, str]:
    imports: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.asname:
                    imports[alias.asname] = alias.name
                else:
                    imports[alias.name] = alias.name
        elif isinstance(statement, ast.ImportFrom) and statement.module:
            # `from package import member` can bind a package attribute instead
            # of a module; it cannot establish a unique dynamic getattr target.
            if statement.module == "xml.etree":
                for alias in statement.names:
                    if alias.name == "ElementTree":
                        imports[alias.asname or alias.name] = "xml.etree.ElementTree"
    return imports


def _parse_aliases(tree: ast.Module) -> tuple[set[str], set[str]]:
    module_aliases = {
        alias
        for alias, module in _imported_modules(tree).items()
        if module == "xml.etree.ElementTree"
    }
    function_aliases: set[str] = set()
    for statement in tree.body:
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.module == "xml.etree.ElementTree"
        ):
            function_aliases.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name == "parse"
            )
    return module_aliases, function_aliases


def _scope_for(
    tree: ast.Module, node: ast.AST
) -> ast.Module | ast.FunctionDef | ast.ClassDef:
    functions = [
        function
        for function in ast.walk(tree)
        if isinstance(function, ast.FunctionDef)
        and function.lineno
        <= getattr(node, "lineno", 0)
        <= (function.end_lineno or function.lineno)
    ]
    async_functions = [
        function
        for function in ast.walk(tree)
        if isinstance(function, ast.AsyncFunctionDef)
        and function.lineno
        <= getattr(node, "lineno", 0)
        <= (function.end_lineno or function.lineno)
    ]
    classes = [
        cls
        for cls in ast.walk(tree)
        if isinstance(cls, ast.ClassDef)
        and cls.lineno <= getattr(node, "lineno", 0) <= (cls.end_lineno or cls.lineno)
    ]
    if (
        len(classes) > 1
        or len(functions) > 1
        or async_functions
        or (classes and functions)
    ):
        raise _Gap("PARSER_XML_UNRESOLVED")
    return functions[0] if functions else classes[0] if classes else tree


def _assigns_name(statements: list[ast.stmt], name: str) -> bool:
    return any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id == name
        for statement in statements
        for node in ast.walk(statement)
    )


def _import_bound_names(node: ast.Import | ast.ImportFrom) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(alias.asname or alias.name.split(".")[0] for alias in node.names)
    return tuple(alias.asname or alias.name for alias in node.names)


def _local_import_binds_name(
    scope: ast.Module | ast.FunctionDef | ast.ClassDef, name: str
) -> bool:
    for statement in scope.body:
        if isinstance(scope, ast.Module) and isinstance(
            statement, (ast.Import, ast.ImportFrom)
        ):
            continue
        for node in ast.walk(statement):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and name in (
                _import_bound_names(node)
            ):
                return True
    return False


def _shadowed(
    tree: ast.Module, scope: ast.Module | ast.FunctionDef | ast.ClassDef, name: str
) -> bool:
    # An import only establishes identity until an assignment or parameter
    # shadows that name. Conservatively reject even a branch-local mutation.
    direct_imports = [
        (statement, alias)
        for statement in tree.body
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for alias in statement.names
        if (
            alias.asname
            or (
                alias.name.split(".")[0]
                if isinstance(statement, ast.Import)
                else alias.name
            )
        )
        == name
    ]
    # `import package` followed by `import package.module` binds the same
    # package root twice. It does not replace that root with another object.
    repeated_same_root = all(
        isinstance(statement, ast.Import)
        and alias.name.split(".")[0] == name
        and alias.asname in (None, name)
        for statement, alias in direct_imports
    )
    if (
        (len(direct_imports) > 1 and not repeated_same_root)
        or _assigns_name(tree.body, name)
        or _local_import_binds_name(tree, name)
    ):
        return True
    return isinstance(scope, ast.FunctionDef) and (
        name
        in {
            argument.arg
            for argument in [
                *scope.args.posonlyargs,
                *scope.args.args,
                *scope.args.kwonlyargs,
            ]
        }
        or _assigns_name(scope.body, name)
        or _local_import_binds_name(scope, name)
    )


def _assignments(statements: list[ast.stmt]) -> dict[str, ast.AST]:
    assigned: dict[str, ast.AST] = {}
    for statement in statements:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and isinstance(
            statement.value, ast.AST
        ):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    if target.id in assigned:
                        raise _Gap("DYNAMIC_DISPATCH_UNRESOLVED")
                    assigned[target.id] = statement.value
    return assigned


def _resolve(node: ast.AST, assignments: dict[str, ast.AST]) -> ast.AST:
    seen: set[str] = set()
    while isinstance(node, ast.Name) and node.id in assignments:
        if node.id in seen:
            raise _Gap("DYNAMIC_DISPATCH_UNRESOLVED")
        seen.add(node.id)
        node = assignments[node.id]
    return node


def _findtext(
    node: ast.AST, record_name: str, assignments: dict[str, ast.AST]
) -> tuple[str, int] | None:
    node = _resolve(node, assignments)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "findtext"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == record_name
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        tag = node.args[0].value
        if _IDENTIFIER.fullmatch(tag):
            return tag, node.lineno
    return None


def _getattr_binding(
    node: ast.AST,
    record_name: str,
    assignments: dict[str, ast.AST],
    imports: dict[str, str],
) -> tuple[str, str, int, int] | None:
    node = _resolve(node, assignments)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Call):
        node = node.func  # Accept a class constructed immediately after lookup.
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) == 2
    ):
        return None
    source_name = _expression_name(node.args[0])
    module = imports.get(source_name or "")
    symbol = _findtext(node.args[1], record_name, assignments)
    if module is None or symbol is None or module == "xml.etree.ElementTree":
        return None
    return module, symbol[0], symbol[1], node.lineno


def _contains_parse(
    node: ast.AST, parse_call: ast.Call, assignments: dict[str, ast.AST]
) -> bool:
    node = _resolve(node, assignments)
    if node is parse_call:
        return True
    return any(
        _contains_parse(child, parse_call, assignments)
        for child in ast.iter_child_nodes(node)
    )


def _loop_for_parse(
    scope: ast.Module | ast.FunctionDef | ast.ClassDef, parse_call: ast.Call
) -> tuple[ast.For, str, dict[str, ast.AST]]:
    assignments = _assignments(scope.body)
    candidates: list[tuple[ast.For, str]] = []
    for statement in scope.body:
        if not isinstance(statement, ast.For) or not isinstance(
            statement.target, ast.Name
        ):
            continue
        iterable = _resolve(statement.iter, assignments)
        if not (
            isinstance(iterable, ast.Call)
            and isinstance(iterable.func, ast.Attribute)
            and iterable.func.attr == "findall"
            and len(iterable.args) == 1
            and isinstance(iterable.args[0], ast.Constant)
            and isinstance(iterable.args[0].value, str)
            and _contains_parse(iterable.func.value, parse_call, assignments)
        ):
            continue
        selector = iterable.args[0].value
        if selector.startswith("./"):
            selector = selector[2:]
        if not _IDENTIFIER.fullmatch(selector):
            raise _Gap("PARSER_XML_UNRESOLVED")
        candidates.append((statement, selector))
    if len(candidates) != 1:
        raise _Gap("PARSER_XML_UNRESOLVED")
    loop, selector = candidates[0]
    return loop, selector, assignments


def _used_collection(
    scope: ast.Module | ast.FunctionDef, loop: ast.For, name: str
) -> int | None:
    for statement in scope.body:
        if statement.lineno <= loop.lineno:
            continue
        if (
            isinstance(statement, ast.Return)
            and isinstance(statement.value, ast.Name)
            and statement.value.id == name
        ) or (
            isinstance(statement, ast.For)
            and isinstance(statement.iter, ast.Name)
            and statement.iter.id == name
        ):
            return statement.lineno
    return None


def _class_route_use(
    scope: ast.ClassDef, collection: str, attribute: str
) -> int | None:
    """Find a method that compares the constructed route and calls its item."""

    for method in scope.body:
        if not isinstance(method, ast.FunctionDef) or not method.args.args:
            continue
        receiver = method.args.args[0].arg
        if _assigns_name(method.body, receiver):
            continue
        for iterator in ast.walk(method):
            if not (
                isinstance(iterator, ast.For)
                and isinstance(iterator.target, ast.Name)
                and isinstance(iterator.iter, ast.Attribute)
                and isinstance(iterator.iter.value, ast.Name)
                and iterator.iter.value.id == receiver
                and iterator.iter.attr == collection
            ):
                continue
            item = iterator.target.id
            if _assigns_name(iterator.body, item):
                continue
            for branch in iterator.body:
                if not isinstance(branch, ast.If) or not isinstance(
                    branch.test, ast.Compare
                ):
                    continue
                test_nodes = list(ast.walk(branch.test))
                compares_route = any(
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == item
                    and node.attr == attribute
                    for node in test_nodes
                )
                calls_item = any(
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == item
                    for statement in branch.body
                    for node in ast.walk(statement)
                )
                if compares_route and calls_item:
                    return branch.lineno
    return None


def _dispatch_shape(
    tree: ast.Module, parse_call: ast.Call
) -> tuple[str, str, str, str, tuple[int, ...], str | None]:
    scope = _scope_for(tree, parse_call)
    loop, selector, scope_assignments = _loop_for_parse(scope, parse_call)
    assert isinstance(loop.target, ast.Name)
    record_name = loop.target.id
    if _assigns_name(loop.body, record_name):
        raise _Gap("DYNAMIC_DISPATCH_UNRESOLVED")
    local = _assignments(loop.body)
    imports = _imported_modules(tree)
    candidates: list[tuple[str, str, str, tuple[int, ...]]] = []
    for statement in loop.body:
        if not (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Attribute)
            and statement.value.func.attr == "append"
            and isinstance(statement.value.func.value, ast.Name)
            and len(statement.value.args) == 1
        ):
            continue
        collection = statement.value.func.value.id
        initial = scope_assignments.get(collection)
        if (
            not isinstance(initial, ast.List)
            or initial.elts
            or _assigns_name(loop.body, collection)
        ):
            continue
        item = statement.value.args[0]
        possible: list[tuple[ast.AST, tuple[str, int] | None, int | None]] = []
        if isinstance(item, (ast.Tuple, ast.List)) and len(item.elts) == 2:
            if not isinstance(scope, ast.ClassDef):
                use_line = _used_collection(scope, loop, collection)
                for handler, route in (
                    (item.elts[0], item.elts[1]),
                    (item.elts[1], item.elts[0]),
                ):
                    possible.append(
                        (handler, _findtext(route, record_name, local), use_line)
                    )
        elif isinstance(scope, ast.ClassDef):
            instance = _resolve(item, local)
            if isinstance(instance, ast.Call) and isinstance(instance.func, ast.Call):
                for keyword in instance.keywords:
                    if keyword.arg is None:
                        continue
                    possible.append(
                        (
                            instance,
                            _findtext(keyword.value, record_name, local),
                            _class_route_use(scope, collection, keyword.arg),
                        )
                    )
        for handler_node, route_tag, use_line in possible:
            target = _getattr_binding(handler_node, record_name, local, imports)
            if target is None or route_tag is None or use_line is None:
                continue
            module, class_tag, class_line, lookup_line = target
            if class_tag == route_tag[0]:
                continue
            sites = tuple(
                sorted(
                    {
                        parse_call.lineno,
                        loop.lineno,
                        route_tag[1],
                        class_line,
                        lookup_line,
                        statement.lineno,
                        use_line,
                    }
                )
            )
            candidates.append((module, class_tag, route_tag[0], sites))
    if len(candidates) != 1:
        raise _Gap("DYNAMIC_DISPATCH_UNRESOLVED")
    module, class_tag, route_field, sites = candidates[0]
    if any(
        _shadowed(tree, scope, alias.split(".")[0])
        for alias, imported in imports.items()
        if imported == module
    ):
        raise _Gap("DYNAMIC_DISPATCH_UNRESOLVED")
    function_name = scope.name if isinstance(scope, ast.FunctionDef) else None
    return module, selector, class_tag, route_field, sites, function_name


def _parser_shape(
    raw: bytes, path: str
) -> tuple[ast.Module, str, str, str, str, str, tuple[int, ...], str | None]:
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=path)
    except (SyntaxError, UnicodeError) as error:
        raise _Gap("PARSER_XML_UNRESOLVED") from error
    modules, functions = _parse_aliases(tree)
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _expression_name(node.func)
        if name in functions or any(name == f"{module}.parse" for module in modules):
            calls.append(node)
    if not calls or len(calls) > 4:
        raise _Gap("PARSER_XML_UNRESOLVED")
    candidates: list[tuple[str, str, str, str, str, tuple[int, ...], str | None]] = []
    reasons: list[str] = []
    for parse_call in calls:
        try:
            config_path = _config_literal(tree, parse_call)
            shape = _dispatch_shape(tree, parse_call)
            candidates.append((config_path, *shape))
        except _Gap as gap:
            reasons.append(gap.code)
    if len(candidates) != 1:
        raise _Gap(
            reasons[0] if len(calls) == 1 and reasons else "PARSER_XML_UNRESOLVED"
        )
    config_path, module, selector, class_tag, route_tag, sites, function_name = (
        candidates[0]
    )
    if any(_config_literal(tree, call) != config_path for call in calls):
        raise _Gap("PARSER_XML_UNRESOLVED")
    return (
        tree,
        module,
        config_path,
        selector,
        class_tag,
        route_tag,
        sites,
        function_name,
    )


def _possible_cwd_change(tree: ast.Module) -> bool:
    os_aliases = {"os"}
    cwd_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            os_aliases.update(
                alias.asname or "os" for alias in node.names if alias.name == "os"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            if any(alias.name == "*" for alias in node.names):
                return True
            cwd_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name in {"chdir", "fchdir"}
            )
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in {"chdir", "fchdir"}:
            return True
        if isinstance(node, ast.Name) and node.id in cwd_names:
            return True
        if not isinstance(node, ast.Call):
            continue
        name = _expression_name(node.func)
        if name in {"exec", "eval", "__import__"}:
            return True
        if (
            name == "getattr"
            and node.args
            and _expression_name(node.args[0]) in os_aliases
        ):
            return True
    return False


def _config_literal(tree: ast.Module, parse_call: ast.Call) -> str:
    if len(parse_call.args) != 1:
        raise _Gap("PARSER_XML_UNRESOLVED")
    scope = _scope_for(tree, parse_call)
    parse_name = _expression_name(parse_call.func)
    assert parse_name is not None
    if _shadowed(tree, scope, parse_name.split(".")[0]) or _shadowed(
        tree, scope, "getattr"
    ):
        raise _Gap("PARSER_XML_UNRESOLVED")
    literal = parse_call.args[0]
    if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
        raise _Gap("PARSER_XML_UNRESOLVED")
    xml_literal = literal.value
    if (
        not xml_literal
        or len(xml_literal) > 240
        or xml_literal.startswith(("/", "\\"))
        or "\\" in xml_literal
        or ":" in xml_literal
        or any(part == ".." for part in PurePosixPath(xml_literal).parts)
    ):
        raise _Gap("CONFIG_PATH_UNRESOLVED")
    config_path = posixpath.normpath(xml_literal)
    if not config_path.endswith(".xml") or not _safe_repo_path(config_path):
        raise _Gap("CONFIG_PATH_UNRESOLVED")
    if _possible_cwd_change(tree):
        raise _Gap("PARSER_CWD_UNPROVEN")
    return config_path


def _docker_command(value: str) -> list[str]:
    try:
        if not value.startswith("["):
            raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN")
        parsed: Any = json.loads(value)
        if not isinstance(parsed, list) or not all(
            isinstance(part, str) for part in parsed
        ):
            raise ValueError
        return parsed
    except (ValueError, json.JSONDecodeError) as error:
        raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN") from error


def _final_stage_directives(raw: bytes, *, decode_gap: str) -> dict[str, list[str]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise _Gap(decode_gap) from error
    directives: dict[str, list[str]] = {}
    stage_count = 0
    final_base = ""
    for line in lines:
        content = line.strip()
        if not content or content.startswith("#"):
            continue
        parts = content.split(None, 1)
        keyword = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""
        if keyword == "FROM":
            stage_count += 1
            final_base = rest.strip().split()[0] if rest.strip() else ""
            directives = {}
        elif stage_count:
            directives.setdefault(keyword, []).append(rest.strip())
    if not stage_count or not final_base:
        raise _Gap("LAUNCHER_FINAL_STAGE_UNPROVEN")
    if stage_count > 1 and not (
        final_base == "python"
        or final_base.startswith("python:")
        or final_base.startswith("python@")
    ):
        raise _Gap("LAUNCHER_FINAL_STAGE_UNPROVEN")
    return directives


def _launched_path(
    raw: bytes, runtime_workdir: str | None, workspace: Path, commit_id: str
) -> str:
    if (
        runtime_workdir is None
        or not runtime_workdir.startswith("/")
        or "$" in runtime_workdir
        or ".." in PurePosixPath(runtime_workdir).parts
    ):
        raise _Gap("RUNTIME_WORKDIR_UNPROVEN")
    directives = _final_stage_directives(raw, decode_gap="LAUNCHER_ENTRYPOINT_UNPROVEN")
    # A final-stage command or a second source layer can replace a pinned XML
    # or Python file. We do not model arbitrary image transformations.
    if (
        directives.get("ADD")
        or len(directives.get("COPY", [])) > 1
        or directives.get("RUN")
        and not _safe_precopy_runs(raw)
    ):
        raise _Gap("LAUNCHER_RUNTIME_CONTENT_UNPROVEN")
    workdirs = directives.get("WORKDIR", [])
    if (
        len(workdirs) != 1
        or not workdirs[0].startswith("/")
        or "$" in workdirs[0]
        or posixpath.normpath(workdirs[0]) != posixpath.normpath(runtime_workdir)
    ):
        raise _Gap("RUNTIME_WORKDIR_UNPROVEN")
    copy_lines = directives.get("COPY", []) + directives.get("ADD", [])
    try:
        workspace_copied = any(
            len(parts := shlex.split(line)) == 2
            and parts[0] == "."
            and parts[1] in {".", posixpath.normpath(runtime_workdir)}
            for line in copy_lines
        )
    except ValueError as error:
        raise _Gap("LAUNCHER_WORKSPACE_UNPROVEN") from error
    if not workspace_copied:
        raise _Gap("LAUNCHER_WORKSPACE_UNPROVEN")
    if len(directives.get("ENTRYPOINT", [])) > 1 or len(directives.get("CMD", [])) > 1:
        raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN")
    command: list[str] = []
    if directives.get("ENTRYPOINT"):
        command.extend(_docker_command(directives["ENTRYPOINT"][0]))
    if directives.get("CMD"):
        command.extend(_docker_command(directives["CMD"][0]))
    if not command or not re.fullmatch(
        r"python(?:\d+(?:\.\d+)?)?", posixpath.basename(command[0])
    ):
        raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN")
    args = command[1:]
    while args and args[0] in {"-u", "-B", "-I"}:
        if args[0] == "-I":
            # Isolated Python does not put the copied cwd/script directory on
            # sys.path, so imported code may not be the pinned repository.
            raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN")
        args = args[1:]
    if len(args) >= 2 and args[0] == "-m":
        module_path = _module_file(args[1])
        package_path = module_path.removesuffix(".py")
        if _pinned_or_checkout_paths_present(
            workspace,
            commit_id,
            (f"{package_path}/__init__.py", f"{package_path}/__main__.py"),
            "LAUNCHER_MODULE_COLLISION_UNPROVEN",
        ):
            raise _Gap("LAUNCHER_MODULE_COLLISION_UNPROVEN")
        return module_path
    if args and ".." not in PurePosixPath(args[0]).parts:
        script = posixpath.normpath(args[0])
        if _safe_repo_path(script) and script.endswith(".py"):
            return script
    raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN")


def _pinned_or_checkout_paths_present(
    workspace: Path, commit_id: str, paths: tuple[str, ...], gap_code: str
) -> bool:
    if any(os.path.lexists(workspace / path) for path in paths):
        return True
    try:
        result = subprocess.run(
            (
                "git",
                "-C",
                str(workspace),
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                commit_id,
                "--",
                *paths,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _Gap(gap_code) from error
    if result.returncode != 0:
        raise _Gap(gap_code)
    return bool(result.stdout)


def _context_ignore_present(
    workspace: Path, commit_id: str, launcher_path: str
) -> bool:
    for path in (".dockerignore", f"{launcher_path}.dockerignore"):
        if not _pinned_or_checkout_paths_present(
            workspace, commit_id, (path,), "LAUNCHER_BUILD_CONTEXT_UNPROVEN"
        ):
            continue
        try:
            raw, _ = _verified_blob(workspace, commit_id, path, 8192)
            rules = raw.decode("utf-8").splitlines()
        except (_Gap, UnicodeError):
            return True
        if any(
            line.strip()
            and not line.lstrip().startswith("#")
            and line.strip() not in {".git", ".git/"}
            for line in rules
        ):
            return True
    return False


def _safe_precopy_runs(raw: bytes) -> bool:
    """Accept only bounded read-only/package setup before the source copy."""

    try:
        physical = raw.decode("utf-8").splitlines()
    except UnicodeError:
        return False
    logical: list[str] = []
    pending = ""
    for line in physical:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pending += (" " if pending else "") + stripped.rstrip("\\").rstrip()
        if stripped.endswith("\\"):
            continue
        logical.append(pending)
        pending = ""
    if pending:
        return False
    final_from = max(
        (
            index
            for index, line in enumerate(logical)
            if line.split(None, 1)[0].upper() == "FROM"
        ),
        default=-1,
    )
    if final_from < 0:
        return False
    directives = [
        (parts[0].upper(), parts[1] if len(parts) > 1 else "")
        for line in logical[final_from + 1 :]
        if (parts := line.split(None, 1))
    ]
    copies = [
        index for index, (keyword, _) in enumerate(directives) if keyword == "COPY"
    ]
    if len(copies) != 1:
        return False
    for index, (keyword, command) in enumerate(directives):
        if keyword != "RUN":
            continue
        safe_setup = (
            command in {"python -V", "python --version"}
            or re.fullmatch(
                r"apt-get update\s*&&\s*apt-get install -y\s+"
                r"[A-Za-z0-9+.\- ]+\s*&&\s*rm -rf /var/lib/apt/lists/\*",
                command,
            )
            is not None
        )
        if index >= copies[0] or not safe_setup:
            return False
    return True


def _xml_import_shadow_present(
    workspace: Path, commit_id: str, parser_path: str, launched_path: str
) -> bool:
    # `-m` adds the working directory to sys.path; direct scripts can also
    # add their own directory. A local xml module/package defeats the assumed
    # stdlib ElementTree parser, even if its source is not in the AST manifest.
    directories = {
        PurePosixPath("."),
        PurePosixPath(parser_path).parent,
        PurePosixPath(launched_path).parent,
    }
    prefixes = {
        "" if directory == PurePosixPath(".") else f"{directory.as_posix()}/"
        for directory in directories
    }
    paths = tuple(
        sorted(
            f"{prefix}{name}"
            for prefix in prefixes
            for name in ("xml", "xml.py", "xml.pyc", "xml.so")
        )
    )
    return _pinned_or_checkout_paths_present(
        workspace, commit_id, paths, "PARSER_XML_IMPORT_UNPROVEN"
    )


def _direct_function_call(tree: ast.Module, name: str) -> bool:
    def calls(statements: list[ast.stmt]) -> bool:
        return any(
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and _expression_name(statement.value.func) == name
            for statement in statements
        )

    if calls(tree.body):
        return True
    for statement in tree.body:
        if (
            isinstance(statement, ast.If)
            and isinstance(statement.test, ast.Compare)
            and isinstance(statement.test.left, ast.Name)
            and statement.test.left.id == "__name__"
            and len(statement.test.ops) == 1
            and isinstance(statement.test.ops[0], ast.Eq)
            and len(statement.test.comparators) == 1
            and isinstance(statement.test.comparators[0], ast.Constant)
            and statement.test.comparators[0].value == "__main__"
            and calls(statement.body)
        ):
            return True
    return False


def _launcher_links_parser(
    workspace: Path,
    commit_id: str,
    launcher_raw: bytes,
    runtime_workdir: str | None,
    parser_path: str,
    parser_tree: ast.Module,
    parser_function: str | None,
) -> None:
    launched = _launched_path(launcher_raw, runtime_workdir, workspace, commit_id)
    if launched == parser_path:
        if parser_function is None or (
            not _assigns_name(parser_tree.body, parser_function)
            and _direct_function_call(parser_tree, parser_function)
        ):
            return
        raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN")
    try:
        entry_raw, _ = _verified_blob(workspace, commit_id, launched, _MAX_PYTHON_BYTES)
        entry_tree = ast.parse(entry_raw.decode("utf-8"), filename=launched)
    except (_Gap, SyntaxError, UnicodeError) as error:
        raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN") from error
    parser_module = parser_path.removesuffix(".py").replace("/", ".")
    if parser_function is None:
        symbols = {
            statement.name
            for statement in parser_tree.body
            if isinstance(statement, (ast.ClassDef, ast.FunctionDef))
        }
        if any(
            isinstance(statement, ast.Import)
            and any(
                alias.name == parser_module
                and not _assigns_name(
                    entry_tree.body, (alias.asname or alias.name).split(".")[0]
                )
                for alias in statement.names
            )
            or isinstance(statement, ast.ImportFrom)
            and statement.module == parser_module
            and any(alias.name in symbols for alias in statement.names)
            for statement in entry_tree.body
        ):
            return
    else:
        for statement in entry_tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    name = alias.asname or alias.name
                    if (
                        alias.name == parser_module
                        and not _assigns_name(entry_tree.body, name.split(".")[0])
                        and _direct_function_call(
                            entry_tree,
                            f"{name}.{parser_function}",
                        )
                    ):
                        return
            if not (
                isinstance(statement, ast.ImportFrom)
                and statement.module == parser_module
            ):
                continue
            for alias in statement.names:
                name = alias.asname or alias.name
                if (
                    alias.name == parser_function
                    and not _assigns_name(entry_tree.body, name)
                    and _direct_function_call(entry_tree, name)
                ):
                    return
    raise _Gap("LAUNCHER_ENTRYPOINT_UNPROVEN")


def _xml_records(
    raw: bytes, selector: str, class_tag: str, route_tag: str
) -> tuple[tuple[str, str], ...]:
    if _XML_DECLARATION.search(raw):
        raise _Gap("XML_DTD_OR_ENTITY")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise _Gap("XML_INVALID") from error
    if sum(1 for _ in root.iter()) > _MAX_XML_NODES:
        raise _Gap("XML_TOO_LARGE")
    records = root.findall(selector)
    if not records or len(records) > _MAX_XML_RECORDS:
        raise _Gap("XML_RECORDS_UNRESOLVED")
    pairs: list[tuple[str, str]] = []
    classes: set[str] = set()
    routes: set[str] = set()
    for record in records:
        class_elements = [child for child in record if child.tag == class_tag]
        route_elements = [child for child in record if child.tag == route_tag]
        if len(class_elements) != 1 or len(route_elements) != 1:
            raise _Gap("XML_RECORDS_UNRESOLVED")
        class_element, route_element = class_elements[0], route_elements[0]
        if len(class_element) or len(route_element):
            raise _Gap("XML_RECORDS_UNRESOLVED")
        symbol, route = class_element.text, route_element.text
        if (
            symbol is None
            or route is None
            or not _CLASS.fullmatch(symbol)
            or not _ROUTE.fullmatch(route)
            or route.startswith("//")
            or ".." in PurePosixPath(route).parts
        ):
            raise _Gap("XML_RECORDS_UNRESOLVED")
        if symbol in classes or route in routes:
            raise _Gap("AMBIGUOUS_ROUTE_BINDING")
        classes.add(symbol)
        routes.add(route)
        pairs.append((route, symbol))
    return tuple(pairs)


def load_operational_routes(
    workspace: Path,
    commit_id: str,
    parser_path: str,
    parser_source: bytes,
    launcher_path: str,
    *,
    runtime_workdir: str | None,
    max_bytes: int = 131072,
) -> OperationalRouteMap:
    """Return conditional source-bound bindings from pinned repository files.

    Any unresolved part returns an empty map and a closed reason code. Neither
    XML answer-key elements nor source snippets enter the result object. This
    does not prove the context or byte contents of a deployed Docker image.
    """

    try:
        if max_bytes <= 0 or max_bytes > 1024 * 1024:
            raise _Gap("XML_TOO_LARGE")
        _verify_commit(workspace, commit_id)
        parser_raw, parser_hash = _verified_blob(
            workspace, commit_id, parser_path, _MAX_PYTHON_BYTES
        )
        if parser_raw != parser_source:
            raise _Gap("PINNED_BLOB_MISMATCH")
        (
            parser_tree,
            module,
            config_path,
            selector,
            class_tag,
            route_tag,
            parser_sites,
            parser_function,
        ) = _parser_shape(parser_raw, parser_path)
        launcher_raw, launcher_hash = _verified_blob(
            workspace, commit_id, launcher_path, _MAX_LAUNCHER_BYTES
        )
        if _context_ignore_present(workspace, commit_id, launcher_path):
            raise _Gap("LAUNCHER_BUILD_CONTEXT_UNPROVEN")
        _launcher_links_parser(
            workspace,
            commit_id,
            launcher_raw,
            runtime_workdir,
            parser_path,
            parser_tree,
            parser_function,
        )
        launched_path = _launched_path(
            launcher_raw, runtime_workdir, workspace, commit_id
        )
        if _xml_import_shadow_present(workspace, commit_id, parser_path, launched_path):
            raise _Gap("PARSER_XML_IMPORT_UNPROVEN")
        config_raw, config_hash = _verified_blob(
            workspace, commit_id, config_path, max_bytes, oversize_gap="XML_TOO_LARGE"
        )
        pairs = _xml_records(config_raw, selector, class_tag, route_tag)
        # The imported module, not a same-named class elsewhere, chooses the
        # target. A second definition in that exact file remains ambiguous.
        target_path = _module_file(module)
        target_raw, target_hash = _verified_blob(
            workspace, commit_id, target_path, _MAX_PYTHON_BYTES
        )
        try:
            target_tree = ast.parse(target_raw.decode("utf-8"), filename=target_path)
        except (SyntaxError, UnicodeError) as error:
            raise _Gap("AMBIGUOUS_TARGET_CLASS") from error
        definitions: dict[str, int] = {}
        for statement in target_tree.body:
            if isinstance(statement, ast.ClassDef):
                definitions[statement.name] = definitions.get(statement.name, 0) + 1
        if any(
            definitions.get(symbol) != 1
            or _assigns_name(target_tree.body, symbol)
            or any(
                isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                and statement.name == symbol
                for statement in target_tree.body
            )
            for _, symbol in pairs
        ):
            raise _Gap("AMBIGUOUS_TARGET_CLASS")
        bindings = tuple(
            OperationalRouteBinding(
                route=route,
                module_path=module,
                class_symbol=symbol,
                config_path=config_path,
                config_sha256=config_hash,
                parser_path=parser_path,
                parser_sha256=parser_hash,
                parser_sites=parser_sites,
                target_path=target_path,
                target_sha256=target_hash,
                launcher_path=launcher_path,
                launcher_sha256=launcher_hash,
            )
            for route, symbol in pairs
        )
        return OperationalRouteMap(bindings=bindings, gaps=())
    except _Gap as gap:
        return OperationalRouteMap(bindings=(), gaps=(gap.code,))


def _pinned_launcher_paths(workspace: Path, commit_id: str) -> tuple[str, ...]:
    try:
        result = subprocess.run(
            (
                "git",
                "-C",
                str(workspace),
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                commit_id,
                "--",
                "Dockerfile",
                "Containerfile",
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _Gap("LAUNCHER_DISCOVERY_UNPROVEN") from error
    if result.returncode != 0 or len(result.stdout) > _MAX_TREE_OUTPUT_BYTES:
        raise _Gap("LAUNCHER_DISCOVERY_UNPROVEN")
    try:
        names = (name.decode("utf-8") for name in result.stdout.split(b"\x00") if name)
        launchers = tuple(
            name
            for name in names
            if _safe_repo_path(name)
            and PurePosixPath(name).parent == PurePosixPath(".")
            and PurePosixPath(name).name in {"Dockerfile", "Containerfile"}
        )
    except UnicodeError as error:
        raise _Gap("LAUNCHER_DISCOVERY_UNPROVEN") from error
    if not launchers or len(launchers) > _MAX_DISCOVERY_LAUNCHERS:
        raise _Gap("LAUNCHER_DISCOVERY_UNPROVEN")
    return launchers


def _literal_workdir(launcher: bytes) -> str:
    directives = _final_stage_directives(
        launcher, decode_gap="RUNTIME_WORKDIR_UNPROVEN"
    )
    workdirs = directives.get("WORKDIR", [])
    if len(workdirs) != 1:
        raise _Gap("RUNTIME_WORKDIR_UNPROVEN")
    workdir = workdirs[0]
    if (
        not workdir.startswith("/")
        or not re.fullmatch(r"/[A-Za-z0-9_./-]*", workdir)
        or ".." in PurePosixPath(workdir).parts
        or posixpath.normpath(workdir) != workdir
    ):
        raise _Gap("RUNTIME_WORKDIR_UNPROVEN")
    return workdir


def discover_operational_route_maps(
    workspace: Path,
    commit_id: str,
    tracked_hashes: Mapping[str, str],
    *,
    max_bytes: int = 131072,
) -> OperationalRouteMap:
    """Find one source-proven parser/launcher pair from a bounded AST manifest.

    ``tracked_hashes`` contains repo-relative Python paths and their SHA-256
    hashes. No project-specific filename, working directory, or XML value is
    guessed. Multiple successful parser/launcher pairs are ambiguous.
    """

    try:
        _verify_commit(workspace, commit_id)
        if max_bytes <= 0 or max_bytes > 1024 * 1024:
            raise _Gap("XML_TOO_LARGE")
        python_paths = sorted(path for path in tracked_hashes if path.endswith(".py"))
        if not python_paths or len(python_paths) > _MAX_DISCOVERY_FILES:
            raise _Gap("SOURCE_MANIFEST_UNAVAILABLE")
        total_bytes = 0
        parsers: list[tuple[str, bytes]] = []
        parser_reasons: set[str] = set()
        for path in python_paths:
            expected_hash = tracked_hashes[path]
            if not _safe_repo_path(path) or not re.fullmatch(
                r"[0-9a-f]{64}", expected_hash
            ):
                raise _Gap("SOURCE_MANIFEST_UNAVAILABLE")
            raw, actual_hash = _verified_blob(
                workspace, commit_id, path, _MAX_PYTHON_BYTES
            )
            total_bytes += len(raw)
            if total_bytes > _MAX_DISCOVERY_BYTES:
                raise _Gap("DISCOVERY_BUDGET_EXHAUSTED")
            if actual_hash != expected_hash:
                raise _Gap("PINNED_BLOB_MISMATCH")
            try:
                _parser_shape(raw, path)
            except _Gap as gap:
                parser_reasons.add(gap.code)
                continue
            parsers.append((path, raw))
        if not parsers:
            if "PARSER_CWD_UNPROVEN" in parser_reasons:
                raise _Gap("PARSER_CWD_UNPROVEN")
            raise _Gap("OPERATIONAL_PARSER_UNRESOLVED")
        launcher_paths = _pinned_launcher_paths(workspace, commit_id)
        if len(parsers) * len(launcher_paths) > _MAX_DISCOVERY_PAIRS:
            raise _Gap("DISCOVERY_BUDGET_EXHAUSTED")
        proven: list[OperationalRouteMap] = []
        reasons: set[str] = set()
        for launcher_path in launcher_paths:
            launcher, _ = _verified_blob(
                workspace, commit_id, launcher_path, _MAX_LAUNCHER_BYTES
            )
            try:
                workdir = _literal_workdir(launcher)
            except _Gap as gap:
                reasons.add(gap.code)
                continue
            for parser_path, parser_source in parsers:
                result = load_operational_routes(
                    workspace,
                    commit_id,
                    parser_path,
                    parser_source,
                    launcher_path,
                    runtime_workdir=workdir,
                    max_bytes=max_bytes,
                )
                if result.bindings:
                    proven.append(result)
                else:
                    reasons.update(result.gaps)
        if len(proven) != 1:
            if proven:
                raise _Gap("AMBIGUOUS_OPERATIONAL_ROUTE_SOURCE")
            return OperationalRouteMap(
                bindings=(),
                gaps=tuple(sorted(reasons)) or ("OPERATIONAL_ROUTE_UNPROVEN",),
            )
        result = proven[0]
        if any(
            tracked_hashes.get(binding.target_path) != binding.target_sha256
            for binding in result.bindings
        ):
            raise _Gap("SOURCE_MANIFEST_UNAVAILABLE")
        return result
    except _Gap as gap:
        return OperationalRouteMap(bindings=(), gaps=(gap.code,))
