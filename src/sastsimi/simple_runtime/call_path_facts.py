"""Bounded, syntax-only request-to-sink context for Python candidates.

This module deliberately does *not* prove taint propagation.  A path produced
here means that statically resolvable Python syntax connects a known request
registration point to the function containing a candidate.  It gives later
Agents the source they need to assess attacker control without turning a
heuristic into a vulnerability verdict.
"""

from __future__ import annotations

import ast
import os
import stat
from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import unquote, urlsplit

from .candidates import StaticCandidate
from .facts import safe_tracked_file

_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SCAN_FILES = 4_000
_MAX_SCANNER_STEPS = 12
_MAX_SYNTAX_HOPS = 6
_MAX_SYNTAX_PATHS = 4
_MAX_PATH_FILES = 4
_MAX_REQUEST_CONTEXT_LINES = 8
_MAX_DOWNSTREAM_PATHS = 4
_MAX_DOWNSTREAM_HOPS = 2
_MAX_DOWNSTREAM_BODY_LINES = 16
_MAX_ENCLOSING_BODY_LINES = 24
_ROUTE_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "websocket",
    "api_route",
}
_ROUTE_REGISTRATIONS = {"add_route", "add_api_route", "add_url_rule"}
# Positional handler indexes for supported route-registration APIs.  These
# APIs do not share a common signature: aiohttp's add_route takes
# (method, path, handler), whereas add_api_route takes (path, endpoint).
_ROUTE_REGISTRATION_HANDLER_INDEX = {
    "add_route": 2,
    "add_api_route": 1,
    "add_url_rule": 2,
}
# Keyword names are framework API-specific.  In particular, Flask's
# ``endpoint`` is a routing label while ``view_func`` is the callable; treating
# both as equivalent loses valid route-to-sink paths when the label is listed
# first in source order.
_ROUTE_REGISTRATION_HANDLER_KEYWORDS = {
    "add_route": ("handler",),
    "add_api_route": ("endpoint",),
    "add_url_rule": ("view_func", "view"),
}
_REQUEST_PARAMETER_NAMES = {
    "request",
    "req",
    "http_request",
    "httprequest",
}
_REQUEST_INPUT_ATTRIBUTES = {
    "GET",
    "POST",
    "args",
    "body",
    "cookies",
    "data",
    "files",
    "form",
    "forms",
    "get_json",
    "json",
    "match_info",
    "path_params",
    "post",
    "query",
    "query_params",
    "values",
}


@dataclass(frozen=True, slots=True)
class _Definition:
    key: str
    path: str
    symbol: str
    line: int
    end_line: int
    route_lines: tuple[int, ...]
    request_context_lines: tuple[int, ...]
    request_context_truncated: bool


@dataclass(frozen=True, slots=True)
class _CallEdge:
    caller: str
    callee: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class _ImportBinding:
    # ``path`` is deliberately optional for an implicit namespace package.
    # A dotted import can still explicitly bind one of its tracked children
    # without making every sibling below that namespace resolvable.
    path: str | None
    symbol: str | None
    # The suffixes that this source file actually imported below ``path``.
    # For ``import pkg.views`` Python binds only ``pkg``, but the only child
    # this syntax proves is available is ``views``.  Keeping the exact suffix
    # prevents an unimported sibling such as ``pkg.admin`` from becoming a
    # fabricated call-graph edge.
    explicit_modules: tuple[tuple[tuple[str, ...], str], ...] = ()


@dataclass(frozen=True, slots=True)
class CandidateCallPaths:
    """Paths and explicit analysis gaps for one static candidate."""

    status: Literal["AVAILABLE", "PARTIAL"]
    paths: tuple[dict[str, object], ...]
    gaps: tuple[str, ...]


def _function_key(path: str, symbol: str) -> str:
    return f"{path}:{symbol}"


def _terminal_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _terminal_name(node.func)
    return None


def _attribute_parts(node: ast.AST) -> tuple[str, ...] | None:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        prefix = _attribute_parts(node.value)
        return (*prefix, node.attr) if prefix is not None else None
    return None


def _regular_source(workspace: Path, path: str) -> str:
    """Read one tracked source file without following a replacement symlink."""

    source = safe_tracked_file(workspace, path)
    if source is None:
        raise ValueError("CALL_PATH_SOURCE_UNAVAILABLE")
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or source.is_symlink():
        raise ValueError("CALL_PATH_SOURCE_UNAVAILABLE")
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        current = os.fstat(stream.fileno())
        if not stat.S_ISREG(current.st_mode) or (
            before.st_dev,
            before.st_ino,
        ) != (current.st_dev, current.st_ino):
            raise ValueError("CALL_PATH_SOURCE_CHANGED")
        raw = stream.read(_MAX_SOURCE_BYTES + 1)
    if len(raw) > _MAX_SOURCE_BYTES:
        raise ValueError("CALL_PATH_SOURCE_TOO_LARGE")
    return raw.decode("utf-8")


def _normalise_tracked_path(workspace: Path, raw: object) -> str | None:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return None
    value = raw.replace("\\", "/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"", "file"} or parsed.netloc not in {"", "localhost"}:
        return None
    if parsed.query or parsed.fragment:
        return None
    try:
        decoded = unquote(parsed.path, errors="strict")
    except UnicodeDecodeError:
        return None
    if parsed.scheme == "file":
        # Windows file URI form is /C:/... .  ``Path`` handles its native form
        # after the leading slash is removed.
        if len(decoded) > 2 and decoded.startswith("/") and decoded[2:3] == ":":
            decoded = decoded[1:]
        try:
            resolved = Path(decoded).resolve(strict=True)
            relative = resolved.relative_to(workspace.resolve(strict=True))
        except (OSError, RuntimeError, ValueError):
            return None
        result = relative.as_posix()
    else:
        pure = PurePosixPath(decoded)
        if (
            pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
            or ":" in decoded
        ):
            return None
        result = pure.as_posix()
    return result if safe_tracked_file(workspace, result) is not None else None


def _module_candidates(path: str) -> tuple[str, ...]:
    pure = PurePosixPath(path)
    if pure.suffix != ".py":
        return ()
    without_suffix = pure.with_suffix("")
    if without_suffix.name == "__init__":
        without_suffix = without_suffix.parent
    dotted = ".".join(without_suffix.parts)
    return tuple(value for value in (dotted, without_suffix.as_posix()) if value)


def _module_from_import(
    path: str,
    module: str | None,
    level: int,
    modules: dict[str, str],
) -> str | None:
    # ``level == 0`` is an absolute import.  Do not prepend the importing
    # module's package: from ``sqli.views`` importing ``sqli.dao.student``
    # must resolve to ``sqli.dao.student``, not ``sqli.sqli.dao.student``.
    if level == 0:
        if not module:
            return None
        return modules.get(module) or modules.get(module.replace(".", "/"))
    # ``path.parent`` is the package of both ``pkg/module.py`` and
    # ``pkg/__init__.py``.  Treating the latter as ``pkg.__init__`` breaks
    # ordinary package-initializer imports such as ``from . import views``.
    package = list(PurePosixPath(path).parent.parts)
    if level:
        # ``from ..x`` inside ``pkg/__init__.py`` is invalid: a relative
        # import may not climb beyond the top-level package.  It must not
        # become a route-to-sink edge merely because a matching tracked file
        # happens to exist at repository root.
        if level > len(package):
            return None
        package = package[: len(package) - (level - 1)]
    suffix = module.split(".") if module else []
    key = ".".join((*package, *suffix))
    return modules.get(key) or modules.get("/".join((*package, *suffix)))


def _is_package_module(path: str | None) -> bool:
    """Whether a resolved import target can provide child modules.

    ``None`` represents an implicit namespace package: there is no tracked
    initializer, but a tracked child module can still be imported below it.
    """

    return path is None or PurePosixPath(path).name == "__init__.py"


def _line_of(node: ast.AST) -> int:
    value = getattr(node, "lineno", 0)
    return value if isinstance(value, int) and value > 0 else 0


def _request_context_lines(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[tuple[int, ...], bool]:
    """Return bounded handler-local request reads as syntax context only.

    This intentionally records neither data flow nor attacker control.  It
    gives the Agent the route handler declaration and bounded request-access
    lines needed to assess those facts itself.
    """

    parameters = (
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    )
    request_names = {
        argument.arg
        for argument in parameters
        if argument.arg.casefold() in _REQUEST_PARAMETER_NAMES
    }
    if node.args.vararg is not None and (
        node.args.vararg.arg.casefold() in _REQUEST_PARAMETER_NAMES
    ):
        request_names.add(node.args.vararg.arg)
    if node.args.kwarg is not None and (
        node.args.kwarg.arg.casefold() in _REQUEST_PARAMETER_NAMES
    ):
        request_names.add(node.args.kwarg.arg)
    # Flask-style handlers often import a singleton named ``request`` instead
    # of accepting it as a parameter.  This remains context, not a source claim.
    request_names.add("request")
    lines: set[int] = set()

    class Collector(ast.NodeVisitor):
        def visit_FunctionDef(self, nested: ast.FunctionDef) -> None:
            del nested

        def visit_AsyncFunctionDef(self, nested: ast.AsyncFunctionDef) -> None:
            del nested

        def visit_Lambda(self, nested: ast.Lambda) -> None:
            del nested

        def visit_ClassDef(self, nested: ast.ClassDef) -> None:
            del nested

        def visit_Attribute(self, attribute: ast.Attribute) -> None:
            value = attribute.value
            while isinstance(value, (ast.Attribute, ast.Subscript)):
                value = value.value
            if (
                attribute.attr in _REQUEST_INPUT_ATTRIBUTES
                and isinstance(value, ast.Name)
                and value.id in request_names
            ):
                line = _line_of(attribute)
                if line:
                    lines.add(line)
            self.generic_visit(attribute)

    collector = Collector()
    for statement in node.body:
        collector.visit(statement)
    ordered = tuple(sorted(lines))
    return (
        ordered[:_MAX_REQUEST_CONTEXT_LINES],
        len(ordered) > _MAX_REQUEST_CONTEXT_LINES,
    )


def _function_local_bindings(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    """Return names that cannot resolve to a module-level definition.

    This is deliberately a bounded scope model. Python decides local scope
    from assignments anywhere in the function, so an unqualified call through
    a parameter, assignment, nested definition, or import must not become a
    fabricated edge to a same-named module function.
    """

    result = {
        argument.arg
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
    }
    if node.args.vararg is not None:
        result.add(node.args.vararg.arg)
    if node.args.kwarg is not None:
        result.add(node.args.kwarg.arg)
    declared_global: set[str] = set()

    def add_target(target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            result.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                add_target(item)
        elif isinstance(target, ast.Starred):
            add_target(target.value)

    class Collector(ast.NodeVisitor):
        def visit_FunctionDef(self, nested: ast.FunctionDef) -> None:
            result.add(nested.name)

        def visit_AsyncFunctionDef(self, nested: ast.AsyncFunctionDef) -> None:
            result.add(nested.name)

        def visit_ClassDef(self, nested: ast.ClassDef) -> None:
            result.add(nested.name)

        def visit_Lambda(self, nested: ast.Lambda) -> None:
            del nested

        def visit_Assign(self, assignment: ast.Assign) -> None:
            for target in assignment.targets:
                add_target(target)
            self.generic_visit(assignment.value)

        def visit_AnnAssign(self, assignment: ast.AnnAssign) -> None:
            add_target(assignment.target)
            if assignment.value is not None:
                self.generic_visit(assignment.value)

        def visit_AugAssign(self, assignment: ast.AugAssign) -> None:
            add_target(assignment.target)
            self.generic_visit(assignment.value)

        def visit_NamedExpr(self, expression: ast.NamedExpr) -> None:
            add_target(expression.target)
            self.generic_visit(expression.value)

        def visit_Import(self, import_node: ast.Import) -> None:
            for item in import_node.names:
                result.add(item.asname or item.name.split(".")[0])

        def visit_ImportFrom(self, import_node: ast.ImportFrom) -> None:
            for item in import_node.names:
                if item.name != "*":
                    result.add(item.asname or item.name)

        def visit_For(self, loop: ast.For) -> None:
            add_target(loop.target)
            self.generic_visit(loop)

        def visit_AsyncFor(self, loop: ast.AsyncFor) -> None:
            add_target(loop.target)
            self.generic_visit(loop)

        def visit_With(self, with_node: ast.With) -> None:
            for item in with_node.items:
                if item.optional_vars is not None:
                    add_target(item.optional_vars)
            self.generic_visit(with_node)

        def visit_AsyncWith(self, with_node: ast.AsyncWith) -> None:
            for item in with_node.items:
                if item.optional_vars is not None:
                    add_target(item.optional_vars)
            self.generic_visit(with_node)

        def visit_ExceptHandler(self, handler: ast.ExceptHandler) -> None:
            if handler.name is not None:
                result.add(handler.name)
            self.generic_visit(handler)

        def visit_Global(self, global_node: ast.Global) -> None:
            declared_global.update(global_node.names)

    collector = Collector()
    for statement in node.body:
        collector.visit(statement)
    return frozenset(result - declared_global)


class PythonCallPathIndex:
    """An immutable and deliberately narrow Python call graph."""

    def __init__(self, workspace: Path, tracked: Sequence[str]) -> None:
        self._workspace = workspace.resolve(strict=True)
        self._tracked = tuple(
            sorted(
                {
                    path
                    for path in tracked
                    if path.endswith(".py") and safe_tracked_file(self._workspace, path)
                }
            )
        )
        self._definitions: dict[str, _Definition] = {}
        self._by_path_symbol: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._trees: dict[str, ast.Module] = {}
        self._imports: dict[str, dict[str, _ImportBinding]] = {}
        self._modules: dict[str, str] = {}
        self._edges: tuple[_CallEdge, ...] = ()
        self._route_entries: dict[str, tuple[tuple[str, int], ...]] = {}
        # A gap in one callable is not automatically a gap in every candidate
        # from its module. Keep global limits, module-level source failures and
        # definition-local gaps distinct, then join only reverse-reachable
        # definitions when materializing one candidate.
        self._global_gaps: set[str] = set()
        self._module_gaps: dict[str, set[str]] = defaultdict(set)
        self._definition_gaps: dict[str, set[str]] = defaultdict(set)
        # A package export can make a particular child module's route
        # reachability uncertain without affecting unrelated modules.
        self._candidate_path_gaps: dict[str, set[str]] = defaultdict(set)
        self._build()

    @property
    def gaps(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                self._global_gaps
                | {gap for values in self._module_gaps.values() for gap in values}
                | {gap for values in self._definition_gaps.values() for gap in values}
                | {
                    gap
                    for values in self._candidate_path_gaps.values()
                    for gap in values
                }
            )
        )

    def _build(self) -> None:
        if len(self._tracked) > _MAX_SCAN_FILES:
            self._global_gaps.add("CALL_PATH_FILE_LIMIT")
            return
        modules: dict[str, str] = {}
        for path in self._tracked:
            for name in _module_candidates(path):
                current = modules.get(name)
                # Python resolves a package initializer before a same-named
                # module file (``pkg/sub/__init__.py`` before ``pkg/sub.py``).
                # Keep that precedence independent of tracked-file ordering.
                if current is None or (
                    _is_package_module(path) and not _is_package_module(current)
                ):
                    modules[name] = path
        self._modules = modules
        for path in self._tracked:
            try:
                tree = ast.parse(_regular_source(self._workspace, path), filename=path)
            except (OSError, RuntimeError, UnicodeError, ValueError, SyntaxError):
                self._module_gaps[path].add("CALL_PATH_SOURCE_UNAVAILABLE")
                continue
            self._trees[path] = tree
        # Import bindings can depend on an initializer that sorts after its
        # importer.  Parse every safe tracked module first so collision checks
        # below never depend on lexical file ordering.
        for path, tree in self._trees.items():
            self._imports[path] = self._collect_imports(path, tree, modules)
            self._collect_definitions(path, tree)
        edges: list[_CallEdge] = []
        registrations: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for path, tree in self._trees.items():
            module_edges, module_registrations = self._collect_edges(path, tree)
            edges.extend(module_edges)
            for key, value in module_registrations.items():
                registrations[key].extend(value)
        self._edges = tuple(
            sorted(
                edges,
                key=lambda item: (item.caller, item.callee, item.path, item.line),
            )
        )
        route_entries: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for key, definition in self._definitions.items():
            route_entries[key].extend(
                (definition.path, line) for line in definition.route_lines
            )
        for key, values in registrations.items():
            route_entries[key].extend(values)
        self._route_entries = {
            key: tuple(sorted(set(values))) for key, values in route_entries.items()
        }

    def _collect_imports(
        self,
        path: str,
        tree: ast.Module,
        modules: dict[str, str],
    ) -> dict[str, _ImportBinding]:
        bindings: dict[str, _ImportBinding] = {}
        loaded_children: dict[str, dict[tuple[str, ...], str]] = defaultdict(dict)
        root_aliases: dict[str, set[str]] = defaultdict(set)
        alias_roots: dict[str, str] = {}

        def binding_with_children(root: str, binding: _ImportBinding) -> _ImportBinding:
            """Retain children explicitly loaded under this package root."""

            known_children = dict(loaded_children.get(root, {}))
            if binding.symbol is None:
                known_children.update(binding.explicit_modules)
            return _ImportBinding(
                binding.path,
                binding.symbol,
                tuple(
                    sorted(
                        known_children.items(),
                        key=lambda value: (len(value[0]), value[0]),
                        reverse=True,
                    )
                ),
            )

        def bind_root_alias(root: str, alias: str, target: str | None) -> None:
            """Bind one local root alias and remember its imported children."""

            previous_root = alias_roots.get(alias)
            if previous_root is not None and previous_root != root:
                root_aliases[previous_root].discard(alias)
            alias_roots[alias] = root
            root_aliases[root].add(alias)
            bindings[alias] = binding_with_children(root, _ImportBinding(target, None))

        def refresh_root_aliases(root: str) -> None:
            """Reflect a later child import on every still-bound root alias."""

            for alias in tuple(root_aliases.get(root, ())):
                binding = bindings.get(alias)
                if binding is not None and binding.symbol is None:
                    bindings[alias] = binding_with_children(root, binding)

        def remember_nested_target(target: str) -> None:
            candidates = _module_candidates(target)
            if not candidates:
                return
            parts = candidates[0].split(".")
            if len(parts) > 1:
                loaded_children[parts[0]][tuple(parts[1:])] = target
                refresh_root_aliases(parts[0])

        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    target = _module_from_import(path, item.name, 0, modules)
                    if "." not in item.name:
                        # An alias binds the complete imported module.  A
                        # single-segment import does the same.  An implicit
                        # namespace has no tracked initializer target, but a
                        # child explicitly loaded above still makes the root
                        # package usable for that exact child only.
                        if target is None and not loaded_children.get(item.name):
                            continue
                        bind_root_alias(item.name, item.asname or item.name, target)
                        continue
                    if target is None:
                        continue
                    # Python binds the first segment for a non-aliased dotted
                    # import: ``import pkg.views`` binds ``pkg``.  Retain the
                    # exact imported suffix rather than looking up arbitrary
                    # tracked children under ``pkg`` later.
                    parts = item.name.split(".")
                    root, *suffix = parts
                    root_target = _module_from_import(path, root, 0, modules)
                    if not all(
                        _is_package_module(
                            _module_from_import(
                                path, ".".join(parts[:index]), 0, modules
                            )
                        )
                        for index in range(1, len(parts))
                    ):
                        # Every non-final prefix must be a package (or an
                        # implicit namespace).  A regular ``pkg/sub.py``
                        # cannot legally import ``pkg.sub.handler``.
                        continue
                    loaded_children[root][tuple(suffix)] = target
                    refresh_root_aliases(root)
                    if item.asname:
                        # An alias binds the complete dotted module locally,
                        # but loading it still makes the child available on a
                        # later explicit ``import pkg``.
                        bindings[item.asname] = _ImportBinding(target, None)
                        continue
                    bind_root_alias(root, root, root_target)
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    if item.name == "*":
                        self._module_gaps[path].add("UNRESOLVED_STAR_IMPORT")
                        continue
                    # ``from package import module`` is a module binding, not
                    # necessarily an attribute named ``module`` on
                    # ``package/__init__.py``.  Prefer a tracked submodule;
                    # otherwise preserve the ordinary imported-symbol binding.
                    nested_module = (
                        f"{node.module}.{item.name}" if node.module else item.name
                    )
                    nested_target = _module_from_import(
                        path, nested_module, node.level, modules
                    )
                    target = _module_from_import(path, node.module, node.level, modules)
                    if nested_target is None and target is None:
                        continue
                    if target is not None:
                        # ``from pkg.views import create`` loads
                        # ``pkg.views`` before binding ``create``. Python then
                        # exposes that loaded child on the parent package, so
                        # a previously imported root alias may legally use
                        # ``pkg.views`` later in this module.
                        remember_nested_target(target)
                    use_nested_target = False
                    if nested_target is not None and _is_package_module(target):
                        use_nested_target = True
                    if use_nested_target and target is not None:
                        assert nested_target is not None
                        export_kind = self._module_export_kind(
                            target,
                            item.name,
                            nested_target,
                            modules,
                        )
                        if export_kind in {"other", "unknown"}:
                            use_nested_target = False
                            if export_kind == "unknown":
                                self._candidate_path_gaps[nested_target].add(
                                    "UNRESOLVED_PACKAGE_EXPORT"
                                )
                    if use_nested_target and nested_target is not None:
                        # A later explicit root import may access the exact
                        # child that this ``from`` import loaded, but must not
                        # gain unrelated siblings.
                        remember_nested_target(nested_target)
                    bindings[item.asname or item.name] = _ImportBinding(
                        nested_target if use_nested_target else target,
                        None if use_nested_target else item.name,
                    )
        return bindings

    def _module_export_kind(
        self,
        module_path: str,
        name: str,
        nested_target: str,
        modules: dict[str, str],
    ) -> Literal["module", "other", "unknown"] | None:
        """Return how an initializer already binds ``name``, if at all.

        ``from pkg import views`` first reads a package attribute. If an
        initializer explicitly binds ``views`` to something other than the
        child module, preferring ``pkg/views.py`` would create a false edge.
        Direct top-level bindings are evaluated in source order. A nested
        conditional binding is explicit uncertainty, not evidence that the
        sibling module is exported at runtime.
        """

        tree = self._trees.get(module_path)
        if tree is None:
            return None
        binding: Literal["module", "other", "unknown"] | None = None
        nested_names = set(_module_candidates(nested_target))

        def assigns_target(target: ast.expr) -> bool:
            if isinstance(target, ast.Name):
                return target.id == name
            if isinstance(target, (ast.Tuple, ast.List)):
                return any(assigns_target(item) for item in target.elts)
            if isinstance(target, ast.Starred):
                return assigns_target(target.value)
            return False

        def has_nested_binding(statement: ast.stmt) -> bool:
            """Whether a conditional branch can bind the requested export."""

            found = False

            class Collector(ast.NodeVisitor):
                def visit_FunctionDef(self, nested: ast.FunctionDef) -> None:
                    nonlocal found
                    found = found or nested.name == name

                def visit_AsyncFunctionDef(self, nested: ast.AsyncFunctionDef) -> None:
                    nonlocal found
                    found = found or nested.name == name

                def visit_ClassDef(self, nested: ast.ClassDef) -> None:
                    nonlocal found
                    found = found or nested.name == name

                def visit_Lambda(self, nested: ast.Lambda) -> None:
                    del nested

                def visit_Assign(self, assignment: ast.Assign) -> None:
                    nonlocal found
                    found = found or any(
                        assigns_target(target) for target in assignment.targets
                    )
                    self.generic_visit(assignment.value)

                def visit_AnnAssign(self, assignment: ast.AnnAssign) -> None:
                    nonlocal found
                    found = found or assigns_target(assignment.target)
                    if assignment.value is not None:
                        self.generic_visit(assignment.value)

                def visit_AugAssign(self, assignment: ast.AugAssign) -> None:
                    nonlocal found
                    found = found or assigns_target(assignment.target)
                    self.generic_visit(assignment.value)

                def visit_NamedExpr(self, expression: ast.NamedExpr) -> None:
                    nonlocal found
                    found = found or assigns_target(expression.target)
                    self.generic_visit(expression.value)

                def visit_Import(self, import_node: ast.Import) -> None:
                    nonlocal found
                    for item in import_node.names:
                        target = _module_from_import(module_path, item.name, 0, modules)
                        bound = item.asname or item.name.split(".")[0]
                        if target == nested_target or bound == name:
                            found = True

                def visit_ImportFrom(self, import_node: ast.ImportFrom) -> None:
                    nonlocal found
                    for item in import_node.names:
                        if item.name == "*":
                            continue
                        child = (
                            f"{import_node.module}.{item.name}"
                            if import_node.module
                            else item.name
                        )
                        target = _module_from_import(
                            module_path, child, import_node.level, modules
                        )
                        if (
                            target == nested_target
                            or (item.asname or item.name) == name
                        ):
                            found = True

            Collector().visit(statement)
            return found

        # Only direct initializer statements have a stable source order here.
        # Nested conditional imports remain unresolved rather than becoming an
        # unsupported ordering claim.
        for statement in tree.body:
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                if statement.name == name:
                    binding = "other"
                elif statement.name == "__getattr__" and binding is None:
                    # PEP 562 can synthesize a package attribute that is not a
                    # tracked child module. Later direct bindings still win.
                    binding = "unknown"
            elif isinstance(statement, ast.Assign):
                if any(assigns_target(target) for target in statement.targets):
                    binding = "other"
            elif isinstance(statement, ast.AnnAssign):
                if assigns_target(statement.target):
                    binding = "other"
            elif isinstance(statement, ast.AugAssign):
                if assigns_target(statement.target):
                    binding = "other"
            elif isinstance(statement, ast.Import):
                for item in statement.names:
                    target = _module_from_import(module_path, item.name, 0, modules)
                    if target == nested_target or item.name in nested_names:
                        # Importing a child attaches it to its parent package,
                        # even when the local name is an alias or the root.
                        binding = "module"
                    bound = item.asname or item.name.split(".")[0]
                    if bound == name:
                        binding = "module" if target == nested_target else "other"
            elif isinstance(statement, ast.ImportFrom):
                for item in statement.names:
                    if item.name == "*":
                        continue
                    child = (
                        f"{statement.module}.{item.name}"
                        if statement.module
                        else item.name
                    )
                    target = _module_from_import(
                        module_path, child, statement.level, modules
                    )
                    if target == nested_target:
                        binding = "module"
                    if (item.asname or item.name) == name:
                        binding = "module" if target == nested_target else "other"
            elif isinstance(
                statement,
                (
                    ast.If,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.With,
                    ast.AsyncWith,
                    ast.Try,
                    ast.Match,
                ),
            ) and has_nested_binding(statement):
                binding = "unknown"
        return binding

    def _collect_definitions(self, path: str, tree: ast.Module) -> None:
        class Collector(ast.NodeVisitor):
            def __init__(self, outer: PythonCallPathIndex) -> None:
                self.outer = outer
                self.classes: list[str] = []

            def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                symbol = ".".join((*self.classes, node.name))
                key = _function_key(path, symbol)
                decorators = tuple(
                    sorted(
                        {
                            _line_of(decorator)
                            for decorator in node.decorator_list
                            if isinstance(decorator, ast.Call)
                            and _terminal_name(decorator.func) in _ROUTE_DECORATORS
                            and _line_of(decorator)
                        }
                    )
                )
                request_context_lines, request_context_truncated = (
                    _request_context_lines(node)
                )
                definition = _Definition(
                    key=key,
                    path=path,
                    symbol=symbol,
                    line=_line_of(node),
                    end_line=getattr(node, "end_lineno", None) or _line_of(node),
                    route_lines=decorators,
                    request_context_lines=request_context_lines,
                    request_context_truncated=request_context_truncated,
                )
                self.outer._definitions[key] = definition
                self.outer._by_path_symbol[(path, symbol)].append(key)
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._function(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._function(node)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                self.classes.append(node.name)
                self.generic_visit(node)
                self.classes.pop()

        Collector(self).visit(tree)

    def _resolve(
        self, path: str, node: ast.AST, owner: _Definition | None
    ) -> str | None:
        parts = _attribute_parts(node)
        if not parts:
            return None
        first, *rest = parts
        bindings = self._imports.get(path, {})
        target_path: str | None = path
        symbol: str | None = None
        if first == "self" and owner is not None and "." in owner.symbol:
            target_path = path
            symbol = owner.symbol.rsplit(".", 1)[0]
        elif first in bindings:
            binding = bindings[first]
            target_path = binding.path
            symbol = binding.symbol
            # Resolve only child modules explicitly imported by this source
            # file.  A tracked sibling is not proof that it was imported or
            # exposed by the package at runtime.
            for module_suffix, resolved_module in binding.explicit_modules:
                if tuple(rest[: len(module_suffix)]) == module_suffix:
                    target_path = resolved_module
                    symbol = None
                    rest = rest[len(module_suffix) :]
                    break
        else:
            # A direct function or a class method in the current module.
            symbol = first
        if target_path is None:
            return None
        if rest:
            symbol = ".".join(part for part in (symbol, *rest) if part)
        if not symbol:
            return None
        matches = self._by_path_symbol.get((target_path, symbol), [])
        return matches[0] if len(matches) == 1 else None

    def _collect_edges(
        self, path: str, tree: ast.Module
    ) -> tuple[list[_CallEdge], dict[str, list[tuple[str, int]]]]:
        edges: list[_CallEdge] = []
        registrations: dict[str, list[tuple[str, int]]] = defaultdict(list)

        class Collector(ast.NodeVisitor):
            def __init__(self, outer: PythonCallPathIndex) -> None:
                self.outer = outer
                self.functions: list[_Definition] = []
                self.dynamic_modules: list[dict[str, str]] = []
                self.local_bindings: list[frozenset[str]] = []

            def _lookup(
                self, node: ast.FunctionDef | ast.AsyncFunctionDef
            ) -> _Definition | None:
                classes: list[str] = []
                for current in self.functions:
                    if "." in current.symbol:
                        classes = current.symbol.rsplit(".", 1)[0].split(".")
                # Definitions are already indexed. Prefer the smallest
                # definition range that covers this function declaration.
                matches = [
                    value
                    for value in self.outer._definitions.values()
                    if value.path == path
                    and value.line == _line_of(node)
                    and value.symbol.split(".")[-1] == node.name
                ]
                if len(matches) == 1:
                    return matches[0]
                del classes
                return None

            def _resolve_visible(
                self, node: ast.AST, owner: _Definition | None
            ) -> str | None:
                """Resolve only names not shadowed by the current function."""

                parts = _attribute_parts(node)
                if (
                    owner is not None
                    and parts
                    and parts[0] != "self"
                    and self.local_bindings
                    and parts[0] in self.local_bindings[-1]
                ):
                    target = self.outer._resolve(path, node, owner)
                    if target is not None:
                        # Keep the uncertainty on the definition that would
                        # otherwise be the callee. This reaches downstream
                        # candidates without fabricating a call edge.
                        self.outer._definition_gaps[target].add(
                            "UNRESOLVED_LOCAL_SHADOWING"
                        )
                    return None
                return self.outer._resolve(path, node, owner)

            def _visit_function(
                self, node: ast.FunctionDef | ast.AsyncFunctionDef
            ) -> None:
                definition = self._lookup(node)
                if definition is None:
                    self.outer._module_gaps[path].add("CALL_PATH_DEFINITION_UNRESOLVED")
                    return
                self.functions.append(definition)
                self.dynamic_modules.append({})
                self.local_bindings.append(_function_local_bindings(node))
                self.generic_visit(node)
                self.local_bindings.pop()
                self.dynamic_modules.pop()
                self.functions.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._visit_function(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._visit_function(node)

            def visit_Call(self, node: ast.Call) -> None:
                owner = self.functions[-1] if self.functions else None
                if isinstance(node.func, ast.Name) and node.func.id in {
                    "getattr",
                    "__import__",
                }:
                    if owner is None:
                        self.outer._module_gaps[path].add("UNRESOLVED_DYNAMIC_DISPATCH")
                    else:
                        self.outer._definition_gaps[owner.key].add(
                            "UNRESOLVED_DYNAMIC_DISPATCH"
                        )
                    if (
                        node.func.id == "getattr"
                        and self.dynamic_modules
                        and len(node.args) >= 2
                        and isinstance(node.args[0], ast.Name)
                        and isinstance(node.args[1], ast.Constant)
                        and isinstance(node.args[1].value, str)
                    ):
                        target_path = self.dynamic_modules[-1].get(node.args[0].id)
                        if target_path is not None:
                            matches = self.outer._by_path_symbol.get(
                                (target_path, node.args[1].value), ()
                            )
                            if len(matches) == 1:
                                self.outer._definition_gaps[matches[0]].add(
                                    "UNRESOLVED_DYNAMIC_DISPATCH"
                                )
                target = self._resolve_visible(node.func, owner)
                if owner is not None and target is not None and _line_of(node):
                    edges.append(_CallEdge(owner.key, target, path, _line_of(node)))
                terminal = _terminal_name(node.func)
                if terminal in _ROUTE_REGISTRATIONS:
                    endpoint = self._registration_target(node)
                    target = (
                        self._resolve_visible(endpoint, owner)
                        if endpoint is not None
                        else None
                    )
                    if target is None:
                        if owner is None:
                            self.outer._module_gaps[path].add(
                                "UNRESOLVED_ROUTE_REGISTRATION"
                            )
                        else:
                            self.outer._definition_gaps[owner.key].add(
                                "UNRESOLVED_ROUTE_REGISTRATION"
                            )
                    elif _line_of(node):
                        registrations[target].append((path, _line_of(node)))
                elif (
                    target is None
                    and owner is not None
                    and "UNRESOLVED_STAR_IMPORT"
                    in self.outer._module_gaps.get(path, ())
                ):
                    self.outer._definition_gaps[owner.key].add("UNRESOLVED_STAR_IMPORT")
                self.generic_visit(node)

            def visit_Assign(self, node: ast.Assign) -> None:
                if self.dynamic_modules and isinstance(node.value, ast.Call):
                    func_name = _terminal_name(node.value.func)
                    first_arg = node.value.args[0] if node.value.args else None
                    if (
                        func_name in {"import_module", "__import__"}
                        and isinstance(first_arg, ast.Constant)
                        and isinstance(first_arg.value, str)
                    ):
                        target_path = self.outer._modules.get(first_arg.value)
                        if target_path is not None:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.dynamic_modules[-1][target.id] = target_path
                self.generic_visit(node)

            @staticmethod
            def _registration_target(node: ast.Call) -> ast.AST | None:
                terminal = _terminal_name(node.func)
                if terminal is None:
                    return None
                names = _ROUTE_REGISTRATION_HANDLER_KEYWORDS.get(terminal, ())
                for keyword in node.keywords:
                    if keyword.arg in names:
                        return keyword.value
                handler_index = _ROUTE_REGISTRATION_HANDLER_INDEX.get(terminal)
                if handler_index is not None and len(node.args) > handler_index:
                    return node.args[handler_index]
                return None

        Collector(self).visit(tree)
        return edges, registrations

    def _definition_at(self, path: str, line: int) -> _Definition | None:
        matches = [
            item
            for item in self._definitions.values()
            if item.path == path and item.line <= line <= item.end_line
        ]
        if not matches:
            return None
        return min(matches, key=lambda item: (item.end_line - item.line, item.key))

    def _scanner_path(
        self, candidate: StaticCandidate, gaps: set[str]
    ) -> dict[str, object] | None:
        trace = candidate.flow_trace
        if candidate.kind != "FLOW" or not isinstance(trace, dict):
            return None
        seen: set[tuple[str, int]] = set()
        locations: list[tuple[str, int]] = []

        def add(raw_path: object, raw_line: object) -> None:
            if len(locations) >= _MAX_SCANNER_STEPS:
                gaps.add("SCANNER_FLOW_STEP_LIMIT")
                return
            path = _normalise_tracked_path(self._workspace, raw_path)
            line = raw_line if isinstance(raw_line, int) else 0
            if path is not None and path not in self._tracked:
                gaps.add("SCANNER_FLOW_PATH_UNSUPPORTED")
                return
            if path is None or line < 1 or (path, line) in seen:
                return
            seen.add((path, line))
            locations.append((path, line))

        def walk(value: object, depth: int = 0) -> None:
            if depth > 32 or len(locations) >= _MAX_SCANNER_STEPS:
                return
            if isinstance(value, list):
                for item in value:
                    walk(item, depth + 1)
                return
            if not isinstance(value, dict):
                return
            physical = value.get("physicalLocation")
            if isinstance(physical, dict):
                artifact = physical.get("artifactLocation")
                region = physical.get("region")
                if isinstance(artifact, dict) and isinstance(region, dict):
                    add(artifact.get("uri"), region.get("startLine"))
            raw_path = value.get("path")
            if raw_path is not None:
                raw_line = value.get("line")
                if not isinstance(raw_line, int):
                    start = value.get("start")
                    raw_line = start.get("line") if isinstance(start, dict) else None
                add(raw_path, raw_line)
            for item in value.values():
                walk(item, depth + 1)

        walk(trace)
        if len(locations) < 2:
            return None
        if len({path for path, _line in locations}) > _MAX_PATH_FILES:
            gaps.add("SCANNER_FLOW_FILE_LIMIT")
            return None
        return {
            "kind": "call_path_v1",
            "provenance": "scanner",
            "assurance": "TOOL_PROVEN",
            "status": "AVAILABLE",
            "steps": [
                {
                    "role": "FLOW_STEP",
                    "path": path,
                    "line": line,
                }
                for path, line in locations
            ],
            "gaps": [],
        }

    def _syntax_paths(
        self, candidate: StaticCandidate, gaps: set[str]
    ) -> tuple[dict[str, object], ...]:
        sink = self._definition_at(candidate.path, candidate.line)
        if sink is None:
            gaps.add("SINK_ENCLOSING_FUNCTION_UNAVAILABLE")
            return ()
        reverse: dict[str, list[_CallEdge]] = defaultdict(list)
        for edge in self._edges:
            reverse[edge.callee].append(edge)
        result: list[dict[str, object]] = []
        pending: deque[tuple[str, tuple[_CallEdge, ...], frozenset[str]]] = deque(
            [(sink.key, (), frozenset({sink.key}))]
        )
        while pending and len(result) < _MAX_SYNTAX_PATHS:
            current, backwards, visited = pending.popleft()
            entries = self._route_entries.get(current, ())
            if entries:
                forward = tuple(reversed(backwards))
                route_path, route_line = entries[0]
                definition = self._definitions[current]
                if definition.request_context_truncated:
                    gaps.add("REQUEST_CONTEXT_LINE_LIMIT")
                steps: list[dict[str, object]] = [
                    {
                        "role": "ROUTE_ENTRY",
                        "path": route_path,
                        "line": route_line,
                        "end_line": route_line,
                        "symbol": definition.symbol,
                    }
                ]
                steps.append(
                    {
                        "role": "HANDLER_DEFINITION",
                        "path": definition.path,
                        "line": definition.line,
                        "end_line": definition.line,
                        "symbol": definition.symbol,
                    }
                )
                steps.extend(
                    {
                        "role": "REQUEST_CONTEXT",
                        "path": definition.path,
                        "line": line,
                        "end_line": line,
                        "symbol": definition.symbol,
                    }
                    for line in definition.request_context_lines
                )
                for edge in forward:
                    callee = self._definitions[edge.callee]
                    steps.append(
                        {
                            "role": "CALL",
                            "path": edge.path,
                            "line": edge.line,
                            "end_line": edge.line,
                            "symbol": callee.symbol,
                        }
                    )
                steps.append(
                    {
                        "role": "SINK",
                        "path": candidate.path,
                        "line": candidate.line,
                        "end_line": candidate.end_line,
                        "symbol": sink.symbol,
                    }
                )
                if len({str(step["path"]) for step in steps}) <= _MAX_PATH_FILES:
                    result.append(
                        {
                            "kind": "call_path_v1",
                            "provenance": "python_syntax",
                            "assurance": "SYNTACTIC_REACHABILITY",
                            "status": "AVAILABLE",
                            "steps": steps,
                            "gaps": [],
                        }
                    )
                else:
                    gaps.add("SYNTAX_FLOW_FILE_LIMIT")
                continue
            if len(backwards) >= _MAX_SYNTAX_HOPS:
                gaps.add("SYNTAX_FLOW_HOP_LIMIT")
                continue
            for edge in sorted(
                reverse.get(current, ()),
                key=lambda item: (item.path, item.line, item.caller),
            ):
                if edge.caller not in visited:
                    pending.append(
                        (edge.caller, (*backwards, edge), visited | {edge.caller})
                    )
        if pending:
            gaps.add("SYNTAX_FLOW_PATH_LIMIT")
        return tuple(result)

    def _reachable_syntax_gaps(self, candidate: StaticCandidate) -> set[str]:
        """Return unresolved syntax only from functions that can reach this sink."""

        sink = self._definition_at(candidate.path, candidate.line)
        if sink is None:
            return set(self._module_gaps.get(candidate.path, ()))
        reverse: dict[str, list[_CallEdge]] = defaultdict(list)
        for edge in self._edges:
            reverse[edge.callee].append(edge)
        pending: deque[tuple[str, int]] = deque([(sink.key, 0)])
        visited = {sink.key}
        gaps: set[str] = set()
        while pending:
            current, hops = pending.popleft()
            gaps.update(self._definition_gaps.get(current, ()))
            for edge in reverse.get(current, ()):
                if edge.caller in visited:
                    continue
                if hops >= _MAX_SYNTAX_HOPS:
                    gaps.add("SYNTAX_FLOW_HOP_LIMIT")
                    continue
                visited.add(edge.caller)
                pending.append((edge.caller, hops + 1))
        return gaps

    def _downstream_context_paths(
        self, candidate: StaticCandidate, gaps: set[str]
    ) -> tuple[dict[str, object], ...]:
        """Show bounded callees after an input hint, without asserting taint flow.

        A request-read hint is often *before* the dangerous call. Reverse
        route-to-candidate paths alone therefore omit the implementation the
        hypothesis Agent needs to inspect. Only statically resolved calls are
        included, and every truncation is explicit.
        """

        if candidate.kind not in {"HINT", "ENTRY_POINT"}:
            return ()
        owner = self._definition_at(candidate.path, candidate.line)
        if owner is None:
            return ()
        outgoing: dict[str, list[_CallEdge]] = defaultdict(list)
        for edge in self._edges:
            outgoing[edge.caller].append(edge)
        seed: tuple[dict[str, object], ...] = (
            {
                "role": "CANDIDATE",
                "path": candidate.path,
                "line": candidate.line,
                "end_line": candidate.end_line,
                "symbol": owner.symbol,
            },
        )
        pending: deque[
            tuple[str, int, tuple[dict[str, object], ...], frozenset[str], int]
        ] = deque([(owner.key, candidate.line, seed, frozenset({owner.key}), 0)])
        result: list[dict[str, object]] = []
        while pending and len(result) < _MAX_DOWNSTREAM_PATHS:
            current, first_line, steps, visited, depth = pending.popleft()
            eligible = [
                edge
                for edge in outgoing.get(current, ())
                if edge.line >= first_line and edge.callee not in visited
            ]
            for index, edge in enumerate(eligible):
                callee = self._definitions[edge.callee]
                path_count = len({str(item["path"]) for item in steps} | {callee.path})
                if path_count > _MAX_PATH_FILES:
                    gaps.add("DOWNSTREAM_CONTEXT_FILE_LIMIT")
                    continue
                body_lines = list(range(callee.line, callee.end_line + 1))
                if len(body_lines) > _MAX_DOWNSTREAM_BODY_LINES:
                    half = _MAX_DOWNSTREAM_BODY_LINES // 2
                    body_lines = [*body_lines[:half], *body_lines[-half:]]
                    gaps.add("DOWNSTREAM_CALLEE_BODY_TRUNCATED")
                extended = (
                    *steps,
                    {
                        "role": "CALL",
                        "path": edge.path,
                        "line": edge.line,
                        "end_line": edge.line,
                        "symbol": callee.symbol,
                    },
                    *(
                        {
                            "role": "CALLEE_BODY_LINE",
                            "path": callee.path,
                            "line": line,
                            "end_line": line,
                            "symbol": callee.symbol,
                        }
                        for line in body_lines
                    ),
                )
                result.append(
                    {
                        "kind": "candidate_downstream_context_v1",
                        "provenance": "python_syntax",
                        "assurance": "SYNTACTIC_REACHABILITY",
                        "status": "AVAILABLE",
                        "steps": list(extended),
                        "gaps": [],
                    }
                )
                if len(result) >= _MAX_DOWNSTREAM_PATHS:
                    if (
                        index + 1 < len(eligible)
                        or pending
                        or (
                            depth + 1 < _MAX_DOWNSTREAM_HOPS
                            and outgoing.get(edge.callee)
                        )
                    ):
                        gaps.add("DOWNSTREAM_CONTEXT_PATH_LIMIT")
                    break
                if depth + 1 < _MAX_DOWNSTREAM_HOPS:
                    pending.append(
                        (edge.callee, 1, extended, visited | {edge.callee}, depth + 1)
                    )
            if len(result) >= _MAX_DOWNSTREAM_PATHS:
                break
        if pending:
            gaps.add("DOWNSTREAM_CONTEXT_PATH_LIMIT")
        return tuple(result)

    def _enclosing_context_path(
        self, candidate: StaticCandidate, gaps: set[str]
    ) -> dict[str, object] | None:
        """Include bounded local statements before a sink, without claiming flow."""

        owner = self._definition_at(candidate.path, candidate.line)
        if owner is None:
            return None
        all_lines = range(owner.line, owner.end_line + 1)
        if len(all_lines) <= _MAX_ENCLOSING_BODY_LINES:
            selected = list(all_lines)
        else:
            # Keep the declaration and nearby statements, including the lines
            # where a sink argument is commonly assembled. Do not silently
            # imply that the omitted part of a long function was inspected.
            first = max(owner.line, candidate.line - 12)
            last = min(owner.end_line, first + _MAX_ENCLOSING_BODY_LINES - 2)
            first = max(owner.line, last - _MAX_ENCLOSING_BODY_LINES + 2)
            selected = sorted({owner.line, *range(first, last + 1)})
            gaps.add("ENCLOSING_CONTEXT_TRUNCATED")
        return {
            "kind": "candidate_enclosing_context_v1",
            "provenance": "python_syntax",
            "assurance": "SOURCE_CONTEXT_ONLY",
            "status": "AVAILABLE",
            "steps": [
                {
                    "role": "ENCLOSING_BODY_LINE",
                    "path": owner.path,
                    "line": line,
                    "end_line": line,
                    "symbol": owner.symbol,
                }
                for line in selected
            ],
            "gaps": [],
        }

    def for_candidate(
        self,
        candidate: StaticCandidate,
        *,
        include_downstream: bool = False,
        include_enclosing: bool = False,
    ) -> CandidateCallPaths:
        """Return only verifiable, bounded path facts for one candidate."""

        gaps = set(self._global_gaps)
        gaps.update(self._candidate_path_gaps.get(candidate.path, ()))
        paths: list[dict[str, object]] = []
        scanner = self._scanner_path(candidate, gaps)
        if scanner is not None:
            paths.append(scanner)
        syntax_gaps: set[str] = set()
        syntax_paths = self._syntax_paths(candidate, syntax_gaps)
        paths.extend(syntax_paths)
        if include_downstream:
            paths.extend(self._downstream_context_paths(candidate, gaps))
        if include_enclosing:
            enclosing = self._enclosing_context_path(candidate, gaps)
            if enclosing is not None:
                paths.append(enclosing)
        if scanner is None:
            gaps.update(self._reachable_syntax_gaps(candidate))
            gaps.update(syntax_gaps)
            if not syntax_paths:
                gaps.add("SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE")
        frozen_gaps = tuple(sorted(gaps))
        return CandidateCallPaths(
            status="AVAILABLE" if paths and not frozen_gaps else "PARTIAL",
            paths=tuple(paths),
            gaps=frozen_gaps,
        )


def build_python_call_path_index(
    workspace: Path, tracked: Sequence[str]
) -> PythonCallPathIndex:
    """Build a best-effort index; unsupported syntax is an explicit gap."""

    return PythonCallPathIndex(workspace, tracked)


def call_path_step_locations(
    paths: Iterable[dict[str, object]],
) -> tuple[tuple[str, int], ...]:
    """Return deterministic, trusted source locations visible for one path set."""

    result: set[tuple[str, int]] = set()
    for path in paths:
        steps = path.get("steps") if isinstance(path, dict) else None
        if not isinstance(steps, list):
            continue
        for step in steps:
            if (
                isinstance(step, dict)
                and isinstance(step.get("path"), str)
                and type(step.get("line")) is int
                and step["line"] >= 1
            ):
                result.add((step["path"], step["line"]))
    return tuple(sorted(result))
