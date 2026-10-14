"""Conservative, source-pinned Python route/boundary evidence.

This module does not reinterpret a saved v9 certificate. It gives a later
coverage round additional evidence for a *particular* route and gap event.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .attack_surfaces import AttackSurface, SurfaceIndex, surface_review_contract
from .call_path_facts import _function_local_bindings
from .surface_applicability_v9 import assess_optional_analyzers
from .surface_path_proof_v9 import (
    DownstreamPathV9,
    PathCertificateV9,
    _flask_binding,
    _request_binding,
    _source_and_tree,
    validate_path_certificate,
)


@dataclass(frozen=True, slots=True)
class RouteBoundaryProofV10:
    surface_id: str
    source_hashes: tuple[tuple[str, str], ...]
    resolved_edges: tuple[dict[str, object], ...]
    discharged_gap_events: tuple[dict[str, object], ...]
    remaining_gap_events: tuple[dict[str, object], ...]
    boundary_kind: str
    external_scope_limit: str | None
    unresolved_reasons: tuple[str, ...]
    expected_v9_path_ids: tuple[str, ...] = ()
    unresolved_v9_path_ids: tuple[str, ...] = ()
    resolved_v9_path_ids: tuple[str, ...] = ()
    expected_v9_part_count: int = 0

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_route_boundary_proof_v10",
            "surface_id": self.surface_id,
            "source_hashes": [list(row) for row in self.source_hashes],
            "resolved_edges": list(self.resolved_edges),
            "discharged_gap_events": list(self.discharged_gap_events),
            "remaining_gap_events": list(self.remaining_gap_events),
            "boundary_kind": self.boundary_kind,
            "external_scope_limit": self.external_scope_limit,
            "unresolved_reasons": list(self.unresolved_reasons),
            "expected_v9_path_ids": list(self.expected_v9_path_ids),
            "unresolved_v9_path_ids": list(self.unresolved_v9_path_ids),
            "resolved_v9_path_ids": list(self.resolved_v9_path_ids),
            "expected_v9_part_count": self.expected_v9_part_count,
        }


def _route_function(tree: ast.Module, surface: AttackSurface) -> ast.FunctionDef | None:
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and len(node.decorator_list) == 1
        and any(
            isinstance(decorator, ast.Call)
            and (
                decorator.lineno == surface.line
                or (
                    node.lineno <= surface.line <= (node.end_lineno or node.lineno)
                    and _request_binding(tree, surface.line)
                )
            )
            and _flask_binding(tree, decorator.lineno)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "route"
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == "app"
            and decorator.args
            and isinstance(decorator.args[0], ast.Constant)
            and isinstance(decorator.args[0].value, str)
            for decorator in node.decorator_list
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _direct_functions(tree: ast.Module) -> dict[str, ast.FunctionDef] | None:
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    if len({node.name for node in functions}) != len(functions):
        return None
    return {node.name: node for node in functions}


_KNOWN_IMPORTED_ROUTE_CALLS = frozenset(
    {
        "flask.make_response",
        "flask.render_template",
        "flask.jsonify",
        "flask.request.args.get",
        "flask.request.form.get",
        "flask.request.get_json",
        "sqlite3.connect",
        "subprocess.run",
        "requests.get",
        "html.escape",
        "re.sub",
        "urllib.parse.urlparse",
    }
)
_KNOWN_LOCAL_ROUTE_CALLS = frozenset(
    {
        "json_data.get",
        "sqlite_connection.cursor",
        "sqlite_connection.commit",
        "sqlite_connection.close",
        "sqlite_cursor.execute",
        "sqlite_cursor.fetchall",
    }
)


def _called_local_functions(
    tree: ast.Module,
    route: ast.FunctionDef,
    functions: Mapping[str, ast.FunctionDef],
    indexed_sql_lines: frozenset[int] = frozenset(),
) -> set[str] | None:
    """Return a closed set only when every reached call has a pinned binding."""

    names = set(functions)
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }

    def module_scoped(node: ast.AST) -> bool:
        parent = parents.get(id(node))
        while parent is not None:
            if isinstance(
                parent,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                return False
            parent = parents.get(id(parent))
        return True

    def attribute_parts(node: ast.AST) -> tuple[str, ...] | None:
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Attribute):
            prefix = attribute_parts(node.value)
            return (*prefix, node.attr) if prefix is not None else None
        return None

    def assignment_root(node: ast.AST) -> str | None:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    imports: dict[str, str] = {}
    invalid_imports: set[str] = set()
    module_bindings = set(names)
    for statement in tree.body:
        aliases: list[tuple[str, str]] = []
        if isinstance(statement, ast.Import):
            aliases = [
                (
                    item.asname or item.name.split(".")[0],
                    item.name if item.asname else item.name.split(".")[0],
                )
                for item in statement.names
            ]
        elif isinstance(statement, ast.ImportFrom) and statement.level == 0:
            aliases = [
                (item.asname or item.name, f"{statement.module}.{item.name}")
                for item in statement.names
                if statement.module is not None and item.name != "*"
            ]
        for binding, origin in aliases:
            module_bindings.add(binding)
            if binding in imports:
                invalid_imports.add(binding)
            imports[binding] = origin

    app_route_attributes = {
        id(decorator.func)
        for function in functions.values()
        for decorator in function.decorator_list
        if isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "route"
        and isinstance(decorator.func.value, ast.Name)
        and decorator.func.value.id == "app"
    }
    app_route = any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and id(decorator.func) in app_route_attributes
        for decorator in route.decorator_list
    )
    app_assignments = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "app"
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "Flask"
    ]
    if app_route and len(app_assignments) != 1:
        return None

    dynamic_bindings = {
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "__import__",
        "import_module",
        "reload",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name == "builtins" or alias.name.startswith("importlib")
            for alias in node.names
        ):
            return None
        if isinstance(node, ast.ImportFrom) and (
            node.module is not None
            and (
                node.module == "importlib"
                or node.module.startswith("importlib.")
                or node.module == "builtins"
                and any(alias.name in dynamic_bindings for alias in node.names)
            )
        ):
            return None
        if isinstance(node, ast.Call):
            parts = attribute_parts(node.func)
            if parts is None:
                return None
            qualified = (*imports.get(parts[0], parts[0]).split("."), *parts[1:])
            if qualified[-1] in dynamic_bindings:
                return None
        if not module_scoped(node):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for item in node.names:
                if item.name == "*":
                    return None
                binding = item.asname or (
                    item.name.split(".")[0]
                    if isinstance(node, ast.Import)
                    else item.name
                )
                module_bindings.add(binding)
                if node not in tree.body and binding in imports:
                    invalid_imports.add(binding)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_bindings.add(node.name)
            invalid_imports.add(node.name)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            module_bindings.add(node.id)
            if node.id in imports:
                invalid_imports.add(node.id)
            if (
                app_route
                and node.id == "app"
                and (
                    len(app_assignments) != 1
                    or node is not app_assignments[0].targets[0]
                )
            ):
                return None
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            root = assignment_root(node)
            if root in imports:
                invalid_imports.add(root)
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            module_bindings.add(node.name)
            invalid_imports.add(node.name)
        if isinstance(node, ast.MatchMapping) and node.rest:
            module_bindings.add(node.rest)
            invalid_imports.add(node.rest)
        if isinstance(node, ast.ExceptHandler) and node.name:
            module_bindings.add(node.name)
            invalid_imports.add(node.name)
        if (
            isinstance(node, (ast.AsyncFunctionDef, ast.ClassDef))
            and node.name in names
        ):
            return None
        if isinstance(node, ast.Import) and any(
            (item.asname or item.name.split(".")[0]) in names for item in node.names
        ):
            return None
        if isinstance(node, ast.ImportFrom) and any(
            item.name == "*" or (item.asname or item.name) in names
            for item in node.names
        ):
            return None
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name in names:
            return None
        if isinstance(node, ast.MatchMapping) and node.rest in names:
            return None
        if isinstance(node, ast.ExceptHandler) and node.name in names:
            return None
    if app_route:
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Name)
                or node.id != "app"
                or not isinstance(node.ctx, ast.Load)
            ):
                continue
            parent = parents.get(id(node))
            if not isinstance(parent, ast.Attribute) or parent.value is not node:
                return None
            if id(parent) in app_route_attributes:
                continue
            grandparent = parents.get(id(parent))
            if not (
                parent.attr == "run"
                and isinstance(parent.ctx, ast.Load)
                and module_scoped(parent)
                and isinstance(grandparent, ast.Call)
                and grandparent.func is parent
            ):
                return None
    # A definition may be called directly, but handing its object to any
    # other binding makes a closed direct-call graph unprovable.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in names:
            parent = parents.get(id(node))
            if not isinstance(node.ctx, ast.Load) or not (
                isinstance(parent, ast.Call) and parent.func is node
            ):
                return None
        if isinstance(node, ast.arg) and node.arg in names:
            return None
    for function in functions.values():
        for node in ast.walk(function):
            if isinstance(node, (ast.Global, ast.Nonlocal)) and (
                names | imports.keys() | {"app"}
            ).intersection(node.names):
                return None

    def resolved_call(
        target: ast.AST, local_bindings: frozenset[str], origins: Mapping[str, str]
    ) -> str | None:
        parts = attribute_parts(target)
        if not parts:
            return None
        root = parts[0]
        if root in origins:
            return ".".join((origins[root], *parts[1:]))
        if root in local_bindings or root in invalid_imports:
            return None
        if root in imports:
            return ".".join((imports[root], *parts[1:]))
        if parts == ("str",) and "str" not in module_bindings:
            return "builtins.str"
        return None

    def local_origins(
        function: ast.FunctionDef, local_bindings: frozenset[str]
    ) -> dict[str, str]:
        def guarded_origin_call(value: ast.expr) -> ast.Call | None:
            if isinstance(value, ast.Call):
                return value
            if (
                isinstance(value, ast.BoolOp)
                and isinstance(value.op, ast.Or)
                and len(value.values) == 2
                and isinstance(value.values[0], ast.Call)
                and isinstance(value.values[1], ast.Dict)
                and not value.values[1].keys
                and not value.values[1].values
            ):
                return value.values[0]
            return None

        assignments: dict[str, list[ast.expr]] = {}
        direct_assignments: set[str] = set()
        writes: dict[str, int] = {}
        ambiguous_bindings: set[str] = set()

        def collect_safe_assignment(statement: ast.stmt, *, direct: bool) -> None:
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
            ):
                name = statement.targets[0].id
                assignments.setdefault(name, []).append(statement.value)
                if direct:
                    direct_assignments.add(name)
            elif (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and statement.value is not None
            ):
                name = statement.target.id
                assignments.setdefault(name, []).append(statement.value)
                if direct:
                    direct_assignments.add(name)
            elif isinstance(statement, ast.If):
                for child in (*statement.body, *statement.orelse):
                    collect_safe_assignment(child, direct=False)
            elif isinstance(statement, ast.Try):
                for child in (
                    *statement.body,
                    *statement.orelse,
                    *statement.finalbody,
                ):
                    collect_safe_assignment(child, direct=False)

        for statement in function.body:
            collect_safe_assignment(statement, direct=True)
            for node in ast.walk(statement):
                if isinstance(node, ast.Name) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    writes[node.id] = writes.get(node.id, 0) + 1
                if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                    ambiguous_bindings.add(node.name)
                if isinstance(node, ast.MatchMapping) and node.rest:
                    ambiguous_bindings.add(node.rest)
                if isinstance(node, ast.ExceptHandler) and node.name:
                    ambiguous_bindings.add(node.name)
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    ambiguous_bindings.update(
                        alias.asname
                        or (
                            alias.name.split(".")[0]
                            if isinstance(node, ast.Import)
                            else alias.name
                        )
                        for alias in node.names
                    )
        parameters = {
            argument.arg
            for argument in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
                *((function.args.vararg,) if function.args.vararg else ()),
                *((function.args.kwarg,) if function.args.kwarg else ()),
            )
        }
        origins: dict[str, str] = {}
        for _ in range(len(assignments)):
            changed = False
            for name, values in assignments.items():
                if (
                    name in origins
                    or name in parameters
                    or name in imports
                    or name in names
                    or name in ambiguous_bindings
                    or name not in direct_assignments
                    or writes.get(name) != len(values)
                ):
                    continue
                proven: set[str] = set()
                for value in values:
                    source_call = guarded_origin_call(value)
                    if source_call is None:
                        break
                    called = resolved_call(source_call.func, local_bindings, origins)
                    if called is None:
                        break
                    origin = {
                        "flask.request.get_json": "json_data",
                        "sqlite3.connect": "sqlite_connection",
                        "sqlite_connection.cursor": "sqlite_cursor",
                    }.get(called)
                    if origin is None:
                        break
                    proven.add(origin)
                else:
                    if len(proven) == 1:
                        origins[name] = proven.pop()
                        changed = True
            if not changed:
                break
        return origins

    indexed_sql_call_counts: dict[int, int] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and node.lineno in indexed_sql_lines
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "executemany", "executescript"}
        ):
            indexed_sql_call_counts[node.lineno] = (
                indexed_sql_call_counts.get(node.lineno, 0) + 1
            )

    visited: set[str] = set()
    stack = [route.name]
    while stack:
        name = stack.pop()
        if name in visited:
            continue
        visited.add(name)
        function = functions[name]
        if name != route.name and function.decorator_list:
            return None
        if any(
            isinstance(
                node,
                (
                    ast.Global,
                    ast.Nonlocal,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            )
            for statement in function.body
            for node in ast.walk(statement)
        ):
            return None
        local_bindings = _function_local_bindings(function)
        if names.intersection(local_bindings):
            return None
        if any(
            isinstance(node, (ast.MatchAs, ast.MatchStar))
            and node.name in names
            or isinstance(node, ast.MatchMapping)
            and node.rest in names
            for node in ast.walk(function)
        ):
            return None
        origins = local_origins(function, local_bindings)
        if any(
            isinstance(node, (ast.Attribute, ast.Subscript))
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and assignment_root(node) in imports.keys() | origins.keys()
            for statement in function.body
            for node in ast.walk(statement)
        ):
            return None
        for call in (
            node
            for statement in function.body
            for node in ast.walk(statement)
            if isinstance(node, ast.Call)
        ):
            if isinstance(call.func, ast.Name) and call.func.id in names:
                stack.append(call.func.id)
            elif resolved_call(
                call.func, local_bindings, origins
            ) not in _KNOWN_IMPORTED_ROUTE_CALLS | _KNOWN_LOCAL_ROUTE_CALLS | {
                "builtins.str"
            } and not (
                call.lineno in indexed_sql_lines
                and indexed_sql_call_counts.get(call.lineno) == 1
                and isinstance(call.func, ast.Attribute)
                and call.func.attr in {"execute", "executemany", "executescript"}
            ):
                return None
            if any(
                isinstance(argument, ast.Name) and argument.id in names
                for argument in (*call.args, *(item.value for item in call.keywords))
            ):
                return None
    return visited


def _enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | None:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    return (
        min(matches, key=lambda item: (item.end_lineno or item.lineno) - item.lineno)
        if matches
        else None
    )


def _response_path(
    certificate: PathCertificateV9,
    surface: AttackSurface,
    route: ast.FunctionDef,
) -> tuple[dict[str, object], ...]:
    edges: list[dict[str, object]] = []
    route_lines = {decorator.lineno for decorator in route.decorator_list}
    for path in certificate.downstream_paths:
        if (
            path.kind != "flask_html_response_v9"
            or not path.steps
            or path.steps[0].path != surface.path
            or path.steps[0].line not in route_lines
            or not any(
                step.line == surface.line
                and step.role in {"ROUTE_ENTRY", "REQUEST_CONTEXT"}
                for step in path.steps
            )
            or path.steps[-1].role != "SINK"
            or len(path.edge_ids) != len(path.steps) - 1
        ):
            continue
        edges.extend(
            {
                "path_id": path.path_id,
                "edge_id": edge_id,
                "from_line": first.line,
                "to_line": second.line,
                "source_sha256": first.source_sha256,
            }
            for edge_id, (first, second) in zip(
                path.edge_ids,
                zip(path.steps, path.steps[1:], strict=False),
                strict=True,
            )
        )
    return tuple(edges)


def _indexed_sink_paths(
    index: SurfaceIndex,
    surface: AttackSurface,
    tree: ast.Module,
    route: ast.FunctionDef,
    functions: Mapping[str, ast.FunctionDef],
    reachable: set[str],
    certificate: PathCertificateV9,
) -> tuple[dict[str, object], ...]:
    """Bind every indexed sink in this local call closure to one pinned path.

    This proves syntactic reachability to a Python call site, not taint,
    exploitation, or behavior inside an external library.
    """

    sinks = {
        row.surface_id: row
        for row in index.surfaces
        if row.path == surface.path
        and surface_review_contract(row.type) == "SINK"
        and (owner := _enclosing_function(tree, row.line)) is not None
        and owner is functions.get(owner.name)
        and owner.name in reachable
    }
    if not sinks:
        return ()
    if any(
        path.kind == "call_path_v1" and path.sink_surface_id not in sinks
        for path in certificate.downstream_paths
    ):
        return ()
    route_lines = {decorator.lineno for decorator in route.decorator_list}
    source_hashes = dict(index.ast_source_hashes)
    matched: dict[str, list[DownstreamPathV9]] = {sink_id: [] for sink_id in sinks}
    for path in certificate.downstream_paths:
        sink = sinks.get(path.sink_surface_id)
        if path.kind != "call_path_v1" or sink is None or not path.steps:
            continue
        if (
            path.steps[0].role != "ROUTE_ENTRY"
            or path.steps[0].path != surface.path
            or path.steps[0].line not in route_lines
            or path.steps[-1].role != "SINK"
            or (path.steps[-1].path, path.steps[-1].line) != (sink.path, sink.line)
            or len(path.edge_ids) != len(path.steps) - 1
            or len(path.steps) < 4
            or not any(
                step.role == "REQUEST_CONTEXT"
                and (surface.line in route_lines or step.line == surface.line)
                for step in path.steps
            )
            or any(
                step.path != surface.path
                or step.source_sha256 != source_hashes.get(step.path)
                for step in path.steps
            )
        ):
            continue
        matched[sink.surface_id].append(path)
    if any(len(paths) != 1 for paths in matched.values()):
        return ()
    edges: list[dict[str, object]] = []
    for sink_id in sorted(matched):
        path = matched[sink_id][0]
        for edge_id, (first, second) in zip(
            path.edge_ids,
            zip(path.steps, path.steps[1:], strict=False),
            strict=True,
        ):
            edges.append(
                {
                    "path_id": path.path_id,
                    "sink_surface_id": sink_id,
                    "edge_id": edge_id,
                    "from_line": first.line,
                    "to_line": second.line,
                    "source_sha256": first.source_sha256,
                }
            )
    return tuple(edges)


def _literal_template_boundary(
    tree: ast.Module,
    route: ast.FunctionDef,
    surface: AttackSurface,
    workspace: Path,
    source_hash: str,
    commit_id: str,
) -> tuple[dict[str, object], ...]:
    if "render_template" in _function_local_bindings(route):
        return ()
    imports = [
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "flask"
    ]
    if (
        sum(
            alias.name == "render_template" and alias.asname is None
            for node in imports
            for alias in node.names
        )
        != 1
        or sum(
            alias.name == "Flask" and alias.asname is None
            for node in imports
            for alias in node.names
        )
        != 1
    ):
        return ()
    approved_import = next(
        node
        for node in imports
        if any(
            alias.name == "render_template" and alias.asname is None
            for alias in node.names
        )
    )
    approved_factory_import = next(
        node
        for node in imports
        if any(alias.name == "Flask" and alias.asname is None for alias in node.names)
    )
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }

    def module_scoped(node: ast.AST) -> bool:
        parent = parents.get(id(node))
        while parent is not None:
            if isinstance(
                parent,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
                return False
            parent = parents.get(id(parent))
        return True

    renderer_import_bindings = 0
    factory_import_bindings = 0
    if any(
        isinstance(node, ast.Name)
        and node.id == "__name__"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        or isinstance(node, (ast.Global, ast.Nonlocal))
        and "__name__" in node.names
        for node in ast.walk(tree)
    ):
        return ()
    for node in ast.walk(tree):
        if not module_scoped(node):
            continue
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                return ()
            for alias in node.names:
                if (alias.asname or alias.name) == "__name__":
                    return ()
                if (alias.asname or alias.name) == "Flask":
                    if node is not approved_factory_import or alias.asname is not None:
                        return ()
                    factory_import_bindings += 1
                if (alias.asname or alias.name) == "render_template":
                    if node is not approved_import or alias.asname is not None:
                        return ()
                    renderer_import_bindings += 1
        elif isinstance(node, ast.Import) and any(
            (alias.asname or alias.name.split(".")[0])
            in {"Flask", "render_template", "__name__"}
            for alias in node.names
        ):
            return ()
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in {"Flask", "render_template", "__name__"}:
                return ()
        elif isinstance(node, ast.Name) and node.id in {"Flask", "render_template"}:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                return ()
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name in {"Flask", "render_template", "__name__"}:
                return ()
        elif isinstance(node, ast.MatchMapping):
            if node.rest in {"Flask", "render_template", "__name__"}:
                return ()
        elif isinstance(node, ast.ExceptHandler):
            if node.name in {"Flask", "render_template", "__name__"}:
                return ()
    if renderer_import_bindings != 1 or factory_import_bindings != 1:
        return ()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            app_root = node.value
            while isinstance(app_root, ast.Attribute):
                app_root = app_root.value
            if (
                isinstance(app_root, ast.Name)
                and app_root.id == "app"
                and node.attr
                in {"jinja_loader", "jinja_env", "template_folder", "root_path"}
            ):
                return ()
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "app"
        ):
            return ()
    app_assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "app"
            for target in node.targets
        )
    ]
    if len(app_assignments) != 1:
        return ()
    app_factory = app_assignments[0].value
    if not (
        isinstance(app_factory, ast.Call)
        and isinstance(app_factory.func, ast.Name)
        and app_factory.func.id == "Flask"
        and len(app_factory.args) == 1
        and isinstance(app_factory.args[0], ast.Name)
        and app_factory.args[0].id == "__name__"
        and not any(
            keyword.arg in {"template_folder", "root_path"} or keyword.arg is None
            for keyword in app_factory.keywords
        )
    ):
        return ()
    body = [
        node
        for node in route.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return ()
    returned = body[0].value
    if (
        not isinstance(returned, ast.Call)
        or not isinstance(returned.func, ast.Name)
        or returned.func.id != "render_template"
        or len(returned.args) != 1
        or not isinstance(returned.args[0], ast.Constant)
        or not isinstance(returned.args[0].value, str)
        or returned.keywords
    ):
        return ()
    template_name = returned.args[0].value
    if (
        not template_name
        or "\\" in template_name
        or template_name.startswith("/")
        or any(part in {"", ".", ".."} for part in template_name.split("/"))
    ):
        return ()
    relative = Path(surface.path).parent / "templates" / template_name
    workspace_root = workspace.resolve()
    target = workspace / relative
    try:
        if (
            relative.is_absolute()
            or any(part == ".." for part in relative.parts)
            or any(
                workspace.joinpath(*relative.parts[:depth]).is_symlink()
                for depth in range(1, len(relative.parts) + 1)
            )
            or not target.is_file()
            or not target.resolve().is_relative_to(workspace_root)
        ):
            return ()
        raw = target.read_bytes()
        if len(raw) > 1024 * 1024:
            return ()
        saved = subprocess.run(
            ["git", "-C", str(workspace), "show", f"{commit_id}:{relative.as_posix()}"],
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        if raw != saved:
            return ()
    except (OSError, ValueError, subprocess.SubprocessError):
        return ()
    return (
        {
            "path_id": f"python-template:{surface.surface_id}",
            "from_line": surface.line,
            "to_line": returned.lineno,
            "source_sha256": source_hash,
            "template_path": relative.as_posix(),
            "template_sha256": hashlib.sha256(raw).hexdigest(),
        },
    )


def _unrelated_same_file_sinks(
    index: SurfaceIndex,
    surface: AttackSurface,
    tree: ast.Module,
    reachable: set[str],
) -> bool:
    sinks = [
        row
        for row in index.surfaces
        if row.surface_id != surface.surface_id
        and row.path == surface.path
        and surface_review_contract(row.type) == "SINK"
    ]
    if not sinks:
        return False
    for sink in sinks:
        owner = _enclosing_function(tree, sink.line)
        if owner is None or owner.name in reachable:
            return False
    return True


def _certificate_gap_events(
    surface: AttackSurface,
    graph: Mapping[str, object],
    certificate: PathCertificateV9,
) -> tuple[dict[str, object], ...]:
    """Account for every still-relevant v9 gap, including certificate-only gaps."""

    raw = graph.get("gap_events")
    events = raw if isinstance(raw, list) else []
    result: list[dict[str, object]] = []
    for reason in certificate.unresolved_gap_codes:
        matching = [
            (ordinal, event)
            for ordinal, event in enumerate(events)
            if isinstance(event, dict) and event.get("reason") == reason
        ]
        if matching:
            result.extend(
                {
                    **event,
                    "event_ordinal": ordinal,
                    "ambiguous_event_count": len(matching),
                }
                for ordinal, event in matching
            )
        else:
            result.append(
                {
                    "path": surface.path,
                    "reason": reason,
                    "attribution": "PATH_CERTIFICATE",
                    "event_ordinal": None,
                    "ambiguous_event_count": 0,
                }
            )
    return tuple(result)


def _dischargeable_event(
    event: Mapping[str, object], surface: AttackSurface, boundary: str
) -> bool:
    reason = event.get("reason")
    if event.get("path") != surface.path:
        return False
    if event.get("ambiguous_event_count") == 1:
        return event.get("attribution") == "UNLOCATED" and (
            reason == "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"
            and boundary
            in {"PYTHON_RESPONSE", "LITERAL_TEMPLATE", "PINNED_PYTHON_SINK"}
            or reason
            in {
                "EXTERNAL_IMPLEMENTATION_UNAVAILABLE",
                "SINK_ENCLOSING_FUNCTION_UNAVAILABLE",
            }
            and boundary in {"PYTHON_RESPONSE", "LITERAL_TEMPLATE"}
        )
    return (
        event.get("ambiguous_event_count") == 0
        and event.get("attribution") == "PATH_CERTIFICATE"
        and (
            (reason == "DOWNSTREAM_SINK_NOT_PROVEN" and boundary == "LITERAL_TEMPLATE")
            or (
                reason == "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"
                and boundary in {"PYTHON_RESPONSE", "PINNED_PYTHON_SINK"}
            )
        )
    )


def prove_route_boundaries_v10(
    index: SurfaceIndex,
    workspace: Path,
    graphs: Mapping[str, Mapping[str, object]],
    v9_paths: Mapping[str, PathCertificateV9],
) -> dict[str, RouteBoundaryProofV10]:
    """Prove route-local Python edges; leave every ambiguous gap unresolved."""

    _, trees = _source_and_tree(index, workspace)
    applicability = assess_optional_analyzers(index, workspace)
    result: dict[str, RouteBoundaryProofV10] = {}
    for surface in index.surfaces:
        reasons: set[str] = set()
        edges: tuple[dict[str, object], ...] = ()
        discharged: tuple[dict[str, object], ...] = ()
        remaining: tuple[dict[str, object], ...] = ()
        boundary = "NONE"
        graph = graphs.get(surface.surface_id)
        certificate = v9_paths.get(surface.surface_id)
        tree = trees.get(surface.path)
        if graph is not None and certificate is not None:
            remaining = _certificate_gap_events(surface, graph, certificate)
        if surface.type != "REQUEST_ENTRY":
            reasons.add("NOT_REQUEST_ENTRY")
        elif graph is None or certificate is None or tree is None:
            reasons.add("ROUTE_EVIDENCE_MISSING")
        elif not validate_path_certificate(
            index, surface, graph, applicability, workspace, certificate
        ):
            reasons.add("V9_PATH_INVALID")
        else:
            route = _route_function(tree, surface)
            functions = _direct_functions(tree)
            if route is None or functions is None or route.name not in functions:
                reasons.add("ROUTE_BINDING_UNPROVEN")
            else:
                pinned_sql_sinks = {
                    path.sink_surface_id: path.steps[-1].line
                    for path in certificate.downstream_paths
                    if path.kind == "call_path_v1"
                    and path.steps
                    and path.steps[-1].role == "SINK"
                }
                indexed_sql_lines = frozenset(
                    row.line
                    for row in index.surfaces
                    if row.path == surface.path
                    and row.type == "SQL_EXECUTION"
                    and pinned_sql_sinks.get(row.surface_id) == row.line
                )
                reachable = _called_local_functions(
                    tree, route, functions, indexed_sql_lines
                )
                if reachable is None:
                    reasons.add("ROUTE_CALL_GRAPH_OPEN")
                else:
                    edges = _response_path(certificate, surface, route)
                    if edges:
                        boundary = "PYTHON_RESPONSE"
                    if not edges:
                        edges = _literal_template_boundary(
                            tree,
                            route,
                            surface,
                            workspace,
                            dict(index.ast_source_hashes)[surface.path],
                            index.commit_id,
                        )
                        if edges:
                            boundary = "LITERAL_TEMPLATE"
                    if not edges:
                        edges = _indexed_sink_paths(
                            index,
                            surface,
                            tree,
                            route,
                            functions,
                            reachable,
                            certificate,
                        )
                        if edges:
                            boundary = "PINNED_PYTHON_SINK"
                    if edges:
                        if (
                            boundary == "PINNED_PYTHON_SINK"
                            or _unrelated_same_file_sinks(
                                index, surface, tree, reachable
                            )
                        ):
                            discharged = tuple(
                                {
                                    **event,
                                    "proof_kind": (
                                        "PINNED_LINEAR_PYTHON_RESPONSE"
                                        if boundary == "PYTHON_RESPONSE"
                                        else "PINNED_LITERAL_TEMPLATE_HANDOFF"
                                        if boundary == "LITERAL_TEMPLATE"
                                        else "PINNED_PYTHON_SINK_CALL"
                                    ),
                                }
                                for event in remaining
                                if _dischargeable_event(event, surface, boundary)
                            )
                            discharged_ids = {
                                (event["reason"], event["event_ordinal"])
                                for event in discharged
                            }
                            remaining = tuple(
                                event
                                for event in remaining
                                if (event["reason"], event["event_ordinal"])
                                not in discharged_ids
                            )
                    else:
                        reasons.add("RESPONSE_PATH_UNPROVEN")
        result[surface.surface_id] = RouteBoundaryProofV10(
            surface_id=surface.surface_id,
            source_hashes=index.ast_source_hashes,
            resolved_edges=edges,
            discharged_gap_events=discharged,
            remaining_gap_events=remaining,
            boundary_kind=boundary,
            external_scope_limit=(
                "TEMPLATE_CONTENT_NOT_ANALYZED"
                if boundary == "LITERAL_TEMPLATE"
                else None
            ),
            unresolved_reasons=tuple(sorted(reasons)),
            expected_v9_path_ids=(
                certificate.path_ids if certificate is not None else ()
            ),
            unresolved_v9_path_ids=(
                certificate.unresolved_path_ids if certificate is not None else ()
            ),
            resolved_v9_path_ids=tuple(
                sorted(
                    {
                        path_id
                        for edge in edges
                        if isinstance((path_id := edge.get("path_id")), str)
                    }
                    & (set(certificate.path_ids) if certificate is not None else set())
                )
            ),
            expected_v9_part_count=(
                len(certificate.context_parts) if certificate is not None else 0
            ),
        )
    return result
