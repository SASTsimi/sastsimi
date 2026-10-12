"""Pinned v5 navigation graph for one surface.

HTTP edges are bounded Python syntax reachability, not taint or a verdict.
Operational XML is a separate route/class fact and never supplies a dispatch
edge without a Python invocation path to the sink. Unresolved dispatch is a
first-class graph gap.
"""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import cast

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import AttackSurface, SurfaceIndex
from .call_path_facts import PythonCallPathIndex
from .file_context import prepare_file_context
from .http_route_facts_v5 import verified_http_paths
from .operational_config_v5 import (
    OperationalRouteBinding,
    OperationalRouteMap,
    _assignments,
    _final_stage_directives,
    _findtext,
    _Gap,
    _getattr_binding,
    _imported_modules,
    _launched_path,
    _parser_shape,
    _verified_blob,
    load_operational_routes,
)
from .surface_evidence_graph_v4 import (
    _MAX_ATOMIC_LINE_BYTES,
    _id,
    _raw_source,
    extract_surface_graph_v4,
)

_REPLACEABLE_GAPS = frozenset(
    {"EXTERNAL_IMPLEMENTATION_UNAVAILABLE", "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"}
)
_MAX_PARSER_BYTES = 256 * 1024
_MAX_LAUNCHER_BYTES = 32 * 1024
_ROUTE_VERIFICATION_TOKEN = object()
_HTTP_MODULE_SHADOW_NAMES = ("http.py", "http.pyc", "http.so", "http.pyd")


@lru_cache(maxsize=64)
def _pinned_http_shadow_paths(workspace: str, commit_id: str) -> frozenset[str] | None:
    """Find import-shadowing paths in the immutable pinned tree, not just AST files."""

    try:
        result = subprocess.run(
            ("git", "-C", workspace, "ls-tree", "-r", "-z", "--name-only", commit_id),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    shadows: set[str] = set()
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        parts = raw.decode("utf-8", "surrogateescape").split("/")
        for position, part in enumerate(parts):
            if part == "http":
                shadows.add("/".join(parts[: position + 1]))
        if parts[-1] in _HTTP_MODULE_SHADOW_NAMES:
            shadows.add("/".join(parts))
    return frozenset(shadows)


def _stdlib_http_shadow_absent(
    workspace: Path, commit_id: str, *module_paths: str
) -> bool:
    """Only trust stdlib HTTP imports when relevant checkout and commit paths agree."""

    pinned = _pinned_http_shadow_paths(str(workspace.resolve()), commit_id)
    if pinned is None:
        return False
    directories = {PurePosixPath(".")}
    for module_path in module_paths:
        if (
            not module_path
            or "\\" in module_path
            or module_path.startswith("/")
            or any(part in {"", ".", ".."} for part in module_path.split("/"))
        ):
            return False
        directories.add(PurePosixPath(module_path).parent)
    for directory in directories:
        prefix = "" if directory == PurePosixPath(".") else f"{directory.as_posix()}/"
        candidates = (f"{prefix}http",) + tuple(
            f"{prefix}{name}" for name in _HTTP_MODULE_SHADOW_NAMES
        )
        if any(
            candidate in pinned or os.path.lexists(workspace / candidate)
            for candidate in candidates
        ):
            return False
    return True


class VerifiedOperationalRoutes:
    """Immutable, in-process proof for one index, checkout, and route map.

    This is not a saved artifact. Graph extraction still rechecks each relevant
    checkout blob against its pinned commit, so later source mutation fails closed.
    """

    __slots__ = ("_index", "_workspace", "_route_map", "_class_spans")
    _index: SurfaceIndex
    _workspace: Path
    _route_map: OperationalRouteMap
    _class_spans: Mapping[OperationalRouteBinding, tuple[int, int] | None]

    def __init__(
        self,
        index: SurfaceIndex,
        workspace: Path,
        route_map: OperationalRouteMap,
        class_spans: Mapping[OperationalRouteBinding, tuple[int, int] | None],
        *,
        _token: object,
    ) -> None:
        if _token is not _ROUTE_VERIFICATION_TOKEN:
            raise TypeError("verified routes must be built from pinned sources")
        object.__setattr__(self, "_index", index)
        object.__setattr__(self, "_workspace", workspace)
        object.__setattr__(self, "_route_map", route_map)
        object.__setattr__(self, "_class_spans", MappingProxyType(dict(class_spans)))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("verified routes are immutable")

    def _for_surface(
        self,
        index: SurfaceIndex,
        surface: AttackSurface,
        workspace: Path,
        route_map: OperationalRouteMap,
    ) -> Mapping[OperationalRouteBinding, bool]:
        if (
            self._index != index
            or self._workspace != workspace.resolve()
            or self._route_map != route_map
            or surface not in index.surfaces
        ):
            raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
        matching = tuple(
            binding
            for binding in route_map.bindings
            if binding.target_path == surface.path
        )
        checked: set[tuple[str, int]] = set()
        for binding in matching:
            if binding not in self._class_spans:
                raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
            for path, expected, limit in _binding_source_specs(binding):
                key = (path, limit)
                if key in checked:
                    continue
                try:
                    _, actual = _verified_blob(workspace, index.commit_id, path, limit)
                except _Gap as error:
                    raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH") from error
                if actual != expected:
                    raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
                checked.add(key)
        return MappingProxyType(
            {
                binding: span is not None and span[0] <= surface.line <= span[1]
                for binding in matching
                if (span := self._class_spans[binding]) is not None
            }
        )


def _binding_source_specs(
    binding: OperationalRouteBinding,
) -> tuple[tuple[str, str, int], ...]:
    return (
        (binding.parser_path, binding.parser_sha256, _MAX_PARSER_BYTES),
        (binding.launcher_path, binding.launcher_sha256, _MAX_LAUNCHER_BYTES),
        (binding.config_path, binding.config_sha256, 131072),
        (binding.target_path, binding.target_sha256, _MAX_PARSER_BYTES),
    )


def verify_operational_routes_v5(
    index: SurfaceIndex,
    workspace: Path,
    route_map: OperationalRouteMap,
) -> VerifiedOperationalRoutes:
    """Re-derive all indexed route bindings once for reuse across a v5 plan."""

    source_hashes = dict(index.ast_source_hashes)
    target_paths = {surface.path for surface in index.surfaces}
    relevant = tuple(
        binding for binding in route_map.bindings if binding.target_path in target_paths
    )
    blobs: dict[tuple[str, int], bytes] = {}
    loaders: dict[tuple[str, str, str], OperationalRouteMap] = {}
    target_trees: dict[str, ast.Module] = {}
    spans: dict[OperationalRouteBinding, tuple[int, int] | None] = {}
    for binding in relevant:
        if (
            source_hashes.get(binding.target_path) != binding.target_sha256
            or source_hashes.get(binding.parser_path) != binding.parser_sha256
        ):
            raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
        for path, expected, limit in _binding_source_specs(binding):
            key = (path, limit)
            if key not in blobs:
                try:
                    raw, actual = _verified_blob(
                        workspace, index.commit_id, path, limit
                    )
                except _Gap as error:
                    raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH") from error
                if actual != expected:
                    raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
                blobs[key] = raw
            elif hashlib.sha256(blobs[key]).hexdigest() != expected:
                raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
        launcher_raw = blobs[(binding.launcher_path, _MAX_LAUNCHER_BYTES)]
        try:
            workdirs = [
                line.split(None, 1)[1].strip()
                for line in launcher_raw.decode("utf-8").splitlines()
                if line.strip().upper().startswith("WORKDIR ")
            ]
            if len(workdirs) != 1:
                raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
            if binding.target_path not in target_trees:
                target_trees[binding.target_path] = ast.parse(
                    blobs[(binding.target_path, _MAX_PARSER_BYTES)].decode("utf-8"),
                    filename=binding.target_path,
                )
        except (UnicodeError, SyntaxError, IndexError) as error:
            raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH") from error
        loader_key = (binding.parser_path, binding.launcher_path, workdirs[0])
        if loader_key not in loaders:
            loaders[loader_key] = load_operational_routes(
                workspace,
                index.commit_id,
                binding.parser_path,
                blobs[(binding.parser_path, _MAX_PARSER_BYTES)],
                binding.launcher_path,
                runtime_workdir=workdirs[0],
            )
        if binding not in loaders[loader_key].bindings:
            raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
        matching = [
            node
            for node in target_trees[binding.target_path].body
            if isinstance(node, ast.ClassDef) and node.name == binding.class_symbol
        ]
        spans[binding] = (
            (matching[0].lineno, matching[0].end_lineno or 0)
            if len(matching) == 1
            else None
        )
    return VerifiedOperationalRoutes(
        index, workspace.resolve(), route_map, spans, _token=_ROUTE_VERIFICATION_TOKEN
    )


def _operational_binding_verified(
    index: SurfaceIndex,
    surface: AttackSurface,
    workspace: Path,
    binding: OperationalRouteBinding,
    source_hashes: Mapping[str, str],
) -> bool:
    """Re-derive the binding at the pinned commit; a supplied map is not proof."""

    if binding.target_path != surface.path:
        return False
    if (
        source_hashes.get(binding.target_path) != binding.target_sha256
        or source_hashes.get(binding.parser_path) != binding.parser_sha256
    ):
        raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
    try:
        parser_raw, parser_hash = _verified_blob(
            workspace, index.commit_id, binding.parser_path, _MAX_PARSER_BYTES
        )
        launcher_raw, launcher_hash = _verified_blob(
            workspace, index.commit_id, binding.launcher_path, _MAX_LAUNCHER_BYTES
        )
        _config_raw, config_hash = _verified_blob(
            workspace, index.commit_id, binding.config_path, 131072
        )
        target_raw, target_hash = _verified_blob(
            workspace, index.commit_id, binding.target_path, _MAX_PARSER_BYTES
        )
    except _Gap as error:
        raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH") from error
    if (
        parser_hash != binding.parser_sha256
        or launcher_hash != binding.launcher_sha256
        or config_hash != binding.config_sha256
        or target_hash != binding.target_sha256
    ):
        raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
    try:
        launcher_lines = launcher_raw.decode("utf-8").splitlines()
        workdirs = [
            line.split(None, 1)[1].strip()
            for line in launcher_lines
            if line.strip().upper().startswith("WORKDIR ")
        ]
        tree = ast.parse(target_raw.decode("utf-8"), filename=binding.target_path)
    except (UnicodeError, SyntaxError, IndexError) as error:
        raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH") from error
    if len(workdirs) != 1:
        raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
    rebuilt = load_operational_routes(
        workspace,
        index.commit_id,
        binding.parser_path,
        parser_raw,
        binding.launcher_path,
        runtime_workdir=workdirs[0],
    )
    if binding not in rebuilt.bindings:
        raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
    matching = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == binding.class_symbol
    ]
    return len(matching) == 1 and (
        matching[0].lineno <= surface.line <= (matching[0].end_lineno or 0)
    )


def _add_http_source_lines(
    graph: dict[str, object],
    locations: set[tuple[str, int]],
    index: SurfaceIndex,
    ast_summary: Mapping[str, object],
    manifest_index: Mapping[str, Mapping[str, object]],
    workspace: Path,
    artifacts: SimpleArtifactRepository,
) -> bool:
    """Add only redacted, indexed, exact step lines absent from the v4 graph."""

    files = cast(list[dict[str, object]], graph["source_files"])
    lines = cast(list[dict[str, object]], graph["source_lines"])
    existing_files = {cast(str, row["path"]) for row in files}
    existing_lines = {(cast(str, row["path"]), cast(int, row["line"])) for row in lines}
    source_hashes = dict(index.ast_source_hashes)
    for path in sorted({path for path, _ in locations}):
        expected = source_hashes.get(path)
        if expected is None or path not in manifest_index:
            return False
        prepared = prepare_file_context(
            artifacts,
            ast_summary,
            workspace,
            path,
            manifest_index=manifest_index,
        )
        if (
            prepared.source_unavailable_reason is not None
            or prepared.ast_unavailable_reason is not None
            or prepared.ast_file_ref is None
            or prepared.source_sha256 != expected
        ):
            return False
        _raw_source(workspace, path, expected)
        additions: list[dict[str, object]] = []
        for _, line in sorted(
            location for location in locations if location[0] == path
        ):
            if (path, line) in existing_lines:
                continue
            if line < 1 or line > len(prepared.source_lines):
                return False
            content = prepared.source_lines[line - 1]
            if len(content.encode("utf-8")) > _MAX_ATOMIC_LINE_BYTES:
                return False
            additions.append(
                {
                    "line_id": _id("line", (path, line, expected)),
                    "path": path,
                    "line": line,
                    "text": content,
                    "source_sha256": expected,
                }
            )
        if path not in existing_files:
            files.append(
                {
                    "path": path,
                    "source_sha256": expected,
                    "ast_ref": prepared.ast_file_ref.model_dump(mode="json"),
                    "ast_sha256": prepared.ast_file_ref.content_hash,
                    "redaction_categories": list(prepared.redaction_categories),
                }
            )
            existing_files.add(path)
        lines.extend(additions)
        existing_lines.update((path, cast(int, row["line"])) for row in additions)
    return True


def _single_assignment(statement: ast.stmt) -> tuple[str, ast.expr] | None:
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
    ):
        return None
    return statement.targets[0].id, statement.value


def _plain_function_header(node: ast.FunctionDef) -> bool:
    """Exclude definitions whose header can execute arbitrary import-time code."""

    arguments = node.args
    parameters = (
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
    )
    return not (
        node.decorator_list
        or node.returns is not None
        or node.type_params
        or arguments.defaults
        or any(default is not None for default in arguments.kw_defaults)
        or any(argument.annotation is not None for argument in parameters)
        or arguments.vararg is not None
        and arguments.vararg.annotation is not None
        or arguments.kwarg is not None
        and arguments.kwarg.annotation is not None
    )


def _plain_package_initializers(
    index: SurfaceIndex, workspace: Path, *module_paths: str
) -> bool:
    """Require every imported package initializer to be pinned and empty."""

    source_hashes = dict(index.ast_source_hashes)
    paths = {
        "/".join((*module_path.split("/")[:depth], "__init__.py"))
        for module_path in module_paths
        for depth in range(1, len(module_path.split("/")))
    }
    for path in sorted(paths):
        expected = source_hashes.get(path)
        if expected is None:
            return False
        try:
            raw, actual = _verified_blob(workspace, index.commit_id, path, 1)
        except _Gap:
            return False
        if actual != expected:
            raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
        if raw:
            return False
    return True


def _direct_operational_xml_path(
    index: SurfaceIndex,
    surface: AttackSurface,
    workspace: Path,
    binding: OperationalRouteBinding,
) -> dict[str, object] | None:
    """Prove only a literal list lookup and same-module HTTP invocation chain.

    The operational route map proves the XML selection; these extra syntax
    checks prove that the selected class is actually called with request input.
    Other dispatch idioms deliberately remain unresolved.
    """

    if not _stdlib_http_shadow_absent(
        workspace,
        index.commit_id,
        binding.parser_path,
        binding.target_path,
        binding.launcher_path,
    ):
        return None
    parser_raw, parser_digest = _verified_blob(
        workspace, index.commit_id, binding.parser_path, _MAX_PARSER_BYTES
    )
    launcher_raw, launcher_digest = _verified_blob(
        workspace, index.commit_id, binding.launcher_path, _MAX_LAUNCHER_BYTES
    )
    target_raw, target_digest = _verified_blob(
        workspace, index.commit_id, binding.target_path, _MAX_PARSER_BYTES
    )
    if (
        parser_digest != binding.parser_sha256
        or launcher_digest != binding.launcher_sha256
        or target_digest != binding.target_sha256
    ):
        raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
    if not _plain_package_initializers(
        index, workspace, binding.parser_path, binding.target_path
    ):
        return None
    try:
        workdirs = _final_stage_directives(
            launcher_raw, decode_gap="LAUNCHER_ENTRYPOINT_UNPROVEN"
        ).get("WORKDIR", [])
        if (
            len(workdirs) != 1
            or _launched_path(launcher_raw, workdirs[0], workspace, index.commit_id)
            != binding.parser_path
        ):
            return None
    except _Gap:
        return None
    try:
        (
            parser_tree,
            module_path,
            config_path,
            _selector,
            class_tag,
            route_tag,
            parser_sites,
            function_name,
        ) = _parser_shape(parser_raw, binding.parser_path)
        target_tree = ast.parse(
            target_raw.decode("utf-8"), filename=binding.target_path
        )
    except (_Gap, SyntaxError, UnicodeError):
        return None
    if (
        module_path != binding.module_path
        or config_path != binding.config_path
        or parser_sites != binding.parser_sites
        or function_name is None
    ):
        return None
    functions = [
        node
        for node in parser_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    ]
    if len(functions) != 1:
        return None
    function = functions[0]
    if (
        not _plain_function_header(function)
        or function.args.posonlyargs
        or len(function.args.args) != 1
        or function.args.vararg is not None
        or function.args.kwarg is not None
        or function.args.kwonlyargs
        or len(function.body) != 4
    ):
        return None
    request_name = function.args.args[0].arg
    rows_assignment = _single_assignment(function.body[0])
    routes_assignment = _single_assignment(function.body[1])
    if rows_assignment is None or routes_assignment is None:
        return None
    rows_name, rows_value = rows_assignment
    routes_name, routes_value = routes_assignment
    if (
        len({request_name, rows_name, routes_name}) != 3
        or not isinstance(rows_value, ast.Call)
        or not isinstance(rows_value.func, ast.Attribute)
        or rows_value.func.attr != "findall"
        or not isinstance(routes_value, ast.List)
        or routes_value.elts
        or rows_value.lineno not in parser_sites
    ):
        return None
    mapping_loop, dispatch_loop = function.body[2:]
    if (
        not isinstance(mapping_loop, ast.For)
        or not isinstance(mapping_loop.target, ast.Name)
        or not isinstance(mapping_loop.iter, ast.Name)
        or mapping_loop.iter.id != rows_name
        or mapping_loop.orelse
        or len(mapping_loop.body) != 4
        or mapping_loop.lineno not in parser_sites
        or not isinstance(dispatch_loop, ast.For)
        or not isinstance(dispatch_loop.iter, ast.Name)
        or dispatch_loop.iter.id != routes_name
        or not isinstance(dispatch_loop.target, ast.Tuple)
        or len(dispatch_loop.target.elts) != 2
        or dispatch_loop.orelse
        or len(dispatch_loop.body) != 1
    ):
        return None
    local_names: list[str] = []
    for statement in mapping_loop.body[:3]:
        assigned = _single_assignment(statement)
        if assigned is None:
            return None
        local_names.append(assigned[0])
    if len(set(local_names + [mapping_loop.target.id, request_name])) != 5 or {
        rows_name,
        routes_name,
    }.intersection(local_names):
        return None
    appended = mapping_loop.body[3]
    if not (
        isinstance(appended, ast.Expr)
        and isinstance(appended.value, ast.Call)
        and isinstance(appended.value.func, ast.Attribute)
        and isinstance(appended.value.func.value, ast.Name)
        and appended.value.func.value.id == routes_name
        and appended.value.func.attr == "append"
        and len(appended.value.args) == 1
        and not appended.value.keywords
        and isinstance(appended.value.args[0], ast.Tuple)
        and len(appended.value.args[0].elts) == 2
        and appended.lineno in parser_sites
    ):
        return None
    appended_names = [
        element.id if isinstance(element, ast.Name) else None
        for element in appended.value.args[0].elts
    ]
    loop_names = [
        element.id if isinstance(element, ast.Name) else None
        for element in dispatch_loop.target.elts
    ]
    if (
        any(name is None for name in appended_names + loop_names)
        or len(set(appended_names)) != 2
        or len(set(loop_names)) != 2
        or {request_name, rows_name, routes_name}.intersection(loop_names)
    ):
        return None
    try:
        local = _assignments(mapping_loop.body)
    except _Gap:
        return None
    imports = _imported_modules(parser_tree)
    route_positions: list[int] = []
    for position, name in enumerate(appended_names):
        if name is None:
            continue
        found = _findtext(
            ast.Name(id=name, ctx=ast.Load()), mapping_loop.target.id, local
        )
        if found is not None and found[0] == route_tag:
            route_positions.append(position)
    if len(route_positions) != 1:
        return None
    route_position = route_positions[0]
    handler_position = 1 - route_position
    handler_name = appended_names[handler_position]
    if handler_name is None or handler_name not in local:
        return None
    resolved = _getattr_binding(
        ast.Name(id=handler_name, ctx=ast.Load()),
        mapping_loop.target.id,
        local,
        imports,
    )
    if resolved is None or resolved[:2] != (binding.module_path, class_tag):
        return None
    route_name = loop_names[route_position]
    handler_loop_name = loop_names[handler_position]
    branch = dispatch_loop.body[0]
    if not (
        isinstance(branch, ast.If)
        and not branch.orelse
        and len(branch.body) == 1
        and isinstance(branch.test, ast.Compare)
        and len(branch.test.ops) == 1
        and isinstance(branch.test.ops[0], ast.Eq)
        and len(branch.test.comparators) == 1
        and isinstance(branch.test.left, ast.Name)
        and isinstance(branch.test.comparators[0], ast.Name)
        and {
            branch.test.left.id,
            branch.test.comparators[0].id,
        }
        == {route_name, request_name}
        and isinstance(branch.body[0], ast.Expr)
        and isinstance(branch.body[0].value, ast.Call)
    ):
        return None
    invocation = branch.body[0].value
    if not (
        isinstance(invocation.func, ast.Attribute)
        and isinstance(invocation.func.value, ast.Call)
        and isinstance(invocation.func.value.func, ast.Name)
        and invocation.func.value.func.id == handler_loop_name
        and not invocation.func.value.args
        and not invocation.func.value.keywords
        and len(invocation.args) == 1
        and isinstance(invocation.args[0], ast.Name)
        and invocation.args[0].id == request_name
        and not invocation.keywords
    ):
        return None
    method_name = invocation.func.attr
    imports_http = [
        node
        for node in parser_tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "http.server"
        and node.level == 0
        for alias in node.names
        if alias.name == "BaseHTTPRequestHandler" and alias.asname is None
    ]
    imports_server = [
        node
        for node in parser_tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "http.server"
        and node.level == 0
        for alias in node.names
        if alias.name == "HTTPServer" and alias.asname is None
    ]
    handlers = [
        node
        for node in parser_tree.body
        if isinstance(node, ast.ClassDef)
        and len(node.bases) == 1
        and isinstance(node.bases[0], ast.Name)
        and node.bases[0].id == "BaseHTTPRequestHandler"
        and not node.decorator_list
        and not node.keywords
        and not node.type_params
        and len(node.body) == 1
    ]
    if len(imports_http) != 1 or len(imports_server) != 1 or len(handlers) != 1:
        return None
    handler_class = handlers[0]
    if handler_class.name in {
        function_name,
        "BaseHTTPRequestHandler",
        "HTTPServer",
    }:
        return None
    definitions = [
        node
        for node in parser_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    if (
        [node for node in definitions if node.name == function_name] != [function]
        or [node for node in definitions if node.name == handler_class.name]
        != [handler_class]
        or any(
            node.name in {"BaseHTTPRequestHandler", "HTTPServer"}
            for node in definitions
        )
    ):
        return None
    important_imports: dict[str, list[ast.stmt]] = {
        "BaseHTTPRequestHandler": [],
        "HTTPServer": [],
        handler_class.name: [],
    }
    for statement in parser_tree.body:
        if isinstance(statement, ast.Import):
            bound_names = [
                alias.asname or alias.name.partition(".")[0]
                for alias in statement.names
            ]
        elif isinstance(statement, ast.ImportFrom):
            bound_names = [alias.asname or alias.name for alias in statement.names]
        else:
            continue
        if function_name in bound_names:
            return None
        for name in bound_names:
            if name in important_imports:
                important_imports[name].append(statement)
    if (
        important_imports["BaseHTTPRequestHandler"] != imports_http
        or important_imports["HTTPServer"] != imports_server
        or important_imports[handler_class.name]
    ):
        return None
    if any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id
        in {function_name, "BaseHTTPRequestHandler", "HTTPServer", handler_class.name}
        for statement in parser_tree.body
        for node in ast.walk(statement)
    ):
        return None
    main_guards = [
        node
        for node in parser_tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Eq)
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "__main__"
    ]
    if len(main_guards) != 1 or main_guards[0].orelse or len(main_guards[0].body) != 2:
        return None

    # The main guard is a runtime entry only when executing this parser. Do not
    # silently trust another top-level statement/import that could change cwd,
    # rebind the imported symbols, or prevent the HTTP server from starting.
    def permitted_import(statement: ast.stmt) -> bool:
        if isinstance(statement, ast.Import):
            return bool(statement.names) and all(
                alias.name in {"xml.etree.ElementTree", binding.module_path}
                for alias in statement.names
            )
        if isinstance(statement, ast.ImportFrom) and statement.level == 0:
            allowed = {
                "http.server": {"BaseHTTPRequestHandler", "HTTPServer"},
                "xml.etree": {"ElementTree"},
                "xml.etree.ElementTree": {"parse"},
            }
            return bool(statement.names) and all(
                alias.name in allowed.get(statement.module or "", set())
                for alias in statement.names
            )
        return False

    main_guard = main_guards[0]
    if (
        parser_tree.body[-1] is not main_guard
        or function.lineno >= main_guard.lineno
        or handler_class.lineno >= main_guard.lineno
        or any(
            statement is not function
            and statement is not handler_class
            and statement is not main_guard
            and (
                statement.lineno >= main_guard.lineno or not permitted_import(statement)
            )
            for statement in parser_tree.body
        )
    ):
        return None
    main_call, server_statement = main_guards[0].body
    if not (
        isinstance(main_call, ast.Expr)
        and isinstance(main_call.value, ast.Call)
        and isinstance(main_call.value.func, ast.Name)
        and main_call.value.func.id == function_name
        and len(main_call.value.args) == 1
        and isinstance(main_call.value.args[0], ast.Constant)
        and main_call.value.args[0].value == ""
        and not main_call.value.keywords
        and isinstance(server_statement, ast.Expr)
        and isinstance(server_statement.value, ast.Call)
        and isinstance(server_statement.value.func, ast.Attribute)
        and server_statement.value.func.attr == "serve_forever"
        and not server_statement.value.args
        and not server_statement.value.keywords
        and isinstance(server_statement.value.func.value, ast.Call)
    ):
        return None
    server_constructor = server_statement.value.func.value
    if not (
        isinstance(server_constructor.func, ast.Name)
        and server_constructor.func.id == "HTTPServer"
        and len(server_constructor.args) == 2
        and not server_constructor.keywords
        and isinstance(server_constructor.args[0], ast.Tuple)
        and len(server_constructor.args[0].elts) == 2
        and isinstance(server_constructor.args[0].elts[0], ast.Constant)
        and isinstance(server_constructor.args[0].elts[0].value, str)
        and isinstance(server_constructor.args[0].elts[1], ast.Constant)
        and type(server_constructor.args[0].elts[1].value) is int
        and isinstance(server_constructor.args[1], ast.Name)
        and server_constructor.args[1].id == handler_class.name
    ):
        return None
    entry = handler_class.body[0]
    if not (
        isinstance(entry, ast.FunctionDef)
        and entry.name.startswith("do_")
        and _plain_function_header(entry)
        and len(entry.args.args) == 1
        and not entry.args.posonlyargs
        and not entry.args.kwonlyargs
        and entry.args.vararg is None
        and entry.args.kwarg is None
        and len(entry.body) == 1
        and isinstance(entry.body[0], ast.Expr)
        and isinstance(entry.body[0].value, ast.Call)
    ):
        return None
    request_call = entry.body[0].value
    receiver = entry.args.args[0].arg
    if not (
        isinstance(request_call.func, ast.Name)
        and request_call.func.id == function_name
        and len(request_call.args) == 1
        and not request_call.keywords
        and isinstance(request_call.args[0], ast.Attribute)
        and isinstance(request_call.args[0].value, ast.Name)
        and request_call.args[0].value.id == receiver
        and request_call.args[0].attr == "path"
    ):
        return None
    target_classes = [
        node
        for node in target_tree.body
        if isinstance(node, ast.ClassDef) and node.name == binding.class_symbol
    ]
    if (
        len(target_classes) != 1
        or len(target_tree.body) != 1
        or target_classes[0].decorator_list
        or target_classes[0].bases
        or target_classes[0].keywords
        or target_classes[0].type_params
        or len(target_classes[0].body) != 1
    ):
        return None
    target_methods = [
        node
        for node in target_classes[0].body
        if isinstance(node, ast.FunctionDef) and node.name == method_name
    ]
    if len(target_methods) != 1:
        return None
    target_method = target_methods[0]
    if (
        surface.symbol != f"{binding.class_symbol}.{method_name}"
        or not _plain_function_header(target_method)
        or len(target_method.args.args) != 2
        or target_method.args.posonlyargs
        or target_method.args.kwonlyargs
        or target_method.args.vararg is not None
        or target_method.args.kwarg is not None
        or len(target_method.body) != 1
        or not isinstance(target_method.body[0], ast.Expr)
        or not isinstance(target_method.body[0].value, ast.Call)
    ):
        return None
    sink = target_method.body[0].value
    if (
        sink.lineno != surface.line
        or len(sink.args) != 1
        or not isinstance(sink.args[0], ast.Name)
        or sink.args[0].id != target_method.args.args[1].arg
        or sink.keywords
    ):
        return None

    def step(
        path: str, digest: str, role: str, line: int, symbol: str
    ) -> dict[str, object]:
        return {
            "path": path,
            "source_sha256": digest,
            "role": role,
            "line": line,
            "symbol": symbol,
        }

    return {
        "kind": "operational_xml_call_path_v5",
        "provenance": "python_syntax_and_operational_config",
        "assurance": "SYNTACTIC_REACHABILITY",
        "steps": [
            step(
                binding.parser_path,
                parser_digest,
                "ROUTE_ENTRY",
                server_constructor.lineno,
                handler_class.name,
            ),
            step(binding.parser_path, parser_digest, "CALL", entry.lineno, entry.name),
            step(
                binding.parser_path,
                parser_digest,
                "REQUEST_CONTEXT",
                request_call.lineno,
                "self.path",
            ),
            step(
                binding.parser_path,
                parser_digest,
                "CALL",
                rows_value.lineno,
                function_name,
            ),
            step(
                binding.parser_path,
                parser_digest,
                "CALL",
                resolved[3],
                binding.class_symbol,
            ),
            step(
                binding.parser_path, parser_digest, "CALL", branch.lineno, binding.route
            ),
            step(
                binding.parser_path,
                parser_digest,
                "CALL",
                invocation.lineno,
                f"{binding.class_symbol}.{method_name}",
            ),
            step(
                binding.target_path, target_digest, "SINK", sink.lineno, surface.symbol
            ),
        ],
    }


def extract_surface_graph_v5(
    index: SurfaceIndex,
    surface: AttackSurface,
    ast_summary: Mapping[str, object],
    manifest_index: Mapping[str, Mapping[str, object]],
    workspace: Path,
    artifacts: SimpleArtifactRepository,
    route_map: OperationalRouteMap,
    *,
    max_nodes: int = 256,
    max_edges: int = 512,
    call_index: PythonCallPathIndex | None = None,
    verified_routes: VerifiedOperationalRoutes | None = None,
) -> dict[str, object]:
    """Extend a source-verified v4 graph with only independently pinned v5 facts."""

    graph = extract_surface_graph_v4(
        index,
        surface,
        ast_summary,
        manifest_index,
        workspace,
        artifacts,
        max_nodes=max_nodes,
        max_edges=max_edges,
        call_index=call_index,
    )
    graph["kind"] = "simple_surface_evidence_graph_v5"
    graph["proof_semantics_revision"] = "v5-source-bound-2"
    graph["operational_routes"] = []
    gaps = {
        (cast(str, row["path"]), cast(str, row["reason"]))
        for row in cast(list[dict[str, object]], graph["gaps"])
    }
    source_hashes = dict(index.ast_source_hashes)
    if _stdlib_http_shadow_absent(workspace, index.commit_id, surface.path):
        http = verified_http_paths(workspace, source_hashes, surface)
        gaps.update((surface.path, reason) for reason in http.gaps)
        http_paths = http.paths
    else:
        gaps.add((surface.path, "HTTP_STDLIB_SHADOW_UNRESOLVED"))
        http_paths = ()
    graph_paths = cast(list[dict[str, object]], graph["paths"])
    nodes = cast(list[dict[str, object]], graph["nodes"])
    edges = cast(list[dict[str, object]], graph["edges"])
    lines = cast(list[dict[str, object]], graph["source_lines"])
    facts = cast(list[dict[str, object]], graph["ast_facts"])
    http_added = False
    for raw_path in http_paths:
        raw_steps = raw_path.get("steps")
        if (
            raw_path.get("status") != "AVAILABLE"
            or not isinstance(raw_steps, list)
            or not raw_steps
            or {"ROUTE_ENTRY", "REQUEST_CONTEXT", "SINK"}
            - {step.get("role") for step in raw_steps if isinstance(step, dict)}
        ):
            gaps.add((surface.path, "HTTP_REQUEST_INPUT_UNPROVEN"))
            continue
        steps = cast(list[dict[str, object]], raw_steps)
        step_paths = tuple(step.get("path") for step in steps)
        if not all(
            isinstance(path, str) for path in step_paths
        ) or not _stdlib_http_shadow_absent(
            workspace, index.commit_id, *cast(tuple[str, ...], step_paths)
        ):
            gaps.add((surface.path, "HTTP_STDLIB_SHADOW_UNRESOLVED"))
            continue
        locations: set[tuple[str, int]] = set()
        for step in steps:
            path, line, digest = (
                step.get("path"),
                step.get("line"),
                step.get("source_sha256"),
            )
            if (
                not isinstance(path, str)
                or type(line) is not int
                or line < 1
                or digest != source_hashes.get(path)
            ):
                raise ValueError("SURFACE_GRAPH_HTTP_SOURCE_MISMATCH")
            locations.add((path, line))
        existing_locations = {
            (cast(str, row["path"]), cast(int, row["line"])) for row in lines
        }
        if (
            len(nodes)
            + len(lines)
            + len(facts)
            + len(locations - existing_locations)
            + len(steps)
            > max_nodes
            or len(edges) + len(steps) - 1 > max_edges
        ):
            gaps.add((surface.path, "CONTEXT_BUDGET_EXHAUSTED"))
            continue
        if not _add_http_source_lines(
            graph,
            locations,
            index,
            ast_summary,
            manifest_index,
            workspace,
            artifacts,
        ):
            gaps.add((surface.path, "PATH_SOURCE_UNAVAILABLE"))
            continue
        if (
            len(nodes) + len(lines) + len(facts) + len(steps) > max_nodes
            or len(edges) + len(steps) - 1 > max_edges
        ):
            gaps.add((surface.path, "CONTEXT_BUDGET_EXHAUSTED"))
            continue
        path_id = _id("v5-path", raw_path)
        path_steps = [
            {**step, "node_id": _id("v5-node", (path_id, ordinal, step))}
            for ordinal, step in enumerate(steps)
        ]
        path_edges: list[str] = []
        for ordinal, (first, second) in enumerate(
            zip(path_steps, path_steps[1:], strict=False)
        ):
            edge_type = (
                "ENTRY"
                if first["role"] == "ROUTE_ENTRY"
                else {
                    "REQUEST_CONTEXT": "TRUST_BOUNDARY",
                    "SINK": "SENSITIVE_OPERATION",
                }.get(str(second["role"]), "CALL")
            )
            edge_id = _id(
                "v5-edge", (path_id, ordinal, first["node_id"], second["node_id"])
            )
            edges.append(
                {
                    "edge_id": edge_id,
                    "type": edge_type,
                    "from_node_id": first["node_id"],
                    "to_node_id": second["node_id"],
                    "graph_path_id": path_id,
                }
            )
            path_edges.append(edge_id)
        nodes.extend(path_steps)
        graph_paths.append(
            {
                "path_id": path_id,
                "kind": raw_path["kind"],
                "provenance": raw_path["provenance"],
                "assurance": raw_path["assurance"],
                "steps": path_steps,
                "edge_ids": path_edges,
            }
        )
        http_added = True
    if http_added:
        gaps = {
            (path, reason) for path, reason in gaps if reason not in _REPLACEABLE_GAPS
        }
    operational = cast(list[dict[str, object]], graph["operational_routes"])
    route_proofs = (
        verified_routes._for_surface(index, surface, workspace, route_map)
        if verified_routes is not None
        else None
    )
    for binding in route_map.bindings:
        if binding.target_path != surface.path:
            continue
        proven = (
            route_proofs.get(binding, False)
            if route_proofs is not None
            else _operational_binding_verified(
                index, surface, workspace, binding, source_hashes
            )
        )
        if not proven:
            gaps.add((surface.path, "DYNAMIC_DISPATCH_UNRESOLVED"))
            continue
        operational.append(binding.to_json())
        xml_path = _direct_operational_xml_path(index, surface, workspace, binding)
        if xml_path is None:
            gaps.add((surface.path, "DYNAMIC_DISPATCH_UNRESOLVED"))
            continue
        xml_steps = cast(list[dict[str, object]], xml_path["steps"])
        xml_locations = {
            (cast(str, step["path"]), cast(int, step["line"])) for step in xml_steps
        }
        existing_locations = {
            (cast(str, row["path"]), cast(int, row["line"])) for row in lines
        }
        if (
            len(nodes)
            + len(lines)
            + len(facts)
            + len(xml_locations - existing_locations)
            + len(xml_steps)
            > max_nodes
            or len(edges) + len(xml_steps) - 1 > max_edges
        ):
            gaps.add((surface.path, "CONTEXT_BUDGET_EXHAUSTED"))
            gaps.add((surface.path, "DYNAMIC_DISPATCH_UNRESOLVED"))
            continue
        if not _add_http_source_lines(
            graph,
            xml_locations,
            index,
            ast_summary,
            manifest_index,
            workspace,
            artifacts,
        ):
            gaps.add((surface.path, "PATH_SOURCE_UNAVAILABLE"))
            gaps.add((surface.path, "DYNAMIC_DISPATCH_UNRESOLVED"))
            continue
        xml_path_id = _id("v5-path", xml_path)
        path_steps = [
            {**step, "node_id": _id("v5-node", (xml_path_id, ordinal, step))}
            for ordinal, step in enumerate(xml_steps)
        ]
        xml_path_edges: list[str] = []
        for ordinal, (first, second) in enumerate(
            zip(path_steps, path_steps[1:], strict=False)
        ):
            edge_type = (
                "ENTRY"
                if first["role"] == "ROUTE_ENTRY"
                else {
                    "REQUEST_CONTEXT": "TRUST_BOUNDARY",
                    "SINK": "SENSITIVE_OPERATION",
                }.get(str(second["role"]), "CALL")
            )
            edge_id = _id(
                "v5-edge",
                (xml_path_id, ordinal, first["node_id"], second["node_id"]),
            )
            edges.append(
                {
                    "edge_id": edge_id,
                    "type": edge_type,
                    "from_node_id": first["node_id"],
                    "to_node_id": second["node_id"],
                    "graph_path_id": xml_path_id,
                }
            )
            xml_path_edges.append(edge_id)
        nodes.extend(path_steps)
        graph_paths.append(
            {
                "path_id": xml_path_id,
                "kind": xml_path["kind"],
                "provenance": xml_path["provenance"],
                "assurance": xml_path["assurance"],
                "steps": path_steps,
                "edge_ids": xml_path_edges,
            }
        )
    gaps.update((surface.path, reason) for reason in route_map.gaps)
    graph["source_files"] = sorted(
        cast(list[dict[str, object]], graph["source_files"]),
        key=lambda row: cast(str, row["path"]),
    )
    graph["source_lines"] = sorted(
        lines, key=lambda row: (cast(str, row["path"]), cast(int, row["line"]))
    )
    graph["nodes"] = sorted(nodes, key=lambda row: cast(str, row["node_id"]))
    graph["operational_routes"] = sorted(
        operational,
        key=lambda row: (cast(str, row["route"]), cast(str, row["class_symbol"])),
    )
    graph["gaps"] = [{"path": path, "reason": reason} for path, reason in sorted(gaps)]
    return graph
