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
from .file_context import PreparedFileContext, prepare_file_context
from .http_route_facts_v5 import _MethodAnalyzer, _module, verified_http_paths
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
_HTTP_CONTEXT_RADIUS = 3
_MAX_HTTP_CONTEXT_LINES = 16
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
    *,
    prepared_cache: dict[str, PreparedFileContext | None] | None = None,
) -> bool:
    """Atomically add redacted, indexed source lines absent from the graph."""

    files = cast(list[dict[str, object]], graph["source_files"])
    lines = cast(list[dict[str, object]], graph["source_lines"])
    existing_files = {cast(str, row["path"]) for row in files}
    existing_lines = {(cast(str, row["path"]), cast(int, row["line"])) for row in lines}
    pending_files: list[dict[str, object]] = []
    pending_lines: list[dict[str, object]] = []
    source_hashes = dict(index.ast_source_hashes)
    for path in sorted({path for path, _ in locations}):
        expected = source_hashes.get(path)
        if expected is None or path not in manifest_index:
            return False
        cached = prepared_cache is not None and path in prepared_cache
        if prepared_cache is not None and path in prepared_cache:
            prepared = prepared_cache[path]
        else:
            prepared = prepare_file_context(
                artifacts,
                ast_summary,
                workspace,
                path,
                manifest_index=manifest_index,
            )
        if prepared is None:
            return False
        if (
            prepared.source_unavailable_reason is not None
            or prepared.ast_unavailable_reason is not None
            or prepared.ast_file_ref is None
            or prepared.source_sha256 != expected
        ):
            if prepared_cache is not None:
                prepared_cache[path] = None
            return False
        if not cached:
            _raw_source(workspace, path, expected)
            if prepared_cache is not None:
                prepared_cache[path] = prepared
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
            pending_files.append(
                {
                    "path": path,
                    "source_sha256": expected,
                    "ast_ref": prepared.ast_file_ref.model_dump(mode="json"),
                    "ast_sha256": prepared.ast_file_ref.content_hash,
                    "redaction_categories": list(prepared.redaction_categories),
                }
            )
        pending_lines.extend(additions)
    files.extend(pending_files)
    lines.extend(pending_lines)
    return True


def _supplemental_http_locations(
    index: SurfaceIndex,
    workspace: Path,
    steps: list[dict[str, object]],
) -> list[tuple[str, int]]:
    """Select nearby syntax context without treating it as a path step."""

    hashes = dict(index.ast_source_hashes)
    by_path: dict[str, set[int]] = {}
    for step in steps:
        path, line = step.get("path"), step.get("line")
        if isinstance(path, str) and path.endswith(".py") and type(line) is int:
            if step.get("source_sha256") != hashes.get(path):
                raise ValueError("SURFACE_GRAPH_HTTP_SOURCE_MISMATCH")
            by_path.setdefault(path, set()).add(line)
    ranked: list[tuple[int, str, int]] = []
    for path, step_lines in sorted(by_path.items()):
        expected = hashes.get(path)
        if expected is None:
            continue
        raw = _raw_source(workspace, path, expected)
        try:
            source = raw.decode("utf-8")
            source_lines = source.splitlines()
            tree = ast.parse(source, filename=path)
        except (UnicodeError, SyntaxError, RecursionError) as error:
            raise ValueError("SURFACE_GRAPH_AST_SOURCE_MISMATCH") from error
        methods = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        candidates: set[int] = set()
        for step_line in step_lines:
            enclosing = [
                method
                for method in methods
                if method.lineno <= step_line <= (method.end_lineno or method.lineno)
            ]
            if not enclosing:
                continue
            method = min(
                enclosing,
                key=lambda node: (node.end_lineno or node.lineno) - node.lineno,
            )
            pending: list[ast.AST] = list(method.body)
            while pending:
                node = pending.pop()
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    continue
                if isinstance(node, ast.stmt):
                    line = node.lineno
                    if abs(line - step_line) <= _HTTP_CONTEXT_RADIUS:
                        candidates.add(line)
                    if isinstance(node, ast.If) and node.orelse:
                        marker = node.orelse[0].lineno - 1
                        if (
                            abs(marker - step_line) <= _HTTP_CONTEXT_RADIUS
                            and 1 <= marker <= len(source_lines)
                            and source_lines[marker - 1].strip() == "else:"
                        ):
                            candidates.add(marker)
                pending.extend(ast.iter_child_nodes(node))
        for line in candidates:
            distance = min(abs(line - step_line) for step_line in step_lines)
            ranked.append((distance, path, line))
    return [(path, line) for _, path, line in sorted(ranked)]


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
    """Require pinned initializers with only inert literal metadata assignments."""

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
            raw, actual = _verified_blob(workspace, index.commit_id, path, 8192)
        except _Gap:
            return False
        if actual != expected:
            raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
        if raw:
            try:
                tree = ast.parse(raw.decode("utf-8"), filename=path)
            except (SyntaxError, UnicodeError):
                return False
            if any(
                not isinstance(statement, ast.Assign)
                or len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
                or not isinstance(statement.value, ast.Constant)
                or not isinstance(
                    statement.value.value, (str, int, float, bool, type(None))
                )
                for statement in tree.body
            ):
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


def _unique_plain_method(cls: ast.ClassDef, name: str) -> ast.FunctionDef | None:
    matching = [
        node
        for node in cls.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    method = matching[0] if len(matching) == 1 else None
    literal_constructor_defaults = (
        name == "__init__"
        and isinstance(method, ast.FunctionDef)
        and not method.decorator_list
        and method.returns is None
        and not method.type_params
        and all(
            isinstance(default, ast.Constant)
            and isinstance(default.value, (str, int, float, bool, type(None)))
            for default in (
                *method.args.defaults,
                *(item for item in method.args.kw_defaults if item is not None),
            )
        )
        and all(
            argument.annotation is None
            for argument in (
                *method.args.posonlyargs,
                *method.args.args,
                *method.args.kwonlyargs,
            )
        )
        and (method.args.vararg is None or method.args.vararg.annotation is None)
        and (method.args.kwarg is None or method.args.kwarg.annotation is None)
    )
    if (
        len(matching) != 1
        or not isinstance(method, ast.FunctionDef)
        or not (_plain_function_header(method) or literal_constructor_defaults)
        or any(
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(target, ast.Name) and target.id == name
                for target in (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
            )
            for node in cls.body
        )
    ):
        return None
    return method


def _one_class(tree: ast.Module, name: str) -> ast.ClassDef | None:
    matching = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == name
    ]
    if (
        len(matching) != 1
        or matching[0].decorator_list
        or matching[0].keywords
        or matching[0].type_params
        or any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id == name
            for statement in tree.body
            if statement is not matching[0]
            for node in ast.walk(statement)
        )
    ):
        return None
    return matching[0]


def _same_syntax(first: ast.AST, second: ast.AST) -> bool:
    return ast.dump(first, include_attributes=False) == ast.dump(
        second, include_attributes=False
    )


def _request_attribute(node: ast.AST, request: ast.AST, attribute: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == attribute
        and _same_syntax(node.value, request)
    )


def _method_line_reachable(
    path: str,
    digest: str,
    tree: ast.Module,
    cls: ast.ClassDef,
    method: ast.FunctionDef,
    line: int,
) -> bool:
    module = _module(path, digest, tree)
    indexed = module.methods.get((cls.name, method.name))
    if indexed is None:
        return False
    facts = _MethodAnalyzer(module, indexed, request_self=False).analyze()
    return line in facts.reachable_lines and not any(
        first <= line <= last for first, last in facts.deferred_spans
    )


def _inherited_override(
    tree: ast.Module,
    path: str,
    digest: str,
    class_name: str,
    dispatch_name: str,
    route_attribute: str,
    surface: AttackSurface,
) -> tuple[ast.FunctionDef, ast.FunctionDef, ast.Call] | None:
    """Bind a selected constructor route and inherited self-call to one override."""

    child = _one_class(tree, class_name)
    if (
        child is None
        or len(child.bases) != 1
        or not isinstance(child.bases[0], ast.Name)
        or any(
            isinstance(node, ast.FunctionDef)
            and node.name
            in {"__init__", dispatch_name, "__getattribute__", "__setattr__"}
            for node in child.body
        )
    ):
        return None
    parent = _one_class(tree, child.bases[0].id)
    if (
        parent is None
        or parent.lineno >= child.lineno
        or parent.bases
        or any(
            isinstance(node, ast.FunctionDef)
            and node.name in {"__getattribute__", "__setattr__"}
            for node in parent.body
        )
    ):
        return None
    initialize = _unique_plain_method(parent, "__init__")
    dispatch = _unique_plain_method(parent, dispatch_name)
    if initialize is None or dispatch is None:
        return None
    if len(initialize.args.args) < 2 or len(dispatch.args.args) != 2:
        return None
    self_name = initialize.args.args[0].arg
    assigned_route = [
        statement
        for statement in initialize.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and _request_attribute(
            statement.targets[0],
            ast.Name(id=self_name, ctx=ast.Load()),
            route_attribute,
        )
        and isinstance(statement.value, ast.Name)
        and statement.value.id in {arg.arg for arg in initialize.args.args[1:]}
        and statement.value.id == route_attribute
    ]
    route_writes = [
        node
        for statement in initialize.body
        for node in ast.walk(statement)
        if isinstance(node, ast.Attribute)
        and node.attr == route_attribute
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if (
        len(assigned_route) != 1 or route_writes != [assigned_route[0].targets[0]]
    ) or any(
        isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With))
        for statement in initialize.body
        for node in ast.walk(statement)
    ):
        return None
    receiver, request = (argument.arg for argument in dispatch.args.args)
    override_calls = [
        node
        for node in ast.walk(dispatch)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == receiver
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == request
        and not node.keywords
        and _method_line_reachable(path, digest, tree, parent, dispatch, node.lineno)
    ]
    override_names = {
        cast(ast.Attribute, node.func).attr
        for node in override_calls
        if (
            candidate := _unique_plain_method(
                child, cast(ast.Attribute, node.func).attr
            )
        )
        is not None
        and candidate.lineno <= surface.line <= (candidate.end_lineno or 0)
    }
    if len(override_names) != 1:
        return None
    override_name = next(iter(override_names))
    override = _unique_plain_method(child, override_name)
    if (
        override is None
        or len(override.args.args) != 2
        or not _method_line_reachable(path, digest, tree, child, override, surface.line)
    ):
        return None
    selected_calls = [
        node
        for node in override_calls
        if cast(ast.Attribute, node.func).attr == override_name
    ]
    if len(selected_calls) != 1:
        return None
    return dispatch, override, selected_calls[0]


def _registry_dispatch(
    tree: ast.Module,
    binding: OperationalRouteBinding,
    class_tag: str,
    route_tag: str,
    parser_sites: tuple[int, ...],
    target_tree: ast.Module,
    target_digest: str,
    surface: AttackSurface,
) -> (
    tuple[ast.ClassDef, ast.For, ast.Call, ast.If, ast.Call, str, str, str, ast.AST]
    | None
):
    """Match a class-body XML list and a same-list route-gated item call."""

    imports = _imported_modules(tree)
    for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
        if cls.decorator_list or cls.keywords or cls.type_params:
            continue
        collections = [
            pair
            for statement in cls.body
            if (pair := _single_assignment(statement)) is not None
            and isinstance(pair[1], ast.List)
            and not pair[1].elts
        ]
        for collection, _ in collections:
            # Instance attributes take precedence over the class-body XML
            # registry. A write in any method can replace or delete the
            # collection before the dispatch loop runs, so this path cannot
            # certify that the XML-selected entries are what it iterates.
            if any(
                isinstance(node, ast.Attribute)
                and node.attr == collection
                and isinstance(node.ctx, (ast.Store, ast.Del))
                for method in cls.body
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                for node in ast.walk(method)
            ):
                continue
            for loop in (node for node in cls.body if isinstance(node, ast.For)):
                if (
                    loop.lineno not in parser_sites
                    or loop.orelse
                    or len(loop.body) != 2
                    or not isinstance(loop.target, ast.Name)
                ):
                    continue
                assigned = _single_assignment(loop.body[0])
                append_statement = loop.body[1]
                if assigned is None or not (
                    isinstance(append_statement, ast.Expr)
                    and isinstance(append_statement.value, ast.Call)
                    and isinstance(append_statement.value.func, ast.Attribute)
                    and isinstance(append_statement.value.func.value, ast.Name)
                    and append_statement.value.func.value.id == collection
                    and append_statement.value.func.attr == "append"
                    and len(append_statement.value.args) == 1
                    and isinstance(append_statement.value.args[0], ast.Name)
                    and append_statement.value.args[0].id == assigned[0]
                    and not append_statement.value.keywords
                ):
                    continue
                constructor = assigned[1]
                if (
                    not isinstance(constructor, ast.Call)
                    or constructor.args
                    or any(keyword.arg is None for keyword in constructor.keywords)
                ):
                    continue
                resolved = _getattr_binding(
                    constructor, loop.target.id, {assigned[0]: constructor}, imports
                )
                if resolved is None or resolved[:2] != (binding.module_path, class_tag):
                    continue
                route_fields = [
                    keyword.arg
                    for keyword in constructor.keywords
                    if _findtext(keyword.value, loop.target.id, {})
                    == (route_tag, keyword.value.lineno)
                ]
                if len(route_fields) != 1 or route_fields[0] is None:
                    continue
                route_attribute = route_fields[0]
                if any(
                    isinstance(node, ast.Name)
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.id == collection
                    for statement in cls.body
                    if statement is not loop
                    and not (
                        (pair := _single_assignment(statement)) is not None
                        and pair[0] == collection
                        and isinstance(pair[1], ast.List)
                    )
                    for node in ast.walk(statement)
                ):
                    continue
                for method in (
                    node for node in cls.body if isinstance(node, ast.FunctionDef)
                ):
                    if not _plain_function_header(method) or not method.args.args:
                        continue
                    receiver = method.args.args[0].arg
                    for dispatch_loop in (
                        node for node in method.body if isinstance(node, ast.For)
                    ):
                        if not (
                            isinstance(dispatch_loop.target, ast.Name)
                            and isinstance(dispatch_loop.iter, ast.Attribute)
                            and isinstance(dispatch_loop.iter.value, ast.Name)
                            and dispatch_loop.iter.value.id == receiver
                            and dispatch_loop.iter.attr == collection
                            and not dispatch_loop.orelse
                        ):
                            continue
                        item = dispatch_loop.target.id
                        for branch in (
                            node
                            for node in dispatch_loop.body
                            if isinstance(node, ast.If)
                        ):
                            if not (
                                isinstance(branch.test, ast.Compare)
                                and len(branch.test.ops) == 1
                                and isinstance(branch.test.ops[0], ast.Eq)
                                and len(branch.test.comparators) == 1
                                and not branch.orelse
                            ):
                                continue
                            route_expr = ast.Attribute(
                                value=ast.Name(id=item, ctx=ast.Load()),
                                attr=route_attribute,
                                ctx=ast.Load(),
                            )
                            operands = (branch.test.left, branch.test.comparators[0])
                            if not any(
                                _same_syntax(operand, route_expr)
                                for operand in operands
                            ):
                                continue
                            request_path = next(
                                (
                                    operand
                                    for operand in operands
                                    if not _same_syntax(operand, route_expr)
                                ),
                                None,
                            )
                            if (
                                not isinstance(request_path, ast.Attribute)
                                or request_path.attr != "path"
                            ):
                                continue
                            request_expr = request_path.value
                            calls = [
                                node
                                for statement in branch.body
                                if isinstance(
                                    statement, (ast.Assign, ast.Expr, ast.Return)
                                )
                                and not any(
                                    isinstance(
                                        child,
                                        (
                                            ast.Lambda,
                                            ast.IfExp,
                                            ast.BoolOp,
                                            ast.GeneratorExp,
                                            ast.ListComp,
                                            ast.SetComp,
                                            ast.DictComp,
                                        ),
                                    )
                                    for child in ast.walk(statement)
                                )
                                for node in ast.walk(statement)
                                if isinstance(node, ast.Call)
                                and isinstance(node.func, ast.Attribute)
                                and isinstance(node.func.value, ast.Name)
                                and node.func.value.id == item
                                and len(node.args) == 1
                                and _same_syntax(node.args[0], request_expr)
                                and not node.keywords
                            ]
                            proven_calls = [
                                node
                                for node in calls
                                if isinstance(node.func, ast.Attribute)
                                and _inherited_override(
                                    target_tree,
                                    binding.target_path,
                                    target_digest,
                                    binding.class_symbol,
                                    node.func.attr,
                                    route_attribute,
                                    surface,
                                )
                                is not None
                            ]
                            if len(proven_calls) != 1:
                                continue
                            return (
                                cls,
                                loop,
                                constructor,
                                branch,
                                proven_calls[0],
                                method.name,
                                route_attribute,
                                receiver,
                                request_expr,
                            )
    return None


def _stdlib_imported_name(tree: ast.Module, module: str, name: str) -> str | None:
    aliases = [
        alias.asname or alias.name
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module == module
        for alias in statement.names
        if alias.name == name
    ]
    return aliases[0] if len(aliases) == 1 else None


def _routes_include_operational_xml(
    cls: ast.ClassDef, registry_loop: ast.For, route_tag: str
) -> str | None:
    for statement in cls.body:
        initial = _single_assignment(statement)
        if initial is None or not isinstance(initial[1], ast.Dict):
            continue
        name = initial[0]
        loops = [
            loop
            for loop in cls.body
            if isinstance(loop, ast.For)
            and _same_syntax(loop.iter, registry_loop.iter)
            and isinstance(loop.target, ast.Name)
            and not loop.orelse
            and len(loop.body) == 1
        ]
        if len(loops) != 1:
            continue
        loop = loops[0]
        assignment = loop.body[0]
        if not (
            isinstance(assignment, ast.Assign)
            and len(assignment.targets) == 1
            and isinstance(assignment.targets[0], ast.Subscript)
            and isinstance(assignment.targets[0].value, ast.Name)
            and assignment.targets[0].value.id == name
            and _findtext(
                assignment.targets[0].slice, cast(ast.Name, loop.target).id, {}
            )
            == (route_tag, assignment.targets[0].slice.lineno)
        ):
            continue
        if any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id == name
            for other in cls.body
            if other not in (statement, loop)
            for node in ast.walk(other)
        ):
            continue
        return name
    return None


def _request_path_lineage(
    tree: ast.Module, entry: ast.FunctionDef, receiver: str, branch: ast.If
) -> bool:
    """Do not treat a route selected from a constant rewrite as request input."""

    prior = entry.body[: entry.body.index(branch)]
    writes = [
        statement
        for statement in prior
        for node in ast.walk(statement)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and _request_attribute(node, ast.Name(id=receiver, ctx=ast.Load()), "path")
    ]
    if not writes:
        return True
    if len(writes) != 1 or not isinstance(writes[0], ast.Assign):
        return False
    rewritten = writes[0]
    if (
        len(rewritten.targets) != 1
        or not _request_attribute(
            rewritten.targets[0], ast.Name(id=receiver, ctx=ast.Load()), "path"
        )
        or not isinstance(rewritten.value, ast.Attribute)
        or rewritten.value.attr != "path"
        or not isinstance(rewritten.value.value, ast.Name)
    ):
        return False
    parsed_name = rewritten.value.value.id
    sources = [
        statement
        for statement in prior
        if statement.lineno < rewritten.lineno
        and (assigned := _single_assignment(statement)) is not None
        and assigned[0] == parsed_name
    ]
    if len(sources) != 1 or any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id == parsed_name
        and node.lineno != sources[0].lineno
        for statement in prior
        for node in ast.walk(statement)
    ):
        return False
    source = cast(ast.Assign, sources[0]).value
    aliases = [
        alias.asname
        for statement in tree.body
        if isinstance(statement, ast.Import)
        for alias in statement.names
        if alias.name == "urllib.parse" and alias.asname
    ]
    return (
        len(aliases) == 1
        and isinstance(source, ast.Call)
        and isinstance(source.func, ast.Attribute)
        and source.func.attr == "urlparse"
        and isinstance(source.func.value, ast.Name)
        and source.func.value.id == aliases[0]
        and len(source.args) == 1
        and _request_attribute(
            source.args[0], ast.Name(id=receiver, ctx=ast.Load()), "path"
        )
        and not source.keywords
        and not any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id == aliases[0]
            for node in ast.walk(tree)
        )
    )


def _http_registry_entry(
    tree: ast.Module,
    parser_path: str,
    parser_digest: str,
    registry: ast.ClassDef,
    registry_loop: ast.For,
    dispatch_name: str,
    route_tag: str,
    request_expr: ast.AST,
) -> tuple[ast.ClassDef, ast.FunctionDef, ast.Call, int] | None:
    imported = _stdlib_imported_name(tree, "http.server", "BaseHTTPRequestHandler")
    if imported is None:
        return None
    candidates = [
        cls
        for cls in tree.body
        if isinstance(cls, ast.ClassDef)
        and len(cls.bases) == 1
        and isinstance(cls.bases[0], ast.Name)
        and cls.bases[0].id == imported
        and _one_class(tree, cls.name) is cls
        and not any(
            isinstance(node, ast.FunctionDef)
            and node.name in {"__getattribute__", "__setattr__"}
            for node in cls.body
        )
    ]
    if len(candidates) != 1:
        return None
    handler = candidates[0]
    for entry in (
        node
        for node in handler.body
        if isinstance(node, ast.FunctionDef)
        and node.name.startswith("do_")
        and _plain_function_header(node)
        and len(node.args.args) == 1
    ):
        receiver = entry.args.args[0].arg
        # Direct registration: Registry().select(self).
        direct = [
            statement.value
            for statement in entry.body
            if isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Attribute)
            and statement.value.func.attr == dispatch_name
            and isinstance(statement.value.func.value, ast.Call)
            and isinstance(statement.value.func.value.func, ast.Name)
            and statement.value.func.value.func.id == registry.name
            and not statement.value.func.value.args
            and not statement.value.func.value.keywords
            and len(statement.value.args) == 1
            and isinstance(statement.value.args[0], ast.Name)
            and statement.value.args[0].id == receiver
            and not statement.value.keywords
        ]
        if (
            len(direct) == 1
            and isinstance(request_expr, ast.Name)
            and len(entry.body) == 1
            and _method_line_reachable(
                parser_path, parser_digest, tree, handler, entry, direct[0].lineno
            )
        ):
            return handler, entry, direct[0], direct[0].lineno

        # A route-selected handler instance may be stored locally, then called
        # after the branch. The same XML route table must guard its constructor.
        route_collection = _routes_include_operational_xml(
            handler, registry_loop, route_tag
        )
        if route_collection is None or not isinstance(request_expr, ast.Attribute):
            continue
        branches = [
            statement
            for statement in entry.body
            if isinstance(statement, ast.If)
            and any(
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.In)
                and len(node.comparators) == 1
                and _request_attribute(
                    node.left, ast.Name(id=receiver, ctx=ast.Load()), "path"
                )
                and isinstance(node.comparators[0], ast.Attribute)
                and isinstance(node.comparators[0].value, ast.Name)
                and node.comparators[0].value.id == receiver
                and node.comparators[0].attr == route_collection
                for node in ast.walk(statement.test)
            )
        ]
        if len(branches) != 1:
            continue
        branch = branches[0]
        if not _request_path_lineage(tree, entry, receiver, branch):
            continue
        constructors = [
            (assigned[0], assigned[1])
            for statement in branch.body
            if (assigned := _single_assignment(statement)) is not None
            and isinstance(assigned[1], ast.Call)
            and isinstance(assigned[1].func, ast.Name)
            and assigned[1].func.id == registry.name
            and len(assigned[1].args) == 1
            and isinstance(assigned[1].args[0], ast.Name)
            and assigned[1].args[0].id == receiver
            and not assigned[1].keywords
        ]
        if len(constructors) != 1:
            continue
        local_name, constructor = constructors[0]
        method_calls = [
            node
            for statement in entry.body
            if statement.lineno > branch.lineno
            for node in ast.walk(statement)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == local_name
            and node.func.attr == dispatch_name
            and not node.args
            and not node.keywords
            and not any(
                isinstance(parent, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef))
                for parent in ast.walk(statement)
                if parent is not entry
            )
        ]
        if len(method_calls) != 1:
            continue
        method_call = method_calls[0]
        intervening = [
            statement
            for statement in entry.body
            if branch.lineno < statement.lineno < method_call.lineno
            and any(
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.id == local_name
                for node in ast.walk(statement)
            )
        ]
        if intervening or not _method_line_reachable(
            parser_path, parser_digest, tree, handler, entry, method_call.lineno
        ):
            continue
        return handler, entry, method_call, constructor.lineno
    return None


def _main_guard(tree: ast.Module) -> ast.If | None:
    guards = [
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Eq)
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "__main__"
        and not node.orelse
    ]
    return guards[0] if len(guards) == 1 and tree.body[-1] is guards[0] else None


def _imported_class_path(tree: ast.Module, name: str) -> tuple[str, str] | None:
    matching = [
        (statement.module.replace(".", "/") + ".py", alias.name)
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module
        for alias in statement.names
        if (alias.asname or alias.name) == name
    ]
    return matching[0] if len(matching) == 1 else None


def _source_tree(
    index: SurfaceIndex, workspace: Path, path: str
) -> tuple[ast.Module, str] | None:
    expected = dict(index.ast_source_hashes).get(path)
    if expected is None:
        return None
    try:
        raw, digest = _verified_blob(
            workspace, index.commit_id, path, _MAX_PARSER_BYTES
        )
        if digest != expected:
            raise ValueError("SURFACE_GRAPH_PINNED_ROUTE_MISMATCH")
        return ast.parse(raw.decode("utf-8"), filename=path), digest
    except (_Gap, SyntaxError, UnicodeError):
        return None


def _server_class_is_stdlib_http(
    tree: ast.Module, class_name: str
) -> ast.ClassDef | None:
    cls = _one_class(tree, class_name)
    if cls is None or len(cls.bases) != 1 or not isinstance(cls.bases[0], ast.Name):
        return None
    bases = {
        _stdlib_imported_name(tree, "http.server", name)
        for name in ("HTTPServer", "ThreadingHTTPServer")
    }
    if cls.bases[0].id not in bases or any(
        isinstance(node, ast.FunctionDef)
        and node.name in {"serve_forever", "__new__", "__getattribute__"}
        for node in cls.body
    ):
        return None
    initializer = _unique_plain_method(cls, "__init__")
    if initializer is not None and not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "__init__"
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Name)
        and node.func.value.func.id == "super"
        and not node.func.value.args
        and not node.func.value.keywords
        for statement in initializer.body[:1]
        for node in ast.walk(statement)
    ):
        return None
    return cls


def _launched_http_entry(
    index: SurfaceIndex,
    workspace: Path,
    binding: OperationalRouteBinding,
    launcher_raw: bytes,
    parser_tree: ast.Module,
    handler: ast.ClassDef,
) -> list[tuple[str, str, int, str, str]] | None:
    """Return pinned server/handler registration steps, including imported entry."""

    try:
        workdirs = _final_stage_directives(
            launcher_raw, decode_gap="LAUNCHER_ENTRYPOINT_UNPROVEN"
        ).get("WORKDIR", [])
        if len(workdirs) != 1:
            return None
        launched_path = _launched_path(
            launcher_raw, workdirs[0], workspace, index.commit_id
        )
    except _Gap:
        return None
    if not _stdlib_http_shadow_absent(
        workspace, index.commit_id, launched_path, binding.parser_path
    ) or not _plain_package_initializers(
        index, workspace, launched_path, binding.parser_path
    ):
        return None
    if launched_path == binding.parser_path:
        guard = _main_guard(parser_tree)
        server_name = _stdlib_imported_name(parser_tree, "http.server", "HTTPServer")
        if guard is None or server_name is None or len(guard.body) != 1:
            return None
        statement = guard.body[0]
        if not (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Attribute)
            and statement.value.func.attr == "serve_forever"
            and isinstance(statement.value.func.value, ast.Call)
        ):
            return None
        constructor = statement.value.func.value
        if not (
            isinstance(constructor.func, ast.Name)
            and constructor.func.id == server_name
            and len(constructor.args) == 2
            and isinstance(constructor.args[1], ast.Name)
            and constructor.args[1].id == handler.name
            and not constructor.keywords
        ):
            return None
        return [
            (
                binding.parser_path,
                binding.parser_sha256,
                constructor.lineno,
                "ROUTE_ENTRY",
                handler.name,
            )
        ]
    launched = _source_tree(index, workspace, launched_path)
    if launched is None:
        return None
    launch_tree, launch_digest = launched
    handler_import = _imported_class_path(launch_tree, handler.name)
    if handler_import != (binding.parser_path, handler.name):
        return None
    guard = _main_guard(launch_tree)
    if guard is None or len(guard.body) != 1:
        return None
    main_call = guard.body[0]
    if not (
        isinstance(main_call, ast.Expr)
        and isinstance(main_call.value, ast.Call)
        and isinstance(main_call.value.func, ast.Name)
        and not main_call.value.args
        and not main_call.value.keywords
    ):
        return None
    main_functions = [
        node
        for node in launch_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == main_call.value.func.id
        and _plain_function_header(node)
        and not node.args.args
    ]
    if len(main_functions) != 1:
        return None
    main = main_functions[0]
    registrations = [
        (statement, node)
        for statement in ast.walk(main)
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and isinstance(statement.value, ast.Call)
        for node in [statement.value]
        if isinstance(node.func, ast.Name)
        and len(node.args) == 2
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == handler.name
        and not node.keywords
    ]
    if len(registrations) != 1:
        return None
    assignment, registration = registrations[0]
    assert isinstance(registration.func, ast.Name)
    server_name = registration.func.id
    server_import = _imported_class_path(launch_tree, server_name)
    server_steps: list[tuple[str, str, int, str, str]] = []
    if server_import is None:
        if server_name not in {
            _stdlib_imported_name(launch_tree, "http.server", "HTTPServer"),
            _stdlib_imported_name(launch_tree, "http.server", "ThreadingHTTPServer"),
        }:
            return None
    else:
        server_path, server_symbol = server_import
        if server_path in {binding.parser_path, binding.target_path}:
            return None
        server_source = _source_tree(index, workspace, server_path)
        if (
            server_source is None
            or not _plain_package_initializers(index, workspace, server_path)
            or not _stdlib_http_shadow_absent(workspace, index.commit_id, server_path)
        ):
            return None
        server_tree, server_digest = server_source
        server_cls = _server_class_is_stdlib_http(server_tree, server_symbol)
        if server_cls is None:
            return None
        server_steps.append(
            (server_path, server_digest, server_cls.lineno, "CALL", server_symbol)
        )
    local_name = cast(ast.Name, assignment.targets[0]).id
    serving = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == local_name
        and node.func.attr == "serve_forever"
        and node.lineno > registration.lineno
        and not node.args
        and not node.keywords
    ]
    if (
        len(serving) != 1
        or sum(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id == local_name
            for node in ast.walk(main)
        )
        != 1
    ):
        return None
    return [
        (
            launched_path,
            launch_digest,
            registration.lineno,
            "ROUTE_ENTRY",
            handler.name,
        ),
        *server_steps,
        (launched_path, launch_digest, serving[0].lineno, "CALL", "serve_forever"),
    ]


def _class_body_operational_xml_path(
    index: SurfaceIndex,
    surface: AttackSurface,
    workspace: Path,
    binding: OperationalRouteBinding,
) -> dict[str, object] | None:
    """Prove a bounded class-registry/HTTP/inherited-override composite.

    A route binding alone never supplies this path. Every link is re-read from
    pinned Python, and uncertain dispatch retains the graph's explicit gap.
    """

    if not _stdlib_http_shadow_absent(
        workspace,
        index.commit_id,
        binding.parser_path,
        binding.target_path,
        binding.launcher_path,
    ) or not _plain_package_initializers(
        index, workspace, binding.parser_path, binding.target_path
    ):
        return None
    try:
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
        function_name is not None
        or module_path != binding.module_path
        or config_path != binding.config_path
        or parser_sites != binding.parser_sites
    ):
        return None
    registry = _registry_dispatch(
        parser_tree,
        binding,
        class_tag,
        route_tag,
        parser_sites,
        target_tree,
        target_digest,
        surface,
    )
    if registry is None:
        return None
    (
        registry_class,
        registry_loop,
        constructor,
        branch,
        invocation,
        registry_method_name,
        route_attribute,
        receiver,
        request_expr,
    ) = registry
    if _one_class(parser_tree, registry_class.name) is not registry_class:
        return None
    registry_method = _unique_plain_method(registry_class, registry_method_name)
    if registry_method is None or not _method_line_reachable(
        binding.parser_path,
        parser_digest,
        parser_tree,
        registry_class,
        registry_method,
        invocation.lineno,
    ):
        return None
    if isinstance(request_expr, ast.Name):
        if request_expr.id not in {
            arg.arg for arg in registry_method.args.args[1:]
        } or any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id == request_expr.id
            for statement in registry_method.body
            for node in ast.walk(statement)
        ):
            return None
    elif isinstance(request_expr, ast.Attribute):
        if not (
            isinstance(request_expr.value, ast.Name)
            and request_expr.value.id == receiver
        ):
            return None
        initializer = _unique_plain_method(registry_class, "__init__")
        if initializer is None or len(initializer.args.args) != 2:
            return None
        initialized = [
            statement
            for statement in initializer.body
            if isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and _request_attribute(
                statement.targets[0],
                ast.Name(id=initializer.args.args[0].arg, ctx=ast.Load()),
                request_expr.attr,
            )
            and isinstance(statement.value, ast.Name)
            and statement.value.id == initializer.args.args[1].arg
        ]
        if len(initialized) != 1:
            return None
    else:
        return None
    if not isinstance(invocation.func, ast.Attribute):
        return None
    inherited = _inherited_override(
        target_tree,
        binding.target_path,
        target_digest,
        binding.class_symbol,
        invocation.func.attr,
        route_attribute,
        surface,
    )
    if inherited is None:
        return None
    _base_dispatch, _override, override_call = inherited
    entry = _http_registry_entry(
        parser_tree,
        binding.parser_path,
        parser_digest,
        registry_class,
        registry_loop,
        registry_method_name,
        route_tag,
        request_expr,
    )
    if entry is None:
        return None
    handler, http_method, http_call, constructor_line = entry
    launched = _launched_http_entry(
        index, workspace, binding, launcher_raw, parser_tree, handler
    )
    if launched is None:
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
            *(
                step(path, digest, role, line, symbol)
                for path, digest, line, role, symbol in launched
            ),
            step(
                binding.parser_path,
                parser_digest,
                "CALL",
                http_method.lineno,
                f"{handler.name}.{http_method.name}",
            ),
            step(
                binding.parser_path,
                parser_digest,
                "CALL",
                constructor_line,
                f"{registry_class.name}.{registry_method_name}",
            ),
            *(
                [
                    step(
                        binding.parser_path,
                        parser_digest,
                        "CALL",
                        http_call.lineno,
                        f"{registry_class.name}.{registry_method_name}",
                    )
                ]
                if http_call.lineno != constructor_line
                else []
            ),
            step(
                binding.parser_path,
                parser_digest,
                "REQUEST_CONTEXT",
                branch.lineno,
                "request.path",
            ),
            step(
                binding.parser_path,
                parser_digest,
                "CALL",
                registry_loop.lineno,
                registry_class.name,
            ),
            step(
                binding.parser_path,
                parser_digest,
                "CALL",
                constructor.lineno,
                binding.class_symbol,
            ),
            step(
                binding.parser_path,
                parser_digest,
                "CALL",
                invocation.lineno,
                f"{binding.class_symbol}.{invocation.func.attr}",
            ),
            step(
                binding.target_path,
                target_digest,
                "CALL",
                override_call.lineno,
                surface.symbol,
            ),
            step(
                binding.target_path, target_digest, "SINK", surface.line, surface.symbol
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
    graph["proof_semantics_revision"] = "v5-source-bound-3"
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
                "blocking_gaps": [],
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
            xml_path = _class_body_operational_xml_path(
                index, surface, workspace, binding
            )
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
                "blocking_gaps": [],
            }
        )
    gaps.update((surface.path, reason) for reason in route_map.gaps)
    verified_http_steps = [
        step
        for path in graph_paths
        if path.get("kind")
        in {"stdlib_http_call_path_v5", "operational_xml_call_path_v5"}
        for step in cast(list[dict[str, object]], path["steps"])
    ]
    remaining = min(
        _MAX_HTTP_CONTEXT_LINES,
        max(0, max_nodes - len(nodes) - len(lines) - len(facts)),
    )
    if verified_http_steps and remaining:
        existing = {(cast(str, row["path"]), cast(int, row["line"])) for row in lines}
        added = 0
        prepared_cache: dict[str, PreparedFileContext | None] = {}
        for location in _supplemental_http_locations(
            index, workspace, verified_http_steps
        ):
            if added == remaining:
                break
            if location in existing:
                continue
            if _add_http_source_lines(
                graph,
                {location},
                index,
                ast_summary,
                manifest_index,
                workspace,
                artifacts,
                prepared_cache=prepared_cache,
            ):
                added += 1
        for path, prepared in sorted(prepared_cache.items()):
            if prepared is None:
                continue
            expected = source_hashes.get(path)
            if expected is None:
                raise ValueError("SURFACE_GRAPH_HTTP_SOURCE_MISMATCH")
            _raw_source(workspace, path, expected)
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
