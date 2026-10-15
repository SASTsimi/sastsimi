"""Source-bound certificates for inherited connected attack-surface paths."""

from __future__ import annotations

import ast
import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import redact_untrusted_text_preserving_lines

from .attack_surfaces import AttackSurface, SurfaceIndex, surface_review_contract
from .call_path_facts import (
    PythonCallPathIndex,
    _function_local_bindings,
    build_python_call_path_index,
)
from .flask_html_response_flow_v9 import prove_flask_html_response_flow_v9
from .http_route_facts_v5 import verified_http_paths
from .surface_applicability_v9 import (
    AnalyzerApplicabilityV9,
    assess_optional_analyzers,
)
from .surface_evidence_graph_v4 import _raw_source, _surface_candidate

_MAX_PART_LINES = 64
_MAX_PART_BYTES = 8 * 1024
_MAX_CONTEXT_PARTS = 256
_REPAIRABLE_CONTEXT_GAPS = frozenset(
    {
        "ENCLOSING_CONTEXT_TRUNCATED",
        "DOWNSTREAM_CALLEE_BODY_TRUNCATED",
        "REQUEST_CONTEXT_LINE_LIMIT",
    }
)
_OPTIONAL_GAPS = {
    "HTTP_HANDLER_IMPORT_UNPROVEN": "stdlib_http",
    "OPERATIONAL_PARSER_UNRESOLVED": "operational_xml",
}
_ROUTE_ANCHOR_GAPS = frozenset(
    {
        "SINK_ENCLOSING_FUNCTION_UNAVAILABLE",
        "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "EXTERNAL_IMPLEMENTATION_UNAVAILABLE",
    }
)


def _json_object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
    return cast(dict[str, object], value)


def _json_string(value: object) -> str:
    if type(value) is not str:
        raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
    return value


def _json_integer(value: object) -> int:
    if type(value) is not int:
        raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
    return value


def _json_string_array(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
    return tuple(_json_string(item) for item in value)


def _json_object_array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
    return cast(list[object], value)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _id(prefix: str, value: object) -> str:
    return f"{prefix}-{_digest(value)[:24]}"


@dataclass(frozen=True, slots=True)
class ContextPartV9:
    part_id: str
    path_ids: tuple[str, ...]
    path: str
    start_line: int
    end_line: int
    source_sha256: str
    content_sha256: str

    def to_json(self) -> dict[str, object]:
        return {
            "part_id": self.part_id,
            "path_ids": list(self.path_ids),
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "source_sha256": self.source_sha256,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_json(cls, value: object) -> ContextPartV9:
        row = _json_object(
            value,
            frozenset(
                {
                    "part_id",
                    "path_ids",
                    "path",
                    "start_line",
                    "end_line",
                    "source_sha256",
                    "content_sha256",
                }
            ),
        )
        start = _json_integer(row["start_line"])
        end = _json_integer(row["end_line"])
        if start < 1 or end < start:
            raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
        return cls(
            part_id=_json_string(row["part_id"]),
            path_ids=_json_string_array(row["path_ids"]),
            path=_json_string(row["path"]),
            start_line=start,
            end_line=end,
            source_sha256=_json_string(row["source_sha256"]),
            content_sha256=_json_string(row["content_sha256"]),
        )


@dataclass(frozen=True, slots=True)
class PathStepV9:
    role: str
    path: str
    line: int
    end_line: int
    symbol: str
    source_sha256: str
    node_id: str

    def to_json(self) -> dict[str, object]:
        return {
            "role": self.role,
            "path": self.path,
            "line": self.line,
            "end_line": self.end_line,
            "symbol": self.symbol,
            "source_sha256": self.source_sha256,
            "node_id": self.node_id,
        }

    @classmethod
    def from_json(cls, value: object) -> PathStepV9:
        row = _json_object(
            value,
            frozenset(
                {
                    "role",
                    "path",
                    "line",
                    "end_line",
                    "symbol",
                    "source_sha256",
                    "node_id",
                }
            ),
        )
        line = _json_integer(row["line"])
        end_line = _json_integer(row["end_line"])
        if line < 1 or end_line < line:
            raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
        return cls(
            role=_json_string(row["role"]),
            path=_json_string(row["path"]),
            line=line,
            end_line=end_line,
            symbol=_json_string(row["symbol"]),
            source_sha256=_json_string(row["source_sha256"]),
            node_id=_json_string(row["node_id"]),
        )


@dataclass(frozen=True, slots=True)
class DownstreamPathV9:
    path_id: str
    sink_surface_id: str
    kind: str
    steps: tuple[PathStepV9, ...]
    edge_ids: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "sink_surface_id": self.sink_surface_id,
            "kind": self.kind,
            "assurance": "SYNTACTIC_REACHABILITY",
            "steps": [step.to_json() for step in self.steps],
            "edge_ids": list(self.edge_ids),
        }

    @classmethod
    def from_json(cls, value: object) -> DownstreamPathV9:
        row = _json_object(
            value,
            frozenset(
                {
                    "path_id",
                    "sink_surface_id",
                    "kind",
                    "assurance",
                    "steps",
                    "edge_ids",
                }
            ),
        )
        kind = _json_string(row["kind"])
        if (
            kind
            not in {
                "call_path_v1",
                "stdlib_http_call_path_v5",
                "flask_html_response_v9",
            }
            or row["assurance"] != "SYNTACTIC_REACHABILITY"
        ):
            raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
        return cls(
            path_id=_json_string(row["path_id"]),
            sink_surface_id=_json_string(row["sink_surface_id"]),
            kind=kind,
            steps=tuple(
                PathStepV9.from_json(item) for item in _json_object_array(row["steps"])
            ),
            edge_ids=_json_string_array(row["edge_ids"]),
        )


@dataclass(frozen=True, slots=True)
class PathCertificateV9:
    surface_id: str
    graph_hash: str
    index_hash: str
    applicability_hash: str
    path_ids: tuple[str, ...]
    unresolved_path_ids: tuple[str, ...]
    unresolved_gap_codes: tuple[str, ...]
    context_parts: tuple[ContextPartV9, ...]
    source_complete: bool
    downstream_paths: tuple[DownstreamPathV9, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_surface_path_certificate_v9",
            "surface_id": self.surface_id,
            "graph_hash": self.graph_hash,
            "index_hash": self.index_hash,
            "applicability_hash": self.applicability_hash,
            "path_ids": list(self.path_ids),
            "unresolved_path_ids": list(self.unresolved_path_ids),
            "unresolved_gap_codes": list(self.unresolved_gap_codes),
            "context_parts": [part.to_json() for part in self.context_parts],
            "source_complete": self.source_complete,
            "downstream_paths": [path.to_json() for path in self.downstream_paths],
        }

    @classmethod
    def from_json(cls, value: object) -> PathCertificateV9:
        row = _json_object(
            value,
            frozenset(
                {
                    "kind",
                    "surface_id",
                    "graph_hash",
                    "index_hash",
                    "applicability_hash",
                    "path_ids",
                    "unresolved_path_ids",
                    "unresolved_gap_codes",
                    "context_parts",
                    "source_complete",
                    "downstream_paths",
                }
            ),
        )
        if (
            row["kind"] != "simple_surface_path_certificate_v9"
            or type(row["source_complete"]) is not bool
        ):
            raise ValueError("SURFACE_PATH_CERTIFICATE_INVALID")
        return cls(
            surface_id=_json_string(row["surface_id"]),
            graph_hash=_json_string(row["graph_hash"]),
            index_hash=_json_string(row["index_hash"]),
            applicability_hash=_json_string(row["applicability_hash"]),
            path_ids=_json_string_array(row["path_ids"]),
            unresolved_path_ids=_json_string_array(row["unresolved_path_ids"]),
            unresolved_gap_codes=_json_string_array(row["unresolved_gap_codes"]),
            context_parts=tuple(
                ContextPartV9.from_json(item)
                for item in _json_object_array(row["context_parts"])
            ),
            source_complete=row["source_complete"],
            downstream_paths=tuple(
                DownstreamPathV9.from_json(item)
                for item in _json_object_array(row["downstream_paths"])
            ),
        )


def _rows(graph: Mapping[str, object], key: str) -> list[dict[str, object]]:
    value = graph.get(key)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("SURFACE_PATH_GRAPH_INVALID")
    return cast(list[dict[str, object]], value)


def _source_and_tree(
    index: SurfaceIndex, workspace: Path
) -> tuple[dict[str, tuple[str, ...]], dict[str, ast.Module]]:
    hashes = dict(index.ast_source_hashes)
    if index.index_version != 2 or len(hashes) != len(index.ast_source_hashes):
        raise ValueError("SURFACE_PATH_INDEX_INVALID")
    sources: dict[str, tuple[str, ...]] = {}
    trees: dict[str, ast.Module] = {}
    for path, expected_hash in index.ast_source_hashes:
        raw = _raw_source(workspace, path, expected_hash)
        try:
            text = raw.decode("utf-8")
            trees[path] = ast.parse(text, filename=path)
        except (UnicodeError, SyntaxError, RecursionError) as error:
            raise ValueError("SURFACE_PATH_SOURCE_INVALID") from error
        sources[path] = tuple(text.splitlines())
    return sources, trees


@dataclass(frozen=True, slots=True)
class PathProofReplay:
    """Fresh pinned source checks shared only within one proof replay."""

    index: SurfaceIndex
    workspace: Path
    applicability: AnalyzerApplicabilityV9
    sources: dict[str, tuple[str, ...]]
    trees: dict[str, ast.Module]
    call_index: PythonCallPathIndex


def build_path_proof_replay(
    index: SurfaceIndex,
    workspace: Path,
    *,
    call_index: PythonCallPathIndex | None = None,
) -> PathProofReplay:
    """Validate the pinned checkout once before certifying a batch of surfaces."""

    applicability = assess_optional_analyzers(index, workspace)
    sources, trees = _source_and_tree(index, workspace)
    hashes = dict(index.ast_source_hashes)
    if call_index is None:
        call_index = build_python_call_path_index(workspace, tuple(hashes))
    elif (
        not isinstance(call_index, PythonCallPathIndex)
        or call_index._workspace != workspace.resolve(strict=True)
        or call_index._tracked
        != tuple(sorted(path for path in hashes if path.endswith(".py")))
        or any(
            path not in trees
            or ast.dump(index_tree, include_attributes=True)
            != ast.dump(trees[path], include_attributes=True)
            for path, index_tree in call_index._trees.items()
        )
    ):
        raise ValueError("SURFACE_PATH_CALL_INDEX_INVALID")
    return PathProofReplay(
        index=index,
        workspace=workspace.resolve(strict=True),
        applicability=applicability,
        sources=sources,
        trees=trees,
        call_index=call_index,
    )


def _graph_sources(
    graph: Mapping[str, object],
    index: SurfaceIndex,
    sources: Mapping[str, tuple[str, ...]],
    workspace: Path,
) -> tuple[dict[str, dict[str, object]], set[tuple[str, int]]]:
    indexed = dict(index.ast_source_hashes)
    files: dict[str, dict[str, object]] = {}
    for row in _rows(graph, "source_files"):
        path = row.get("path")
        if (
            not isinstance(path, str)
            or path in files
            or row.get("source_sha256") != indexed.get(path)
            or path not in sources
        ):
            raise ValueError("SURFACE_PATH_GRAPH_SOURCE_INVALID")
        files[path] = row
    redacted: dict[str, tuple[str, ...]] = {}
    for path in files:
        raw = _raw_source(workspace, path, indexed[path])
        try:
            redacted[path] = tuple(
                redact_untrusted_text_preserving_lines(raw)
                .data.decode("utf-8")
                .splitlines()
            )
        except (UnicodeError, ValueError) as error:
            raise ValueError("SURFACE_PATH_GRAPH_SOURCE_INVALID") from error
    locations: set[tuple[str, int]] = set()
    for row in _rows(graph, "source_lines"):
        path, line = row.get("path"), row.get("line")
        if (
            not isinstance(path, str)
            or type(line) is not int
            or line < 1
            or path not in redacted
            or line > len(redacted[path])
            or (path, line) in locations
            or row.get("source_sha256") != indexed[path]
            or row.get("text") != redacted[path][line - 1]
        ):
            raise ValueError("SURFACE_PATH_GRAPH_SOURCE_INVALID")
        locations.add((path, line))
    for row in _rows(graph, "ast_facts"):
        path = row.get("path")
        if not isinstance(path, str) or row.get("source_sha256") != indexed.get(path):
            raise ValueError("SURFACE_PATH_GRAPH_AST_INVALID")
    return files, locations


def _module_bound_names(statement: ast.stmt) -> set[str]:
    class Collector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.names: set[str] = set()

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                self.names.add(node.id)

        def visit_Import(self, node: ast.Import) -> None:
            self.names.update(
                alias.asname or alias.name.split(".")[0] for alias in node.names
            )

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            self.names.update(alias.asname or alias.name for alias in node.names)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.names.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.names.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.names.add(node.name)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name is not None:
                self.names.add(node.name)
            self.generic_visit(node)

    collector = Collector()
    collector.visit(statement)
    return collector.names


def _route_attribute_mutated(statement: ast.stmt, apps: set[str]) -> bool:
    """Fail closed when a registered app's route method may be replaced."""

    for node in ast.walk(statement):
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if (
                node.attr == "route"
                and isinstance(node.value, ast.Name)
                and node.value.id in apps
            ):
                return True
        if isinstance(node, ast.Subscript) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            namespace = node.value
            if (
                isinstance(namespace, ast.Attribute)
                and namespace.attr == "__dict__"
                and isinstance(namespace.value, ast.Name)
                and namespace.value.id in apps
            ):
                return True
        if isinstance(node, ast.Call) and node.args:
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in apps
            ):
                return True
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"__setattr__", "__delattr__"}
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in apps
            ):
                return True
    return False


def _flask_binding(tree: ast.Module, route_line: int) -> bool:
    factories: set[str] = set()
    apps: set[str] = set()
    for statement in tree.body:
        if getattr(statement, "lineno", 0) >= route_line:
            break
        if _route_attribute_mutated(statement, apps):
            return False
        bound = _module_bound_names(statement)
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "flask"
        ):
            factories.difference_update(bound)
            factories.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name in {"Flask", "Blueprint"}
            )
            apps.difference_update(bound)
            continue
        new_app: str | None = None
        if isinstance(statement, ast.Assign):
            if (
                isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Name)
                and statement.value.func.id in factories
                and len(bound) == 1
            ):
                new_app = next(iter(bound))
        apps.difference_update(bound)
        factories.difference_update(bound)
        if new_app is not None:
            apps.add(new_app)
    matches = [
        decorator
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Call)
        and decorator.lineno == route_line
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "route"
        and isinstance(decorator.func.value, ast.Name)
        and decorator.func.value.id in apps
    ]
    return len(matches) == 1


def _request_binding(tree: ast.Module, line: int) -> bool:
    def owner_rebinds_request(
        owner: ast.FunctionDef | ast.AsyncFunctionDef, names: set[str]
    ) -> bool:
        def nested_outer_write(
            scope: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        ) -> bool:
            declarations: set[str] = set()
            writes: set[str] = set()
            descendants: list[
                ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
            ] = []

            class ScopeCollector(ast.NodeVisitor):
                def visit_Name(self, node: ast.Name) -> None:
                    if isinstance(node.ctx, (ast.Store, ast.Del)):
                        writes.add(node.id)

                def visit_Global(self, node: ast.Global) -> None:
                    declarations.update(node.names)

                def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
                    declarations.update(node.names)

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    writes.add(node.name)
                    descendants.append(node)

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    writes.add(node.name)
                    descendants.append(node)

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    writes.add(node.name)
                    descendants.append(node)

                def visit_Import(self, node: ast.Import) -> None:
                    writes.update(_module_bound_names(node))

                def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                    writes.update(_module_bound_names(node))

                def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
                    if node.name is not None:
                        writes.add(node.name)
                    self.generic_visit(node)

            collector = ScopeCollector()
            for statement in scope.body:
                collector.visit(statement)
            return bool(names & declarations & writes) or any(
                nested_outer_write(child) for child in descendants
            )

        class RebindingCollector(ast.NodeVisitor):
            def __init__(self) -> None:
                self.rebound = False

            def visit_Name(self, node: ast.Name) -> None:
                if node.id in names and isinstance(node.ctx, (ast.Store, ast.Del)):
                    self.rebound = True

            def visit_Global(self, node: ast.Global) -> None:
                if names.intersection(node.names):
                    self.rebound = True

            def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
                if names.intersection(node.names):
                    self.rebound = True

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                if node.name in names or nested_outer_write(node):
                    self.rebound = True

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                if node.name in names or nested_outer_write(node):
                    self.rebound = True

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                if node.name in names or nested_outer_write(node):
                    self.rebound = True

            def visit_Import(self, node: ast.Import) -> None:
                if names.intersection(_module_bound_names(node)):
                    self.rebound = True

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                if names.intersection(_module_bound_names(node)):
                    self.rebound = True

            def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
                if node.name in names:
                    self.rebound = True
                self.generic_visit(node)

        collector = RebindingCollector()
        for statement in owner.body:
            collector.visit(statement)
        return collector.rebound

    imports: set[str] = set()
    rebound: set[str] = set()
    for statement in tree.body:
        bound = _module_bound_names(statement)
        direct_imports = (
            {
                alias.asname or alias.name
                for alias in statement.names
                if alias.name == "request"
            }
            if isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "flask"
            else set()
        )
        imports.update(direct_imports)
        rebound.update(bound - direct_imports)
    imports.difference_update(rebound)
    if not imports:
        return False
    owners = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and type(node.end_lineno) is int
        and node.lineno <= line <= node.end_lineno
    ]
    if not owners:
        return False
    if any(
        imports & _function_local_bindings(owner)
        or owner_rebinds_request(owner, imports)
        for owner in owners
    ):
        return False
    return any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in imports
        and node.lineno == line
        for node in ast.walk(tree)
    )


def _sink_call(tree: ast.Module, line: int) -> bool:
    return any(
        isinstance(node, ast.Call) and node.lineno == line for node in ast.walk(tree)
    )


def _enclosing_span(tree: ast.Module, line: int) -> tuple[int, int] | None:
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = min(
            (node.lineno, *(decorator.lineno for decorator in node.decorator_list))
        )
        end = node.end_lineno
        if type(end) is int and start <= line <= end:
            spans.append((start, end))
    return min(spans, key=lambda span: (span[1] - span[0], span[0])) if spans else None


def _context_parts(
    surface_id: str,
    steps_by_path: Mapping[str, list[dict[str, object]]],
    sources: Mapping[str, tuple[str, ...]],
    trees: Mapping[str, ast.Module],
    hashes: Mapping[str, str],
) -> tuple[ContextPartV9, ...]:
    span_owners: dict[tuple[str, int, int], set[str]] = {}
    for path_id, steps in steps_by_path.items():
        for step in steps:
            path, line = step.get("path"), step.get("line")
            if not isinstance(path, str) or type(line) is not int or path not in trees:
                raise ValueError("SURFACE_PATH_CONTEXT_UNAVAILABLE")
            span = _enclosing_span(trees[path], line)
            if span is None:
                raise ValueError("SURFACE_PATH_CONTEXT_UNAVAILABLE")
            span_owners.setdefault((path, *span), set()).add(path_id)
    merged: list[tuple[str, int, int, set[str]]] = []
    for (path, start, end), owners in sorted(span_owners.items()):
        if merged and merged[-1][0] == path and start <= merged[-1][2]:
            prior_path, prior_start, prior_end, prior_owners = merged[-1]
            merged[-1] = (
                prior_path,
                prior_start,
                max(prior_end, end),
                prior_owners | owners,
            )
        else:
            merged.append((path, start, end, set(owners)))
    parts: list[ContextPartV9] = []
    for path, start, end, owners in merged:
        if end > len(sources[path]):
            raise ValueError("SURFACE_PATH_CONTEXT_UNAVAILABLE")
        current = start
        while current <= end:
            stop = current - 1
            size = 0
            while stop < end and stop - current + 1 < _MAX_PART_LINES:
                item = sources[path][stop].encode("utf-8")
                if len(item) > _MAX_PART_BYTES:
                    raise ValueError("SURFACE_PATH_CONTEXT_ATOMIC_LINE_TOO_LARGE")
                if size + len(item) + 1 > _MAX_PART_BYTES:
                    break
                size += len(item) + 1
                stop += 1
            if stop < current:
                raise ValueError("SURFACE_PATH_CONTEXT_UNAVAILABLE")
            content = "\n".join(sources[path][current - 1 : stop])
            content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
            path_ids = tuple(sorted(owners))
            part_id = _id(
                "context",
                {
                    "surface_id": surface_id,
                    "path_ids": path_ids,
                    "path": path,
                    "start_line": current,
                    "end_line": stop,
                    "source_sha256": hashes[path],
                    "content_sha256": content_sha256,
                },
            )
            parts.append(
                ContextPartV9(
                    part_id,
                    path_ids,
                    path,
                    current,
                    stop,
                    hashes[path],
                    content_sha256,
                )
            )
            if len(parts) > _MAX_CONTEXT_PARTS:
                raise ValueError("SURFACE_PATH_CONTEXT_PART_LIMIT")
            current = stop + 1
    return tuple(parts)


def _expected_path(
    raw: dict[str, object],
) -> tuple[str, list[dict[str, object]], list[dict[str, object]]]:
    http = raw.get("kind") == "stdlib_http_call_path_v5"
    path_id = _id("v5-path" if http else "path", raw)
    raw_steps = raw.get("steps")
    if not isinstance(raw_steps, list) or any(
        not isinstance(step, dict) for step in raw_steps
    ):
        raise ValueError("SURFACE_PATH_FRESH_PATH_INVALID")
    steps: list[dict[str, object]] = []
    for ordinal, step in enumerate(raw_steps):
        node_id = (
            _id("v5-node", (path_id, ordinal, step))
            if http
            else _id("node", (step["role"], step["path"], step["line"]))
        )
        steps.append({**step, "node_id": node_id})
    edges = []
    for ordinal, (first, second) in enumerate(zip(steps, steps[1:], strict=False)):
        edge_type = (
            "ENTRY"
            if first["role"] == "ROUTE_ENTRY"
            else {
                "REQUEST_CONTEXT": "TRUST_BOUNDARY",
                "SINK": "SENSITIVE_OPERATION",
            }.get(str(second["role"]), "CALL")
        )
        edges.append(
            {
                "edge_id": _id(
                    "v5-edge" if http else "edge",
                    (path_id, ordinal, first["node_id"], second["node_id"]),
                ),
                "type": edge_type,
                "from_node_id": first["node_id"],
                "to_node_id": second["node_id"],
                "graph_path_id": path_id,
            }
        )
    return path_id, steps, edges


def _applicable_gap(reason: str, applicability: AnalyzerApplicabilityV9) -> bool:
    analyzer = _OPTIONAL_GAPS.get(reason)
    return analyzer is None or applicability.status_for(analyzer) != "NOT_APPLICABLE"


def _graph_gap_codes(
    graph: Mapping[str, object],
    linked_files: set[str],
    surface: AttackSurface,
    source_hashes: Mapping[str, str],
    applicability: AnalyzerApplicabilityV9,
) -> set[str]:
    gaps = _rows(graph, "gaps")
    events = _rows(graph, "gap_events")
    expected = Counter((row.get("path"), row.get("reason")) for row in gaps)
    actual = Counter((row.get("path"), row.get("reason")) for row in events)
    unresolved: set[str] = set()
    if expected != actual:
        unresolved.add("GRAPH_GAP_EVENT_MISMATCH")
    for event in events:
        path, reason = event.get("path"), event.get("reason")
        if not isinstance(path, str) or not isinstance(reason, str):
            unresolved.add("GRAPH_GAP_EVENT_INVALID")
            continue
        if not _applicable_gap(reason, applicability):
            continue
        attribution = event.get("attribution")
        if attribution == "UNLOCATED":
            if path in linked_files or path == surface.path:
                unresolved.add(reason)
            continue
        sink, route = event.get("sink"), event.get("route_entry")
        if (
            attribution != "PINNED_PATH"
            or not isinstance(sink, dict)
            or not isinstance(route, dict)
        ):
            unresolved.add(reason)
            continue
        if any(
            not isinstance(row.get("path"), str)
            or type(row.get("line")) is not int
            or row.get("source_sha256") != source_hashes.get(cast(str, row.get("path")))
            for row in (sink, route)
        ):
            unresolved.add(reason)
        else:
            unresolved.add(reason)
            if (sink["path"], sink["line"]) != (surface.path, surface.line):
                unresolved.add("GRAPH_GAP_EVENT_INVALID")
    return unresolved


def _exact_sink_call(tree: ast.Module, surface: AttackSurface) -> bool:
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and node.lineno == surface.line
    ]
    if surface.detector == "AST":
        calls = [node for node in calls if ast.unparse(node.func) == surface.symbol]
    elif surface.type == "SQL_EXECUTION":
        calls = [
            node
            for node in calls
            if isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "executemany", "executescript"}
        ]
    return len(calls) == 1


def _route_handler_binding(
    tree: ast.Module, route_line: int, handler_line: int
) -> bool:
    if not _flask_binding(tree, route_line):
        return False
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno == handler_line
        and any(
            isinstance(decorator, ast.Call)
            and decorator.lineno == route_line
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "route"
            for decorator in node.decorator_list
        )
        for node in ast.walk(tree)
    )


def _request_anchor_matches(
    surface: AttackSurface, steps: list[dict[str, object]]
) -> bool:
    return any(
        step.get("role") in {"ROUTE_ENTRY", "HANDLER_DEFINITION", "REQUEST_CONTEXT"}
        and (step.get("path"), step.get("line")) == (surface.path, surface.line)
        for step in steps
    )


def _downstream_path(
    surface: AttackSurface,
    sink: AttackSurface,
    raw: dict[str, object],
    trees: Mapping[str, ast.Module],
    hashes: Mapping[str, str],
) -> tuple[str, DownstreamPathV9 | None]:
    path_id = _id("v9-downstream", (sink.surface_id, raw))
    raw_steps = raw.get("steps")
    kind = raw.get("kind")
    if (
        kind not in {"call_path_v1", "stdlib_http_call_path_v5"}
        or raw.get("provenance") != "python_syntax"
        or raw.get("assurance") != "SYNTACTIC_REACHABILITY"
        or raw.get("status") != "AVAILABLE"
        or not isinstance(raw_steps, list)
        or any(not isinstance(step, dict) for step in raw_steps)
    ):
        return path_id, None
    items = cast(list[dict[str, object]], raw_steps)
    route = [i for i, step in enumerate(items) if step.get("role") == "ROUTE_ENTRY"]
    handler = [
        i for i, step in enumerate(items) if step.get("role") == "HANDLER_DEFINITION"
    ]
    request = [
        i for i, step in enumerate(items) if step.get("role") == "REQUEST_CONTEXT"
    ]
    sinks = [i for i, step in enumerate(items) if step.get("role") == "SINK"]
    if (
        len(route) != 1
        or route[0] != 0
        or len(sinks) != 1
        or sinks[0] != len(items) - 1
        or not request
        or not route[0] < min(request) < sinks[0]
        or not _request_anchor_matches(surface, items)
        or (items[-1].get("path"), items[-1].get("line")) != (sink.path, sink.line)
        or not _exact_sink_call(trees[sink.path], sink)
    ):
        return path_id, None
    route_path, route_line = items[0].get("path"), items[0].get("line")
    if (
        not isinstance(route_path, str)
        or type(route_line) is not int
        or route_path not in trees
    ):
        return path_id, None
    if kind == "call_path_v1":
        if len(handler) != 1 or not route[0] < handler[0] < min(request):
            return path_id, None
        handler_path, handler_line = (
            items[handler[0]].get("path"),
            items[handler[0]].get("line"),
        )
        if (
            route_path != handler_path
            or type(handler_line) is not int
            or not _route_handler_binding(trees[route_path], route_line, handler_line)
            or not any(
                isinstance(items[i].get("path"), str)
                and type(items[i].get("line")) is int
                and items[i]["path"] in trees
                and _request_binding(
                    trees[cast(str, items[i]["path"])],
                    cast(int, items[i]["line"]),
                )
                for i in request
            )
        ):
            return path_id, None
    elif (
        handler
        or not any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno == route_line
            and node.name.startswith("do_")
            for node in ast.walk(trees[route_path])
        )
        or items[0].get("stdlib_handler") != "http.server.BaseHTTPRequestHandler"
    ):
        return path_id, None
    steps: list[PathStepV9] = []
    for ordinal, raw_step in enumerate(items):
        role, path, line = (
            raw_step.get("role"),
            raw_step.get("path"),
            raw_step.get("line"),
        )
        end_line, symbol = raw_step.get("end_line"), raw_step.get("symbol")
        if (
            not isinstance(role, str)
            or not isinstance(path, str)
            or path not in hashes
            or type(line) is not int
            or line < 1
            or type(end_line) is not int
            or end_line < line
            or not isinstance(symbol, str)
            or (
                kind == "stdlib_http_call_path_v5"
                and raw_step.get("source_sha256") != hashes[path]
            )
        ):
            return path_id, None
        steps.append(
            PathStepV9(
                role=role,
                path=path,
                line=line,
                end_line=end_line,
                symbol=symbol,
                source_sha256=hashes[path],
                node_id=_id("v9-node", (path_id, ordinal, raw_step, hashes[path])),
            )
        )
    edge_ids = tuple(
        _id("v9-edge", (path_id, ordinal, first.node_id, second.node_id))
        for ordinal, (first, second) in enumerate(zip(steps, steps[1:], strict=False))
    )
    return path_id, DownstreamPathV9(
        path_id=path_id,
        sink_surface_id=sink.surface_id,
        kind=kind,
        steps=tuple(steps),
        edge_ids=edge_ids,
    )


def _flask_html_response_path(
    surface: AttackSurface,
    workspace: Path,
    trees: Mapping[str, ast.Module],
    hashes: Mapping[str, str],
) -> DownstreamPathV9 | None:
    """Derive one narrow HTML route→request→response path from pinned source."""

    tree = trees.get(surface.path)
    source_hash = hashes.get(surface.path)
    if tree is None or source_hash is None:
        return None
    source = _raw_source(workspace, surface.path, source_hash)
    matches: list[DownstreamPathV9] = []
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        for decorator in function.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            route_line = decorator.lineno
            for statement in function.body:
                if not isinstance(statement, ast.Assign):
                    continue
                request_line = statement.lineno
                if surface.line not in {route_line, request_line}:
                    continue
                proof = prove_flask_html_response_flow_v9(
                    source,
                    path=surface.path,
                    expected_sha256=source_hash,
                    route_line=route_line,
                    request_line=request_line,
                )
                if proof is None:
                    continue
                path_id = _id(
                    "v9-html-path",
                    {
                        "surface_id": surface.surface_id,
                        "path": proof.path,
                        "source_sha256": proof.source_sha256,
                        "route_line": proof.route_line,
                        "request_line": proof.request_line,
                        "request_key": proof.request_key,
                        "escape_line": proof.escape_line,
                        "interpolation_line": proof.interpolation_line,
                        "response_line": proof.response_line,
                        "classification": proof.classification,
                    },
                )
                positions: list[tuple[str, int, str]] = [
                    ("ROUTE_ENTRY", proof.route_line, "app.route"),
                    ("HANDLER_DEFINITION", function.lineno, function.name),
                    ("REQUEST_CONTEXT", proof.request_line, "request.get"),
                ]
                if proof.escape_line is not None:
                    positions.append(
                        ("ESCAPE_CALL_OBSERVED", proof.escape_line, "html.escape")
                    )
                positions.extend(
                    [
                        ("INTERPOLATION", proof.interpolation_line, "f-string"),
                        ("SINK", proof.response_line, "make_response:text/html"),
                    ]
                )
                steps = tuple(
                    PathStepV9(
                        role=role,
                        path=surface.path,
                        line=line,
                        end_line=line,
                        symbol=symbol,
                        source_sha256=source_hash,
                        node_id=_id(
                            "v9-html-node",
                            (path_id, ordinal, role, line, symbol, source_hash),
                        ),
                    )
                    for ordinal, (role, line, symbol) in enumerate(positions)
                )
                edge_ids = tuple(
                    _id(
                        "v9-html-edge",
                        (path_id, ordinal, first.node_id, second.node_id),
                    )
                    for ordinal, (first, second) in enumerate(
                        zip(steps, steps[1:], strict=False)
                    )
                )
                matches.append(
                    DownstreamPathV9(
                        path_id=path_id,
                        sink_surface_id=_id(
                            "v9-html-sink",
                            (surface.path, proof.response_line, source_hash),
                        ),
                        kind="flask_html_response_v9",
                        steps=steps,
                        edge_ids=edge_ids,
                    )
                )
    return matches[0] if len(matches) == 1 else None


def _historical_route_paths_valid(
    graph: Mapping[str, object],
    raw_paths: tuple[dict[str, object], ...],
) -> bool:
    fresh = {
        path_id: (raw.get("kind"), steps, edges)
        for raw in raw_paths
        if raw.get("kind") in {"call_path_v1", "candidate_downstream_context_v1"}
        and raw.get("assurance") == "SYNTACTIC_REACHABILITY"
        for path_id, steps, edges in (_expected_path(raw),)
    }
    nodes = {row.get("node_id"): row for row in _rows(graph, "nodes")}
    edges_by_id = {row.get("edge_id"): row for row in _rows(graph, "edges")}
    for row in _rows(graph, "paths"):
        if row.get("assurance") != "SYNTACTIC_REACHABILITY":
            continue
        candidate_id = row.get("path_id")
        expected = fresh.get(candidate_id) if isinstance(candidate_id, str) else None
        if expected is None or row.get("provenance") != "python_syntax":
            return False
        kind, steps, edges = expected
        if (
            row.get("kind") != kind
            or row.get("steps") != steps
            or row.get("edge_ids") != [edge["edge_id"] for edge in edges]
            or any(nodes.get(step["node_id"]) != step for step in steps)
            or any(edges_by_id.get(edge["edge_id"]) != edge for edge in edges)
        ):
            return False
    return True


def _certify_request_entry_paths(
    index: SurfaceIndex,
    surface: AttackSurface,
    graph: Mapping[str, object],
    applicability: AnalyzerApplicabilityV9,
    workspace: Path,
    sources: Mapping[str, tuple[str, ...]],
    trees: Mapping[str, ast.Module],
    hashes: Mapping[str, str],
    call_index: PythonCallPathIndex,
) -> PathCertificateV9:
    own = call_index.for_candidate(
        _surface_candidate(surface), include_downstream=True, include_enclosing=True
    )
    path_ids: set[str] = set()
    unresolved_paths: set[str] = set()
    unresolved_gaps: set[str] = set()
    downstream: list[DownstreamPathV9] = []
    steps_by_path: dict[str, list[dict[str, object]]] = {}
    linked_files: set[str] = set()
    if not _historical_route_paths_valid(graph, own.paths):
        unresolved_gaps.add("HISTORICAL_GRAPH_PATH_INVALID")
    for sink in index.surfaces:
        if (
            sink.surface_id == surface.surface_id
            or surface_review_contract(sink.type) != "SINK"
        ):
            continue
        result = call_index.for_candidate(
            _surface_candidate(sink), include_downstream=True, include_enclosing=True
        )
        http_result = (
            verified_http_paths(workspace, hashes, sink)
            if applicability.status_for("stdlib_http") == "APPLICABLE"
            else None
        )
        relevant = False
        relevant_http = False
        for raw in (*result.paths, *(http_result.paths if http_result else ())):
            raw_steps = raw.get("steps")
            if (
                raw.get("kind") not in {"call_path_v1", "stdlib_http_call_path_v5"}
                or not isinstance(raw_steps, list)
                or any(not isinstance(step, dict) for step in raw_steps)
                or not _request_anchor_matches(
                    surface, cast(list[dict[str, object]], raw_steps)
                )
            ):
                continue
            relevant = True
            relevant_http |= raw.get("kind") == "stdlib_http_call_path_v5"
            path_id, certified = _downstream_path(surface, sink, raw, trees, hashes)
            path_ids.add(path_id)
            if certified is None:
                unresolved_paths.add(path_id)
                continue
            downstream.append(certified)
            steps_by_path[path_id] = [step.to_json() for step in certified.steps]
            linked_files.update(step.path for step in certified.steps)
        if relevant:
            unresolved_gaps.update(
                reason
                for reason in result.gaps
                if _applicable_gap(reason, applicability)
                and reason not in _REPAIRABLE_CONTEXT_GAPS
                and (not relevant_http or reason not in _ROUTE_ANCHOR_GAPS)
            )
            if http_result is not None:
                unresolved_gaps.update(http_result.gaps)
        elif sink.path == surface.path:
            # A bounded/dynamic search that did not produce a path cannot be
            # interpreted as proof that this entry does not reach the sink.
            unresolved_gaps.update(
                reason
                for reason in result.gaps
                if reason not in _REPAIRABLE_CONTEXT_GAPS
                and _applicable_gap(reason, applicability)
            )
    html_path = _flask_html_response_path(surface, workspace, trees, hashes)
    if html_path is not None:
        path_ids.add(html_path.path_id)
        downstream.append(html_path)
        steps_by_path[html_path.path_id] = [step.to_json() for step in html_path.steps]
        linked_files.update(step.path for step in html_path.steps)
    context_parts: tuple[ContextPartV9, ...] = ()
    downstream_repaired = False
    context_steps_by_path = {
        path_id: list(steps) for path_id, steps in steps_by_path.items()
    }
    if "DOWNSTREAM_CALLEE_BODY_TRUNCATED" in own.gaps:
        downstream_paths = [
            raw
            for raw in own.paths
            if raw.get("kind") == "candidate_downstream_context_v1"
        ]
        downstream_steps: list[dict[str, object]] = []
        downstream_valid = bool(downstream_paths)
        for raw in downstream_paths:
            raw_steps = raw.get("steps")
            if (
                raw.get("provenance") != "python_syntax"
                or raw.get("assurance") != "SYNTACTIC_REACHABILITY"
                or raw.get("status") != "AVAILABLE"
                or not isinstance(raw_steps, list)
                or any(not isinstance(step, dict) for step in raw_steps)
            ):
                downstream_valid = False
                break
            steps = cast(list[dict[str, object]], raw_steps)
            if (
                not steps
                or steps[0].get("role") != "CANDIDATE"
                or (steps[0].get("path"), steps[0].get("line"))
                != (surface.path, surface.line)
                or not any(step.get("role") == "CALLEE_BODY_LINE" for step in steps)
            ):
                downstream_valid = False
                break
            downstream_steps.extend(steps)
        if downstream_valid and downstream_steps and context_steps_by_path:
            for steps in context_steps_by_path.values():
                steps.extend(downstream_steps)
            downstream_repaired = True
    if steps_by_path:
        try:
            context_parts = _context_parts(
                surface.surface_id, context_steps_by_path, sources, trees, hashes
            )
        except ValueError as error:
            unresolved_gaps.add(str(error))
    graph_gaps = _graph_gap_codes(graph, linked_files, surface, hashes, applicability)
    if downstream and context_parts:
        # A synthetic HTML path proves only its own linear response. A same-file
        # unlocated graph gap may describe another branch or downstream call.
        if html_path is None:
            graph_gaps.difference_update(_ROUTE_ANCHOR_GAPS)
        if "ENCLOSING_CONTEXT_TRUNCATED" in own.gaps:
            graph_gaps.discard("ENCLOSING_CONTEXT_TRUNCATED")
        if downstream_repaired:
            graph_gaps.discard("DOWNSTREAM_CALLEE_BODY_TRUNCATED")
    unresolved_gaps.update(graph_gaps)
    repairable_gaps = set(_REPAIRABLE_CONTEXT_GAPS)
    if not downstream_repaired:
        repairable_gaps.discard("DOWNSTREAM_CALLEE_BODY_TRUNCATED")
    resolved_route_gaps = (
        {
            "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
            "SINK_ENCLOSING_FUNCTION_UNAVAILABLE",
        }
        if html_path is not None
        else _ROUTE_ANCHOR_GAPS
    )
    unresolved_gaps.update(
        reason
        for reason in own.gaps
        if _applicable_gap(reason, applicability)
        and reason not in resolved_route_gaps
        and (not context_parts or reason not in repairable_gaps)
    )
    if not downstream:
        unresolved_gaps.add("DOWNSTREAM_SINK_NOT_PROVEN")
    for path, expected_hash in index.ast_source_hashes:
        _raw_source(workspace, path, expected_hash)
    ordered_paths = tuple(sorted(path_ids))
    ordered_downstream = tuple(sorted(downstream, key=lambda item: item.path_id))
    if unresolved_gaps:
        unresolved_paths.update(path_ids)
    return PathCertificateV9(
        surface_id=surface.surface_id,
        graph_hash=_digest(graph),
        index_hash=_digest(index.to_json()),
        applicability_hash=_digest(applicability.to_json()),
        path_ids=ordered_paths,
        unresolved_path_ids=tuple(sorted(unresolved_paths)),
        unresolved_gap_codes=tuple(sorted(unresolved_gaps)),
        context_parts=context_parts,
        source_complete=bool(downstream)
        and len(downstream) == len(path_ids)
        and not unresolved_paths
        and not unresolved_gaps
        and bool(context_parts),
        downstream_paths=ordered_downstream,
    )


def certify_surface_paths(
    index: SurfaceIndex,
    surface: AttackSurface,
    graph: Mapping[str, object],
    applicability: AnalyzerApplicabilityV9,
    workspace: Path,
    *,
    call_index: PythonCallPathIndex | None = None,
    replay: PathProofReplay | None = None,
) -> PathCertificateV9:
    if (
        surface not in index.surfaces
        or graph.get("kind") != "simple_surface_evidence_graph_v5"
        or graph.get("anchor")
        != {
            "surface_id": surface.surface_id,
            "path": surface.path,
            "line": surface.line,
        }
        or graph.get("scope_fingerprint") != index.scope_fingerprint
        or graph.get("index_hash") != _digest(index.to_json())
        or graph.get("ast_manifest_hash") != index.ast_manifest_hash
    ):
        raise ValueError("SURFACE_PATH_SCOPE_INVALID")
    if replay is None:
        replay = build_path_proof_replay(index, workspace, call_index=call_index)
    elif (
        replay.index is not index
        or replay.workspace != workspace.resolve(strict=True)
        or (call_index is not None and call_index is not replay.call_index)
    ):
        raise ValueError("SURFACE_PATH_REPLAY_INVALID")
    if replay.applicability != applicability:
        raise ValueError("SURFACE_PATH_APPLICABILITY_INVALID")
    hashes = dict(index.ast_source_hashes)
    sources, trees = replay.sources, replay.trees
    files, locations = _graph_sources(graph, index, sources, workspace)
    call_index = replay.call_index
    if surface.type == "REQUEST_ENTRY":
        return _certify_request_entry_paths(
            index,
            surface,
            graph,
            applicability,
            workspace,
            sources,
            trees,
            hashes,
            call_index,
        )
    raw_paths = call_index.for_candidate(
        _surface_candidate(surface), include_downstream=True, include_enclosing=True
    )
    http_paths = (
        verified_http_paths(workspace, hashes, surface)
        if applicability.status_for("stdlib_http") == "APPLICABLE"
        else None
    )
    fresh: dict[str, tuple[list[dict[str, object]], list[dict[str, object]]]] = {}
    all_raw = [
        raw
        for raw in raw_paths.paths
        if raw.get("kind") == "call_path_v1"
        and raw.get("assurance") == "SYNTACTIC_REACHABILITY"
    ]
    if http_paths is not None:
        all_raw.extend(
            raw
            for raw in http_paths.paths
            if raw.get("kind") == "stdlib_http_call_path_v5"
            and raw.get("assurance") == "SYNTACTIC_REACHABILITY"
            and raw.get("status") == "AVAILABLE"
        )
    for raw in all_raw:
        fresh_path_id, fresh_steps, fresh_edges = _expected_path(raw)
        fresh[fresh_path_id] = (fresh_steps, fresh_edges)
    nodes = {row.get("node_id"): row for row in _rows(graph, "nodes")}
    graph_edges = {row.get("edge_id"): row for row in _rows(graph, "edges")}
    relevant: dict[str, dict[str, object]] = {}
    for graph_path in _rows(graph, "paths"):
        candidate_id, candidate_steps = (
            graph_path.get("path_id"),
            graph_path.get("steps"),
        )
        if not isinstance(candidate_id, str) or not isinstance(candidate_steps, list):
            raise ValueError("SURFACE_PATH_GRAPH_INVALID")
        if graph_path.get("assurance") != "SYNTACTIC_REACHABILITY":
            continue
        if any(
            isinstance(step, dict)
            and step.get("role") == "SINK"
            and (step.get("path"), step.get("line")) == (surface.path, surface.line)
            for step in candidate_steps
        ):
            if candidate_id in relevant:
                raise ValueError("SURFACE_PATH_GRAPH_INVALID")
            relevant[candidate_id] = graph_path
    path_ids = tuple(sorted(set(fresh) | set(relevant)))
    unresolved_paths: set[str] = set()
    steps_by_path: dict[str, list[dict[str, object]]] = {}
    linked_files: set[str] = set()
    for path_id in path_ids:
        expected = fresh.get(path_id)
        selected_path = relevant.get(path_id)
        if expected is None or selected_path is None:
            unresolved_paths.add(path_id)
            continue
        expected_steps, expected_edges = expected
        actual_steps = selected_path.get("steps")
        actual_edge_ids = selected_path.get("edge_ids")
        if (
            selected_path.get("kind")
            not in {"call_path_v1", "stdlib_http_call_path_v5"}
            or selected_path.get("provenance") != "python_syntax"
            or actual_steps != expected_steps
            or actual_edge_ids != [edge["edge_id"] for edge in expected_edges]
            or selected_path.get("blocking_gaps", []) not in ([],)
            or any(nodes.get(step["node_id"]) != step for step in expected_steps)
            or any(graph_edges.get(edge["edge_id"]) != edge for edge in expected_edges)
            or any(
                (step.get("path"), step.get("line")) not in locations
                or step.get("path") not in files
                for step in expected_steps
            )
        ):
            unresolved_paths.add(path_id)
            continue
        route = [
            i
            for i, step in enumerate(expected_steps)
            if step.get("role") == "ROUTE_ENTRY"
        ]
        request = [
            i
            for i, step in enumerate(expected_steps)
            if step.get("role") == "REQUEST_CONTEXT"
        ]
        sinks = [
            i for i, step in enumerate(expected_steps) if step.get("role") == "SINK"
        ]
        if (
            len(route) != 1
            or not request
            or len(sinks) != 1
            or not any(route[0] < boundary < sinks[0] for boundary in request)
            or sinks[0] != len(expected_steps) - 1
            or (
                selected_path.get("kind") == "call_path_v1"
                and (
                    not _flask_binding(
                        trees[cast(str, expected_steps[route[0]]["path"])],
                        cast(int, expected_steps[route[0]]["line"]),
                    )
                    or not any(
                        _request_binding(
                            trees[cast(str, expected_steps[i]["path"])],
                            cast(int, expected_steps[i]["line"]),
                        )
                        for i in request
                    )
                )
            )
            or not _sink_call(trees[surface.path], surface.line)
            or not any(
                row.get("path") == surface.path
                and row.get("line") == surface.line
                and row.get("kind") == "Call"
                for row in _rows(graph, "ast_facts")
            )
        ):
            unresolved_paths.add(path_id)
            continue
        steps_by_path[path_id] = expected_steps
        linked_files.update(cast(str, step["path"]) for step in expected_steps)
    context_parts: tuple[ContextPartV9, ...] = ()
    context_gap: set[str] = set()
    downstream_repaired = False
    context_steps_by_path = {
        path_id: list(steps) for path_id, steps in steps_by_path.items()
    }
    if "DOWNSTREAM_CALLEE_BODY_TRUNCATED" in raw_paths.gaps:
        downstream_paths = [
            raw
            for raw in raw_paths.paths
            if raw.get("kind") == "candidate_downstream_context_v1"
        ]
        downstream_steps: list[dict[str, object]] = []
        downstream_valid = bool(downstream_paths)
        for raw in downstream_paths:
            raw_steps = raw.get("steps")
            if (
                raw.get("assurance") != "SYNTACTIC_REACHABILITY"
                or not isinstance(raw_steps, list)
                or any(not isinstance(step, dict) for step in raw_steps)
                or not any(
                    step.get("role") == "CALLEE_BODY_LINE"
                    for step in cast(list[dict[str, object]], raw_steps)
                )
            ):
                downstream_valid = False
                break
            downstream_steps.extend(cast(list[dict[str, object]], raw_steps))
        if downstream_valid and downstream_steps:
            for steps in context_steps_by_path.values():
                steps.extend(downstream_steps)
            downstream_repaired = bool(context_steps_by_path)
    if steps_by_path:
        try:
            context_parts = _context_parts(
                surface.surface_id, context_steps_by_path, sources, trees, hashes
            )
        except ValueError as error:
            context_gap.add(str(error))
    graph_gaps = _graph_gap_codes(graph, linked_files, surface, hashes, applicability)
    repairable_gaps = set(raw_paths.gaps) & _REPAIRABLE_CONTEXT_GAPS
    if not downstream_repaired:
        repairable_gaps.discard("DOWNSTREAM_CALLEE_BODY_TRUNCATED")
    if context_parts:
        graph_gaps.difference_update(repairable_gaps)
    fresh_gaps = {
        reason
        for reason in raw_paths.gaps
        if _applicable_gap(reason, applicability)
        and (not context_parts or reason not in repairable_gaps)
    }
    if http_paths is not None:
        fresh_gaps.update(http_paths.gaps)
        if any(
            path.get("kind") == "stdlib_http_call_path_v5" for path in relevant.values()
        ):
            fresh_gaps.discard("SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE")
            fresh_gaps.discard("SINK_ENCLOSING_FUNCTION_UNAVAILABLE")
    unresolved_gaps = tuple(sorted(graph_gaps | fresh_gaps | context_gap))
    if unresolved_gaps:
        unresolved_paths.update(path_ids)
    return PathCertificateV9(
        surface_id=surface.surface_id,
        graph_hash=_digest(graph),
        index_hash=_digest(index.to_json()),
        applicability_hash=_digest(applicability.to_json()),
        path_ids=path_ids,
        unresolved_path_ids=tuple(sorted(unresolved_paths)),
        unresolved_gap_codes=unresolved_gaps,
        context_parts=context_parts,
        source_complete=bool(path_ids)
        and not unresolved_paths
        and not unresolved_gaps
        and bool(context_parts),
    )


def validate_path_certificate(
    index: SurfaceIndex,
    surface: AttackSurface,
    graph: Mapping[str, object],
    applicability: AnalyzerApplicabilityV9,
    workspace: Path,
    certificate: PathCertificateV9,
    *,
    call_index: PythonCallPathIndex | None = None,
    replay: PathProofReplay | None = None,
) -> bool:
    if not isinstance(certificate, PathCertificateV9):
        return False
    try:
        return certificate == certify_surface_paths(
            index,
            surface,
            graph,
            applicability,
            workspace,
            call_index=call_index,
            replay=replay,
        )
    except (OSError, TypeError, ValueError):
        return False
