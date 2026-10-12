"""Pinned, redacted syntax context for one previously insufficient surface.

The graph is navigation evidence. A call edge is syntactic reachability, not
taint flow or a vulnerability verdict; unresolved edges remain explicit gaps.
"""

from __future__ import annotations

import ast
import hashlib
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import AttackSurface, SurfaceIndex
from .call_path_facts import (
    PythonCallPathIndex,
    build_python_call_path_index,
    call_path_step_locations,
)
from .candidates import CandidateOrigin, StaticCandidate
from .facts import safe_tracked_file
from .file_context import MAX_CONTEXT_SOURCE_BYTES, prepare_file_context

_MAX_ATOMIC_LINE_BYTES = 64 * 1024


def _id(prefix: str, value: object) -> str:
    return f"{prefix}-{hashlib.sha256(canonical_bytes(value)).hexdigest()[:24]}"


def _raw_source(workspace: Path, path: str, expected_hash: str) -> bytes:
    source = safe_tracked_file(workspace, path)
    if source is None:
        raise ValueError("SURFACE_GRAPH_SOURCE_UNSAFE")
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or source.is_symlink():
            raise ValueError("SURFACE_GRAPH_SOURCE_UNSAFE")
        if before.st_size > MAX_CONTEXT_SOURCE_BYTES:
            raise ValueError("SURFACE_GRAPH_SOURCE_TOO_LARGE")
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            current = os.fstat(stream.fileno())
            if not stat.S_ISREG(current.st_mode) or (
                before.st_dev,
                before.st_ino,
            ) != (current.st_dev, current.st_ino):
                raise ValueError("SURFACE_GRAPH_SOURCE_CHANGED")
            data = stream.read(MAX_CONTEXT_SOURCE_BYTES + 1)
    except OSError as error:
        raise ValueError("SURFACE_GRAPH_SOURCE_UNSAFE") from error
    if len(data) > MAX_CONTEXT_SOURCE_BYTES:
        raise ValueError("SURFACE_GRAPH_SOURCE_TOO_LARGE")
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("SURFACE_GRAPH_SOURCE_HASH_MISMATCH")
    return data


def _enclosing_span(tree: ast.Module, line: int) -> tuple[int, int] | None:
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", None)
        if type(start) is not int or type(end) is not int:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = min(
                (start, *(item.lineno for item in node.decorator_list)),
            )
        if start <= line <= end:
            spans.append((start, end))
    if not spans:
        for node in tree.body:
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if type(start) is int and type(end) is int and start <= line <= end:
                spans.append((start, end))
    if not spans:
        return None
    return min(spans, key=lambda span: (span[1] - span[0], span[0]))


def _surface_candidate(surface: AttackSurface) -> StaticCandidate:
    if not surface.evidence_refs:
        raise ValueError("SURFACE_GRAPH_EVIDENCE_REF_MISSING")
    evidence_ref = surface.evidence_refs[0]
    return StaticCandidate(
        candidate_id=surface.surface_id,
        kind="HINT",
        path=surface.path,
        line=surface.line,
        end_line=surface.line,
        evidence_ref=evidence_ref,
        origins=(
            CandidateOrigin(
                engine="surface",
                rule_id=surface.detector,
                artifact_ref=evidence_ref,
                result_index=0,
            ),
        ),
        evidence_key=surface.surface_id,
    )


def extract_surface_graph_v4(
    index: SurfaceIndex,
    surface: AttackSurface,
    ast_summary: Mapping[str, object],
    manifest_index: Mapping[str, Mapping[str, object]],
    workspace: Path,
    artifacts: SimpleArtifactRepository,
    *,
    max_nodes: int = 256,
    max_edges: int = 512,
    call_index: PythonCallPathIndex | None = None,
) -> dict[str, object]:
    """Return one bounded graph; never invent a route or expose raw source."""

    if (
        index.index_version != 2
        or surface not in index.surfaces
        or surface.line < 1
        or max_nodes < 1
        or max_edges < 1
        or hashlib.sha256(canonical_bytes(ast_summary)).hexdigest()
        != index.ast_manifest_hash
    ):
        raise ValueError("SURFACE_GRAPH_SCOPE_INVALID")
    source_hashes = dict(index.ast_source_hashes)
    if len(source_hashes) != len(index.ast_source_hashes):
        raise ValueError("SURFACE_GRAPH_SCOPE_INVALID")
    if surface.path not in source_hashes:
        reason = "AST_SOURCE_NOT_INDEXED"
        for key, label in (
            ("oversize_paths", "AST_SOURCE_TOO_LARGE"),
            ("parse_errors", "AST_PARSE_ERROR"),
        ):
            paths = ast_summary.get(key)
            if isinstance(paths, list) and surface.path in paths:
                reason = label
                break
        return {
            "kind": "simple_surface_evidence_graph_v4",
            "anchor": {
                "surface_id": surface.surface_id,
                "path": surface.path,
                "line": surface.line,
            },
            "scope_fingerprint": index.scope_fingerprint,
            "index_hash": hashlib.sha256(canonical_bytes(index.to_json())).hexdigest(),
            "ast_manifest_hash": index.ast_manifest_hash,
            "source_files": [],
            "source_lines": [],
            "ast_facts": [],
            "nodes": [],
            "edges": [],
            "paths": [],
            "gaps": [{"path": surface.path, "reason": reason}],
        }
    for path, expected_hash in index.ast_source_hashes:
        entry = manifest_index.get(path)
        if entry is None or entry.get("source_sha256") != expected_hash:
            raise ValueError("SURFACE_GRAPH_AST_SOURCE_MISMATCH")
        # The shared call index parses every indexed module, not only paths
        # selected for the resulting graph. Bind all of its inputs first.
        _raw_source(workspace, path, expected_hash)

    call_index = call_index or build_python_call_path_index(
        workspace, tuple(source_hashes)
    )
    calls = call_index.for_candidate(
        _surface_candidate(surface), include_downstream=True, include_enclosing=True
    )
    raw_paths = [
        path
        for path in calls.paths
        if isinstance(path.get("steps"), list)
        and path.get("assurance") == "SYNTACTIC_REACHABILITY"
    ]
    locations = set(call_path_step_locations(raw_paths))
    locations.add((surface.path, surface.line))
    paths_by_file: dict[str, set[int]] = {}
    for path, line in locations:
        paths_by_file.setdefault(path, set()).add(line)

    gaps: set[tuple[str, str]] = set()
    for gap in calls.gaps:
        mapped = (
            "DYNAMIC_DISPATCH_UNRESOLVED"
            if gap == "UNRESOLVED_DYNAMIC_DISPATCH"
            else gap
        )
        gaps.add((surface.path, mapped))
    files: list[dict[str, object]] = []
    lines: list[dict[str, object]] = []
    facts: list[dict[str, object]] = []
    verified_locations: set[tuple[str, int]] = set()
    for path in sorted(paths_by_file):
        entry = manifest_index.get(path)
        if path not in source_hashes or entry is None:
            gaps.add((path, "RELATED_PATH_NOT_INDEXED"))
            continue
        expected_hash = source_hashes[path]
        prepared = prepare_file_context(
            artifacts,
            ast_summary,
            workspace,
            path,
            manifest_index=manifest_index,
        )
        if prepared.source_unavailable_reason is not None:
            gaps.add((path, prepared.source_unavailable_reason))
            continue
        if prepared.ast_unavailable_reason is not None or prepared.ast_file_ref is None:
            gaps.add((path, prepared.ast_unavailable_reason or "AST_FACTS_UNAVAILABLE"))
            continue
        if prepared.source_sha256 != expected_hash:
            raise ValueError("SURFACE_GRAPH_SOURCE_HASH_MISMATCH")
        raw = _raw_source(workspace, path, expected_hash)
        try:
            tree = ast.parse(raw.decode("utf-8"), filename=path)
        except (UnicodeError, SyntaxError, RecursionError) as error:
            raise ValueError("SURFACE_GRAPH_AST_SOURCE_MISMATCH") from error
        selected: set[int] = set()
        for location in sorted(paths_by_file[path]):
            span = _enclosing_span(tree, location)
            if span is None:
                gaps.add((path, "LOCATION_BEYOND_SOURCE"))
                continue
            selected.update(range(span[0], span[1] + 1))
        files.append(
            {
                "path": path,
                "source_sha256": expected_hash,
                "ast_ref": prepared.ast_file_ref.model_dump(mode="json"),
                "ast_sha256": prepared.ast_file_ref.content_hash,
                "redaction_categories": list(prepared.redaction_categories),
            }
        )
        for line in sorted(selected):
            if line > len(prepared.source_lines):
                gaps.add((path, "LOCATION_BEYOND_SOURCE"))
                continue
            content = prepared.source_lines[line - 1]
            if len(content.encode("utf-8")) > _MAX_ATOMIC_LINE_BYTES:
                gaps.add((path, "ATOMIC_SOURCE_LINE_TOO_LARGE"))
                continue
            lines.append(
                {
                    "line_id": _id("line", (path, line, expected_hash)),
                    "path": path,
                    "line": line,
                    "text": content,
                    "source_sha256": expected_hash,
                }
            )
            verified_locations.add((path, line))
        for fact in prepared.ast_facts:
            if fact["line"] in selected:
                facts.append(
                    {
                        **fact,
                        "fact_id": _id("fact", (path, fact, expected_hash)),
                        "source_sha256": expected_hash,
                        "ast_sha256": prepared.ast_file_ref.content_hash,
                    }
                )

    if (surface.path, surface.line) not in verified_locations:
        gaps.add((surface.path, "ANCHOR_SOURCE_UNAVAILABLE"))
    if len(lines) + len(facts) > max_nodes:
        gaps.add((surface.path, "CONTEXT_BUDGET_EXHAUSTED"))
        lines = lines[:max_nodes]
        facts = facts[: max(0, max_nodes - len(lines))]
        verified_locations = {
            (cast(str, row["path"]), cast(int, row["line"])) for row in lines
        }

    graph_paths: list[dict[str, object]] = []
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []
    for raw_path in raw_paths:
        steps = raw_path["steps"]
        if not isinstance(steps, list):
            continue
        if any(
            not isinstance(step, dict)
            or (step.get("path"), step.get("line")) not in verified_locations
            for step in steps
        ):
            gaps.add((surface.path, "PATH_SOURCE_UNAVAILABLE"))
            continue
        path_id = _id("path", raw_path)
        path_steps: list[dict[str, object]] = []
        path_edges: list[str] = []
        for step in steps:
            assert isinstance(step, dict)
            node_id = _id("node", (step["role"], step["path"], step["line"]))
            node = {**step, "node_id": node_id}
            nodes[node_id] = node
            path_steps.append(node)
        for ordinal, (first, second) in enumerate(
            zip(path_steps, path_steps[1:], strict=False)
        ):
            role = second["role"]
            edge_type = (
                "ENTRY"
                if first["role"] == "ROUTE_ENTRY"
                else {
                    "REQUEST_CONTEXT": "TRUST_BOUNDARY",
                    "SINK": "SENSITIVE_OPERATION",
                }.get(str(role), "CALL")
            )
            edge_id = _id(
                "edge",
                (path_id, ordinal, first["node_id"], second["node_id"]),
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
    if len(nodes) + len(lines) + len(facts) > max_nodes or len(edges) > max_edges:
        gaps.add((surface.path, "CONTEXT_BUDGET_EXHAUSTED"))
        graph_paths = []
        nodes.clear()
        edges.clear()
    if not graph_paths:
        gaps.add((surface.path, "EXTERNAL_IMPLEMENTATION_UNAVAILABLE"))

    return {
        "kind": "simple_surface_evidence_graph_v4",
        "anchor": {
            "surface_id": surface.surface_id,
            "path": surface.path,
            "line": surface.line,
        },
        "scope_fingerprint": index.scope_fingerprint,
        "index_hash": hashlib.sha256(canonical_bytes(index.to_json())).hexdigest(),
        "ast_manifest_hash": index.ast_manifest_hash,
        "source_files": files,
        "source_lines": lines,
        "ast_facts": facts,
        "nodes": list(sorted(nodes.values(), key=lambda node: str(node["node_id"]))),
        "edges": edges,
        "paths": graph_paths,
        "gaps": [{"path": path, "reason": reason} for path, reason in sorted(gaps)],
    }
