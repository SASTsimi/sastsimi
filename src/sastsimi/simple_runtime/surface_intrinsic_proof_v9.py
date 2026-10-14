"""Exact, source-bound intrinsic proofs for one indexed Python surface.

An intrinsic proof records one SQL call shape or one Flask route declaration.
It is never a claim about a route's downstream safety or other calls.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sastsimi.contracts.canonical_json import canonical_bytes

from .artifacts import SimpleArtifactRepository
from .ast_facts import _call_fact, _call_name
from .attack_surfaces import (
    AttackSurface,
    SurfaceIndex,
    _rule_type,
    candidate_inventory_hash,
)
from .candidates import (
    StaticCandidate,
    iter_raw_candidate_pages,
    normalize_candidate_page,
)
from .file_context import MAX_CONTEXT_SOURCE_BYTES
from .operational_config_v5 import _Gap, _verified_blob, _verify_commit
from .surface_evidence_graph_v4 import _id
from .surface_safe_sql_literal import prove_fixed_sql_literal

IntrinsicProofType = Literal["FIXED_SQL_LITERAL", "ROUTE_DECLARATION"]
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SQL_METHODS = frozenset({"execute", "executemany", "raw"})
_MAX_CANDIDATE_ARTIFACT_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class IntrinsicProofV9:
    """A replayable claim tied to a single source location and saved graph."""

    proof_type: IntrinsicProofType
    scope_fingerprint: str
    surface_index_hash: str
    graph_sha256: str
    workspace_id: str
    commit_id: str
    surface_id: str
    path: str
    line: int
    column: int
    surface_symbol: str
    candidate_ids: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    source_sha256: str
    ast_sha256: str
    ast_fact_id: str
    ast_node_sha256: str
    call_name: str
    sql_sha256: str | None = None
    sql_byte_count: int | None = None
    function_name: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_surface_intrinsic_proof_v9",
            "proof_type": self.proof_type,
            "scope_fingerprint": self.scope_fingerprint,
            "surface_index_hash": self.surface_index_hash,
            "graph_sha256": self.graph_sha256,
            "workspace_id": self.workspace_id,
            "commit_id": self.commit_id,
            "surface_id": self.surface_id,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "surface_symbol": self.surface_symbol,
            "candidate_ids": list(self.candidate_ids),
            "evidence_hashes": list(self.evidence_hashes),
            "source_sha256": self.source_sha256,
            "ast_sha256": self.ast_sha256,
            "ast_fact_id": self.ast_fact_id,
            "ast_node_sha256": self.ast_node_sha256,
            "call_name": self.call_name,
            "sql_sha256": self.sql_sha256,
            "sql_byte_count": self.sql_byte_count,
            "function_name": self.function_name,
        }


def _rows(graph: Mapping[str, object], key: str) -> list[dict[str, object]] | None:
    value = graph.get(key)
    if not isinstance(value, list) or any(
        not isinstance(row, dict) or any(not isinstance(k, str) for k in row)
        for row in value
    ):
        return None
    return value


def _source_binding(
    index: SurfaceIndex, surface: AttackSurface, graph: Mapping[str, object]
) -> tuple[str, str, str] | None:
    if (
        index.index_version != 2
        or surface not in index.surfaces
        or type(surface.line) is not int
        or surface.line < 1
        or not _COMMIT.fullmatch(index.commit_id)
        or len(set(index.ast_source_hashes)) != len(index.ast_source_hashes)
        or graph.get("kind") != "simple_surface_evidence_graph_v5"
        or graph.get("anchor")
        != {
            "surface_id": surface.surface_id,
            "path": surface.path,
            "line": surface.line,
        }
        or graph.get("scope_fingerprint") != index.scope_fingerprint
        or graph.get("ast_manifest_hash") != index.ast_manifest_hash
    ):
        return None
    index_hash = hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()
    if graph.get("index_hash") != index_hash:
        return None
    source_hashes = dict(index.ast_source_hashes)
    if len(source_hashes) != len(index.ast_source_hashes):
        return None
    source_sha = source_hashes.get(surface.path)
    if source_sha is None or _SHA256.fullmatch(source_sha) is None:
        return None
    files = _rows(graph, "source_files")
    lines = _rows(graph, "source_lines")
    facts = _rows(graph, "ast_facts")
    if files is None or lines is None or facts is None:
        return None
    matching_files = [row for row in files if row.get("path") == surface.path]
    matching_lines = [
        row
        for row in lines
        if row.get("path") == surface.path and row.get("line") == surface.line
    ]
    if len(matching_files) != 1 or len(matching_lines) != 1:
        return None
    file = matching_files[0]
    ast_sha = file.get("ast_sha256")
    if (
        file.get("source_sha256") != source_sha
        or not isinstance(ast_sha, str)
        or _SHA256.fullmatch(ast_sha) is None
        or matching_lines[0].get("source_sha256") != source_sha
    ):
        return None
    for ref in surface.evidence_refs:
        if (
            str(ref.workspace_id) != index.workspace_id
            or str(ref.commit_id) != index.commit_id
            or ref.data_kind != "artifact"
        ):
            return None
    return source_sha, ast_sha, index_hash


def _fact_id(
    graph: Mapping[str, object],
    *,
    fact: dict[str, object],
    source_sha: str,
    ast_sha: str,
) -> str | None:
    facts = _rows(graph, "ast_facts")
    if facts is None:
        return None
    fact_id = _id("fact", (fact["path"], fact, source_sha))
    expected = {
        **fact,
        "fact_id": fact_id,
        "source_sha256": source_sha,
        "ast_sha256": ast_sha,
    }
    matches = [row for row in facts if row == expected]
    return fact_id if len(matches) == 1 else None


def _common(
    proof_type: IntrinsicProofType,
    index: SurfaceIndex,
    surface: AttackSurface,
    graph: Mapping[str, object],
    source_sha: str,
    ast_sha: str,
    index_hash: str,
    call: ast.Call,
    fact_id: str,
    *,
    sql_sha256: str | None = None,
    sql_byte_count: int | None = None,
    function_name: str | None = None,
) -> IntrinsicProofV9:
    return IntrinsicProofV9(
        proof_type=proof_type,
        scope_fingerprint=index.scope_fingerprint,
        surface_index_hash=index_hash,
        graph_sha256=hashlib.sha256(canonical_bytes(graph)).hexdigest(),
        workspace_id=index.workspace_id,
        commit_id=index.commit_id,
        surface_id=surface.surface_id,
        path=surface.path,
        line=call.lineno,
        column=call.col_offset,
        surface_symbol=surface.symbol,
        candidate_ids=surface.linked_candidate_ids,
        evidence_hashes=tuple(ref.content_hash for ref in surface.evidence_refs),
        source_sha256=source_sha,
        ast_sha256=ast_sha,
        ast_fact_id=fact_id,
        ast_node_sha256=hashlib.sha256(ast.dump(call).encode("utf-8")).hexdigest(),
        call_name=_call_name(call.func) or "",
        sql_sha256=sql_sha256,
        sql_byte_count=sql_byte_count,
        function_name=function_name,
    )


def _sql_candidate_binding(
    index: SurfaceIndex,
    surface: AttackSurface,
    workspace: Path,
    candidates: Mapping[str, StaticCandidate] | None,
    artifacts: SimpleArtifactRepository | None,
) -> bool:
    """Replay every linked scanner hit from its original scoped CAS bytes."""

    if (
        candidates is None
        or artifacts is None
        or not isinstance(artifacts, SimpleArtifactRepository)
        or artifacts.identity.workspace_id != index.workspace_id
        or artifacts.identity.commit_id != index.commit_id
        or artifacts.identity.hypothesis_id is not None
        or len(candidates) != index.candidate_count
        or not surface.linked_candidate_ids
        or len(set(surface.linked_candidate_ids)) != len(surface.linked_candidate_ids)
        or any(
            not isinstance(candidate, StaticCandidate) or key != candidate.candidate_id
            for key, candidate in candidates.items()
        )
    ):
        return False
    try:
        if (
            candidate_inventory_hash(tuple(candidates.values()))
            != index.candidate_inventory_hash
        ):
            return False
    except (TypeError, ValueError, AttributeError):
        return False
    source_refs = set(surface.evidence_refs)
    for candidate_id in surface.linked_candidate_ids:
        candidate = candidates.get(candidate_id)
        if (
            candidate is None
            or candidate.path != surface.path
            or candidate.line != surface.line
            or candidate.evidence_ref not in source_refs
            or not candidate.origins
            or candidate.evidence_ref
            not in {origin.artifact_ref for origin in candidate.origins}
        ):
            return False
        matched_surface_origin = False
        matched_evidence_ref = False
        for origin in candidate.origins:
            if origin.artifact_ref not in source_refs:
                return False
            if _rule_type(origin.rule_id, candidate.kind) == "SQL_EXECUTION" and (
                surface.detector == "AST" or origin.rule_id == surface.symbol
            ):
                matched_surface_origin = True
            try:
                # The bounded read independently verifies the original CAS hash.
                artifacts.read_bounded(
                    origin.artifact_ref, _MAX_CANDIDATE_ARTIFACT_BYTES
                )
                pages = iter_raw_candidate_pages(
                    artifacts,
                    origin.artifact_ref,
                    after_offset=origin.result_index,
                    page_size=1,
                )
                page = next(pages)
                for _remaining in pages:
                    pass  # Finish the bounded artifact's syntax/change checks.
                if (
                    page.start_offset != origin.result_index
                    or len(page.rows) != 1
                    or page.engine == "codeql"
                    and origin.engine != "codeql"
                    or page.engine == "opengrep"
                    and origin.engine not in {"opengrep", "semgrep"}
                ):
                    return False
                replayed = normalize_candidate_page(
                    artifacts.identity,
                    index.scope_fingerprint,
                    origin.engine,
                    origin.artifact_ref,
                    page.rows,
                    page.start_offset,
                    workspace=workspace,
                    identity_version=(
                        "exact-v2"
                        if candidate.evidence_key.startswith("exact-v2:")
                        else "legacy"
                    ),
                )
            except (
                OSError,
                ValueError,
                StopIteration,
                TypeError,
                KeyError,
                UnicodeError,
                RecursionError,
            ):
                return False
            matches = [
                item
                for item in replayed
                if item.candidate_id == candidate.candidate_id
                and item.origins == (origin,)
                and item.kind == candidate.kind
                and item.path == candidate.path
                and item.line == candidate.line
                and item.end_line == candidate.end_line
                and item.start_column == candidate.start_column
                and item.end_column == candidate.end_column
                and item.evidence_key == candidate.evidence_key
                and item.flow_identity == candidate.flow_identity
            ]
            if len(matches) != 1:
                return False
            if origin.artifact_ref == candidate.evidence_ref:
                original = matches[0]
                if (
                    original.summary != candidate.summary
                    or original.evidence_excerpt != candidate.evidence_excerpt
                    or original.flow_trace != candidate.flow_trace
                ):
                    return False
                matched_evidence_ref = True
        if not matched_surface_origin or not matched_evidence_ref:
            return False
    return True


def _sql_proof(
    index: SurfaceIndex,
    surface: AttackSurface,
    workspace: Path,
    graph: Mapping[str, object],
    tree: ast.Module,
    source_sha: str,
    ast_sha: str,
    index_hash: str,
    candidates: Mapping[str, StaticCandidate] | None,
    artifacts: SimpleArtifactRepository | None,
) -> IntrinsicProofV9 | None:
    if (
        surface.type != "SQL_EXECUTION"
        or surface.detector not in {"STATIC_RULE", "AST"}
        or not surface.linked_candidate_ids
        or len(surface.linked_candidate_ids) != len(set(surface.linked_candidate_ids))
        or len(surface.linked_candidate_ids) > index.candidate_count
        or not surface.evidence_refs
        or not _sql_candidate_binding(index, surface, workspace, candidates, artifacts)
        or surface.detector == "STATIC_RULE"
        and not (
            surface.symbol.endswith(".sql-sink")
            or "sql-injection" in surface.symbol.casefold()
        )
    ):
        return None
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and node.lineno == surface.line
    ]
    if len(calls) != 1:
        return None
    call = calls[0]
    name = _call_name(call.func)
    if (
        not isinstance(call.func, ast.Attribute)
        or name is None
        or name.rsplit(".", 1)[-1] not in _SQL_METHODS
        or surface.detector == "AST"
        and surface.symbol != name
    ):
        return None
    fact = _call_fact(call, surface.path)
    fact_id = (
        _fact_id(graph, fact=fact, source_sha=source_sha, ast_sha=ast_sha)
        if fact is not None
        else None
    )
    if fact_id is None:
        return None
    literal = prove_fixed_sql_literal(
        workspace,
        surface,
        source_sha256=source_sha,
        expected_call_name=name,
    )
    if literal is None:
        return None
    sql_sha = literal.get("sql_sha256")
    sql_size = literal.get("sql_byte_count")
    if not isinstance(sql_sha, str) or type(sql_size) is not int:
        return None
    return _common(
        "FIXED_SQL_LITERAL",
        index,
        surface,
        graph,
        source_sha,
        ast_sha,
        index_hash,
        call,
        fact_id,
        sql_sha256=sql_sha,
        sql_byte_count=sql_size,
    )


def _flask_constructor(tree: ast.Module, app_name: str, before_line: int) -> bool:
    assignments = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == app_name
    ]
    if len(assignments) != 1 or assignments[0].lineno >= before_line:
        return False
    assignment = assignments[0]
    if not isinstance(assignment.value, ast.Call) or assignment.value.keywords:
        return False
    constructor = _call_name(assignment.value.func)
    if constructor not in {"Flask", "flask.Flask"}:
        return False
    bindings: list[bool] = []
    for statement in tree.body:
        if statement.lineno >= assignment.lineno:
            break
        if constructor == "Flask" and isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if (alias.asname or alias.name) == "Flask":
                    bindings.append(
                        statement.module == "flask"
                        and alias.name == "Flask"
                        and alias.asname is None
                    )
        elif constructor == "flask.Flask" and isinstance(statement, ast.Import):
            for alias in statement.names:
                if (alias.asname or alias.name.split(".", 1)[0]) == "flask":
                    bindings.append(alias.name == "flask" and alias.asname is None)
    if bindings != [True]:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in {app_name, "Flask", "flask"}:
                return False
        if isinstance(node, ast.ExceptHandler) and node.name in {
            app_name,
            "Flask",
            "flask",
        }:
            return False
        if isinstance(node, ast.Name) and node.id in {app_name, "Flask", "flask"}:
            if (
                isinstance(node.ctx, (ast.Store, ast.Del))
                and node is not assignment.targets[0]
            ):
                return False
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and _call_name(node) == f"{app_name}.route"
        ):
            return False
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == app_name
        ):
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                if bound_name == app_name:
                    return False
                if bound_name in {"Flask", "flask"}:
                    authorized_flask = (
                        constructor == "Flask"
                        and isinstance(node, ast.ImportFrom)
                        and node.module == "flask"
                        and alias.name == "Flask"
                        and alias.asname is None
                    ) or (
                        constructor == "flask.Flask"
                        and isinstance(node, ast.Import)
                        and alias.name == "flask"
                        and alias.asname is None
                    )
                    if not authorized_flask:
                        return False
    return True


def _route_proof(
    index: SurfaceIndex,
    surface: AttackSurface,
    graph: Mapping[str, object],
    tree: ast.Module,
    source_sha: str,
    ast_sha: str,
    index_hash: str,
) -> IntrinsicProofV9 | None:
    if surface.type != "REQUEST_ENTRY" or surface.detector != "AST":
        return None
    matches: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.Call]] = []
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in function.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and decorator.lineno == surface.line
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "route"
                and isinstance(decorator.func.value, ast.Name)
                and _call_name(decorator.func) == surface.symbol
            ):
                matches.append((function, decorator))
    if len(matches) != 1:
        return None
    function, decorator = matches[0]
    decorator_func = decorator.func
    if not isinstance(decorator_func, ast.Attribute) or not isinstance(
        decorator_func.value, ast.Name
    ):
        return None
    app_name = decorator_func.value.id
    if not _flask_constructor(tree, app_name, decorator.lineno):
        return None
    if (
        len(decorator.args) != 1
        or not isinstance(decorator.args[0], ast.Constant)
        or not isinstance(decorator.args[0].value, str)
        or any(keyword.arg is None for keyword in decorator.keywords)
    ):
        return None
    try:
        for keyword in decorator.keywords:
            ast.literal_eval(keyword.value)
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return None
    route_fact = _call_fact(decorator, surface.path)
    fact_id = (
        _fact_id(graph, fact=route_fact, source_sha=source_sha, ast_sha=ast_sha)
        if route_fact is not None
        else None
    )
    function_fact: dict[str, object] = {
        "kind": type(function).__name__,
        "path": surface.path,
        "line": function.lineno,
        "name": function.name,
    }
    if (
        fact_id is None
        or _fact_id(graph, fact=function_fact, source_sha=source_sha, ast_sha=ast_sha)
        is None
    ):
        return None
    return _common(
        "ROUTE_DECLARATION",
        index,
        surface,
        graph,
        source_sha,
        ast_sha,
        index_hash,
        decorator,
        fact_id,
        function_name=function.name,
    )


def prove_intrinsic_surface(
    index: SurfaceIndex,
    surface: AttackSurface,
    workspace: Path,
    graph: Mapping[str, object],
    *,
    candidates: Mapping[str, StaticCandidate] | None = None,
    artifacts: SimpleArtifactRepository | None = None,
) -> IntrinsicProofV9 | None:
    """Recompute one exact intrinsic claim; return ``None`` on uncertainty."""

    try:
        canonical_bytes(graph)
    except (TypeError, ValueError, RecursionError):
        return None
    binding = _source_binding(index, surface, graph)
    if binding is None:
        return None
    source_sha, ast_sha, index_hash = binding
    try:
        _verify_commit(workspace, index.commit_id)
        raw, pinned_sha = _verified_blob(
            workspace, index.commit_id, surface.path, MAX_CONTEXT_SOURCE_BYTES
        )
        if pinned_sha != source_sha:
            return None
        tree = ast.parse(raw.decode("utf-8"), filename=surface.path)
    except (_Gap, ValueError, UnicodeError, SyntaxError, RecursionError):
        return None
    if surface.type == "SQL_EXECUTION":
        return _sql_proof(
            index,
            surface,
            workspace,
            graph,
            tree,
            source_sha,
            ast_sha,
            index_hash,
            candidates,
            artifacts,
        )
    if surface.type == "REQUEST_ENTRY":
        return _route_proof(
            index, surface, graph, tree, source_sha, ast_sha, index_hash
        )
    return None


def validate_intrinsic_proof(
    index: SurfaceIndex,
    surface: AttackSurface,
    workspace: Path,
    graph: Mapping[str, object],
    proof: IntrinsicProofV9 | Mapping[str, object],
    *,
    candidates: Mapping[str, StaticCandidate] | None = None,
    artifacts: SimpleArtifactRepository | None = None,
) -> bool:
    """Recompute the claim, including when read back from a JSON artifact."""

    current = prove_intrinsic_surface(
        index,
        surface,
        workspace,
        graph,
        candidates=candidates,
        artifacts=artifacts,
    )
    if current is None:
        return False
    if isinstance(proof, IntrinsicProofV9):
        return proof == current
    return isinstance(proof, Mapping) and proof == current.to_json()
