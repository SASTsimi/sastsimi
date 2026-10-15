"""A saved graph needs source evidence for every path it claims to cover."""

from __future__ import annotations

import copy
import hashlib
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.call_path_facts import build_python_call_path_index
from sastsimi.simple_runtime.http_route_facts_v5 import verified_http_paths
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.surface_applicability_v9 import assess_optional_analyzers
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_evidence_graph_v4 import _surface_candidate
from sastsimi.simple_runtime.surface_path_proof_v9 import (
    PathCertificateV9,
    build_path_proof_replay,
    certify_surface_paths,
    validate_path_certificate,
)

SOURCE = """from flask import Flask, request
app = Flask(__name__)
@app.route('/lookup')
def lookup():
    key = request.args['key']
    return run_query(key)

def run_query(key):
    return cursor.execute('SELECT 1')
"""

HTTP_SOURCE = """from http.server import BaseHTTPRequestHandler

class Endpoint(BaseHTTPRequestHandler):
    def do_GET(self):
        key = self.path
        return cursor.execute('SELECT 1')
"""

HTML_SOURCE = """from flask import Flask, request, make_response
import html
app = Flask(__name__)
@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    page = f'<h1>Hello, {name}!</h1>'
    return make_response(page, 200, {'Content-Type': 'text/html'})

def unused_sql():
    return cursor.execute('SELECT 1')
"""

ESCAPED_HTML_SOURCE = HTML_SOURCE.replace(
    "    page = f'<h1>Hello, {name}!</h1>'",
    "    escaped = html.escape(name)\n    page = f'<h1>Hello, {escaped}!</h1>'",
)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _id(prefix: str, value: object) -> str:
    return f"{prefix}-{_digest(value)[:24]}"


def _fixture(
    tmp_path: Path, source: str = SOURCE
) -> tuple[SurfaceIndex, AttackSurface, dict[str, object]]:
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "--", "app.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"])
        .decode("ascii")
        .strip()
    )
    sha = hashlib.sha256(raw).hexdigest()
    lines = source.splitlines()
    sink_line = next(i for i, line in enumerate(lines, 1) if "cursor.execute" in line)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id=commit,
        hypothesis_id=None,
    )
    surface = AttackSurface(
        surface_id="surface-1",
        type="SQL_EXECUTION",
        path="app.py",
        symbol="run_query",
        line=sink_line,
        linked_candidate_ids=("candidate-1",),
        evidence_refs=(_ref(identity, "a" * 64),),
        detector="test.sql-sink",
    )
    index = SurfaceIndex(
        scope_fingerprint="s" * 64,
        static_bundle_hash="b" * 64,
        ast_manifest_hash="m" * 64,
        workspace_id="workspace-1",
        commit_id=commit,
        candidate_inventory_hash="c" * 64,
        candidate_count=1,
        surfaces=(surface,),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=(("app.py", sha),),
    )
    call_paths = build_python_call_path_index(tmp_path, ("app.py",)).for_candidate(
        _surface_candidate(surface), include_downstream=True, include_enclosing=True
    )
    raw_paths = [
        path
        for path in call_paths.paths
        if path["kind"] == "call_path_v1"
        and path["assurance"] == "SYNTACTIC_REACHABILITY"
    ]
    raw_paths.extend(
        path
        for path in verified_http_paths(tmp_path, {"app.py": sha}, surface).paths
        if path["kind"] == "stdlib_http_call_path_v5" and path["status"] == "AVAILABLE"
    )
    paths: list[dict[str, object]] = []
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []
    for raw_path in raw_paths:
        http = raw_path["kind"] == "stdlib_http_call_path_v5"
        path_id = _id("v5-path" if http else "path", raw_path)
        steps: list[dict[str, object]] = []
        edge_ids: list[str] = []
        raw_steps = cast(list[dict[str, object]], raw_path["steps"])
        for ordinal, raw_step in enumerate(raw_steps):
            node_id = (
                _id("v5-node", (path_id, ordinal, raw_step))
                if http
                else _id("node", (raw_step["role"], raw_step["path"], raw_step["line"]))
            )
            step = {**raw_step, "node_id": node_id}
            nodes[node_id] = step
            steps.append(step)
        for ordinal, (first, second) in enumerate(zip(steps, steps[1:], strict=False)):
            edge_id = _id(
                "v5-edge" if http else "edge",
                (path_id, ordinal, first["node_id"], second["node_id"]),
            )
            edge_type = (
                "ENTRY"
                if first["role"] == "ROUTE_ENTRY"
                else {
                    "REQUEST_CONTEXT": "TRUST_BOUNDARY",
                    "SINK": "SENSITIVE_OPERATION",
                }.get(cast(str, second["role"]), "CALL")
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
            edge_ids.append(edge_id)
        paths.append(
            {
                "path_id": path_id,
                "kind": raw_path["kind"],
                "provenance": raw_path["provenance"],
                "assurance": raw_path["assurance"],
                "steps": steps,
                "edge_ids": edge_ids,
            }
        )
    graph: dict[str, object] = {
        "kind": "simple_surface_evidence_graph_v5",
        "proof_semantics_revision": "v5-source-bound-5",
        "anchor": {
            "surface_id": surface.surface_id,
            "path": surface.path,
            "line": surface.line,
        },
        "scope_fingerprint": index.scope_fingerprint,
        "index_hash": _digest(index.to_json()),
        "ast_manifest_hash": index.ast_manifest_hash,
        "source_files": [
            {"path": "app.py", "source_sha256": sha, "ast_sha256": "f" * 64}
        ],
        "source_lines": [
            {"path": "app.py", "line": i, "text": text, "source_sha256": sha}
            for i, text in enumerate(lines, 1)
        ],
        "ast_facts": [
            {"path": "app.py", "line": sink_line, "kind": "Call", "source_sha256": sha}
        ],
        "nodes": list(nodes.values()),
        "edges": edges,
        "paths": paths,
        "gaps": [],
        "gap_events": [],
        "operational_routes": [],
    }
    return index, surface, graph


def _request_fixture(
    tmp_path: Path,
    source: str = SOURCE,
    *,
    anchor_line: int = 3,
) -> tuple[SurfaceIndex, AttackSurface, AttackSurface, dict[str, object]]:
    index, sink, graph = _fixture(tmp_path, source)
    request_surface = replace(
        sink,
        surface_id="request-1",
        type="REQUEST_ENTRY",
        line=anchor_line,
        symbol="lookup",
        detector="test.request-source",
    )
    index = replace(index, surfaces=(request_surface, sink), candidate_count=2)
    graph["anchor"] = {
        "surface_id": request_surface.surface_id,
        "path": request_surface.path,
        "line": request_surface.line,
    }
    graph["index_hash"] = _digest(index.to_json())
    # The immutable predecessor graph for an entry may have no downstream
    # path. V9 must derive and bind one from pinned source, not mutate v8.
    graph["paths"] = []
    graph["nodes"] = []
    graph["edges"] = []
    return index, request_surface, sink, graph


def _html_request_fixture(
    tmp_path: Path,
    source: str = HTML_SOURCE,
    *,
    anchor_line: int = 4,
) -> tuple[SurfaceIndex, AttackSurface, dict[str, object]]:
    index, entry, _, graph = _request_fixture(tmp_path, source, anchor_line=anchor_line)
    index = replace(index, surfaces=(entry,), candidate_count=1)
    graph["index_hash"] = _digest(index.to_json())
    return index, entry, graph


def test_batch_replay_scans_pinned_sources_once_without_changing_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index, route, sink, graph = _request_fixture(tmp_path)
    sink_graph = copy.deepcopy(graph)
    sink_graph["anchor"] = {
        "surface_id": sink.surface_id,
        "path": sink.path,
        "line": sink.line,
    }
    applicability = assess_optional_analyzers(index, tmp_path)
    cases = ((route, graph), (sink, sink_graph))
    expected = [
        certify_surface_paths(index, surface, evidence, applicability, tmp_path)
        for surface, evidence in cases
    ]
    from sastsimi.simple_runtime import surface_applicability_v9, surface_path_proof_v9

    original_scan = surface_applicability_v9._scan_sources
    original_sources = surface_path_proof_v9._source_and_tree
    scans = 0
    source_loads = 0

    def counted_scan(index: SurfaceIndex, workspace: Path) -> Any:
        nonlocal scans
        scans += 1
        return original_scan(index, workspace)

    def counted_sources(index: SurfaceIndex, workspace: Path) -> Any:
        nonlocal source_loads
        source_loads += 1
        return original_sources(index, workspace)

    monkeypatch.setattr(surface_applicability_v9, "_scan_sources", counted_scan)
    monkeypatch.setattr(surface_path_proof_v9, "_source_and_tree", counted_sources)
    replay = build_path_proof_replay(index, tmp_path)
    assert replay.applicability == applicability
    for (surface, evidence), certificate in zip(cases, expected, strict=True):
        assert (
            certify_surface_paths(
                index, surface, evidence, applicability, tmp_path, replay=replay
            )
            == certificate
        )
        assert validate_path_certificate(
            index,
            surface,
            evidence,
            applicability,
            tmp_path,
            certificate,
            replay=replay,
        )
    assert scans == 1
    assert source_loads == 1
    with pytest.raises(ValueError, match="SURFACE_PATH_REPLAY_INVALID"):
        certify_surface_paths(
            replace(index), route, graph, applicability, tmp_path, replay=replay
        )


@pytest.mark.parametrize("anchor_line", [4, 6])
def test_html_response_proves_route_and_request_anchor_without_indexed_sink(
    tmp_path: Path, anchor_line: int
) -> None:
    """Removing the HTML terminal must leave the entry unreviewed, not sinkless."""

    index, entry, graph = _html_request_fixture(tmp_path, anchor_line=anchor_line)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, entry, graph, applicability, tmp_path)

    assert certificate.source_complete, certificate.unresolved_gap_codes
    assert len(certificate.downstream_paths) == 1
    path = certificate.downstream_paths[0]
    assert path.kind == "flask_html_response_v9"
    assert path.sink_surface_id != entry.surface_id
    assert path.path_id in certificate.path_ids
    assert [step.role for step in path.steps] == [
        "ROUTE_ENTRY",
        "HANDLER_DEFINITION",
        "REQUEST_CONTEXT",
        "INTERPOLATION",
        "SINK",
    ]
    assert [step.line for step in path.steps] == [4, 5, 6, 7, 8]
    assert all(
        step.source_sha256 == dict(index.ast_source_hashes)["app.py"]
        for step in path.steps
    )
    assert len(path.edge_ids) == len(path.steps) - 1
    assert path == type(path).from_json(path.to_json())
    assert validate_path_certificate(
        index, entry, graph, applicability, tmp_path, certificate
    )


def test_html_escape_call_is_observed_not_a_safe_or_confirmed_verdict(
    tmp_path: Path,
) -> None:
    """A sanitizer call is an intermediate source fact, not sink suppression."""

    index, entry, graph = _html_request_fixture(tmp_path, ESCAPED_HTML_SOURCE)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, entry, graph, applicability, tmp_path)

    assert len(certificate.downstream_paths) == 1
    roles = [step.role for step in certificate.downstream_paths[0].steps]
    assert roles == [
        "ROUTE_ENTRY",
        "HANDLER_DEFINITION",
        "REQUEST_CONTEXT",
        "ESCAPE_CALL_OBSERVED",
        "INTERPOLATION",
        "SINK",
    ]
    assert certificate.downstream_paths[0].steps[-1].line == 9
    assert validate_path_certificate(
        index, entry, graph, applicability, tmp_path, certificate
    )


def test_html_response_certificate_rejects_forged_sink_edge_and_source_hash(
    tmp_path: Path,
) -> None:
    """Saved evidence must be recomputed from the pinned source and exact path."""

    index, entry, graph = _html_request_fixture(tmp_path)
    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, entry, graph, applicability, tmp_path)
    assert certificate.downstream_paths
    path = certificate.downstream_paths[0]

    assert not validate_path_certificate(
        index,
        entry,
        graph,
        applicability,
        tmp_path,
        replace(
            certificate,
            downstream_paths=(replace(path, sink_surface_id="invented"),),
        ),
    )
    assert not validate_path_certificate(
        index,
        entry,
        graph,
        applicability,
        tmp_path,
        replace(certificate, downstream_paths=(replace(path, edge_ids=("fake",)),)),
    )
    assert not validate_path_certificate(
        index,
        entry,
        graph,
        applicability,
        tmp_path,
        replace(
            certificate,
            downstream_paths=(
                replace(
                    path,
                    steps=(
                        *path.steps[:-1],
                        replace(path.steps[-1], source_sha256="0" * 64),
                    ),
                ),
            ),
        ),
    )


@pytest.mark.parametrize(
    "reason", ["DYNAMIC_DISPATCH_UNRESOLVED", "EXTERNAL_IMPLEMENTATION_UNAVAILABLE"]
)
def test_html_response_keeps_unrelated_graph_gap_unresolved(
    tmp_path: Path, reason: str
) -> None:
    """An observed HTML response cannot erase an independent static gap."""

    index, entry, graph = _html_request_fixture(tmp_path)
    graph["gaps"] = [{"path": "app.py", "reason": reason}]
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": reason,
            "attribution": "UNLOCATED",
        }
    ]
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, entry, graph, applicability, tmp_path)

    assert certificate.downstream_paths
    assert not certificate.source_complete
    assert reason in certificate.unresolved_gap_codes


def test_html_response_keeps_fresh_call_index_gap_when_graph_has_none(
    tmp_path: Path,
) -> None:
    """A synthetic terminal cannot clear a fresh analyzer gap absent from v8."""

    index, entry, graph = _html_request_fixture(tmp_path)
    applicability = assess_optional_analyzers(index, tmp_path)
    call_index = build_python_call_path_index(tmp_path, ("app.py",))
    call_index._candidate_path_gaps["app.py"].add("EXTERNAL_IMPLEMENTATION_UNAVAILABLE")

    certificate = certify_surface_paths(
        index, entry, graph, applicability, tmp_path, call_index=call_index
    )

    assert certificate.downstream_paths
    assert not certificate.source_complete
    assert "EXTERNAL_IMPLEMENTATION_UNAVAILABLE" in certificate.unresolved_gap_codes


@pytest.mark.parametrize(
    "mutation",
    [
        HTML_SOURCE.replace("text/html", "application/json"),
        HTML_SOURCE.replace("app = Flask(__name__)", "app = other_factory(__name__)"),
        HTML_SOURCE.replace(
            "f'<h1>Hello, {name}!</h1>'", "f'<h1>Hello, {other}!</h1>'"
        ),
    ],
)
def test_unproven_html_response_remains_unresolved(
    tmp_path: Path, mutation: str
) -> None:
    """An unproven response must not silently count as a reviewed source path."""

    index, entry, graph = _html_request_fixture(tmp_path, mutation)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, entry, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert certificate.downstream_paths == ()
    assert "DOWNSTREAM_SINK_NOT_PROVEN" in certificate.unresolved_gap_codes


def test_request_entry_uses_source_bound_downstream_sink_not_self_path(
    tmp_path: Path,
) -> None:
    index, request_surface, sink, graph = _request_fixture(tmp_path)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    assert certificate.source_complete
    assert len(certificate.downstream_paths) == 1
    downstream = certificate.downstream_paths[0]
    assert downstream.sink_surface_id == sink.surface_id
    assert downstream.path_id in certificate.path_ids
    assert downstream.steps[0].role == "ROUTE_ENTRY"
    assert (downstream.steps[0].path, downstream.steps[0].line) == (
        request_surface.path,
        request_surface.line,
    )
    assert downstream.steps[-1].role == "SINK"
    assert (downstream.steps[-1].path, downstream.steps[-1].line) == (
        sink.path,
        sink.line,
    )
    assert all(
        part.path_ids == certificate.path_ids for part in certificate.context_parts
    )
    assert validate_path_certificate(
        index, request_surface, graph, applicability, tmp_path, certificate
    )


def test_request_source_anchor_binds_exact_request_read(tmp_path: Path) -> None:
    index, request_surface, sink, graph = _request_fixture(tmp_path, anchor_line=5)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    assert certificate.source_complete
    assert certificate.downstream_paths[0].sink_surface_id == sink.surface_id
    assert any(
        step.role == "REQUEST_CONTEXT"
        and (step.path, step.line) == (request_surface.path, request_surface.line)
        for step in certificate.downstream_paths[0].steps
    )


def test_request_entry_keeps_unproven_same_file_sink_gap(tmp_path: Path) -> None:
    """One proved route-to-sink path cannot cover another unproved sink."""

    source = SOURCE + "\ndef unused_sql():\n    return cursor.execute('SELECT 2')\n"
    index, request_surface, reachable_sink, graph = _request_fixture(tmp_path, source)
    other_sink = replace(
        reachable_sink,
        surface_id="sink-other",
        line=source.splitlines().index("    return cursor.execute('SELECT 2')") + 1,
        symbol="unused_sql",
    )
    index = replace(
        index,
        surfaces=(request_surface, reachable_sink, other_sink),
        candidate_count=3,
    )
    graph["index_hash"] = _digest(index.to_json())
    call_index = build_python_call_path_index(tmp_path, ("app.py",))
    other_result = call_index.for_candidate(
        _surface_candidate(other_sink), include_downstream=True, include_enclosing=True
    )
    assert "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE" in other_result.gaps
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index,
        request_surface,
        graph,
        applicability,
        tmp_path,
        call_index=call_index,
    )

    assert certificate.downstream_paths
    assert not certificate.source_complete
    assert "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE" in certificate.unresolved_gap_codes


def _request_with_long_downstream_helper(
    tmp_path: Path,
) -> tuple[SurfaceIndex, AttackSurface, dict[str, object], str]:
    helper_body = "\n".join(f"    local_{i} = {i}" for i in range(50))
    source = (
        SOURCE.replace(
            "    return run_query(key)",
            "    result = run_query(key)\n    return helper(result)",
        )
        + "\ndef helper(result):\n"
        + helper_body
        + "\n    return result\n"
    )
    index, request_surface, _, graph = _request_fixture(tmp_path, source, anchor_line=5)
    return index, request_surface, graph, source


def test_request_entry_context_includes_full_pinned_downstream_helper(
    tmp_path: Path,
) -> None:
    index, request_surface, graph, source = _request_with_long_downstream_helper(
        tmp_path
    )
    raw = build_python_call_path_index(tmp_path, ("app.py",)).for_candidate(
        _surface_candidate(request_surface),
        include_downstream=True,
        include_enclosing=True,
    )
    assert "DOWNSTREAM_CALLEE_BODY_TRUNCATED" in raw.gaps
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    middle_line = source.splitlines().index("    local_25 = 25") + 1
    assert certificate.source_complete
    assert any(
        part.path == "app.py" and part.start_line <= middle_line <= part.end_line
        for part in certificate.context_parts
    )


def test_request_entry_accepts_exact_historical_downstream_context_path(
    tmp_path: Path,
) -> None:
    index, request_surface, graph, source = _request_with_long_downstream_helper(
        tmp_path
    )
    raw = build_python_call_path_index(tmp_path, ("app.py",)).for_candidate(
        _surface_candidate(request_surface),
        include_downstream=True,
        include_enclosing=True,
    )
    candidate = next(
        path
        for path in raw.paths
        if path["kind"] == "candidate_downstream_context_v1"
        and any(
            step["role"] == "CALLEE_BODY_LINE" and step["symbol"] == "helper"
            for step in cast(list[dict[str, object]], path["steps"])
        )
    )
    path_id = _id("path", candidate)
    steps = [
        {
            **step,
            "node_id": _id("node", (step["role"], step["path"], step["line"])),
        }
        for step in cast(list[dict[str, object]], candidate["steps"])
    ]
    edges = [
        {
            "edge_id": _id(
                "edge",
                (path_id, ordinal, first["node_id"], second["node_id"]),
            ),
            "type": "CALL",
            "from_node_id": first["node_id"],
            "to_node_id": second["node_id"],
            "graph_path_id": path_id,
        }
        for ordinal, (first, second) in enumerate(zip(steps, steps[1:], strict=False))
    ]
    graph["paths"] = [
        {
            "path_id": path_id,
            "kind": candidate["kind"],
            "provenance": candidate["provenance"],
            "assurance": candidate["assurance"],
            "steps": steps,
            "edge_ids": [edge["edge_id"] for edge in edges],
        }
    ]
    graph["nodes"] = steps
    graph["edges"] = edges
    graph["gaps"] = [{"path": "app.py", "reason": "DOWNSTREAM_CALLEE_BODY_TRUNCATED"}]
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "DOWNSTREAM_CALLEE_BODY_TRUNCATED",
            "attribution": "UNLOCATED",
        }
    ]
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    middle_line = source.splitlines().index("    local_25 = 25") + 1
    assert certificate.source_complete
    assert "HISTORICAL_GRAPH_PATH_INVALID" not in certificate.unresolved_gap_codes
    assert any(
        part.path == "app.py" and part.start_line <= middle_line <= part.end_line
        for part in certificate.context_parts
    )
    assert validate_path_certificate(
        index, request_surface, graph, applicability, tmp_path, certificate
    )

    forged_graph = copy.deepcopy(graph)
    forged_paths = cast(list[dict[str, object]], forged_graph["paths"])
    forged_steps = cast(list[dict[str, object]], forged_paths[0]["steps"])
    forged_steps[0]["line"] = cast(int, forged_steps[0]["line"]) + 1
    forged = certify_surface_paths(
        index, request_surface, forged_graph, applicability, tmp_path
    )
    assert not forged.source_complete
    assert "HISTORICAL_GRAPH_PATH_INVALID" in forged.unresolved_gap_codes

    wrong_kind_graph = copy.deepcopy(graph)
    wrong_kind_paths = cast(list[dict[str, object]], wrong_kind_graph["paths"])
    wrong_kind_paths[0]["kind"] = "call_path_v1"
    wrong_kind = certify_surface_paths(
        index, request_surface, wrong_kind_graph, applicability, tmp_path
    )
    assert not wrong_kind.source_complete
    assert "HISTORICAL_GRAPH_PATH_INVALID" in wrong_kind.unresolved_gap_codes


def test_route_object_rebinding_blocks_derived_downstream_path(tmp_path: Path) -> None:
    source = SOURCE.replace(
        "@app.route('/lookup')", "app = object()\n@app.route('/lookup')"
    )
    index, request_surface, _, graph = _request_fixture(tmp_path, source, anchor_line=4)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    assert not certificate.source_complete
    assert certificate.downstream_paths == ()


@pytest.mark.parametrize(
    "mutation",
    [
        "app.route = lambda *a, **k: lambda f: f",
        "app.route += other",
        "del app.route",
        "setattr(app, 'route', lambda *a, **k: lambda f: f)",
        "name = 'route'; setattr(app, name, other)",
        "app.__dict__['route'] = lambda *a, **k: lambda f: f",
    ],
)
def test_route_attribute_mutation_blocks_derived_downstream_path(
    tmp_path: Path, mutation: str
) -> None:
    source = SOURCE.replace(
        "@app.route('/lookup')", f"{mutation}\n@app.route('/lookup')"
    )
    route_line = source.splitlines().index("@app.route('/lookup')") + 1
    index, request_surface, _, graph = _request_fixture(
        tmp_path, source, anchor_line=route_line
    )
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    assert not certificate.source_complete
    assert certificate.downstream_paths == ()


def test_unrelated_app_config_assignment_preserves_route_path(tmp_path: Path) -> None:
    source = SOURCE.replace(
        "@app.route('/lookup')", "app.config['TESTING'] = True\n@app.route('/lookup')"
    )
    index, request_surface, _, graph = _request_fixture(tmp_path, source, anchor_line=4)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    assert certificate.source_complete
    assert len(certificate.downstream_paths) == 1


def test_unindexed_downstream_call_is_not_invented_as_certified_sink(
    tmp_path: Path,
) -> None:
    index, request_surface, _, graph = _request_fixture(tmp_path)
    index = replace(index, surfaces=(request_surface,), candidate_count=1)
    graph["index_hash"] = _digest(index.to_json())
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    assert not certificate.source_complete
    assert certificate.downstream_paths == ()


def test_stdlib_http_request_entry_uses_verified_handler_path(tmp_path: Path) -> None:
    index, request_surface, sink, graph = _request_fixture(
        tmp_path, HTTP_SOURCE, anchor_line=4
    )
    applicability = assess_optional_analyzers(index, tmp_path)
    assert applicability.status_for("stdlib_http") == "APPLICABLE"

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    assert certificate.source_complete
    assert len(certificate.downstream_paths) == 1
    assert certificate.downstream_paths[0].sink_surface_id == sink.surface_id
    assert certificate.downstream_paths[0].steps[0].role == "ROUTE_ENTRY"
    assert certificate.downstream_paths[0].steps[-1].role == "SINK"


def test_request_entry_retains_distinct_downstream_sinks(tmp_path: Path) -> None:
    source = (
        SOURCE.replace(
            "    return run_query(key)",
            "    run_query(key)\n    return run_query_two(key)",
        )
        + "\ndef run_query_two(key):\n    return cursor.execute('SELECT 2')\n"
    )
    index, request_surface, sink, graph = _request_fixture(tmp_path, source)
    second_line = source.splitlines().index("    return cursor.execute('SELECT 2')") + 1
    second_sink = replace(sink, surface_id="sink-2", line=second_line)
    index = replace(
        index, surfaces=(request_surface, sink, second_sink), candidate_count=3
    )
    graph["index_hash"] = _digest(index.to_json())
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )

    assert certificate.source_complete
    assert len(certificate.downstream_paths) == 2
    assert {path.sink_surface_id for path in certificate.downstream_paths} == {
        sink.surface_id,
        second_sink.surface_id,
    }
    assert len(set(certificate.path_ids)) == 2
    assert not validate_path_certificate(
        index,
        request_surface,
        graph,
        applicability,
        tmp_path,
        replace(certificate, downstream_paths=certificate.downstream_paths[:1]),
    )


def test_precomputed_call_index_must_match_pinned_workspace_and_manifest(
    tmp_path: Path,
) -> None:
    index, request_surface, _, graph = _request_fixture(tmp_path)
    applicability = assess_optional_analyzers(index, tmp_path)
    shared = build_python_call_path_index(tmp_path, ("app.py",))

    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path, call_index=shared
    )
    assert certificate == certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )
    assert validate_path_certificate(
        index,
        request_surface,
        graph,
        applicability,
        tmp_path,
        certificate,
        call_index=shared,
    )

    unrelated = build_python_call_path_index(tmp_path, ())
    with pytest.raises(ValueError, match="SURFACE_PATH_CALL_INDEX_INVALID"):
        certify_surface_paths(
            index,
            request_surface,
            graph,
            applicability,
            tmp_path,
            call_index=unrelated,
        )
    (tmp_path / "app.py").write_text(SOURCE + "# changed\n", encoding="utf-8")
    assert not validate_path_certificate(
        index,
        request_surface,
        graph,
        applicability,
        tmp_path,
        certificate,
        call_index=shared,
    )


def test_precomputed_call_index_rejects_stale_ast_for_new_pinned_manifest(
    tmp_path: Path,
) -> None:
    _request_fixture(tmp_path)
    stale = build_python_call_path_index(tmp_path, ("app.py",))
    updated = SOURCE.replace("return run_query(key)", "return run_query(key, 'x')")
    index, request_surface, _, graph = _request_fixture(tmp_path, updated)
    applicability = assess_optional_analyzers(index, tmp_path)

    with pytest.raises(ValueError, match="SURFACE_PATH_CALL_INDEX_INVALID"):
        certify_surface_paths(
            index,
            request_surface,
            graph,
            applicability,
            tmp_path,
            call_index=stale,
        )


def test_unrelated_sink_context_truncation_does_not_hide_unproven_path(
    tmp_path: Path,
) -> None:
    unrelated_body = "\n".join(f"    local_{i} = {i}" for i in range(40))
    source = (
        SOURCE
        + "\ndef unrelated():\n"
        + unrelated_body
        + "\n    return cursor.execute('SELECT 2')\n"
    )
    index, request_surface, sink, graph = _request_fixture(tmp_path, source)
    second_line = source.splitlines().index("    return cursor.execute('SELECT 2')") + 1
    unrelated_sink = replace(sink, surface_id="sink-2", line=second_line)
    index = replace(
        index, surfaces=(request_surface, sink, unrelated_sink), candidate_count=3
    )
    graph["index_hash"] = _digest(index.to_json())
    call_index = build_python_call_path_index(tmp_path, ("app.py",))
    assert (
        "ENCLOSING_CONTEXT_TRUNCATED"
        in call_index.for_candidate(
            _surface_candidate(unrelated_sink), include_enclosing=True
        ).gaps
    )
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(
        index,
        request_surface,
        graph,
        applicability,
        tmp_path,
        call_index=call_index,
    )

    assert not certificate.source_complete
    assert "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE" in certificate.unresolved_gap_codes
    assert "ENCLOSING_CONTEXT_TRUNCATED" not in certificate.unresolved_gap_codes
    assert len(certificate.downstream_paths) == 1
    assert certificate.downstream_paths[0].sink_surface_id == sink.surface_id


def test_path_certificate_json_parser_rejects_ambiguous_nested_payloads(
    tmp_path: Path,
) -> None:
    index, request_surface, _, graph = _request_fixture(tmp_path)
    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(
        index, request_surface, graph, applicability, tmp_path
    )
    raw = certificate.to_json()
    assert PathCertificateV9.from_json(raw) == certificate

    extra = {**raw, "unapproved": True}
    with pytest.raises(ValueError, match="SURFACE_PATH_CERTIFICATE_INVALID"):
        PathCertificateV9.from_json(extra)

    bad_line = copy.deepcopy(raw)
    bad_line_paths = cast(list[dict[str, object]], bad_line["downstream_paths"])
    bad_line_steps = cast(list[dict[str, object]], bad_line_paths[0]["steps"])
    bad_line_steps[0]["line"] = True
    with pytest.raises(ValueError, match="SURFACE_PATH_CERTIFICATE_INVALID"):
        PathCertificateV9.from_json(bad_line)

    bad_context = copy.deepcopy(raw)
    bad_context_parts = cast(list[dict[str, object]], bad_context["context_parts"])
    del bad_context_parts[0]["content_sha256"]
    with pytest.raises(ValueError, match="SURFACE_PATH_CERTIFICATE_INVALID"):
        PathCertificateV9.from_json(bad_context)

    bad_edges = copy.deepcopy(raw)
    bad_edges_paths = cast(list[dict[str, object]], bad_edges["downstream_paths"])
    bad_edges_paths[0]["edge_ids"] = [None]
    with pytest.raises(ValueError, match="SURFACE_PATH_CERTIFICATE_INVALID"):
        PathCertificateV9.from_json(bad_edges)


def test_inherited_flask_path_without_blocking_gaps_gets_source_certificate(
    tmp_path: Path,
) -> None:
    index, surface, graph = _fixture(tmp_path)

    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert certificate.source_complete
    assert len(certificate.path_ids) == 1
    assert certificate.unresolved_path_ids == ()
    assert certificate.unresolved_gap_codes == ()
    assert all(
        part.path_ids == certificate.path_ids for part in certificate.context_parts
    )
    assert all(
        part.part_id.startswith("context-") for part in certificate.context_parts
    )
    assert all(
        part.to_json()["part_id"] == part.part_id
        and part.to_json()["path_ids"] == list(part.path_ids)
        for part in certificate.context_parts
    )
    assert validate_path_certificate(
        index, surface, graph, applicability, tmp_path, certificate
    )


def test_stdlib_http_handler_path_is_source_bound(tmp_path: Path) -> None:
    index, surface, graph = _fixture(tmp_path, HTTP_SOURCE)
    paths = graph["paths"]
    assert isinstance(paths, list)
    assert any(path["kind"] == "stdlib_http_call_path_v5" for path in paths)
    applicability = assess_optional_analyzers(index, tmp_path)
    assert applicability.status_for("stdlib_http") == "APPLICABLE"

    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert certificate.source_complete
    assert certificate.unresolved_path_ids == ()


def test_optional_gap_is_removed_only_for_its_analyzer(tmp_path: Path) -> None:
    index, surface, graph = _fixture(tmp_path)
    graph["gaps"] = [{"path": "app.py", "reason": "HTTP_HANDLER_IMPORT_UNPROVEN"}]
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "HTTP_HANDLER_IMPORT_UNPROVEN",
            "attribution": "UNLOCATED",
        }
    ]

    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert certificate.source_complete
    assert certificate.unresolved_gap_codes == ()


def test_unknown_same_file_gap_blocks_path(tmp_path: Path) -> None:
    index, surface, graph = _fixture(tmp_path)
    graph["gaps"] = [{"path": "app.py", "reason": "DYNAMIC_DISPATCH_UNRESOLVED"}]
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "DYNAMIC_DISPATCH_UNRESOLVED",
            "attribution": "UNLOCATED",
        }
    ]

    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert certificate.unresolved_path_ids == certificate.path_ids
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in certificate.unresolved_gap_codes


def test_complete_context_parts_clear_historical_truncation_gap(tmp_path: Path) -> None:
    body = "\n".join(f"    local_{i} = {i}" for i in range(150))
    source = SOURCE.replace(
        "    return cursor.execute", body + "\n    return cursor.execute"
    )
    index, surface, graph = _fixture(tmp_path, source)
    graph["gaps"] = [{"path": "app.py", "reason": "ENCLOSING_CONTEXT_TRUNCATED"}]
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "ENCLOSING_CONTEXT_TRUNCATED",
            "attribution": "UNLOCATED",
        }
    ]
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert certificate.source_complete
    assert certificate.unresolved_gap_codes == ()


def test_downstream_truncation_includes_entire_callee_body(tmp_path: Path) -> None:
    body = "\n".join(f"    local_{i} = {i}" for i in range(30))
    source = SOURCE.replace(
        "    return cursor.execute('SELECT 1')",
        "    result = cursor.execute('SELECT 1')\n"
        "    return helper(result)\n\n"
        "def helper(result):\n" + body + "\n    return result",
    )
    index, surface, graph = _fixture(tmp_path, source)
    raw_paths = build_python_call_path_index(tmp_path, ("app.py",)).for_candidate(
        _surface_candidate(surface), include_downstream=True, include_enclosing=True
    )
    assert "DOWNSTREAM_CALLEE_BODY_TRUNCATED" in raw_paths.gaps

    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    middle_line = source.splitlines().index("    local_15 = 15") + 1
    assert certificate.source_complete
    assert any(
        part.path == "app.py" and part.start_line <= middle_line <= part.end_line
        for part in certificate.context_parts
    )


def test_oversize_downstream_callee_blocks_truncation_repair(tmp_path: Path) -> None:
    body = "\n".join(f"    local_{i} = {i}" for i in range(30))
    source = SOURCE.replace(
        "    return cursor.execute('SELECT 1')",
        "    result = cursor.execute('SELECT 1')\n"
        "    return helper(result)\n\n"
        "def helper(result):\n"
        + body
        + "\n    payload = '"
        + "x" * 8192
        + "'\n    return result",
    )
    index, surface, graph = _fixture(tmp_path, source)

    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert (
        "SURFACE_PATH_CONTEXT_ATOMIC_LINE_TOO_LARGE" in certificate.unresolved_gap_codes
    )


def test_one_unresolved_alternate_path_blocks_complete_surface(tmp_path: Path) -> None:
    second_route = """@app.route('/second')
def second():
    key = request.args['key']
    return run_query(key)

"""
    source = SOURCE.replace("def run_query(key):", second_route + "def run_query(key):")
    index, surface, graph = _fixture(tmp_path, source)
    paths = graph["paths"]
    assert isinstance(paths, list)
    assert len(paths) == 2
    alternate = paths[1]
    alternate["blocking_gaps"] = ["DYNAMIC_CALL"]
    alternate_id = alternate["path_id"]

    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert certificate.path_ids == tuple(sorted(path["path_id"] for path in paths))
    assert certificate.unresolved_path_ids == (alternate_id,)
    assert all(alternate_id not in part.path_ids for part in certificate.context_parts)


def test_no_connected_path_stays_incomplete(tmp_path: Path) -> None:
    source = SOURCE.replace("@app.route('/lookup')\n", "")
    index, surface, graph = _fixture(tmp_path, source)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert certificate.path_ids == ()


def test_shadowed_request_name_cannot_prove_flask_input(tmp_path: Path) -> None:
    source = SOURCE.replace("def lookup():", "def lookup(request):")
    index, surface, graph = _fixture(tmp_path, source)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert certificate.unresolved_path_ids == certificate.path_ids


def test_module_rebound_request_cannot_prove_flask_input(tmp_path: Path) -> None:
    source = SOURCE.replace(
        "app = Flask(__name__)\n", "app = Flask(__name__)\nrequest = object()\n"
    )
    index, surface, graph = _fixture(tmp_path, source)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert certificate.unresolved_path_ids == certificate.path_ids


def test_rebound_route_object_cannot_prove_flask_entry(tmp_path: Path) -> None:
    source = SOURCE.replace(
        "@app.route('/lookup')", "app = object()\n@app.route('/lookup')"
    )
    index, surface, graph = _fixture(tmp_path, source)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert certificate.unresolved_path_ids == certificate.path_ids


def test_annotated_rebound_route_object_cannot_prove_flask_entry(
    tmp_path: Path,
) -> None:
    source = SOURCE.replace(
        "@app.route('/lookup')", "app: object = object()\n@app.route('/lookup')"
    )
    index, surface, graph = _fixture(tmp_path, source)
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert certificate.unresolved_path_ids == certificate.path_ids


def test_forged_other_sink_gap_attribution_does_not_clear_gap(tmp_path: Path) -> None:
    index, surface, graph = _fixture(tmp_path)
    sha = index.ast_source_hashes[0][1]
    paths = cast(list[dict[str, object]], graph["paths"])
    graph["gaps"] = [{"path": "app.py", "reason": "DYNAMIC_DISPATCH_UNRESOLVED"}]
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "DYNAMIC_DISPATCH_UNRESOLVED",
            "attribution": "PINNED_PATH",
            "graph_path_id": paths[0]["path_id"],
            "route_entry": {"path": "app.py", "line": 3, "source_sha256": sha},
            "sink": {"path": "app.py", "line": 1, "source_sha256": sha},
        }
    ]
    applicability = assess_optional_analyzers(index, tmp_path)

    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert not certificate.source_complete
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in certificate.unresolved_gap_codes


def test_source_or_edge_mutation_invalidates_certificate(tmp_path: Path) -> None:
    index, surface, graph = _fixture(tmp_path)
    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)
    edges = graph["edges"]
    assert isinstance(edges, list)
    edge = edges[0]
    assert isinstance(edge, dict)
    original_target = edge["to_node_id"]
    edge["to_node_id"] = "forged"
    assert not validate_path_certificate(
        index, surface, graph, applicability, tmp_path, certificate
    )

    edge["to_node_id"] = original_target
    (tmp_path / "app.py").write_text(SOURCE + "# changed\n", encoding="utf-8")
    assert not validate_path_certificate(
        index, surface, graph, applicability, tmp_path, certificate
    )


def test_long_function_is_split_without_dropping_lines(tmp_path: Path) -> None:
    body = "\n".join(f"    local_{i} = {i}" for i in range(150))
    source = SOURCE.replace(
        "    return cursor.execute", body + "\n    return cursor.execute"
    )
    index, surface, graph = _fixture(tmp_path, source)

    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)

    assert certificate.source_complete
    parts = [
        part
        for part in certificate.context_parts
        if part.path == "app.py"
        and part.start_line <= surface.line <= part.end_line
        or part.path == "app.py"
        and part.start_line >= 8
    ]
    assert len(parts) > 1
    covered = [
        line for part in parts for line in range(part.start_line, part.end_line + 1)
    ]
    assert covered == list(range(8, len(source.splitlines()) + 1))


def test_missing_or_reordered_context_part_fails_validation(tmp_path: Path) -> None:
    body = "\n".join(f"    local_{i} = {i}" for i in range(150))
    source = SOURCE.replace(
        "    return cursor.execute", body + "\n    return cursor.execute"
    )
    index, surface, graph = _fixture(tmp_path, source)
    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)
    assert len(certificate.context_parts) > 1

    assert not validate_path_certificate(
        index,
        surface,
        graph,
        applicability,
        tmp_path,
        replace(certificate, context_parts=certificate.context_parts[:-1]),
    )
    assert not validate_path_certificate(
        index,
        surface,
        graph,
        applicability,
        tmp_path,
        replace(certificate, context_parts=tuple(reversed(certificate.context_parts))),
    )
    first, *rest = certificate.context_parts
    assert not validate_path_certificate(
        index,
        surface,
        graph,
        applicability,
        tmp_path,
        replace(
            certificate,
            context_parts=(replace(first, part_id="context-forged"), *rest),
        ),
    )
