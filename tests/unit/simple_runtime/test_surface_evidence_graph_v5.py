"""V5 graph facts and Agent claims stay on one pinned, connected path."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime import surface_evidence_graph_v5 as graph_v5
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast, index_ast_manifest
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.call_path_facts import (
    CandidateCallPaths,
    build_python_call_path_index,
)
from sastsimi.simple_runtime.file_context import (
    PreparedFileContext,
    prepare_file_context,
)
from sastsimi.simple_runtime.http_route_facts_v5 import verified_http_paths
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.operational_config_v5 import (
    OperationalRouteMap,
    load_operational_routes,
)
from sastsimi.simple_runtime.surface_evidence_graph_v4 import (
    _raw_source as original_raw_source,
)
from sastsimi.simple_runtime.surface_evidence_graph_v5 import (
    VerifiedOperationalRoutes,
    extract_surface_graph_v5,
    verify_operational_routes_v5,
)
from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
    validate_v5_context,
    validate_v5_response,
)

GraphFixture = tuple[
    SurfaceIndex,
    AttackSurface,
    dict[str, object],
    dict[str, dict[str, object]],
    Path,
    SimpleArtifactRepository,
]


def _fixture(
    tmp_path: Path,
    sources: dict[str, bytes],
    *,
    surface_path: str,
    surface_line: int,
) -> GraphFixture:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    for relative, raw in sources.items():
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "add", "--", *sources], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
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
        subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"])
        .decode()
        .strip()
    )
    identity = CheckpointIdentity(
        analysis_id="graph-v5-analysis",
        workspace_id="graph-v5-workspace",
        commit_id=commit,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    python_paths = tuple(sorted(path for path in sources if path.endswith(".py")))
    summary = collect_python_ast(
        workspace, python_paths, artifacts, max_source_bytes=2 * 1024 * 1024
    )
    manifest = index_ast_manifest(artifacts, summary)
    evidence_ref = artifacts.put_json({"kind": "graph_v5_fixture"})
    surface = AttackSurface(
        surface_id="surface-v5-1",
        type="COMMAND_EXECUTION",
        path=surface_path,
        symbol="fixture",
        line=surface_line,
        linked_candidate_ids=(),
        evidence_refs=(evidence_ref,),
        detector="AST",
    )
    index = SurfaceIndex(
        scope_fingerprint="f" * 64,
        static_bundle_hash="b" * 64,
        ast_manifest_hash=hashlib.sha256(canonical_bytes(summary)).hexdigest(),
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="d" * 64,
        candidate_count=0,
        surfaces=(surface,),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=tuple(
            sorted(
                (path, str(entry["source_sha256"])) for path, entry in manifest.items()
            )
        ),
    )
    return index, surface, summary, manifest, workspace, artifacts


def _graph(
    fixture: GraphFixture,
    route_map: OperationalRouteMap | None = None,
    *,
    max_nodes: int = 256,
) -> dict[str, object]:
    return extract_surface_graph_v5(
        *fixture,
        route_map=route_map or OperationalRouteMap((), ()),
        max_nodes=max_nodes,
    )


def _rows(graph: dict[str, object], category: str) -> list[dict[str, object]]:
    value = graph[category]
    assert isinstance(value, list)
    assert all(isinstance(row, dict) for row in value)
    return cast(list[dict[str, object]], value)


def _source_text(row: dict[str, object]) -> str:
    value = row["text"]
    assert isinstance(value, str)
    return value


def test_imported_http_handler_adds_one_hashed_connected_path(
    tmp_path: Path,
) -> None:
    raw = (
        b"from http.server import BaseHTTPRequestHandler\n"
        b"class Endpoint(BaseHTTPRequestHandler):\n"
        b"    def do_GET(self):\n"
        b"        route = self.path\n"
        b"        worker = Worker()\n"
        b"        worker.run(route)\n"
        b"class Worker:\n"
        b"    def run(self, route):\n"
        b"        dangerous(route)\n"
    )
    fixture = _fixture(
        tmp_path, {"server.py": raw}, surface_path="server.py", surface_line=9
    )

    graph = _graph(fixture)

    assert graph["kind"] == "simple_surface_evidence_graph_v5"
    assert graph["proof_semantics_revision"] == "v5-source-bound-3"
    paths = [
        row
        for row in _rows(graph, "paths")
        if row.get("kind") == "stdlib_http_call_path_v5"
    ]
    assert len(paths) == 1
    path = paths[0]
    assert path["assurance"] == "SYNTACTIC_REACHABILITY"
    steps = _rows(path, "steps")
    assert [(step["role"], step["line"]) for step in steps] == [
        ("ROUTE_ENTRY", 3),
        ("REQUEST_CONTEXT", 4),
        ("CALL", 5),
        ("CALL", 6),
        ("SINK", 9),
    ]
    assert all(
        step["source_sha256"] == hashlib.sha256(raw).hexdigest() for step in steps
    )
    assert {(row["path"], row["line"]) for row in _rows(graph, "source_lines")} >= {
        ("server.py", line) for line in (3, 4, 5, 6, 9)
    }
    edge_ids = path["edge_ids"]
    assert isinstance(edge_ids, list)
    assert len(edge_ids) == len(steps) - 1
    assert not any(
        row["reason"]
        in {
            "EXTERNAL_IMPLEMENTATION_UNAVAILABLE",
            "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        }
        for row in _rows(graph, "gaps")
    )


@pytest.mark.parametrize(
    "shadow_path", ["http.py", "http/__init__.py", "http/server.py"]
)
def test_pinned_local_http_shadow_cannot_prove_stdlib_route(
    tmp_path: Path, shadow_path: str
) -> None:
    raw = (
        b"from http.server import BaseHTTPRequestHandler\n"
        b"class Endpoint(BaseHTTPRequestHandler):\n"
        b"    def do_GET(self):\n"
        b"        dangerous(self.path)\n"
    )
    fixture = _fixture(
        tmp_path,
        {"server.py": raw, shadow_path: b"# local shadow\n"},
        surface_path="server.py",
        surface_line=4,
    )

    graph = _graph(fixture)

    assert not any(
        row.get("kind") == "stdlib_http_call_path_v5" for row in _rows(graph, "paths")
    )
    assert "HTTP_STDLIB_SHADOW_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_untracked_local_http_shadow_cannot_prove_stdlib_route(tmp_path: Path) -> None:
    raw = (
        b"from http.server import BaseHTTPRequestHandler\n"
        b"class Endpoint(BaseHTTPRequestHandler):\n"
        b"    def do_GET(self):\n"
        b"        dangerous(self.path)\n"
    )
    fixture = _fixture(
        tmp_path, {"server.py": raw}, surface_path="server.py", surface_line=4
    )
    shadow = fixture[4] / "http.py"
    shadow.write_bytes(b"# untracked local shadow\n")

    graph = _graph(fixture)

    assert not any(
        row.get("kind") == "stdlib_http_call_path_v5" for row in _rows(graph, "paths")
    )
    assert "HTTP_STDLIB_SHADOW_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_pinned_http_shadow_remains_unproven_after_checkout_removal(
    tmp_path: Path,
) -> None:
    fixture = _fixture(
        tmp_path,
        {
            "server.py": b"from http.server import BaseHTTPRequestHandler\n",
            "http.py": b"# committed shadow\n",
        },
        surface_path="server.py",
        surface_line=1,
    )
    (fixture[4] / "http.py").unlink()

    assert not graph_v5._stdlib_http_shadow_absent(
        fixture[4], fixture[0].commit_id, "server.py"
    )


def test_v5_reuses_supplied_pinned_call_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = b"def entry(value):\n    return dangerous(value)\n"
    fixture = _fixture(tmp_path, {"app.py": raw}, surface_path="app.py", surface_line=2)
    workspace = fixture[4]
    call_index = build_python_call_path_index(workspace, ("app.py",))
    expected = _graph(fixture)

    def no_rebuild(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("v5 rebuilt a supplied call index")

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_evidence_graph_v4.build_python_call_path_index",
        no_rebuild,
    )
    actual = extract_surface_graph_v5(
        *fixture, route_map=OperationalRouteMap((), ()), call_index=call_index
    )
    assert actual == expected


def test_namesake_handler_remains_an_explicit_graph_gap(tmp_path: Path) -> None:
    raw = (
        b"class BaseHTTPRequestHandler: pass\n"
        b"class Endpoint(BaseHTTPRequestHandler):\n"
        b"    def do_GET(self):\n"
        b"        route = self.path\n"
        b"        dangerous(route)\n"
    )
    fixture = _fixture(
        tmp_path, {"server.py": raw}, surface_path="server.py", surface_line=5
    )

    graph = _graph(fixture)

    assert not any(
        row.get("kind") == "stdlib_http_call_path_v5" for row in _rows(graph, "paths")
    )
    assert "HTTP_HANDLER_IMPORT_UNPROVEN" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_http_path_budget_failure_does_not_leave_unbounded_lines(
    tmp_path: Path,
) -> None:
    raw = (
        b"from http.server import BaseHTTPRequestHandler\n"
        b"class Endpoint(BaseHTTPRequestHandler):\n"
        b"    def do_GET(self):\n"
        b"        route = self.path\n"
        b"        worker = Worker()\n"
        b"        worker.run(route)\n"
        b"class Worker:\n"
        b"    def run(self, route):\n"
        b"        dangerous(route)\n"
    )
    fixture = _fixture(
        tmp_path, {"server.py": raw}, surface_path="server.py", surface_line=9
    )

    graph = _graph(fixture, max_nodes=5)

    total = sum(
        len(_rows(graph, key)) for key in ("source_lines", "ast_facts", "nodes")
    )
    assert total <= 5
    assert "CONTEXT_BUDGET_EXHAUSTED" in {row["reason"] for row in _rows(graph, "gaps")}


def test_source_mutation_cannot_add_a_http_graph_path(tmp_path: Path) -> None:
    raw = (
        b"from http.server import BaseHTTPRequestHandler\n"
        b"class Endpoint(BaseHTTPRequestHandler):\n"
        b"    def do_GET(self):\n"
        b"        dangerous(self.path)\n"
    )
    fixture = _fixture(
        tmp_path, {"server.py": raw}, surface_path="server.py", surface_line=4
    )
    (fixture[4] / "server.py").write_bytes(raw + b"# changed\n")

    with pytest.raises(ValueError, match="SOURCE_HASH_MISMATCH"):
        _graph(fixture)


def test_source_line_batch_failure_leaves_graph_unchanged(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {"a.py": b"value = 1\n", "z.py": b"#" + b"x" * 65537 + b"\n"},
        surface_path="a.py",
        surface_line=1,
    )
    index, _surface, summary, manifest, workspace, artifacts = fixture
    graph: dict[str, object] = {"source_files": [], "source_lines": []}

    added = graph_v5._add_http_source_lines(
        graph,
        {("a.py", 1), ("z.py", 1)},
        index,
        summary,
        manifest,
        workspace,
        artifacts,
    )

    assert not added
    assert graph == {"source_files": [], "source_lines": []}


_PARSER = b"""import xml.etree.ElementTree as XML
import pkg.endpoints as actions

def build():
    rows = XML.parse('./cfg/routes.xml').findall('mapping')
    routes = []
    for node in rows:
        endpoint = node.findtext('url')
        symbol = node.findtext('type')
        handler = getattr(actions, symbol)
        routes.append((endpoint, handler))
    return routes

if __name__ == '__main__':
    build()
"""
_TARGET = b"class Catalog:\n    def run(self):\n        dangerous()\n"
_DIRECT_PARSER = b"""import xml.etree.ElementTree as XML
import pkg.endpoints as actions
from http.server import BaseHTTPRequestHandler, HTTPServer

def dispatch(request_path):
    rows = XML.parse('./cfg/routes.xml').findall('mapping')
    routes = []
    for node in rows:
        endpoint = node.findtext('url')
        symbol = node.findtext('type')
        handler = getattr(actions, symbol)
        routes.append((endpoint, handler))
    for endpoint, handler in routes:
        if endpoint == request_path:
            handler().run(request_path)

class Endpoint(BaseHTTPRequestHandler):
    def do_GET(self):
        dispatch(self.path)

if __name__ == '__main__':
    dispatch('')
    HTTPServer(('127.0.0.1', 0), Endpoint).serve_forever()
"""
_DIRECT_TARGET = (
    b"class Catalog:\n    def run(self, value):\n        dangerous(value)\n"
)
_CLASS_REGISTRY_PARSER = b"""import xml.etree.ElementTree as XML
import pkg.endpoints as actions
from http.server import BaseHTTPRequestHandler, HTTPServer

class Registry:
    entries = []
    for item in XML.parse('./cfg/routes.xml').findall('mapping'):
        instance = getattr(actions, item.findtext('type'))(url=item.findtext('url'))
        entries.append(instance)

    def select(self, request):
        for entry in self.entries:
            if request.path == entry.url:
                entry.execute(request)

class Endpoint(BaseHTTPRequestHandler):
    def do_GET(self):
        Registry().select(self)

if __name__ == '__main__':
    HTTPServer(('127.0.0.1', 0), Endpoint).serve_forever()
"""
_INHERITED_TARGET = b"""class Operation:
    def __init__(self, url):
        self.url = url
    def execute(self, request):
        return self.run(request)

class Catalog(Operation):
    def run(self, request):
        dangerous(request.path)
"""
_COMPOSITE_PARSER = b"""import pkg.endpoints as actions
import xml.etree.ElementTree as XML
import urllib.parse as urlparse
from http.server import BaseHTTPRequestHandler

class RequestBase:
    def get_content(self):
        return ''

class Registry(RequestBase):
    entries = []
    for item in XML.parse('./cfg/routes.xml').findall('mapping'):
        instance = getattr(actions, item.findtext('type'))(
            url=item.findtext('url'), title=item.findtext('title'))
        entries.append(instance)

    def __init__(self, request):
        self.request = request

    def get_content(self):
        content = ''
        for entry in self.entries:
            if self.request.path == entry.url:
                content = entry.lesson(self.request) + entry.execute(self.request)
                break
        return content

class StaticHandler(RequestBase):
    pass

class Endpoint(BaseHTTPRequestHandler):
    routes = {}
    for item in XML.parse('./cfg/routes.xml').findall('mapping'):
        routes[item.findtext('url')] = {'template': item.findtext('template')}

    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        self.path = parsed.path
        if self.path in self.routes:
            handler = Registry(self)
        else:
            handler = StaticHandler()
        try:
            content = handler.get_content()
        except Exception:
            content = ''
"""
_COMPOSITE_TARGET = b"""class Operation:
    def __init__(self, url, title=''):
        self.url = url
        self.title = title

    def lesson(self, request):
        return ''

    def execute(self, request):
        if getattr(request, 'security_mode', 'open') == 'secure':
            return self.run_secure(request)
        return self.run(request)

    def run_secure(self, request):
        return ''

class Catalog(Operation):
    def run(self, request):
        value = request.path
        try:
            dangerous(value)
        except ValueError:
            return ''
"""
_COMPOSITE_SERVER = b"""from http.server import ThreadingHTTPServer

class Server(ThreadingHTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
"""
_COMPOSITE_START = b"""from pkg.httpd import Server
from pkg.dispatch import Endpoint

def main():
    httpd = Server(('127.0.0.1', 0), Endpoint)
    httpd.serve_forever()

if __name__ == '__main__':
    main()
"""
_XML = (
    b"<root><mapping><url>/catalog</url><type>Catalog</type>"
    b"<good_path>private lesson</good_path><evil_path>private exploit</evil_path>"
    b"<source>private answer</source><sink>private answer</sink>"
    b"<description>private description</description>"
    b"<objective>private objective</objective>"
    b"</mapping></root>"
)
_LAUNCHER = (
    b"FROM python:3.12\nWORKDIR /service\nCOPY . .\n"
    b'CMD ["python", "-m", "pkg.dispatch"]\n'
)
_SEPARATE_LAUNCHER = (
    b'FROM python:3.12\nWORKDIR /service\nCOPY . .\nCMD ["python", "-m", "pkg.start"]\n'
)
_BUILD_ONLY_ENTRY = b"from pkg.dispatch import dispatch\ndispatch('')\n"


def _git_fixture(
    tmp_path: Path,
    *,
    parser_source: bytes = _PARSER,
    target_source: bytes = _TARGET,
    xml_source: bytes = _XML,
    launcher_source: bytes = _LAUNCHER,
    entry_source: bytes | None = None,
    extra_sources: Mapping[str, bytes] | None = None,
    require_binding: bool = True,
    surface_line: int = 3,
    surface_symbol: str = "Catalog.run",
) -> tuple[GraphFixture, OperationalRouteMap]:
    sources = {
        "pkg/__init__.py": b"",
        "pkg/dispatch.py": parser_source,
        "pkg/endpoints.py": target_source,
        "cfg/routes.xml": xml_source,
        "Dockerfile": launcher_source,
    }
    if entry_source is not None:
        sources["pkg/start.py"] = entry_source
    if extra_sources is not None:
        sources.update(extra_sources)
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    for relative, raw in sources.items():
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "add", "--", *sources], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
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
        subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"])
        .decode()
        .strip()
    )
    identity = CheckpointIdentity(
        analysis_id="graph-v5-xml",
        workspace_id="graph-v5-xml-workspace",
        commit_id=commit,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    summary = collect_python_ast(
        workspace,
        tuple(sorted(path for path in sources if path.endswith(".py"))),
        artifacts,
        max_source_bytes=2 * 1024 * 1024,
    )
    manifest = index_ast_manifest(artifacts, summary)
    evidence_ref = artifacts.put_json({"kind": "xml_fixture"})
    surface = AttackSurface(
        surface_id="surface-xml-1",
        type="COMMAND_EXECUTION",
        path="pkg/endpoints.py",
        symbol=surface_symbol,
        line=surface_line,
        linked_candidate_ids=(),
        evidence_refs=(evidence_ref,),
        detector="AST",
    )
    index = SurfaceIndex(
        scope_fingerprint="f" * 64,
        static_bundle_hash="b" * 64,
        ast_manifest_hash=hashlib.sha256(canonical_bytes(summary)).hexdigest(),
        workspace_id=identity.workspace_id,
        commit_id=commit,
        candidate_inventory_hash="d" * 64,
        candidate_count=0,
        surfaces=(surface,),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=tuple(
            sorted(
                (path, str(entry["source_sha256"])) for path, entry in manifest.items()
            )
        ),
    )
    route_map = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser_source,
        "Dockerfile",
        runtime_workdir="/service",
    )
    if require_binding:
        assert route_map.bindings, route_map
    return (index, surface, summary, manifest, workspace, artifacts), route_map


def test_operational_xml_binding_is_redacted_and_not_a_dispatch_edge(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(tmp_path)

    graph = _graph(fixture, route_map)

    assert len(_rows(graph, "operational_routes")) == 1
    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }
    serialized = json.dumps(graph)
    for private in (
        "good_path",
        "evil_path",
        "private lesson",
        "private exploit",
        "private answer",
        "description",
        "objective",
    ):
        assert private not in serialized


def test_operational_xml_direct_dispatch_adds_source_bound_path(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path, parser_source=_DIRECT_PARSER, target_source=_DIRECT_TARGET
    )

    graph = _graph(fixture, route_map)

    paths = [
        row
        for row in _rows(graph, "paths")
        if row.get("kind") == "operational_xml_call_path_v5"
    ]
    assert len(paths) == 1
    assert paths[0]["assurance"] == "SYNTACTIC_REACHABILITY"
    assert [step["role"] for step in _rows(paths[0], "steps")] == [
        "ROUTE_ENTRY",
        "CALL",
        "REQUEST_CONTEXT",
        "CALL",
        "CALL",
        "CALL",
        "CALL",
        "SINK",
    ]
    assert "DYNAMIC_DISPATCH_UNRESOLVED" not in {
        row["reason"] for row in _rows(graph, "gaps")
    }
    assert any(
        "HTTPServer" in _source_text(row)
        for row in _rows(graph, "source_lines")
        if row["path"] == "pkg/dispatch.py"
    )
    serialized = json.dumps(graph)
    for private in ("good_path", "evil_path", "private answer", "description"):
        assert private not in serialized


def test_class_body_xml_registry_reaches_inherited_dispatch_override(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_CLASS_REGISTRY_PARSER,
        target_source=_INHERITED_TARGET,
        surface_line=9,
    )

    graph = _graph(fixture, route_map)

    paths = [
        row
        for row in _rows(graph, "paths")
        if row.get("kind") == "operational_xml_call_path_v5"
    ]
    assert len(paths) == 1
    path = paths[0]
    assert path["blocking_gaps"] == []
    assert [step["role"] for step in _rows(path, "steps")] == [
        "ROUTE_ENTRY",
        "CALL",
        "CALL",
        "REQUEST_CONTEXT",
        "CALL",
        "CALL",
        "CALL",
        "CALL",
        "SINK",
    ]
    assert [(step["path"], step["line"]) for step in _rows(path, "steps")][-3:] == [
        ("pkg/dispatch.py", 14),
        ("pkg/endpoints.py", 5),
        ("pkg/endpoints.py", 9),
    ]
    assert "DYNAMIC_DISPATCH_UNRESOLVED" not in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_imported_http_entry_reaches_class_body_registry_and_override(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_COMPOSITE_PARSER,
        target_source=_COMPOSITE_TARGET,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=_COMPOSITE_START,
        extra_sources={"pkg/httpd.py": _COMPOSITE_SERVER},
        surface_line=21,
        surface_symbol="synthetic.sink-label",
    )

    graph = _graph(fixture, route_map)

    paths = [
        row
        for row in _rows(graph, "paths")
        if row.get("kind") == "operational_xml_call_path_v5"
    ]
    assert len(paths) == 1
    assert paths[0]["blocking_gaps"] == []
    steps = _rows(paths[0], "steps")
    assert steps[0]["path"] == "pkg/start.py"
    assert steps[-1]["path"] == "pkg/endpoints.py"
    assert steps[-1]["line"] == 21
    assert "REQUEST_CONTEXT" in {step["role"] for step in steps}
    assert "DYNAMIC_DISPATCH_UNRESOLVED" not in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_verified_operational_http_path_adds_redacted_input_and_control_context(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_COMPOSITE_PARSER,
        target_source=_COMPOSITE_TARGET,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=_COMPOSITE_START,
        extra_sources={"pkg/httpd.py": _COMPOSITE_SERVER},
        surface_line=21,
        surface_symbol="synthetic.sink-label",
    )

    graph = _graph(fixture, route_map)

    path = next(
        row
        for row in _rows(graph, "paths")
        if row["kind"] == "operational_xml_call_path_v5"
    )
    lines = {
        row["line"]: _source_text(row)
        for row in _rows(graph, "source_lines")
        if row["path"] == "pkg/dispatch.py"
    }
    assert lines[37] == "        parsed = urlparse.urlparse(self.path)"
    assert lines[38] == "        self.path = parsed.path"
    assert lines[39] == "        if self.path in self.routes:"
    assert lines[41] == "        else:"
    steps = _rows(path, "steps")
    assert {(step["path"], step["line"]) for step in steps}.isdisjoint(
        {("pkg/dispatch.py", line) for line in (37, 38, 39, 41)}
    )
    edge_ids = path["edge_ids"]
    assert isinstance(edge_ids, list)
    assert len(edge_ids) == len(steps) - 1
    assert len(_rows(graph, "edges")) == len(steps) - 1
    assert path["assurance"] == "SYNTACTIC_REACHABILITY"
    assert not any(
        row["path"] == "cfg/routes.xml" for row in _rows(graph, "source_lines")
    )
    serialized = json.dumps(graph)
    for private in (
        "good_path",
        "evil_path",
        "private answer",
        "private objective",
    ):
        assert private not in serialized


def test_supplemental_http_context_prepares_each_file_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_COMPOSITE_PARSER,
        target_source=_COMPOSITE_TARGET,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=_COMPOSITE_START,
        extra_sources={"pkg/httpd.py": _COMPOSITE_SERVER},
        surface_line=21,
        surface_symbol="synthetic.sink-label",
    )
    original_locations = graph_v5._supplemental_http_locations
    original_prepare = prepare_file_context
    supplemental_started = False
    prepare_count = 0

    def mark_supplemental_phase(
        index: SurfaceIndex, workspace: Path, steps: list[dict[str, object]]
    ) -> list[tuple[str, int]]:
        nonlocal supplemental_started
        supplemental_started = True
        return original_locations(index, workspace, steps)

    def count_prepared_file(
        artifacts: SimpleArtifactRepository,
        ast_summary: Mapping[str, object],
        workspace: Path,
        path: str,
        *,
        manifest_index: Mapping[str, Mapping[str, object]] | None = None,
    ) -> PreparedFileContext:
        nonlocal prepare_count
        if supplemental_started and path == "pkg/dispatch.py":
            prepare_count += 1
        return original_prepare(
            artifacts,
            ast_summary,
            workspace,
            path,
            manifest_index=manifest_index,
        )

    monkeypatch.setattr(
        graph_v5, "_supplemental_http_locations", mark_supplemental_phase
    )
    monkeypatch.setattr(graph_v5, "prepare_file_context", count_prepared_file)

    graph = _graph(fixture, route_map)

    assert {
        row["line"]
        for row in _rows(graph, "source_lines")
        if row["path"] == "pkg/dispatch.py"
    } >= {37, 38, 39, 41}
    assert prepare_count == 1


def test_supplemental_http_context_rechecks_cached_source_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_COMPOSITE_PARSER,
        target_source=_COMPOSITE_TARGET,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=_COMPOSITE_START,
        extra_sources={"pkg/httpd.py": _COMPOSITE_SERVER},
        surface_line=21,
        surface_symbol="synthetic.sink-label",
    )
    original_locations = graph_v5._supplemental_http_locations
    supplemental_started = False
    mutated = False

    def mark_supplemental_phase(
        index: SurfaceIndex, workspace: Path, steps: list[dict[str, object]]
    ) -> list[tuple[str, int]]:
        nonlocal supplemental_started
        locations = original_locations(index, workspace, steps)
        supplemental_started = True
        return locations

    def mutate_after_first_source_verification(
        workspace: Path, path: str, expected_hash: str
    ) -> bytes:
        nonlocal mutated
        raw = original_raw_source(workspace, path, expected_hash)
        if supplemental_started and path == "pkg/dispatch.py" and not mutated:
            source = workspace / path
            source.write_bytes(source.read_bytes() + b"\n# changed mid-scan\n")
            mutated = True
        return raw

    monkeypatch.setattr(
        graph_v5, "_supplemental_http_locations", mark_supplemental_phase
    )
    monkeypatch.setattr(graph_v5, "_raw_source", mutate_after_first_source_verification)

    with pytest.raises(ValueError, match="SURFACE_GRAPH_SOURCE_HASH_MISMATCH"):
        _graph(fixture, route_map)
    assert mutated


def test_supplemental_http_line_uses_redacted_source(tmp_path: Path) -> None:
    parser = _COMPOSITE_PARSER.replace(
        b"parsed = urlparse.urlparse(self.path)",
        b"parsed = urlparse.urlparse(self.path) # Authorization: synthetic-secret",
    )
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=parser,
        target_source=_COMPOSITE_TARGET,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=_COMPOSITE_START,
        extra_sources={"pkg/httpd.py": _COMPOSITE_SERVER},
        surface_line=21,
        surface_symbol="synthetic.sink-label",
    )

    graph = _graph(fixture, route_map)

    line = next(
        row
        for row in _rows(graph, "source_lines")
        if row["path"] == "pkg/dispatch.py" and row["line"] == 37
    )
    assert "parsed = urlparse.urlparse(self.path)" in _source_text(line)
    assert "synthetic-secret" not in json.dumps(graph)


def test_invalid_supplemental_line_does_not_hide_valid_neighbor(
    tmp_path: Path,
) -> None:
    parser = _COMPOSITE_PARSER.replace(
        b"parsed = urlparse.urlparse(self.path)",
        b"parsed = urlparse.urlparse(self.path) # " + b"x" * 65537,
    )
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=parser,
        target_source=_COMPOSITE_TARGET,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=_COMPOSITE_START,
        extra_sources={"pkg/httpd.py": _COMPOSITE_SERVER},
        surface_line=21,
        surface_symbol="synthetic.sink-label",
    )

    graph = _graph(fixture, route_map)

    assert any(
        row["kind"] == "operational_xml_call_path_v5" for row in _rows(graph, "paths")
    )
    lines = {
        row["line"]: _source_text(row)
        for row in _rows(graph, "source_lines")
        if row["path"] == "pkg/dispatch.py"
    }
    assert 37 not in lines
    assert lines[38] == "        self.path = parsed.path"
    assert lines[39] == "        if self.path in self.routes:"


def test_supplemental_http_context_never_displaces_a_verified_path(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_COMPOSITE_PARSER,
        target_source=_COMPOSITE_TARGET,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=_COMPOSITE_START,
        extra_sources={"pkg/httpd.py": _COMPOSITE_SERVER},
        surface_line=21,
        surface_symbol="synthetic.sink-label",
    )

    graph = _graph(fixture, route_map, max_nodes=31)

    assert any(
        row["kind"] == "operational_xml_call_path_v5" for row in _rows(graph, "paths")
    )
    assert (
        sum(
            len(_rows(graph, category))
            for category in ("source_lines", "ast_facts", "nodes")
        )
        <= 31
    )
    assert ("pkg/dispatch.py", 37) not in {
        (row["path"], row["line"]) for row in _rows(graph, "source_lines")
    }


@pytest.mark.parametrize(
    "parser_source,target_source,entry_source",
    [
        (
            _COMPOSITE_PARSER.replace(
                b"routes[item.findtext('url')]", b"routes['/unrelated']"
            ),
            _COMPOSITE_TARGET,
            _COMPOSITE_START,
        ),
        (
            _COMPOSITE_PARSER.replace(
                b"self.request.path == entry.url", b"self.request.path != entry.url"
            ),
            _COMPOSITE_TARGET,
            _COMPOSITE_START,
        ),
        (
            _COMPOSITE_PARSER.replace(
                b"entry.lesson(self.request) + entry.execute(self.request)",
                b"entry.lesson(self.request) + entry.lesson(self.request)",
            ),
            _COMPOSITE_TARGET,
            _COMPOSITE_START,
        ),
        (
            _COMPOSITE_PARSER.replace(
                b"handler = Registry(self)", b"handler = StaticHandler()"
            ),
            _COMPOSITE_TARGET,
            _COMPOSITE_START,
        ),
        (
            _COMPOSITE_PARSER.replace(
                b"self.path = parsed.path", b"self.path = '/fixed'"
            ),
            _COMPOSITE_TARGET,
            _COMPOSITE_START,
        ),
        (
            _COMPOSITE_PARSER,
            _COMPOSITE_TARGET.replace(b"title=''", b"title=unknown_default()"),
            _COMPOSITE_START,
        ),
        (
            _COMPOSITE_PARSER,
            _COMPOSITE_TARGET,
            _COMPOSITE_START.replace(
                b"Server(('127.0.0.1', 0), Endpoint)",
                b"Server(('127.0.0.1', 0), OtherEndpoint)",
            ),
        ),
    ],
)
def test_imported_http_registry_rejects_broken_composite_link(
    tmp_path: Path,
    parser_source: bytes,
    target_source: bytes,
    entry_source: bytes,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=parser_source,
        target_source=target_source,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=entry_source,
        extra_sources={"pkg/httpd.py": _COMPOSITE_SERVER},
        surface_line=21,
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


@pytest.mark.parametrize(
    "parser_source,target_source",
    [
        (
            _CLASS_REGISTRY_PARSER.replace(b"Registry().select(self)", b"pass"),
            _INHERITED_TARGET,
        ),
        (
            _CLASS_REGISTRY_PARSER.replace(
                b"entry.execute(request)", b"entry.run(request)"
            ),
            _INHERITED_TARGET,
        ),
        (
            _CLASS_REGISTRY_PARSER.replace(
                b"request.path == entry.url", b"request.path != entry.url"
            ),
            _INHERITED_TARGET,
        ),
        (
            _CLASS_REGISTRY_PARSER.replace(
                b"HTTPServer(('127.0.0.1', 0), Endpoint)",
                b"HTTPServer(('127.0.0.1', 0), OtherEndpoint)",
            ),
            _INHERITED_TARGET,
        ),
        (
            _CLASS_REGISTRY_PARSER,
            _INHERITED_TARGET.replace(b"class Catalog(Operation):", b"class Catalog:"),
        ),
        (
            _CLASS_REGISTRY_PARSER,
            _INHERITED_TARGET.replace(
                b"return self.run(request)", b"return self.other(request)"
            ),
        ),
        (
            _CLASS_REGISTRY_PARSER.replace(
                b"    def select(self, request):",
                b"    def __init__(self):\n"
                b"        self.entries = []\n\n"
                b"    def select(self, request):",
            ),
            _INHERITED_TARGET,
        ),
        (
            _CLASS_REGISTRY_PARSER.replace(
                b"        for entry in self.entries:",
                b"        self.entries = []\n        for entry in self.entries:",
            ),
            _INHERITED_TARGET,
        ),
        (
            _CLASS_REGISTRY_PARSER.replace(
                b"        for entry in self.entries:",
                b"        del self.entries\n        for entry in self.entries:",
            ),
            _INHERITED_TARGET,
        ),
    ],
)
def test_class_body_xml_registry_rejects_unproven_call_chain(
    tmp_path: Path, parser_source: bytes, target_source: bytes
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=parser_source,
        target_source=target_source,
        surface_line=9,
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


@pytest.mark.parametrize("overwrite", [b"self.url = '/fixed'", b"del self.url"])
def test_inherited_route_rewrite_cannot_prove_xml_dispatch(
    tmp_path: Path, overwrite: bytes
) -> None:
    target = _INHERITED_TARGET.replace(
        b"        self.url = url\n",
        b"        self.url = url\n        " + overwrite + b"\n",
    )
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_CLASS_REGISTRY_PARSER,
        target_source=target,
        surface_line=10,
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_operational_xml_direct_dispatch_rejects_local_http_shadow(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_DIRECT_PARSER,
        target_source=_DIRECT_TARGET,
        extra_sources={"pkg/http/__init__.py": b"# shadow standard HTTP package\n"},
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_operational_xml_parser_main_guard_not_run_by_build_only_launcher(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_DIRECT_PARSER,
        target_source=_DIRECT_TARGET,
        launcher_source=_SEPARATE_LAUNCHER,
        entry_source=_BUILD_ONLY_ENTRY,
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_operational_xml_path_rejects_unverified_top_level_import_side_effect(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=b"import pkg.helper\n" + _DIRECT_PARSER,
        target_source=_DIRECT_TARGET,
        extra_sources={"pkg/helper.py": b"import os\nos.chdir('/elsewhere')\n"},
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


@pytest.mark.parametrize(
    "parser,target",
    [
        (
            _DIRECT_PARSER,
            _DIRECT_TARGET.replace(
                b"def run(self, value):",
                b"def run(self, value=__import__('os').chdir('/elsewhere')):",
            ),
        ),
        (
            _DIRECT_PARSER,
            _DIRECT_TARGET.replace(
                b"def run(self, value):",
                b"def run(self, value: __import__('os').chdir('/elsewhere')):",
            ),
        ),
        (
            _DIRECT_PARSER.replace(
                b"def do_GET(self):",
                b"def do_GET(self=unknown_at_import()):",
            ),
            _DIRECT_TARGET,
        ),
        (
            _DIRECT_PARSER.replace(
                b"def do_GET(self):",
                b"def do_GET(self: unknown_at_import()):",
            ),
            _DIRECT_TARGET,
        ),
        (
            _DIRECT_PARSER.replace(
                b"def dispatch(request_path):",
                b"def dispatch(request_path: unknown_at_import()):",
            ),
            _DIRECT_TARGET,
        ),
    ],
    ids=(
        "target_default",
        "target_annotation",
        "entry_default",
        "entry_annotation",
        "parser_annotation",
    ),
)
def test_operational_xml_path_rejects_import_time_signature_side_effect(
    tmp_path: Path, parser: bytes, target: bytes
) -> None:
    clean_root = tmp_path / "clean"
    clean_root.mkdir()
    _clean_fixture, clean_routes = _git_fixture(
        clean_root, parser_source=_DIRECT_PARSER, target_source=_DIRECT_TARGET
    )
    variant_root = tmp_path / "variant"
    variant_root.mkdir()
    fixture, _variant_routes = _git_fixture(
        variant_root,
        parser_source=parser,
        target_source=target,
        require_binding=False,
    )
    binding = replace(
        clean_routes.bindings[0],
        parser_sha256=hashlib.sha256(parser).hexdigest(),
        target_sha256=hashlib.sha256(target).hexdigest(),
    )

    assert (
        graph_v5._direct_operational_xml_path(
            fixture[0], fixture[1], fixture[4], binding
        )
        is None
    )


def test_operational_xml_path_rejects_package_initializer_side_effect(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path,
        parser_source=_DIRECT_PARSER,
        target_source=_DIRECT_TARGET,
        extra_sources={"pkg/__init__.py": b"import os\nos.chdir('/elsewhere')\n"},
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


@pytest.mark.parametrize(
    "parser,target",
    [
        (
            _DIRECT_PARSER.replace(b"dispatch(self.path)", b"dispatch('/catalog')"),
            _DIRECT_TARGET,
        ),
        (
            _DIRECT_PARSER.replace(
                b"handler().run(request_path)", b"handler().run('constant')"
            ),
            _DIRECT_TARGET,
        ),
        (
            _DIRECT_PARSER,
            b"class Catalog:\n    def run(self, value):\n"
            b"        dangerous('constant')\n",
        ),
        (
            _DIRECT_PARSER.replace(
                b"for endpoint, handler in routes:\n"
                b"        if endpoint == request_path:",
                b"for request_path, handler in routes:\n"
                b"        if request_path == request_path:",
            ),
            _DIRECT_TARGET,
        ),
        (
            _DIRECT_PARSER,
            _DIRECT_TARGET + b"Catalog.run = lambda self, value: None\n",
        ),
        (
            _DIRECT_PARSER.replace(
                b"from http.server import BaseHTTPRequestHandler, HTTPServer\n",
                b"from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                b"from collections import deque as BaseHTTPRequestHandler\n",
            ),
            _DIRECT_TARGET,
        ),
    ],
    ids=(
        "constant_entry",
        "constant_dispatch_arg",
        "constant_sink_arg",
        "request_name_rebound",
        "target_method_rebound",
        "http_base_import_rebound",
    ),
)
def test_operational_xml_dispatch_without_connected_request_stays_unresolved(
    tmp_path: Path, parser: bytes, target: bytes
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path, parser_source=parser, target_source=target
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


@pytest.mark.parametrize(
    "parser",
    [
        _DIRECT_PARSER.replace(
            b"    HTTPServer(('127.0.0.1', 0), Endpoint).serve_forever()\n", b""
        ),
        _DIRECT_PARSER.replace(
            b"HTTPServer(('127.0.0.1', 0), Endpoint)",
            b"HTTPServer(('127.0.0.1', 0), object)",
        ),
        _DIRECT_PARSER.replace(
            b"if __name__ == '__main__':\n",
            b"def HTTPServer(*args):\n    return object()\n\n"
            b"if __name__ == '__main__':\n",
        ),
        _DIRECT_PARSER.replace(b"    dispatch('')\n", b"    dispatch('/catalog')\n"),
    ],
    ids=(
        "no_server",
        "different_handler",
        "shadowed_server_constructor",
        "startup_dispatch_may_prevent_server",
    ),
)
def test_operational_xml_dispatch_without_exact_server_registration_stays_unresolved(
    tmp_path: Path, parser: bytes
) -> None:
    fixture, route_map = _git_fixture(
        tmp_path, parser_source=parser, target_source=_DIRECT_TARGET
    )

    graph = _graph(fixture, route_map)

    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_xml_constructor_and_returned_route_list_are_not_request_dispatch(
    tmp_path: Path,
) -> None:
    parser = _PARSER.replace(
        b"handler = getattr(actions, symbol)",
        b"handler = getattr(actions, symbol)()",
    )
    target = b"class Catalog:\n    def __init__(self):\n        dangerous()\n"
    fixture, route_map = _git_fixture(
        tmp_path, parser_source=parser, target_source=target
    )

    graph = _graph(fixture, route_map)

    assert _rows(graph, "operational_routes")
    assert not any(
        row.get("kind") == "operational_xml_call_path_v5"
        for row in _rows(graph, "paths")
    )
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in {
        row["reason"] for row in _rows(graph, "gaps")
    }


def test_moved_xml_after_binding_cannot_supply_graph_fact(tmp_path: Path) -> None:
    fixture, route_map = _git_fixture(tmp_path)
    (fixture[4] / "cfg/routes.xml").write_bytes(_XML + b"\nchanged")

    with pytest.raises(ValueError, match="SURFACE_GRAPH_PINNED_ROUTE_MISMATCH"):
        _graph(fixture, route_map)


def test_forged_route_map_cannot_supply_operational_fact(tmp_path: Path) -> None:
    fixture, route_map = _git_fixture(tmp_path)
    forged = OperationalRouteMap((replace(route_map.bindings[0], route="/forged"),), ())

    with pytest.raises(ValueError, match="SURFACE_GRAPH_PINNED_ROUTE_MISMATCH"):
        _graph(fixture, forged)


def test_prevalidated_operational_routes_are_equivalent_and_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xml_source = _XML.replace(
        b"</root>",
        b"<mapping><url>/other</url><type>Other</type></mapping></root>",
    )
    target_source = _TARGET + (
        b"\nclass Other:\n    def run(self):\n        dangerous()\n"
    )
    fixture, route_map = _git_fixture(
        tmp_path, target_source=target_source, xml_source=xml_source
    )
    assert len(route_map.bindings) == 2
    uncached = _graph(fixture, route_map)
    original_loader = load_operational_routes
    calls = 0

    def count_loader(
        workspace: Path,
        commit_id: str,
        parser_path: str,
        parser_source: bytes,
        launcher_path: str,
        *,
        runtime_workdir: str | None,
        max_bytes: int = 131072,
    ) -> OperationalRouteMap:
        nonlocal calls
        calls += 1
        return original_loader(
            workspace,
            commit_id,
            parser_path,
            parser_source,
            launcher_path,
            runtime_workdir=runtime_workdir,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(graph_v5, "load_operational_routes", count_loader)
    verified = verify_operational_routes_v5(fixture[0], fixture[4], route_map)
    assert isinstance(verified, VerifiedOperationalRoutes)
    assert calls == 1

    def unexpected_loader(*args: object, **kwargs: object) -> OperationalRouteMap:
        pytest.fail("each graph must reuse the plan's verified route bindings")

    monkeypatch.setattr(graph_v5, "load_operational_routes", unexpected_loader)
    for _ in range(2):
        assert (
            extract_surface_graph_v5(
                *fixture, route_map=route_map, verified_routes=verified
            )
            == uncached
        )


@pytest.mark.parametrize(
    "path", ("cfg/routes.xml", "Dockerfile", "pkg/dispatch.py", "pkg/endpoints.py")
)
def test_prevalidated_operational_routes_reject_later_source_mutation(
    tmp_path: Path, path: str
) -> None:
    fixture, route_map = _git_fixture(tmp_path)
    verified = verify_operational_routes_v5(fixture[0], fixture[4], route_map)
    source = fixture[4] / path
    source.write_bytes(source.read_bytes() + b"\n# changed")

    expected = (
        "SURFACE_GRAPH_SOURCE_HASH_MISMATCH"
        if path.endswith(".py")
        else "SURFACE_GRAPH_PINNED_ROUTE_MISMATCH"
    )
    with pytest.raises(ValueError, match=expected):
        extract_surface_graph_v5(
            *fixture, route_map=route_map, verified_routes=verified
        )


def test_prevalidated_routes_recheck_after_graph_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, route_map = _git_fixture(tmp_path)
    verified = verify_operational_routes_v5(fixture[0], fixture[4], route_map)
    config = fixture[4] / "cfg/routes.xml"
    original_http = verified_http_paths

    def mutate_during_graph(
        workspace: Path,
        tracked_hashes: Mapping[str, str],
        surface: AttackSurface,
        *,
        max_hops: int = 6,
        max_paths: int = 4,
    ) -> CandidateCallPaths:
        result = original_http(
            workspace,
            tracked_hashes,
            surface,
            max_hops=max_hops,
            max_paths=max_paths,
        )
        config.write_bytes(config.read_bytes() + b"\nchanged")
        return result

    monkeypatch.setattr(graph_v5, "verified_http_paths", mutate_during_graph)
    with pytest.raises(ValueError, match="SURFACE_GRAPH_PINNED_ROUTE_MISMATCH"):
        extract_surface_graph_v5(
            *fixture, route_map=route_map, verified_routes=verified
        )


def test_prevalidated_operational_routes_reject_scope_or_route_map_change(
    tmp_path: Path,
) -> None:
    fixture, route_map = _git_fixture(tmp_path)
    verified = verify_operational_routes_v5(fixture[0], fixture[4], route_map)
    forged = OperationalRouteMap((replace(route_map.bindings[0], route="/forged"),), ())
    with pytest.raises(ValueError, match="SURFACE_GRAPH_PINNED_ROUTE_MISMATCH"):
        verify_operational_routes_v5(fixture[0], fixture[4], forged)
    with pytest.raises(ValueError, match="SURFACE_GRAPH_PINNED_ROUTE_MISMATCH"):
        extract_surface_graph_v5(*fixture, route_map=forged, verified_routes=verified)
    with pytest.raises(ValueError, match="SURFACE_GRAPH_PINNED_ROUTE_MISMATCH"):
        extract_surface_graph_v5(
            replace(fixture[0], scope_fingerprint="e" * 64),
            *fixture[1:],
            route_map=route_map,
            verified_routes=verified,
        )


_REVIEW_SOURCE = (
    "from http.server import BaseHTTPRequestHandler\n"
    "class Endpoint(BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        value = self.path\n"
    "        dangerous(value)\n"
)
_REVIEW_SHA = hashlib.sha256(_REVIEW_SOURCE.encode()).hexdigest()


def _review_graph() -> dict[str, object]:
    nodes = [
        {
            "node_id": "n-entry",
            "role": "ROUTE_ENTRY",
            "path": "server.py",
            "line": 3,
            "source_sha256": _REVIEW_SHA,
        },
        {
            "node_id": "n-handler",
            "role": "HANDLER_DEFINITION",
            "path": "server.py",
            "line": 3,
            "source_sha256": _REVIEW_SHA,
        },
        {
            "node_id": "n-boundary",
            "role": "REQUEST_CONTEXT",
            "path": "server.py",
            "line": 4,
            "source_sha256": _REVIEW_SHA,
        },
        {
            "node_id": "n-sink",
            "role": "SINK",
            "path": "server.py",
            "line": 5,
            "source_sha256": _REVIEW_SHA,
        },
    ]
    edges = [
        {
            "edge_id": "e-entry",
            "type": "ENTRY",
            "from_node_id": "n-entry",
            "to_node_id": "n-handler",
            "graph_path_id": "p-1",
        },
        {
            "edge_id": "e-boundary",
            "type": "TRUST_BOUNDARY",
            "from_node_id": "n-handler",
            "to_node_id": "n-boundary",
            "graph_path_id": "p-1",
        },
        {
            "edge_id": "e-sink",
            "type": "SENSITIVE_OPERATION",
            "from_node_id": "n-boundary",
            "to_node_id": "n-sink",
            "graph_path_id": "p-1",
        },
    ]
    return {
        "kind": "simple_surface_evidence_graph_v5",
        "anchor": {"surface_id": "surface-v5-1", "path": "server.py", "line": 5},
        "scope_fingerprint": "f" * 64,
        "index_hash": "c" * 64,
        "ast_manifest_hash": "d" * 64,
        "source_files": [{"path": "server.py", "source_sha256": _REVIEW_SHA}],
        "source_lines": [
            {
                "line_id": f"l-{line}",
                "path": "server.py",
                "line": line,
                "text": _REVIEW_SOURCE.splitlines()[line - 1],
                "source_sha256": _REVIEW_SHA,
            }
            for line in (3, 4, 5)
        ],
        "ast_facts": [],
        "nodes": nodes,
        "edges": edges,
        "paths": [
            {
                "path_id": "p-1",
                "kind": "stdlib_http_call_path_v5",
                "provenance": "python_syntax",
                "assurance": "SYNTACTIC_REACHABILITY",
                "steps": nodes,
                "edge_ids": ["e-entry", "e-boundary", "e-sink"],
            }
        ],
        "operational_routes": [],
        "gaps": [],
    }


def _context(graph: dict[str, object]) -> dict[str, object]:
    anchor = cast(dict[str, object], graph["anchor"])
    items = [
        {"category": category, "ordinal": ordinal, "value": value}
        for category in (
            "source_files",
            "source_lines",
            "ast_facts",
            "nodes",
            "edges",
            "paths",
            "operational_routes",
            "gaps",
        )
        for ordinal, value in enumerate(_rows(graph, category))
    ]
    payload: dict[str, object] = {
        "kind": "simple_surface_context_v5",
        "surface_id": anchor["surface_id"],
        "path": anchor["path"],
        "line": anchor["line"],
        "graph_hash": hashlib.sha256(canonical_bytes(graph)).hexdigest(),
        "scope_fingerprint": graph["scope_fingerprint"],
        "surface_index_hash": graph["index_hash"],
        "ast_manifest_hash": graph["ast_manifest_hash"],
        "plan_binding_hash": "e" * 64,
        "part_index": 0,
        "part_count": 1,
        "unavailable_item_count": 0,
        "items": items,
    }
    context_hash = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v5",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": payload["surface_id"],
                "part_index": payload["part_index"],
                "context_hash": context_hash,
            }
        )
    ).hexdigest()
    return {
        "context_payload": payload,
        "graph_payload": graph,
        "context_hash": context_hash,
        "context_id": context_id,
    }


def _response(context: dict[str, object]) -> dict[str, object]:
    digest = cast(str, context["context_hash"])
    return {
        "surface_id": "surface-v5-1",
        "context_id": context["context_id"],
        "status": "NO_HYPOTHESIS",
        "reason": "All source roles reviewed without a supported hypothesis",
        "hypotheses": [],
        "review_evidence": [
            {
                "part": part,
                "location": f"server.py:{line}",
                "context_hash": digest,
                "source_sha256": _REVIEW_SHA,
                "graph_path_id": "p-1",
                "edge_ids": edges,
                "explanation": "Exact source and edge reviewed",
            }
            for part, line, edges in (
                ("ENTRY", 3, ["e-entry"]),
                ("TRUST_BOUNDARY", 4, ["e-boundary"]),
                ("SENSITIVE_OPERATION", 5, ["e-sink"]),
            )
        ],
    }


def test_validator_accepts_three_roles_on_one_pinned_connected_path() -> None:
    context = _context(_review_graph())

    checked = validate_v5_response(context, _response(context))

    assert checked.status == "NO_HYPOTHESIS"
    assert checked.verified_path_id == "p-1"
    assert checked.reviewed_parts == frozenset(
        {"ENTRY", "TRUST_BOUNDARY", "SENSITIVE_OPERATION"}
    )
    assert checked.evidence_locations == ("server.py:3", "server.py:4", "server.py:5")


def test_context_preflight_rejects_changed_graph() -> None:
    context = _context(_review_graph())
    validate_v5_context(context)
    graph = cast(dict[str, object], context["graph_payload"])
    graph["gaps"] = [{"path": "server.py", "reason": "forged"}]

    with pytest.raises(ValueError, match="V5_GRAPH_INVALID"):
        validate_v5_context(context)


def test_extracted_graph_is_valid_validator_input(tmp_path: Path) -> None:
    raw = (
        b"from http.server import BaseHTTPRequestHandler\n"
        b"class Endpoint(BaseHTTPRequestHandler):\n"
        b"    def do_GET(self):\n"
        b"        route = self.path\n"
        b"        worker = Worker()\n"
        b"        worker.run(route)\n"
        b"class Worker:\n"
        b"    def run(self, route):\n"
        b"        dangerous(route)\n"
    )
    graph = _graph(
        _fixture(tmp_path, {"server.py": raw}, surface_path="server.py", surface_line=9)
    )
    context = _context(graph)
    response = _response(context)
    response["status"] = "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    response["review_evidence"] = []

    checked = validate_v5_response(context, response)

    assert checked.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert checked.verified_path_id is None


def test_validator_cannot_join_roles_from_two_paths() -> None:
    graph = _review_graph()
    paths = _rows(graph, "paths")
    first = dict(paths[0])
    first["steps"] = _rows(first, "steps")[:3]
    first["edge_ids"] = ["e-entry", "e-boundary"]
    second_nodes = [
        {
            "node_id": "n-call",
            "role": "CALL",
            "path": "server.py",
            "line": 4,
            "source_sha256": _REVIEW_SHA,
        },
        {
            "node_id": "n-sink",
            "role": "SINK",
            "path": "server.py",
            "line": 5,
            "source_sha256": _REVIEW_SHA,
        },
    ]
    paths[:] = [
        first,
        {
            "path_id": "p-2",
            "kind": "call_path_v1",
            "provenance": "python_syntax",
            "assurance": "SYNTACTIC_REACHABILITY",
            "steps": second_nodes,
            "edge_ids": ["e-other"],
        },
    ]
    _rows(graph, "nodes").append(second_nodes[0])
    _rows(graph, "edges")[:] = [
        edge for edge in _rows(graph, "edges") if edge["edge_id"] != "e-sink"
    ] + [
        {
            "edge_id": "e-other",
            "type": "SENSITIVE_OPERATION",
            "from_node_id": "n-call",
            "to_node_id": "n-sink",
            "graph_path_id": "p-2",
        }
    ]
    context = _context(graph)
    response = _response(context)
    response["status"] = "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    review = cast(list[dict[str, object]], response["review_evidence"])
    review[2]["graph_path_id"] = "p-2"
    review[2]["edge_ids"] = ["e-other"]

    checked = validate_v5_response(context, response)

    assert checked.reviewed_parts == frozenset()
    assert checked.verified_path_id is None


def test_validator_rejects_wrong_edge_and_changed_graph_hash() -> None:
    context = _context(_review_graph())
    wrong_edge = _response(context)
    cast(list[dict[str, object]], wrong_edge["review_evidence"])[2]["edge_ids"] = [
        "e-entry"
    ]
    with pytest.raises(ValueError, match="V5_REVIEW_EDGE_INVALID"):
        validate_v5_response(context, wrong_edge)

    changed_graph = _review_graph()
    changed_context = _context(changed_graph)
    changed_graph["gaps"] = [{"path": "server.py", "reason": "forged"}]
    with pytest.raises(ValueError, match="V5_GRAPH_INVALID"):
        validate_v5_response(changed_context, _response(changed_context))


def test_validator_rejects_invisible_role_or_unresolved_no_hypothesis() -> None:
    graph = _review_graph()
    context = _context(graph)
    payload = cast(dict[str, object], context["context_payload"])
    items = cast(list[dict[str, object]], payload["items"])
    payload["items"] = [
        item
        for item in items
        if not (item["category"] == "source_lines" and item["ordinal"] == 2)
    ]
    context["context_hash"] = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    context["context_id"] = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v5",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": payload["surface_id"],
                "part_index": payload["part_index"],
                "context_hash": context["context_hash"],
            }
        )
    ).hexdigest()
    response = _response(context)
    response["status"] = "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    with pytest.raises(ValueError, match="V5_REVIEW_LOCATION_INVALID"):
        validate_v5_response(context, response)

    unresolved = _review_graph()
    unresolved["gaps"] = [
        {"path": "server.py", "reason": "DYNAMIC_DISPATCH_UNRESOLVED"}
    ]
    unresolved_context = _context(unresolved)
    with pytest.raises(ValueError, match="V5_SOURCE_INCOMPLETE"):
        validate_v5_response(unresolved_context, _response(unresolved_context))
