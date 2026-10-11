"""Source-bound facts for opt-in standard-library HTTP call paths."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sastsimi.simple_runtime.attack_surfaces import AttackSurface
from sastsimi.simple_runtime.http_route_facts_v5 import verified_http_paths


def _surface(path: str, line: int, symbol: str = "Worker.run") -> AttackSurface:
    return AttackSurface(
        surface_id="surface-http-fixture",
        type="REQUEST_ENTRY",
        path=path,
        symbol=symbol,
        line=line,
        linked_candidate_ids=(),
        evidence_refs=(),
        detector="fixture",
    )


def _fixture(tmp_path: Path, lines: list[str]) -> tuple[Path, dict[str, str]]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    raw = ("\n".join(lines) + "\n").encode("utf-8")
    (workspace / "server.py").write_bytes(raw)
    return workspace, {"server.py": hashlib.sha256(raw).hexdigest()}


def _roles(result: object) -> list[tuple[str, str, int]]:
    paths = result.paths  # type: ignore[attr-defined]
    assert len(paths) == 1
    steps = paths[0]["steps"]
    assert isinstance(steps, list)
    return [(step["role"], step["symbol"], step["line"]) for step in steps]


def test_imported_handler_binds_three_request_reads_and_local_constructor(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        metadata = self.headers",
        "        body = self.rfile.read()",
        "        worker = Worker(route)",
        "        worker.run(metadata, body)",
        "class Worker:",
        "    def __init__(self, route):",
        "        self.route = route",
        "    def run(self, metadata, body):",
        "        dangerous(self.route, metadata, body)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 13))

    assert result.status == "AVAILABLE"
    assert result.gaps == ()
    assert result.paths[0]["provenance"] == "python_syntax"
    assert result.paths[0]["assurance"] == "SYNTACTIC_REACHABILITY"
    roles = _roles(result)
    assert roles[0] == ("ROUTE_ENTRY", "Endpoint.do_GET", 3)
    assert [(role, line) for role, _, line in roles if role == "REQUEST_CONTEXT"] == [
        ("REQUEST_CONTEXT", 4),
        ("REQUEST_CONTEXT", 5),
        ("REQUEST_CONTEXT", 6),
    ]
    assert ("CALL", "Worker", 7) in roles
    assert ("CALL", "Worker.run", 8) in roles
    assert roles[-1] == ("SINK", "Worker.run", 13)
    assert all(
        step["path"] == "server.py" and step["source_sha256"] == hashes["server.py"]
        for step in result.paths[0]["steps"]
    )


def test_import_alias_and_nonstandard_uppercase_http_verb(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler as ImportedHandler",
        "class Endpoint(ImportedHandler):",
        "    def do_BDR(self):",
        "        route = self.path",
        "        self.run(route)",
        "    def run(self, route):",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 7, "Endpoint.run")
    )

    assert result.status == "AVAILABLE"
    assert result.gaps == ()
    assert _roles(result)[0] == ("ROUTE_ENTRY", "Endpoint.do_BDR", 3)
    assert ("REQUEST_CONTEXT", "Endpoint.do_BDR", 4) in _roles(result)
    assert ("CALL", "Endpoint.run", 5) in _roles(result)


@pytest.mark.parametrize(
    "lines",
    [
        [
            "class BaseHTTPRequestHandler:",
            "    pass",
            "class Endpoint(BaseHTTPRequestHandler):",
            "    def do_GET(self):",
            "        value = self.path",
            "        dangerous(value)",
        ],
        [
            "from http.server import BaseHTTPRequestHandler",
            "BaseHTTPRequestHandler = object",
            "class Endpoint(BaseHTTPRequestHandler):",
            "    def do_GET(self):",
            "        value = self.path",
            "        dangerous(value)",
        ],
    ],
)
def test_namesake_or_shadowed_handler_has_no_network_entry(
    tmp_path: Path, lines: list[str]
) -> None:
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", len(lines), "Endpoint.do_GET")
    )

    assert result.paths == ()
    assert "HTTP_HANDLER_IMPORT_UNPROVEN" in result.gaps


def test_static_method_cannot_supply_request_self(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    @staticmethod",
        "    def do_GET(self):",
        "        value = self.path",
        "        dangerous(value)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 6, "Endpoint.do_GET")
    )

    assert result.paths == ()
    assert "HTTP_REQUEST_SELF_UNPROVEN" in result.gaps


def test_reassigned_self_cannot_supply_request_context(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        self = Worker()",
        "        value = self.path",
        "        dangerous(value)",
        "class Worker:",
        "    path = 'fake'",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 6, "Endpoint.do_GET")
    )

    assert result.paths == ()
    assert "HTTP_REQUEST_SELF_REBOUND" in result.gaps


def test_branch_local_constructor_and_call_resolve_only_matching_class(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        if self.path:",
        "            worker = Alpha()",
        "            worker.run()",
        "        else:",
        "            worker = Beta()",
        "            worker.run()",
        "class Alpha:",
        "    def run(self):",
        "        dangerous()",
        "class Beta:",
        "    def run(self):",
        "        harmless()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 12))

    assert result.paths
    assert ("CALL", "Alpha", 5) in _roles(result)
    assert ("CALL", "Alpha.run", 6) in _roles(result)
    assert ("CALL", "Beta.run", 9) not in _roles(result)
    assert ("REQUEST_CONTEXT", "Endpoint.do_GET", 4) in _roles(result)


def test_branch_assignments_are_not_merged_into_a_direct_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        if route:",
        "            worker = Alpha()",
        "        else:",
        "            worker = Beta()",
        "        worker.run()",
        "class Alpha:",
        "    def run(self):",
        "        dangerous()",
        "class Beta:",
        "    def run(self):",
        "        harmless()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 12))

    assert result.paths == ()
    assert "HTTP_BRANCH_ASSIGNMENT_UNRESOLVED" in result.gaps


def test_reassigned_local_does_not_resolve_a_method_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        worker = Worker()",
        "        worker = Worker()",
        "        worker.run()",
        "class Worker:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 10))

    assert result.paths == ()
    assert "HTTP_LOCAL_REASSIGNED" in result.gaps


def test_cycle_is_finite_and_reported_even_with_a_sink(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        self.loop(route)",
        "    def loop(self, route):",
        "        self.loop(route)",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 8, "Endpoint.loop")
    )

    assert len(result.paths) == 1
    assert "HTTP_CALL_CYCLE" in result.gaps
    assert ("CALL", "Endpoint.loop", 5) in _roles(result)
    assert _roles(result)[-1] == ("SINK", "Endpoint.loop", 8)


def test_changed_tracked_source_fails_closed_before_parsing(tmp_path: Path) -> None:
    workspace, hashes = _fixture(tmp_path, ["class Placeholder: pass"])
    (workspace / "server.py").write_text(
        "from http.server import BaseHTTPRequestHandler\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="HTTP_SOURCE_HASH_MISMATCH"):
        verified_http_paths(workspace, hashes, _surface("server.py", 1))


def test_shadowed_local_class_cannot_supply_constructor_identity(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        worker = Worker()",
        "        worker.run()",
        "class Worker:",
        "    def run(self):",
        "        dangerous()",
        "class Other:",
        "    def run(self):",
        "        harmless()",
        "Worker = Other",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 9))

    assert result.paths == ()
    assert "HTTP_CLASS_BINDING_AMBIGUOUS" in result.gaps


def test_function_local_names_do_not_shadow_module_import(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "def unrelated():",
        "    BaseHTTPRequestHandler = object",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 7, "Endpoint.do_GET")
    )

    assert result.status == "AVAILABLE"
    assert _roles(result)[0] == ("ROUTE_ENTRY", "Endpoint.do_GET", 5)


def test_unrelated_dynamic_call_does_not_taint_a_verified_path(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        dangerous(route)",
        "class Other:",
        "    def unrelated(self, value):",
        "        getattr(value, 'run')()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 5, "Endpoint.do_GET")
    )

    assert result.status == "AVAILABLE"
    assert result.gaps == ()


def test_method_rebound_in_class_body_cannot_supply_call_target(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        worker = Worker()",
        "        worker.run()",
        "class Worker:",
        "    def run(self):",
        "        dangerous()",
        "    run = lambda self: harmless()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 9))

    assert result.paths == ()
    assert "HTTP_METHOD_BINDING_AMBIGUOUS" in result.gaps


def test_local_constructor_name_shadow_cannot_resolve_to_module_class(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        Worker = Other",
        "        worker = Worker()",
        "        worker.run()",
        "class Worker:",
        "    def run(self):",
        "        dangerous()",
        "class Other:",
        "    def run(self):",
        "        harmless()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 10))

    assert result.paths == ()
    assert "HTTP_LOCAL_CLASS_SHADOWED" in result.gaps


def test_uninvoked_lambda_does_not_add_a_call_edge(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        deferred = lambda: self.run(route)",
        "    def run(self, route):",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 7, "Endpoint.run")
    )

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


def test_call_after_unconditional_return_is_not_a_route_edge(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        return",
        "        self.run(route)",
        "    def run(self, route):",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 8, "Endpoint.run")
    )

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


def test_request_read_in_direct_handler_helper_keeps_handler_identity(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        self.inspect()",
        "    def inspect(self):",
        "        route = self.path",
        "        self.run(route)",
        "    def run(self, route):",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(
        workspace, hashes, _surface("server.py", 9, "Endpoint.run")
    )

    assert result.status == "AVAILABLE"
    assert ("REQUEST_CONTEXT", "Endpoint.inspect", 6) in _roles(result)


def test_namesake_request_read_in_local_worker_is_not_a_trust_boundary(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        worker = Worker()",
        "        worker.run()",
        "class Worker:",
        "    def run(self):",
        "        route = self.path",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 9))

    assert result.status == "PARTIAL"
    assert "HTTP_REQUEST_INPUT_UNPROVEN" in result.gaps
    assert not any(
        step["role"] == "REQUEST_CONTEXT"
        for path in result.paths
        for step in path["steps"]
    )


def test_tracked_file_budget_returns_an_explicit_gap_before_scanning(
    tmp_path: Path,
) -> None:
    workspace, hashes = _fixture(tmp_path, ["class Placeholder: pass"])
    hashes.update({f"extra{i}.py": "0" * 64 for i in range(4000)})

    result = verified_http_paths(workspace, hashes, _surface("server.py", 1))

    assert result.paths == ()
    assert "HTTP_SCAN_FILE_LIMIT" in result.gaps
