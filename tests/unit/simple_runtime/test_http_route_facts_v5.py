"""Source-bound facts for opt-in standard-library HTTP call paths."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

import pytest

from sastsimi.simple_runtime.attack_surfaces import AttackSurface
from sastsimi.simple_runtime.call_path_facts import CandidateCallPaths
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


def _path_steps(path: dict[str, object]) -> list[dict[str, object]]:
    steps = path["steps"]
    assert isinstance(steps, list)
    assert all(isinstance(step, dict) for step in steps)
    return cast(list[dict[str, object]], steps)


def _roles(result: CandidateCallPaths) -> list[tuple[str, str, int]]:
    assert len(result.paths) == 1
    roles: list[tuple[str, str, int]] = []
    for step in _path_steps(result.paths[0]):
        role, symbol, line = step["role"], step["symbol"], step["line"]
        assert isinstance(role, str)
        assert isinstance(symbol, str)
        assert isinstance(line, int)
        roles.append((role, symbol, line))
    return roles


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
        for step in _path_steps(result.paths[0])
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


def test_inline_local_constructor_keeps_parsed_request_call_path(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "from urllib.parse import parse_qs",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        self.params = parse_qs(self.path)",
        "        Adapter(self).run()",
        "class Adapter:",
        "    def __init__(self, request):",
        "        self.request = request",
        "    def run(self):",
        "        dangerous(self.request.params)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 11))

    assert result.status == "AVAILABLE"
    assert result.gaps == ()
    assert ("REQUEST_CONTEXT", "Gateway.do_GET", 5) in _roles(result)
    assert ("CALL", "Adapter", 6) in _roles(result)
    assert ("CALL", "Adapter.run", 6) in _roles(result)
    assert _roles(result)[-1] == ("SINK", "Adapter.run", 11)


def test_inline_unknown_factory_method_keeps_dispatch_unresolved(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        factory(self).run()",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 8))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


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


def test_two_branch_constructors_keep_separate_guarded_call_paths(
    tmp_path: Path,
) -> None:
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

    assert result.status == "AVAILABLE"
    assert len(result.paths) == 1
    assert ("CALL", "Alpha", 6) in _roles(result)
    constructor = next(
        step for step in _path_steps(result.paths[0]) if step["symbol"] == "Alpha"
    )
    assert constructor["branch_guard"] == [{"line": 5, "arm": "body"}]
    assert constructor["source_sha256"] == hashes["server.py"]


def test_branch_read_does_not_leak_to_other_constructor_path(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        if unknown():",
        "            worker = Alpha()",
        "        else:",
        "            route = self.path",
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

    assert result.status == "PARTIAL"
    assert len(result.paths) == 1
    assert result.paths[0]["status"] == "PARTIAL"
    assert "HTTP_REQUEST_INPUT_UNPROVEN" in result.gaps
    assert not any(
        step["role"] == "REQUEST_CONTEXT" for step in _path_steps(result.paths[0])
    )


def test_single_branch_constructor_reaches_post_branch_method_call(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "from urllib.parse import parse_qs",
        "class Gateway(BaseHTTPRequestHandler):",
        "    routes = {'/chosen': {}}",
        "    def do_GET(self):",
        "        self.params = parse_qs(self.path)",
        "        if self.path in self.routes:",
        "            handler = Adapter(self)",
        "        handler.run()",
        "class Adapter:",
        "    def __init__(self, request):",
        "        self.request = request",
        "    def run(self):",
        "        dangerous(self.request.params)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 14))

    assert result.status == "AVAILABLE"
    assert result.gaps == ()
    assert ("REQUEST_CONTEXT", "Gateway.do_GET", 6) in _roles(result)
    assert ("CALL", "Adapter", 8) in _roles(result)
    assert ("CALL", "Adapter.run", 9) in _roles(result)


def test_deleted_branch_constructor_cannot_reach_post_branch_call(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        if unknown():",
        "            worker = Alpha()",
        "            del worker",
        "        else:",
        "            pass",
        "        worker.run()",
        "class Alpha:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 13))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


@pytest.mark.parametrize("loop_exit", ["break", "continue"])
def test_branch_constructor_with_loop_exit_cannot_reach_following_call(
    tmp_path: Path, loop_exit: str
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        for _ in (1,):",
        "            if unknown():",
        "                worker = Alpha()",
        f"                {loop_exit}",
        "            else:",
        "                worker = Beta()",
        "            worker.run()",
        "class Alpha:",
        "    def run(self):",
        "        dangerous()",
        "class Beta:",
        "    def run(self):",
        "        harmless()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 14))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


@pytest.mark.parametrize("loop_exit", ["break", "continue"])
def test_loop_exit_still_reaches_call_after_finite_loop(
    tmp_path: Path, loop_exit: str
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        for _ in (1,):",
        f"            {loop_exit}",
        "        Adapter().run()",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 10))

    assert result.status == "AVAILABLE"
    assert ("CALL", "Adapter.run", 7) in _roles(result)


@pytest.mark.parametrize("loop_header", ["while False:", "for _ in ():"])
def test_literal_empty_loop_cannot_supply_route_call(
    tmp_path: Path, loop_header: str
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        f"        {loop_header}",
        "            Adapter().run()",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 9))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


@pytest.mark.parametrize("loop_header", ["while False:", "for _ in ():"])
def test_literal_empty_loop_else_still_reaches_route_call(
    tmp_path: Path, loop_header: str
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        f"        {loop_header}",
        "            pass",
        "        else:",
        "            Adapter().run()",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 11))

    assert result.status == "AVAILABLE"
    assert ("CALL", "Adapter.run", 8) in _roles(result)


def test_loop_else_return_after_continue_blocks_following_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        for _ in (1,):",
        "            continue",
        "        else:",
        "            return",
        "        Adapter().run()",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 12))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


def test_finally_return_overrides_loop_break_before_following_call(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        while True:",
        "            try:",
        "                break",
        "            finally:",
        "                return",
        "        Adapter().run()",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 13))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


def test_literal_false_branch_cannot_supply_sink_or_request_read(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        if False:",
        "            dangerous(self.path)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 5))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


def test_literal_false_branch_same_line_sink_is_unreachable(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        if False: dangerous(self.path)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 4))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


def test_literal_true_branch_cannot_add_else_call_edge(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        if True:",
        "            pass",
        "        else:",
        "            self.run()",
        "    def run(self):",
        "        dangerous(self.path)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 9))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


def test_literal_true_branch_preserves_executed_call_edge(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        if True:",
        "            self.run()",
        "        else:",
        "            pass",
        "    def run(self):",
        "        dangerous(self.path)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 9))

    assert result.status == "AVAILABLE"
    assert ("CALL", "Endpoint.run", 5) in _roles(result)


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


def test_later_local_shadow_blocks_inline_constructor_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        Adapter().run()",
        "        Adapter = None",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 9))

    assert result.paths == ()
    assert "HTTP_LOCAL_CLASS_SHADOWED" in result.gaps


def test_later_local_shadow_blocks_assigned_constructor_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        worker = Adapter()",
        "        worker.run()",
        "        Adapter = None",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 10))

    assert result.paths == ()
    assert "HTTP_LOCAL_CLASS_SHADOWED" in result.gaps


def test_later_match_capture_blocks_inline_constructor_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Gateway(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        Adapter().run()",
        "        match 1:",
        "            case Adapter:",
        "                pass",
        "class Adapter:",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 11))

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


def test_unconsumed_generator_body_is_not_a_sink(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        unused = (dangerous(route) for _ in [])",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 5))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


def test_unconsumed_generator_body_does_not_add_a_call_edge(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        unused = (self.run(self.path) for _ in [])",
        "    def run(self, route):",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


def test_later_read_in_same_expression_cannot_precede_a_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        pair = (self.run(), self.path)",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.status == "PARTIAL"
    assert "HTTP_REQUEST_INPUT_UNPROVEN" in result.gaps
    assert not any(path["status"] == "AVAILABLE" for path in result.paths)


@pytest.mark.parametrize(
    "expression",
    ["(self.path, self.run())", "self.run(self.path)"],
)
def test_read_evaluated_before_call_remains_request_context(
    tmp_path: Path, expression: str
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        f"        pair = {expression}",
        "    def run(self, *args):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.status == "AVAILABLE"
    assert ("REQUEST_CONTEXT", "Endpoint.do_GET", 4) in _roles(result)


def test_dict_later_key_read_cannot_precede_earlier_value_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        unused = {1: self.run(), self.path: 2}",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.status == "PARTIAL"
    assert "HTTP_REQUEST_INPUT_UNPROVEN" in result.gaps
    assert not any(path["status"] == "AVAILABLE" for path in result.paths)


def test_dict_earlier_key_read_precedes_later_value_call(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        unused = {self.path: 1, 2: self.run()}",
        "    def run(self):",
        "        dangerous()",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.status == "AVAILABLE"
    assert ("REQUEST_CONTEXT", "Endpoint.do_GET", 4) in _roles(result)


@pytest.mark.parametrize(
    "expression",
    [
        "[self.run(self.path) for _ in [1]]",
        "{self.run(self.path) for _ in [1]}",
        "{1: self.run(self.path) for _ in [1]}",
    ],
)
def test_comprehension_inner_call_is_unresolved(
    tmp_path: Path, expression: str
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        f"        unused = {expression}",
        "    def run(self, route):",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.paths == ()
    assert "HTTP_COMPREHENSION_EVALUATION_UNRESOLVED" in result.gaps


@pytest.mark.parametrize(
    "expression",
    [
        "False and self.run(self.path)",
        "True or self.run(self.path)",
        "self.run(self.path) if False else None",
        "None if True else self.run(self.path)",
    ],
)
def test_literal_short_circuit_or_ternary_does_not_add_dead_call(
    tmp_path: Path, expression: str
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        f"        unused = {expression}",
        "    def run(self, route):",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.paths == ()
    assert "HTTP_ROUTE_TO_SURFACE_UNAVAILABLE" in result.gaps


def test_literal_short_circuit_same_line_sink_is_unreachable(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        unused = False and dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 5))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


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


def test_sink_after_return_in_called_method_is_not_available(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        self.run(route)",
        "    def run(self, route):",
        "        return",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 8))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


def test_sink_after_return_on_same_line_is_not_available(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        return; dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 5))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


def test_sink_inside_uncalled_nested_function_is_not_available(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        self.run(route)",
        "    def run(self, route):",
        "        def deferred():",
        "            dangerous(route)",
        "        return None",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 8))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


def test_sink_inside_uncalled_lambda_is_not_available(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        self.run(route)",
        "    def run(self, route):",
        "        deferred = lambda: dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 7))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


def test_sink_in_reachable_conditional_branch_stays_available(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        route = self.path",
        "        self.run(route)",
        "    def run(self, route):",
        "        if route:",
        "            dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 8))

    assert result.status == "AVAILABLE"
    assert _roles(result)[-1] == ("SINK", "Endpoint.run", 8)


@pytest.mark.parametrize(
    "terminal_block",
    [
        ["        while True:", "            return"],
        ["        for _ in (1,):", "            return"],
        ["        try:", "            return", "        finally:", "            pass"],
        ["        match 1:", "            case _:", "                return"],
        ["        with self.rfile:", "            return"],
    ],
)
def test_sink_after_proven_terminal_structured_block_is_unreachable(
    tmp_path: Path, terminal_block: list[str]
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        *terminal_block,
        "        dangerous(self.path)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", len(lines)))

    assert result.paths == ()
    assert "HTTP_SURFACE_LINE_UNREACHABLE" in result.gaps


@pytest.mark.parametrize(
    "maybe_continuing_block",
    [
        ["        while should_stop():", "            return"],
        ["        for _ in ():", "            return"],
        ["        match 1:", "            case 2:", "                return"],
        [
            "        try:",
            "            return maybe_fails()",
            "        except Exception:",
            "            pass",
        ],
    ],
)
def test_sink_after_possibly_continuing_structured_block_stays_available(
    tmp_path: Path, maybe_continuing_block: list[str]
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        *maybe_continuing_block,
        "        dangerous(self.path)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", len(lines)))

    assert result.status == "AVAILABLE"
    assert _roles(result)[-1] == ("SINK", "Endpoint.do_GET", len(lines))


@pytest.mark.parametrize("attribute", ["path", "headers", "rfile"])
@pytest.mark.parametrize(
    "mutation", ["self.{attribute} = object()", "del self.{attribute}"]
)
def test_request_attribute_mutation_before_read_is_not_trusted(
    tmp_path: Path, attribute: str, mutation: str
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        f"        {mutation.format(attribute=attribute)}",
        f"        route = self.{attribute}",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.status == "PARTIAL"
    assert "HTTP_REQUEST_ATTRIBUTE_REBOUND" in result.gaps
    assert not any(path["status"] == "AVAILABLE" for path in result.paths)


def test_called_helper_effect_before_request_read_is_a_gap(tmp_path: Path) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        self.rewrite()",
        "        route = self.path",
        "        dangerous(route)",
        "    def rewrite(self):",
        "        self.path = '/fixed'",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 6))

    assert result.status == "PARTIAL"
    assert "HTTP_REQUEST_ATTRIBUTE_EFFECT_UNPROVEN" in result.gaps
    assert not any(path["status"] == "AVAILABLE" for path in result.paths)


def test_request_attribute_rebound_before_helper_read_is_not_trusted(
    tmp_path: Path,
) -> None:
    lines = [
        "from http.server import BaseHTTPRequestHandler",
        "class Endpoint(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        self.path = '/fixed'",
        "        self.inspect()",
        "    def inspect(self):",
        "        route = self.path",
        "        dangerous(route)",
    ]
    workspace, hashes = _fixture(tmp_path, lines)

    result = verified_http_paths(workspace, hashes, _surface("server.py", 8))

    assert result.status == "PARTIAL"
    assert "HTTP_REQUEST_ATTRIBUTE_REBOUND" in result.gaps
    assert not any(path["status"] == "AVAILABLE" for path in result.paths)


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
    roles = _roles(result)
    assert (
        roles.index(("CALL", "Endpoint.inspect", 4))
        < roles.index(("REQUEST_CONTEXT", "Endpoint.inspect", 6))
        < roles.index(("CALL", "Endpoint.run", 7))
    )


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
        for step in _path_steps(path)
    )


def test_tracked_file_budget_returns_an_explicit_gap_before_scanning(
    tmp_path: Path,
) -> None:
    workspace, hashes = _fixture(tmp_path, ["class Placeholder: pass"])
    hashes.update({f"extra{i}.py": "0" * 64 for i in range(4000)})

    result = verified_http_paths(workspace, hashes, _surface("server.py", 1))

    assert result.paths == ()
    assert "HTTP_SCAN_FILE_LIMIT" in result.gaps
