"""A route may discharge only source-proven unrelated graph gaps."""

from __future__ import annotations

import ast
import hashlib
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.surface_applicability_v9 import assess_optional_analyzers
from sastsimi.simple_runtime.surface_path_proof_v9 import certify_surface_paths
from sastsimi.simple_runtime.surface_route_boundary_v10 import (
    _called_local_functions,
    _direct_functions,
    prove_route_boundaries_v10,
)
from tests.unit.simple_runtime.test_surface_path_proof_v9 import (
    _request_fixture,
)

STARTUP_SQL_AND_HTML = """from flask import Flask, request, make_response
app = Flask(__name__)
def init_db():
    cursor.execute('CREATE TABLE example(id INTEGER)')
init_db()
@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    page = f'<p>{name}</p>'
    return make_response(page, 200, {'Content-Type': 'text/html'})
"""

LITERAL_TEMPLATE = """from flask import Flask, render_template
app = Flask(__name__)
def init_db():
    cursor.execute('CREATE TABLE example(id INTEGER)')
init_db()
@app.route('/')
def index():
    return render_template('index.html')
"""

PINNED_SQL_ROUTE = """from flask import Flask, request
app = Flask(__name__)
@app.route('/sql')
def sql_route():
    username = request.args.get('username', '')
    cursor.execute(username)
    return 'done'
"""


def test_startup_sql_gap_is_not_attributed_to_request_route(tmp_path: Path) -> None:
    index, route, _startup_sql, graph = _request_fixture(
        tmp_path, STARTUP_SQL_AND_HTML, anchor_line=6
    )
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
    }
    graph["gaps"] = [{"path": event["path"], "reason": event["reason"]}]
    graph["gap_events"] = [event]
    applicability = assess_optional_analyzers(index, tmp_path)
    v9_path = certify_surface_paths(index, route, graph, applicability, tmp_path)
    assert not v9_path.source_complete

    proof = prove_route_boundaries_v10(
        index,
        tmp_path,
        {route.surface_id: graph},
        {route.surface_id: v9_path},
    )[route.surface_id]

    assert proof.boundary_kind == "PYTHON_RESPONSE"
    assert proof.unresolved_reasons == ()
    assert len(proof.discharged_gap_events) == 1
    assert proof.discharged_gap_events[0]["reason"] == event["reason"]
    assert proof.remaining_gap_events == ()
    assert proof.resolved_edges
    assert proof.expected_v9_path_ids == v9_path.path_ids
    assert proof.unresolved_v9_path_ids == v9_path.unresolved_path_ids
    assert proof.resolved_v9_path_ids == v9_path.path_ids
    assert proof.expected_v9_part_count == len(v9_path.context_parts)


def test_literal_template_is_only_a_python_boundary_proof(tmp_path: Path) -> None:
    index, route, graph, v9_path = _template_inputs(
        tmp_path, LITERAL_TEMPLATE, anchor_line=6
    )
    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: v9_path}
    )[route.surface_id]

    assert proof.boundary_kind == "LITERAL_TEMPLATE"
    assert proof.external_scope_limit == "TEMPLATE_CONTENT_NOT_ANALYZED"
    assert proof.unresolved_reasons == ()
    assert proof.resolved_edges


def _template_inputs(tmp_path: Path, source: str, *, anchor_line: int):
    index, route, _startup_sql, graph = _request_fixture(
        tmp_path, source, anchor_line=anchor_line
    )
    template = tmp_path / "templates" / "index.html"
    template.parent.mkdir()
    template.write_text("<h1>Home</h1>", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "--", "templates/index.html"], check=True
    )
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
            "template",
        ],
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"])
        .decode()
        .strip()
    )
    index = replace(index, commit_id=commit)
    graph["index_hash"] = hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()
    applicability = assess_optional_analyzers(index, tmp_path)
    v9_path = certify_surface_paths(index, route, graph, applicability, tmp_path)
    return index, route, graph, v9_path


def test_rebound_template_renderer_cannot_certify_boundary(tmp_path: Path) -> None:
    source = LITERAL_TEMPLATE.replace(
        "app = Flask(__name__)",
        "app = Flask(__name__)\nrender_template = lambda name: name",
    )
    index, route, graph, v9_path = _template_inputs(tmp_path, source, anchor_line=7)

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: v9_path}
    )[route.surface_id]

    assert proof.boundary_kind == "NONE"
    assert "RESPONSE_PATH_UNPROVEN" in proof.unresolved_reasons


def test_module_alias_to_sql_function_keeps_route_gap(tmp_path: Path) -> None:
    source = STARTUP_SQL_AND_HTML.replace(
        "init_db()\n@app.route", "init_db()\nother = init_db\n@app.route"
    )
    index, route, _startup_sql, graph = _request_fixture(
        tmp_path, source, anchor_line=7
    )
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
    }
    graph["gaps"] = [{"path": event["path"], "reason": event["reason"]}]
    graph["gap_events"] = [event]
    applicability = assess_optional_analyzers(index, tmp_path)
    v9_path = certify_surface_paths(index, route, graph, applicability, tmp_path)

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: v9_path}
    )[route.surface_id]

    assert proof.discharged_gap_events == ()
    assert "ROUTE_CALL_GRAPH_OPEN" in proof.unresolved_reasons


def test_request_use_inside_decorated_handler_binds_its_route(tmp_path: Path) -> None:
    index, route, sink, graph = _request_fixture(
        tmp_path, STARTUP_SQL_AND_HTML, anchor_line=8
    )
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
            "attribution": "UNLOCATED",
        }
    ]
    graph["gaps"] = [
        {"path": "app.py", "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"}
    ]
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "PYTHON_RESPONSE"
    assert proof.discharged_gap_events
    assert sink.line == 4


def test_sanitization_control_is_not_treated_as_sql_sink(tmp_path: Path) -> None:
    source = STARTUP_SQL_AND_HTML.replace(
        "page = f'<p>{name}</p>'",
        "safe_name = html.escape(name)\n    page = f'<p>{safe_name}</p>'",
    ).replace("from flask import Flask", "import html\nfrom flask import Flask")
    index, route, sink, graph = _request_fixture(tmp_path, source, anchor_line=7)
    control = replace(
        sink, surface_id="control-1", type="SANITIZATION_CONTROL", line=10
    )
    index = replace(index, surfaces=(route, sink, control), candidate_count=3)
    graph["index_hash"] = hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
    }
    graph["gap_events"] = [event]
    graph["gaps"] = [{"path": "app.py", "reason": event["reason"]}]
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "PYTHON_RESPONSE"
    assert len(proof.discharged_gap_events) == 1


def test_ambiguous_flask_app_binding_cannot_certify_template(tmp_path: Path) -> None:
    source = LITERAL_TEMPLATE.replace(
        "app = Flask(__name__)", "app = Flask(__name__)\napp = object()"
    )
    index, route, graph, certificate = _template_inputs(tmp_path, source, anchor_line=7)

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "NONE"
    assert "ROUTE_BINDING_UNPROVEN" in proof.unresolved_reasons


def test_list_alias_to_local_sql_function_keeps_route_gap(tmp_path: Path) -> None:
    source = STARTUP_SQL_AND_HTML.replace(
        "init_db()\n@app.route", "init_db()\ncallbacks = [init_db]\n@app.route"
    ).replace(
        "name = request.args.get('name', '')",
        "callbacks[0]()\n    name = request.args.get('name', '')",
    )
    index, route, _sink, graph = _request_fixture(tmp_path, source, anchor_line=7)
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
            "attribution": "UNLOCATED",
        }
    ]
    graph["gaps"] = [
        {"path": "app.py", "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"}
    ]
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.discharged_gap_events == ()
    assert "ROUTE_CALL_GRAPH_OPEN" in proof.unresolved_reasons


def test_custom_template_folder_cannot_use_default_template_proof(
    tmp_path: Path,
) -> None:
    source = LITERAL_TEMPLATE.replace(
        "Flask(__name__)", "Flask(__name__, template_folder='different')"
    )
    index, route, graph, certificate = _template_inputs(tmp_path, source, anchor_line=6)

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "NONE"
    assert "RESPONSE_PATH_UNPROVEN" in proof.unresolved_reasons


def test_template_context_is_not_a_literal_handoff(tmp_path: Path) -> None:
    source = LITERAL_TEMPLATE.replace(
        "render_template('index.html')",
        "render_template('index.html', user=request.args['user'])",
    ).replace("Flask, render_template", "Flask, render_template, request")
    index, route, graph, certificate = _template_inputs(tmp_path, source, anchor_line=6)

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "NONE"


def test_closed_route_discharge_accounts_for_every_relevant_v9_gap(
    tmp_path: Path,
) -> None:
    index, route, _sink, graph = _request_fixture(
        tmp_path, STARTUP_SQL_AND_HTML, anchor_line=6
    )
    reasons = (
        "EXTERNAL_IMPLEMENTATION_UNAVAILABLE",
        "SINK_ENCLOSING_FUNCTION_UNAVAILABLE",
        "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
    )
    graph["gap_events"] = [
        {"path": "app.py", "reason": reason, "attribution": "UNLOCATED"}
        for reason in reasons
    ]
    graph["gaps"] = [{"path": "app.py", "reason": reason} for reason in reasons]
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )
    assert set(reasons).issubset(certificate.unresolved_gap_codes)

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "PYTHON_RESPONSE"
    assert {event["reason"] for event in proof.discharged_gap_events} == set(reasons)
    assert proof.remaining_gap_events == ()


def test_shadowed_template_renderer_parameter_cannot_certify_handoff(
    tmp_path: Path,
) -> None:
    source = LITERAL_TEMPLATE.replace("def index():", "def index(render_template):")
    index, route, graph, certificate = _template_inputs(tmp_path, source, anchor_line=6)

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "NONE"


def test_duplicate_unlocated_gap_events_remain_unresolved(tmp_path: Path) -> None:
    index, route, _sink, graph = _request_fixture(
        tmp_path, STARTUP_SQL_AND_HTML, anchor_line=6
    )
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
    }
    graph["gap_events"] = [event, event.copy()]
    graph["gaps"] = [{"path": "app.py", "reason": event["reason"]}]
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.discharged_gap_events == ()
    assert (
        sum(
            event["reason"] == "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"
            for event in proof.remaining_gap_events
        )
        == 2
    )


def test_exact_html_response_path_resolves_certificate_only_syntax_gap(
    tmp_path: Path,
) -> None:
    index, route, _sink, graph = _request_fixture(
        tmp_path, STARTUP_SQL_AND_HTML, anchor_line=8
    )
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )
    assert "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE" in certificate.unresolved_gap_codes

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "PYTHON_RESPONSE"
    assert any(
        event["reason"] == "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"
        for event in proof.discharged_gap_events
    )
    assert all(
        event["reason"] != "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"
        for event in proof.remaining_gap_events
    )


def test_template_changed_after_pin_cannot_certify_handoff(tmp_path: Path) -> None:
    index, route, graph, certificate = _template_inputs(
        tmp_path, LITERAL_TEMPLATE, anchor_line=6
    )
    (tmp_path / "templates" / "index.html").write_text(
        "<h1>Modified after commit</h1>", encoding="utf-8"
    )

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "NONE"
    assert "RESPONSE_PATH_UNPROVEN" in proof.unresolved_reasons


def test_python_source_changed_after_pin_fails_closed(tmp_path: Path) -> None:
    index, route, _sink, graph = _request_fixture(
        tmp_path, STARTUP_SQL_AND_HTML, anchor_line=6
    )
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )
    (tmp_path / "app.py").write_text("# changed", encoding="utf-8")

    with pytest.raises(ValueError):
        prove_route_boundaries_v10(
            index,
            tmp_path,
            {route.surface_id: graph},
            {route.surface_id: certificate},
        )


@pytest.mark.parametrize(
    ("inserted", "expected_boundary"),
    [
        ("init_db()", "PINNED_PYTHON_SINK"),
        ("getattr(globals(), 'init_db')()", "NONE"),
        ("if name == 'skip':\n        return 'skip'", "NONE"),
    ],
)
def test_route_extra_operation_cannot_discharge_unlocated_gap(
    tmp_path: Path, inserted: str, expected_boundary: str
) -> None:
    source = STARTUP_SQL_AND_HTML.replace(
        "page = f'<p>{name}</p>'", f"{inserted}\n    page = f'<p>{{name}}</p>'"
    )
    index, route, _sink, graph = _request_fixture(tmp_path, source, anchor_line=6)
    reason = "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"
    graph["gap_events"] = [
        {"path": "app.py", "reason": reason, "attribution": "UNLOCATED"}
    ]
    graph["gaps"] = [{"path": "app.py", "reason": reason}]
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == expected_boundary
    if expected_boundary == "NONE":
        assert proof.discharged_gap_events == ()
    else:
        assert proof.remaining_gap_events == ()
        assert proof.resolved_v9_path_ids == certificate.path_ids


def test_pinned_route_to_indexed_sql_sink_is_a_python_boundary(
    tmp_path: Path,
) -> None:
    index, route, sink, graph = _request_fixture(
        tmp_path, PINNED_SQL_ROUTE, anchor_line=3
    )
    certificate = certify_surface_paths(
        index, route, graph, assess_optional_analyzers(index, tmp_path), tmp_path
    )
    assert any(
        path.kind == "call_path_v1" and path.sink_surface_id == sink.surface_id
        for path in certificate.downstream_paths
    )

    proof = prove_route_boundaries_v10(
        index, tmp_path, {route.surface_id: graph}, {route.surface_id: certificate}
    )[route.surface_id]

    assert proof.boundary_kind == "PINNED_PYTHON_SINK"
    assert proof.resolved_edges
    assert proof.unresolved_reasons == ()
    assert proof.expected_v9_path_ids == certificate.path_ids
    assert proof.unresolved_v9_path_ids == certificate.unresolved_path_ids
    assert proof.resolved_v9_path_ids == certificate.path_ids
    assert proof.expected_v9_part_count == len(certificate.context_parts)


def test_nested_function_shadow_cannot_bind_module_helper() -> None:
    tree = ast.parse(
        "def helper():\n    return 1\n"
        "def route():\n    def helper():\n        return 2\n"
        "    return helper()\n"
    )
    functions = _direct_functions(tree)
    assert functions is not None
    assert _called_local_functions(tree, functions["route"], functions) is None


@pytest.mark.parametrize(
    "shadow",
    [
        "from other import helper\n",
        "class helper:\n    pass\n",
        "async def helper():\n    return 2\n",
    ],
)
def test_module_shadow_cannot_bind_python_route_helper(shadow: str) -> None:
    tree = ast.parse(
        "def helper():\n    return 1\n" + shadow + "def route():\n    return helper()\n"
    )
    functions = _direct_functions(tree)
    assert functions is not None
    assert _called_local_functions(tree, functions["route"], functions) is None


def test_match_capture_cannot_bind_module_helper() -> None:
    tree = ast.parse(
        "def helper():\n    return 1\n"
        "def route(value):\n"
        "    match value:\n"
        "        case helper:\n"
        "            return helper()\n"
    )
    functions = _direct_functions(tree)
    assert functions is not None
    assert _called_local_functions(tree, functions["route"], functions) is None
