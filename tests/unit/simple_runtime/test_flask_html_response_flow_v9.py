"""A bound Flask HTML response is evidence, not a vulnerability verdict."""

from __future__ import annotations

import hashlib

import pytest

from sastsimi.simple_runtime.flask_html_response_flow_v9 import (
    FlaskHtmlResponseFlowV9,
    prove_flask_html_response_flow_v9,
)

VULNERABLE = """from flask import Flask, request, make_response
import html
app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")
    page = f"<h1>Hello, {name}!</h1>"
    return make_response(page, 200, {"Content-Type": "text/html"})
"""

ESCAPED = VULNERABLE.replace(
    '    page = f"<h1>Hello, {name}!</h1>"',
    '    escaped = html.escape(name)\n    page = f"<h1>Hello, {escaped}!</h1>"',
)


def _prove(
    source: str, *, route_line: int = 5, request_line: int = 7
) -> FlaskHtmlResponseFlowV9 | None:
    raw = source.encode("utf-8")
    return prove_flask_html_response_flow_v9(
        raw,
        path="app.py",
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        route_line=route_line,
        request_line=request_line,
    )


def test_direct_request_interpolation_is_unescaped_flow_evidence() -> None:
    """Dropping the def-use check must not classify an unrelated response."""

    proof = _prove(VULNERABLE)

    assert proof is not None
    assert proof.classification == "UNESCAPED_INTERPOLATION"
    assert proof.path == "app.py"
    assert proof.request_key == "name"
    assert proof.route_line == 5
    assert proof.request_line == 7
    assert proof.interpolation_line == 8
    assert proof.response_line == 9
    assert proof.escape_line is None


def test_html_escape_path_is_distinct_from_unescaped_path() -> None:
    """A source-observed escape call is not a runtime safety verdict."""

    proof = _prove(ESCAPED)

    assert proof is not None
    assert proof.classification == "HTML_ESCAPE_CALL_OBSERVED"
    assert proof.escape_line == 8
    assert proof.interpolation_line == 9
    assert proof.response_line == 10


def test_source_hash_mismatch_cannot_reuse_a_proof() -> None:
    """A changed checkout must not inherit proof from a prior source blob."""

    raw = VULNERABLE.encode("utf-8")

    assert (
        prove_flask_html_response_flow_v9(
            raw,
            path="app.py",
            expected_sha256="0" * 64,
            route_line=5,
            request_line=7,
        )
        is None
    )


@pytest.mark.parametrize(
    "source",
    [
        VULNERABLE.replace(
            "from flask import Flask, request, make_response",
            "from flask import Flask, request",
        ),
        VULNERABLE.replace("app = Flask(__name__)", "app = unknown_factory(__name__)"),
        VULNERABLE.replace("request.args.get", "other.args.get"),
        VULNERABLE.replace("text/html", "application/json"),
        VULNERABLE.replace(
            '    page = f"<h1>Hello, {name}!</h1>"',
            '    if name:\n        page = f"<h1>Hello, {name}!</h1>"',
        ),
        VULNERABLE.replace(
            '    page = f"<h1>Hello, {name}!</h1>"',
            '    page = f"<h1>Hello, {name}!</h1>{other}"',
        ),
        VULNERABLE.replace("def hello():", "def hello(request):"),
        VULNERABLE.replace(
            '    page = f"<h1>Hello, {name}!</h1>"',
            "    make_response = lambda value, *args: value\n"
            '    page = f"<h1>Hello, {name}!</h1>"',
        ),
    ],
)
def test_ambiguous_binding_context_or_flow_stays_unknown(source: str) -> None:
    """Unsupported paths must never silently become reviewed source→sink flows."""

    assert _prove(source) is None


@pytest.mark.parametrize(
    "escape_expression",
    [
        "other.escape(name)",
        "html.escape(name, quote=False)",
        "html.escape(name, **options)",
        "html.escape(name).replace('&lt;', '<')",
    ],
)
def test_unproven_escape_or_reintroduction_stays_unknown(
    escape_expression: str,
) -> None:
    """An unsafe or unresolved sanitizer must not receive an escape credit."""

    assert _prove(ESCAPED.replace("html.escape(name)", escape_expression)) is None


def test_shadowed_html_module_stays_unknown() -> None:
    """Local rebinding must not receive stdlib html.escape credit."""

    source = ESCAPED.replace(
        "    escaped = html.escape(name)",
        "    html = FakeHtml()\n    escaped = html.escape(name)",
    )

    assert _prove(source) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "app.route = fake_route",
        "Flask.route = fake_route",
        'setattr(app, "route", fake_route)',
    ],
)
def test_mutated_route_registration_stays_unknown(mutation: str) -> None:
    """A call spelled app.route is not a Flask route if it was replaced."""

    source = VULNERABLE.replace(
        "app = Flask(__name__)",
        "app = Flask(__name__)\n" + mutation,
    )

    assert _prove(source, route_line=6, request_line=8) is None


def test_html_escape_dict_mutation_stays_unknown() -> None:
    """Mutating the stdlib module dictionary invalidates the escape edge."""

    source = ESCAPED.replace(
        "import html",
        "import html\nhtml.__dict__['escape'] = lambda value: value",
    )

    assert _prove(source, route_line=6, request_line=8) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "globals()['html'].escape = lambda value: value",
        "globals()['html'].__dict__['escape'] = lambda value: value",
        "vars(html)['escape'] = lambda value: value",
        "html.__dict__.update(escape=lambda value: value)",
        "getattr(html, '__dict__').update(escape=lambda value: value)",
        'exec("html.escape = lambda value: value")',
        "eval(\"setattr(html, 'escape', lambda value: value)\")",
        "__import__('html').escape = lambda value: value",
        "alias = html\nalias.escape = lambda value: value",
        "import sys\nsys.modules['html'].escape = lambda value: value",
    ],
)
def test_indirect_html_escape_mutation_stays_unknown(mutation: str) -> None:
    """Reflection may replace the callable even when the direct import is intact."""

    source = ESCAPED.replace("import html", "import html\n" + mutation)

    extra_lines = mutation.count("\n") + 1
    assert (
        _prove(source, route_line=5 + extra_lines, request_line=7 + extra_lines) is None
    )


def test_untrusted_path_label_is_not_certified() -> None:
    """A pinned hash alone must not bless a path outside the checkout."""

    raw = VULNERABLE.encode("utf-8")

    assert (
        prove_flask_html_response_flow_v9(
            raw,
            path="../app.py",
            expected_sha256=hashlib.sha256(raw).hexdigest(),
            route_line=5,
            request_line=7,
        )
        is None
    )


def test_flask_import_after_app_construction_stays_unknown() -> None:
    """A syntactic import is not a valid binding before it executes."""

    source = VULNERABLE.replace(
        "from flask import Flask, request, make_response\nimport html\n",
        "import html\napp = Flask(__name__)\n",
    ).replace(
        "app = Flask(__name__)\n\n@app.route",
        "from flask import Flask, request, make_response\n\n@app.route",
    )

    assert _prove(source) is None
