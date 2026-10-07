"""Conservative identity for direct Flask cookie deserialization flows."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest

from sastsimi.simple_runtime.finding_flow import (
    FlowAnchor,
    FlowEvidenceInvalid,
    resolve_flow_anchor,
)

COOKIE_SOURCE = """import pickle
from base64 import b64decode
from flask import Flask, request
app = Flask(__name__)
@app.route('/cookie', methods=['GET', 'POST'])
def cookie():
    if 'value' in request.cookies:
        return pickle.loads(b64decode(request.cookies['value']))
    return 'missing'
"""


def _anchor(
    tmp_path: Path,
    source: str = COOKIE_SOURCE,
    *,
    lines: tuple[int, ...] = (8,),
    cwe: str = "CWE-502",
    trace: Mapping[str, object] | None = None,
) -> FlowAnchor | None:
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    return resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": [f"app.py:{line}" for line in lines]},
        cwe,
        trace,
    )


def test_direct_cookie_base64_pickle_flow_has_stable_identity(tmp_path: Path) -> None:
    first = _anchor(tmp_path, lines=(5, 7, 8))
    second = _anchor(tmp_path, lines=(8,))

    assert first is not None
    assert first == second
    assert first.route == "/cookie"
    assert first.source_access == "request.cookies"
    assert first.source_key == "value"
    assert first.source_line == 8
    assert first.sink_callee == "pickle.loads"
    assert first.sink_line == 8
    assert first.sink_argument == 0
    assert first.cwe == "CWE-502"


def test_cookie_pickle_identity_keeps_different_key_and_route_separate(
    tmp_path: Path,
) -> None:
    original = _anchor(tmp_path)
    different_key = _anchor(
        tmp_path,
        COOKIE_SOURCE.replace("request.cookies['value']", "request.cookies['other']"),
    )
    different_route = _anchor(
        tmp_path,
        COOKIE_SOURCE.replace("'/cookie'", "'/alternate'"),
    )

    assert original is not None
    assert different_key is not None
    assert different_route is not None
    assert original != different_key
    assert original != different_route
    assert different_key.source_key == "other"
    assert different_route.route == "/alternate"


def test_cookie_pickle_identity_requires_cited_sink_callsite(tmp_path: Path) -> None:
    assert _anchor(tmp_path, lines=(7,)) is None


def test_cookie_pickle_identity_keeps_distinct_sink_calls_separate(
    tmp_path: Path,
) -> None:
    original = _anchor(tmp_path)
    moved_call = _anchor(
        tmp_path,
        COOKIE_SOURCE.replace(
            "        return pickle.loads",
            "        # Separate callsite.\n        return pickle.loads",
        ),
        lines=(9,),
    )

    assert original is not None
    assert moved_call is not None
    assert original != moved_call
    assert moved_call.sink_line == 9


def test_cookie_pickle_identity_abstains_on_dynamic_key_or_wrapper(
    tmp_path: Path,
) -> None:
    dynamic_key = COOKIE_SOURCE.replace(
        "    if 'value' in request.cookies:\n",
        "    key = 'value'\n    if key in request.cookies:\n",
    ).replace("request.cookies['value']", "request.cookies[key]")
    wrapper = COOKIE_SOURCE.replace(
        "b64decode(request.cookies['value'])",
        "custom_decode(request.cookies['value'])",
    )

    assert _anchor(tmp_path, dynamic_key, lines=(9,)) is None
    assert _anchor(tmp_path, wrapper) is None


def test_cookie_pickle_identity_abstains_on_import_or_attribute_shadow(
    tmp_path: Path,
) -> None:
    replacement = COOKIE_SOURCE.replace(
        "app = Flask(__name__)",
        "pickle.loads = harmless\napp = Flask(__name__)",
    )
    dynamic_replacement = COOKIE_SOURCE.replace(
        "app = Flask(__name__)",
        "setattr(pickle, 'loads', harmless)\napp = Flask(__name__)",
    )

    assert _anchor(tmp_path, replacement, lines=(9,)) is None
    assert _anchor(tmp_path, dynamic_replacement, lines=(9,)) is None


def test_cookie_pickle_identity_abstains_on_second_module_alias(
    tmp_path: Path,
) -> None:
    alias_replacement = COOKIE_SOURCE.replace(
        "import pickle\n",
        "import pickle\nimport pickle as other_pickle\nother_pickle.loads = harmless\n",
    )

    assert _anchor(tmp_path, alias_replacement, lines=(10,)) is None


@pytest.mark.parametrize(
    "dynamic_binding",
    [
        "import importlib\nimportlib.import_module('pickle').loads = harmless",
        "from importlib import import_module as loader\n"
        "loader('pickle').loads = harmless",
        "import sys\nsys.modules['pickle'].loads = harmless",
    ],
)
def test_cookie_pickle_identity_abstains_on_dynamic_module_mutation(
    tmp_path: Path, dynamic_binding: str
) -> None:
    source = COOKIE_SOURCE.replace(
        "app = Flask(__name__)",
        f"{dynamic_binding}\napp = Flask(__name__)",
    )

    assert _anchor(tmp_path, source, lines=(10,)) is None


def test_cookie_pickle_identity_rejects_conflicting_candidate_trace(
    tmp_path: Path,
) -> None:
    trace: dict[str, object] = {
        "sarif_steps": [
            {"path": "app.py", "line": 8},
            {"path": "app.py", "line": 9},
        ]
    }

    assert _anchor(tmp_path, trace=trace) is None


@pytest.mark.parametrize(
    "trace",
    [
        {
            "source": {"path": "app.py", "line": 8},
            "sink": {"path": "app.py", "line": 8},
            "source_key": "other",
        },
        {
            "source": {"path": "app.py", "line": 8},
            "sink": {"path": "app.py", "line": 8},
            "sink_argument": 1,
        },
        {
            "sarif_steps": [
                {"path": "app.py", "line": 8, "column": 1},
                {"path": "app.py", "line": 8, "column": 1},
            ]
        },
        {
            "source": {"path": "app.py", "line": 8, "column": 1},
            "sink": {"path": "app.py", "line": 8},
        },
    ],
)
def test_cookie_pickle_identity_rejects_conflicting_identity_details(
    tmp_path: Path, trace: dict[str, object]
) -> None:
    assert _anchor(tmp_path, trace=trace) is None


@pytest.mark.parametrize(
    ("endpoint", "field", "wrong_value"),
    [("source", "source_key", "other"), ("sink", "sink_argument", 1)],
)
def test_cookie_pickle_identity_rejects_nested_candidate_identity_mismatch(
    tmp_path: Path, endpoint: str, field: str, wrong_value: str | int
) -> None:
    source_line = COOKIE_SOURCE.splitlines()[7]
    source = {
        "path": "app.py",
        "line": 8,
        "column": source_line.index("request.cookies") + 1,
        "source_key": "value",
    }
    sink = {
        "path": "app.py",
        "line": 8,
        "column": source_line.index("pickle.loads") + 1,
        "sink_argument": 0,
    }
    endpoints = {"source": source, "sink": sink}
    endpoints[endpoint][field] = wrong_value

    assert _anchor(tmp_path, trace=endpoints) is None


def test_cookie_pickle_identity_accepts_matching_candidate_columns(
    tmp_path: Path,
) -> None:
    source_line = COOKIE_SOURCE.splitlines()[7]
    trace: dict[str, object] = {
        "source_key": "value",
        "sink_argument": 0,
        "sarif_steps": [
            {
                "path": "app.py",
                "line": 8,
                "column": source_line.index("request.cookies") + 1,
            },
            {
                "path": "app.py",
                "line": 8,
                "column": source_line.index("pickle.loads") + 1,
            },
        ],
    }

    assert _anchor(tmp_path, trace=trace) is not None


def test_cookie_pickle_identity_is_not_an_xss_identity(tmp_path: Path) -> None:
    assert _anchor(tmp_path, cwe="CWE-79") is None


def test_cookie_pickle_identity_rejects_changed_source_hash(tmp_path: Path) -> None:
    raw = COOKIE_SOURCE.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    with pytest.raises(FlowEvidenceInvalid, match="FLOW_SOURCE_HASH_MISMATCH"):
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            "0" * 64,
            {"code_locations": ["app.py:8"]},
            "CWE-502",
        )
