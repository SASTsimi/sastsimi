from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sastsimi.simple_runtime.finding_flow import (
    FlowEvidenceInvalid,
    resolve_flow_anchor,
)
from sastsimi.simple_runtime.finding_group_projection import _normalized_trace

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "finding_groups"


def _fixture(tmp_path: Path, name: str) -> tuple[Path, str]:
    raw = (FIXTURES / name).read_bytes()
    (tmp_path / "app.py").write_bytes(raw)
    return tmp_path, hashlib.sha256(raw).hexdigest()


def test_same_ping_flow_from_different_proposal_wording_and_neighbor_context(
    tmp_path: Path,
) -> None:
    workspace, sha = _fixture(tmp_path, "antony_routes.py")
    static = {
        "title": "OS command injection",
        "code_locations": ["app.py:10", "app.py:11"],
    }
    surface = {"title": "Shell injection near /upload", "code_locations": ["app.py:11"]}
    first = resolve_flow_anchor(workspace, "app.py", sha, static, "CWE-78")
    second = resolve_flow_anchor(workspace, "app.py", sha, surface, "CWE-78")
    assert first == second
    assert first is not None
    assert first.route == "/ping"
    assert first.source_key == "target"
    assert first.sink_callee == "os.system"
    assert first.sink_argument == 0


def test_json_command_assignment_chain_resolves_from_sink_only(tmp_path: Path) -> None:
    workspace, sha = _fixture(tmp_path, "gnu_routes.py")
    sink_only = {"code_locations": ["app.py:15"]}
    full = {"code_locations": ["app.py:10", "app.py:11", "app.py:15"]}
    first = resolve_flow_anchor(workspace, "app.py", sha, sink_only, "CWE-78")
    second = resolve_flow_anchor(workspace, "app.py", sha, full, "CWE-78")
    assert first == second
    assert first is not None
    assert first.source_access == "request.json"
    assert first.source_key == "cmd"
    assert first.sink_callee == "subprocess.run"


def test_distinct_keys_sink_arguments_callsites_and_branches_do_not_merge(
    tmp_path: Path,
) -> None:
    source = """from flask import request
import os
@app.route('/run')
def run():
    left = request.args.get('left')
    right = request.args.get('right')
    if request.args.get('mode'):
        os.system(left)
    else:
        os.system(right)
    os.system(left)
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    anchors = [
        resolve_flow_anchor(
            tmp_path, "app.py", sha, {"code_locations": [f"app.py:{line}"]}, "CWE-78"
        )
        for line in (8, 10, 11)
    ]
    # Sink-only citations in a multi-input handler cannot identify which
    # input an independently verified PoC exercised.
    assert anchors == [None, None, None]


def test_ambiguous_reaching_definition_and_unrecognized_source_abstain(
    tmp_path: Path,
) -> None:
    source = """from flask import request
import os
@app.route('/run')
def run():
    if request.args.get('which'):
        cmd = request.args.get('left')
    else:
        cmd = request.args.get('right')
    os.system(cmd)
    os.system(fetch_remote())
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    for line in (9, 10):
        assert (
            resolve_flow_anchor(
                tmp_path,
                "app.py",
                sha,
                {"code_locations": [f"app.py:{line}"]},
                "CWE-78",
            )
            is None
        )


def test_unmodelled_reassignment_cannot_reuse_old_source_definition(
    tmp_path: Path,
) -> None:
    source = """from flask import request
import os
@app.route('/run')
def run():
    cmd = request.args.get('cmd')
    cmd += ' suffix'
    os.system(cmd)
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:7"]},
            "CWE-78",
        )
        is None
    )


def test_conflicting_trace_abstains_and_source_hash_mismatch_fails_closed(
    tmp_path: Path,
) -> None:
    workspace, sha = _fixture(tmp_path, "antony_routes.py")
    proposal = {"code_locations": ["app.py:11"]}
    assert (
        resolve_flow_anchor(
            workspace,
            "app.py",
            sha,
            proposal,
            "CWE-78",
            {
                "source": {"path": "app.py", "line": 12},
                "sink": {"path": "app.py", "line": 11},
            },
        )
        is None
    )
    with pytest.raises(FlowEvidenceInvalid):
        resolve_flow_anchor(workspace, "app.py", "0" * 64, proposal, "CWE-78")


def test_sarif_trace_must_contain_actual_source_and_end_at_sink(tmp_path: Path) -> None:
    workspace, sha = _fixture(tmp_path, "antony_routes.py")
    proposal = {"code_locations": ["app.py:11"]}
    agreeing = {
        "sarif_steps": [
            {"path": "app.py", "line": 10},
            {"path": "app.py", "line": 11},
        ]
    }
    assert resolve_flow_anchor(workspace, "app.py", sha, proposal, "CWE-78", agreeing)
    unrelated_import = {
        "sarif_steps": [
            {"path": "app.py", "line": 1},
            {"path": "app.py", "line": 10},
            {"path": "app.py", "line": 11},
        ]
    }
    assert (
        resolve_flow_anchor(
            workspace, "app.py", sha, proposal, "CWE-78", unrelated_import
        )
        is None
    )
    missing_source = {
        "sarif_steps": [{"path": "app.py", "line": 1}, {"path": "app.py", "line": 11}]
    }
    assert (
        resolve_flow_anchor(
            workspace, "app.py", sha, proposal, "CWE-78", missing_source
        )
        is None
    )
    wrong_sink = {
        "sarif_steps": [{"path": "app.py", "line": 10}, {"path": "app.py", "line": 16}]
    }
    assert (
        resolve_flow_anchor(workspace, "app.py", sha, proposal, "CWE-78", wrong_sink)
        is None
    )


def test_supplied_trace_fields_must_all_agree(tmp_path: Path) -> None:
    workspace, sha = _fixture(tmp_path, "antony_routes.py")
    proposal = {"code_locations": ["app.py:11"]}
    correct = {
        "source": {"path": "app.py", "line": 10},
        "sink": {"path": "app.py", "line": 11},
    }
    steps = [
        {"path": "app.py", "line": 10},
        {"path": "app.py", "line": 11},
    ]
    for trace in (
        {**correct, "sarif_steps": steps, "source": {"path": "app.py", "line": 16}},
        {**correct, "sarif_steps": steps, "sink": {"path": "app.py", "line": 16}},
        {**correct, "sarif_steps": [{"path": "app.py", "line": 10}]},
        {**correct, "sarif_steps": "not a list"},
    ):
        assert (
            resolve_flow_anchor(workspace, "app.py", sha, proposal, "CWE-78", trace)
            is None
        )


def test_repeated_identical_trace_endpoints_do_not_split_group(tmp_path: Path) -> None:
    workspace, sha = _fixture(tmp_path, "antony_routes.py")
    proposal = {"code_locations": ["app.py:11"]}
    source = {"path": "app.py", "line": 10}
    sink = {"path": "app.py", "line": 11}
    direct = resolve_flow_anchor(
        workspace, "app.py", sha, proposal, "CWE-78", {"sarif_steps": [source, sink]}
    )
    repeated = resolve_flow_anchor(
        workspace,
        "app.py",
        sha,
        proposal,
        "CWE-78",
        {"sarif_steps": [source, source, sink]},
    )
    assert direct is not None and repeated == direct


def test_redirected_or_missing_source_fails_closed(tmp_path: Path) -> None:
    workspace, sha = _fixture(tmp_path, "antony_routes.py")
    assert (
        resolve_flow_anchor(
            workspace,
            "missing.py",
            sha,
            {"code_locations": ["missing.py:11"]},
            "CWE-78",
        )
        is None
    )
    with pytest.raises(FlowEvidenceInvalid):
        resolve_flow_anchor(
            workspace, "../app.py", sha, {"code_locations": ["../app.py:11"]}, "CWE-78"
        )


@pytest.mark.parametrize(
    "expression",
    [
        "f\"{request.args.get('a')}{request.args['b']}\"",
        'request.args.get("a") + transform(request.args.get("b"))',
        'request.args.get("a", request.args.get("b"))',
    ],
)
def test_mixed_or_unresolved_sink_inputs_abstain(
    tmp_path: Path, expression: str
) -> None:
    source = (
        "from flask import request\nimport os\n@app.route('/run')\ndef run():\n"
        f"    os.system({expression})\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:5"]},
            "CWE-78",
        )
        is None
    )


def test_sarif_trace_with_another_request_input_abstains(tmp_path: Path) -> None:
    source = """from flask import request
import os
@app.route('/run')
def run():
    a = request.args.get('a')
    b = request.args.get('b')
    os.system(a)
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    proposal = {"code_locations": ["app.py:7"]}
    assert resolve_flow_anchor(tmp_path, "app.py", sha, proposal, "CWE-78") is None
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            sha,
            proposal,
            "CWE-78",
            {
                "sarif_steps": [
                    {"path": "app.py", "line": 6},
                    {"path": "app.py", "line": 5},
                    {"path": "app.py", "line": 7},
                ]
            },
        )
        is None
    )


def test_deep_expression_abstains_without_crashing(tmp_path: Path) -> None:
    source = (
        "from flask import request\nimport os\n@app.route('/run')\ndef run():\n"
        "    value = request.args.get('a')\n"
        "    os.system(" + "value" + " + 'x'" * 1400 + ")\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:6"]},
            "CWE-78",
        )
        is None
    )


def test_unrelated_deep_callee_does_not_crash_projection(tmp_path: Path) -> None:
    source = (
        "import os\nfrom flask import request\n@app.route('/run')\ndef run():\n"
        "    x" + ".y" * 1400 + "()\n"
        "    os.system(request.args.get('a'))\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    result = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:6"]},
        "CWE-78",
    )
    assert result is None or result.source_key == "a"


def test_additional_dynamic_sink_arguments_abstain(tmp_path: Path) -> None:
    source = """import subprocess
from flask import Flask, request
app = Flask(__name__)
@app.route('/run')
def run():
    subprocess.run(request.args.get('cmd'), shell=request.args.get('shell'))
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:6"]},
            "CWE-78",
        )
        is None
    )
    safe = source.replace("shell=request.args.get('shell')", "shell=True")
    raw = safe.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:6"]},
        "CWE-78",
    )


@pytest.mark.parametrize(
    "write",
    [
        "if flag:\n        (cmd := 'other')",
        "cmd, other = 'other', 1",
    ],
)
def test_unmodelled_rebinding_abstains(tmp_path: Path, write: str) -> None:
    source = (
        "import os\nfrom flask import request\n@app.route('/run')\ndef run():\n"
        "    cmd = request.args.get('a')\n"
        f"    {write}\n"
        "    os.system(cmd)\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    sink_line = len(source.splitlines())
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{sink_line}"]},
            "CWE-78",
        )
        is None
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "import subprocess\nsubprocess = choose_runner()\n",
        "",
    ],
)
def test_unproven_or_rebound_sink_module_abstains(tmp_path: Path, prefix: str) -> None:
    source = (
        prefix + "from flask import request\n@app.route('/run')\ndef run():\n"
        "    subprocess.run(request.args.get('cmd'), shell=True)\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{len(source.splitlines())}"]},
            "CWE-78",
        )
        is None
    )


@pytest.mark.parametrize(
    "decorators",
    [
        "@app.route('/admin')\n@app.route('/user')\n",
        "@app.route('/run', methods=['GET', 'POST'])\n",
        "@app.route(path_from_config())\n",
        "",
    ],
)
def test_multiple_dynamic_or_missing_routes_abstain(
    tmp_path: Path, decorators: str
) -> None:
    source = (
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        + decorators
        + "def run():\n    os.system(request.args.get('cmd'))\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{len(source.splitlines())}"]},
            "CWE-78",
        )
        is None
    )


def test_rebound_request_source_abstains(tmp_path: Path) -> None:
    source = """import os
from flask import request
@app.route('/run')
def run():
    request = choose_request()
    os.system(request.args.get('cmd'))
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:6"]},
            "CWE-78",
        )
        is None
    )


def test_json_container_mutation_abstains(tmp_path: Path) -> None:
    source = """import os
from flask import request
@app.route('/run')
def run():
    data = request.get_json() or {}
    data['cmd'] = transformed()
    cmd = data.get('cmd', '')
    os.system(cmd)
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:8"]},
            "CWE-78",
        )
        is None
    )


@pytest.mark.parametrize(
    "rebinding",
    [
        "from other import request\n",
        "request.args = other_args\n",
        "import subprocess\nsubprocess.run = other_runner\n",
    ],
)
def test_module_level_source_or_sink_rebinding_abstains(
    tmp_path: Path, rebinding: str
) -> None:
    source = (
        "import os\nimport subprocess\nfrom flask import request\n"
        + rebinding
        + "@app.route('/run')\ndef run():\n"
        "    subprocess.run(request.args.get('cmd'), shell=True)\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{len(source.splitlines())}"]},
            "CWE-78",
        )
        is None
    )


@pytest.mark.parametrize(
    "binding",
    [
        "for os in runners:\n    pass\n",
        "with context() as os:\n    pass\n",
        "try:\n    pass\nexcept Exception as os:\n    pass\n",
        "for request in requests:\n    pass\n",
        "with context() as request:\n    pass\n",
        "try:\n    pass\nexcept Exception as request:\n    pass\n",
    ],
)
def test_module_scope_control_flow_cannot_rebind_proven_imports(
    tmp_path: Path, binding: str
) -> None:
    source = (
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        + binding
        + "@app.route('/run')\ndef run():\n"
        "    os.system(request.args.get('cmd'))\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{len(source.splitlines())}"]},
            "CWE-78",
        )
        is None
    )


@pytest.mark.parametrize(
    "extra",
    [
        "    req = request\n    if req.args['enable']:\n",
        "    if request.cookies['enable']:\n",
        "    if request.values.get('enable'):\n",
    ],
)
def test_other_request_input_or_alias_prevents_single_input_proof(
    tmp_path: Path, extra: str
) -> None:
    source = (
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/run')\ndef run():\n"
        "    cmd = request.args.get('cmd')\n" + extra + "        os.system(cmd)\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{len(source.splitlines())}"]},
            "CWE-78",
        )
        is None
    )


@pytest.mark.parametrize(
    "setup, decorator",
    [
        ("app = Wrapper()\n", "@app.route('/run')\n"),
        ("wrapper = Wrapper()\n", "@wrapper.route('/run')\n"),
        ("from other import Flask\napp = Flask(__name__)\n", "@app.route('/run')\n"),
    ],
)
def test_unproven_route_receiver_abstains(
    tmp_path: Path, setup: str, decorator: str
) -> None:
    source = (
        "import os\nfrom flask import request\n"
        + setup
        + decorator
        + "def run():\n    os.system(request.args.get('cmd'))\n"
    )
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{len(source.splitlines())}"]},
            "CWE-78",
        )
        is None
    )


def test_programmatic_second_route_prevents_unique_route_proof(tmp_path: Path) -> None:
    source = """import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/x')
def run():
    os.system(request.args.get('cmd'))
app.add_url_rule('/y', view_func=run)
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:6"]},
            "CWE-78",
        )
        is None
    )


def test_nested_registration_prevents_unique_route_proof(tmp_path: Path) -> None:
    source = """import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/x')
def run():
    os.system(request.args.get('cmd'))
def register():
    app.add_url_rule('/y', view_func=run)
register()
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:6"]},
            "CWE-78",
        )
        is None
    )


def test_dynamic_module_lookup_prevents_unique_route_proof(tmp_path: Path) -> None:
    source = """import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/x')
def run():
    os.system(request.args.get('cmd'))
globals()['app'].add_url_rule('/y', view_func=run)
"""
    raw = source.encode()
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:6"]},
            "CWE-78",
        )
        is None
    )


@pytest.mark.parametrize(
    "source,cwe,sink_line,callee,key",
    [
        (
            "import sqlite3\nfrom flask import Flask, request\n"
            "app = Flask(__name__)\n@app.route('/query')\n"
            "def query():\n    user = request.args.get('username')\n"
            "    db = sqlite3.connect(':memory:')\n    cursor = db.cursor()\n"
            "    sql = f\"SELECT * FROM users WHERE name='{user}'\"\n"
            "    cursor.execute(sql)\n",
            "CWE-89",
            10,
            "cursor.execute",
            "username",
        ),
        (
            "import requests\nfrom flask import Flask, request\n"
            "app = Flask(__name__)\n@app.route('/fetch')\n"
            "def fetch():\n    url = request.args.get('url')\n"
            "    return requests.get(url).text\n",
            "CWE-918",
            7,
            "requests.get",
            "url",
        ),
        (
            "from flask import Flask, request\napp = Flask(__name__)\n"
            "@app.route('/evaluate')\ndef evaluate():\n"
            "    payload = request.form.get('payload')\n"
            "    return str(eval(payload))\n",
            "CWE-95",
            6,
            "eval",
            "payload",
        ),
        (
            "from flask import Flask, request, make_response\n"
            "app = Flask(__name__)\n@app.route('/hello')\n"
            "def hello():\n    name = request.args.get('name')\n"
            "    body = f'<h1>{name}</h1>'\n"
            "    return make_response(body)\n",
            "CWE-79",
            7,
            "make_response",
            "name",
        ),
        (
            "from flask import Flask, request\napp = Flask(__name__)\n"
            "@app.route('/file')\ndef file():\n"
            "    path = request.args.get('path')\n"
            "    return open(path).read()\n",
            "CWE-22",
            6,
            "open",
            "path",
        ),
    ],
)
def test_common_python_families_group_only_the_same_cited_flow(
    tmp_path: Path,
    source: str,
    cwe: str,
    sink_line: int,
    callee: str,
    key: str,
) -> None:
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    first = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"title": "first engine", "code_locations": [f"app.py:{sink_line}"]},
        cwe,
    )
    second = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"title": "other agent", "code_locations": [f"app.py:{sink_line}"]},
        cwe,
    )
    assert first is not None
    assert first == second
    assert first.sink_callee == callee
    assert first.source_key == key
    assert first.cwe == cwe


@pytest.mark.parametrize(
    "source,cwe,sink_line",
    [
        (
            "import sqlite3\nfrom flask import Flask, request\n"
            "app = Flask(__name__)\n@app.route('/query')\n"
            "def query():\n    user = request.args.get('username')\n"
            "    db = sqlite3.connect(':memory:')\n    cursor = db.cursor()\n"
            "    cursor.execute('SELECT * FROM users WHERE name=?', (user,))\n",
            "CWE-89",
            9,
        ),
        (
            "from flask import Flask, request, make_response\n"
            "from markupsafe import escape\napp = Flask(__name__)\n"
            "@app.route('/hello')\ndef hello():\n"
            "    name = request.args.get('name')\n"
            "    return make_response(f'<h1>{escape(name)}</h1>')\n",
            "CWE-79",
            7,
        ),
        (
            "from flask import Flask, request\napp = Flask(__name__)\n"
            "@app.route('/evaluate')\ndef evaluate(eval):\n"
            "    payload = request.form.get('payload')\n"
            "    return eval(payload)\n",
            "CWE-95",
            6,
        ),
        (
            "import requests\nfrom flask import Flask, request\n"
            "app = Flask(__name__)\n@app.route('/fetch')\n"
            "def fetch():\n    url = request.args.get('url')\n"
            "    requests = object()\n    return requests.get(url)\n",
            "CWE-918",
            8,
        ),
        (
            "from flask import Flask, request\napp = Flask(__name__)\n"
            "@app.route('/file')\ndef file(open):\n"
            "    path = request.args.get('path')\n    return open(path)\n",
            "CWE-22",
            6,
        ),
        (
            "import sqlite3\nfrom flask import Flask, request\n"
            "app = Flask(__name__)\n@app.route('/query')\n"
            "def query():\n    user = request.args.get('username')\n"
            "    cursor = get_cursor()\n"
            "    cursor.execute(f'SELECT * FROM users WHERE name={user}')\n",
            "CWE-89",
            8,
        ),
    ],
)
def test_common_python_families_abstain_without_exact_proof(
    tmp_path: Path, source: str, cwe: str, sink_line: int
) -> None:
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{sink_line}"]},
            cwe,
        )
        is None
    )


@pytest.mark.parametrize(
    "source,cwe,sink_line,source_key",
    [
        (
            "import sqlite3\nfrom flask import Flask, request\n"
            "app = Flask(__name__)\nDB = 'lab.db'\n"
            "@app.route('/query')\ndef query():\n"
            "    user = request.args.get('username', '')\n"
            "    conn = sqlite3.connect(DB)\n    c = conn.cursor()\n"
            "    sql = f\"SELECT * FROM users WHERE name='{user}'\"\n"
            "    try:\n        c.execute(sql)\n"
            "    except Exception:\n        pass\n",
            "CWE-89",
            12,
            "username",
        ),
        (
            "from flask import Flask, request, make_response\n"
            "app = Flask(__name__)\n@app.route('/hello')\n"
            "def hello():\n    name = request.args.get('name')\n"
            "    body = f'<h1>{name}</h1>'\n"
            "    return make_response(body, 200, {'Content-Type': 'text/html'})\n",
            "CWE-79",
            7,
            "name",
        ),
    ],
)
def test_realistic_direct_flows_use_exact_local_provenance(
    tmp_path: Path, source: str, cwe: str, sink_line: int, source_key: str
) -> None:
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": [f"app.py:{sink_line}"]},
        cwe,
    )
    assert anchor is not None
    assert anchor.source_key == source_key


def test_file_path_grouping_abstains_without_a_proven_read_effect(
    tmp_path: Path,
) -> None:
    source = """from flask import Flask, request
app = Flask(__name__)
@app.route('/file')
def file(flag=False):
    path = request.args.get('path')
    handle = open(path, 'r+')
    if flag:
        return handle.read()
    handle.write('fixed')
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:6"]},
            "CWE-22",
        )
        is None
    )


def test_xss_grouping_abstains_when_response_is_mutated_after_sink(
    tmp_path: Path,
) -> None:
    source = """from flask import Flask, request, make_response
app = Flask(__name__)
@app.route('/hello')
def hello():
    name = request.args.get('name')
    body = f'<h1>{name}</h1>'
    response = make_response(body)
    response.headers['Content-Type'] = 'text/plain'
    return response
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:7"]},
            "CWE-79",
        )
        is None
    )


def test_sql_grouping_distinguishes_cited_request_fields_at_one_sink(
    tmp_path: Path,
) -> None:
    source = """import sqlite3
from flask import Flask, request
app = Flask(__name__)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = f\"SELECT * FROM users WHERE name='{username}' AND password='{password}'\"
    return cursor.execute(query)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()

    username = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:6", "app.py:11"]},
        "CWE-89",
    )
    password = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:7", "app.py:11"]},
        "CWE-89",
    )
    source_less = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:10", "app.py:11"]},
        "CWE-89",
    )

    assert username is not None
    assert password is not None
    assert username.source_key == "username"
    assert password.source_key == "password"
    assert username != password
    assert source_less is None


def test_sql_grouping_supports_a_direct_execute_fetchone_result(tmp_path: Path) -> None:
    source = """import sqlite3
from flask import Flask, request
app = Flask(__name__)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = f\"SELECT * FROM users WHERE name='{username}' AND password='{password}'\"
    result = cursor.execute(query).fetchone()
    return result
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:6", "app.py:11"]},
        "CWE-89",
    )

    assert anchor is not None
    assert anchor.source_key == "username"
    assert anchor.sink_callee == "cursor.execute"


def test_xss_grouping_supports_a_direct_html_f_string_return(tmp_path: Path) -> None:
    source = """from flask import Flask, request
app = Flask(__name__)
@app.route('/search')
def search():
    query = request.args.get('q')
    return f'<h1>{query}</h1>'
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:5", "app.py:6"]},
        "CWE-79",
    )

    assert anchor is not None
    assert anchor.sink_callee == "return_html"
    assert anchor.source_key == "q"


def test_codeql_import_preamble_preserves_a_single_proven_sql_flow(
    tmp_path: Path,
) -> None:
    source = """import sqlite3
from flask import Flask, request
app = Flask(__name__)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = f\"SELECT * FROM users WHERE name='{username}'\"
    return cursor.execute(query)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    trace = _normalized_trace(
        {
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1},
                                        },
                                        "message": {
                                            "text": "ControlFlowNode for ImportMember"
                                        },
                                    }
                                },
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1},
                                        },
                                        "message": {
                                            "text": "ControlFlowNode for request"
                                        },
                                    }
                                },
                                *(
                                    {
                                        "location": {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "app.py"},
                                                "region": {"startLine": line},
                                            }
                                        }
                                    }
                                    for line in (6, 9, 10)
                                ),
                            ]
                        }
                    ]
                }
            ]
        },
        "app.py",
        tmp_path,
    )
    assert trace == {
        "sarif_steps": [
            {"path": "app.py", "line": 6},
            {"path": "app.py", "line": 9},
            {"path": "app.py", "line": 10},
        ]
    }
    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:6", "app.py:10"]},
        "CWE-89",
        trace,
    )

    assert anchor is not None
    assert anchor.source_key == "username"
    assert anchor.sink_line == 10


def test_codeql_trace_with_another_request_input_still_abstains(tmp_path: Path) -> None:
    source = """import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/run')
def run():
    left = request.args.get('left')
    right = request.args.get('right')
    os.system(right)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:7", "app.py:8"]},
            "CWE-78",
            {
                "sarif_steps": [
                    {"path": "app.py", "line": 1},
                    {"path": "app.py", "line": 6},
                    {"path": "app.py", "line": 7},
                    {"path": "app.py", "line": 8},
                ]
            },
        )
        is None
    )


def test_xss_grouping_supports_a_client_controlled_cookie_value(tmp_path: Path) -> None:
    source = """from flask import Flask, request
app = Flask(__name__)
@app.route('/dashboard')
def dashboard():
    user = request.cookies.get('session', 'guest')
    return f'<h1>{user}</h1>'
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:5", "app.py:6"]},
        "CWE-79",
    )

    assert anchor is not None
    assert anchor.source_access == "request.cookies"
    assert anchor.source_key == "session"


def test_distinct_valid_trace_steps_do_not_share_a_group_anchor(tmp_path: Path) -> None:
    source = """import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/ping')
def ping():
    a = request.args.get('cmd')
    b = a
    c = b
    os.system(c)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()

    def trace(lines: tuple[int, ...]) -> dict[str, object]:
        return {"sarif_steps": [{"path": "app.py", "line": line} for line in lines]}

    first = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:9"]},
        "CWE-78",
        trace((6, 7, 9)),
    )
    second = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:9"]},
        "CWE-78",
        trace((6, 8, 9)),
    )
    impossible = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:9"]},
        "CWE-78",
        trace((6, 3, 9)),
    )
    assert first is not None and second is not None
    assert first != second
    assert impossible is None


def test_fastapi_typed_request_query_source_has_a_proven_route(tmp_path: Path) -> None:
    source = """import os
from fastapi import FastAPI, Request
app = FastAPI()
@app.get('/run')
async def run(req: Request):
    command = req.query_params.get('cmd')
    os.system(command)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:6", "app.py:7"]},
        "CWE-78",
    )

    assert anchor is not None
    assert anchor.route == "/run"
    assert anchor.source_access == "req.query_params"
    assert anchor.source_key == "cmd"
    assert anchor.sink_callee == "os.system"


def test_fastapi_query_keys_at_one_sink_remain_distinct(tmp_path: Path) -> None:
    source = """import os
from fastapi import FastAPI, Request
app = FastAPI()
@app.post('/run')
async def run(req: Request):
    left = req.query_params.get('left')
    right = req.query_params.get('right')
    os.system(f'{left} {right}')
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()

    left = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:6", "app.py:8"]},
        "CWE-78",
    )
    right = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:7", "app.py:8"]},
        "CWE-78",
    )
    ambiguous = resolve_flow_anchor(
        tmp_path,
        "app.py",
        sha,
        {"code_locations": ["app.py:8"]},
        "CWE-78",
    )

    assert left is not None and right is not None
    assert left.route == right.route == "/run"
    assert left.source_key == "left"
    assert right.source_key == "right"
    assert left != right
    assert ambiguous is None


@pytest.mark.parametrize(
    "source",
    [
        """import os
from fake import FastAPI
from fastapi import Request
api = FastAPI()
@api.get('/run')
async def run(req: Request):
    command = req.query_params.get('cmd')
    os.system(command)
""",
        """import os
from fastapi import FastAPI
from fake import Request
api = FastAPI()
@api.get('/run')
async def run(req: Request):
    command = req.query_params.get('cmd')
    os.system(command)
""",
        """import os
from fastapi import FastAPI, Request
api = FastAPI()
@api.get('/run')
async def run(req: Request):
    command = req.query_params.get('cmd')
    os.system(command)
api.add_api_route('/another', run)
""",
        """import os
from fastapi import FastAPI, Request
api = FastAPI()
@api.get('/run')
@api.post('/run')
async def run(req: Request):
    command = req.query_params.get('cmd')
    os.system(command)
""",
        """import os
from fastapi import FastAPI, Request
api = FastAPI()
@api.get('/run')
async def run(req: Request):
    req = replacement
    command = req.query_params.get('cmd')
    os.system(command)
""",
    ],
)
def test_fastapi_unproven_route_or_request_abstains(
    tmp_path: Path, source: str
) -> None:
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    sink_line = source.splitlines().index("    os.system(command)") + 1

    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{sink_line}"]},
            "CWE-78",
        )
        is None
    )


@pytest.mark.parametrize("shadowed", ["FastAPI", "Request"])
def test_fastapi_import_alias_shadowing_abstains(tmp_path: Path, shadowed: str) -> None:
    source = f"""import os
from fastapi import FastAPI, Request
import fake as {shadowed}
api = FastAPI()
@api.get('/run')
async def run(req: Request):
    command = req.query_params.get('cmd')
    os.system(command)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:8"]},
            "CWE-78",
        )
        is None
    )


def test_fastapi_wildcard_import_cannot_prove_a_builtin_sink(tmp_path: Path) -> None:
    source = """from fastapi import FastAPI, Request
from fake import *
api = FastAPI()
@api.get('/file')
async def file(req: Request):
    path = req.query_params.get('path')
    return open(path).read()
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": ["app.py:7"]},
            "CWE-22",
        )
        is None
    )


def test_fastapi_awaited_json_key_has_a_proven_body_source(tmp_path: Path) -> None:
    source = """import os
from fastapi import FastAPI, Request
app = FastAPI()
@app.post('/run')
async def run(req: Request):
    data = await req.json()
    command = data.get('cmd')
    os.system(command)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:7", "app.py:8"]},
        "CWE-78",
    )

    assert anchor is not None
    assert anchor.route == "/run"
    assert anchor.source_line == 6
    assert anchor.source_access == "req.json"
    assert anchor.source_key == "cmd"


def test_fastapi_bare_string_parameter_is_a_query_source(tmp_path: Path) -> None:
    source = """import os
from fastapi import FastAPI
app = FastAPI()
@app.get('/select')
async def select(username: str):
    os.system(username)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:5", "app.py:6"]},
        "CWE-78",
    )

    assert anchor is not None
    assert anchor.route == "/select"
    assert anchor.source_line == 5
    assert anchor.source_access == "fastapi.query"
    assert anchor.source_key == "username"


def test_fastapi_optional_string_query_with_unused_body_argument(
    tmp_path: Path,
) -> None:
    source = """import os
from typing import Optional
from fastapi import FastAPI
class User:
    pass
app = FastAPI()
@app.delete('/user')
async def delete(username: Optional[str] = '', user: Optional[User] = None):
    os.system(username)
"""
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)

    anchor = resolve_flow_anchor(
        tmp_path,
        "app.py",
        hashlib.sha256(raw).hexdigest(),
        {"code_locations": ["app.py:8", "app.py:9"]},
        "CWE-78",
    )

    assert anchor is not None
    assert anchor.route == "/user"
    assert anchor.source_line == 8
    assert anchor.source_access == "fastapi.query"
    assert anchor.source_key == "username"


@pytest.mark.parametrize(
    "source",
    [
        """import os
from fastapi import FastAPI
app = FastAPI()
@app.get('/run')
async def run(left: str, right: str):
    os.system(f'{left} {right}')
""",
        """import os
from fastapi import FastAPI
app = FastAPI()
@app.get('/run/{username}')
async def run(username: str):
    os.system(username)
""",
        """import os
from fastapi import FastAPI
import fake as str
app = FastAPI()
@app.get('/run')
async def run(username: str):
    os.system(username)
""",
        """import os
from typing import Optional
from fastapi import FastAPI
import fake as Optional
app = FastAPI()
@app.get('/run')
async def run(username: Optional[str] = ''):
    os.system(username)
""",
        """import os
from fastapi import FastAPI
app = FastAPI()
@app.get('/run')
async def run(username: str):
    username = replacement
    os.system(username)
""",
        """import os
from fastapi import FastAPI, Request
app = FastAPI()
@app.post('/run')
async def run(req: Request):
    req = replacement
    data = await req.json()
    os.system(data.get('cmd'))
""",
        """import os
from fastapi import FastAPI, Request
app = FastAPI()
@app.post('/run')
async def run(req: Request):
    data = req.json()
    os.system(data.get('cmd'))
""",
        """import os
from fastapi import FastAPI, Request
app = FastAPI()
@app.post('/run')
async def run(req: Request):
    data = await req.json()
    left = data.get('left')
    right = data.get('right')
    os.system(f'{left} {right}')
""",
    ],
)
def test_fastapi_ambiguous_source_or_route_abstains(
    tmp_path: Path, source: str
) -> None:
    raw = source.encode("utf-8")
    (tmp_path / "app.py").write_bytes(raw)
    sink_line = next(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "os.system(" in line
    )

    assert (
        resolve_flow_anchor(
            tmp_path,
            "app.py",
            hashlib.sha256(raw).hexdigest(),
            {"code_locations": [f"app.py:{sink_line}"]},
            "CWE-78",
        )
        is None
    )
