from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sastsimi.simple_runtime.finding_flow import (
    FlowEvidenceInvalid,
    resolve_flow_anchor,
)

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
            {"path": "app.py", "line": 1},
            {"path": "app.py", "line": 10},
            {"path": "app.py", "line": 11},
        ]
    }
    assert resolve_flow_anchor(workspace, "app.py", sha, proposal, "CWE-78", agreeing)
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
