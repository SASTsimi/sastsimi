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
        "code_locations": ["app.py:7", "app.py:8"],
    }
    surface = {"title": "Shell injection near /upload", "code_locations": ["app.py:8"]}
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
    sink_only = {"code_locations": ["app.py:12"]}
    full = {"code_locations": ["app.py:7", "app.py:8", "app.py:12"]}
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
    assert all(anchor is not None for anchor in anchors)
    assert len(set(anchors)) == 3
    assert anchors[0].source_key == "left"
    assert anchors[1].source_key == "right"


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
            {"code_locations": ["app.py:6"]},
            "CWE-78",
        )
        is None
    )


def test_conflicting_trace_abstains_and_source_hash_mismatch_fails_closed(
    tmp_path: Path,
) -> None:
    workspace, sha = _fixture(tmp_path, "antony_routes.py")
    proposal = {"code_locations": ["app.py:8"]}
    assert (
        resolve_flow_anchor(
            workspace,
            "app.py",
            sha,
            proposal,
            "CWE-78",
            {
                "source": {"path": "app.py", "line": 12},
                "sink": {"path": "app.py", "line": 8},
            },
        )
        is None
    )
    with pytest.raises(FlowEvidenceInvalid):
        resolve_flow_anchor(workspace, "app.py", "0" * 64, proposal, "CWE-78")


def test_redirected_or_missing_source_fails_closed(tmp_path: Path) -> None:
    workspace, sha = _fixture(tmp_path, "antony_routes.py")
    assert (
        resolve_flow_anchor(
            workspace, "missing.py", sha, {"code_locations": ["missing.py:8"]}, "CWE-78"
        )
        is None
    )
    with pytest.raises(FlowEvidenceInvalid):
        resolve_flow_anchor(
            workspace, "../app.py", sha, {"code_locations": ["../app.py:8"]}, "CWE-78"
        )
