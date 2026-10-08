"""Exercise candidate-only Python authentication hints with the real OpenGrep CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.candidates import normalize_candidate_page
from sastsimi.simple_runtime.models import CheckpointIdentity

RULES = (
    Path(__file__).resolve().parents[3]
    / "config"
    / "static-analysis"
    / "candidate-v1"
    / "opengrep"
    / "rules.yml"
)


def _scan(tmp_path: Path, source_text: str) -> list[dict[str, object]]:
    tool = shutil.which("opengrep")
    if tool is None:
        pytest.skip("OpenGrep is not installed")
    source = tmp_path / "example.py"
    source.write_text(source_text, encoding="utf-8")
    output = tmp_path / "results.json"
    environment = os.environ.copy()
    environment.update(
        {
            "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log"),
            "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
            "TEMP": str(tmp_path),
            "TMP": str(tmp_path),
        }
    )
    completed = subprocess.run(
        [
            tool,
            "scan",
            "--json",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--config",
            str(RULES),
            "--output",
            str(output),
            str(source),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-3000:]
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded["errors"] == []
    results = loaded["results"]
    assert isinstance(results, list)
    return results


def _lines(results: list[dict[str, object]], rule_id: str) -> set[int]:
    selected: set[int] = set()
    for result in results:
        if result["check_id"] != rule_id:
            continue
        start = result["start"]
        assert isinstance(start, dict)
        line = start["line"]
        assert isinstance(line, int)
        selected.add(line)
    return selected


def _candidate_lines(
    tmp_path: Path, results: list[dict[str, object]], rule_id: str
) -> set[int]:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    ref = artifacts.put_json({"results": results})
    candidates = normalize_candidate_page(
        identity,
        "scope-1",
        "opengrep",
        ref,
        results,
        workspace=tmp_path,
        identity_version="exact-v2",
    )
    selected = [
        candidate
        for candidate in candidates
        if any(origin.rule_id == rule_id for origin in candidate.origins)
    ]
    assert all(candidate.kind == "HINT" for candidate in selected)
    return {candidate.line for candidate in selected}


def test_weak_password_hash_hint_targets_passwords_not_file_checksums(
    tmp_path: Path,
) -> None:
    results = _scan(
        tmp_path,
        """\
import hashlib
from hashlib import md5 as fast_md5

def password_digests(password, raw_password, passwd, file_bytes):
    first = hashlib.md5(password.encode()).hexdigest()
    second = hashlib.sha1(raw_password.encode('utf-8')).hexdigest()
    third = fast_md5(passwd.encode()).hexdigest()
    checksum = hashlib.md5(file_bytes).hexdigest()
    return first, second, third, checksum
""",
    )
    assert _lines(results, "sastsimi.python.weak-password-hash") == {5, 6, 7}
    assert _candidate_lines(
        tmp_path, results, "sastsimi.python.weak-password-hash"
    ) == {
        5,
        6,
        7,
    }


def test_session_identity_write_hint_never_infers_missing_rotation(
    tmp_path: Path,
) -> None:
    results = _scan(
        tmp_path,
        """\
from aiohttp_session import get_session

async def login(request, user):
    session = await get_session(request)
    session['theme'] = 'dark'
    session['user_id'] = user.id
    request.session.cycle_key()
    request.session['principal_id'] = user.id
    request.session['theme'] = 'light'
    return session
""",
    )
    assert _lines(results, "sastsimi.python.session-identity-write") == {6, 8}
    assert _candidate_lines(
        tmp_path, results, "sastsimi.python.session-identity-write"
    ) == {
        6,
        8,
    }


def test_query_parser_hint_excludes_constant_queries(tmp_path: Path) -> None:
    results = _scan(
        tmp_path,
        """\
import urllib.parse
import urllib.parse as parse_mod
from urllib.parse import parse_qs, urlparse

def handler(request):
    first = parse_qs(request.query_string)
    second = urllib.parse.parse_qsl(request.query_string)
    third = parse_qs(urlparse(request.path).query)
    fourth = parse_mod.parse_qs(request.query_string)
    parsed_request = parse_mod.urlparse(request.path)
    fifth = parse_mod.parse_qs(parsed_request.query)
    parsed_constant = parse_mod.urlparse('https://example.org/?page=1')
    ignored = parse_mod.parse_qs(parsed_constant.query)
    fixed = parse_qs('page=1')
    return first, second, third, fourth, fifth, ignored, fixed
""",
    )
    assert _lines(results, "sastsimi.python.query-parse-source") == {6, 7, 8, 9, 11}
    assert _candidate_lines(
        tmp_path, results, "sastsimi.python.query-parse-source"
    ) == {6, 7, 8, 9, 11}


def test_unsafe_deserialization_hint_excludes_safe_loaders(tmp_path: Path) -> None:
    results = _scan(
        tmp_path,
        """\
import json
import pickle
import yaml

def handler(payload):
    first = pickle.loads(payload)
    second = yaml.load(payload, Loader=yaml.UnsafeLoader)
    safe_json = json.loads(payload)
    safe_yaml = yaml.safe_load(payload)
    explicit_safe = yaml.load(payload, Loader=yaml.SafeLoader)
    return first, second, safe_json, safe_yaml, explicit_safe
""",
    )
    assert _lines(results, "sastsimi.python.deserialization-sink") == {6, 7}
    assert _candidate_lines(
        tmp_path, results, "sastsimi.python.deserialization-sink"
    ) == {6, 7}


def test_identity_cookie_hint_excludes_unrelated_cookie(tmp_path: Path) -> None:
    results = _scan(
        tmp_path,
        """\
from flask import session

def handler(response, identity):
    session['user_id'] = identity
    response.set_cookie('session', identity)
    response.set_cookie('SESSIONID', identity)
    response.set_cookie('session_id', identity)
    response.set_cookie('theme', 'dark')
    cookie = response.cookie
    cookie['session_id'] = identity
    cookie['theme'] = 'dark'
    response.cookie['auth'] = identity
    return response
""",
    )
    assert _lines(results, "sastsimi.python.session-identity-write") == {4}
    assert _lines(results, "sastsimi.python.identity-cookie-write") == {
        5,
        6,
        7,
        10,
        12,
    }
    assert _candidate_lines(
        tmp_path, results, "sastsimi.python.identity-cookie-write"
    ) == {5, 6, 7, 10, 12}


def test_base_http_handler_methods_are_possible_request_entries(
    tmp_path: Path,
) -> None:
    results = _scan(
        tmp_path,
        """\
from http.server import BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        return self.path

    def do_POST(self):
        return self.rfile.read(1)

class Helper:
    def do_GET(self):
        return 'not an HTTP handler'
""",
    )
    assert _lines(results, "sastsimi.python.http-method-handler") == {4, 7}
    assert _candidate_lines(
        tmp_path, results, "sastsimi.python.http-method-handler"
    ) == {4, 7}


def test_dynamic_redirect_hint_excludes_constant_targets(tmp_path: Path) -> None:
    results = _scan(
        tmp_path,
        """\
from flask import redirect

def handler(self, next_url):
    first = redirect(next_url)
    self.send_header('Location', next_url)
    fixed = redirect('/home')
    self.send_header('Location', '/home')
    dynamic_f = redirect(f'/users/{next_url}')
    fixed_f = redirect(f'/home')
    return first, fixed, dynamic_f, fixed_f
""",
    )
    assert _lines(results, "sastsimi.python.redirect-sink") == {4, 5, 8}
    assert _candidate_lines(tmp_path, results, "sastsimi.python.redirect-sink") == {
        4,
        5,
        8,
    }
