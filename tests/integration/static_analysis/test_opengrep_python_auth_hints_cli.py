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


def test_password_fast_hash_hint_targets_passwords_not_file_checksums(
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
    assert _lines(results, "sastsimi.python.password-fast-hash") == {5, 6, 7}
    assert _candidate_lines(
        tmp_path, results, "sastsimi.python.password-fast-hash"
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
