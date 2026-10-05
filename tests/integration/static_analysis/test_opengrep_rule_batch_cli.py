"""Compare the real OpenGrep CLI's full scan with two rule-selective scans."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from sastsimi.simple_runtime.opengrep_rule_batches import (
    RuleBatch,
    parse_rule_batch,
    plan_rule_batches,
)


def _hits(results: object, source: Path) -> Counter[tuple[object, ...]]:
    selected: Counter[tuple[object, ...]] = Counter()
    assert isinstance(results, list)
    for item in results:
        assert isinstance(item, dict)
        raw_path = Path(str(item["path"]))
        absolute = raw_path if raw_path.is_absolute() else source / raw_path
        start = item["start"]
        end = item["end"]
        assert isinstance(start, dict) and isinstance(end, dict)
        selected[
            (
                item["check_id"],
                absolute.resolve().relative_to(source.resolve()).as_posix(),
                start.get("line"),
                start.get("col"),
                end.get("line"),
                end.get("col"),
            )
        ] += 1
    return selected


def test_rule_batches_match_unbatched_opengrep_cli(tmp_path: Path) -> None:
    tool = shutil.which("opengrep")
    if tool is None:
        pytest.skip("OpenGrep is not installed")
    root = Path(__file__).resolve().parents[3]
    config = (
        root / "config" / "static-analysis" / "candidate-v1" / "opengrep" / "rules.yml"
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(
        "import subprocess\nsubprocess.run(['echo', 'ok'])\n", encoding="utf-8"
    )
    (source / "app.js").write_text("document.write(req.body);\n", encoding="utf-8")
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    environment = os.environ.copy()
    environment.update(
        {
            "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log"),
            "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
            "TEMP": str(tmp_path),
            "TMP": str(tmp_path),
        }
    )
    plan = plan_rule_batches(
        config.read_bytes(),
        tool_version="1.30.0",
        executable_sha256=hashlib.sha256(Path(tool).read_bytes()).hexdigest(),
        batch_size=9,
    )

    def scan(name: str, batch: RuleBatch | None) -> dict[str, object]:
        output = output_root / f"{name}.json"
        command = [
            tool,
            "scan",
            "--json",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--config",
            str(config),
            "--output",
            str(output),
        ]
        if batch is not None:
            for rule_id in batch.excluded_rule_ids:
                command.extend(("--exclude-rule", rule_id))
        command.append(str(source))
        completed = subprocess.run(
            command,
            cwd=source,
            env=environment,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr[-3000:]
        assert output.is_file()
        raw = output.read_bytes()
        if batch is not None:
            return parse_rule_batch(raw, batch)
        loaded = json.loads(raw)
        assert isinstance(loaded, dict)
        assert loaded.get("errors") == []
        return loaded

    baseline = scan("full", None)
    partial = [scan(f"batch-{batch.index}", batch) for batch in plan.batches]
    baseline_results = baseline["results"]
    assert isinstance(baseline_results, list)
    ids = {item["check_id"] for item in baseline_results}
    assert {
        "sastsimi.python.command-sink",
        "sastsimi.javascript.dom-xss-sink",
    } <= ids
    combined: list[object] = []
    for result in partial:
        values = result["results"]
        assert isinstance(values, list)
        combined.extend(values)
    assert _hits(combined, source) == _hits(baseline_results, source)


def test_python_request_source_rule_covers_common_web_entries(tmp_path: Path) -> None:
    tool = shutil.which("opengrep")
    if tool is None:
        pytest.skip("OpenGrep is not installed")
    root = Path(__file__).resolve().parents[3]
    config = (
        root / "config" / "static-analysis" / "candidate-v1" / "opengrep" / "rules.yml"
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "aiohttp_app.py").write_text(
        "async def create(request):\n"
        "    fields = await request.post()\n"
        "    return fields['name']\n",
        encoding="utf-8",
    )
    (source / "fastapi_app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/create')\n"
        "async def create(username: str):\n"
        "    return username\n"
        "@router.get('/find')\n"
        "def find(name: str):\n"
        "    return name\n",
        encoding="utf-8",
    )
    (source / "flask_app.py").write_text(
        "from flask import request\n"
        "def current_user():\n"
        "    token = request.cookies.get('session')\n"
        "    key = request.headers.get('x-api-key')\n"
        "    body = request.get_json()\n"
        "    return token, key, body\n",
        encoding="utf-8",
    )
    (source / "worker.py").write_text(
        "async def read(queue):\n    return await queue.get()\n",
        encoding="utf-8",
    )
    output = tmp_path / "result.json"
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
            str(config),
            "--output",
            str(output),
            str(source),
        ],
        cwd=source,
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-3000:]
    scan = json.loads(output.read_text(encoding="utf-8"))
    assert scan["errors"] == []
    entries = {
        Path(item["path"]).name
        for item in scan["results"]
        if item["check_id"] == "sastsimi.python.request-source"
    }
    assert entries == {"aiohttp_app.py", "fastapi_app.py", "flask_app.py"}
    fastapi_lines = {
        item["start"]["line"]
        for item in scan["results"]
        if item["check_id"] == "sastsimi.python.request-source"
        and Path(item["path"]).name == "fastapi_app.py"
    }
    assert {3, 6} <= fastapi_lines
    assert all(
        item["end"]["line"] == item["start"]["line"]
        for item in scan["results"]
        if item["check_id"] == "sastsimi.python.request-source"
        and Path(item["path"]).name == "fastapi_app.py"
    )


def test_weak_password_hash_hint_excludes_generic_checksums(tmp_path: Path) -> None:
    tool = shutil.which("opengrep")
    if tool is None:
        pytest.skip("OpenGrep is not installed")
    root = Path(__file__).resolve().parents[3]
    config = root / "config/static-analysis/candidate-v1/opengrep/rules.yml"
    source = tmp_path / "source"
    source.mkdir()
    (source / "passwords.py").write_text(
        "from hashlib import md5\n"
        "def check_password(password, saved_hash):\n"
        "    return saved_hash == md5(password.encode()).hexdigest()\n"
        "def file_checksum(contents):\n"
        "    return md5(contents.encode()).hexdigest()\n",
        encoding="utf-8",
    )
    output = tmp_path / "result.json"
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
            str(config),
            "--output",
            str(output),
            str(source),
        ],
        cwd=source,
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-3000:]
    scan = json.loads(output.read_text(encoding="utf-8"))
    assert scan["errors"] == []
    hints = [
        item
        for item in scan["results"]
        if item["check_id"] == "sastsimi.python.weak-password-hash"
    ]
    assert [item["start"]["line"] for item in hints] == [3]
