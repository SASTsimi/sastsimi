"""The recall audit command is a read-only consumer of saved analyses."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.simple_runtime.models import SimpleAnalysisRun
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tools.recall_audit import _load_oracle

_REPO = Path(__file__).resolve().parents[3]
_COMMAND = _REPO / "tools" / "recall_audit.py"
_COMMIT = "a" * 40
_REPOSITORY = "https://example.test/python-repo"
_SOURCE_MARKER = "PRIVATE_SOURCE_SNIPPET_MUST_NOT_BE_PRINTED"


def _analysis(tmp_path: Path) -> tuple[Path, Path]:
    data_dir = tmp_path / "data"
    database = RuntimePaths(data_dir).database
    store = SimpleCheckpointStore(database)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-1",
            display_analysis_id="A-001",
            workspace_id="workspace-1",
            commit_id=_COMMIT,
            repository=_REPOSITORY,
        )
    )
    return data_dir, database


def _oracle(tmp_path: Path, **changes: object) -> Path:
    payload: dict[str, object] = {
        "repository": _REPOSITORY,
        "commit": _COMMIT,
        "cases": [
            {
                "case_id": "case-1",
                "cwe": "CWE-89",
                "path": "app.py",
                "source_line": 10,
                "sink_line": 20,
                "rationale": _SOURCE_MARKER,
            }
        ],
    }
    payload.update(changes)
    path = tmp_path / "oracle.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run(
    data_dir: Path, oracle_path: Path, analysis_id: str = "analysis-1"
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [
            sys.executable,
            str(_COMMAND),
            "--data-dir",
            str(data_dir),
            "--analysis-id",
            analysis_id,
            "--oracle",
            str(oracle_path),
        ],
        capture_output=True,
        text=True,
        cwd=_REPO,
        env=environment,
        timeout=30,
        check=False,
    )


def test_valid_oracle_prints_only_stage_json_without_mutating_database(
    tmp_path: Path,
) -> None:
    data_dir, database = _analysis(tmp_path)
    oracle_path = _oracle(tmp_path)
    before = database.read_bytes()

    completed = _run(data_dir, oracle_path)

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["analysis_id"] == "analysis-1"
    assert payload["oracle_commit"] == _COMMIT
    assert payload["counts"] == {"INCOMPLETE": 1}
    assert payload["cases"][0]["status"] == "INCOMPLETE"
    assert _SOURCE_MARKER not in completed.stdout
    assert completed.stderr == ""
    assert database.read_bytes() == before


def test_oracle_commit_mismatch_fails_without_result_json(tmp_path: Path) -> None:
    data_dir, _ = _analysis(tmp_path)
    oracle_path = _oracle(tmp_path, commit="b" * 40)

    completed = _run(data_dir, oracle_path)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "RECALL_ORACLE_TARGET_MISMATCH" in completed.stderr
    assert _SOURCE_MARKER not in completed.stderr


def test_oracle_repository_mismatch_fails_without_result_json(tmp_path: Path) -> None:
    data_dir, _ = _analysis(tmp_path)
    oracle_path = _oracle(tmp_path, repository="https://example.test/other-repo")

    completed = _run(data_dir, oracle_path)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "RECALL_ORACLE_TARGET_MISMATCH" in completed.stderr


def test_missing_analysis_fails_without_result_json(tmp_path: Path) -> None:
    data_dir, _ = _analysis(tmp_path)

    completed = _run(data_dir, _oracle(tmp_path), analysis_id="absent")

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "RECALL_ANALYSIS_NOT_FOUND" in completed.stderr


def test_malformed_oracle_json_is_rejected(tmp_path: Path) -> None:
    data_dir, _ = _analysis(tmp_path)
    oracle_path = tmp_path / "oracle.json"
    oracle_path.write_text("{not JSON", encoding="utf-8")

    completed = _run(data_dir, oracle_path)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "RECALL_ORACLE_INVALID" in completed.stderr


def test_missing_required_oracle_field_is_rejected(tmp_path: Path) -> None:
    data_dir, _ = _analysis(tmp_path)
    oracle_path = _oracle(tmp_path, cases=[{"case_id": "case-1"}])

    completed = _run(data_dir, oracle_path)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "RECALL_ORACLE_INVALID" in completed.stderr


def test_missing_database_fails_without_creating_one(tmp_path: Path) -> None:
    data_dir = tmp_path / "absent-data"

    completed = _run(data_dir, _oracle(tmp_path))

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "RECALL_ANALYSIS_DB_MISSING" in completed.stderr
    assert not RuntimePaths(data_dir).database.exists()


def test_corrupt_database_is_reported_without_a_traceback(tmp_path: Path) -> None:
    data_dir, database = _analysis(tmp_path)
    database.write_bytes(b"not a sqlite database")

    completed = _run(data_dir, _oracle(tmp_path))

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr.strip() == "RECALL_ANALYSIS_DATA_CORRUPT"


def test_reviewed_finding_inventory_flag_reaches_evaluator_input(
    tmp_path: Path,
) -> None:
    oracle_path = _oracle(tmp_path)
    payload = json.loads(oracle_path.read_text(encoding="utf-8"))
    payload["cases"][0]["finding_inventory_reviewed"] = True
    oracle_path.write_text(json.dumps(payload), encoding="utf-8")

    parsed = _load_oracle(oracle_path)

    assert parsed.cases[0].finding_inventory_reviewed is True


def test_help_explains_when_missed_status_is_allowed() -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(_COMMAND), "--help"],
        capture_output=True,
        text=True,
        cwd=_REPO,
        env=environment,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0
    assert "finding_inventory_reviewed" in completed.stdout
    assert "MISSED" in completed.stdout
    assert "POSSIBLE" in completed.stdout
    assert "FINDING_INVENTORY_UNREVIEWED" in completed.stdout
