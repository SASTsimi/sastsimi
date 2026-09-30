from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import ast_facts
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.models import CheckpointIdentity


def _artifacts(tmp_path: Path) -> SimpleArtifactRepository:
    return SimpleArtifactRepository(
        tmp_path / "data",
        CheckpointIdentity(
            analysis_id="analysis-ast-unit",
            workspace_id="workspace-ast-unit",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )


def test_ast_manifest_distinguishes_empty_parsed_file_from_unparsed_files(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "empty.py").write_text("# no calls\n", encoding="utf-8")
    (workspace / "invalid.py").write_text("def broken(:\n", encoding="utf-8")
    (workspace / "large.py").write_text("f()\n" * 10, encoding="utf-8")
    artifacts = _artifacts(tmp_path)

    summary = collect_python_ast(
        workspace,
        ("invalid.py", "large.py", "empty.py"),
        artifacts,
        max_source_bytes=20,
    )

    assert summary["parsed_file_count"] == 1
    assert summary["fact_count"] == 0
    assert summary["parse_errors"] == ["invalid.py"]
    assert summary["oversize_paths"] == ["large.py"]
    assert summary["truncated"] is False
    manifest = json.loads(
        artifacts.read(StoredDataRef.model_validate(summary["manifest_ref"]))
    )
    assert manifest["parsed_file_count"] == 1
    assert manifest["entries"][0]["path"] == "empty.py"
    assert manifest["entries"][0]["fact_count"] == 0
    file_record = json.loads(
        artifacts.read(StoredDataRef.model_validate(manifest["entries"][0]["ref"]))
    )
    assert file_record == {
        "kind": "simple_python_ast_file_v1",
        "path": "empty.py",
        "facts": [],
    }


def test_ast_focus_selects_nearby_facts_without_losing_file_evidence(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("f()\n" * 1000, encoding="utf-8")
    artifacts = _artifacts(tmp_path)
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=10_000
    )

    focused = ast_facts.focus_ast_facts(
        artifacts, summary, path="app.py", line=900, max_bytes=1024
    )

    assert len(canonical_bytes(focused)) <= 1024
    assert focused["total_count"] == 1000
    facts = focused["facts"]
    assert isinstance(facts, list)
    assert focused["omitted_count"] == 1000 - len(facts)
    assert 0 < focused["omitted_count"] < 1000
    assert any(fact["line"] == 900 for fact in facts)
    manifest = json.loads(
        artifacts.read(StoredDataRef.model_validate(summary["manifest_ref"]))
    )
    assert focused["file_ref"] == manifest["entries"][0]["ref"]


def test_ast_manifest_validation_rejects_wrong_file_count(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("f()\n", encoding="utf-8")
    artifacts = _artifacts(tmp_path)
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=100
    )
    manifest = json.loads(
        artifacts.read(StoredDataRef.model_validate(summary["manifest_ref"]))
    )
    manifest["entries"][0]["fact_count"] = 2
    bad_manifest_ref = artifacts.put_json(manifest)
    broken_summary = summary | {
        "manifest_ref": bad_manifest_ref.model_dump(mode="json")
    }

    with pytest.raises(ValueError, match="AST_MANIFEST_INVALID"):
        ast_facts.validate_ast_manifest(artifacts, broken_summary)


def test_ast_manifest_validation_rejects_missing_file_artifact(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("f()\n", encoding="utf-8")
    artifacts = _artifacts(tmp_path)
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=100
    )
    manifest = json.loads(
        artifacts.read(StoredDataRef.model_validate(summary["manifest_ref"]))
    )
    manifest["entries"][0]["ref"]["content_hash"] = "0" * 64
    broken_summary = summary | {
        "manifest_ref": artifacts.put_json(manifest).model_dump(mode="json")
    }

    with pytest.raises(ValueError, match="AST_MANIFEST_INVALID"):
        ast_facts.validate_ast_manifest(artifacts, broken_summary)


def test_ast_focus_reads_one_file_when_manifest_exceeds_prompt_budget(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    paths = tuple(f"file_{index:04}.py" for index in range(1100))
    for path in paths:
        (workspace / path).write_text("f()\n", encoding="utf-8")
    artifacts = _artifacts(tmp_path)
    summary = collect_python_ast(workspace, paths, artifacts, max_source_bytes=100)
    manifest_raw = artifacts.read(StoredDataRef.model_validate(summary["manifest_ref"]))
    assert len(manifest_raw) > 256 * 1024

    focused = ast_facts.focus_ast_facts(artifacts, summary, path="file_0550.py", line=1)

    assert focused["total_count"] == 1
    assert focused["omitted_count"] == 0
    facts = focused["facts"]
    assert isinstance(facts, list)
    assert facts[0]["path"] == "file_0550.py"
    assert len(canonical_bytes(focused)) < 8192


def test_ast_focus_marks_sarif_without_primary_location_unavailable(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("f()\n", encoding="utf-8")
    artifacts = _artifacts(tmp_path)
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=100
    )

    focused = ast_facts.focus_ast_facts(artifacts, summary, path="", line=0)

    assert focused["status"] == "UNAVAILABLE"
    assert focused["reason"] == "CANDIDATE_LOCATION_UNAVAILABLE"
    assert focused["facts"] == []
    assert focused["total_count"] is None


def test_ast_focus_unavailable_result_remains_bounded(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifacts = _artifacts(tmp_path)
    summary = collect_python_ast(workspace, (), artifacts, max_source_bytes=100)
    summary["parse_errors"] = ["p" * 1024 + ".py"]
    parse_errors = summary["parse_errors"]
    assert isinstance(parse_errors, list)

    with pytest.raises(ValueError, match="AST_FOCUS_BUDGET_TOO_SMALL"):
        ast_facts.focus_ast_facts(
            artifacts, summary, path=parse_errors[0], line=1, max_bytes=512
        )


def test_ast_focus_reuses_one_validated_manifest_for_many_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("f()\n" * 100, encoding="utf-8")
    artifacts = _artifacts(tmp_path)
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=1000
    )
    calls = 0
    original = ast_facts._new_manifest

    def counted(
        artifacts: SimpleArtifactRepository, summary: Mapping[str, object]
    ) -> list[dict[str, Any]]:
        nonlocal calls
        calls += 1
        return original(artifacts, summary)

    monkeypatch.setattr(ast_facts, "_new_manifest", counted)

    index = ast_facts.index_ast_manifest(artifacts, summary)
    for line in range(1, 101):
        focused = ast_facts.focus_ast_facts(
            artifacts, summary, path="app.py", line=line, manifest_index=index
        )
        facts = focused["facts"]
        assert isinstance(facts, list)
        assert any(fact["line"] == line for fact in facts)

    assert calls == 1
