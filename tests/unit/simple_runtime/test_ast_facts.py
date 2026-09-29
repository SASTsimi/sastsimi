from __future__ import annotations

import json
from pathlib import Path

from sastsimi.contracts.refs import StoredDataRef
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
