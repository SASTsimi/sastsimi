"""Repository profiling is closed over the exact safe Git manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.ports.dto import RepositoryPreparation, TrackedFile
from sastsimi.static_analysis.repository_profile import (
    ActiveStaticCapability,
    RepositoryProfiler,
    select_static_tools,
)
from tests.integration.runtime_support import metadata


def _blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def _write(root: Path, path: str, raw: bytes) -> TrackedFile:
    target = root.joinpath(*path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return TrackedFile(path, "100644", _blob(raw), len(raw))


def _preparation(root: Path, tracked: tuple[TrackedFile, ...]) -> RepositoryPreparation:
    return RepositoryPreparation(
        analysis_id="analysis",
        workspace_id="workspace",
        repository_url="file:///fixture",
        requested_ref="main",
        status="READY",
        resolved_commit_id="a" * 40,
        root=root,
        tracked_files=tracked,
        gaps=(),
        errors=(),
        lease_id="lease",
    )


def _meta() -> RecordMeta:
    return RecordMeta.model_validate_json(
        json.dumps(
            metadata("repository_profile", "repository-profile", code=True)
            | {
                "analysis_id": "analysis",
                "workspace_id": "workspace",
                "commit_id": "a" * 40,
                "attempt_id": "attempt",
            }
        )
    )


def _workspace_ref() -> RunStoredDataRef:
    return RunStoredDataRef.model_validate_json(
        json.dumps(
            {
                "stored_data_id": "workspace-record",
                "data_kind": "code_workspace",
                "content_hash": "d" * 64,
                "analysis_id": "analysis",
                "record_id": "workspace-record",
            }
        )
    )


def _profile(adapter: str, name: str) -> StaticToolProfile:
    return StaticToolProfile.model_validate_json(
        json.dumps(
            {
                "meta": metadata("static_tool_profile", name, code=True),
                "profile_key": name,
                "purpose": "PRODUCTION",
                "status": "ACTIVE",
                "adapter_key": adapter,
                "tool_name": "AST" if adapter == "PYTHON_AST" else adapter,
                "tool_kind": ("STRUCTURE" if adapter == "PYTHON_AST" else "RULE_BASED"),
                "executable_key": name,
                "executable_sha256": "b" * 64,
                "expected_version": "1",
                "capability_evidence_ref": {
                    "stored_data_id": "capability",
                    "data_kind": "capability_evidence",
                    "content_hash": "c" * 64,
                    "workspace_id": "w1",
                    "commit_id": "c1",
                    "record_id": "capability",
                },
                "probe_timeout_ms": 1,
                "run_timeout_ms": 1,
                "stdout_limit_bytes": 1,
                "stderr_limit_bytes": 1,
                "max_attempt_output_bytes": 1,
                "max_output_file_bytes": 1,
                "max_artifact_read_bytes": 1,
            }
        )
    )


def test_profile_uses_only_exact_tracked_files_and_detects_known_inputs(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "src/app.py", b"from fastapi import FastAPI\n"),
        _write(
            tmp_path,
            "pyproject.toml",
            b'[project]\nname="demo"\ndependencies=["fastapi>=0.100"]\n',
        ),
        _write(tmp_path, "Dockerfile", b"FROM python:3.12-slim\n"),
    )
    # An untracked package file must never influence detection.
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"*"}}')

    result = RepositoryProfiler().build(
        _preparation(tmp_path, tracked),
        meta=_meta(),
        workspace_ref=_workspace_ref(),
    )

    assert result.status == "READY"
    assert [item.name for item in result.languages] == ["PYTHON"]
    assert [item.name for item in result.frameworks] == ["FASTAPI"]
    assert [item.kind for item in result.config_files] == ["DOCKERFILE", "PYPROJECT"]
    assert tuple(item.git_path for item in result.tracked_files) == tuple(
        sorted(item.git_path for item in tracked)
    )
    assert all(len(item.content_sha256) == 64 for item in result.tracked_files)


def test_profile_fails_closed_when_a_tracked_blob_changed(tmp_path: Path) -> None:
    tracked = (_write(tmp_path, "app.py", b"print('safe')\n"),)
    (tmp_path / "app.py").write_text("print('changed')\n")

    with pytest.raises(ValueError, match="REPOSITORY_MANIFEST_MISMATCH"):
        RepositoryProfiler().build(
            _preparation(tmp_path, tracked),
            meta=_meta(),
            workspace_ref=_workspace_ref(),
        )


def test_unknown_or_ambiguous_build_is_not_guessed(tmp_path: Path) -> None:
    tracked = (_write(tmp_path, "README.md", b"custom build instructions"),)

    result = RepositoryProfiler().build(
        _preparation(tmp_path, tracked),
        meta=_meta(),
        workspace_ref=_workspace_ref(),
    )

    assert result.status == "NEEDS_CONFIRMATION"
    assert result.languages == ()
    assert "LANGUAGE_UNCONFIRMED" in result.confirmation_reasons
    assert "BUILD_UNCONFIRMED" in result.confirmation_reasons


def test_javascript_framework_uses_source_and_tracked_package_evidence(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "src/server.js", b"export const server = true;\n"),
        _write(
            tmp_path,
            "package.json",
            b'{"dependencies":{"express":"^5.0.0"}}',
        ),
    )

    result = RepositoryProfiler().build(
        _preparation(tmp_path, tracked),
        meta=_meta(),
        workspace_ref=_workspace_ref(),
    )

    assert result.status == "READY"
    assert [item.name for item in result.languages] == ["JAVASCRIPT"]
    assert [item.name for item in result.frameworks] == ["EXPRESS"]


def test_package_declaration_alone_does_not_guess_a_language(tmp_path: Path) -> None:
    tracked = (_write(tmp_path, "package.json", b'{"dependencies":{}}'),)

    result = RepositoryProfiler().build(
        _preparation(tmp_path, tracked),
        meta=_meta(),
        workspace_ref=_workspace_ref(),
    )

    assert result.status == "NEEDS_CONFIRMATION"
    assert result.languages == ()
    assert result.confirmation_reasons == ("LANGUAGE_UNCONFIRMED",)


def test_tool_selection_requires_active_verified_capability(tmp_path: Path) -> None:
    tracked = (
        _write(tmp_path, "app.py", b"print('ok')\n"),
        _write(tmp_path, "requirements.txt", b""),
    )
    repository = RepositoryProfiler().build(
        _preparation(tmp_path, tracked),
        meta=_meta(),
        workspace_ref=_workspace_ref(),
    )
    ast = _profile("PYTHON_AST", "python-ast")
    codeql = _profile("CODEQL", "codeql-python")

    selection = select_static_tools(
        repository,
        (
            ActiveStaticCapability(ast, ("PYTHON",)),
            ActiveStaticCapability(codeql, ("PYTHON",)),
        ),
    )

    assert selection.status == "READY"
    assert [item.adapter_key for item in selection.selected_tools] == [
        "CODEQL",
        "PYTHON_AST",
    ]


def test_tool_selection_blocks_when_required_capability_is_missing(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "app.py", b"print('ok')\n"),
        _write(tmp_path, "requirements.txt", b""),
    )
    repository = RepositoryProfiler().build(
        _preparation(tmp_path, tracked),
        meta=_meta(),
        workspace_ref=_workspace_ref(),
    )

    selection = select_static_tools(repository, ())

    assert selection.status == "BLOCKED"
    assert selection.block_reasons == ("NO_ACTIVE_STATIC_CAPABILITY",)


def test_tool_selection_blocks_when_one_detected_language_is_uncovered(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "app.py", b"print('ok')\n"),
        _write(tmp_path, "web.js", b"export const ok = true;\n"),
        _write(tmp_path, "requirements.txt", b""),
    )
    repository = RepositoryProfiler().build(
        _preparation(tmp_path, tracked),
        meta=_meta(),
        workspace_ref=_workspace_ref(),
    )

    selection = select_static_tools(
        repository,
        (ActiveStaticCapability(_profile("PYTHON_AST", "python-ast"), ("PYTHON",)),),
    )

    assert selection.status == "BLOCKED"
    assert selection.selected_tools == ()
    assert selection.block_reasons == ("UNSUPPORTED_LANGUAGE:JAVASCRIPT",)
