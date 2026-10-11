"""A saved Python scope may be narrowed only by pinned source evidence."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import StaticGap, SurfaceIndex
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.surface_scope_recertification import (
    build_python_scope_certificate,
)


def _run_git(workspace: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(workspace), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _pinned_workspace(tmp_path: Path, files: dict[str, bytes]) -> tuple[Path, str]:
    workspace = tmp_path / "source"
    workspace.mkdir()
    _run_git(workspace, "init", "--quiet")
    for name, content in files.items():
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    _run_git(workspace, "add", "--", *files)
    _run_git(
        workspace,
        "-c",
        "user.name=Scope Test",
        "-c",
        "user.email=scope-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "pinned scope fixture",
    )
    return workspace, _run_git(workspace, "rev-parse", "HEAD")


def _fixture(
    tmp_path: Path,
    files: dict[str, bytes],
    gaps: tuple[StaticGap, ...],
    excluded: list[dict[str, str]],
) -> tuple[CheckpointIdentity, SurfaceIndex, object, object, dict[str, object], Path]:
    workspace, commit_id = _pinned_workspace(tmp_path, files)
    identity = CheckpointIdentity(
        analysis_id="scope-analysis",
        workspace_id="scope-workspace",
        commit_id=commit_id,
        hypothesis_id=None,
    )
    index = SurfaceIndex(
        scope_fingerprint="f" * 64,
        static_bundle_hash="a" * 64,
        ast_manifest_hash="b" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="c" * 64,
        candidate_count=0,
        surfaces=(),
        static_gaps=gaps,
    )
    coverage: dict[str, object] = {
        "kind": "simple_static_coverage_v1",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "fingerprint": "f" * 64,
        "expected_count": 1,
        "verified_count": 1,
        "gaps": [],
        "unsupported": [],
        "unsupported_files": [],
        "unavailable_paths": [],
        "excluded_paths": [],
        "ast_parsed_file_count": 1,
        "ast_parse_error_count": 0,
        "ast_parse_errors": [],
        "ast_oversize_count": 0,
        "ast_oversize_paths": [],
        "ast_truncated": False,
        "codeql_error": None,
        "engine_errors": [],
        "out_of_scope_product_files": excluded,
        "excluded_test_files": [],
    }
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    return (
        identity,
        index,
        artifacts.put_json(index.to_json()),
        artifacts.put_json(coverage),
        coverage,
        workspace,
    )


def _certificate(
    fixture: tuple[
        CheckpointIdentity, SurfaceIndex, object, object, dict[str, object], Path
    ],
) -> dict[str, object]:
    return build_python_scope_certificate(*fixture)


def test_three_pinned_js_exclusions_leave_zero_effective_gaps(tmp_path: Path) -> None:
    entries = [
        ("web/first.js", "non_python_product_source"),
        ("web/second.ts", "declared_non_python_entry"),
        ("web/third.jsx", "non_python_product_source"),
    ]
    fixture = _fixture(
        tmp_path,
        {
            "app.py": b"print('ready')\n",
            **{path: b"// source\n" for path, _ in entries},
        },
        tuple(StaticGap(path, "STATIC_SCOPE", reason) for path, reason in entries),
        [{"path": path, "reason": reason} for path, reason in entries],
    )

    certificate = _certificate(fixture)

    assert certificate["kind"] == "simple_python_scope_recertification_v1"
    assert certificate["commit_id"] == fixture[0].commit_id
    assert certificate["scope_fingerprint"] == "f" * 64
    assert certificate["raw_static_gaps"] == [
        {"path": path, "rule_id": "STATIC_SCOPE", "reason": reason, "engine": "STATIC"}
        for path, reason in entries
    ]
    assert certificate["raw_out_of_scope_product_files"] == [
        {"path": path, "reason": reason} for path, reason in entries
    ]
    assert certificate["effective_static_gaps"] == []
    assert {row["decision"] for row in certificate["file_decisions"]} == {
        "OUT_OF_SCOPE"
    }
    assert {row["source_sha256"] for row in certificate["file_decisions"]} == {
        hashlib.sha256(b"// source\n").hexdigest()
    }


def test_python_parser_gap_remains_effective(tmp_path: Path) -> None:
    gap = StaticGap("app.py", "AST", "AST_PARSE_ERROR", "AST")
    fixture = _fixture(
        tmp_path,
        {"app.py": b"broken = (\n"},
        (gap,),
        [],
    )

    certificate = _certificate(fixture)

    assert certificate["effective_static_gaps"] == [
        {
            "path": "app.py",
            "rule_id": "AST",
            "reason": "AST_PARSE_ERROR",
            "engine": "AST",
        }
    ]
    assert certificate["file_decisions"][0]["decision"] == "IN_SCOPE"


@pytest.mark.parametrize("mutation", ("missing", "changed"))
def test_missing_or_modified_js_blob_never_passes(
    tmp_path: Path, mutation: str
) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    target = fixture[-1] / "web/view.js"
    if mutation == "missing":
        target.unlink()
    else:
        target.write_bytes(b"// changed after checkout\n")

    certificate = _certificate(fixture)

    assert certificate["effective_static_gaps"] == [
        {
            "path": "web/view.js",
            "rule_id": "STATIC_SCOPE",
            "reason": "non_python_product_source",
            "engine": "STATIC",
        }
    ]
    assert certificate["file_decisions"][0]["decision"] == "IN_SCOPE"
    assert certificate["file_decisions"][0]["source_sha256"] is None


def test_unknown_reason_and_pyi_remain_effective(tmp_path: Path) -> None:
    gaps = (
        StaticGap("web/view.js", "STATIC_SCOPE", "UNKNOWN_SCOPE"),
        StaticGap("types.pyi", "STATIC_SCOPE", "python_stub_not_scanned"),
    )
    fixture = _fixture(
        tmp_path,
        {
            "app.py": b"print('ready')\n",
            "web/view.js": b"// pinned\n",
            "types.pyi": b"def ready() -> bool: ...\n",
        },
        gaps,
        [
            {"path": "web/view.js", "reason": "UNKNOWN_SCOPE"},
            {"path": "types.pyi", "reason": "python_stub_not_scanned"},
        ],
    )

    certificate = _certificate(fixture)

    assert {row["path"] for row in certificate["effective_static_gaps"]} == {
        "web/view.js",
        "types.pyi",
    }
    assert {row["decision"] for row in certificate["file_decisions"]} == {"IN_SCOPE"}


def test_changed_pinned_commit_rejected_before_reclassification(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    workspace = fixture[-1]
    (workspace / "app.py").write_bytes(b"print('new commit')\n")
    _run_git(workspace, "add", "--", "app.py")
    _run_git(
        workspace,
        "-c",
        "user.name=Scope Test",
        "-c",
        "user.email=scope-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "changed scope fixture",
    )

    with pytest.raises(ValueError, match="SCOPE_RECERTIFICATION_COMMIT_MISMATCH"):
        _certificate(fixture)


def test_malformed_unverified_gap_cannot_be_certified(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    coverage["gaps"] = [{"path": "app.py"}]
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    with pytest.raises(ValueError, match="SCOPE_RECERTIFICATION_COVERAGE_INVALID"):
        build_python_scope_certificate(
            identity, index, index_ref, coverage_ref, coverage, workspace
        )


def test_unindexed_python_file_rule_gap_stays_effective(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    coverage["expected_count"] = 2
    coverage["verified_count"] = 1
    coverage["gaps"] = [
        {"path": "app.py", "rule_id": "python/path-sink", "reason": "TIMEOUT"}
    ]
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    certificate = build_python_scope_certificate(
        identity, index, index_ref, coverage_ref, coverage, workspace
    )

    assert {row["path"] for row in certificate["effective_static_gaps"]} == {"app.py"}


@pytest.mark.parametrize(
    ("field", "count_field", "reason"),
    [
        ("ast_parse_errors", "ast_parse_error_count", "AST_PARSE_ERROR"),
        ("ast_oversize_paths", "ast_oversize_count", "AST_SOURCE_TOO_LARGE"),
    ],
)
def test_unindexed_ast_error_stays_effective(
    tmp_path: Path, field: str, count_field: str, reason: str
) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    coverage[field] = ["app.py"]
    coverage[count_field] = 1
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    certificate = build_python_scope_certificate(
        identity, index, index_ref, coverage_ref, coverage, workspace
    )

    assert any(
        row["path"] == "app.py" and row["reason"] == reason
        for row in certificate["effective_static_gaps"]
    )


def test_unindexed_engine_error_stays_effective(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    coverage["engine_errors"] = ["OPENGREP_SCAN_FAILED"]
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    certificate = build_python_scope_certificate(
        identity, index, index_ref, coverage_ref, coverage, workspace
    )

    assert any(
        row["path"] == "" and row["reason"] == "ENGINE_ERROR:OPENGREP_SCAN_FAILED"
        for row in certificate["effective_static_gaps"]
    )


def test_coverage_from_another_static_scope_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    coverage["fingerprint"] = "d" * 64
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    with pytest.raises(ValueError, match="SCOPE_RECERTIFICATION_COVERAGE_INVALID"):
        build_python_scope_certificate(
            identity, index, index_ref, coverage_ref, coverage, workspace
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("ast_truncated", "yes"),
        ("codeql_error", {"error": "failed"}),
        ("unavailable", "yes"),
    ],
)
def test_malformed_coverage_markers_are_rejected(
    tmp_path: Path, field: str, invalid: object
) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    coverage[field] = invalid
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    with pytest.raises(ValueError, match="SCOPE_RECERTIFICATION_COVERAGE_INVALID"):
        build_python_scope_certificate(
            identity, index, index_ref, coverage_ref, coverage, workspace
        )


@pytest.mark.parametrize("duplicate", (False, True))
def test_missing_or_duplicate_file_rule_gap_cannot_be_hidden_by_js_exclusion(
    tmp_path: Path, duplicate: bool
) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    js_gap = {
        "path": "web/view.js",
        "rule_id": "STATIC_SCOPE",
        "reason": "non_python_product_source",
    }
    coverage["expected_count"] = 3
    coverage["verified_count"] = 1
    coverage["gaps"] = [js_gap, js_gap] if duplicate else [js_gap]
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    with pytest.raises(ValueError, match="SCOPE_RECERTIFICATION_COVERAGE_INVALID"):
        build_python_scope_certificate(
            identity, index, index_ref, coverage_ref, coverage, workspace
        )


@pytest.mark.parametrize(
    "field", ("unsupported", "unsupported_files", "unavailable_paths", "excluded_paths")
)
def test_missing_producer_coverage_field_is_rejected(
    tmp_path: Path, field: str
) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n", "web/view.js": b"// pinned\n"},
        (StaticGap("web/view.js", "STATIC_SCOPE", "non_python_product_source"),),
        [{"path": "web/view.js", "reason": "non_python_product_source"}],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    coverage.pop(field)
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    with pytest.raises(ValueError, match="SCOPE_RECERTIFICATION_COVERAGE_INVALID"):
        build_python_scope_certificate(
            identity, index, index_ref, coverage_ref, coverage, workspace
        )


def test_raw_scan_gap_provenance_is_preserved(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": b"print('ready')\n"},
        (),
        [],
    )
    identity, index, index_ref, _, coverage, workspace = fixture
    coverage["expected_count"] = 2
    coverage["verified_count"] = 1
    coverage["gaps"] = [
        {
            "path": "app.py",
            "rule_id": "python/sink",
            "reason": "TIMEOUT",
            "history_status": "INTERRUPTED",
            "known_attempt_count": 2,
            "known_attempts_by_engine": {"opengrep": 1, "semgrep": 1},
        }
    ]
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )

    certificate = build_python_scope_certificate(
        identity, index, index_ref, coverage_ref, coverage, workspace
    )

    assert certificate["raw_coverage_gaps"] == coverage["gaps"]
    assert any(
        row["path"] == "app.py" and row["rule_id"] == "python/sink"
        for row in certificate["effective_static_gaps"]
    )
