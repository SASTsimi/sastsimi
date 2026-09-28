from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.static_scan_provenance import enrich_gap_provenance
from sastsimi.simple_runtime.store import StaticScanExecution


def _artifacts(tmp_path: Path) -> SimpleArtifactRepository:
    return SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="provenance-test",
            workspace_id="workspace-test",
            commit_id="commit-test",
            hypothesis_id=None,
        ),
    )


def _target_run_key(
    tool: str,
    targets: tuple[str, ...],
    *,
    legacy: bool = False,
    timeout: int | None = None,
) -> str:
    if tool == "opengrep":
        key_data: dict[str, object] = {
            "kind": "opengrep_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ("rule.py",),
            "targets": targets,
        }
    else:
        key_data = {
            "batch": "batch-1",
            "rules": ("rule.py",),
            "targets": targets,
        }
        if not legacy:
            key_data["adaptive"] = 1
        if timeout is not None:
            key_data["per_file_timeout_seconds"] = timeout
    return hashlib.sha256(canonical_bytes(key_data)).hexdigest()


def test_gap_provenance_counts_only_targeted_invocations(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    full = artifacts.put_json(
        {
            "kind": "opengrep_full_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
        }
    )
    chunk = artifacts.put_json(
        {
            "kind": "opengrep_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
            "targets": ["app.py", "good.py"],
        }
    )
    child = artifacts.put_json(
        {
            "kind": "opengrep_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
            "targets": ["app.py"],
        }
    )
    semgrep = artifacts.put_json(
        {
            "kind": "semgrep_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
            "targets": ["app.py"],
            "per_file_timeout_seconds": None,
        }
    )
    timeout_error = artifacts.put_json({"error_code": "EXTERNAL_TOOL_TIMEOUT"})
    parse_error = artifacts.put_json({"error_code": "SEMGREP_PARTIAL_SCAN"})
    executions = (
        StaticScanExecution(
            1,
            "repo",
            "fp",
            "opengrep",
            "batch-1",
            "BLOCKED",
            None,
            "EXTERNAL_TOOL_TIMEOUT",
            full,
            timeout_error,
            120,
        ),
        StaticScanExecution(
            2,
            "repo",
            "fp",
            "opengrep",
            _target_run_key("opengrep", ("app.py", "good.py")),
            "BLOCKED",
            None,
            "EXTERNAL_TOOL_TIMEOUT",
            chunk,
            timeout_error,
            120,
        ),
        StaticScanExecution(
            3,
            "repo",
            "fp",
            "opengrep",
            _target_run_key("opengrep", ("app.py",)),
            "SUCCEEDED",
            None,
            None,
            child,
            None,
            120,
        ),
        StaticScanExecution(
            4,
            "repo",
            "fp",
            "semgrep",
            _target_run_key("semgrep", ("app.py",)),
            "BLOCKED",
            None,
            "SEMGREP_PARTIAL_SCAN",
            semgrep,
            parse_error,
            120,
        ),
    )
    gaps: list[dict[str, object]] = [
        {"path": "app.py", "rule_id": "rule.py", "reason": "parse_or_scan_error"},
        {"path": "good.py", "rule_id": "rule.py", "reason": "scan_timeout"},
    ]

    enriched = enrich_gap_provenance(
        gaps,
        executions,
        artifacts,
        batch_rules={"batch-1": ("rule.py",)},
        expected_pairs=frozenset({("app.py", "rule.py"), ("good.py", "rule.py")}),
        legacy_history_incomplete=False,
    )

    assert [(item["path"], item["attempt_count"]) for item in enriched] == [
        ("app.py", 4),
        ("good.py", 2),
    ]
    assert enriched[0]["known_attempts_by_engine"] == {"opengrep": 3, "semgrep": 1}
    assert enriched[1]["known_attempts_by_engine"] == {"opengrep": 2, "semgrep": 0}
    assert enriched[0]["latest_error_code"] == "SEMGREP_PARTIAL_SCAN"
    assert enriched[0]["latest_error_ref"] == parse_error.model_dump(mode="json")
    assert enriched[1]["latest_error_ref"] == timeout_error.model_dump(mode="json")
    assert all(item["history_complete"] for item in enriched)


@pytest.mark.parametrize(
    ("tool", "legacy", "timeout"),
    [
        ("opengrep", False, None),
        ("semgrep", True, None),
        ("semgrep", True, 30),
        ("semgrep", False, None),
        ("semgrep", False, 30),
    ],
)
def test_gap_provenance_rejects_other_run_valid_target_descriptor(
    tmp_path: Path,
    tool: str,
    legacy: bool,
    timeout: int | None,
) -> None:
    artifacts = _artifacts(tmp_path)
    descriptor: dict[str, object] = {
        "kind": f"{tool}_scan_request_v1",
        "batch_key": "batch-1",
        "rule_ids": ["rule.py"],
        "targets": ["app.py"],
    }
    if tool == "semgrep":
        descriptor["per_file_timeout_seconds"] = timeout
    request_ref = artifacts.put_json(descriptor)
    original_error = artifacts.put_json({"error_code": "ORIGINAL_ERROR"})
    other_error = artifacts.put_json({"error_code": "MISATTRIBUTED_ERROR"})
    executions = (
        StaticScanExecution(
            1,
            "repo",
            "fp",
            tool,
            _target_run_key(tool, ("app.py",), legacy=legacy, timeout=timeout),
            "BLOCKED",
            None,
            "ORIGINAL_ERROR",
            request_ref,
            original_error,
            120,
        ),
        StaticScanExecution(
            2,
            "repo",
            "fp",
            tool,
            _target_run_key(tool, ("good.py",), legacy=legacy, timeout=timeout),
            "BLOCKED",
            None,
            "MISATTRIBUTED_ERROR",
            request_ref,
            other_error,
            120,
        ),
    )
    gaps: list[dict[str, object]] = [
        {"path": "app.py", "rule_id": "rule.py", "reason": "scan_timeout"},
        {"path": "good.py", "rule_id": "rule.py", "reason": "scan_timeout"},
    ]

    enriched = enrich_gap_provenance(
        gaps,
        executions,
        artifacts,
        batch_rules={"batch-1": ("rule.py",)},
        expected_pairs=frozenset({("app.py", "rule.py"), ("good.py", "rule.py")}),
        legacy_history_incomplete=False,
    )

    assert [item["known_attempt_count"] for item in enriched] == [1, 0]
    assert enriched[0]["latest_error_code"] == "ORIGINAL_ERROR"
    assert enriched[0]["latest_error_ref"] == original_error.model_dump(mode="json")
    assert enriched[1]["latest_error_code"] is None
    assert all(item["history_complete"] is False for item in enriched)
    assert all(item["attempt_count"] is None for item in enriched)


def test_gap_provenance_does_not_count_started_execution(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    request_ref = artifacts.put_json(
        {
            "kind": "opengrep_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
            "targets": ["app.py"],
        }
    )
    error_ref = artifacts.put_json({"error_code": "EXTERNAL_TOOL_TIMEOUT"})
    run_key = _target_run_key("opengrep", ("app.py",))
    executions = (
        StaticScanExecution(
            1,
            "repo",
            "fp",
            "opengrep",
            run_key,
            "BLOCKED",
            None,
            "EXTERNAL_TOOL_TIMEOUT",
            request_ref,
            error_ref,
            120,
        ),
        StaticScanExecution(
            2,
            "repo",
            "fp",
            "opengrep",
            run_key,
            "STARTED",
            None,
            None,
            request_ref,
            None,
            120,
        ),
    )

    enriched = enrich_gap_provenance(
        [{"path": "app.py", "rule_id": "rule.py", "reason": "scan_timeout"}],
        executions,
        artifacts,
        batch_rules={"batch-1": ("rule.py",)},
        expected_pairs=frozenset({("app.py", "rule.py")}),
        legacy_history_incomplete=False,
    )

    assert enriched[0]["known_attempt_count"] == 1
    assert enriched[0]["attempt_count"] is None
    assert enriched[0]["history_complete"] is False
    assert enriched[0]["history_status"] == "INTERRUPTED"
    assert enriched[0]["latest_error_code"] == "EXTERNAL_TOOL_TIMEOUT"


def test_started_execution_only_makes_its_target_history_incomplete(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    request_ref = artifacts.put_json(
        {
            "kind": "opengrep_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
            "targets": ["app.py"],
        }
    )
    execution = StaticScanExecution(
        1,
        "repo",
        "fp",
        "opengrep",
        _target_run_key("opengrep", ("app.py",)),
        "STARTED",
        None,
        None,
        request_ref,
        None,
        120,
    )
    gaps: list[dict[str, object]] = [
        {"path": "app.py", "rule_id": "rule.py", "reason": "scan_timeout"},
        {"path": "good.py", "rule_id": "rule.py", "reason": "scan_timeout"},
    ]

    enriched = enrich_gap_provenance(
        gaps,
        (execution,),
        artifacts,
        batch_rules={"batch-1": ("rule.py",)},
        expected_pairs=frozenset({("app.py", "rule.py"), ("good.py", "rule.py")}),
        legacy_history_incomplete=False,
    )

    assert enriched[0]["history_complete"] is False
    assert enriched[0]["history_status"] == "INTERRUPTED"
    assert enriched[0]["attempt_count"] is None
    assert enriched[1]["history_complete"] is True
    assert enriched[1]["history_status"] == "COMPLETE"
    assert enriched[1]["attempt_count"] == 0


def test_gap_provenance_marks_semgrep_descriptor_without_timeout_field_incomplete(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    request_ref = artifacts.put_json(
        {
            "kind": "semgrep_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
            "targets": ["app.py"],
        }
    )
    executions = (
        StaticScanExecution(
            1,
            "repo",
            "fp",
            "semgrep",
            _target_run_key("semgrep", ("app.py",)),
            "BLOCKED",
            None,
            "EXTERNAL_TOOL_TIMEOUT",
            request_ref,
            None,
            120,
        ),
    )

    enriched = enrich_gap_provenance(
        [{"path": "app.py", "rule_id": "rule.py", "reason": "scan_timeout"}],
        executions,
        artifacts,
        batch_rules={"batch-1": ("rule.py",)},
        expected_pairs=frozenset({("app.py", "rule.py")}),
        legacy_history_incomplete=False,
    )

    assert enriched[0]["known_attempt_count"] == 0
    assert enriched[0]["attempt_count"] is None
    assert enriched[0]["history_complete"] is False


def test_gap_provenance_marks_legacy_or_corrupt_descriptors_incomplete(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    full = artifacts.put_json(
        {
            "kind": "opengrep_full_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
        }
    )
    invalid = artifacts.put_json({"kind": "unknown"})
    executions = (
        StaticScanExecution(
            1,
            "repo",
            "fp",
            "opengrep",
            "batch-1",
            "BLOCKED",
            None,
            "EXTERNAL_TOOL_TIMEOUT",
            full,
            None,
            120,
        ),
        StaticScanExecution(
            2,
            "repo",
            "fp",
            "opengrep",
            "bad",
            "BLOCKED",
            None,
            "EXTERNAL_TOOL_TIMEOUT",
            invalid,
            None,
            120,
        ),
    )
    gaps: list[dict[str, object]] = [
        {"path": "app.py", "rule_id": "rule.py", "reason": "scan_timeout"}
    ]

    enriched = enrich_gap_provenance(
        gaps,
        executions,
        artifacts,
        batch_rules={"batch-1": ("rule.py",)},
        expected_pairs=frozenset({("app.py", "rule.py")}),
        legacy_history_incomplete=True,
    )

    assert enriched[0]["known_attempt_count"] == 1
    assert enriched[0]["attempt_count"] is None
    assert enriched[0]["history_complete"] is False


def test_gap_provenance_uses_newest_error_across_fingerprint_order(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    request = artifacts.put_json(
        {
            "kind": "opengrep_full_scan_request_v1",
            "batch_key": "batch-1",
            "rule_ids": ["rule.py"],
        }
    )
    older_error = artifacts.put_json({"error_code": "OLD_ERROR"})
    newer_error = artifacts.put_json({"error_code": "NEW_ERROR"})
    executions = (
        StaticScanExecution(
            2,
            "repo",
            "current",
            "opengrep",
            "batch-1",
            "BLOCKED",
            None,
            "NEW_ERROR",
            request,
            newer_error,
            120,
        ),
        StaticScanExecution(
            1,
            "repo",
            "prior",
            "opengrep",
            "batch-1",
            "BLOCKED",
            None,
            "OLD_ERROR",
            request,
            older_error,
            120,
        ),
    )

    enriched = enrich_gap_provenance(
        [{"path": "app.py", "rule_id": "rule.py", "reason": "scan_timeout"}],
        executions,
        artifacts,
        batch_rules={"batch-1": ("rule.py",)},
        expected_pairs=frozenset({("app.py", "rule.py")}),
        legacy_history_incomplete=False,
    )

    assert enriched[0]["attempt_count"] == 2
    assert enriched[0]["latest_error_code"] == "NEW_ERROR"
    assert enriched[0]["latest_error_ref"] == newer_error.model_dump(mode="json")
