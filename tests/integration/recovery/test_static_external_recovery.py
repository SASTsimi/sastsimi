from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.orchestration.static_external_runner import (
    StaticExternalRunner,
    _guarded_read,
)
from sastsimi.ports.dto import (
    ProcessReceipt,
    StaticToolObservation,
    StaticToolRequest,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref


def _request() -> tuple[StaticToolRequest, StaticToolProfile]:
    action = ActionRequest.model_validate_json(
        canonical_bytes(
            make("ActionRequest", "action_request")
            | {
                "action_id": "ast-action",
                "requested_by": "STATIC_ANALYSIS",
                "action_type": "RUN_TOOL",
                "work_ref": ref("work_execution_state"),
                "expected_state_version": 1,
                "tool_name": "AST",
                "file_paths": ("src/app.py",),
            }
        )
    )
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            make("CodeWorkspace")
            | {
                "repository_url": "https://example.invalid/repository.git",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    profile = StaticToolProfile.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("static_tool_profile", attempt=None),
                "profile_key": "ast-fixture",
                "purpose": "FIXTURE",
                "status": "APPROVED",
                "adapter_key": "PYTHON_AST",
                "tool_name": "AST",
                "tool_kind": "STRUCTURE",
                "executable_key": "python",
                "executable_sha256": "a" * 64,
                "expected_version": "3.12",
                "capability_evidence_ref": None,
                "probe_timeout_ms": 100,
                "run_timeout_ms": 200,
                "stdout_limit_bytes": 1024,
                "stderr_limit_bytes": 1024,
                "max_attempt_output_bytes": 4096,
                "max_output_file_bytes": 2048,
                "max_artifact_read_bytes": 2048,
            }
        )
    )
    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    return (
        StaticToolRequest(
            action=action,
            workspace=workspace,
            tool_profile_ref=profile_ref,
            analysis_config_ref=StoredDataRef.model_validate(
                ref("analysis_configuration")
            ),
            rule_catalog_ref=None,
        ),
        profile,
    )


def _service(root: Path) -> StaticExternalRunner:
    runner = cast(WorkflowRunner, SimpleNamespace())
    return StaticExternalRunner(
        runner,
        root,
        cast(Any, None),
        cast(Any, None),
        static_publisher=cast(Any, SimpleNamespace(rule_catalogs={})),
    )


def _process(action_id: str, attempt_id: str, sequence: int) -> ProcessReceipt:
    return ProcessReceipt(
        action_id=action_id,
        invocation_id=f"{action_id}:ast:{sequence}",
        command_kind=f"ast-{sequence}",
        attempt_id=attempt_id,
        command_fingerprint=f"{sequence + 1:x}" * 64,
        outcome="SUCCEEDED",
        return_code=0,
        stdout_name=f"{sequence}.stdout",
        stdout_size=2,
        stdout_sha256="b" * 64,
        stderr_name=f"{sequence}.stderr",
        stderr_size=0,
        stderr_sha256="c" * 64,
        elapsed_ms=1,
    )


def _observation() -> StaticToolObservation:
    return StaticToolObservation(
        tool_name="AST",
        tool_version="3.12",
        tool_kind="STRUCTURE",
        status="SUCCEEDED",
        raw_output=b"{}",
        raw_media_type="application/json",
        analyzed_paths=("src/app.py",),
        skipped_paths=(),
        analyzed_languages=("python",),
        skipped_languages=(),
        notes=(),
        selected_rule_packs=(),
        rules=(),
        symbols=(),
        facts=(),
        relations=(),
        gaps=(),
        errors=(),
        started_monotonic_ms=1,
        finished_monotonic_ms=2,
    )


def test_static_recovery_read_is_bounded(tmp_path: Path) -> None:
    candidate = tmp_path / "observation.json"
    candidate.write_bytes(b"12345")

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        _guarded_read(candidate, 4)


def test_static_recovery_never_follows_observation_link(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_bytes(b"{}")
    linked = tmp_path / "observation.json"
    try:
        linked.symlink_to(real)
    except OSError:
        pytest.skip("symlinks are unavailable on this host")

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        _guarded_read(linked, 64)


def test_static_receipt_round_trip_binds_ordered_process_receipts(
    tmp_path: Path,
) -> None:
    request, profile = _request()
    assert isinstance(request.action.meta, RecordMeta)
    assert request.action.meta.attempt_id is not None
    decision_ref = StoredDataRef.model_validate(ref("action_decision"))
    receipts = tuple(
        _process(
            str(request.action.action_id), str(request.action.meta.attempt_id), index
        )
        for index in range(2)
    )
    service = _service(tmp_path / "receipts")
    service._write_tool_receipt(
        request,
        decision_ref,
        _observation(),
        1,
        profile.max_attempt_output_bytes,
        receipts,
    )

    aggregate, recovered, recovered_receipts = service._read_tool_receipt(
        request, decision_ref, profile
    )

    assert recovered == _observation()
    assert recovered_receipts == receipts
    assert aggregate.process_receipt_hashes == tuple(
        hashlib.sha256(canonical_bytes(asdict(item))).hexdigest() for item in receipts
    )


def test_static_recovery_rejects_forged_process_receipt_hash(
    tmp_path: Path,
) -> None:
    request, profile = _request()
    assert isinstance(request.action.meta, RecordMeta)
    assert request.action.meta.attempt_id is not None
    decision_ref = StoredDataRef.model_validate(ref("action_decision"))
    service = _service(tmp_path / "receipts")
    service._write_tool_receipt(
        request,
        decision_ref,
        _observation(),
        1,
        profile.max_attempt_output_bytes,
        (
            _process(
                str(request.action.action_id), str(request.action.meta.attempt_id), 0
            ),
        ),
    )
    target = service._tool_receipt_path(str(request.action.action_id))
    payload = json.loads(target.read_bytes())
    payload["process_receipt_hashes"] = ["f" * 64]
    target.write_bytes(canonical_bytes(payload))

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        service._read_tool_receipt(request, decision_ref, profile)
