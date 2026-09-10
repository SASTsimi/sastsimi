from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy import select

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, CheckType, RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.static_external_runner import (
    StaticDispatchState,
    StaticExternalRunner,
    _guarded_read,
)
from sastsimi.ports.dto import (
    CandidateGap,
    ProcessReceipt,
    StaticToolObservation,
    StaticToolRequest,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage import models
from sastsimi.storage.codec import REF_ADAPTER
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref
from tests.integration.runtime_support import Harness


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


def _runtime_request(
    tmp_path: Path,
) -> tuple[Harness, WorkflowRunner, StaticToolRequest, StaticToolProfile]:
    h = Harness(tmp_path)
    execution = h.execution(max_work=10)
    assert execution.approval_ref is not None
    identity = execution.approval_ref
    recovery_identity = h.records.stage_record(execution)
    assert isinstance(recovery_identity, (RunStoredDataRef, StoredDataRef))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    h.evidence.identities[recovery_identity] = RequesterRole.RECOVERY
    approved_profiles: set[str] = set()
    trusted = cast(Any, h.evidence)
    trusted.static_tool_configuration_approved = lambda candidate: (
        content_hash(candidate) in approved_profiles
    )
    runtime = build_runtime(
        tmp_path,
        WorkspaceId("w1"),
        CommitId("c1"),
        h.clock,
        h.ids,
        recovery_identity,
        h.evidence,
    )
    execution_ref = h.pin_execution(runtime.budget_registry, execution)
    binding, raw_workspace_ref = h.binding(execution_ref.model_dump(mode="json"))
    workspace_ref = RunStoredDataRef.model_validate_json(json.dumps(raw_workspace_ref))
    scope = h.pin_binding(runtime.budget_registry, binding, workspace_ref)
    workspace = h.records.get_exact(workspace_ref)
    assert isinstance(workspace, CodeWorkspace)
    runner = WorkflowRunner(runtime, h.clock, h.ids)
    original_units = runner.units
    cast(Any, runner).units = lambda **values: original_units(
        **(values | {"cost_minor_units": 1})
    )
    profile = StaticToolProfile.model_validate_json(
        canonical_bytes(
            {
                "meta": runner.metadata(binding.meta, "static_tool_profile"),
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
    approved_profiles.add(content_hash(profile))
    profile_ref = runtime.configuration.register_static_tool_profile(profile)
    original_action_evidence = h.evidence.action_evidence
    trusted.action_evidence = lambda candidate, check: (
        (profile_ref,)
        if check == CheckType.TOOL
        else original_action_evidence(candidate, check)
    )
    analysis_config_ref = profile_ref
    work = runner.start(
        scope,
        binding.meta,
        "STATIC_TOOL",
        "ANALYSIS",
        "a1",
        identity,
        inputs=(profile_ref,),
    )
    h.evidence.identities[identity] = RequesterRole.STATIC_ANALYSIS
    action = runner.action(
        work,
        identity,
        "STATIC_ANALYSIS",
        "RUN_TOOL",
        tool_name="AST",
        file_paths=("src/app.py",),
    )
    return (
        h,
        runner,
        StaticToolRequest(
            action,
            workspace,
            profile_ref,
            analysis_config_ref,
            None,
        ),
        profile,
    )


def _dispatch_reader(runner: WorkflowRunner) -> Any:
    def read(action_id: str) -> StaticDispatchState | None:
        records = cast(Any, runner.runtime.unit_of_work.records)
        with records.database.engine.connect() as connection:
            row = (
                connection.execute(
                    select(models.external_dispatches).where(
                        models.external_dispatches.c.action_id == action_id
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            return None
        state = (
            "RETURNED"
            if row["returned_at"] is not None
            else "DISPATCHED"
            if row["dispatched_at"] is not None
            else "PREPARED"
        )
        return StaticDispatchState(
            action_id=row["action_id"],
            work_id=row["work_id"],
            attempt_id=row["attempt_id"],
            decision_ref=REF_ADAPTER.validate_json(row["decision_ref"]),
            reservation_ref=REF_ADAPTER.validate_json(row["reservation_ref"]),
            state=cast(Any, state),
            idempotency_key=row["idempotency_key"],
        )

    return read


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


class _Crash(BaseException):
    pass


@pytest.mark.asyncio
async def test_complete_static_receipt_recovers_without_rerunning_tool(
    tmp_path: Path,
) -> None:
    _, runner, request, profile = _runtime_request(tmp_path)
    assert isinstance(request.action.meta, RecordMeta)
    assert request.action.meta.attempt_id is not None
    calls = 0

    async def operation(_deadline: object) -> StaticToolObservation:
        nonlocal calls
        calls += 1
        return _observation()

    def checkpoint(stage: str) -> None:
        if stage == "STATIC_RECEIPT_DURABLE":
            raise _Crash

    process = _process(
        str(request.action.action_id), str(request.action.meta.attempt_id), 0
    )
    service = StaticExternalRunner(
        runner,
        tmp_path / "static-receipts",
        cast(Any, None),
        cast(Any, None),
        checkpoint=checkpoint,
        static_process_receipts=lambda _action, _attempt: (process,),
        static_dispatch_state=_dispatch_reader(runner),
    )
    with pytest.raises(_Crash):
        await service.invoke(request, profile, operation)

    recovered = await service.recover_tool(request, profile)

    assert calls == 1
    assert recovered.status == "SUCCEEDED"
    assert request.action.work_ref is not None
    work = runner.runtime.unit_of_work.records.get_exact(request.action.work_ref)
    assert isinstance(work, WorkExecutionState)
    assert runner.runtime.work.get(str(work.work_id)).status == "SUCCEEDED"


@pytest.mark.asyncio
async def test_prepared_static_dispatch_resumes_exact_attempt_without_prior_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, runner, request, profile = _runtime_request(tmp_path)
    assert isinstance(request.action.meta, RecordMeta)
    assert request.action.meta.attempt_id is not None
    calls = 0
    process = _process(
        str(request.action.action_id), str(request.action.meta.attempt_id), 0
    )

    async def operation(_deadline: object) -> StaticToolObservation:
        nonlocal calls
        calls += 1
        return _observation()

    authorization = runner.runtime.external.authorization
    original = authorization.mark_dispatched

    def crash_before_dispatch(*_values: object, **_named: object) -> None:
        raise _Crash

    monkeypatch.setattr(authorization, "mark_dispatched", crash_before_dispatch)
    service = StaticExternalRunner(
        runner,
        tmp_path / "static-receipts",
        cast(Any, None),
        cast(Any, None),
        static_process_receipts=lambda _action, _attempt: (
            () if calls == 0 else (process,)
        ),
        static_dispatch_state=_dispatch_reader(runner),
    )
    with pytest.raises(_Crash):
        await service.invoke(request, profile, operation)
    assert calls == 0

    monkeypatch.setattr(authorization, "mark_dispatched", original)
    recovered = await service.recover_tool(request, profile, operation)

    assert recovered.status == "SUCCEEDED"
    assert calls == 1


@pytest.mark.asyncio
async def test_missing_then_late_static_receipt_blocks_and_is_quarantined(
    tmp_path: Path,
) -> None:
    _, runner, request, profile = _runtime_request(tmp_path)
    assert isinstance(request.action.meta, RecordMeta)
    assert request.action.meta.attempt_id is not None
    calls = 0

    async def crash_before_receipt(_deadline: object) -> StaticToolObservation:
        nonlocal calls
        calls += 1
        raise _Crash

    service = StaticExternalRunner(
        runner,
        tmp_path / "static-receipts",
        cast(Any, None),
        cast(Any, None),
        static_process_receipts=lambda _action, _attempt: (),
        static_dispatch_state=_dispatch_reader(runner),
    )
    with pytest.raises(_Crash):
        await service.invoke(request, profile, crash_before_receipt)
    with pytest.raises(ValueError, match="STATIC_TOOL_RECOVERY_AMBIGUOUS"):
        await service.recover_tool(request, profile)

    assert request.action.work_ref is not None
    work = runner.runtime.unit_of_work.records.get_exact(request.action.work_ref)
    assert isinstance(work, WorkExecutionState)
    assert runner.runtime.work.get(str(work.work_id)).status == "BLOCKED"
    service._write_tool_receipt(
        request,
        StoredDataRef.model_validate(ref("action_decision")),
        _observation(),
        1,
        profile.max_attempt_output_bytes,
        (
            _process(
                str(request.action.action_id),
                str(request.action.meta.attempt_id),
                0,
            ),
        ),
    )
    with pytest.raises(ValueError, match="STATIC_TOOL_RECOVERY_INVALID"):
        await service.recover_tool(request, profile)
    assert not service._tool_receipt_path(str(request.action.action_id)).exists()
    assert (service.receipt_root / "quarantine").is_dir()
    assert calls == 1


def test_partial_cancellation_preserves_complete_bounded_observation(
    tmp_path: Path,
) -> None:
    request, profile = _request()
    partial = replace(
        _observation(),
        status="PARTIAL",
        gaps=(
            CandidateGap(
                "STATIC_ANALYSIS",
                "STATIC_COVERAGE_MISSING",
                "MISSING",
                "A bounded tool partition remains incomplete.",
                (),
                (),
                (),
                True,
            ),
        ),
    )

    cancelled = _service(tmp_path)._cancelled_observation(request, profile, 5, partial)

    assert cancelled.status == "PARTIAL"
    assert cancelled.raw_output == partial.raw_output
    assert tuple(gap.code for gap in cancelled.gaps) == (
        "STATIC_COVERAGE_MISSING",
        "STATIC_TOOL_CANCELLED",
    )
