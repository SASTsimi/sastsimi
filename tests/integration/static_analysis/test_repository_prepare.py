"""Workspace PREPARING -> READY/FAILED publication and run-state projection."""

import hashlib
from pathlib import Path
from typing import Any

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import WorkType
from sastsimi.orchestration.static_publication import WorkspacePreparationPublisher
from sastsimi.ports.dto import CandidateError, ProcessReceipt, RepositoryPreparation
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.process import process_command_fingerprint
from sastsimi.static_analysis.repository_loader import (
    canonicalize_repository_source,
    repository_process_specs,
)
from sastsimi.static_analysis.workspace_storage import decode_workspace_storage_policy
from tests.integration.runtime_support import Harness


def prepared(tmp_path: Path, *, store_policy: bool = True) -> tuple[Any, ...]:
    h = Harness(tmp_path)
    execution = h.execution(max_work=10)
    assert execution.approval_ref is not None
    h.evidence.identities[execution.approval_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    scope = h.pin_execution(runtime.budget_registry, execution)
    raw = canonical_bytes(
        {
            "kind": "workspace_storage_policy",
            "schema_version": "1.0",
            "max_git_bytes": 10,
            "max_checkout_bytes": 20,
            "max_file_count": 2,
            "min_free_bytes": 30,
        }
    )
    if store_policy:
        policy_ref = runtime.unit_of_work.artifacts.commit_run(
            runtime.unit_of_work.artifacts.stage_bytes(raw, "application/json"),
            execution.meta.analysis_id,
        )
    else:
        digest = hashlib.sha256(raw).hexdigest()
        policy_ref = RunStoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            analysis_id=AnalysisId(str(execution.meta.analysis_id)),
            record_id=None,
        )
    runner = WorkflowRunner(runtime, h.clock, h.ids)
    work = runner.start(
        scope,
        execution.meta,
        "WORKSPACE_PREP",
        "ANALYSIS",
        "a1",
        execution.approval_ref,
        inputs=(policy_ref,),
    )
    h.evidence.identities[execution.approval_ref] = RequesterRole.REPOSITORY_LOADER
    return h, runtime, runner, work, execution.approval_ref, scope, policy_ref


def test_preparing_and_ready_are_append_only_and_atomically_projected(
    tmp_path: Path,
) -> None:
    """Publishing either pointer alone would expose a contradictory workspace."""
    h, runtime, runner, work, identity, _, _ = prepared(tmp_path)
    publisher = WorkspacePreparationPublisher(runner, identity)
    started = publisher.begin(
        work, "https://example.invalid/team/repo.git", WorkspaceId("workspace")
    )
    assert started.workspace.status == "PREPARING"
    assert started.workspace.meta.revision_number == 1
    assert started.workspace_ref.record_id == started.workspace.meta.record_id
    state = runtime.budget_registry.current_state("a1")
    assert state.workspace_ref == started.workspace_ref
    assert str(state.workspace_id) == "workspace"
    assert state.commit_id is None
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"

    outcome = RepositoryPreparation(
        analysis_id="a1",
        workspace_id="workspace",
        repository_url="https://example.invalid/team/repo.git",
        requested_ref="main",
        status="READY",
        resolved_commit_id="a" * 40,
        root=tmp_path / "lease",
        tracked_files=(),
        gaps=(),
        errors=(),
    )
    finished = publisher.finish(work, started, outcome)
    assert finished.workspace.status == "READY"
    assert (
        finished.workspace.meta.logical_record_id
        == started.workspace.meta.logical_record_id
    )
    assert (
        finished.workspace.meta.previous_record_id == started.workspace.meta.record_id
    )
    assert finished.workspace.meta.revision_number == 2
    assert finished.work.status == "SUCCEEDED"
    assert finished.work.output_refs == (finished.workspace_ref,)
    state = runtime.budget_registry.current_state("a1")
    assert (state.workspace_ref, state.workspace_id, state.commit_id) == (
        finished.workspace_ref,
        finished.workspace.workspace_id,
        finished.workspace.commit_id,
    )
    assert h.records.get_exact(started.workspace_ref) == started.workspace


def test_failed_workspace_finishes_work_without_commit_or_ready(tmp_path: Path) -> None:
    """Turning repository failure into READY would allow static work on unknown code."""
    _, runtime, runner, work, identity, _, _ = prepared(tmp_path)
    publisher = WorkspacePreparationPublisher(runner, identity)
    started = publisher.begin(
        work, "https://example.invalid/repo", WorkspaceId("workspace")
    )
    failed = publisher.finish(
        work,
        started,
        RepositoryPreparation(
            analysis_id="a1",
            workspace_id="workspace",
            repository_url="https://example.invalid/repo",
            requested_ref="main",
            status="FAILED",
            resolved_commit_id=None,
            root=tmp_path / "failed-lease",
            tracked_files=(),
            gaps=(),
            errors=(
                CandidateError("REPOSITORY", "GIT_FAILED", "Git failed safely", True),
            ),
        ),
    )
    assert failed.workspace.status == "FAILED"
    assert failed.work.status == "FAILED"
    assert failed.work.error_ids
    assert runtime.budget_registry.current_state("a1").commit_id is None


def test_direct_ready_revision_one_is_rejected(tmp_path: Path) -> None:
    """Skipping PREPARING would break crash recovery and exact predecessor checks."""
    _, _, runner, work, identity, scope, _ = prepared(tmp_path)
    direct = CodeWorkspace.model_validate_json(
        canonical_bytes(
            {
                "meta": runner.metadata(work.meta, "code_workspace"),
                "workspace_id": "workspace",
                "analysis_id": "a1",
                "repository_url": "https://example.invalid/repo",
                "commit_id": "a" * 40,
                "status": "READY",
            }
        )
    )
    with pytest.raises(ValueError, match="WORKSPACE_LIFECYCLE_INVALID"):
        runner.complete(work, identity, "REPOSITORY_LOADER", (direct,))


class FakeRepositoryLoader:
    process_receipts: tuple[ProcessReceipt, ...] = ()

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = 0

    def verify_git_capability(self, subject_key: str, expected_sha256: str) -> None:
        del subject_key, expected_sha256

    async def prepare(self, **values: Any) -> RepositoryPreparation:
        self.calls += 1
        deadline = values["deadline"]
        attempt_id = str(values["attempt_id"])
        specs = repository_process_specs(
            git_executable=self.root.parent / "git.exe",
            root=self.root,
            output_dir=self.root.parent / "output",
            deadline=deadline,
            attempt_id=attempt_id,
            repository_url=str(values["submitted_source"]),
            requested_ref=str(values["requested_ref"]),
            commit_id="a" * 40,
        )
        self.process_receipts = tuple(
            ProcessReceipt(
                action_id=deadline.action_id,
                invocation_id=spec.invocation_id,
                command_kind=spec.command_kind,
                attempt_id=attempt_id,
                command_fingerprint=process_command_fingerprint(spec),
                outcome="SUCCEEDED",
                return_code=0,
                stdout_name=f"{spec.command_kind}.stdout",
                stdout_size=0,
                stdout_sha256="e" * 64,
                stderr_name=f"{spec.command_kind}.stderr",
                stderr_size=0,
                stderr_sha256="e" * 64,
                elapsed_ms=1,
            )
            for spec in specs
        )
        return RepositoryPreparation(
            analysis_id=values["analysis_id"],
            workspace_id=values["workspace_id"],
            repository_url=values["submitted_source"],
            requested_ref=values["requested_ref"],
            status="READY",
            resolved_commit_id="a" * 40,
            root=self.root,
            tracked_files=(),
            gaps=(),
            errors=(),
            lease_id=self.root.name,
        )


@pytest.mark.asyncio
async def test_external_runner_verifies_exact_policy_before_claim_and_git(
    tmp_path: Path,
) -> None:
    """Missing/substituted quota bytes must cause zero repository invocations."""
    from sastsimi.orchestration.static_external_runner import StaticExternalRunner

    _, runtime, runner, work, identity, scope, policy_ref = prepared(tmp_path)
    loader = FakeRepositoryLoader(tmp_path / "lease")
    service = StaticExternalRunner(
        runner,
        tmp_path / "receipts",
        canonicalize_repository_source,
        decode_workspace_storage_policy,
    )
    completed = await service.prepare_repository(
        work=work,
        budget_scope=scope,
        identity=identity,
        workspace_id=WorkspaceId("workspace"),
        submitted_source="https://example.invalid/team/repo.git",
        requested_ref="main",
        policy_ref=policy_ref,
        timeout_ms=1_000,
        loader=loader,
    )
    assert completed.workspace.status == "READY"
    assert loader.calls == 1

    _, _, missing_runner, missing_work, missing_identity, missing_scope, missing_ref = (
        prepared(tmp_path / "missing", store_policy=False)
    )
    missing_loader = FakeRepositoryLoader(tmp_path / "missing-lease")
    missing_service = StaticExternalRunner(
        missing_runner,
        tmp_path / "missing-receipts",
        canonicalize_repository_source,
        decode_workspace_storage_policy,
    )
    with pytest.raises(ValueError, match="WORKSPACE_STORAGE_POLICY_INVALID"):
        await missing_service.prepare_repository(
            work=missing_work,
            budget_scope=missing_scope,
            identity=missing_identity,
            workspace_id=WorkspaceId("workspace"),
            submitted_source="https://example.invalid/team/repo.git",
            requested_ref="main",
            policy_ref=missing_ref,
            timeout_ms=1_000,
            loader=missing_loader,
        )
    assert missing_loader.calls == 0

    substitute = policy_ref.model_copy(update={"content_hash": "f" * 64})
    with pytest.raises(ValueError, match="WORKSPACE_STORAGE_POLICY_INVALID"):
        await service.prepare_repository(
            work=work,
            budget_scope=scope,
            identity=identity,
            workspace_id=WorkspaceId("workspace-2"),
            submitted_source="https://example.invalid/team/repo.git",
            requested_ref="main",
            policy_ref=substitute,
            timeout_ms=1_000,
            loader=loader,
        )
    assert loader.calls == 1


@pytest.mark.parametrize(
    ("role", "action_type", "work_type"),
    [
        ("STATIC_ANALYSIS", "RUN_TOOL", "WORKSPACE_PREP"),
        ("REPOSITORY_LOADER", "READ_CODE", "WORKSPACE_PREP"),
        ("REPOSITORY_LOADER", "RUN_TOOL", "STATIC_TOOL"),
    ],
)
def test_preparing_workspace_exception_is_exactly_bounded(
    tmp_path: Path, role: str, action_type: str, work_type: str
) -> None:
    """No neighboring role/action/work combination may consume PREPARING code."""
    from sastsimi.storage.current_inputs import (
        READY_WORKSPACE_STATUS,
        allowed_workspace_statuses,
    )

    _, _, runner, work, identity, scope, _ = prepared(tmp_path)
    started = WorkspacePreparationPublisher(runner, identity).begin(
        work, "https://example.invalid/team/repo.git", WorkspaceId("workspace")
    )
    candidate_work = started.work.model_copy(update={"work_type": WorkType(work_type)})
    action = runner.action(
        started.work,
        identity,
        role,
        action_type,
        tool_name="git" if action_type == "RUN_TOOL" else None,
        file_paths=("workspace/workspace",),
    )
    assert allowed_workspace_statuses(action, candidate_work) == READY_WORKSPACE_STATUS
    if candidate_work.work_type == WorkType.WORKSPACE_PREP:
        reservation = runner.reserve(
            started.work,
            scope,
            action,
            runner.units(elapsed_ms=1, cost_minor_units=1),
        )
        with pytest.raises(ValueError, match="ACTION_DENIED"):
            runner.authorize(started.work, action, reservation)


@pytest.mark.asyncio
async def test_workspace_change_before_claim_prevents_git(
    tmp_path: Path,
) -> None:
    """Authorization against PREPARING cannot survive a terminal workspace revision."""
    _, runtime, runner, work, identity, scope, policy_ref = prepared(tmp_path)
    publisher = WorkspacePreparationPublisher(runner, identity)
    started = publisher.begin(
        work, "https://example.invalid/team/repo.git", WorkspaceId("workspace")
    )
    action = runner.action(
        started.work,
        identity,
        "REPOSITORY_LOADER",
        "RUN_TOOL",
        input_refs=(started.workspace_ref, policy_ref),
        tool_name="git",
        file_paths=("workspace/workspace",),
    )
    reservation = runner.reserve(
        started.work,
        scope,
        action,
        runner.units(elapsed_ms=1, cost_minor_units=1),
    )
    decision = runner.authorize(started.work, action, reservation)
    publisher.finish(
        started.work,
        started,
        RepositoryPreparation(
            analysis_id="a1",
            workspace_id="workspace",
            repository_url="https://example.invalid/team/repo.git",
            requested_ref="main",
            status="FAILED",
            resolved_commit_id=None,
            root=tmp_path / "failed-lease",
            tracked_files=(),
            gaps=(),
            errors=(CandidateError("REPOSITORY", "GIT_FAILED", "failed", False),),
        ),
    )
    calls = 0

    async def git_operation() -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(ValueError, match="ATTEMPT_NOT_ACTIVE"):
        await runtime.external.invoke(
            str(started.work.work_id),
            decision,
            runtime.unit_of_work.records.stage_record(reservation),
            git_operation,
        )
    assert calls == 0
