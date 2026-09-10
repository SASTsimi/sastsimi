"""Crash recovery for append-only repository workspace publication."""

import json
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.ids import WorkspaceId
from sastsimi.orchestration.static_external_runner import StaticExternalRunner
from sastsimi.orchestration.static_publication import WorkspacePreparationPublisher
from sastsimi.ports.dto import CandidateError, ProcessReceipt, RepositoryPreparation
from sastsimi.static_analysis.repository_loader import canonicalize_repository_source
from sastsimi.static_analysis.workspace_storage import decode_workspace_storage_policy
from sastsimi.storage.intermediate_publication import IntermediatePublicationService
from tests.integration.static_analysis.test_repository_prepare import prepared


class SimulatedCrash(BaseException):
    pass


class RecoverableLoader:
    def __init__(
        self, root: Path, *, failed: bool = False, lease_id: str = "lease-id"
    ) -> None:
        self.root = root
        self.failed = failed
        self.lease_id = lease_id
        self.calls = 0
        self.process_receipts: tuple[ProcessReceipt, ...] = (
            ProcessReceipt(
                invocation_id="clone",
                attempt_id="attempt-1",
                command_fingerprint="f" * 64,
                outcome="SUCCEEDED",
                return_code=0,
                stdout_name="clone.stdout",
                stdout_size=0,
                stdout_sha256="e" * 64,
                stderr_name="clone.stderr",
                stderr_size=0,
                stderr_sha256="e" * 64,
                elapsed_ms=1,
            ),
        )

    async def prepare(self, **values: Any) -> RepositoryPreparation:
        self.calls += 1
        return RepositoryPreparation(
            analysis_id=values["analysis_id"],
            workspace_id=values["workspace_id"],
            repository_url=values["submitted_source"],
            requested_ref=values["requested_ref"],
            status="FAILED" if self.failed else "READY",
            resolved_commit_id=None if self.failed else "a" * 40,
            root=None if self.failed else self.root,
            tracked_files=(),
            gaps=(),
            errors=(
                (CandidateError("REPOSITORY", "GIT_FAILED", "failed", True),)
                if self.failed
                else ()
            ),
            lease_id=None if self.failed else self.lease_id,
        )


def test_preparing_publication_crash_is_atomic_and_retryable(tmp_path: Path) -> None:
    _, runtime, runner, work, identity, _, _ = prepared(tmp_path)
    publisher = WorkspacePreparationPublisher(runner, identity)
    store = cast(IntermediatePublicationService, runtime.intermediate.store)

    def crash(stage: str) -> None:
        if stage == "before_commit":
            raise SimulatedCrash(stage)

    store.checkpoint = crash
    with pytest.raises(SimulatedCrash):
        publisher.begin(
            work,
            "https://example.invalid/team/repo.git",
            WorkspaceId("workspace"),
        )
    assert runtime.budget_registry.current_state("a1").workspace_ref is None
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"

    store.checkpoint = lambda _stage: None
    replayed = publisher.begin(
        runtime.work.get(str(work.work_id)),
        "https://example.invalid/team/repo.git",
        WorkspaceId("workspace"),
    )
    assert replayed.workspace.status == "PREPARING"
    assert (
        runtime.budget_registry.current_state("a1").workspace_ref
        == replayed.workspace_ref
    )


def test_terminal_prepared_journal_replay_converges_workspace_and_run_state(
    tmp_path: Path,
) -> None:
    _, runtime, runner, work, identity, _, _ = prepared(tmp_path)
    publisher = WorkspacePreparationPublisher(runner, identity)
    started = publisher.begin(
        work, "https://example.invalid/team/repo.git", WorkspaceId("workspace")
    )
    store = cast(IntermediatePublicationService, runtime.intermediate.store)

    def crash(stage: str) -> None:
        if stage == "PREPARED":
            raise SimulatedCrash(stage)

    store.transitions.checkpoint = crash
    with pytest.raises(SimulatedCrash):
        publisher.finish(
            started.work,
            started,
            RepositoryPreparation(
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
            ),
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"

    store.transitions.checkpoint = lambda _stage: None
    store.transitions.recover_prepared()
    recovered = runtime.work.get(str(work.work_id))
    state = runtime.budget_registry.current_state("a1")
    assert recovered.status == "SUCCEEDED"
    assert recovered.output_refs == (state.workspace_ref,)
    assert str(state.commit_id) == "a" * 40


@pytest.mark.asyncio
@pytest.mark.parametrize("crash_stage", ("RECEIPT_DURABLE", "RETURNED", "ACCOUNTED"))
async def test_repository_receipt_recovers_each_return_account_publish_window(
    tmp_path: Path,
    crash_stage: str,
) -> None:
    _, runtime, runner, work, identity, scope, policy_ref = prepared(tmp_path)
    lease_root = tmp_path / "resolved-root"
    lease_root.mkdir()
    loader = RecoverableLoader(lease_root)

    def crash(stage: str) -> None:
        if stage == crash_stage:
            raise SimulatedCrash(stage)

    service = StaticExternalRunner(
        runner,
        tmp_path / "receipts",
        canonicalize_repository_source,
        decode_workspace_storage_policy,
        checkpoint=crash,
        lease_root_resolver=lambda lease_id: (
            lease_root if lease_id == "lease-id" else tmp_path / "unexpected"
        ),
    )
    with pytest.raises(SimulatedCrash, match=crash_stage):
        await service.prepare_repository(
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

    current = runtime.work.get(str(work.work_id))
    assert current.status == "RUNNING"
    state = runtime.budget_registry.current_state("a1")
    assert state.workspace_ref is not None
    assert loader.calls == 1
    receipt_document = json.loads(
        next((tmp_path / "receipts").glob("*.receipt.json")).read_bytes()
    )
    assert "root" not in receipt_document
    assert receipt_document["lease_id"] == "lease-id"
    assert len(receipt_document["process_receipt_hashes"]) == 1

    recovered = await StaticExternalRunner(
        runner,
        tmp_path / "receipts",
        canonicalize_repository_source,
        decode_workspace_storage_policy,
        lease_root_resolver=lambda lease_id: (
            lease_root if lease_id == "lease-id" else tmp_path / "unexpected"
        ),
    ).recover_repository(
        work=current,
        identity=identity,
        policy_ref=policy_ref,
    )

    assert recovered.workspace.status == "READY"
    assert recovered.work.status == "SUCCEEDED"
    assert loader.calls == 1


@pytest.mark.asyncio
async def test_allocation_failure_is_accounted_receipted_and_terminal_failed(
    tmp_path: Path,
) -> None:
    _, _, runner, work, identity, scope, policy_ref = prepared(tmp_path)
    loader = RecoverableLoader(tmp_path / "unused", failed=True)
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

    assert completed.workspace.status == "FAILED"
    assert completed.work.status == "FAILED"
    assert tuple((tmp_path / "receipts").glob("*.receipt.json"))


@pytest.mark.asyncio
async def test_repository_recovery_rejects_tampered_observation(
    tmp_path: Path,
) -> None:
    _, runtime, runner, work, identity, scope, policy_ref = prepared(tmp_path)
    lease_root = tmp_path / "resolved-root"
    lease_root.mkdir()
    loader = RecoverableLoader(lease_root)

    def crash(stage: str) -> None:
        if stage == "RECEIPT_DURABLE":
            raise SimulatedCrash(stage)

    service = StaticExternalRunner(
        runner,
        tmp_path / "receipts",
        canonicalize_repository_source,
        decode_workspace_storage_policy,
        checkpoint=crash,
        lease_root_resolver=lambda lease_id: (
            lease_root if lease_id == "lease-id" else tmp_path / "unexpected"
        ),
    )
    with pytest.raises(SimulatedCrash):
        await service.prepare_repository(
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

    observation = next((tmp_path / "receipts").glob("*.repository.json"))
    observation.write_bytes(observation.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        await StaticExternalRunner(
            runner,
            tmp_path / "receipts",
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda lease_id: (
                lease_root if lease_id == "lease-id" else tmp_path / "unexpected"
            ),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"
