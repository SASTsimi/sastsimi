"""Crash recovery for append-only repository workspace publication."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import WorkspaceId
from sastsimi.orchestration.static_external_runner import StaticExternalRunner
from sastsimi.orchestration.static_publication import WorkspacePreparationPublisher
from sastsimi.ports.dto import (
    CandidateError,
    MonotonicActionDeadline,
    ProcessReceipt,
    RepositoryPreparation,
)
from sastsimi.static_analysis.process import process_command_fingerprint
from sastsimi.static_analysis.repository_loader import (
    canonicalize_repository_source,
    repository_process_specs,
)
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
        self.process_receipts: tuple[ProcessReceipt, ...] = ()

    async def prepare(self, **values: Any) -> RepositoryPreparation:
        self.calls += 1
        deadline = cast(MonotonicActionDeadline, values["deadline"])
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


class AcceptingRecoveryValidator:
    def __init__(self) -> None:
        self.calls = 0

    async def validate(
        self,
        outcome: RepositoryPreparation,
        *,
        action_id: str,
        attempt_id: str,
        process_receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        assert outcome.status == "READY"
        assert action_id
        assert attempt_id
        del process_receipts
        self.calls += 1


class ExactCommitRecoveryValidator(AcceptingRecoveryValidator):
    def __init__(self, expected_commit: str) -> None:
        super().__init__()
        self.expected_commit = expected_commit

    async def validate(
        self,
        outcome: RepositoryPreparation,
        *,
        action_id: str,
        attempt_id: str,
        process_receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        await super().validate(
            outcome,
            action_id=action_id,
            attempt_id=attempt_id,
            process_receipts=process_receipts,
        )
        if outcome.resolved_commit_id != self.expected_commit:
            raise ValueError("WORKSPACE_CHANGED")


async def durable_repository_crash(tmp_path: Path) -> tuple[Any, ...]:
    _, runtime, runner, work, identity, scope, policy_ref = prepared(tmp_path)
    lease_root = tmp_path / "resolved-root"
    lease_root.mkdir()
    loader = RecoverableLoader(lease_root)

    def crash(stage: str) -> None:
        if stage == "RECEIPT_DURABLE":
            raise SimulatedCrash(stage)

    with pytest.raises(SimulatedCrash):
        await StaticExternalRunner(
            runner,
            tmp_path / "receipts",
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            checkpoint=crash,
        ).prepare_repository(
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
    return runtime, runner, work, identity, policy_ref, lease_root


def rewrite_observation(receipt_root: Path, payload: dict[str, Any]) -> None:
    receipt_path = next(receipt_root.glob("*.receipt.json"))
    receipt = json.loads(receipt_path.read_bytes())
    raw = canonical_bytes(payload)
    (receipt_root / receipt["observation_name"]).write_bytes(raw)
    receipt["observation_size"] = len(raw)
    receipt["observation_sha256"] = hashlib.sha256(raw).hexdigest()
    receipt_path.write_bytes(canonical_bytes(receipt))


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
    assert len(receipt_document["process_receipt_hashes"]) == 5
    for digest in receipt_document["process_receipt_hashes"]:
        assert (tmp_path / "receipts" / f"{digest}.process.json").is_file()

    recovered = await StaticExternalRunner(
        runner,
        tmp_path / "receipts",
        canonicalize_repository_source,
        decode_workspace_storage_policy,
        lease_root_resolver=lambda lease_id: (
            lease_root if lease_id == "lease-id" else tmp_path / "unexpected"
        ),
        recovery_validator=AcceptingRecoveryValidator(),
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
            recovery_validator=AcceptingRecoveryValidator(),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"


@pytest.mark.asyncio
async def test_ready_repository_recovery_requires_trusted_workspace_guard(
    tmp_path: Path,
) -> None:
    _, runtime, runner, work, identity, scope, policy_ref = prepared(tmp_path)
    lease_root = tmp_path / "resolved-root"
    lease_root.mkdir()
    loader = RecoverableLoader(lease_root)

    def crash(stage: str) -> None:
        if stage == "RECEIPT_DURABLE":
            raise SimulatedCrash(stage)

    with pytest.raises(SimulatedCrash):
        await StaticExternalRunner(
            runner,
            tmp_path / "receipts",
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            checkpoint=crash,
        ).prepare_repository(
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

    with pytest.raises(ValueError, match="REPOSITORY_RECOVERY_GUARD_REQUIRED"):
        await StaticExternalRunner(
            runner,
            tmp_path / "receipts",
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda _lease_id: lease_root,
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )


@pytest.mark.asyncio
async def test_recovery_rejects_missing_or_mismatched_process_receipt(
    tmp_path: Path,
) -> None:
    (
        runtime,
        runner,
        work,
        identity,
        policy_ref,
        lease_root,
    ) = await durable_repository_crash(tmp_path)
    receipt_root = tmp_path / "receipts"
    receipt_path = next(receipt_root.glob("*.receipt.json"))
    receipt = json.loads(receipt_path.read_bytes())
    process_path = receipt_root / (
        receipt["process_receipt_hashes"][0] + ".process.json"
    )
    process_path.unlink()

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        await StaticExternalRunner(
            runner,
            receipt_root,
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda _lease_id: lease_root,
            recovery_validator=AcceptingRecoveryValidator(),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"


@pytest.mark.asyncio
async def test_recovery_rejects_hardlinked_observation(tmp_path: Path) -> None:
    (
        runtime,
        runner,
        work,
        identity,
        policy_ref,
        lease_root,
    ) = await durable_repository_crash(tmp_path)
    receipt_root = tmp_path / "receipts"
    receipt = json.loads(next(receipt_root.glob("*.receipt.json")).read_bytes())
    observation = receipt_root / receipt["observation_name"]
    backing = receipt_root / "observation-backing"
    observation.replace(backing)
    os.link(backing, observation)

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        await StaticExternalRunner(
            runner,
            receipt_root,
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda _lease_id: lease_root,
            recovery_validator=AcceptingRecoveryValidator(),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"


@pytest.mark.asyncio
async def test_recovery_rejects_self_consistent_oversized_observation(
    tmp_path: Path,
) -> None:
    (
        runtime,
        runner,
        work,
        identity,
        policy_ref,
        lease_root,
    ) = await durable_repository_crash(tmp_path)
    receipt_root = tmp_path / "receipts"
    receipt = json.loads(next(receipt_root.glob("*.receipt.json")).read_bytes())
    observation_path = receipt_root / receipt["observation_name"]
    payload = json.loads(observation_path.read_bytes())
    payload["requested_ref"] = "x" * (4 * 1024 * 1024)
    rewrite_observation(receipt_root, payload)

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        await StaticExternalRunner(
            runner,
            receipt_root,
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda _lease_id: lease_root,
            recovery_validator=AcceptingRecoveryValidator(),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"


@pytest.mark.asyncio
async def test_recovery_rejects_forged_self_consistent_observation(
    tmp_path: Path,
) -> None:
    (
        runtime,
        runner,
        work,
        identity,
        policy_ref,
        lease_root,
    ) = await durable_repository_crash(tmp_path)
    receipt_root = tmp_path / "receipts"
    receipt = json.loads(next(receipt_root.glob("*.receipt.json")).read_bytes())
    observation_path = receipt_root / receipt["observation_name"]
    payload = json.loads(observation_path.read_bytes())
    payload["resolved_commit_id"] = "b" * 40
    rewrite_observation(receipt_root, payload)

    with pytest.raises(ValueError, match="WORKSPACE_CHANGED"):
        await StaticExternalRunner(
            runner,
            receipt_root,
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda _lease_id: lease_root,
            recovery_validator=ExactCommitRecoveryValidator("a" * 40),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"


@pytest.mark.asyncio
async def test_recovery_rejects_self_consistent_wrong_process_binding(
    tmp_path: Path,
) -> None:
    (
        runtime,
        runner,
        work,
        identity,
        policy_ref,
        lease_root,
    ) = await durable_repository_crash(tmp_path)
    receipt_root = tmp_path / "receipts"
    receipt_path = next(receipt_root.glob("*.receipt.json"))
    receipt = json.loads(receipt_path.read_bytes())
    old_digest = receipt["process_receipt_hashes"][0]
    process = json.loads((receipt_root / f"{old_digest}.process.json").read_bytes())
    process["action_id"] = "forged-action"
    process_raw = canonical_bytes(process)
    new_digest = hashlib.sha256(process_raw).hexdigest()
    (receipt_root / f"{new_digest}.process.json").write_bytes(process_raw)
    receipt["process_receipt_hashes"][0] = new_digest
    receipt_path.write_bytes(canonical_bytes(receipt))

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        await StaticExternalRunner(
            runner,
            receipt_root,
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda _lease_id: lease_root,
            recovery_validator=AcceptingRecoveryValidator(),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"


@pytest.mark.asyncio
async def test_recovery_rejects_observation_identity_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        runtime,
        runner,
        work,
        identity,
        policy_ref,
        lease_root,
    ) = await durable_repository_crash(tmp_path)
    receipt_root = tmp_path / "receipts"
    receipt = json.loads(next(receipt_root.glob("*.receipt.json")).read_bytes())
    observation = receipt_root / receipt["observation_name"]
    replacement = receipt_root / "replacement.repository.json"
    replacement.write_bytes(observation.read_bytes())
    original_lstat = Path.lstat
    observation_lstats = 0

    def swapped_lstat(path: Path) -> os.stat_result:
        nonlocal observation_lstats
        if path == observation:
            observation_lstats += 1
            if observation_lstats >= 2:
                return original_lstat(replacement)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", swapped_lstat)
    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        await StaticExternalRunner(
            runner,
            receipt_root,
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda _lease_id: lease_root,
            recovery_validator=AcceptingRecoveryValidator(),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
    assert runtime.work.get(str(work.work_id)).status == "RUNNING"


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="file symlink creation needs privilege")
async def test_recovery_rejects_symlinked_observation(tmp_path: Path) -> None:
    (
        runtime,
        runner,
        work,
        identity,
        policy_ref,
        lease_root,
    ) = await durable_repository_crash(tmp_path)
    receipt_root = tmp_path / "receipts"
    receipt = json.loads(next(receipt_root.glob("*.receipt.json")).read_bytes())
    observation = receipt_root / receipt["observation_name"]
    backing = receipt_root / "observation-backing"
    observation.replace(backing)
    observation.symlink_to(backing)

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        await StaticExternalRunner(
            runner,
            receipt_root,
            canonicalize_repository_source,
            decode_workspace_storage_policy,
            lease_root_resolver=lambda _lease_id: lease_root,
            recovery_validator=AcceptingRecoveryValidator(),
        ).recover_repository(
            work=runtime.work.get(str(work.work_id)),
            identity=identity,
            policy_ref=policy_ref,
        )
