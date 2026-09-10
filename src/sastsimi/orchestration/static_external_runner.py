"""Authorized application boundary for exact repository preparation."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import WorkspaceId
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, RunStoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import (
    CanonicalRepositorySource,
    MonotonicActionDeadline,
    ProcessReceipt,
    PublishedWorkspaceMaterial,
    RepositoryPreparation,
    StaticActionReceipt,
    WorkspaceStoragePolicy,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .static_publication import WorkspacePreparationPublisher

type RepositorySourceCanonicalizer = Callable[[str], CanonicalRepositorySource]
type WorkspacePolicyDecoder = Callable[
    [RunStoredDataRef, bytes, str], WorkspaceStoragePolicy
]


class RepositoryLoaderPort(Protocol):
    process_receipts: tuple[ProcessReceipt, ...]

    def prepare(
        self,
        *,
        submitted_source: str,
        requested_ref: str,
        analysis_id: str,
        workspace_id: str,
        attempt_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
        deadline: MonotonicActionDeadline,
    ) -> Awaitable[RepositoryPreparation]: ...


class StaticExternalRunner:
    """Verify config, reserve, claim, dispatch, account, then publish."""

    def __init__(
        self,
        runner: WorkflowRunner,
        receipt_root: Path,
        canonicalize_source: RepositorySourceCanonicalizer,
        decode_policy: WorkspacePolicyDecoder,
        *,
        monotonic_ns: object = time.monotonic_ns,
    ) -> None:
        self.runner = runner
        self.receipt_root = receipt_root
        self.canonicalize_source = canonicalize_source
        self.decode_policy = decode_policy
        self.monotonic_ns = monotonic_ns

    def _verified_policy(
        self, work: WorkExecutionState, policy_ref: RunStoredDataRef
    ) -> WorkspaceStoragePolicy:
        run_artifacts = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, RunStoredDataRef)
            and ref.record_id is None
            and ref.data_kind == "artifact"
        )
        if run_artifacts != (policy_ref,):
            raise ValueError("WORKSPACE_STORAGE_POLICY_INVALID")
        try:
            with self.runner.runtime.unit_of_work.artifacts.open_verified(
                policy_ref
            ) as stream:
                raw = stream.read()
        except (OSError, ValueError) as error:
            raise ValueError("WORKSPACE_STORAGE_POLICY_INVALID") from error
        return self.decode_policy(policy_ref, raw, str(work.meta.analysis_id))

    async def prepare_repository(
        self,
        *,
        work: WorkExecutionState,
        budget_scope: BudgetScopeRef,
        identity: BudgetScopeRef,
        workspace_id: WorkspaceId,
        submitted_source: str,
        requested_ref: str,
        policy_ref: RunStoredDataRef,
        timeout_ms: int,
        loader: RepositoryLoaderPort,
    ) -> PublishedWorkspaceMaterial:
        source = self.canonicalize_source(submitted_source)
        policy = self._verified_policy(work, policy_ref)
        if timeout_ms <= 0:
            raise ValueError("WORKSPACE_TIMEOUT_INVALID")
        publisher = WorkspacePreparationPublisher(self.runner, identity)
        preparing = publisher.begin(work, source.url, workspace_id)
        current = preparing.work
        action = self.runner.action(
            current,
            identity,
            "REPOSITORY_LOADER",
            "RUN_TOOL",
            input_refs=(preparing.workspace_ref, policy_ref),
            tool_name="git",
            file_paths=(f"workspace/{workspace_id}",),
            reason="Prepare the exact authorized repository revision",
        )
        reservation = self.runner.reserve(
            current,
            budget_scope,
            action,
            self.runner.units(elapsed_ms=timeout_ms, cost_minor_units=1),
        )
        decision_ref = self.runner.authorize(current, action, reservation)
        started_ns = self._now_ns()
        deadline = MonotonicActionDeadline(
            action_id=str(action.action_id),
            started_ns=started_ns,
            expires_ns=started_ns + timeout_ms * 1_000_000,
        )

        async def operation(_claimed: RecordRef) -> RepositoryPreparation:
            assert current.active_attempt_id is not None
            return await loader.prepare(
                submitted_source=source.url,
                requested_ref=requested_ref,
                analysis_id=str(current.meta.analysis_id),
                workspace_id=str(workspace_id),
                attempt_id=str(current.active_attempt_id),
                policy_ref=policy_ref,
                policy=policy,
                deadline=deadline,
            )

        outcome, _ = await self.runner.runtime.external.invoke_bound(
            str(current.work_id),
            decision_ref,
            self.runner.runtime.unit_of_work.records.stage_record(reservation),
            operation,
            idempotency_key=str(action.action_id),
        )
        elapsed_ms = max(0, (self._now_ns() - started_ns) // 1_000_000)
        self.runner.account(
            reservation,
            self.runner.units(elapsed_ms=elapsed_ms, cost_minor_units=1),
        )
        self._write_receipt(
            str(action.action_id),
            str(current.active_attempt_id),
            (preparing.workspace_ref, policy_ref),
            outcome,
            loader.process_receipts,
            elapsed_ms,
        )
        return publisher.finish(current, preparing, outcome)

    def _now_ns(self) -> int:
        if not callable(self.monotonic_ns):
            raise ValueError("MONOTONIC_CLOCK_INVALID")
        return int(self.monotonic_ns())

    def _write_receipt(
        self,
        action_id: str,
        attempt_id: str,
        input_refs: tuple[RecordRef, ...],
        outcome: RepositoryPreparation,
        process_receipts: tuple[ProcessReceipt, ...],
        elapsed_ms: int,
    ) -> Path:
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        if self.receipt_root.is_symlink():
            raise ValueError("STATIC_RECEIPT_ROOT_INVALID")
        prefix = hashlib.sha256(action_id.encode()).hexdigest()[:24]
        observation = canonical_bytes(
            {
                "analysis_id": outcome.analysis_id,
                "workspace_id": outcome.workspace_id,
                "repository_url": outcome.repository_url,
                "requested_ref": outcome.requested_ref,
                "status": outcome.status,
                "resolved_commit_id": outcome.resolved_commit_id,
                "tracked_files": [asdict(item) for item in outcome.tracked_files],
                "gaps": [asdict(item) for item in outcome.gaps],
                "errors": [asdict(item) for item in outcome.errors],
            }
        )
        observation_name = prefix + ".repository.json"
        self._atomic_write(self.receipt_root / observation_name, observation)
        receipt = StaticActionReceipt(
            action_id=action_id,
            attempt_id=attempt_id,
            operation_kind="REPOSITORY_PREPARE",
            input_fingerprint=hashlib.sha256(canonical_bytes(input_refs)).hexdigest(),
            process_receipt_hashes=tuple(
                hashlib.sha256(canonical_bytes(asdict(item))).hexdigest()
                for item in process_receipts
            ),
            observation_name=observation_name,
            observation_size=len(observation),
            observation_sha256=hashlib.sha256(observation).hexdigest(),
            elapsed_ms=elapsed_ms,
        )
        target = self.receipt_root / (prefix + ".receipt.json")
        self._atomic_write(target, canonical_bytes(asdict(receipt)))
        return target

    @staticmethod
    def _atomic_write(target: Path, data: bytes) -> None:
        temporary = target.with_suffix(target.suffix + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(target)
