"""Authorized application boundary for exact repository preparation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from pathlib import Path
from typing import Literal, Protocol, cast

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation, BudgetUnits
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import WorkspaceId
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    RunStoredDataRef,
    reference,
)
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import (
    CandidateError,
    CandidateGap,
    CandidateLocation,
    CanonicalRepositorySource,
    MonotonicActionDeadline,
    ProcessReceipt,
    PublishedWorkspaceMaterial,
    RepositoryPreparation,
    StaticActionReceipt,
    TrackedFile,
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
        checkpoint: Callable[[str], None] = lambda _stage: None,
        lease_root_resolver: Callable[[str], Path] | None = None,
    ) -> None:
        self.runner = runner
        self.receipt_root = receipt_root
        self.canonicalize_source = canonicalize_source
        self.decode_policy = decode_policy
        self.monotonic_ns = monotonic_ns
        self.checkpoint = checkpoint
        self.lease_root_resolver = lease_root_resolver

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
        receipt_elapsed_ms: int | None = None

        async def operation(_claimed: RecordRef) -> RepositoryPreparation:
            nonlocal receipt_elapsed_ms
            assert current.active_attempt_id is not None
            outcome = await loader.prepare(
                submitted_source=source.url,
                requested_ref=requested_ref,
                analysis_id=str(current.meta.analysis_id),
                workspace_id=str(workspace_id),
                attempt_id=str(current.active_attempt_id),
                policy_ref=policy_ref,
                policy=policy,
                deadline=deadline,
            )
            receipt_elapsed_ms = max(0, (self._now_ns() - started_ns) // 1_000_000)
            self._write_receipt(
                str(action.action_id),
                str(current.active_attempt_id),
                (preparing.workspace_ref, policy_ref),
                outcome,
                loader.process_receipts,
                receipt_elapsed_ms,
            )
            self.checkpoint("RECEIPT_DURABLE")
            return outcome

        outcome, _ = await self.runner.runtime.external.invoke_bound(
            str(current.work_id),
            decision_ref,
            self.runner.runtime.unit_of_work.records.stage_record(reservation),
            operation,
            idempotency_key=str(action.action_id),
        )
        self.checkpoint("RETURNED")
        if receipt_elapsed_ms is None:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        self._account_once(
            reservation,
            self.runner.units(elapsed_ms=receipt_elapsed_ms, cost_minor_units=1),
        )
        self.checkpoint("ACCOUNTED")
        return publisher.finish(current, preparing, outcome)

    async def recover_repository(
        self,
        *,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        policy_ref: RunStoredDataRef,
    ) -> PublishedWorkspaceMaterial:
        current = self.runner.runtime.work.get(str(work.work_id))
        state = self.runner.runtime.budget_registry.current_state(
            str(current.meta.analysis_id)
        )
        if current.status != "RUNNING" or current.active_attempt_id is None:
            raise ValueError("REPOSITORY_RECOVERY_INVALID")
        if not isinstance(state.workspace_ref, RunStoredDataRef):
            raise ValueError("REPOSITORY_RECOVERY_INVALID")
        workspace = self.runner.runtime.unit_of_work.records.get_exact(
            state.workspace_ref
        )
        if not isinstance(workspace, CodeWorkspace) or workspace.status != "PREPARING":
            raise ValueError("REPOSITORY_RECOVERY_INVALID")
        preparing = PublishedWorkspaceMaterial(
            workspace=workspace,
            workspace_ref=state.workspace_ref,
            work=current,
            analysis_state=state,
        )
        input_refs = (preparing.workspace_ref, policy_ref)
        receipt, outcome = self._read_receipt(
            str(current.active_attempt_id), input_refs
        )
        action, decision, reservation = self._recovery_records(
            str(current.meta.analysis_id), receipt.action_id
        )
        action_ref = reference(action)
        decision_ref = reference(decision)
        if (
            action.input_refs != input_refs
            or action.work_ref is None
            or action.work_ref.record_id != current.meta.record_id
            or reservation.action_ref != action_ref
            or decision.action_ref != action_ref
        ):
            raise ValueError("REPOSITORY_RECOVERY_INVALID")
        try:
            self.runner.runtime.validator.mark_returned(decision_ref)
        except ValueError as error:
            if str(error) != "EXTERNAL_DISPATCH_MISMATCH":
                raise
        actual = self.runner.units(elapsed_ms=receipt.elapsed_ms, cost_minor_units=1)
        self._account_once(reservation, actual)
        return WorkspacePreparationPublisher(self.runner, identity).finish(
            current, preparing, outcome
        )

    def _recovery_records(
        self, analysis_id: str, action_id: str
    ) -> tuple[ActionRequest, ActionDecision, BudgetReservation]:
        published = self.runner.runtime.queries.published_records(analysis_id)
        actions = tuple(
            item
            for item in published
            if isinstance(item, ActionRequest) and str(item.action_id) == action_id
        )
        if len(actions) != 1:
            raise ValueError("REPOSITORY_RECOVERY_INVALID")
        action_ref = reference(actions[0])
        decisions = tuple(
            item
            for item in published
            if isinstance(item, ActionDecision)
            and item.action_ref == action_ref
            and item.use_status == "UNUSED"
        )
        reservations = tuple(
            item
            for item in published
            if isinstance(item, BudgetReservation)
            and item.action_ref == action_ref
            and item.status == "RESERVED"
        )
        if len(decisions) != 1 or len(reservations) != 1:
            raise ValueError("REPOSITORY_RECOVERY_INVALID")
        return actions[0], decisions[0], reservations[0]

    def _account_once(
        self, reservation: BudgetReservation, actual: BudgetUnits
    ) -> None:
        entries = tuple(
            item
            for item in self.runner.runtime.queries.published_records(
                str(reservation.meta.analysis_id)
            )
            if isinstance(item, BudgetLedgerEntry)
            and item.reservation_ref.record_id == reservation.meta.record_id
        )
        if entries:
            if len(entries) != 1 or entries[0].actual_units != actual:
                raise ValueError("REPOSITORY_ACCOUNTING_MISMATCH")
            return
        self.runner.account(reservation, actual)

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
        if outcome.status == "READY" and (
            outcome.root is None
            or outcome.lease_id is None
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", outcome.lease_id)
        ):
            raise ValueError("WORKSPACE_LEASE_INVALID")
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
            lease_id=outcome.lease_id if outcome.status == "READY" else None,
        )
        target = self.receipt_root / (prefix + ".receipt.json")
        self._atomic_write(target, canonical_bytes(asdict(receipt)))
        return target

    def _read_receipt(
        self,
        attempt_id: str,
        input_refs: tuple[RecordRef, ...],
    ) -> tuple[StaticActionReceipt, RepositoryPreparation]:
        expected_fingerprint = hashlib.sha256(canonical_bytes(input_refs)).hexdigest()
        matches: list[tuple[StaticActionReceipt, RepositoryPreparation]] = []
        try:
            root = self.receipt_root.resolve(strict=True)
            if self.receipt_root.is_symlink() or not root.is_dir():
                raise ValueError
            for target in root.glob("*.receipt.json"):
                if target.is_symlink() or not target.is_file():
                    raise ValueError
                raw = target.read_bytes()
                if len(raw) > 64 * 1024:
                    raise ValueError
                value = json.loads(raw)
                if not isinstance(value, dict) or set(value) != set(
                    StaticActionReceipt.__dataclass_fields__
                ):
                    raise ValueError
                operation_kind = self._string(value["operation_kind"])
                if operation_kind not in (
                    "REPOSITORY_PREPARE",
                    "STATIC_TOOL",
                    "CONTEXT_READ",
                ):
                    raise ValueError
                lease_value = value["lease_id"]
                if lease_value is not None and not isinstance(lease_value, str):
                    raise ValueError
                receipt = StaticActionReceipt(
                    action_id=self._string(value["action_id"]),
                    attempt_id=self._string(value["attempt_id"]),
                    operation_kind=cast(
                        Literal["REPOSITORY_PREPARE", "STATIC_TOOL", "CONTEXT_READ"],
                        operation_kind,
                    ),
                    input_fingerprint=self._string(value["input_fingerprint"]),
                    process_receipt_hashes=self._strings(
                        value["process_receipt_hashes"]
                    ),
                    observation_name=self._string(value["observation_name"]),
                    observation_size=self._non_negative_int(value["observation_size"]),
                    observation_sha256=self._string(value["observation_sha256"]),
                    elapsed_ms=self._non_negative_int(value["elapsed_ms"]),
                    lease_id=lease_value,
                )
                if canonical_bytes(asdict(receipt)) != raw:
                    raise ValueError
                prefix = hashlib.sha256(receipt.action_id.encode()).hexdigest()[:24]
                if (
                    receipt.operation_kind != "REPOSITORY_PREPARE"
                    or target.name != prefix + ".receipt.json"
                    or receipt.observation_name != prefix + ".repository.json"
                    or not re.fullmatch(r"[0-9a-f]{64}", receipt.input_fingerprint)
                    or any(
                        not re.fullmatch(r"[0-9a-f]{64}", digest)
                        for digest in receipt.process_receipt_hashes
                    )
                    or receipt.elapsed_ms < 0
                    or (
                        receipt.lease_id is not None
                        and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", receipt.lease_id)
                    )
                ):
                    raise ValueError
                observation_path = root / receipt.observation_name
                observation = observation_path.read_bytes()
                if (
                    observation_path.is_symlink()
                    or not observation_path.is_file()
                    or len(observation) != receipt.observation_size
                    or hashlib.sha256(observation).hexdigest()
                    != receipt.observation_sha256
                ):
                    raise ValueError
                payload = json.loads(observation)
                expected_fields = {
                    "analysis_id",
                    "workspace_id",
                    "repository_url",
                    "requested_ref",
                    "status",
                    "resolved_commit_id",
                    "tracked_files",
                    "gaps",
                    "errors",
                }
                if not isinstance(payload, dict) or set(payload) != expected_fields:
                    raise ValueError
                if canonical_bytes(payload) != observation:
                    raise ValueError
                outcome = self._decode_observation(payload, receipt)
                if (
                    receipt.attempt_id == attempt_id
                    and receipt.input_fingerprint == expected_fingerprint
                ):
                    matches.append((receipt, outcome))
        except (OSError, TypeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID") from error
        if len(matches) != 1:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return matches[0]

    def _decode_observation(
        self, payload: dict[str, object], receipt: StaticActionReceipt
    ) -> RepositoryPreparation:
        root: Path | None = None
        if receipt.lease_id is not None:
            if self.lease_root_resolver is None:
                raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
            configured = self.lease_root_resolver(receipt.lease_id)
            if configured.is_symlink():
                raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
            root = configured.resolve(strict=True)
            if not root.is_dir():
                raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        tracked = tuple(
            self._tracked_file(item) for item in self._objects(payload["tracked_files"])
        )
        gaps = tuple(
            self._candidate_gap(item) for item in self._objects(payload["gaps"])
        )
        errors = tuple(
            self._candidate_error(item) for item in self._objects(payload["errors"])
        )
        status = self._string(payload["status"])
        if status not in ("READY", "FAILED"):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        resolved_commit = payload["resolved_commit_id"]
        if resolved_commit is not None and not isinstance(resolved_commit, str):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return RepositoryPreparation(
            analysis_id=self._string(payload["analysis_id"]),
            workspace_id=self._string(payload["workspace_id"]),
            repository_url=self._string(payload["repository_url"]),
            requested_ref=self._string(payload["requested_ref"]),
            status=cast(Literal["READY", "FAILED"], status),
            resolved_commit_id=resolved_commit,
            root=root,
            tracked_files=tracked,
            gaps=gaps,
            errors=errors,
            lease_id=receipt.lease_id,
        )

    @staticmethod
    def _objects(value: object) -> tuple[dict[str, object], ...]:
        if not isinstance(value, list) or any(
            not isinstance(item, dict) for item in value
        ):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return cast(tuple[dict[str, object], ...], tuple(value))

    @staticmethod
    def _string(value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return value

    @classmethod
    def _strings(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return tuple(cls._string(item) for item in value)

    @staticmethod
    def _non_negative_int(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return value

    @staticmethod
    def _boolean(value: object) -> bool:
        if not isinstance(value, bool):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return value

    @classmethod
    def _tracked_file(cls, value: dict[str, object]) -> TrackedFile:
        if set(value) != {"git_path", "git_mode", "blob_id", "size_bytes"}:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return TrackedFile(
            git_path=cls._string(value["git_path"]),
            git_mode=cls._string(value["git_mode"]),
            blob_id=cls._string(value["blob_id"]),
            size_bytes=cls._non_negative_int(value["size_bytes"]),
        )

    @classmethod
    def _candidate_error(cls, value: dict[str, object]) -> CandidateError:
        if set(value) != {"stage", "code", "safe_message", "retryable"}:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return CandidateError(
            stage=cls._string(value["stage"]),
            code=cls._string(value["code"]),
            safe_message=cls._string(value["safe_message"]),
            retryable=cls._boolean(value["retryable"]),
        )

    @classmethod
    def _candidate_location(cls, value: dict[str, object]) -> CandidateLocation:
        expected = {
            "file_path",
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        }
        if set(value) != expected:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        start_column = value["start_column"]
        end_column = value["end_column"]
        if start_column is not None:
            start_column = cls._non_negative_int(start_column)
        if end_column is not None:
            end_column = cls._non_negative_int(end_column)
        return CandidateLocation(
            file_path=cls._string(value["file_path"]),
            start_line=cls._non_negative_int(value["start_line"]),
            start_column=start_column,
            end_line=cls._non_negative_int(value["end_line"]),
            end_column=end_column,
        )

    @classmethod
    def _candidate_gap(cls, value: dict[str, object]) -> CandidateGap:
        expected = {
            "stage",
            "code",
            "reason",
            "description",
            "affected_paths",
            "affected_languages",
            "affected_locations",
            "retryable",
        }
        if set(value) != expected:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        locations = tuple(
            cls._candidate_location(item)
            for item in cls._objects(value["affected_locations"])
        )
        return CandidateGap(
            stage=cls._string(value["stage"]),
            code=cls._string(value["code"]),
            reason=cls._string(value["reason"]),
            description=cls._string(value["description"]),
            affected_paths=cls._strings(value["affected_paths"]),
            affected_languages=cls._strings(value["affected_languages"]),
            affected_locations=locations,
            retryable=cls._boolean(value["retryable"]),
        )

    @staticmethod
    def _atomic_write(target: Path, data: bytes) -> None:
        temporary = target.with_suffix(target.suffix + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(target)
