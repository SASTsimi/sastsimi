"""Authorized application boundary for exact repository preparation."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Literal, Protocol, cast

from pydantic import TypeAdapter

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.budget import (
    BudgetAgentRole,
    BudgetLedgerEntry,
    BudgetProfileBinding,
    BudgetReservation,
    BudgetUnits,
    OperationKind,
    WorkBudgetProfile,
    select_work_limit,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    RunStoredDataRef,
    reference,
)
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile, ToolRunResult
from sastsimi.contracts.work import WorkExecutionState, WorkType
from sastsimi.ports.dto import (
    CandidateError,
    CandidateGap,
    CandidateLocation,
    CandidateRule,
    CanonicalRepositorySource,
    MonotonicActionDeadline,
    ProcessReceipt,
    PublishedWorkspaceMaterial,
    RepositoryPreparation,
    StaticActionReceipt,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
    WorkspaceStoragePolicy,
)
from sastsimi.ports.static_tool import validate_static_tool_profile_binding
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.coordinator import StaticToolCoordinator

from .static_publication import StaticAttemptPublisher, WorkspacePreparationPublisher

type RepositorySourceCanonicalizer = Callable[[str], CanonicalRepositorySource]
type WorkspacePolicyDecoder = Callable[
    [RunStoredDataRef, bytes, str], WorkspaceStoragePolicy
]
type StaticProcessReceiptReader = Callable[[str, str], Sequence[ProcessReceipt]]

_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_OBSERVATION_BYTES = 4 * 1024 * 1024
_PROCESS_SEQUENCE = ("clone", "resolve", "checkout", "head", "manifest")


def _file_identity(
    details: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_size,
        details.st_mtime_ns,
        details.st_nlink,
        getattr(details, "st_file_attributes", 0),
    )


def _guarded_read(path: Path, limit: int) -> bytes:
    """Read one private regular file without following/reusing another identity."""
    descriptor = -1
    try:
        before = path.lstat()
        attributes = getattr(before, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or attributes & 0x400
            or before.st_size > limit
        ):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            _file_identity(opened) != _file_identity(before)
            or opened.st_nlink != 1
            or getattr(opened, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = path.lstat()
        if len(raw) > limit or _file_identity(after) != _file_identity(opened):
            raise ValueError
        return raw
    except (OSError, ValueError) as error:
        raise ValueError("STATIC_ACTION_RECEIPT_INVALID") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


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


class RepositoryRecoveryValidatorPort(Protocol):
    async def validate(
        self,
        outcome: RepositoryPreparation,
        *,
        action_id: str,
        attempt_id: str,
        process_receipts: tuple[ProcessReceipt, ...],
    ) -> None: ...


class UncertainDispatchRecoveryPort(Protocol):
    def block_uncertain(self, work: WorkExecutionState) -> None: ...


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
        recovery_validator: RepositoryRecoveryValidatorPort | None = None,
        static_publisher: StaticAttemptPublisher | None = None,
        static_process_receipts: StaticProcessReceiptReader | None = None,
    ) -> None:
        self.runner = runner
        self.receipt_root = receipt_root
        self.canonicalize_source = canonicalize_source
        self.decode_policy = decode_policy
        self.monotonic_ns = monotonic_ns
        self.checkpoint = checkpoint
        self.lease_root_resolver = lease_root_resolver
        self.recovery_validator = recovery_validator
        self.static_publisher = static_publisher or StaticAttemptPublisher(runner)
        self.static_process_receipts = static_process_receipts

    async def invoke(
        self,
        request: StaticToolRequest,
        profile: StaticToolProfile,
        operation: Callable[
            [MonotonicActionDeadline], Awaitable[StaticToolObservation]
        ],
    ) -> ToolRunResult:
        """Close authorization, dispatch, receipt, accounting and publication once."""
        action = request.action
        if action.work_ref is None:
            raise ValueError("STATIC_TOOL_REQUEST_INVALID")
        referenced_work = self.runner.runtime.unit_of_work.records.get_exact(
            action.work_ref
        )
        if not isinstance(referenced_work, WorkExecutionState):
            raise ValueError("STATIC_TOOL_REQUEST_INVALID")
        work = self.runner.runtime.work.get(str(referenced_work.work_id))
        resolved_profile = (
            self.runner.runtime.configuration.resolve_static_tool_profile(
                request.tool_profile_ref
            )
        )
        state = self.runner.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        binding_ref = state.budget_binding_ref
        if binding_ref is None or state.workspace_ref != reference(request.workspace):
            raise ValueError("STATIC_TOOL_REQUEST_INVALID")
        records = self.runner.runtime.unit_of_work.records
        binding = records.get_exact(binding_ref)
        if not isinstance(binding, BudgetProfileBinding):
            raise ValueError("STATIC_TOOL_REQUEST_INVALID")
        work_profile = records.get_exact(binding.work_budget_profile_ref)
        if not isinstance(work_profile, WorkBudgetProfile):
            raise ValueError("STATIC_TOOL_REQUEST_INVALID")
        limit = select_work_limit(
            work_profile,
            WorkType.STATIC_TOOL,
            OperationKind.STATIC_TOOL,
            BudgetAgentRole.STATIC_ANALYSIS,
        )
        approved_timeout = resolved_profile.run_timeout_ms
        if limit.timeout_ms is not None:
            approved_timeout = min(approved_timeout, limit.timeout_ms)
        if (
            profile != resolved_profile
            or work != referenced_work
            or not isinstance(action.meta, RecordMeta)
            or action.meta.attempt_id is None
            or not isinstance(work.meta, RecordMeta)
            or work.status != "RUNNING"
            or work.active_attempt_id != action.meta.attempt_id
            or request.workspace.status != "READY"
            or request.workspace.commit_id != work.meta.commit_id
            or request.workspace.workspace_id != work.meta.workspace_id
            or action.input_refs.count(request.tool_profile_ref) != 1
            or work.input_refs.count(request.tool_profile_ref) != 1
            or action.input_refs.count(request.analysis_config_ref) != 1
            or work.input_refs.count(request.analysis_config_ref) != 1
            or (
                request.rule_catalog_ref is not None
                and (
                    action.input_refs.count(request.rule_catalog_ref) != 1
                    or work.input_refs.count(request.rule_catalog_ref) != 1
                )
            )
            or approved_timeout <= 0
        ):
            raise ValueError("STATIC_TOOL_REQUEST_INVALID")
        attempt_id = str(action.meta.attempt_id)
        reservation = self.runner.reserve(
            work,
            binding_ref,
            action,
            self.runner.units(elapsed_ms=approved_timeout),
        )
        decision_ref = self.runner.authorize(work, action, reservation)
        decision = records.get_exact(decision_ref)
        if not isinstance(decision, ActionDecision):
            raise ValueError("STATIC_TOOL_DECISION_INVALID")
        validate_static_tool_profile_binding(request, work, decision, resolved_profile)
        started_ns = self._now_ns()
        elapsed_ms: int | None = None
        process_receipts: tuple[ProcessReceipt, ...] = ()

        async def bound(_claimed: RecordRef) -> StaticToolObservation:
            nonlocal elapsed_ms, process_receipts
            deadline = MonotonicActionDeadline(
                action_id=str(action.action_id),
                started_ns=started_ns,
                expires_ns=started_ns + approved_timeout * 1_000_000,
            )
            observation = await operation(deadline)
            elapsed_ms = max(0, (self._now_ns() - started_ns) // 1_000_000)
            process_receipts = self._current_tool_process_receipts(
                str(action.action_id), attempt_id
            )
            self._write_tool_receipt(
                request,
                decision_ref,
                observation,
                elapsed_ms,
                resolved_profile.max_attempt_output_bytes,
                process_receipts,
            )
            self.checkpoint("STATIC_RECEIPT_DURABLE")
            return observation

        try:
            observation, _ = await self.runner.runtime.external.invoke_bound(
                str(work.work_id),
                decision_ref,
                records.stage_record(reservation),
                bound,
                idempotency_key=str(action.action_id),
            )
        except asyncio.CancelledError:
            elapsed_ms = max(0, (self._now_ns() - started_ns) // 1_000_000)
            process_receipts = self._current_tool_process_receipts(
                str(action.action_id), attempt_id
            )
            observation = self._cancelled_observation(
                request, resolved_profile, elapsed_ms
            )
            self._write_tool_receipt(
                request,
                decision_ref,
                observation,
                elapsed_ms,
                resolved_profile.max_attempt_output_bytes,
                process_receipts,
            )
            self.runner.runtime.validator.mark_returned(decision_ref)
        except Exception:
            if not self._tool_receipt_path(str(action.action_id)).is_file():
                self._block_uncertain(work)
            raise
        self.checkpoint("STATIC_RETURNED")
        if elapsed_ms is None:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        self._account_once(reservation, self.runner.units(elapsed_ms=elapsed_ms))
        self.checkpoint("STATIC_ACCOUNTED")
        return self.static_publisher.publish(request, observation).result

    async def recover_tool(
        self, request: StaticToolRequest, profile: StaticToolProfile
    ) -> ToolRunResult:
        """Recover a complete static receipt without invoking the tool again."""
        action = request.action
        if action.work_ref is None or not isinstance(action.meta, RecordMeta):
            raise ValueError("STATIC_TOOL_RECOVERY_INVALID")
        referenced = self.runner.runtime.unit_of_work.records.get_exact(action.work_ref)
        if not isinstance(referenced, WorkExecutionState):
            raise ValueError("STATIC_TOOL_RECOVERY_INVALID")
        work = self.runner.runtime.work.get(str(referenced.work_id))
        if work.status in {"SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED"}:
            results = tuple(
                self.runner.runtime.unit_of_work.records.get_exact(output_ref)
                for output_ref in work.output_refs
                if output_ref.data_kind == "tool_run_result"
            )
            if (
                len(results) == 1
                and isinstance(results[0], ToolRunResult)
                and results[0].meta.attempt_id == action.meta.attempt_id
            ):
                return results[0]
            raise ValueError("STATIC_TOOL_RECOVERY_INVALID")
        if work.status != "RUNNING" or work.active_attempt_id != action.meta.attempt_id:
            self._quarantine_tool_receipt(str(action.action_id))
            raise ValueError("STATIC_TOOL_RECOVERY_INVALID")
        try:
            recovered_action, decision, reservation = self._recovery_records(
                str(work.meta.analysis_id), str(action.action_id)
            )
            decision_ref = reference(decision)
            if recovered_action != action or profile != (
                self.runner.runtime.configuration.resolve_static_tool_profile(
                    request.tool_profile_ref
                )
            ):
                raise ValueError("STATIC_TOOL_RECOVERY_INVALID")
            validate_static_tool_profile_binding(request, work, decision, profile)
            receipt, observation, _ = self._read_tool_receipt(
                request, decision_ref, profile
            )
        except (LookupError, OSError, ValueError) as error:
            self._block_uncertain(work)
            self._quarantine_tool_receipt(str(action.action_id))
            raise ValueError("STATIC_TOOL_RECOVERY_AMBIGUOUS") from error
        try:
            self.runner.runtime.validator.mark_returned(decision_ref)
        except ValueError as error:
            if str(error) != "EXTERNAL_DISPATCH_MISMATCH":
                raise
        self._account_once(
            reservation, self.runner.units(elapsed_ms=receipt.elapsed_ms)
        )
        return self.static_publisher.publish(request, observation).result

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
        receipt, outcome, process_receipts = self._read_receipt(
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
            or outcome.analysis_id != str(current.meta.analysis_id)
            or outcome.workspace_id != str(workspace.workspace_id)
            or outcome.repository_url != str(workspace.repository_url)
            or reservation.action_ref != action_ref
            or decision.action_ref != action_ref
        ):
            raise ValueError("REPOSITORY_RECOVERY_INVALID")
        if outcome.status == "READY":
            if self.recovery_validator is None:
                raise ValueError("REPOSITORY_RECOVERY_GUARD_REQUIRED")
            await self.recovery_validator.validate(
                outcome,
                action_id=receipt.action_id,
                attempt_id=receipt.attempt_id,
                process_receipts=process_receipts,
            )
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

    def _current_tool_process_receipts(
        self, action_id: str, attempt_id: str
    ) -> tuple[ProcessReceipt, ...]:
        if self.static_process_receipts is None:
            return ()
        return self._validate_tool_process_receipts(
            action_id,
            attempt_id,
            tuple(self.static_process_receipts(action_id, attempt_id)),
        )

    @staticmethod
    def _validate_tool_process_receipts(
        action_id: str,
        attempt_id: str,
        receipts: tuple[ProcessReceipt, ...],
    ) -> tuple[ProcessReceipt, ...]:
        invocation_ids = tuple(item.invocation_id for item in receipts)
        receipt_hashes = tuple(
            hashlib.sha256(canonical_bytes(asdict(item))).hexdigest()
            for item in receipts
        )
        if len(invocation_ids) != len(set(invocation_ids)) or len(
            receipt_hashes
        ) != len(set(receipt_hashes)):
            raise ValueError("STATIC_PROCESS_RECEIPT_INVALID")
        for item in receipts:
            valid_result = (
                (item.outcome == "SUCCEEDED" and item.return_code == 0)
                or (
                    item.outcome == "FAILED"
                    and isinstance(item.return_code, int)
                    and item.return_code != 0
                )
                or (
                    item.outcome in {"TIMED_OUT", "CANCELLED"}
                    and (item.return_code is None or isinstance(item.return_code, int))
                )
            )
            hashes = (
                item.command_fingerprint,
                item.stdout_sha256,
                item.stderr_sha256,
            )
            if (
                item.action_id != action_id
                or item.attempt_id != attempt_id
                or not item.invocation_id
                or not item.command_kind
                or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
                or not item.stdout_name
                or Path(item.stdout_name).name != item.stdout_name
                or not item.stderr_name
                or Path(item.stderr_name).name != item.stderr_name
                or not valid_result
            ):
                raise ValueError("STATIC_PROCESS_RECEIPT_INVALID")
        return receipts

    @staticmethod
    def _tool_input_fingerprint(
        request: StaticToolRequest, decision_ref: RecordRef
    ) -> str:
        if not isinstance(request.action.meta, RecordMeta):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return hashlib.sha256(
            canonical_bytes(
                (
                    "static_tool_v1",
                    reference(request.action),
                    request.action.work_ref,
                    request.action.meta.attempt_id,
                    decision_ref,
                    request.tool_profile_ref,
                    request.analysis_config_ref,
                    request.rule_catalog_ref,
                    reference(request.workspace),
                )
            )
        ).hexdigest()

    def _tool_receipt_path(self, action_id: str) -> Path:
        prefix = hashlib.sha256(action_id.encode()).hexdigest()[:24]
        return self.receipt_root / (prefix + ".receipt.json")

    def _block_uncertain(self, work: WorkExecutionState) -> None:
        blocker = cast(
            UncertainDispatchRecoveryPort,
            self.runner.runtime.recovery.recovery,
        )
        blocker.block_uncertain(work)

    def _quarantine_tool_receipt(self, action_id: str) -> None:
        target = self._tool_receipt_path(action_id)
        try:
            target.lstat()
        except OSError:
            return
        quarantine = self.receipt_root / "quarantine"
        quarantine.mkdir(mode=0o700, exist_ok=True)
        if quarantine.is_symlink() or not quarantine.is_dir():
            raise ValueError("STATIC_RECEIPT_ROOT_INVALID")
        destination = quarantine / target.name
        if destination.exists():
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        target.replace(destination)

    def _cancelled_observation(
        self,
        request: StaticToolRequest,
        profile: StaticToolProfile,
        elapsed_ms: int,
    ) -> StaticToolObservation:
        catalog_rule_ids: tuple[str, ...] = ()
        if profile.tool_kind == "RULE_BASED":
            if request.rule_catalog_ref is None:
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
            try:
                catalog_rule_ids = self.static_publisher.rule_catalogs[
                    request.rule_catalog_ref
                ]
            except KeyError as error:
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH") from error
        return StaticToolObservation(
            tool_name=profile.tool_name,
            tool_version=profile.expected_version,
            tool_kind=profile.tool_kind,
            status="SKIPPED",
            raw_output=None,
            raw_media_type=None,
            analyzed_paths=(),
            skipped_paths=request.action.file_paths,
            analyzed_languages=(),
            skipped_languages=(),
            notes=("The static tool attempt was cancelled by the caller.",),
            selected_rule_packs=(),
            rules=tuple(
                CandidateRule(
                    rule_id,
                    "SELECTED",
                    "NOT_EXECUTED",
                    None,
                    "CANCELLED",
                    None,
                )
                for rule_id in catalog_rule_ids
            ),
            symbols=(),
            facts=(),
            relations=(),
            gaps=(
                CandidateGap(
                    "STATIC_ANALYSIS",
                    "STATIC_TOOL_CANCELLED",
                    "BLOCKED",
                    "The static tool attempt was cancelled by the caller.",
                    request.action.file_paths,
                    (),
                    (),
                    True,
                ),
            ),
            errors=(),
            started_monotonic_ms=0,
            finished_monotonic_ms=elapsed_ms,
        )

    def _write_tool_receipt(
        self,
        request: StaticToolRequest,
        decision_ref: RecordRef,
        observation: StaticToolObservation,
        elapsed_ms: int,
        output_limit: int,
        process_receipts: tuple[ProcessReceipt, ...] = (),
    ) -> Path:
        if not isinstance(request.action.meta, RecordMeta):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        attempt_id = request.action.meta.attempt_id
        if attempt_id is None:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        if self.receipt_root.is_symlink():
            raise ValueError("STATIC_RECEIPT_ROOT_INVALID")
        prefix = hashlib.sha256(str(request.action.action_id).encode()).hexdigest()[:24]
        payload = asdict(observation)
        payload["raw_output"] = (
            None
            if observation.raw_output is None
            else base64.b64encode(observation.raw_output).decode("ascii")
        )
        raw = canonical_bytes(payload)
        process_receipts = self._validate_tool_process_receipts(
            str(request.action.action_id), str(attempt_id), process_receipts
        )
        projected_bytes = len(raw) + sum(
            item.stdout_size + item.stderr_size for item in process_receipts
        )
        if projected_bytes > output_limit:
            raise ValueError("STATIC_TOOL_OUTPUT_LIMIT")
        observation_name = prefix + ".static.json"
        self._atomic_write(self.receipt_root / observation_name, raw)
        process_hashes: list[str] = []
        for process_receipt in process_receipts:
            process_raw = canonical_bytes(asdict(process_receipt))
            process_digest = hashlib.sha256(process_raw).hexdigest()
            self._atomic_write(
                self.receipt_root / f"{process_digest}.process.json", process_raw
            )
            process_hashes.append(process_digest)
        receipt = StaticActionReceipt(
            action_id=str(request.action.action_id),
            attempt_id=str(attempt_id),
            operation_kind="STATIC_TOOL",
            input_fingerprint=self._tool_input_fingerprint(request, decision_ref),
            process_receipt_hashes=tuple(process_hashes),
            observation_name=observation_name,
            observation_size=len(raw),
            observation_sha256=hashlib.sha256(raw).hexdigest(),
            elapsed_ms=elapsed_ms,
        )
        target = self.receipt_root / (prefix + ".receipt.json")
        self._atomic_write(target, canonical_bytes(asdict(receipt)))
        return target

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
        self._validate_process_receipts(
            action_id, attempt_id, outcome, process_receipts
        )
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
        process_hashes: list[str] = []
        for process_receipt in process_receipts:
            process_raw = canonical_bytes(asdict(process_receipt))
            process_digest = hashlib.sha256(process_raw).hexdigest()
            self._atomic_write(
                self.receipt_root / f"{process_digest}.process.json", process_raw
            )
            process_hashes.append(process_digest)
        receipt = StaticActionReceipt(
            action_id=action_id,
            attempt_id=attempt_id,
            operation_kind="REPOSITORY_PREPARE",
            input_fingerprint=hashlib.sha256(canonical_bytes(input_refs)).hexdigest(),
            process_receipt_hashes=tuple(process_hashes),
            observation_name=observation_name,
            observation_size=len(observation),
            observation_sha256=hashlib.sha256(observation).hexdigest(),
            elapsed_ms=elapsed_ms,
            lease_id=outcome.lease_id if outcome.status == "READY" else None,
        )
        target = self.receipt_root / (prefix + ".receipt.json")
        self._atomic_write(target, canonical_bytes(asdict(receipt)))
        return target

    def _read_tool_receipt(
        self,
        request: StaticToolRequest,
        decision_ref: RecordRef,
        profile: StaticToolProfile,
    ) -> tuple[
        StaticActionReceipt,
        StaticToolObservation,
        tuple[ProcessReceipt, ...],
    ]:
        if not isinstance(request.action.meta, RecordMeta):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        attempt_id = request.action.meta.attempt_id
        if attempt_id is None:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        try:
            root = self.receipt_root.resolve(strict=True)
            if self.receipt_root.is_symlink() or not root.is_dir():
                raise ValueError
            target = self._tool_receipt_path(str(request.action.action_id))
            raw = _guarded_read(target, _MAX_RECEIPT_BYTES)
            value = json.loads(raw)
            if not isinstance(value, dict) or set(value) != set(
                StaticActionReceipt.__dataclass_fields__
            ):
                raise ValueError
            operation_kind = self._string(value["operation_kind"])
            if operation_kind != "STATIC_TOOL":
                raise ValueError
            receipt = StaticActionReceipt(
                action_id=self._string(value["action_id"]),
                attempt_id=self._string(value["attempt_id"]),
                operation_kind="STATIC_TOOL",
                input_fingerprint=self._string(value["input_fingerprint"]),
                process_receipt_hashes=self._strings(value["process_receipt_hashes"]),
                observation_name=self._string(value["observation_name"]),
                observation_size=self._non_negative_int(value["observation_size"]),
                observation_sha256=self._string(value["observation_sha256"]),
                elapsed_ms=self._non_negative_int(value["elapsed_ms"]),
                lease_id=(
                    None
                    if value["lease_id"] is None
                    else self._string(value["lease_id"])
                ),
            )
            prefix = hashlib.sha256(receipt.action_id.encode()).hexdigest()[:24]
            if (
                canonical_bytes(asdict(receipt)) != raw
                or target.parent.resolve(strict=True) != root
                or target.name != prefix + ".receipt.json"
                or receipt.action_id != str(request.action.action_id)
                or receipt.attempt_id != str(attempt_id)
                or receipt.input_fingerprint
                != self._tool_input_fingerprint(request, decision_ref)
                or receipt.observation_name != prefix + ".static.json"
                or Path(receipt.observation_name).name != receipt.observation_name
                or receipt.lease_id is not None
                or receipt.observation_size
                > min(_MAX_OBSERVATION_BYTES, profile.max_attempt_output_bytes)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.observation_sha256)
                or any(
                    not re.fullmatch(r"[0-9a-f]{64}", digest)
                    for digest in receipt.process_receipt_hashes
                )
            ):
                raise ValueError
            observation_raw = _guarded_read(
                root / receipt.observation_name,
                min(_MAX_OBSERVATION_BYTES, profile.max_attempt_output_bytes),
            )
            if (
                len(observation_raw) != receipt.observation_size
                or hashlib.sha256(observation_raw).hexdigest()
                != receipt.observation_sha256
            ):
                raise ValueError
            payload = json.loads(observation_raw)
            if not isinstance(payload, dict) or set(payload) != set(
                StaticToolObservation.__dataclass_fields__
            ):
                raise ValueError
            if canonical_bytes(payload) != observation_raw:
                raise ValueError
            encoded = payload["raw_output"]
            if encoded is not None:
                if not isinstance(encoded, str):
                    raise ValueError
                decoded_raw = base64.b64decode(encoded, validate=True)
                if base64.b64encode(decoded_raw).decode("ascii") != encoded:
                    raise ValueError
                payload["raw_output"] = decoded_raw
            observation = TypeAdapter(StaticToolObservation).validate_python(payload)
            StaticToolCoordinator._validate_observation(profile, observation)
            process_receipts = self._read_process_receipts(root, receipt)
            process_receipts = self._validate_tool_process_receipts(
                receipt.action_id, receipt.attempt_id, process_receipts
            )
            projected = receipt.observation_size + sum(
                item.stdout_size + item.stderr_size for item in process_receipts
            )
            if projected > profile.max_attempt_output_bytes:
                raise ValueError
        except (
            OSError,
            TypeError,
            json.JSONDecodeError,
            ValueError,
        ) as error:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID") from error
        return receipt, observation, process_receipts

    def _read_receipt(
        self,
        attempt_id: str,
        input_refs: tuple[RecordRef, ...],
    ) -> tuple[StaticActionReceipt, RepositoryPreparation, tuple[ProcessReceipt, ...]]:
        expected_fingerprint = hashlib.sha256(canonical_bytes(input_refs)).hexdigest()
        matches: list[
            tuple[
                StaticActionReceipt,
                RepositoryPreparation,
                tuple[ProcessReceipt, ...],
            ]
        ] = []
        try:
            root = self.receipt_root.resolve(strict=True)
            if self.receipt_root.is_symlink() or not root.is_dir():
                raise ValueError
            for target in root.glob("*.receipt.json"):
                if target.is_symlink() or not target.is_file():
                    raise ValueError
                raw = _guarded_read(target, _MAX_RECEIPT_BYTES)
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
                if receipt.observation_size > _MAX_OBSERVATION_BYTES:
                    raise ValueError
                observation = _guarded_read(observation_path, _MAX_OBSERVATION_BYTES)
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
                process_receipts = self._read_process_receipts(root, receipt)
                self._validate_process_receipts(
                    receipt.action_id,
                    receipt.attempt_id,
                    outcome,
                    process_receipts,
                )
                if (
                    receipt.attempt_id == attempt_id
                    and receipt.input_fingerprint == expected_fingerprint
                ):
                    matches.append((receipt, outcome, process_receipts))
        except (OSError, TypeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID") from error
        if len(matches) != 1:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return matches[0]

    def _read_process_receipts(
        self, root: Path, receipt: StaticActionReceipt
    ) -> tuple[ProcessReceipt, ...]:
        if len(set(receipt.process_receipt_hashes)) != len(
            receipt.process_receipt_hashes
        ):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        decoded: list[ProcessReceipt] = []
        for digest in receipt.process_receipt_hashes:
            raw = _guarded_read(root / f"{digest}.process.json", _MAX_RECEIPT_BYTES)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
            try:
                value = json.loads(raw)
                decoded_receipt = self._decode_process_receipt(value)
            except (TypeError, json.JSONDecodeError, ValueError) as error:
                raise ValueError("STATIC_ACTION_RECEIPT_INVALID") from error
            if canonical_bytes(asdict(decoded_receipt)) != raw:
                raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
            decoded.append(decoded_receipt)
        return tuple(decoded)

    def _decode_process_receipt(self, value: object) -> ProcessReceipt:
        if not isinstance(value, dict) or set(value) != set(
            ProcessReceipt.__dataclass_fields__
        ):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        outcome = self._string(value["outcome"])
        if outcome not in ("SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return_code = value["return_code"]
        if return_code is not None and (
            isinstance(return_code, bool) or not isinstance(return_code, int)
        ):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        return ProcessReceipt(
            action_id=self._string(value["action_id"]),
            invocation_id=self._string(value["invocation_id"]),
            command_kind=self._string(value["command_kind"]),
            attempt_id=self._string(value["attempt_id"]),
            command_fingerprint=self._string(value["command_fingerprint"]),
            outcome=cast(
                Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"],
                outcome,
            ),
            return_code=return_code,
            stdout_name=self._string(value["stdout_name"]),
            stdout_size=self._non_negative_int(value["stdout_size"]),
            stdout_sha256=self._string(value["stdout_sha256"]),
            stderr_name=self._string(value["stderr_name"]),
            stderr_size=self._non_negative_int(value["stderr_size"]),
            stderr_sha256=self._string(value["stderr_sha256"]),
            elapsed_ms=self._non_negative_int(value["elapsed_ms"]),
        )

    @staticmethod
    def _validate_process_receipts(
        action_id: str,
        attempt_id: str,
        outcome: RepositoryPreparation,
        receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        kinds = tuple(item.command_kind for item in receipts)
        if kinds != _PROCESS_SEQUENCE[: len(kinds)]:
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        if outcome.status == "READY" and (
            kinds != _PROCESS_SEQUENCE
            or any(
                item.outcome != "SUCCEEDED" or item.return_code != 0
                for item in receipts
            )
        ):
            raise ValueError("STATIC_ACTION_RECEIPT_INVALID")
        for item in receipts:
            hashes = (
                item.command_fingerprint,
                item.stdout_sha256,
                item.stderr_sha256,
            )
            valid_result = (
                (item.outcome == "SUCCEEDED" and item.return_code == 0)
                or (
                    item.outcome == "FAILED"
                    and isinstance(item.return_code, int)
                    and item.return_code != 0
                )
                or item.outcome in {"TIMED_OUT", "CANCELLED"}
            )
            if (
                item.action_id != action_id
                or item.attempt_id != attempt_id
                or item.invocation_id != f"{attempt_id}-{item.command_kind}"
                or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
                or not item.stdout_name
                or Path(item.stdout_name).name != item.stdout_name
                or not item.stderr_name
                or Path(item.stderr_name).name != item.stderr_name
                or not valid_result
            ):
                raise ValueError("STATIC_ACTION_RECEIPT_INVALID")

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
