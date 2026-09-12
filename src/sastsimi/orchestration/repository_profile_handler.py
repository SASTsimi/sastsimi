"""Production handler for guarded repository detection and durable publication."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import (
    CodeWorkspace,
    RepositoryExecutionSelection,
    RepositoryProfile,
)
from sastsimi.contracts.work import (
    AttemptStatus,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    ProcessReceipt,
    RepositoryPreparation,
    WorkContext,
    WorkHandlerResult,
)
from sastsimi.ports.repository_profile import (
    RepositoryExecutionSelectorPort,
    RepositoryProfilerPort,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner


class RepositoryProfileGuard(Protocol):
    def verify_git_capability(self, subject_key: str, expected_sha256: str) -> None: ...

    async def assert_preparation_unchanged(
        self,
        outcome: RepositoryPreparation,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]: ...


@dataclass(frozen=True)
class PublishedRepositoryProfile:
    profile: RepositoryProfile
    profile_ref: StoredDataRef
    selection: RepositoryExecutionSelection
    selection_ref: StoredDataRef
    work: WorkExecutionState
    integrity_receipts: tuple[ProcessReceipt, ...]


@dataclass(frozen=True)
class RepositoryProfileCall:
    workspace: CodeWorkspace
    workspace_ref: RunStoredDataRef
    preparation: RepositoryPreparation
    deadline: MonotonicActionDeadline
    git_clone_profile_ref: HostConfigurationRef
    git_checkout_profile_ref: HostConfigurationRef


class RepositoryProfileCallResolver(Protocol):
    def __call__(self, context: WorkContext) -> RepositoryProfileCall: ...


class RepositoryProfileHandler:
    """Keep profiling authority in runtime code, never in an LLM agent."""

    def __init__(
        self,
        runner: WorkflowRunner,
        profiler: RepositoryProfilerPort,
        selector: RepositoryExecutionSelectorPort,
        guard: RepositoryProfileGuard,
    ) -> None:
        self.runner = runner
        self.profiler = profiler
        self.selector = selector
        self.guard = guard

    async def execute(
        self,
        *,
        work: WorkExecutionState,
        budget_scope: BudgetScopeRef,
        identity: BudgetScopeRef,
        state_identity: BudgetScopeRef,
        workspace: CodeWorkspace,
        workspace_ref: RunStoredDataRef,
        preparation: RepositoryPreparation,
        deadline: MonotonicActionDeadline,
        git_clone_profile_ref: HostConfigurationRef,
        git_checkout_profile_ref: HostConfigurationRef,
    ) -> PublishedRepositoryProfile:
        current = self.runner.runtime.work.get(str(work.work_id))
        expected_inputs: tuple[RecordRef, ...] = (
            workspace_ref,
            *tuple(dict.fromkeys((git_clone_profile_ref, git_checkout_profile_ref))),
        )
        if (
            current != work
            or current.work_type != WorkType.REPOSITORY_PROFILE
            or current.status != "RUNNING"
            or current.active_attempt_id is None
            or not isinstance(current.meta, RecordMeta)
            or current.meta.hypothesis_id is not None
            or current.input_refs != expected_inputs
            or workspace.status != "READY"
            or workspace.commit_id is None
            or workspace_ref.data_kind != "code_workspace"
            or workspace_ref.record_id != workspace.meta.record_id
            or workspace_ref.analysis_id != current.meta.analysis_id
            or workspace.workspace_id != current.meta.workspace_id
            or workspace.commit_id != current.meta.commit_id
            or preparation.analysis_id != str(current.meta.analysis_id)
            or preparation.workspace_id != str(current.meta.workspace_id)
            or preparation.resolved_commit_id != str(current.meta.commit_id)
        ):
            raise ValueError("REPOSITORY_PROFILE_WORK_INVALID")
        attempt_id = str(current.active_attempt_id)
        clone_identity = self.selector.git_executable_identity(
            git_clone_profile_ref, "CLONE"
        )
        checkout_identity = self.selector.git_executable_identity(
            git_checkout_profile_ref, "CHECKOUT"
        )
        if clone_identity != checkout_identity:
            raise ValueError("GIT_CAPABILITY_EXECUTABLE_MISMATCH")
        self.guard.verify_git_capability(*clone_identity)
        paths = tuple(item.git_path for item in preparation.tracked_files)
        if not paths:
            self.runner.block(
                current,
                state_identity,
                "REPOSITORY_PROFILE_EMPTY_MANIFEST",
            )
            raise ValueError("REPOSITORY_PROFILE_EMPTY_MANIFEST")
        approved_timeout_ms = max(
            1, (deadline.expires_ns - deadline.started_ns) // 1_000_000
        )
        action = self.runner.action(
            current,
            identity,
            "STATIC_ANALYSIS",
            "RUN_TOOL",
            input_refs=expected_inputs,
            tool_name="repository-profiler",
            file_paths=paths,
            reason="Read the exact tracked repository manifest for profiling",
        )
        try:
            reservation = self.runner.reserve(
                current,
                budget_scope,
                action,
                self.runner.units(elapsed_ms=approved_timeout_ms, cost_minor_units=1),
            )
            decision_ref = self.runner.authorize(current, action, reservation)
        except Exception as error:
            self.runner.block(
                current,
                state_identity,
                "REPOSITORY_PROFILE_AUTHORIZATION_BLOCKED",
            )
            raise ValueError("REPOSITORY_PROFILE_BLOCKED") from error
        if not isinstance(decision_ref, StoredDataRef):
            raise ValueError("REPOSITORY_PROFILE_ACTION_INVALID")
        receipts: tuple[ProcessReceipt, ...] = ()

        async def profile_claimed(claimed_ref: RecordRef) -> RepositoryProfile:
            nonlocal receipts
            if not isinstance(claimed_ref, StoredDataRef):
                raise ValueError("REPOSITORY_PROFILE_ACTION_INVALID")
            before = await self.guard.assert_preparation_unchanged(
                preparation,
                deadline,
                attempt_id=attempt_id,
                check_id="repository-profile-before",
            )
            meta = RecordMeta.model_validate(
                self.runner.metadata(
                    current.meta,
                    "repository_profile",
                    attempt_id=current.active_attempt_id,
                )
            )
            profile = self.profiler.build(
                preparation,
                meta=meta,
                workspace_ref=workspace_ref,
                action_decision_ref=claimed_ref,
            )
            after = await self.guard.assert_preparation_unchanged(
                preparation,
                deadline,
                attempt_id=attempt_id,
                check_id="repository-profile-after",
            )
            receipts = before + after
            return profile

        started_ns = time.monotonic_ns()
        try:
            profile, _ = await self.runner.runtime.external.invoke_bound(
                str(current.work_id),
                decision_ref,
                self.runner.runtime.unit_of_work.records.stage_record(reservation),
                profile_claimed,
                idempotency_key=str(action.action_id),
            )
        except Exception as error:
            self.runner.block(
                self.runner.runtime.work.get(str(current.work_id)),
                state_identity,
                "REPOSITORY_PROFILE_INPUT_CHANGED",
            )
            raise ValueError("REPOSITORY_PROFILE_BLOCKED") from error
        elapsed_ms = max(1, (time.monotonic_ns() - started_ns) // 1_000_000)
        self.runner.account(
            reservation,
            self.runner.units(elapsed_ms=elapsed_ms, cost_minor_units=1),
        )
        candidate_profile_ref = reference(profile)
        if not isinstance(candidate_profile_ref, StoredDataRef):
            raise ValueError("REPOSITORY_PROFILE_REFERENCE_INVALID")
        selection = self.selector.select(
            profile,
            meta=RecordMeta.model_validate(
                self.runner.metadata(
                    current.meta,
                    "repository_execution_selection",
                    attempt_id=current.active_attempt_id,
                )
            ),
            repository_profile_ref=candidate_profile_ref,
            git_clone_profile_ref=git_clone_profile_ref,
            git_checkout_profile_ref=git_checkout_profile_ref,
        )
        target_status = {
            "READY": "SUCCEEDED",
            "BLOCKED": "BLOCKED",
            "FAILED": "FAILED",
        }[selection.status]
        try:
            completed = self.runner.complete(
                current,
                identity,
                "STATIC_ANALYSIS",
                (profile, selection),
                status=target_status,
                cause=(
                    "COMPLETED"
                    if target_status == "SUCCEEDED"
                    else (
                        "REPOSITORY_CAPABILITY_SELECTION_FAILED"
                        if target_status == "FAILED"
                        else "REPOSITORY_CONFIRMATION_REQUIRED"
                    )
                ),
                gap_ids=tuple(str(item.gap_id) for item in selection.gaps),
                error_ids=tuple(str(item.error_id) for item in selection.errors),
                action_input_refs=expected_inputs,
            )
        except Exception as error:
            self.runner.block(
                self.runner.runtime.work.get(str(current.work_id)),
                state_identity,
                "REPOSITORY_PROFILE_PUBLICATION_BLOCKED",
            )
            raise ValueError("REPOSITORY_PROFILE_BLOCKED") from error
        profile_ref = completed.output_refs[0]
        selection_ref = completed.output_refs[1]
        if not isinstance(profile_ref, StoredDataRef) or not isinstance(
            selection_ref, StoredDataRef
        ):
            raise ValueError("REPOSITORY_PROFILE_REFERENCE_INVALID")
        return PublishedRepositoryProfile(
            profile,
            profile_ref,
            selection,
            selection_ref,
            completed,
            receipts,
        )


@dataclass(frozen=True)
class RepositoryProfileWorkHandler:
    """T14-facing adapter for one already-claimed profile work attempt."""

    service: RepositoryProfileHandler
    resolve_call: RepositoryProfileCallResolver
    budget_scope_ref: BudgetScopeRef
    requester_identity_ref: BudgetScopeRef
    state_identity_ref: BudgetScopeRef

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        work, attempt = context.work, context.attempt
        if (
            work.work_type != WorkType.REPOSITORY_PROFILE
            or work.status != WorkStatus.RUNNING
            or attempt.status != AttemptStatus.RUNNING
            or work.active_attempt_id is None
            or work.active_attempt_id != attempt.attempt_id
            or work.work_id != attempt.work_id
            or work.input_hash != attempt.input_hash
            or work.input_hash != content_hash(work.input_refs)
            or not isinstance(work.meta, RecordMeta)
            or not isinstance(attempt.meta, RecordMeta)
            or work.meta.analysis_id != attempt.meta.analysis_id
            or work.meta.workspace_id != attempt.meta.workspace_id
            or work.meta.commit_id != attempt.meta.commit_id
        ):
            raise ValueError("WORK_CONTEXT_NOT_CURRENT")
        call = self.resolve_call(context)
        expected_inputs: tuple[RecordRef, ...] = (
            call.workspace_ref,
            *tuple(
                dict.fromkeys(
                    (call.git_clone_profile_ref, call.git_checkout_profile_ref)
                )
            ),
        )
        if work.input_refs != expected_inputs:
            raise ValueError("REPOSITORY_PROFILE_WORK_INVALID")
        completed = await self.service.execute(
            work=work,
            budget_scope=self.budget_scope_ref,
            identity=self.requester_identity_ref,
            state_identity=self.state_identity_ref,
            workspace=call.workspace,
            workspace_ref=call.workspace_ref,
            preparation=call.preparation,
            deadline=call.deadline,
            git_clone_profile_ref=call.git_clone_profile_ref,
            git_checkout_profile_ref=call.git_checkout_profile_ref,
        )
        return WorkHandlerResult(
            completed.work.output_refs,
            action_input_refs=expected_inputs,
        )


__all__ = [
    "PublishedRepositoryProfile",
    "RepositoryProfileCall",
    "RepositoryProfileCallResolver",
    "RepositoryProfileGuard",
    "RepositoryProfileHandler",
    "RepositoryProfileWorkHandler",
]
