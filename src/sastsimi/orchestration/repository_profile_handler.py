"""Production handler for guarded repository detection and durable publication."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.static import CodeWorkspace, RepositoryProfile
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
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.repository_profile import RepositoryProfiler


class RepositoryProfileGuard(Protocol):
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
    work: WorkExecutionState
    integrity_receipts: tuple[ProcessReceipt, ...]


@dataclass(frozen=True)
class RepositoryProfileCall:
    workspace: CodeWorkspace
    workspace_ref: RunStoredDataRef
    preparation: RepositoryPreparation
    deadline: MonotonicActionDeadline


class RepositoryProfileCallResolver(Protocol):
    def __call__(self, context: WorkContext) -> RepositoryProfileCall: ...


class RepositoryProfileHandler:
    """Keep profiling authority in runtime code, never in an LLM agent."""

    def __init__(
        self,
        runner: WorkflowRunner,
        profiler: RepositoryProfiler,
        guard: RepositoryProfileGuard,
    ) -> None:
        self.runner = runner
        self.profiler = profiler
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
    ) -> PublishedRepositoryProfile:
        current = self.runner.runtime.work.get(str(work.work_id))
        if (
            current != work
            or current.work_type != WorkType.REPOSITORY_PROFILE
            or current.status != "RUNNING"
            or current.active_attempt_id is None
            or not isinstance(current.meta, RecordMeta)
            or current.meta.hypothesis_id is not None
            or current.input_refs != (workspace_ref,)
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
            input_refs=(workspace_ref,),
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
        try:
            completed = self.runner.complete(
                current,
                identity,
                "STATIC_ANALYSIS",
                (profile,),
                status=("SUCCEEDED" if profile.status == "READY" else "BLOCKED"),
                cause=(
                    "COMPLETED"
                    if profile.status == "READY"
                    else "REPOSITORY_CONFIRMATION_REQUIRED"
                ),
                action_input_refs=(workspace_ref,),
            )
        except Exception as error:
            self.runner.block(
                self.runner.runtime.work.get(str(current.work_id)),
                state_identity,
                "REPOSITORY_PROFILE_PUBLICATION_BLOCKED",
            )
            raise ValueError("REPOSITORY_PROFILE_BLOCKED") from error
        profile_ref = completed.output_refs[0]
        if not isinstance(profile_ref, StoredDataRef):
            raise ValueError("REPOSITORY_PROFILE_REFERENCE_INVALID")
        return PublishedRepositoryProfile(profile, profile_ref, completed, receipts)


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
        if work.input_refs != (call.workspace_ref,):
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
        )
        return WorkHandlerResult(
            completed.work.output_refs,
            action_input_refs=(call.workspace_ref,),
        )


__all__ = [
    "PublishedRepositoryProfile",
    "RepositoryProfileCall",
    "RepositoryProfileCallResolver",
    "RepositoryProfileGuard",
    "RepositoryProfileHandler",
    "RepositoryProfileWorkHandler",
]
