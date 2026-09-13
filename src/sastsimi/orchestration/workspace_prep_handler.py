"""Production WORKSPACE_PREP handler with exact durable input recovery."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sastsimi.contracts.analysis import AnalysisRunInput
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import WorkspaceId
from sastsimi.contracts.records import RunMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    RunStoredDataRef,
    reference,
)
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import AttemptStatus, WorkStatus, WorkType
from sastsimi.orchestration.static_external_runner import (
    RepositoryLoaderPort,
    StaticExternalRunner,
)
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.runtime.workflow_runner import WorkflowRunner


@dataclass(frozen=True, slots=True)
class WorkspacePrepCall:
    run_input: AnalysisRunInput
    policy_ref: RunStoredDataRef
    git_clone_profile_ref: HostConfigurationRef | None
    git_checkout_profile_ref: HostConfigurationRef | None
    recovery_workspace_id: WorkspaceId | None


class ExactWorkspacePrepCallResolver:
    """Resolve one call only from the current run input and work revision."""

    def __init__(self, runner: WorkflowRunner) -> None:
        self._runner = runner

    def __call__(self, context: WorkContext) -> WorkspacePrepCall:
        work, attempt = context.work, context.attempt
        runtime = self._runner.runtime
        current = runtime.work.get(str(work.work_id))
        attempts = runtime.work.store.attempts_for_work(str(work.work_id))
        latest_attempt = attempts[-1] if attempts else None
        if (
            current != work
            or latest_attempt != attempt
            or work.work_type != WorkType.WORKSPACE_PREP
            or work.status != WorkStatus.RUNNING
            or attempt.status != AttemptStatus.RUNNING
            or work.active_attempt_id is None
            or work.active_attempt_id != attempt.attempt_id
            or work.work_id != attempt.work_id
            or work.input_hash != attempt.input_hash
            or work.input_hash != content_hash(work.input_refs)
            or not isinstance(work.meta, RunMeta)
            or not isinstance(attempt.meta, RunMeta)
            or work.meta.analysis_id != attempt.meta.analysis_id
        ):
            raise ValueError("WORKSPACE_PREP_CONTEXT_INVALID")

        analysis_id = str(work.meta.analysis_id)
        state = runtime.budget_registry.current_state(analysis_id)
        run_input = runtime.budget_registry.current_input(analysis_id)
        input_ref = reference(run_input)
        policies = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, RunStoredDataRef)
            and ref.data_kind == "artifact"
            and ref.record_id is None
        )
        git_refs = tuple(
            ref for ref in work.input_refs if isinstance(ref, HostConfigurationRef)
        )
        if (
            not isinstance(input_ref, RunStoredDataRef)
            or len(policies) != 1
            or len(git_refs) not in {0, 1, 2}
            or work.input_refs != (input_ref, policies[0], *git_refs)
            or input_ref != state.analysis_input_ref
            or run_input.meta.analysis_id != state.meta.analysis_id
            or run_input.program_id != state.program_id
            or run_input.purpose != state.purpose
            or not re.fullmatch(
                r"[0-9a-f]{40}|[0-9a-f]{64}", run_input.requested_git_ref
            )
        ):
            raise ValueError("WORKSPACE_PREP_INPUT_MISMATCH")

        recovery_workspace_id: WorkspaceId | None = None
        if state.workspace_ref is None:
            if state.workspace_id is not None or state.commit_id is not None:
                raise ValueError("WORKSPACE_PREP_STATE_INVALID")
        else:
            workspace = runtime.unit_of_work.records.get_exact(state.workspace_ref)
            if (
                not isinstance(workspace, CodeWorkspace)
                or workspace.status != "PREPARING"
                or state.workspace_id != workspace.workspace_id
                or state.commit_id is not None
                or workspace.commit_id is not None
                or str(workspace.analysis_id) != analysis_id
            ):
                raise ValueError("WORKSPACE_PREP_STATE_INVALID")
            recovery_workspace_id = workspace.workspace_id

        return WorkspacePrepCall(
            run_input=run_input,
            policy_ref=policies[0],
            git_clone_profile_ref=git_refs[0] if git_refs else None,
            git_checkout_profile_ref=git_refs[-1] if git_refs else None,
            recovery_workspace_id=recovery_workspace_id,
        )


@dataclass(frozen=True)
class WorkspacePrepWorkHandler:
    external: StaticExternalRunner
    loader: RepositoryLoaderPort
    resolve_call: ExactWorkspacePrepCallResolver
    requester_identity_ref: BudgetScopeRef
    workspace_id: WorkspaceId
    timeout_ms: int

    def __post_init__(self) -> None:
        if self.timeout_ms <= 0:
            raise ValueError("WORKSPACE_PREP_TIMEOUT_INVALID")

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        call = self.resolve_call(context)
        if (
            call.recovery_workspace_id is not None
            and call.recovery_workspace_id != self.workspace_id
        ):
            raise ValueError("WORKSPACE_PREP_SCOPE_MISMATCH")
        if call.recovery_workspace_id is None:
            completed = await self.external.prepare_repository(
                work=context.work,
                budget_scope=self.external.runner.runtime.work.registration_scope(
                    str(context.work.work_id)
                ),
                identity=self.requester_identity_ref,
                workspace_id=self.workspace_id,
                submitted_source=call.run_input.repository_ref,
                requested_ref=call.run_input.requested_git_ref,
                policy_ref=call.policy_ref,
                timeout_ms=self.timeout_ms,
                loader=self.loader,
                git_clone_profile_ref=call.git_clone_profile_ref,
                git_checkout_profile_ref=call.git_checkout_profile_ref,
            )
        else:
            completed = await self.external.recover_repository(
                work=context.work,
                identity=self.requester_identity_ref,
                policy_ref=call.policy_ref,
            )
        if (
            completed.workspace.workspace_id != self.workspace_id
            or completed.workspace.analysis_id != context.work.meta.analysis_id
            or (
                completed.workspace.status == "READY"
                and str(completed.workspace.commit_id)
                != call.run_input.requested_git_ref
            )
        ):
            raise ValueError("WORKSPACE_PREP_SCOPE_MISMATCH")
        return WorkHandlerResult(
            completed.work.output_refs,
            action_input_refs=context.work.input_refs,
        )


__all__ = [
    "ExactWorkspacePrepCallResolver",
    "WorkspacePrepCall",
    "WorkspacePrepWorkHandler",
]
