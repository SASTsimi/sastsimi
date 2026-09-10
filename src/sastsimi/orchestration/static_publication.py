"""Trusted application-side publication for the exact workspace lifecycle."""

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import ErrorId, WorkspaceId
from sastsimi.contracts.refs import BudgetScopeRef, RunStoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import PublishedWorkspaceMaterial, RepositoryPreparation
from sastsimi.runtime.workflow_runner import WorkflowRunner


class WorkspacePreparationPublisher:
    """Own metadata, persistence and terminal transition for repository loading."""

    def __init__(self, runner: WorkflowRunner, identity: BudgetScopeRef) -> None:
        self.runner = runner
        self.identity = identity

    def begin(
        self,
        work: WorkExecutionState,
        repository_url: str,
        workspace_id: WorkspaceId,
    ) -> PublishedWorkspaceMaterial:
        if work.status != "RUNNING" or work.active_attempt_id is None:
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        workspace = CodeWorkspace.model_validate_json(
            canonical_bytes(
                {
                    "meta": self.runner.metadata(work.meta, "code_workspace"),
                    "workspace_id": workspace_id,
                    "analysis_id": work.meta.analysis_id,
                    "repository_url": repository_url,
                    "commit_id": None,
                    "status": "PREPARING",
                }
            )
        )
        (workspace_ref,) = self.runner.publish_intermediate(
            work, self.identity, "REPOSITORY_LOADER", (workspace,)
        )
        if not isinstance(workspace_ref, RunStoredDataRef):
            raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
        return PublishedWorkspaceMaterial(
            workspace=workspace,
            workspace_ref=workspace_ref,
            work=self.runner.runtime.work.get(str(work.work_id)),
            analysis_state=self.runner.runtime.budget_registry.current_state(
                str(work.meta.analysis_id)
            ),
        )

    def finish(
        self,
        work: WorkExecutionState,
        preparing: PublishedWorkspaceMaterial,
        outcome: RepositoryPreparation,
    ) -> PublishedWorkspaceMaterial:
        current = self.runner.runtime.work.get(str(work.work_id))
        if (
            current != preparing.work
            or current.status != "RUNNING"
            or preparing.workspace.status != "PREPARING"
            or preparing.workspace_ref != reference(preparing.workspace)
            or str(preparing.workspace.analysis_id) != outcome.analysis_id
            or str(preparing.workspace.workspace_id) != outcome.workspace_id
            or preparing.workspace.repository_url != outcome.repository_url
        ):
            raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
        terminal = CodeWorkspace.model_validate_json(
            canonical_bytes(
                {
                    "meta": self.runner.revision_metadata(preparing.workspace.meta),
                    "workspace_id": preparing.workspace.workspace_id,
                    "analysis_id": preparing.workspace.analysis_id,
                    "repository_url": preparing.workspace.repository_url,
                    "commit_id": outcome.resolved_commit_id,
                    "status": outcome.status,
                }
            )
        )
        if outcome.status == "READY":
            completed = self.runner.complete(
                current,
                self.identity,
                "REPOSITORY_LOADER",
                (terminal,),
            )
        else:
            error_ids = tuple(
                str(self.runner.ids.new(ErrorId)) for _ in (outcome.errors or (None,))
            )
            completed = self.runner.complete(
                current,
                self.identity,
                "REPOSITORY_LOADER",
                (terminal,),
                status="FAILED",
                cause="REPOSITORY_PREPARATION_FAILED",
                error_ids=error_ids,
            )
        terminal_ref = reference(terminal)
        if not isinstance(terminal_ref, RunStoredDataRef):
            raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
        return PublishedWorkspaceMaterial(
            workspace=terminal,
            workspace_ref=terminal_ref,
            work=completed,
            analysis_state=self.runner.runtime.budget_registry.current_state(
                str(work.meta.analysis_id)
            ),
        )
