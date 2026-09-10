"""Attempt-owned workspace storage and immutable workspace lookup ports."""

from pathlib import Path
from typing import Protocol

from sastsimi.contracts.ids import WorkspaceId
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import WorkExecutionState

from .dto import (
    MonotonicActionDeadline,
    PublishedWorkspaceMaterial,
    RepositoryPreparation,
    WorkspaceStorageLease,
    WorkspaceStoragePolicy,
    WorkspaceStorageUsage,
)


class WorkspaceStoragePort(Protocol):
    def allocate(
        self,
        *,
        attempt_id: str,
        workspace_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
    ) -> WorkspaceStorageLease: ...

    def measure(self, lease: WorkspaceStorageLease) -> WorkspaceStorageUsage: ...
    def seal(self, lease: WorkspaceStorageLease, reason: str) -> None: ...
    def cleanup_or_quarantine(self, lease: WorkspaceStorageLease) -> None: ...


class WorkspaceLocatorPort(Protocol):
    def root_for(self, workspace: CodeWorkspace) -> Path: ...

    async def assert_unchanged(
        self, workspace: CodeWorkspace, deadline: MonotonicActionDeadline
    ) -> None: ...


class WorkspacePreparationPublisherPort(Protocol):
    def begin(
        self,
        work: WorkExecutionState,
        repository_url: str,
        workspace_id: WorkspaceId,
    ) -> PublishedWorkspaceMaterial: ...

    def finish(
        self,
        work: WorkExecutionState,
        preparing: PublishedWorkspaceMaterial,
        outcome: RepositoryPreparation,
    ) -> PublishedWorkspaceMaterial: ...
