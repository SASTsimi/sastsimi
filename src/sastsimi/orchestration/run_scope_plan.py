"""Allocate the immutable identity scope used by one production analysis run."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.ports.dto import RepositoryPreparation
from sastsimi.ports.id_generator import IdGenerator

_EXACT_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class PlannedRunScope:
    """Identity allocated before checkout and never mutated afterward."""

    analysis_id: AnalysisId
    workspace_id: WorkspaceId
    commit_id: CommitId
    repository_ref: str


class ProductionRunScopeAllocator:
    """Create one isolated scope and bind it to the exact checkout receipt."""

    def __init__(self, ids: IdGenerator) -> None:
        self._ids = ids

    def allocate(self, request: AnalysisStartRequest) -> PlannedRunScope:
        commit = request.requested_git_ref.lower()
        if _EXACT_COMMIT.fullmatch(commit) is None:
            raise ValueError("EXACT_COMMIT_REQUIRED")
        return PlannedRunScope(
            analysis_id=self._ids.new(AnalysisId),
            workspace_id=self._ids.new(WorkspaceId),
            commit_id=CommitId(commit),
            repository_ref=str(request.repository_ref),
        )

    def require_checkout(
        self,
        scope: PlannedRunScope,
        checkout: RepositoryPreparation,
    ) -> None:
        """Reject a checkout receipt that does not prove the allocated scope."""

        expected_commit = str(scope.commit_id)
        if (
            checkout.status != "READY"
            or checkout.analysis_id != str(scope.analysis_id)
            or checkout.workspace_id != str(scope.workspace_id)
            or checkout.requested_ref.lower() != expected_commit
            or checkout.resolved_commit_id is None
            or checkout.resolved_commit_id.lower() != expected_commit
            or checkout.root is None
            or checkout.lease_id is None
        ):
            raise ValueError("CHECKOUT_SCOPE_MISMATCH")


__all__ = ["PlannedRunScope", "ProductionRunScopeAllocator"]
