"""Read the exact current workspace scope for a durable analysis run."""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import ValidationError

from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.storage.database import Database
from sastsimi.storage.run_states import get_run


class RunScopeError(ValueError):
    """Safe failure raised when a reusable exact run scope is unavailable."""


@dataclass(frozen=True, slots=True)
class RunScope:
    analysis_id: AnalysisId
    workspace_id: WorkspaceId
    commit_id: CommitId


class RunScopeLocator:
    """Resolve only the current AnalysisRunState stored in SQLite."""

    def __init__(self, database: Database) -> None:
        database.check_ready()
        self._database = database

    def locate(
        self,
        analysis_id: str,
        *,
        expected_workspace_id: WorkspaceId | None = None,
        expected_commit_id: CommitId | None = None,
    ) -> RunScope:
        if (
            not analysis_id
            or analysis_id != analysis_id.strip()
            or (expected_workspace_id is None) != (expected_commit_id is None)
        ):
            raise RunScopeError("RUN_SCOPE_INPUT_INVALID")
        try:
            with self._database.engine.connect() as connection:
                state = get_run(connection, analysis_id)
        except (LookupError, ValueError, ValidationError):
            raise RunScopeError("RUN_SCOPE_NOT_FOUND") from None
        if (
            str(state.meta.analysis_id) != analysis_id
            or state.workspace_id is None
            or state.commit_id is None
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(state.commit_id))
            is None
        ):
            raise RunScopeError("RUN_SCOPE_NOT_READY")
        scope = RunScope(state.meta.analysis_id, state.workspace_id, state.commit_id)
        if expected_workspace_id is not None and (
            scope.workspace_id != expected_workspace_id
            or scope.commit_id != expected_commit_id
        ):
            raise RunScopeError("RUN_SCOPE_STALE")
        return scope


__all__ = ["RunScope", "RunScopeError", "RunScopeLocator"]
