"""Read-side currentness of candidate finding and report projections."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

from .artifacts import SimpleArtifactRepository
from .models import SimpleAnalysisRun, SimpleStage, StageCheckpoint, StageStatus
from .run_lease import analysis_run_lease_active
from .store import SimpleCheckpointStore

ScopeKey = tuple[str, str, str]


def candidate_integrity_blocked_scopes(
    candidate_pipeline_version: int | None,
    checkpoints: Iterable[StageCheckpoint],
) -> frozenset[ScopeKey]:
    """Return exact candidate scopes whose root rejects hypothesis provenance."""

    if candidate_pipeline_version not in {1, 2}:
        return frozenset()
    return frozenset(
        (
            item.identity.analysis_id,
            item.identity.workspace_id,
            item.identity.commit_id,
        )
        for item in checkpoints
        if item.identity.hypothesis_id is None
        and item.stage is SimpleStage.HYPOTHESIS_DONE
        and item.status in {StageStatus.BLOCKED, StageStatus.FAILED}
        and item.error_code == "HYPOTHESIS_EVIDENCE_INVALID"
    )


def candidate_report_integrity_blocked(
    run: SimpleAnalysisRun | None, checkpoints: Iterable[StageCheckpoint]
) -> bool:
    """A rejected root hypothesis provenance invalidates prior child results."""

    if run is None:
        return False
    return (run.analysis_id, run.workspace_id, run.commit_id) in (
        candidate_integrity_blocked_scopes(run.candidate_pipeline_version, checkpoints)
    )


def candidate_report_currentness_blocked(
    run: SimpleAnalysisRun | None,
    checkpoints: Iterable[StageCheckpoint],
    *,
    data_dir: Path,
    store: SimpleCheckpointStore,
) -> bool:
    """Withhold candidate results when resume cannot audit saved provenance."""

    values = tuple(checkpoints)
    if candidate_report_integrity_blocked(run, values):
        return True
    if run is None or run.candidate_pipeline_version not in {1, 2}:
        return False
    if analysis_run_lease_active(data_dir, run.analysis_id) is True:
        return False
    try:
        if store.unresolved_codex_call(run.analysis_id) is not None:
            return True
    except (OSError, ValueError, sqlite3.Error):
        return True

    scope = (run.analysis_id, run.workspace_id, run.commit_id)
    root_codex_pending = next(
        (
            checkpoint
            for checkpoint in values
            if (
                checkpoint.identity.analysis_id,
                checkpoint.identity.workspace_id,
                checkpoint.identity.commit_id,
            )
            == scope
            and checkpoint.identity.hypothesis_id is None
            and checkpoint.stage is SimpleStage.HYPOTHESIS_DONE
            and checkpoint.status in {StageStatus.BLOCKED, StageStatus.FAILED}
            and (checkpoint.error_code or "").startswith(
                "CANDIDATE_CHILD_CODEX_STATE_PENDING"
            )
        ),
        None,
    )
    if root_codex_pending is not None:
        marker_parts = (root_codex_pending.error_code or "").split(":", 2)
        child_id = marker_parts[1] if len(marker_parts) == 3 else ""
        attempt_id = marker_parts[2] if len(marker_parts) == 3 else ""
        if not any(
            child_id
            and attempt_id
            and checkpoint.identity.hypothesis_id == child_id
            and checkpoint.identity.workspace_id == run.workspace_id
            and checkpoint.identity.commit_id == run.commit_id
            and checkpoint.attempt_id == attempt_id
            and checkpoint.status in {StageStatus.BLOCKED, StageStatus.FAILED}
            and checkpoint.error_code
            in {"CODEX_CALL_IN_FLIGHT_UNRESOLVED", "CODEX_PROCESS_CLEANUP_UNCONFIRMED"}
            for checkpoint in values
        ):
            return True

    for checkpoint in values:
        if (
            (
                checkpoint.identity.analysis_id,
                checkpoint.identity.workspace_id,
                checkpoint.identity.commit_id,
            )
            != scope
            or checkpoint.status not in {StageStatus.BLOCKED, StageStatus.FAILED}
            or checkpoint.error_code != "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
        ):
            continue
        try:
            confirmed = store.has_codex_cleanup_confirmation(
                checkpoint,
                SimpleArtifactRepository(data_dir, checkpoint.identity),
            )
        except (LookupError, OSError, ValueError, sqlite3.Error):
            return True
        if not confirmed:
            return True
    return False
