"""Read-side currentness of candidate finding and report projections."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import TypedDict

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import surface_index_from_json
from .models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from .run_lease import analysis_run_lease_active
from .store import SimpleCheckpointStore
from .surface_proof_read import (
    read_surface_scope_certificate,
    verified_surface_coverage_counts,
)

ScopeKey = tuple[str, str, str]
_MAX_SURFACE_OBJECT = 16 * 1024 * 1024


class SurfaceReportBinding(TypedDict, total=False):
    current_surface_proof_version: int
    current_surface_hash: str


def current_surface_report_binding(
    run: SimpleAnalysisRun,
    checkpoints: Iterable[StageCheckpoint],
    *,
    data_dir: Path,
    store: SimpleCheckpointStore,
) -> SurfaceReportBinding:
    """Bind a published report to the exact pinned successor proof, if any."""

    if run.surface_enrichment_v11_plan_ref is None:
        return {}
    terminal = run.candidate_terminal
    if (
        terminal is None
        or terminal.surface_proof_version != 9
        or terminal.status not in {"PARTIAL", "COMPLETE"}
        or run.surface_enrichment_status not in {"PARTIAL", "COMPLETE"}
        or not terminal.surface_coverage_hash
    ):
        raise ValueError("REPORT_SURFACE_PROOF_STALE")
    if not run.candidate_scope_fingerprint or not terminal.surface_index_hash:
        raise ValueError("REPORT_SURFACE_PROOF_STALE")
    identity = CheckpointIdentity(
        analysis_id=run.analysis_id,
        workspace_id=run.workspace_id,
        commit_id=run.commit_id,
        hypothesis_id=None,
    )
    try:
        artifacts = SimpleArtifactRepository(data_dir, identity, create_dirs=False)
        index_record = store.get_attack_surface_index(
            identity, run.candidate_scope_fingerprint
        )
        if (
            index_record is None
            or index_record.index_ref.content_hash != terminal.surface_index_hash
        ):
            raise ValueError("surface index unavailable")
        index = surface_index_from_json(
            json.loads(
                artifacts.read_bounded(index_record.index_ref, _MAX_SURFACE_OBJECT)
            )
        )
        refs = (
            ref
            for checkpoint in checkpoints
            if checkpoint.identity == identity
            and checkpoint.stage is SimpleStage.HYPOTHESIS_DONE
            and checkpoint.status is StageStatus.SUCCEEDED
            for ref in checkpoint.output_refs
            if ref.content_hash == terminal.surface_coverage_hash
        )
        coverage_ref = next(refs, None)
        if coverage_ref is None:
            coverage_ref = next(
                (
                    ref
                    for checkpoint in store.list_checkpoints(run.analysis_id)
                    if checkpoint.identity == identity
                    and checkpoint.stage is SimpleStage.HYPOTHESIS_DONE
                    and checkpoint.status is StageStatus.SUCCEEDED
                    for ref in checkpoint.output_refs
                    if ref.content_hash == terminal.surface_coverage_hash
                ),
                None,
            )
        if coverage_ref is None:
            raise ValueError("surface proof unavailable")
        proof = json.loads(artifacts.read_bounded(coverage_ref, _MAX_SURFACE_OBJECT))
        certificate = read_surface_scope_certificate(
            artifacts,
            run.python_scope_certificate_ref,
            run.static_coverage_ref,
            terminal,
        )
        counts = verified_surface_coverage_counts(
            proof,
            index,
            terminal,
            certificate_payload=certificate,
            artifacts=artifacts,
            coverage_ref=coverage_ref,
            store=store,
        )
        if counts is None:
            raise ValueError("surface proof invalid")
    except (OSError, ValueError, TypeError, LookupError, sqlite3.Error) as error:
        raise ValueError("REPORT_SURFACE_PROOF_STALE") from error
    return {
        "current_surface_proof_version": 9,
        "current_surface_hash": terminal.surface_coverage_hash,
    }


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
    if (
        run is not None
        and run.surface_enrichment_v11_plan_ref is not None
        and (
            run.candidate_terminal is None
            or run.candidate_terminal.surface_proof_version != 9
            or run.candidate_terminal.status not in {"PARTIAL", "COMPLETE"}
            or run.surface_enrichment_status not in {"PARTIAL", "COMPLETE"}
        )
    ):
        return True
    if run is not None and run.surface_enrichment_v11_plan_ref is not None:
        try:
            current_surface_report_binding(run, values, data_dir=data_dir, store=store)
        except ValueError:
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
