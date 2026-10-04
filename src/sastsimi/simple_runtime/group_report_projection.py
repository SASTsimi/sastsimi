"""Read-only currentness gate for verified same-flow report archives."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from functools import partial
from pathlib import Path

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.bundle_files import MAX_BUNDLE_FILE_BYTES, read_bundle_file
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.reporting.grouped_bundle import (
    GroupBundleUnavailable,
    GroupSourceBundle,
    build_group_bundle,
)

from .artifacts import SimpleArtifactRepository
from .finding_group_projection import project_current_finding_groups
from .finding_groups import FindingGroup, FindingGroupProjection
from .models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from .report_currentness import candidate_report_integrity_blocked
from .scope_policy import project_scope_review, safe_public_report


def _read_only_artifact_reader(
    data_dir: Path, identity: CheckpointIdentity
) -> SimpleArtifactRepository:
    """Require existing CAS directories before invoking the creating constructor."""

    paths = RuntimePaths(data_dir)
    if not all(
        path.is_dir()
        for path in (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    ):
        raise GroupBundleUnavailable("GROUP_ARTIFACT_STORE_UNAVAILABLE")
    return SimpleArtifactRepository(data_dir, identity)


def _current_display_refs(
    run: SimpleAnalysisRun,
    checkpoints: Sequence[StageCheckpoint],
    database_path: Path,
) -> dict[str, StoredDataRef]:
    current = {
        (item.identity, item.output_refs[0]): item
        for item in checkpoints
        if item.stage is SimpleStage.FINDING_DONE
        and item.status is StageStatus.SUCCEEDED
        and len(item.output_refs) == 1
        and item.identity.analysis_id == run.analysis_id
        and item.identity.workspace_id == run.workspace_id
        and item.identity.commit_id == run.commit_id
    }
    reports = {
        item.identity: item
        for item in checkpoints
        if item.stage is SimpleStage.REPORT_DONE
        and item.status is StageStatus.SUCCEEDED
        and item.identity.analysis_id == run.analysis_id
        and item.identity.workspace_id == run.workspace_id
        and item.identity.commit_id == run.commit_id
    }
    result: dict[str, StoredDataRef] = {}
    with sqlite3.connect(
        f"file:{database_path.resolve(strict=True).as_posix()}?mode=ro", uri=True
    ) as connection:
        rows = connection.execute(
            "SELECT display_number, finding_ref_json FROM finding_display_ids "
            "WHERE analysis_id = ? ORDER BY display_number",
            (run.analysis_id,),
        ).fetchall()
    for number, ref_json in rows:
        display_id = f"F-{number:03d}"
        finding_ref = StoredDataRef.model_validate_json(ref_json)
        if (
            FindingDisplayIdStore.resolve_existing(
                database_path, run.analysis_id, display_id
            )
            != finding_ref
        ):
            raise GroupBundleUnavailable("GROUP_DISPLAY_REFERENCE_INVALID")
        matched = [
            item
            for (identity, ref), item in current.items()
            if ref == finding_ref
            and identity in reports
            and finding_ref in reports[identity].input_refs
        ]
        if len(matched) == 1:
            result[display_id] = finding_ref
    return result


def current_report_groups(
    run: SimpleAnalysisRun,
    checkpoints: Sequence[StageCheckpoint],
    *,
    data_dir: Path,
    database_path: Path,
) -> FindingGroupProjection:
    """One read-only grouping projection for CLI and dashboard consumers."""

    if candidate_report_integrity_blocked(run, checkpoints):
        raise GroupBundleUnavailable("GROUP_NOT_CURRENT")
    eligible = _current_display_refs(run, checkpoints, database_path)
    return project_current_finding_groups(
        run,
        checkpoints,
        eligible,
        data_dir=data_dir,
        database_path=database_path,
    )


def current_group_bundle(
    run: SimpleAnalysisRun,
    checkpoints: Sequence[StageCheckpoint],
    group: FindingGroup,
    *,
    data_dir: Path,
    database_path: Path,
    _current_projection: FindingGroupProjection | None = None,
) -> bytes:
    """Verify member bundles; optionally reuse this request's trusted group snapshot.

    Only the outputs-tab caller supplies ``_current_projection`` after calling
    ``current_report_groups`` with these same run/checkpoints. Independent
    download requests omit it and reproject before serving bytes.
    """

    if (
        group.status != "PROVEN_SAME_FLOW"
        or len(group.member_ids) < 2
        or candidate_report_integrity_blocked(run, checkpoints)
    ):
        raise GroupBundleUnavailable("GROUP_NOT_CURRENT")
    try:
        if _current_projection is None:
            eligible = _current_display_refs(run, checkpoints, database_path)
            if any(member_id not in eligible for member_id in group.member_ids):
                raise GroupBundleUnavailable("GROUP_MEMBER_STALE")
            projected = project_current_finding_groups(
                run,
                checkpoints,
                eligible,
                data_dir=data_dir,
                database_path=database_path,
            )
        else:
            projected = _current_projection
        exact = next(
            (item for item in projected.groups if item.group_id == group.group_id),
            None,
        )
        if exact is None or exact != group or exact.status != "PROVEN_SAME_FLOW":
            raise GroupBundleUnavailable("GROUP_NOT_CURRENT")
    except (LookupError, OSError, ValueError, sqlite3.Error) as error:
        if isinstance(error, GroupBundleUnavailable):
            raise
        raise GroupBundleUnavailable("GROUP_NOT_CURRENT") from error

    sources: list[GroupSourceBundle] = []
    for member in exact.members:
        identity = next(
            (
                item.identity
                for item in checkpoints
                if item.stage is SimpleStage.FINDING_DONE
                and member.finding_ref in item.output_refs
            ),
            None,
        )
        if identity is None:
            raise GroupBundleUnavailable("GROUP_MEMBER_STALE")
        stages = {item.stage: item for item in checkpoints if item.identity == identity}
        artifacts = _read_only_artifact_reader(data_dir, identity)
        report = stages.get(SimpleStage.REPORT_DONE)
        review = project_scope_review(
            stages.get(SimpleStage.SCOPE_GATE_DONE),
            artifacts,
            policy_snapshot_ref=run.policy_snapshot_ref,
            repository_url=run.repository,
        )
        try:
            if report is None:
                raise ValueError("missing report")
            artifacts.require_current_report_coverage(
                report,
                member.finding_ref,
                run.static_coverage_ref,
                run.static_disposition,
            )
            manifest, _archive = artifacts.verified_report_bundle(
                checkpoints=stages,
                finding_ref=member.finding_ref,
                display_id=member.display_id,
                scope_status=str(review["status"]),
                public_projection=partial(safe_public_report, review=review),
            )
            files = {
                entry.path: read_bundle_file(
                    manifest,
                    entry.path,
                    partial(artifacts.read_bounded, max_bytes=MAX_BUNDLE_FILE_BYTES),
                )[0]
                for entry in manifest.files
            }
            provenance = json.loads(files["evidence/provenance.json"])
            if (
                not isinstance(provenance, dict)
                or provenance.get("analysis_id") != run.analysis_id
                or provenance.get("tested_commit") != run.commit_id
                or provenance.get("repository") != run.repository
            ):
                raise ValueError("stale provenance")
        except (KeyError, OSError, ValueError, TypeError) as error:
            raise GroupBundleUnavailable("GROUP_MEMBER_STALE") from error
        sources.append(
            GroupSourceBundle(
                display_id=member.display_id,
                files=files,
                provenance=provenance,
            )
        )
    return build_group_bundle(exact.group_id, sources)
