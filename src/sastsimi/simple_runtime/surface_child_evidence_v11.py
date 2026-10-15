"""Pure inventory of linked historical child HOLD checkpoints."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex
from .models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from .store import (
    ChildRevalidationProgressRecordV11,
    SimpleCheckpointStore,
    SurfaceExplorationProgressRecord,
)
from .surface_coverage_v2 import _related_child_ids


@dataclass(frozen=True, slots=True)
class ChildHoldTargetV11:
    hypothesis_id: str
    stage: SimpleStage
    surface_ids: tuple[str, ...]
    checkpoint_hash: str


_INTERIM_STATUSES = ("PENDING", "RUNNING", "RESOLVED", "STILL_HOLD", "ERROR")
_HOLD_STAGES = frozenset(
    {
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_EXECUTION_DONE,
        SimpleStage.VERIFICATION_FINAL_DONE,
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def interim_child_attempt_counts_v11(
    run: SimpleAnalysisRun,
    identity: CheckpointIdentity,
    index_hash: str,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> dict[str, int]:
    """Count exact pinned ledger rows as unverified attempt status only.

    This reader does not replay result artifacts or issue a coverage verdict.
    The independent proof9 reader owns those claims after promotion.
    """

    plan_ref = run.surface_enrichment_v11_plan_ref
    terminal = run.candidate_terminal
    if (
        identity.hypothesis_id is not None
        or artifacts.identity != identity
        or run.analysis_id != identity.analysis_id
        or run.workspace_id != identity.workspace_id
        or run.commit_id != identity.commit_id
        or run.surface_enrichment_status not in {"RUNNING", "BLOCKED"}
        or plan_ref is None
        or run.surface_enrichment_v10_plan_ref is None
        or terminal is None
        or terminal.surface_proof_version != 8
        or terminal.status != "PARTIAL"
        or terminal.surface_index_hash != index_hash
        or terminal.scope_fingerprint != run.candidate_scope_fingerprint
        or _SHA256.fullmatch(index_hash) is None
    ):
        raise ValueError("SURFACE_CHILD_V11_INTERIM_INVALID")
    try:
        plan = json.loads(artifacts.read_bounded(plan_ref, 16 * 1024 * 1024))
        if not isinstance(plan, dict):
            raise ValueError("plan object missing")
        frozen_terminal = CandidateTerminal.model_validate(plan["v10_terminal"])
        frozen_root = StageCheckpoint.model_validate_json(json.dumps(plan["v10_root"]))
        coverage_ref = StoredDataRef.model_validate_json(
            json.dumps(plan["v10_coverage_ref"])
        )
        raw_targets = plan["targets"]
        if (
            plan.get("kind") != "simple_surface_enrichment_plan_v11"
            or plan.get("analysis_id") != identity.analysis_id
            or plan.get("workspace_id") != identity.workspace_id
            or plan.get("commit_id") != identity.commit_id
            or plan.get("scope_fingerprint") != run.candidate_scope_fingerprint
            or plan.get("static_bundle_hash") != frozen_terminal.bundle_hash
            or plan.get("index_hash") != index_hash
            or plan.get("v10_plan_ref")
            != run.surface_enrichment_v10_plan_ref.model_dump(mode="json")
            or frozen_terminal.surface_proof_version != 8
            or frozen_terminal.model_copy(update={"status": "PARTIAL"}) != terminal
            or coverage_ref.content_hash != frozen_terminal.surface_coverage_hash
            or frozen_root.identity != identity
            or frozen_root.stage is not SimpleStage.HYPOTHESIS_DONE
            or frozen_root.status is not StageStatus.SUCCEEDED
            or len(frozen_root.output_refs) != 2
            or frozen_root.output_refs[0].content_hash != index_hash
            or frozen_root.output_refs[1] != coverage_ref
            or not isinstance(raw_targets, list)
            or not isinstance(plan.get("child_snapshot_hash"), str)
            or _SHA256.fullmatch(plan["child_snapshot_hash"]) is None
            or not isinstance(plan.get("v9_progress_hash"), str)
            or _SHA256.fullmatch(plan["v9_progress_hash"]) is None
        ):
            raise ValueError("plan binding mismatch")
        targets: dict[tuple[str, SimpleStage], str] = {}
        for raw in raw_targets:
            if not isinstance(raw, dict):
                raise ValueError("target object missing")
            hypothesis_id = raw.get("hypothesis_id")
            stage = SimpleStage(raw["stage"])
            checkpoint_hash = raw.get("checkpoint_hash")
            surface_ids = raw.get("surface_ids")
            if (
                not isinstance(hypothesis_id, str)
                or not hypothesis_id
                or stage not in _HOLD_STAGES
                or not isinstance(checkpoint_hash, str)
                or _SHA256.fullmatch(checkpoint_hash) is None
                or not isinstance(surface_ids, list)
                or not surface_ids
                or any(not isinstance(item, str) or not item for item in surface_ids)
                or len(set(surface_ids)) != len(surface_ids)
            ):
                raise ValueError("target invalid")
            key = (hypothesis_id, stage)
            if key in targets:
                raise ValueError("target duplicate")
            targets[key] = checkpoint_hash
        rows = store.list_surface_child_revalidation_v11(
            identity, run.candidate_scope_fingerprint or "", plan_ref
        )
        if set(rows) != set(targets):
            raise ValueError("ledger target mismatch")
        counts = {status: 0 for status in _INTERIM_STATUSES}
        for key, row in rows.items():
            if (
                not isinstance(row, ChildRevalidationProgressRecordV11)
                or row.hypothesis_id != key[0]
                or row.stage is not key[1]
                or row.checkpoint_hash != targets[key]
                or row.status not in counts
                or row.status == "PENDING"
                and (
                    row.reason_code is not None
                    or row.result_ref is not None
                    or row.attempt_id is not None
                )
                or row.status == "RUNNING"
                and (
                    not row.attempt_id
                    or row.reason_code is not None
                    or row.result_ref is not None
                )
                or row.status in {"RESOLVED", "STILL_HOLD", "ERROR"}
                and (
                    not row.attempt_id or not row.reason_code or row.result_ref is None
                )
                or row.result_ref is not None
                and (
                    row.result_ref.workspace_id.root != identity.workspace_id
                    or row.result_ref.commit_id.root != identity.commit_id
                )
            ):
                raise ValueError("ledger row mismatch")
            counts[row.status] += 1
        return counts
    except (KeyError, OSError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError("SURFACE_CHILD_V11_INTERIM_INVALID") from error


def recount_incomplete_hypotheses_v11(
    identity: CheckpointIdentity, store: SimpleCheckpointStore
) -> int:
    """Recount current unfinished children instead of inheriting old maxima."""

    if identity.hypothesis_id is not None:
        raise ValueError("CHILD_EVIDENCE_V11_IDENTITY_INVALID")
    count = 0
    after_id: str | None = None
    while True:
        page = store.list_incomplete_hypotheses(identity, after_id=after_id, limit=100)
        if (
            len(page) > 100
            or tuple(sorted(set(page))) != page
            or any(not item for item in page)
            or after_id is not None
            and any(item <= after_id for item in page)
        ):
            raise ValueError("CHILD_EVIDENCE_V11_PENDING_PAGE_INVALID")
        count += len(page)
        if len(page) < 100:
            return count
        after_id = page[-1]


class _CheckedCandidateLinkStore:
    """Preserve duplicate-link errors hidden by `_related_child_ids`' set."""

    def __init__(self, store: SimpleCheckpointStore) -> None:
        self._store = store
        self._seen: dict[str, set[str]] = {}

    def list_candidate_hypothesis_ids(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        *,
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        page = self._store.list_candidate_hypothesis_ids(
            identity, scope_fingerprint, candidate_id, after_id=after_id, limit=limit
        )
        seen = self._seen.setdefault(candidate_id, set())
        if (
            len(page) > limit
            or len(set(page)) != len(page)
            or any(not child_id or child_id in seen for child_id in page)
            or any(child_id <= after_id for child_id in page if after_id is not None)
        ):
            raise ValueError("CHILD_EVIDENCE_V11_DUPLICATE_ID")
        seen.update(page)
        return page


def collect_child_hold_targets_v11(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
) -> tuple[tuple[ChildHoldTargetV11, ...], str]:
    """Collect HOLD obligations and bind them to a stable linked-child digest."""

    if (
        identity.hypothesis_id is not None
        or identity.workspace_id != index.workspace_id
        or identity.commit_id != index.commit_id
    ):
        raise ValueError("CHILD_EVIDENCE_V11_IDENTITY_INVALID")
    surface_ids = [surface.surface_id for surface in index.surfaces]
    if len(set(surface_ids)) != len(surface_ids) or any(not sid for sid in surface_ids):
        raise ValueError("CHILD_EVIDENCE_V11_DUPLICATE_ID")
    for surface in index.surfaces:
        if len(set(surface.linked_candidate_ids)) != len(surface.linked_candidate_ids):
            raise ValueError("CHILD_EVIDENCE_V11_DUPLICATE_ID")
    for row in progress.values():
        if row.surface_id not in surface_ids:
            continue
        if len(set(row.hypothesis_ids)) != len(row.hypothesis_ids) or any(
            not child_id for child_id in row.hypothesis_ids
        ):
            raise ValueError("CHILD_EVIDENCE_V11_DUPLICATE_ID")

    linked: dict[str, set[str]] = {}
    for surface in index.surfaces:
        for hypothesis_id in _related_child_ids(
            identity,
            surface,
            progress,
            cast(SimpleCheckpointStore, _CheckedCandidateLinkStore(store)),
            index.scope_fingerprint,
        ):
            if not hypothesis_id:
                raise ValueError("CHILD_EVIDENCE_V11_DUPLICATE_ID")
            linked.setdefault(hypothesis_id, set()).add(surface.surface_id)

    checkpoints_by_key: dict[tuple[str | None, SimpleStage], StageCheckpoint] = {}
    for listed_checkpoint in store.list_checkpoints(identity.analysis_id):
        if (
            not isinstance(listed_checkpoint, StageCheckpoint)
            or listed_checkpoint.identity.analysis_id != identity.analysis_id
            or listed_checkpoint.identity.workspace_id != identity.workspace_id
            or listed_checkpoint.identity.commit_id != identity.commit_id
            or listed_checkpoint.identity.hypothesis_id == ""
        ):
            raise ValueError("CHILD_EVIDENCE_V11_CHECKPOINT_INVALID")
        key = (listed_checkpoint.identity.hypothesis_id, listed_checkpoint.stage)
        if key in checkpoints_by_key:
            raise ValueError("CHILD_EVIDENCE_V11_DUPLICATE_ID")
        if (
            store.get(listed_checkpoint.identity, listed_checkpoint.stage)
            != listed_checkpoint
        ):
            raise ValueError("CHILD_EVIDENCE_V11_CHECKPOINT_INVALID")
        checkpoints_by_key[key] = listed_checkpoint

    targets: list[ChildHoldTargetV11] = []
    snapshot: list[dict[str, object]] = []
    for hypothesis_id in sorted(linked):
        child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
        surfaces = tuple(sorted(linked[hypothesis_id]))
        checkpoints: list[dict[str, str]] = []
        for stage in SimpleStage:
            checkpoint = checkpoints_by_key.get((hypothesis_id, stage))
            if checkpoint is None:
                continue
            if (
                not isinstance(checkpoint, StageCheckpoint)
                or checkpoint.identity != child
                or checkpoint.stage is not stage
            ):
                raise ValueError("CHILD_EVIDENCE_V11_CHECKPOINT_INVALID")
            checkpoint_hash = hashlib.sha256(canonical_bytes(checkpoint)).hexdigest()
            checkpoints.append(
                {"stage": stage.value, "checkpoint_hash": checkpoint_hash}
            )
            if checkpoint.verdict == "HOLD":
                targets.append(
                    ChildHoldTargetV11(hypothesis_id, stage, surfaces, checkpoint_hash)
                )
        checkpoints.sort(key=lambda row: row["stage"])
        snapshot.append(
            {
                "hypothesis_id": hypothesis_id,
                "surface_ids": surfaces,
                "checkpoints": checkpoints,
            }
        )
    targets.sort(key=lambda target: (target.hypothesis_id, target.stage.value))
    snapshot_hash = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "child_hold_inventory_v11",
                "identity": identity,
                "scope_fingerprint": index.scope_fingerprint,
                "children": snapshot,
            }
        )
    ).hexdigest()
    return tuple(targets), snapshot_hash
