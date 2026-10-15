"""Read the immutable v8 predecessor while its v9 successor is unfinished.

The saved v6 coverage was verified before the v9 plan was pinned. Successor
rows and children must not be counted as changes to that predecessor. This
reader checks the pin, the old progress snapshot, the saved proof, and every
new incomplete child's v9 registration without changing runtime state.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import surface_index_from_json
from .models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_coverage_v2 import _ref
from .surface_coverage_v6 import (
    surface_coverage_v6_from_json,
    verified_saved_coverage_v6,
)
from .surface_enrichment_v9 import V9Part
from .surface_enrichment_v9_bindings import (
    missing_v8_part_set,
    prior_v8_progress_snapshot_hash,
)
from .surface_evidence_validation_v9 import validate_saved_v9_result

_MAX_PROOF_BYTES = 16 * 1024 * 1024


def _object(
    artifacts: SimpleArtifactRepository, ref: StoredDataRef
) -> dict[str, object]:
    value = json.loads(artifacts.read_bounded(ref, _MAX_PROOF_BYTES))
    if not isinstance(value, dict):
        raise ValueError("SURFACE_V9_PREDECESSOR_OBJECT_INVALID")
    return value


def _incomplete_ids(
    store: SimpleCheckpointStore, identity: CheckpointIdentity
) -> set[str]:
    selected: set[str] = set()
    after: str | None = None
    while True:
        page = store.list_incomplete_hypotheses(identity, after_id=after, limit=100)
        if not page:
            return selected
        if (
            len(page) > 100
            or tuple(sorted(set(page))) != page
            or (after is not None and page[0] <= after)
        ):
            raise ValueError("SURFACE_V9_PREDECESSOR_CHILD_PAGE_INVALID")
        selected.update(page)
        if len(page) < 100:
            return selected
        after = page[-1]


class _FrozenV8Store:
    """Read-only v8 view; successor progress and children are not predecessors."""

    __slots__ = (
        "_base",
        "_identity",
        "_scope",
        "_progress",
        "_successor_ids",
        "_pending",
    )

    def __init__(
        self,
        base: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        scope: str,
        progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
        successor_ids: set[str],
        pending: set[str],
    ) -> None:
        self._base = base
        self._identity = identity
        self._scope = scope
        self._progress = dict(progress)
        self._successor_ids = frozenset(successor_ids)
        self._pending = tuple(sorted(pending - successor_ids))

    def _check(self, identity: CheckpointIdentity, scope: str | None = None) -> None:
        if identity != self._identity or (scope is not None and scope != self._scope):
            raise ValueError("SURFACE_V9_PREDECESSOR_SCOPE_CHANGED")

    def require_analysis_run(self, analysis_id: str) -> SimpleAnalysisRun:
        if analysis_id != self._identity.analysis_id:
            raise ValueError("SURFACE_V9_PREDECESSOR_ANALYSIS_CHANGED")
        return self._base.require_analysis_run(analysis_id)

    def get(
        self, identity: CheckpointIdentity, stage: SimpleStage
    ) -> StageCheckpoint | None:
        if identity.hypothesis_id in self._successor_ids:
            raise ValueError("SURFACE_V9_PREDECESSOR_SUCCESSOR_CHECKPOINT")
        if identity.model_copy(update={"hypothesis_id": None}) != self._identity:
            raise ValueError("SURFACE_V9_PREDECESSOR_SCOPE_CHANGED")
        return self._base.get(identity, stage)

    def list_checkpoints(self, analysis_id: str) -> tuple[StageCheckpoint, ...]:
        if analysis_id != self._identity.analysis_id:
            raise ValueError("SURFACE_V9_PREDECESSOR_ANALYSIS_CHANGED")
        return tuple(
            item
            for item in self._base.list_checkpoints(analysis_id)
            if item.identity.hypothesis_id not in self._successor_ids
        )

    def registered_hypothesis_ref(
        self, identity: CheckpointIdentity, hypothesis_id: str
    ) -> StoredDataRef | None:
        self._check(identity)
        if hypothesis_id in self._successor_ids:
            raise ValueError("SURFACE_V9_PREDECESSOR_SUCCESSOR_CHILD")
        return self._base.registered_hypothesis_ref(identity, hypothesis_id)

    def list_surface_exploration_progress(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> dict[tuple[str, str], SurfaceExplorationProgressRecord]:
        self._check(identity, scope_fingerprint)
        return dict(self._progress)

    def candidate_counts(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> dict[str, int]:
        self._check(identity, scope_fingerprint)
        return self._base.candidate_counts(identity, scope_fingerprint)

    def candidate_deep_counts(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> dict[str, int]:
        self._check(identity, scope_fingerprint)
        return self._base.candidate_deep_counts(identity, scope_fingerprint)

    def list_incomplete_hypotheses(
        self,
        identity: CheckpointIdentity,
        *,
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        self._check(identity)
        if limit <= 0:
            raise ValueError("SURFACE_V9_PREDECESSOR_PAGE_INVALID")
        return tuple(
            child for child in self._pending if after_id is None or child > after_id
        )[:limit]

    def list_candidate_hypothesis_ids(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        *,
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        self._check(identity, scope_fingerprint)
        if limit <= 0:
            raise ValueError("SURFACE_V9_PREDECESSOR_PAGE_INVALID")
        selected: list[str] = []
        cursor: str | None = None
        while True:
            page = self._base.list_candidate_hypothesis_ids(
                identity, scope_fingerprint, candidate_id, after_id=cursor, limit=100
            )
            if (
                len(page) > 100
                or tuple(sorted(set(page))) != page
                or (cursor is not None and page and page[0] <= cursor)
            ):
                raise ValueError("SURFACE_V9_PREDECESSOR_CHILD_PAGE_INVALID")
            selected.extend(child for child in page if child not in self._successor_ids)
            if len(page) < 100:
                break
            cursor = page[-1]
        return tuple(
            child for child in selected if after_id is None or child > after_id
        )[:limit]


def verified_pending_v9_predecessor(
    run: SimpleAnalysisRun,
    artifacts: SimpleArtifactRepository,
    store: SimpleCheckpointStore,
) -> bool:
    """Return true only for an exact pinned, still-partial v6 predecessor.

    The return value does not say that the current v9 scan or analysis is
    complete. It permits a report to disclose the frozen PARTIAL predecessor
    while clearly keeping successor work separate.
    """

    terminal = run.candidate_terminal
    plan_ref = run.surface_enrichment_v9_plan_ref
    v8_ref = run.surface_enrichment_v8_plan_ref
    static_ref = run.static_coverage_ref
    certificate_ref = run.python_scope_certificate_ref
    if (
        terminal is None
        or terminal.surface_proof_version != 6
        or terminal.status != "PARTIAL"
        or not terminal.producer_finished
        or terminal.pending_child_count != 0
        or run.candidate_pipeline_version != 2
        or run.candidate_scope_fingerprint != terminal.scope_fingerprint
        or run.surface_enrichment_status not in {"RUNNING", "FAILED"}
        or run.surface_enrichment_status == "FAILED"
        and run.surface_enrichment_error_code != "REPORT_SURFACE_PROOF_UNVERIFIED"
        or plan_ref is None
        or v8_ref is None
        or static_ref is None
        or certificate_ref is None
        or certificate_ref.content_hash != terminal.scope_certificate_hash
        or artifacts.identity.analysis_id != run.analysis_id
        or artifacts.identity.workspace_id != run.workspace_id
        or artifacts.identity.commit_id != run.commit_id
    ):
        return False
    identity = artifacts.identity.model_copy(update={"hypothesis_id": None})
    root_artifacts = SimpleArtifactRepository(
        artifacts.data_dir, identity, create_dirs=False
    )
    try:
        if store.require_analysis_run(run.analysis_id) != run:
            return False
        root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            root is None
            or root.identity != identity
            or root.stage_version != STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE]
            or root.status is not StageStatus.SUCCEEDED
            or len(root.output_refs) != 2
            or root.output_refs[0].content_hash != terminal.surface_index_hash
            or root.output_refs[1].content_hash != terminal.surface_coverage_hash
        ):
            return False
        index_ref, coverage_ref = root.output_refs
        index = surface_index_from_json(_object(root_artifacts, index_ref))
        parent = surface_coverage_v6_from_json(_object(root_artifacts, coverage_ref))
        plan = _object(root_artifacts, plan_ref)
        v8_plan = _object(root_artifacts, v8_ref)
        certificate = _object(root_artifacts, certificate_ref)
        root_artifacts.read_bounded(static_ref, _MAX_PROOF_BYTES)
        if (
            index.workspace_id != run.workspace_id
            or index.commit_id != run.commit_id
            or index.scope_fingerprint != terminal.scope_fingerprint
            or index.static_bundle_hash != terminal.bundle_hash
            or parent.scope_fingerprint != terminal.scope_fingerprint
            or parent.static_bundle_hash != terminal.bundle_hash
            or parent.ast_manifest_hash != index.ast_manifest_hash
            or parent.candidate_inventory_hash != index.candidate_inventory_hash
            or parent.candidate_count != index.candidate_count
            or parent.index_hash != index_ref.content_hash
            or parent.v8_plan_ref != v8_ref
            or parent.scope_certificate_ref != certificate_ref
            or parent.pending_candidate_count != 0
            or parent.pending_child_count != 0
            or parent.complete
            or len(parent.surfaces) != len(index.surfaces)
            or any(
                (saved.surface_id, saved.path, saved.line)
                != (indexed.surface_id, indexed.path, indexed.line)
                for saved, indexed in zip(parent.surfaces, index.surfaces, strict=True)
            )
            or dict(Counter(row.coverage_status for row in parent.surfaces))
            != {key: value for key, value in terminal.surface_counts.items() if value}
            or certificate.get("analysis_id") != run.analysis_id
            or certificate.get("workspace_id") != run.workspace_id
            or certificate.get("commit_id") != run.commit_id
            or certificate.get("coverage_ref") != static_ref.model_dump(mode="json")
            or certificate.get("index_ref") != index_ref.model_dump(mode="json")
            or v8_plan.get("kind") != "simple_surface_enrichment_plan_v8"
            or v8_plan.get("analysis_id") != run.analysis_id
            or v8_plan.get("workspace_id") != run.workspace_id
            or v8_plan.get("commit_id") != run.commit_id
            or v8_plan.get("scope_fingerprint") != terminal.scope_fingerprint
            or v8_plan.get("static_bundle_hash") != terminal.bundle_hash
            or v8_plan.get("index_ref") != index_ref.model_dump(mode="json")
        ):
            return False
        binding = dict(plan)
        binding.pop("expected_parts", None)
        binding_hash = binding.pop("plan_binding_hash", None)
        binding["kind"] = "simple_surface_enrichment_binding_v9"
        if (
            plan.get("kind") != "simple_surface_enrichment_plan_v9"
            or binding_hash != hashlib.sha256(canonical_bytes(binding)).hexdigest()
            or plan.get("analysis_id") != run.analysis_id
            or plan.get("workspace_id") != run.workspace_id
            or plan.get("commit_id") != run.commit_id
            or plan.get("scope_fingerprint") != terminal.scope_fingerprint
            or plan.get("static_bundle_hash") != terminal.bundle_hash
            or plan.get("ast_manifest_hash") != index.ast_manifest_hash
            or plan.get("candidate_inventory_hash") != index.candidate_inventory_hash
            or plan.get("candidate_count") != index.candidate_count
            or plan.get("index_ref") != index_ref.model_dump(mode="json")
            or plan.get("prior_v8_plan_ref") != v8_ref.model_dump(mode="json")
            or plan.get("prior_v8_coverage_ref") != coverage_ref.model_dump(mode="json")
        ):
            return False
        progress = store.list_surface_exploration_progress(
            identity, terminal.scope_fingerprint
        )
        predecessor = {
            key: row for key, row in progress.items() if row.proposal_version <= 8
        }
        if (
            prior_v8_progress_snapshot_hash(predecessor)
            != plan.get("prior_v8_progress_hash")
            or missing_v8_part_set(v8_plan, predecessor)
            or any(row.proposal_version > 9 for row in progress.values())
        ):
            return False
        expected = plan.get("expected_parts")
        if not isinstance(expected, list) or not expected:
            return False
        by_key: dict[tuple[str, str], dict[str, object]] = {}
        for item in expected:
            if not isinstance(item, dict):
                return False
            surface_id, context_id = item.get("surface_id"), item.get("context_id")
            if (
                not isinstance(surface_id, str)
                or not isinstance(context_id, str)
                or not surface_id
                or not context_id
                or (surface_id, context_id) in by_key
            ):
                return False
            by_key[(surface_id, context_id)] = item
        v9_children: set[str] = set()
        for key, row in progress.items():
            if row.proposal_version != 9:
                continue
            part_record = by_key.get(key)
            if part_record is None:
                return False
            context_part = part_record.get("context_part")
            if (
                not isinstance(context_part, dict)
                or row.static_bundle_hash != terminal.bundle_hash
                or row.index_hash != index_ref.content_hash
                or row.context_hash != part_record.get("context_hash")
                or row.source_sha256 != context_part.get("source_sha256")
            ):
                return False
            payload = _object(root_artifacts, _ref(identity, row.context_hash))
            if (
                payload.get("context_part") != context_part
                or payload.get("plan_binding_hash") != binding_hash
                or payload.get("graph_hash") != part_record.get("graph_hash")
                or payload.get("path_certificate_hash")
                != part_record.get("path_certificate_hash")
            ):
                return False
            part = V9Part(
                payload=payload,
                surface_id=row.surface_id,
                context_id=row.context_id,
                context_hash=row.context_hash,
                part_id=cast(str, part_record["part_id"]),
                part_index=cast(int, part_record["part_index"]),
                part_count=cast(int, part_record["part_count"]),
                source_sha256=cast(str, row.source_sha256),
            )
            validate_saved_v9_result(
                part, _object(root_artifacts, row.result_ref), row.hypothesis_ids
            )
            if v9_children.intersection(row.hypothesis_ids):
                return False
            v9_children.update(row.hypothesis_ids)
        incomplete = _incomplete_ids(store, identity)
        if not incomplete <= v9_children or v9_children.intersection(
            child_id for row in predecessor.values() for child_id in row.hypothesis_ids
        ):
            return False
        frozen = _FrozenV8Store(
            store,
            identity,
            terminal.scope_fingerprint,
            predecessor,
            v9_children,
            incomplete,
        )
        recomputed = verified_saved_coverage_v6(
            identity,
            index,
            coverage_ref,
            cast(SimpleCheckpointStore, frozen),
            root_artifacts,
        )
        return recomputed == parent
    except (OSError, KeyError, TypeError, ValueError, UnicodeError):
        return False
