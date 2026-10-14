"""Read-side verification of the additive v9 surface-coverage certificate.

The terminal's counts are claims. A report or dashboard may display them only
after replaying the pinned plan, source proofs, saved Agent reviews and current
candidate/child completion against the exact CAS objects.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex
from .models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from .store import SimpleCheckpointStore
from .surface_coverage_v2 import _ref
from .surface_coverage_v6 import surface_coverage_v6_from_json
from .surface_coverage_v7 import SurfaceCoverageV7, evaluate_surface_coverage_v7
from .surface_enrichment_v9 import prepare_surface_enrichment_v9
from .surface_enrichment_v9_bindings import (
    missing_v8_part_set,
    prior_v8_progress_snapshot_hash,
)
from .surface_evidence_validation_v9 import validate_saved_v9_result
from .surface_v9_runtime_evidence import recompute_v9_runtime_evidence

_MAX_PROOF_BYTES = 8 * 1024 * 1024
_MAX_STATIC_BUNDLE_BYTES = 64 * 1024 * 1024


def _read_object(
    artifacts: SimpleArtifactRepository, ref: StoredDataRef, limit: int
) -> dict[str, object]:
    value = json.loads(artifacts.read_bounded(ref, limit))
    if not isinstance(value, dict):
        raise ValueError("SURFACE_COVERAGE_V7_OBJECT_INVALID")
    return value


def _require_saved(
    artifacts: SimpleArtifactRepository,
    identity: CheckpointIdentity,
    value: object,
) -> None:
    digest = hashlib.sha256(canonical_bytes(value)).hexdigest()
    if artifacts.read(_ref(identity, digest)) != canonical_bytes(value):
        raise ValueError("SURFACE_COVERAGE_V7_EVIDENCE_CHANGED")


def verified_saved_coverage_v7(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    *,
    predecessor_terminal: CandidateTerminal | None = None,
    predecessor_root: StageCheckpoint | None = None,
) -> SurfaceCoverageV7:
    """Recompute the v9 proof, then compare every terminal claim exactly."""

    invalid = "SURFACE_COVERAGE_V7_VERIFIED_INVALID"
    try:
        run = store.require_analysis_run(identity.analysis_id)
        terminal = predecessor_terminal or run.candidate_terminal
        plan_ref = run.surface_enrichment_v9_plan_ref
        v8_ref = run.surface_enrichment_v8_plan_ref
        bundle_ref = run.static_bundle_ref
        workspace = run.workspace_path
        root = predecessor_root or store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            (predecessor_terminal is None) != (predecessor_root is None)
            or root is not None
            and (
                root.identity != identity
                or root.stage is not SimpleStage.HYPOTHESIS_DONE
            )
            or identity.hypothesis_id is not None
            or identity != artifacts.identity
            or identity.workspace_id != run.workspace_id
            or identity.commit_id != run.commit_id
            or terminal is None
            or terminal.surface_proof_version != 7
            or not terminal.producer_finished
            or terminal.surface_coverage_hash != coverage_ref.content_hash
            or terminal.bundle_hash != index.static_bundle_hash
            or terminal.scope_fingerprint != index.scope_fingerprint
            or plan_ref is None
            or v8_ref is None
            or bundle_ref is None
            or workspace is None
            or run.candidate_scope_fingerprint != index.scope_fingerprint
            or bundle_ref.content_hash != index.static_bundle_hash
            or root is None
            or root.status is not StageStatus.SUCCEEDED
            or len(root.output_refs) != 2
            or root.output_refs[1] != coverage_ref
        ):
            raise ValueError("v9 terminal unbound")
        plan = _read_object(artifacts, plan_ref, _MAX_PROOF_BYTES)
        v8_plan = _read_object(artifacts, v8_ref, _MAX_PROOF_BYTES)
        bundle = _read_object(artifacts, bundle_ref, _MAX_STATIC_BUNDLE_BYTES)
        index_ref = StoredDataRef.model_validate(plan["index_ref"])
        parent_ref = StoredDataRef.model_validate(plan["prior_v8_coverage_ref"])
        parent = surface_coverage_v6_from_json(
            _read_object(artifacts, parent_ref, _MAX_PROOF_BYTES)
        )
        ast_summary = bundle.get("ast_summary")
        if (
            not isinstance(ast_summary, dict)
            or hashlib.sha256(canonical_bytes(ast_summary)).hexdigest()
            != index.ast_manifest_hash
            or _read_object(artifacts, index_ref, _MAX_PROOF_BYTES) != index.to_json()
            or root.output_refs[0] != index_ref
            or parent.v8_plan_ref != v8_ref
            or plan.get("prior_v8_plan_ref") != v8_ref.model_dump(mode="json")
            or plan.get("prior_v8_coverage_ref") != parent_ref.model_dump(mode="json")
        ):
            raise ValueError("v9 predecessor changed")
        progress = store.list_surface_exploration_progress(
            identity, index.scope_fingerprint
        )
        old_progress = {
            key: row for key, row in progress.items() if row.proposal_version <= 8
        }
        prior_hash = prior_v8_progress_snapshot_hash(old_progress)
        if (
            prior_hash != plan.get("prior_v8_progress_hash")
            or missing_v8_part_set(v8_plan, old_progress)
            or any(row.proposal_version > 9 for row in progress.values())
        ):
            raise ValueError("v9 predecessor progress changed")
        applicability, intrinsic, paths, graphs, candidates = (
            recompute_v9_runtime_evidence(
                identity,
                index,
                Path(workspace),
                artifacts,
                store,
                cast(dict[str, object], ast_summary),
            )
        )
        reconstructed, parts = prepare_surface_enrichment_v9(
            identity,
            cast(str, plan["scope"]),
            index,
            index_ref,
            v8_ref,
            v8_plan,
            parent_ref,
            parent,
            prior_hash,
            applicability,
            intrinsic,
            paths,
            graphs,
            Path(workspace),
            candidates=candidates,
            artifacts=artifacts,
        )
        if reconstructed != plan:
            raise ValueError("v9 plan changed")
        for evidence in (
            applicability.to_json(),
            *(proof.to_json() for proof in intrinsic.values()),
            *(certificate.to_json() for certificate in paths.values()),
            *graphs.values(),
            *(part.payload for part in parts),
        ):
            _require_saved(artifacts, identity, evidence)
        expected = {(part.surface_id, part.context_id): part for part in parts}
        completed = {}
        for key, row in progress.items():
            if row.proposal_version != 9:
                continue
            part = expected.get(key)
            if (
                part is None
                or key != (row.surface_id, row.context_id)
                or row.static_bundle_hash != index.static_bundle_hash
                or row.index_hash != index_ref.content_hash
                or row.context_hash != part.context_hash
                or row.source_sha256 != part.source_sha256
            ):
                raise ValueError("v9 progress changed")
            saved = _read_object(artifacts, row.result_ref, _MAX_PROOF_BYTES)
            if saved.get("status") != row.status:
                raise ValueError("v9 review status changed")
            completed[key] = validate_saved_v9_result(part, saved, row.hypothesis_ids)
            for hypothesis_id in row.hypothesis_ids:
                child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
                checkpoint = store.require(child, SimpleStage.PRO_CON_DONE)
                if len(checkpoint.input_refs) < 2 or checkpoint.input_refs[1] != _ref(
                    identity, part.context_hash
                ):
                    raise ValueError("v9 child registration changed")
        decisions = store.candidate_counts(identity, index.scope_fingerprint)
        deep = store.candidate_deep_counts(identity, index.scope_fingerprint)
        pending_candidates = sum(
            decisions.get(name, 0) for name in ("PENDING", "ERROR")
        )
        pending_children = store.list_incomplete_hypotheses(identity, limit=1)
        if (
            pending_candidates
            or pending_children
            or any(deep.get(name, 0) for name in ("PENDING", "RUNNING", "ERROR"))
        ):
            raise ValueError("v9 pending work changed")
        current = evaluate_surface_coverage_v7(
            identity,
            index,
            index_ref,
            v8_ref,
            v8_plan,
            parent_ref,
            parent,
            plan_ref,
            plan,
            prior_hash,
            applicability,
            intrinsic,
            paths,
            graphs,
            completed,
            Path(workspace),
            pending_candidate_count=0,
            pending_child_count=0,
            candidates=candidates,
            artifacts=artifacts,
            progress=progress,
            store=store,
        )
        counts = {
            status: sum(row.coverage_status == status for row in current.surfaces)
            for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
        }
        if (
            _read_object(artifacts, coverage_ref, _MAX_PROOF_BYTES) != current.to_json()
            or terminal.status != ("COMPLETE" if current.complete else "PARTIAL")
            or terminal.surface_counts != counts
            or terminal.pending_child_count != current.pending_child_count
            or terminal.scope_certificate_hash
            != current.scope_certificate_ref.content_hash
            or terminal.surface_index_hash != current.index_hash
        ):
            raise ValueError("v9 terminal differs from proof")
        return current
    except (
        KeyError,
        LookupError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        subprocess.CalledProcessError,
    ) as error:
        raise ValueError(invalid) from error
