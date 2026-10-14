"""Independent replay of a saved v10 route-bound surface certificate.

The live terminal is only a claim. This reader replays the immutable v9
predecessor, rebuilds every route proof from pinned Python sources, and then
recomputes the successor coverage before exposing its counts.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

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
from .surface_coverage_v7_read import _require_saved, verified_saved_coverage_v7
from .surface_coverage_v8 import SurfaceCoverageV8, evaluate_surface_coverage_v8
from .surface_enrichment_v10 import (
    prepare_surface_enrichment_v10,
    v9_progress_snapshot_hash,
)
from .surface_route_boundary_v10 import prove_route_boundaries_v10
from .surface_v9_runtime_evidence import recompute_v9_runtime_evidence

_MAX_PLAN_BYTES = 8 * 1024 * 1024
_MAX_BUNDLE_BYTES = 64 * 1024 * 1024


def _object(
    artifacts: SimpleArtifactRepository, ref: StoredDataRef, limit: int
) -> dict[str, object]:
    payload = json.loads(artifacts.read_bounded(ref, limit))
    if not isinstance(payload, dict):
        raise ValueError("SURFACE_COVERAGE_V8_OBJECT_INVALID")
    return payload


def verified_saved_coverage_v8(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV8:
    """Return only source- and parent-replayed V8 coverage, or fail closed."""

    invalid = "SURFACE_COVERAGE_V8_VERIFIED_INVALID"
    try:
        run = store.require_analysis_run(identity.analysis_id)
        terminal = run.candidate_terminal
        plan_ref = run.surface_enrichment_v10_plan_ref
        root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        bundle_ref = run.static_bundle_ref
        workspace = run.workspace_path
        if (
            identity.hypothesis_id is not None
            or identity != artifacts.identity
            or identity.workspace_id != run.workspace_id
            or identity.commit_id != run.commit_id
            or terminal is None
            or terminal.surface_proof_version != 8
            or not terminal.producer_finished
            or terminal.surface_coverage_hash != coverage_ref.content_hash
            or terminal.surface_index_hash is None
            or terminal.bundle_hash != index.static_bundle_hash
            or terminal.scope_fingerprint != index.scope_fingerprint
            or run.candidate_scope_fingerprint != index.scope_fingerprint
            or plan_ref is None
            or bundle_ref is None
            or bundle_ref.content_hash != index.static_bundle_hash
            or workspace is None
            or root is None
            or root.identity != identity
            or root.stage is not SimpleStage.HYPOTHESIS_DONE
            or root.status is not StageStatus.SUCCEEDED
            or len(root.output_refs) != 2
            or root.output_refs[1] != coverage_ref
            or root.output_refs[0].content_hash != terminal.surface_index_hash
        ):
            raise ValueError("v10 terminal unbound")
        plan = _object(artifacts, plan_ref, _MAX_PLAN_BYTES)
        bundle = _object(artifacts, bundle_ref, _MAX_BUNDLE_BYTES)
        ast_summary = bundle.get("ast_summary")
        if not isinstance(ast_summary, dict):
            raise ValueError("v10 AST summary missing")
        parent_plan_ref = StoredDataRef.model_validate(plan["v9_plan_ref"])
        parent_ref = StoredDataRef.model_validate(plan["v9_coverage_ref"])
        predecessor_terminal = CandidateTerminal.model_validate_json(
            json.dumps(plan["v9_terminal"])
        )
        predecessor_root = StageCheckpoint.model_validate_json(
            json.dumps(plan["v9_root"])
        )
        if (
            run.surface_enrichment_v9_plan_ref != parent_plan_ref
            or root
            != predecessor_root.model_copy(
                update={
                    "output_refs": root.output_refs,
                    "updated_at": root.updated_at,
                }
            )
            or predecessor_root.output_refs != (root.output_refs[0], parent_ref)
            or predecessor_terminal.surface_coverage_hash != parent_ref.content_hash
            or predecessor_terminal.surface_index_hash
            != root.output_refs[0].content_hash
            or predecessor_terminal.scope_certificate_hash
            != terminal.scope_certificate_hash
            or _object(artifacts, root.output_refs[0], _MAX_PLAN_BYTES)
            != index.to_json()
        ):
            raise ValueError("v10 predecessor unbound")
        parent = verified_saved_coverage_v7(
            identity,
            index,
            parent_ref,
            store,
            artifacts,
            predecessor_terminal=predecessor_terminal,
            predecessor_root=predecessor_root,
        )
        parent_plan = _object(artifacts, parent_plan_ref, _MAX_PLAN_BYTES)
        progress = store.list_surface_exploration_progress(
            identity, index.scope_fingerprint
        )
        progress_hash = v9_progress_snapshot_hash(parent_plan, progress)
        if plan.get("v9_progress_hash") != progress_hash:
            raise ValueError("v10 parent progress changed")
        _, _, paths, graphs, _ = recompute_v9_runtime_evidence(
            identity,
            index,
            Path(workspace),
            artifacts,
            store,
            cast(dict[str, object], ast_summary),
        )
        proofs = prove_route_boundaries_v10(index, Path(workspace), graphs, paths)
        reconstructed = prepare_surface_enrichment_v10(
            identity,
            index,
            parent,
            parent_plan_ref,
            parent_ref,
            predecessor_terminal,
            progress_hash,
            proofs,
            v9_root=predecessor_root,
        )
        if plan != reconstructed:
            raise ValueError("v10 plan changed")
        for proof in proofs.values():
            _require_saved(artifacts, identity, proof.to_json())
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
            raise ValueError("v10 downstream work changed")
        current = evaluate_surface_coverage_v8(
            index,
            parent,
            plan_ref,
            proofs,
            pending_candidate_count=0,
            pending_child_count=0,
        )
        counts = {
            status: sum(row.coverage_status == status for row in current.surfaces)
            for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
        }
        expected_terminal = predecessor_terminal.model_copy(
            update={
                "status": (
                    "COMPLETE"
                    if current.complete and run.static_disposition == "FULL"
                    else "PARTIAL"
                ),
                "surface_coverage_hash": coverage_ref.content_hash,
                "surface_counts": counts,
                "surface_proof_version": 8,
                "pending_child_count": current.pending_child_count,
            }
        )
        if (
            _object(artifacts, coverage_ref, _MAX_PLAN_BYTES) != current.to_json()
            or terminal != expected_terminal
        ):
            raise ValueError("v10 terminal differs from proof")
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
