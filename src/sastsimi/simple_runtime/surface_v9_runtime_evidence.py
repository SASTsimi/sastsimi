"""Recompute v9 source proofs from one immutable Python analysis scope.

The application and read-side coverage verifier share this routine so a
saved graph or certificate is never promoted solely because its CAS hash
exists. All source and candidate bindings are checked again on replay.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .artifacts import SimpleArtifactRepository
from .ast_facts import index_ast_manifest
from .attack_surfaces import SurfaceIndex, candidate_inventory_hash
from .call_path_facts import build_python_call_path_index
from .candidates import StaticCandidate
from .models import CheckpointIdentity
from .operational_config_v5 import discover_operational_route_maps
from .store import SimpleCheckpointStore
from .surface_applicability_v9 import (
    AnalyzerApplicabilityV9,
    assess_optional_analyzers,
)
from .surface_evidence_graph_v5 import (
    extract_surface_graph_v5,
    verify_operational_routes_v5,
)
from .surface_intrinsic_proof_v9 import IntrinsicProofV9, prove_intrinsic_surface
from .surface_path_proof_v9 import PathCertificateV9, certify_surface_paths


def recompute_v9_runtime_evidence(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    workspace: Path,
    artifacts: SimpleArtifactRepository,
    store: SimpleCheckpointStore,
    ast_summary: Mapping[str, object],
) -> tuple[
    AnalyzerApplicabilityV9,
    dict[str, IntrinsicProofV9],
    dict[str, PathCertificateV9],
    dict[str, dict[str, object]],
    dict[str, StaticCandidate],
]:
    """Return applicability, intrinsic proofs, path certs, graphs, candidates."""

    manifest = index_ast_manifest(artifacts, dict(ast_summary))
    source_hashes = tuple(
        (path, str(entry["source_sha256"])) for path, entry in sorted(manifest.items())
    )
    if index.ast_source_hashes != source_hashes:
        raise ValueError("SURFACE_ENRICHMENT_V9_AST_SOURCE_CHANGED")
    candidates: dict[str, StaticCandidate] = {}
    after_id: str | None = None
    while True:
        page = store.list_candidates(
            identity, index.scope_fingerprint, after_id=after_id, limit=128
        )
        if not page:
            break
        for candidate in page:
            if candidate.candidate_id in candidates:
                raise ValueError("SURFACE_ENRICHMENT_V9_CANDIDATE_CHANGED")
            candidates[candidate.candidate_id] = candidate
        after_id = page[-1].candidate_id
    if (
        len(candidates) != index.candidate_count
        or candidate_inventory_hash(tuple(candidates.values()))
        != index.candidate_inventory_hash
    ):
        raise ValueError("SURFACE_ENRICHMENT_V9_CANDIDATE_CHANGED")
    applicability = assess_optional_analyzers(index, workspace)
    graphs: dict[str, dict[str, object]] = {}
    intrinsic: dict[str, IntrinsicProofV9] = {}
    paths: dict[str, PathCertificateV9] = {}
    if index.surfaces:
        route_map = discover_operational_route_maps(
            workspace, identity.commit_id, dict(source_hashes)
        )
        verified_routes = verify_operational_routes_v5(index, workspace, route_map)
        call_index = build_python_call_path_index(
            workspace, tuple(path for path, _ in source_hashes)
        )
        for surface in index.surfaces:
            graph = extract_surface_graph_v5(
                index,
                surface,
                dict(ast_summary),
                manifest,
                workspace,
                artifacts,
                route_map,
                call_index=call_index,
                verified_routes=verified_routes,
                proof_semantics_revision="v5-source-bound-5",
            )
            graphs[surface.surface_id] = graph
            proof = prove_intrinsic_surface(
                index,
                surface,
                workspace,
                graph,
                candidates=candidates,
                artifacts=artifacts,
            )
            if proof is not None:
                intrinsic[surface.surface_id] = proof
            paths[surface.surface_id] = certify_surface_paths(
                index,
                surface,
                graph,
                applicability,
                workspace,
                call_index=call_index,
            )
    return applicability, intrinsic, paths, graphs, candidates
