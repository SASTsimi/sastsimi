"""Read-side validation of saved attack-surface coverage proof."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.surface_reason_codes import (
    SURFACE_REASON_CODE_PREFIX,
    SURFACE_REASON_CODES,
)

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex
from .models import CandidateTerminal
from .store import SimpleCheckpointStore
from .surface_coverage_v3 import verified_saved_coverage_v3
from .surface_coverage_v4 import verified_saved_coverage_v4
from .surface_coverage_v5 import SurfaceCoverageV5, verified_saved_coverage_v5
from .surface_coverage_v6 import SurfaceCoverageV6, verified_saved_coverage_v6
from .surface_coverage_v7 import SurfaceCoverageV7
from .surface_coverage_v7_read import verified_saved_coverage_v7
from .surface_coverage_v8 import SurfaceCoverageV8
from .surface_coverage_v8_read import verified_saved_coverage_v8

SURFACE_STATUSES = ("COVERED", "UNCOVERED", "INSUFFICIENT")


def read_surface_scope_certificate(
    artifacts: SimpleArtifactRepository,
    certificate_ref: StoredDataRef | None,
    static_coverage_ref: StoredDataRef | None,
    terminal: CandidateTerminal,
) -> dict[str, object] | None:
    """Load the exact v2 scope certificate, also retained by v3 proof."""

    if (
        terminal.surface_proof_version not in (2, 3, 4, 5, 6, 7, 8)
        or certificate_ref is None
        or static_coverage_ref is None
        or certificate_ref.content_hash != terminal.scope_certificate_hash
    ):
        return None
    try:
        payload = json.loads(artifacts.read_bounded(certificate_ref, 2 * 1024 * 1024))
        if not isinstance(payload, dict):
            return None
        embedded_ref = StoredDataRef.model_validate(payload.get("coverage_ref"))
        digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        with artifacts.artifacts.open_verified(static_coverage_ref):
            pass
    except (OSError, TypeError, UnicodeError, ValueError):
        return None
    if (
        digest != certificate_ref.content_hash
        or embedded_ref != static_coverage_ref
        or payload.get("analysis_id") != artifacts.identity.analysis_id
        or payload.get("workspace_id") != artifacts.identity.workspace_id
        or payload.get("commit_id") != artifacts.identity.commit_id
    ):
        return None
    return payload


def _verified_surface_v2_counts(
    payload: dict[str, object],
    index: SurfaceIndex,
    terminal: CandidateTerminal,
    certificate_payload: object,
    artifacts: SimpleArtifactRepository | None,
) -> dict[str, int] | None:
    if (
        not isinstance(certificate_payload, dict)
        or artifacts is None
        or artifacts.identity.workspace_id != index.workspace_id
        or artifacts.identity.commit_id != index.commit_id
    ):
        return None
    try:
        index_hash = hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()
        certificate_hash = hashlib.sha256(
            canonical_bytes(certificate_payload)
        ).hexdigest()
        coverage_hash = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        certificate_ref = StoredDataRef.model_validate(
            payload.get("scope_certificate_ref")
        )
        original_ref = StoredDataRef.model_validate(
            payload.get("original_coverage_ref")
        )
        index_ref = StoredDataRef.model_validate(certificate_payload.get("index_ref"))
        static_ref = StoredDataRef.model_validate(
            certificate_payload.get("coverage_ref")
        )
    except (TypeError, ValueError):
        return None
    raw = index.to_json()["static_gaps"]
    effective = certificate_payload.get("effective_static_gaps")
    if (
        index.index_version != 2
        or payload.get("kind") != "simple_attack_surface_coverage_v2"
        or certificate_payload.get("kind") != "simple_python_scope_recertification_v1"
        or not isinstance(certificate_payload.get("analysis_id"), str)
        or not certificate_payload["analysis_id"]
        or certificate_payload.get("workspace_id") != index.workspace_id
        or certificate_payload.get("commit_id") != index.commit_id
        or certificate_payload.get("scope_fingerprint") != index.scope_fingerprint
        or certificate_payload.get("index_hash") != index_hash
        or index_ref.content_hash != index_hash
        or certificate_payload.get("raw_static_gaps") != raw
        or not isinstance(certificate_payload.get("raw_coverage_gaps"), list)
        or not isinstance(
            certificate_payload.get("raw_out_of_scope_product_files"), list
        )
        or not isinstance(effective, list)
        or any(not isinstance(item, dict) for item in effective)
        or certificate_ref.content_hash != certificate_hash
        or payload.get("scope_certificate_hash") != certificate_hash
        or terminal.scope_certificate_hash != certificate_hash
        or terminal.surface_index_hash != index_hash
        or terminal.surface_coverage_hash != coverage_hash
        or terminal.bundle_hash != index.static_bundle_hash
        or payload.get("index_hash") != index_hash
        or payload.get("scope_fingerprint") != index.scope_fingerprint
        or payload.get("static_bundle_hash") != index.static_bundle_hash
        or payload.get("ast_manifest_hash") != index.ast_manifest_hash
        or payload.get("candidate_inventory_hash") != index.candidate_inventory_hash
        or payload.get("candidate_count") != index.candidate_count
        or payload.get("raw_static_gaps") != raw
        or payload.get("effective_python_gaps") != effective
        or any(
            str(ref.workspace_id) != index.workspace_id
            or str(ref.commit_id) != index.commit_id
            or ref.data_kind != "artifact"
            or str(ref.stored_data_id) != ref.content_hash
            for ref in (certificate_ref, original_ref, index_ref, static_ref)
        )
    ):
        return None
    try:
        for ref in (certificate_ref, original_ref, index_ref, static_ref):
            with artifacts.artifacts.open_verified(ref):
                pass
    except (OSError, TypeError, ValueError):
        return None
    pending_candidates = payload.get("pending_candidate_count")
    pending_children = payload.get("pending_child_count")
    rows = payload.get("surfaces")
    if (
        type(pending_candidates) is not int
        or pending_candidates < 0
        or type(pending_children) is not int
        or pending_children < 0
        or pending_children != terminal.pending_child_count
        or not isinstance(rows, list)
        or len(rows) != len(index.surfaces)
    ):
        return None
    indexed = {surface.surface_id: surface for surface in index.surfaces}
    seen: set[str] = set()
    verified_refs: set[str] = set()
    counts = {status: 0 for status in SURFACE_STATUSES}
    unresolved_reason_count = 0
    for row in rows:
        if not isinstance(row, dict):
            return None
        surface_id, status = row.get("surface_id"), row.get("coverage_status")
        if (
            not isinstance(surface_id, str)
            or surface_id not in indexed
            or surface_id in seen
            or not isinstance(status, str)
            or status not in counts
            or row.get("path") != indexed[surface_id].path
            or row.get("line") != indexed[surface_id].line
            or not isinstance(row.get("verified_roles"), list)
            or not isinstance(row.get("evidence_refs"), list)
            or not isinstance(row.get("unresolved_reason_codes"), list)
            or any(
                not isinstance(reason, str)
                or not reason
                or len(reason) > 128
                or any(ord(char) < 32 for char in reason)
                for reason in row["unresolved_reason_codes"]
            )
            or len(set(row["unresolved_reason_codes"]))
            != len(row["unresolved_reason_codes"])
            or (status == "COVERED" and bool(row["unresolved_reason_codes"]))
            or (status != "COVERED" and not row["unresolved_reason_codes"])
            or (status == "COVERED" and not row["evidence_refs"])
        ):
            return None
        for ref_data in row["evidence_refs"]:
            try:
                ref = StoredDataRef.model_validate(ref_data)
                if ref.content_hash not in verified_refs:
                    with artifacts.artifacts.open_verified(ref):
                        pass
                    verified_refs.add(ref.content_hash)
            except (OSError, TypeError, ValueError):
                return None
        seen.add(surface_id)
        counts[status] += 1
        unresolved_reason_count += len(row["unresolved_reason_codes"])
    complete = (
        not effective
        and pending_candidates == 0
        and pending_children == 0
        and counts["COVERED"] == len(indexed)
    )
    if (
        seen != set(indexed)
        or payload.get("complete") is not complete
        or terminal.status != ("COMPLETE" if complete else "PARTIAL")
        or counts != terminal.surface_counts
    ):
        return None
    return {
        **counts,
        "RAW_STATIC_GAP_COUNT": len(cast(list[object], raw)),
        "EFFECTIVE_PYTHON_GAP_COUNT": len(cast(list[object], effective)),
        "UNRESOLVED_REASON_COUNT": unresolved_reason_count,
    }


def verified_surface_coverage_counts(
    payload: object,
    index: SurfaceIndex,
    terminal: CandidateTerminal,
    *,
    certificate_payload: object | None = None,
    artifacts: SimpleArtifactRepository | None = None,
    coverage_ref: StoredDataRef | None = None,
    store: SimpleCheckpointStore | None = None,
) -> dict[str, int] | None:
    """Count only a scope-bound coverage artifact that agrees with terminal proof."""

    if not isinstance(payload, dict):
        return None
    if terminal.surface_proof_version in (3, 4, 5, 6, 7, 8):
        if artifacts is None or coverage_ref is None or store is None:
            return None
        try:
            current = (
                verified_saved_coverage_v8(
                    artifacts.identity, index, coverage_ref, store, artifacts
                )
                if terminal.surface_proof_version == 8
                else verified_saved_coverage_v7(
                    artifacts.identity, index, coverage_ref, store, artifacts
                )
                if terminal.surface_proof_version == 7
                else verified_saved_coverage_v6(
                    artifacts.identity, index, coverage_ref, store, artifacts
                )
                if terminal.surface_proof_version == 6
                else verified_saved_coverage_v5(
                    artifacts.identity, index, coverage_ref, store, artifacts
                )
                if terminal.surface_proof_version == 5
                else verified_saved_coverage_v4(
                    artifacts.identity, index, coverage_ref, store, artifacts
                )
                if terminal.surface_proof_version == 4
                else verified_saved_coverage_v3(
                    artifacts.identity, index, coverage_ref, store, artifacts
                )
            )
            static_disposition = "FULL"
            if terminal.surface_proof_version == 8:
                verified_run = store.require_analysis_run(
                    artifacts.identity.analysis_id
                )
                if verified_run.candidate_terminal != terminal:
                    return None
                static_disposition = verified_run.static_disposition
        except (LookupError, OSError, TypeError, ValueError):
            return None
        counts = {
            status: sum(row.coverage_status == status for row in current.surfaces)
            for status in SURFACE_STATUSES
        }
        if (
            payload != current.to_json()
            or terminal.surface_coverage_hash != coverage_ref.content_hash
            or terminal.surface_counts != counts
            or terminal.status
            != (
                "COMPLETE"
                if current.complete and static_disposition == "FULL"
                else "PARTIAL"
            )
            or terminal.pending_child_count != current.pending_child_count
            or not isinstance(current, SurfaceCoverageV8)
            and terminal.scope_certificate_hash
            != current.scope_certificate_ref.content_hash
        ):
            return None
        reasons = Counter(
            code if code in SURFACE_REASON_CODES else "OTHER"
            for row in current.surfaces
            for code in row.unresolved_reason_codes
        )
        version5_counts: dict[str, int] = {}
        if terminal.surface_proof_version in (5, 6, 7, 8):
            if not isinstance(
                current,
                (
                    SurfaceCoverageV5,
                    SurfaceCoverageV6,
                    SurfaceCoverageV7,
                    SurfaceCoverageV8,
                ),
            ):
                return None
            version5_counts["COMPLETED_INCONCLUSIVE_CHILD_COUNT"] = len(
                {
                    child["hypothesis_id"]
                    for row in current.surfaces
                    for child in row.completed_inconclusive_children
                }
            )
        reviewed_count = (
            sum(bool(row.reviewed_context_ids) for row in current.surfaces)
            if isinstance(current, SurfaceCoverageV8)
            else sum(row.review_classification is not None for row in current.surfaces)
        )
        return {
            **counts,
            **version5_counts,
            "REVIEWED": reviewed_count,
            **(
                {
                    "TEMPLATE_CONTENT_NOT_ANALYZED_COUNT": sum(
                        row.external_scope_limit == "TEMPLATE_CONTENT_NOT_ANALYZED"
                        for row in current.surfaces
                    )
                }
                if isinstance(current, SurfaceCoverageV8)
                else {}
            ),
            "RAW_STATIC_GAP_COUNT": len(current.raw_static_gaps),
            "EFFECTIVE_PYTHON_GAP_COUNT": len(current.effective_python_gaps),
            "UNRESOLVED_REASON_COUNT": sum(
                len(row.unresolved_reason_codes) for row in current.surfaces
            ),
            **{
                f"{SURFACE_REASON_CODE_PREFIX}{code}": count
                for code, count in reasons.items()
            },
        }
    if terminal.surface_proof_version == 2:
        return _verified_surface_v2_counts(
            payload, index, terminal, certificate_payload, artifacts
        )
    if terminal.surface_proof_version != 1:
        return None
    if (
        payload.get("kind") != "simple_attack_surface_coverage_v1"
        or payload.get("scope_fingerprint") != index.scope_fingerprint
        or payload.get("static_bundle_hash") != index.static_bundle_hash
        or payload.get("ast_manifest_hash") != index.ast_manifest_hash
        or payload.get("candidate_inventory_hash") != index.candidate_inventory_hash
        or payload.get("candidate_count") != index.candidate_count
        or payload.get("static_gaps") != index.to_json()["static_gaps"]
    ):
        return None
    rows = payload.get("surfaces")
    if not isinstance(rows, list):
        return None
    indexed_ids = {surface.surface_id for surface in index.surfaces}
    seen: set[str] = set()
    counts = {status: 0 for status in SURFACE_STATUSES}
    for row in rows:
        if not isinstance(row, dict):
            return None
        surface_id = row.get("surface_id")
        status = row.get("coverage_status")
        if (
            not isinstance(surface_id, str)
            or surface_id not in indexed_ids
            or surface_id in seen
            or not isinstance(status, str)
            or status not in counts
        ):
            return None
        seen.add(surface_id)
        counts[status] += 1
    complete = not index.static_gaps and counts["COVERED"] == len(indexed_ids)
    if (
        seen != indexed_ids
        or payload.get("complete") is not complete
        or counts != terminal.surface_counts
        or terminal.status == "COMPLETE"
        and not complete
    ):
        return None
    return counts
