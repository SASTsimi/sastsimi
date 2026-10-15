"""Each source part must cite its own claimed path roles before coverage."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.surface_coverage_v7 import _connected_review
from sastsimi.simple_runtime.surface_enrichment_v9 import (
    ReviewStatusV9,
    RoleV9,
    V9Part,
    V9ReviewedPart,
    V9RoleCitation,
)
from sastsimi.simple_runtime.surface_evidence_validation_v9 import (
    validate_saved_v9_result,
    validate_v9_response,
)
from sastsimi.simple_runtime.surface_path_proof_v9 import PathCertificateV9
from tests.unit.simple_runtime.test_surface_evidence_validation_v9 import (
    _case,
    _response,
    _saved_case,
)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _part(part_id: str, roles: tuple[RoleV9, ...]) -> V9Part:
    return V9Part(
        payload={
            "context_part": {
                "part_id": part_id,
                "path_ids": ["path-a"],
                "source_sha256": "a" * 64,
                "content_sha256": "b" * 64,
            },
            "role_directory": [
                {
                    "path_id": "path-a",
                    "role": role,
                    "location": f"app.py:{part_id}",
                    "source_sha256": "a" * 64,
                    "edge_ids": [part_id],
                }
                for role in roles
            ],
        },
        surface_id="surface-a",
        context_id=part_id,
        context_hash="c" * 64,
        part_id=part_id,
        part_index=0 if part_id == "part-1" else 1,
        part_count=2,
        source_sha256="a" * 64,
    )


def _review(
    part: V9Part, roles: tuple[RoleV9, ...], status: ReviewStatusV9
) -> V9ReviewedPart:
    return V9ReviewedPart(
        surface_id=part.surface_id,
        context_id=part.context_id,
        context_hash=part.context_hash,
        part_id=part.part_id,
        source_sha256=part.source_sha256,
        content_sha256="b" * 64,
        status=status,
        reviewed_path_ids=("path-a",),
        role_citations=tuple(
            V9RoleCitation(
                path_id="path-a",
                role=role,
                location=f"app.py:{part.part_id}",
                source_sha256="a" * 64,
                edge_ids=(part.part_id,),
            )
            for role in roles
        ),
    )


def test_duplicate_role_in_other_part_cannot_complete_incomplete_part() -> None:
    first = _part("part-1", ("ENTRY", "TRUST_BOUNDARY", "ANCHOR"))
    second = _part("part-2", ("TRUST_BOUNDARY",))
    certificate = PathCertificateV9(
        surface_id="surface-a",
        graph_hash="d" * 64,
        index_hash="e" * 64,
        applicability_hash="f" * 64,
        path_ids=("path-a",),
        unresolved_path_ids=(),
        unresolved_gap_codes=(),
        context_parts=(),
        source_complete=True,
    )

    ready, reasons, _roles, reviewed_paths, _contexts = _connected_review(
        "surface-a",
        certificate,
        (first, second),
        {
            ("surface-a", first.context_id): _review(
                first, ("ENTRY", "ANCHOR"), "HYPOTHESES"
            ),
            ("surface-a", second.context_id): _review(
                second, ("TRUST_BOUNDARY",), "NO_HYPOTHESIS"
            ),
        },
    )

    assert not ready
    assert "SURFACE_EVIDENCE_INSUFFICIENT" in reasons
    assert reviewed_paths == ()


def test_duplicate_role_within_part_needs_both_exact_citations() -> None:
    part = _part("part-1", ("ENTRY", "TRUST_BOUNDARY", "ANCHOR"))
    directory = cast(list[dict[str, object]], part.payload["role_directory"])
    part = replace(
        part,
        payload={
            **part.payload,
            "role_directory": [
                *directory,
                {**directory[1], "location": "app.py:2", "edge_ids": ["edge-2"]},
            ],
        },
    )
    certificate = PathCertificateV9(
        surface_id="surface-a",
        graph_hash="d" * 64,
        index_hash="e" * 64,
        applicability_hash="f" * 64,
        path_ids=("path-a",),
        unresolved_path_ids=(),
        unresolved_gap_codes=(),
        context_parts=(),
        source_complete=True,
    )

    ready, reasons, _roles, reviewed_paths, _contexts = _connected_review(
        "surface-a",
        certificate,
        (part,),
        {
            ("surface-a", part.context_id): _review(
                part, ("ENTRY", "TRUST_BOUNDARY", "ANCHOR"), "HYPOTHESES"
            ),
        },
    )

    assert not ready
    assert "SURFACE_EVIDENCE_INSUFFICIENT" in reasons
    assert reviewed_paths == ()


def test_response_duplicate_role_needs_both_exact_citations(tmp_path: Path) -> None:
    context, payload, _ = _case(tmp_path)
    duplicate = {
        **payload["role_directory"][1],
        "location": "app.py:2",
        "edge_ids": ["edge-other"],
    }
    payload["role_directory"].append(duplicate)
    response = _response(context, payload)
    response.update(
        status="HYPOTHESES",
        hypotheses=[{"title": "Potential issue"}],
        review_evidence=response["review_evidence"][:-1],
    )

    checked = validate_v9_response(context, payload, response)

    assert checked.review_complete is False


def test_saved_duplicate_role_needs_both_exact_citations(tmp_path: Path) -> None:
    context, payload, _ = _case(tmp_path)
    payload["role_directory"].append(
        {
            **payload["role_directory"][1],
            "location": "app.py:2",
            "edge_ids": ["edge-other"],
        }
    )
    context_hash = _digest(payload)
    context_id = _digest(
        {
            "kind": "simple_surface_context_id_v9",
            "plan_binding_hash": payload["plan_binding_hash"],
            "surface_id": payload["surface_id"],
            "part_id": payload["context_part"]["part_id"],
            "context_hash": context_hash,
        }
    )
    bound_context = replace(context, context_hash=context_hash, context_id=context_id)
    part, saved = _saved_case(bound_context, payload)
    saved.update(
        status="HYPOTHESES",
        seed_ids=["hypothesis-a"],
        role_citations=saved["role_citations"][:-1],
        review_complete=False,
        reviewed_parts=[],
        evidence_locations=[],
    )

    reviewed = validate_saved_v9_result(part, saved, ("hypothesis-a",))

    assert reviewed.review_complete is False


def test_saved_incomplete_review_propagates_to_coverage_value(tmp_path: Path) -> None:
    context, payload, _ = _case(tmp_path)
    part, saved = _saved_case(context, payload)
    saved.update(
        status="HYPOTHESES",
        seed_ids=["hypothesis-a"],
        role_citations=saved["role_citations"][:-1],
        review_complete=False,
        reviewed_parts=[],
        evidence_locations=[],
    )

    reviewed = validate_saved_v9_result(part, saved, ("hypothesis-a",))

    assert reviewed.review_complete is False
