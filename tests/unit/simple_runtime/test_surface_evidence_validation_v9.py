"""A v9 review cannot promote model prose into path coverage without citations."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from sastsimi.simple_runtime.surface_enrichment_v9 import (
    V9Part,
    prepare_surface_enrichment_v9,
)
from sastsimi.simple_runtime.surface_evidence_validation_v9 import (
    v9_response_schema,
    validate_saved_v9_result,
    validate_v9_context,
    validate_v9_response,
)
from tests.unit.simple_runtime.test_surface_enrichment_v9 import connected_inputs


def _case(
    tmp_path: Path,
) -> tuple[SurfaceContext, dict[str, Any], CheckpointIdentity]:
    identity = CheckpointIdentity(
        analysis_id="analysis-v9",
        workspace_id="workspace-v9",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    source = "@app.route('/x')\ndef route():\n    return request.args['x']\n"
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    payload: dict[str, Any] = {
        "kind": "simple_surface_context_v9",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": "app.py",
        "scope_fingerprint": "scope-v9",
        "static_bundle_hash": "b" * 64,
        "ast_manifest_hash": "c" * 64,
        "surface_index_hash": "d" * 64,
        "prior_v8_plan_hash": "e" * 64,
        "prior_v8_coverage_hash": "f" * 64,
        "prior_v8_progress_hash": "1" * 64,
        "plan_binding_hash": "2" * 64,
        "surface_id": "surface-v9",
        "surface_type": "REQUEST_ENTRY",
        "path": "app.py",
        "line": 1,
        "graph_hash": "3" * 64,
        "path_certificate_hash": "4" * 64,
        "context_part": {
            "part_id": "part-1",
            "path_ids": ["path-a"],
            "path": "app.py",
            "start_line": 1,
            "end_line": 3,
            "source_sha256": source_hash,
            "content_sha256": source_hash,
        },
        "part_index": 0,
        "part_count": 1,
        "source_excerpt": source.rstrip("\n"),
        "role_directory": [
            {
                "path_id": "path-a",
                "role": "ENTRY",
                "location": "app.py:1",
                "source_sha256": source_hash,
                "edge_ids": ["edge-1"],
            },
            {
                "path_id": "path-a",
                "role": "TRUST_BOUNDARY",
                "location": "app.py:3",
                "source_sha256": source_hash,
                "edge_ids": ["edge-2"],
            },
            {
                "path_id": "path-a",
                "role": "ANCHOR",
                "location": "app.py:1",
                "source_sha256": source_hash,
                "edge_ids": ["edge-1"],
            },
        ],
    }
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v9",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": payload["surface_id"],
                "part_id": payload["context_part"]["part_id"],
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    context = SurfaceContext(
        surface_id="surface-v9",
        context_id=context_id,
        context_hash=ref.content_hash,
        context_ref=ref,
        part_index=0,
        part_count=1,
        prompt_bytes=len(artifacts.read(ref)),
        source_sha256=source_hash,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=0,
        omitted_ast_fact_count=0,
    )
    return context, payload, identity


def _response(context: SurfaceContext, payload: dict[str, Any]) -> dict[str, Any]:
    part = payload["context_part"]
    assert isinstance(part, dict)
    return {
        "surface_id": context.surface_id,
        "context_id": context.context_id,
        "context_hash": context.context_hash,
        "part_id": part["part_id"],
        "source_sha256": part["source_sha256"],
        "content_sha256": part["content_sha256"],
        "status": "NO_HYPOTHESIS",
        "reason": "The visible local source has no supported hypothesis.",
        "hypotheses": [],
        "reviewed_path_ids": ["path-a"],
        "review_evidence": [
            {**item, "explanation": "Reviewed the exact visible role."}
            for item in payload["role_directory"]
        ],
    }


def test_v9_valid_review_requires_exact_part_and_path_roles(tmp_path: Path) -> None:
    context, payload, identity = _case(tmp_path)

    validate_v9_context(context, payload, identity, "b" * 64)
    reviewed = validate_v9_response(context, payload, _response(context, payload))

    assert reviewed.status == "NO_HYPOTHESIS"
    assert reviewed.review_complete
    assert reviewed.reviewed_path_ids == ("path-a",)
    assert {(row["path_id"], row["role"]) for row in reviewed.role_citations} == {
        ("path-a", "ENTRY"),
        ("path-a", "TRUST_BOUNDARY"),
        ("path-a", "ANCHOR"),
    }


def test_v9_provider_schema_omits_unsupported_unique_items(tmp_path: Path) -> None:
    context, payload, _ = _case(tmp_path)

    schema = v9_response_schema(
        context,
        payload,
        {"type": "array", "items": {"type": "string"}},
    )

    assert "uniqueItems" not in schema["properties"]["reviewed_path_ids"]


def test_v9_semantic_validation_still_rejects_duplicate_paths(
    tmp_path: Path,
) -> None:
    context, payload, _ = _case(tmp_path)
    response = _response(context, payload)
    response["reviewed_path_ids"] = ["path-a", "path-a"]

    with pytest.raises(ValueError, match="V9_REVIEW_PATH_INVALID"):
        validate_v9_response(context, payload, response)


def test_v9_positive_review_missing_visible_role_is_rejected(tmp_path: Path) -> None:
    context, payload, _ = _case(tmp_path)
    response = _response(context, payload)
    response["review_evidence"] = response["review_evidence"][:-1]

    with pytest.raises(ValueError, match="V9_REVIEW_INCOMPLETE"):
        validate_v9_response(context, payload, response)


def test_v9_hypothesis_can_be_kept_without_claiming_complete_review(
    tmp_path: Path,
) -> None:
    context, payload, _ = _case(tmp_path)
    response = _response(context, payload)
    response["status"] = "HYPOTHESES"
    response["hypotheses"] = [{"title": "Potential issue"}]
    response["reviewed_path_ids"] = []
    response["review_evidence"] = []

    checked = validate_v9_response(context, payload, response)

    assert checked.status == "HYPOTHESES"
    assert not checked.review_complete
    assert checked.reviewed_path_ids == ()


def test_v9_rejects_cross_path_role_and_wrong_source_hash(tmp_path: Path) -> None:
    context, payload, _ = _case(tmp_path)
    response = _response(context, payload)
    response["review_evidence"][0]["path_id"] = "path-b"
    with pytest.raises(ValueError, match="V9_REVIEW_CITATION"):
        validate_v9_response(context, payload, response)

    response = _response(context, payload)
    response["review_evidence"][0]["source_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="V9_REVIEW_CITATION"):
        validate_v9_response(context, payload, response)


def test_v9_context_rejects_tampered_part_identity(tmp_path: Path) -> None:
    context, payload, identity = _case(tmp_path)
    tampered = dict(payload)
    tampered["plan_binding_hash"] = "5" * 64

    with pytest.raises(ValueError, match="V9_CONTEXT_INVALID"):
        validate_v9_context(context, tampered, identity, "b" * 64)


def test_v9_insufficient_can_name_only_paths_actually_reviewed(tmp_path: Path) -> None:
    context, payload, _ = _case(tmp_path)
    response = _response(context, payload)
    response.update(
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        reason="The downstream function was not visible.",
        reviewed_path_ids=[],
        review_evidence=[],
    )

    checked = validate_v9_response(context, payload, response)

    assert not checked.review_complete
    assert checked.reviewed_path_ids == ()


def test_v9_preserves_a_blank_final_source_line(tmp_path: Path) -> None:
    context, payload, identity = _case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    part = dict(payload["context_part"])
    part["end_line"] = 4
    payload["context_part"] = part
    payload["source_excerpt"] = payload["source_excerpt"] + "\n"
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v9",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": payload["surface_id"],
                "part_id": part["part_id"],
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    blank_end = replace(
        context,
        context_ref=ref,
        context_hash=ref.content_hash,
        context_id=context_id,
        prompt_bytes=len(artifacts.read(ref)),
    )

    validate_v9_context(blank_end, payload, identity, "b" * 64)


def test_v9_accepts_a_real_plan_context_part(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    _plan, parts = prepare_surface_enrichment_v9(**inputs)
    assert parts
    part = parts[0]
    identity = inputs["identity"]
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    # The path-proof fixture uses a non-hex AST placeholder ("m" * 64),
    # unlike a real content hash. Keep the planned shape and rebind that field.
    payload = {**part.payload, "ast_manifest_hash": "c" * 64}
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v9",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": part.surface_id,
                "part_id": part.part_id,
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    context = SurfaceContext(
        surface_id=part.surface_id,
        context_id=context_id,
        context_hash=ref.content_hash,
        context_ref=ref,
        part_index=part.part_index,
        part_count=part.part_count,
        prompt_bytes=len(artifacts.read(ref)),
        source_sha256=part.source_sha256,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=0,
        omitted_ast_fact_count=0,
    )

    validate_v9_context(context, payload, identity, inputs["index"].static_bundle_hash)


def _saved_case(
    context: SurfaceContext, payload: dict[str, Any]
) -> tuple[V9Part, dict[str, Any]]:
    part = payload["context_part"]
    assert isinstance(part, dict)
    planned = V9Part(
        payload=payload,
        surface_id=context.surface_id,
        context_id=context.context_id,
        context_hash=context.context_hash,
        part_id=part["part_id"],
        part_index=context.part_index,
        part_count=context.part_count,
        source_sha256=part["source_sha256"],
    )
    saved: dict[str, Any] = {
        "kind": "simple_surface_hypothesis_result_v9",
        "analysis_id": "analysis-v9",
        "surface_id": context.surface_id,
        "context_id": context.context_id,
        "context_hash": context.context_hash,
        "part_id": part["part_id"],
        "part_index": context.part_index,
        "part_count": context.part_count,
        "source_sha256": part["source_sha256"],
        "content_sha256": part["content_sha256"],
        "static_bundle_hash": payload["static_bundle_hash"],
        "status": "NO_HYPOTHESIS",
        "reason": "Reviewed local source.",
        "reviewed_path_ids": ["path-a"],
        "role_citations": payload["role_directory"],
        "review_complete": True,
        "reviewed_parts": ["ANCHOR", "ENTRY", "TRUST_BOUNDARY"],
        "evidence_locations": ["app.py:1", "app.py:3"],
        "seed_ids": [],
        "response": {},
        "validation_status": "VALID",
        "validation_feedback": None,
        "attempt_input_refs": [],
        "llm_request_ref": None,
        "llm_response_ref": None,
        "llm_raw_output_ref": None,
    }
    return planned, saved


def test_v9_saved_result_replay_reconstructs_exact_complete_review(
    tmp_path: Path,
) -> None:
    context, payload, _identity = _case(tmp_path)
    part, saved = _saved_case(context, payload)

    reviewed = validate_saved_v9_result(part, saved, ())

    assert reviewed.status == "NO_HYPOTHESIS"
    assert reviewed.reviewed_path_ids == ("path-a",)
    assert {row.role for row in reviewed.role_citations} == {
        "ENTRY",
        "TRUST_BOUNDARY",
        "ANCHOR",
    }


def test_v9_saved_result_replay_rejects_forged_completeness_and_seeds(
    tmp_path: Path,
) -> None:
    context, payload, _identity = _case(tmp_path)
    part, saved = _saved_case(context, payload)
    saved["role_citations"] = saved["role_citations"][:-1]
    with pytest.raises(ValueError, match="V9_SAVED_RESULT_INVALID"):
        validate_saved_v9_result(part, saved, ())

    part, saved = _saved_case(context, payload)
    saved["seed_ids"] = ["hypothesis-forged"]
    with pytest.raises(ValueError, match="V9_SAVED_RESULT_INVALID"):
        validate_saved_v9_result(part, saved, ())


def test_v9_saved_result_replay_keeps_incomplete_hypothesis_insufficient(
    tmp_path: Path,
) -> None:
    context, payload, _identity = _case(tmp_path)
    part, saved = _saved_case(context, payload)
    saved.update(
        status="HYPOTHESES",
        reviewed_path_ids=[],
        role_citations=[],
        review_complete=False,
        reviewed_parts=[],
        evidence_locations=[],
        seed_ids=["hypothesis-valid"],
    )

    reviewed = validate_saved_v9_result(part, saved, ("hypothesis-valid",))

    assert reviewed.status == "HYPOTHESES"
    assert reviewed.reviewed_path_ids == ()
    assert reviewed.role_citations == ()


def test_v9_saved_result_replay_preserves_nonempty_path_subset(tmp_path: Path) -> None:
    context, payload, identity = _case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    context_part = dict(payload["context_part"])
    context_part["path_ids"] = ["path-a", "path-b"]
    payload["context_part"] = context_part
    payload["role_directory"] = [
        *payload["role_directory"],
        *[{**row, "path_id": "path-b"} for row in payload["role_directory"]],
    ]
    ref = artifacts.put_json(payload)
    context_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v9",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": payload["surface_id"],
                "part_id": context_part["part_id"],
                "context_hash": ref.content_hash,
            }
        )
    ).hexdigest()
    context = replace(context, context_id=context_id, context_hash=ref.content_hash)
    part, saved = _saved_case(context, payload)
    saved.update(
        context_hash=context.context_hash,
        context_id=context.context_id,
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        reviewed_path_ids=["path-a"],
        review_complete=False,
        reviewed_parts=[],
        evidence_locations=[],
    )
    saved["role_citations"] = [
        row for row in payload["role_directory"] if row["path_id"] == "path-a"
    ]

    reviewed = validate_saved_v9_result(part, saved, ())

    assert reviewed.reviewed_path_ids == ("path-a",)
    assert {row.path_id for row in reviewed.role_citations} == {"path-a"}


def test_v9_rejects_citation_for_path_not_marked_reviewed(tmp_path: Path) -> None:
    context, payload, _ = _case(tmp_path)
    response = _response(context, payload)
    response["status"] = "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    response["reviewed_path_ids"] = []

    with pytest.raises(ValueError, match="V9_REVIEW_CITATION_INVALID"):
        validate_v9_response(context, payload, response)
