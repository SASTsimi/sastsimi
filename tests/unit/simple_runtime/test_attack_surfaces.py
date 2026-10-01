"""Attack surfaces require exact evidence, not merely nearby candidates."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.attack_surfaces import (
    SurfaceReview,
    build_attack_surface_index,
    candidate_inventory_hash,
    evaluate_surface_coverage,
    surface_index_from_json,
)
from sastsimi.simple_runtime.candidates import CandidateOrigin, StaticCandidate
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SimpleCheckpointStore

_SOURCE = (
    "def helper(value):\n"
    "    return value\n"
    "\n"
    "def route(path):\n"
    "    check_permission(path)\n"
    "    Path(path).write_text('payload')\n"
)


def _fixture(
    tmp_path: Path,
    *,
    source: str = _SOURCE,
    coverage_gaps: list[dict[str, str]] | None = None,
    candidate_lines: tuple[int, ...] = (5,),
    flow_identities: tuple[str | None, ...] = (None,),
) -> tuple[
    dict[str, object],
    dict[str, object],
    tuple[StaticCandidate, ...],
    SimpleArtifactRepository,
]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(source, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="surface-analysis",
        workspace_id="surface-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=32_768
    )
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "fingerprint": "scope-surface",
            "expected_count": 2,
            "verified_count": 2 - len(coverage_gaps or []),
            "gaps": coverage_gaps or [],
            "unsupported": [],
            "excluded_paths": [],
        }
    )
    bundle: dict[str, object] = {
        "kind": "simple_static_fact_bundle",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "static_coverage_ref": coverage_ref.model_dump(mode="json"),
        "ast_summary": summary,
    }
    raw_ref = artifacts.put_json({"kind": "fixture-raw"})
    candidates = tuple(
        StaticCandidate(
            candidate_id=f"C-{index}",
            kind="FLOW" if flow_id is not None else "HINT",
            path="app.py",
            line=line,
            end_line=line,
            evidence_ref=raw_ref,
            origins=(
                CandidateOrigin(
                    engine="opengrep",
                    rule_id=(
                        "sastsimi.python.permission-check"
                        if line == 5
                        else "sastsimi.python.path-sink"
                    ),
                    artifact_ref=raw_ref,
                    result_index=index,
                ),
            ),
            flow_identity=flow_id,
            evidence_key=f"evidence-{index}",
        )
        for index, (line, flow_id) in enumerate(
            zip(candidate_lines, flow_identities, strict=True)
        )
    )
    return bundle, summary, candidates, artifacts


def test_surface_index_tracks_unreviewed_sink(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)

    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)
    coverage = evaluate_surface_coverage(index, ())

    assert {surface.type for surface in coverage.surfaces} >= {
        "AUTHORIZATION",
        "FILE_WRITE",
    }
    assert all(surface.symbol != "helper" for surface in coverage.surfaces)
    auth = next(surface for surface in coverage.surfaces if surface.line == 5)
    sink = next(surface for surface in coverage.surfaces if surface.line == 6)
    assert auth.linked_candidate_ids == ("C-0",)
    assert sink.linked_candidate_ids == ()
    assert sink.coverage_status == "UNCOVERED"
    assert coverage.complete is False


def test_saved_surface_index_replays_exactly_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)
    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)
    payload = index.to_json()

    assert surface_index_from_json(payload) == index
    altered = {**payload, "kind": "simple_attack_surface_index_unknown"}
    with pytest.raises(ValueError, match="SURFACE_INDEX_CHECKPOINT_INVALID"):
        surface_index_from_json(altered)


def test_candidate_presence_and_partial_review_do_not_cover_surface(
    tmp_path: Path,
) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)
    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)
    auth = next(surface for surface in index.surfaces if surface.line == 5)
    proof_ref = artifacts.put_json({"kind": "verified-review"})
    partial = SurfaceReview(
        surface_id=auth.surface_id,
        candidate_id="C-0",
        hypothesis_id="H-0",
        verification_status="COMPLETE",
        reviewed_parts=frozenset({"ENTRY", "SENSITIVE_OPERATION"}),
        evidence_locations=("app.py:5",),
        evidence_refs=(proof_ref,),
    )

    partial_coverage = evaluate_surface_coverage(index, (partial,))
    assert (
        next(
            item.coverage_status
            for item in partial_coverage.surfaces
            if item.surface_id == auth.surface_id
        )
        == "INSUFFICIENT"
    )

    full = SurfaceReview(
        surface_id=auth.surface_id,
        candidate_id="C-0",
        hypothesis_id="H-0",
        verification_status="COMPLETE",
        reviewed_parts=frozenset({"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"}),
        evidence_locations=("app.py:5",),
        evidence_refs=(proof_ref,),
    )
    reviewed = evaluate_surface_coverage(index, (full,))
    covered_auth = next(
        item for item in reviewed.surfaces if item.surface_id == auth.surface_id
    )
    assert covered_auth.coverage_status == "COVERED"
    assert covered_auth.review_evidence_refs == (proof_ref,)
    serialized = reviewed.to_json()["surfaces"]
    assert isinstance(serialized, list)
    assert next(
        row["review_evidence_refs"]
        for row in serialized
        if row["surface_id"] == auth.surface_id
    ) == [proof_ref.model_dump(mode="json")]
    assert reviewed.complete is False  # The unreviewed file-write sink remains.


def test_static_file_rule_gap_is_separate_from_surface_gap(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(
        tmp_path,
        coverage_gaps=[
            {
                "path": "app.py",
                "rule_id": "sastsimi.python.path-sink",
                "reason": "TIMEOUT",
            }
        ],
    )
    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)
    coverage = evaluate_surface_coverage(index, ())

    assert [(gap.path, gap.rule_id, gap.reason) for gap in index.static_gaps] == [
        ("app.py", "sastsimi.python.path-sink", "TIMEOUT")
    ]
    assert all(surface.line > 0 for surface in coverage.surfaces)
    assert coverage.static_gaps == index.static_gaps
    assert coverage.complete is False


def test_distinct_flows_at_same_sink_remain_distinct(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(
        tmp_path,
        candidate_lines=(6, 6),
        flow_identities=("source-a-to-sink", "source-b-to-sink"),
    )
    first = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)
    replay = build_attack_surface_index(
        bundle, summary, tuple(reversed(candidates)), artifacts=artifacts
    )

    flows = [surface for surface in first.surfaces if surface.flow_identity]
    assert len(flows) == 2
    assert len({surface.surface_id for surface in flows}) == 2
    assert [surface.surface_id for surface in replay.surfaces] == [
        surface.surface_id for surface in first.surfaces
    ]


def test_missing_cas_reader_does_not_turn_unknown_coverage_into_complete(
    tmp_path: Path,
) -> None:
    bundle, summary, candidates, _artifacts = _fixture(tmp_path)

    with pytest.raises(ValueError, match="SURFACE_EVIDENCE_UNAVAILABLE"):
        build_attack_surface_index(bundle, summary, candidates)


def test_unavailable_engine_without_file_rows_remains_a_separate_gap(
    tmp_path: Path,
) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)
    bundle["static_coverage_ref"] = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "fingerprint": "scope-surface",
            "expected_count": 1,
            "verified_count": 0,
            "gaps": [],
            "unsupported": [],
            "excluded_paths": [],
            "unavailable": True,
            "unavailable_paths": [],
            "codeql_error": "CODEQL_QUERY_FAILED",
        }
    ).model_dump(mode="json")

    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)

    assert {(gap.rule_id, gap.reason) for gap in index.static_gaps} >= {
        ("STATIC", "STATIC_UNAVAILABLE"),
        ("CODEQL", "CODEQL_QUERY_FAILED"),
    }
    assert evaluate_surface_coverage(index, ()).complete is False


def test_raw_candidate_evidence_is_not_a_completed_review(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)
    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)
    auth = next(surface for surface in index.surfaces if surface.line == 5)
    raw_ref = candidates[0].evidence_ref
    raw_only = SurfaceReview(
        surface_id=auth.surface_id,
        candidate_id="C-0",
        hypothesis_id="H-0",
        verification_status="COMPLETE",
        reviewed_parts=frozenset({"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"}),
        evidence_locations=("app.py:5",),
        evidence_refs=(raw_ref,),
    )

    result = evaluate_surface_coverage(index, (raw_only,))

    assert (
        next(
            surface.coverage_status
            for surface in result.surfaces
            if surface.surface_id == auth.surface_id
        )
        == "INSUFFICIENT"
    )


def test_index_rejects_ast_manifest_from_another_static_bundle(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)
    bundle["ast_summary"] = {"kind": "simple_python_ast", "facts": []}

    with pytest.raises(ValueError, match="SURFACE_AST_BUNDLE_MISMATCH"):
        build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)


def test_unsupported_product_path_does_not_become_complete(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)
    bundle["static_coverage_ref"] = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "fingerprint": "scope-surface",
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported": [],
            "unsupported_files": [
                {"path": "app/native.c", "reason": "UNSUPPORTED_LANGUAGE"}
            ],
            "excluded_paths": [],
        }
    ).model_dump(mode="json")

    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)

    assert (
        "app/native.c",
        "STATIC_SCOPE",
        "UNSUPPORTED_LANGUAGE",
    ) in {(gap.path, gap.rule_id, gap.reason) for gap in index.static_gaps}
    assert evaluate_surface_coverage(index, ()).complete is False


def test_same_rule_hint_and_flow_have_stable_distinct_ids(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(
        tmp_path,
        candidate_lines=(6, 6),
        flow_identities=(None, "attacker-route-to-file"),
    )

    first = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)
    replay = build_attack_surface_index(
        bundle, summary, tuple(reversed(candidates)), artifacts=artifacts
    )

    static_surfaces = [
        surface for surface in first.surfaces if surface.detector == "STATIC_RULE"
    ]
    assert len(static_surfaces) == 2
    assert len({surface.surface_id for surface in static_surfaces}) == 2
    assert [surface.surface_id for surface in first.surfaces] == [
        surface.surface_id for surface in replay.surfaces
    ]


def test_no_rules_and_unsupported_extension_are_not_complete(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)
    bundle["static_coverage_ref"] = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "fingerprint": "scope-surface",
            "expected_count": 0,
            "verified_count": 0,
            "gaps": [],
            "unsupported": [{"extension": ".c", "file_count": 1}],
            "excluded_paths": [],
        }
    ).model_dump(mode="json")

    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)

    assert {(gap.rule_id, gap.reason) for gap in index.static_gaps} >= {
        ("STATIC", "NO_STATIC_RULES"),
        ("STATIC_SCOPE", "UNSUPPORTED_EXTENSION:.c"),
    }
    assert evaluate_surface_coverage(index, ()).complete is False


def test_surface_index_ref_is_bound_to_exact_candidate_set(tmp_path: Path) -> None:
    bundle, summary, candidates, artifacts = _fixture(tmp_path)
    identity = artifacts.identity
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    index = build_attack_surface_index(bundle, summary, candidates, artifacts=artifacts)
    ref = artifacts.put_json(index.to_json())
    candidate_hash = candidate_inventory_hash(candidates)

    store.save_attack_surface_index(
        identity,
        index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=candidate_hash,
        candidate_count=len(candidates),
        index_ref=ref,
    )
    saved = store.get_attack_surface_index(identity, index.scope_fingerprint)
    assert saved is not None
    assert saved.index_ref == ref
    assert saved.candidate_inventory_hash == candidate_hash
    assert saved.candidate_count == len(candidates)
    with pytest.raises(ValueError, match="SURFACE_INDEX_CHECKPOINT_CONFLICT"):
        store.save_attack_surface_index(
            identity,
            index.scope_fingerprint,
            static_bundle_hash=index.static_bundle_hash,
            ast_manifest_hash=index.ast_manifest_hash,
            candidate_inventory_hash="changed",
            candidate_count=len(candidates),
            index_ref=ref,
        )


def test_candidate_inventory_hash_detects_changed_origin(tmp_path: Path) -> None:
    _bundle, _summary, candidates, _artifacts = _fixture(tmp_path)
    altered = candidates[0].model_copy(
        update={
            "origins": candidates[0].origins
            + (candidates[0].origins[0].model_copy(update={"engine": "semgrep"}),)
        }
    )

    assert candidate_inventory_hash(candidates) != candidate_inventory_hash((altered,))
