"""A v2 coverage proof may certify only pinned, connected evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import surface_enrichment_v4
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import (
    AttackSurface,
    StaticGap,
    SurfaceCoverage,
    SurfaceIndex,
)
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import (
    SimpleCheckpointStore,
    SurfaceExplorationProgressRecord,
)
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from sastsimi.simple_runtime.surface_coverage_v2 import (
    evaluate_surface_coverage_v2,
)
from sastsimi.simple_runtime.surface_enrichment_v4 import (
    prepare_surface_enrichment_v4,
)
from sastsimi.simple_runtime.surface_evidence_validation_v4 import (
    validate_v4_response,
)


@dataclass
class _Case:
    identity: CheckpointIdentity
    index: SurfaceIndex
    index_ref: StoredDataRef
    coverage: SurfaceCoverage
    coverage_ref: StoredDataRef
    plan: dict[str, object]
    certificate: dict[str, object]
    progress: dict[tuple[str, str], SurfaceExplorationProgressRecord]
    store: SimpleCheckpointStore
    artifacts: SimpleArtifactRepository

    def evaluate(self):
        return evaluate_surface_coverage_v2(
            self.identity,
            self.index,
            self.index_ref,
            self.coverage,
            self.plan,
            self.certificate,
            self.progress,
            self.store,
            self.artifacts,
        )


def _case(
    tmp_path: Path,
    *,
    unrelated_role: bool = False,
    old_hold: bool = False,
    python_gap: bool = False,
    persist_certificate: bool = True,
    forge_gap_clearance: bool = False,
    persist_old_result: bool = True,
    python_exclusion: bool = False,
    omit_sensitive_role: bool = False,
) -> _Case:
    identity = CheckpointIdentity(
        analysis_id="analysis-v2",
        workspace_id="workspace-v2",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    store = SimpleCheckpointStore(
        artifacts.paths.database,
        artifact_data_dir=data_dir,
    )
    static_ref = artifacts.put_json({"kind": "static-bundle"})
    static_coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "gaps": [],
            "out_of_scope_product_files": (
                [{"path": "app.py", "reason": "python_product_source"}]
                if python_exclusion
                else []
            ),
        }
    )
    evidence_ref = artifacts.put_json({"kind": "static-evidence"})
    source = (
        "@app.route('/run')\n"
        "def route(value):\n"
        "    value = request.args['value']\n"
        "    return dangerous(value)\n"
    )
    source_sha = hashlib.sha256(source.encode()).hexdigest()
    surface = AttackSurface(
        surface_id="surface-1",
        type="COMMAND_EXECUTION",
        path="app.py",
        symbol="dangerous",
        line=4,
        linked_candidate_ids=(),
        evidence_refs=(evidence_ref,),
        detector="AST",
    )
    old_proof_ref = artifacts.put_json({"kind": "old-surface-proof"})
    covered = replace(
        surface,
        surface_id="surface-covered",
        line=2,
        coverage_status="UNCOVERED",
    )
    gap = StaticGap("app.py", "AST", "AST_PARSE_ERROR", "AST")
    gaps = (gap,) if python_gap else ()
    index = SurfaceIndex(
        scope_fingerprint="f" * 64,
        static_bundle_hash=static_ref.content_hash,
        ast_manifest_hash="b" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="c" * 64,
        candidate_count=0,
        surfaces=(surface, covered),
        static_gaps=gaps,
        index_version=2,
        ast_source_hashes=(("app.py", source_sha),),
    )
    index_ref = artifacts.put_json(index.to_json())
    coverage = SurfaceCoverage(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=0,
        surfaces=(
            replace(surface, coverage_status="INSUFFICIENT"),
            replace(
                covered,
                coverage_status="COVERED",
                review_evidence_refs=(old_proof_ref,),
            ),
        ),
        static_gaps=gaps,
    )
    coverage_ref = artifacts.put_json(coverage.to_json())
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="example/repository",
            static_disposition="FULL",
            static_bundle_ref=static_ref,
            static_coverage_ref=static_coverage_ref,
            candidate_terminal=CandidateTerminal(
                status="PARTIAL",
                bundle_hash=static_ref.content_hash,
                scope_fingerprint=index.scope_fingerprint,
                decision_counts={
                    "PENDING": 0,
                    "INCLUDE": 0,
                    "EXCLUDE": 0,
                    "UNDECIDED": 0,
                    "ERROR": 0,
                },
                deep_counts={},
                hypothesis_count=0,
                surface_index_hash=index_ref.content_hash,
                surface_coverage_hash=coverage_ref.content_hash,
                surface_counts={"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 1},
                producer_finished=True,
                pending_child_count=0,
            ),
        )
    )
    certificate = {
        "kind": "simple_python_scope_recertification_v1",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": index.scope_fingerprint,
        "index_ref": index_ref.model_dump(mode="json"),
        "index_hash": index_ref.content_hash,
        "coverage_ref": static_coverage_ref.model_dump(mode="json"),
        "raw_static_gaps": index.to_json()["static_gaps"],
        "raw_coverage_gaps": [],
        "raw_out_of_scope_product_files": (
            [{"path": "app.py", "reason": "python_product_source"}]
            if python_exclusion
            else []
        ),
        "file_decisions": [],
        "effective_static_gaps": (
            [] if forge_gap_clearance else index.to_json()["static_gaps"]
        ),
    }
    if persist_certificate:
        artifacts.put_json(certificate)
    nodes = [
        {"node_id": "node-entry", "role": "ROUTE_ENTRY", "path": "app.py", "line": 1},
        {
            "node_id": "node-boundary",
            "role": "REQUEST_CONTEXT",
            "path": "app.py",
            "line": 3,
        },
        {"node_id": "node-sink", "role": "SINK", "path": "app.py", "line": 4},
    ]
    edges = [
        {
            "edge_id": "edge-entry",
            "type": "ENTRY",
            "from_node_id": "node-entry",
            "to_node_id": "node-boundary",
            "graph_path_id": "path-real",
        },
        {
            "edge_id": "edge-sink",
            "type": "SENSITIVE_OPERATION",
            "from_node_id": "node-boundary",
            "to_node_id": "node-sink",
            "graph_path_id": "path-real",
        },
    ]
    graph: dict[str, object] = {
        "kind": "simple_surface_evidence_graph_v4",
        "anchor": {
            "surface_id": surface.surface_id,
            "path": surface.path,
            "line": surface.line,
        },
        "scope_fingerprint": index.scope_fingerprint,
        "index_hash": index_ref.content_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "source_files": [{"path": "app.py", "source_sha256": source_sha}],
        "source_lines": [
            {
                "line_id": f"line-{line}",
                "path": "app.py",
                "line": line,
                "text": text,
                "source_sha256": source_sha,
            }
            for line, text in enumerate(source.splitlines(), 1)
        ],
        "ast_facts": [],
        "nodes": nodes,
        "edges": edges,
        "paths": [
            {
                "path_id": "path-real",
                "kind": "call_path_v1",
                "provenance": "python_syntax",
                "assurance": "SYNTACTIC_REACHABILITY",
                "steps": nodes,
                "edge_ids": ["edge-entry", "edge-sink"],
            }
        ],
        "gaps": [],
    }
    if unrelated_role:
        decoy_edges = [
            {
                **edge,
                "edge_id": "decoy-" + edge["edge_id"],
                "graph_path_id": "path-decoy",
            }
            for edge in edges
        ]
        graph["edges"] = [*edges, *decoy_edges]
        graph["paths"] = [
            *graph["paths"],
            {
                "path_id": "path-decoy",
                "kind": "call_path_v1",
                "provenance": "python_syntax",
                "assurance": "SYNTACTIC_REACHABILITY",
                "steps": nodes,
                "edge_ids": ["decoy-edge-entry", "decoy-edge-sink"],
            },
        ]
    graph_ref = artifacts.put_json(graph)
    prior_progress: dict[tuple[str, str], SurfaceExplorationProgressRecord] = {}
    if old_hold:
        hold_ref = artifacts.put_json({"kind": "old-environment-hold"})
        child_id = "hypothesis-old"
        child = identity.model_copy(update={"hypothesis_id": child_id})
        store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=SimpleStage.VERIFICATION_INITIAL_DONE,
                stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(hold_ref,),
                external_prerequisites_ref=hold_ref,
                verdict="HOLD",
            )
        )
        old_result_ref = (
            artifacts.put_json({"kind": "old-v3-result"})
            if persist_old_result
            else StoredDataRef(
                stored_data_id=StoredDataId("9" * 64),
                data_kind="artifact",
                content_hash="9" * 64,
                workspace_id=WorkspaceId(identity.workspace_id),
                commit_id=CommitId(identity.commit_id),
                record_id=None,
            )
        )
        old_context_ref = artifacts.put_json(
            {"kind": "simple_surface_context_v3", "surface_id": surface.surface_id}
        )
        prior_progress[(surface.surface_id, "old-v3-context")] = (
            SurfaceExplorationProgressRecord(
                surface_id=surface.surface_id,
                context_id="old-v3-context",
                static_bundle_hash=static_ref.content_hash,
                index_hash=index_ref.content_hash,
                context_hash=old_context_ref.content_hash,
                source_sha256=source_sha,
                status="HYPOTHESES",
                result_ref=old_result_ref,
                hypothesis_ids=(child_id,),
                proposal_version=3,
            )
        )
    plan, parts = prepare_surface_enrichment_v4(
        identity,
        index.scope_fingerprint,
        static_ref,
        index,
        index_ref,
        certificate,
        coverage,
        prior_progress,
        {surface.surface_id: graph},
        prior_coverage_ref=coverage_ref,
    )
    plan_ref = artifacts.put_json(plan)
    certificate_ref = (
        artifacts.put_json(certificate)
        if persist_certificate
        else StoredDataRef(
            stored_data_id=StoredDataId(
                hashlib.sha256(canonical_bytes(certificate)).hexdigest()
            ),
            data_kind="artifact",
            content_hash=hashlib.sha256(canonical_bytes(certificate)).hexdigest(),
            workspace_id=WorkspaceId(identity.workspace_id),
            commit_id=CommitId(identity.commit_id),
            record_id=None,
        )
    )
    current = store.require_analysis_run(identity.analysis_id)
    store.save_analysis_run(
        current.model_copy(
            update={
                "surface_enrichment_plan_ref": plan_ref,
                "python_scope_certificate_ref": certificate_ref,
            }
        )
    )
    progress = dict(prior_progress)
    for part in parts:
        context_ref = artifacts.put_json(part.payload)
        context = SurfaceContext(
            surface_id=part.surface_id,
            context_id=part.context_id,
            context_hash=part.context_hash,
            context_ref=context_ref,
            part_index=part.part_index,
            part_count=part.part_count,
            prompt_bytes=len(canonical_bytes(part.payload)),
            source_sha256=part.source_sha256,
            source_unavailable_reason=None,
            ast_unavailable_reason=None,
            omitted_source_line_count=0,
            omitted_ast_fact_count=0,
        )
        visible_lines = {
            item["value"]["line"]
            for item in part.payload["items"]
            if item["category"] == "source_lines"
        }
        reply: dict[str, object] = {
            "surface_id": surface.surface_id,
            "context_id": context.context_id,
            "status": (
                "NO_HYPOTHESIS"
                if len(parts) == 1
                else "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
            ),
            "reason": "Reviewed exact source path.",
            "hypotheses": [],
            "review_evidence": [
                {
                    "part": role,
                    "location": f"app.py:{line}",
                    "context_hash": context.context_hash,
                    "source_sha256": source_sha,
                    "graph_path_id": "path-real",
                    "edge_ids": edge_ids,
                    "explanation": f"Verified {role}.",
                }
                for role, line, edge_ids in (
                    ("ENTRY", 1, ["edge-entry"]),
                    ("TRUST_BOUNDARY", 3, ["edge-entry", "edge-sink"]),
                    ("SENSITIVE_OPERATION", 4, ["edge-sink"]),
                )
                if line in visible_lines
                and (role != "SENSITIVE_OPERATION" or not omit_sensitive_role)
            ],
        }
        validated = validate_v4_response(reply, context, part.payload, graph)
        if unrelated_role:
            review = reply["review_evidence"]
            assert isinstance(review, list)
            boundary = review[1]
            assert isinstance(boundary, dict)
            boundary["graph_path_id"] = "path-decoy"
            boundary["edge_ids"] = ["decoy-edge-entry", "decoy-edge-sink"]
            validated = validate_v4_response(reply, context, part.payload, graph)
        result_ref = artifacts.put_json(
            {
                "kind": "simple_surface_hypothesis_result_v4",
                "analysis_id": identity.analysis_id,
                "surface_id": surface.surface_id,
                "context_id": context.context_id,
                "part_index": context.part_index,
                "part_count": context.part_count,
                "context_hash": context.context_hash,
                "static_bundle_hash": static_ref.content_hash,
                "graph_hash": graph_ref.content_hash,
                "graph_ref": graph_ref.model_dump(mode="json"),
                "status": validated.status,
                "reason": validated.reason,
                "reviewed_parts": sorted(validated.reviewed_parts),
                "evidence_locations": list(validated.evidence_locations),
                "verified_roles": list(validated.verified_roles),
                "seed_ids": [],
                "response": reply,
                "validation_status": "VALID",
            }
        )
        progress[(surface.surface_id, context.context_id)] = (
            SurfaceExplorationProgressRecord(
                surface_id=surface.surface_id,
                context_id=context.context_id,
                static_bundle_hash=static_ref.content_hash,
                index_hash=index_ref.content_hash,
                context_hash=context.context_hash,
                source_sha256=source_sha,
                status=validated.status,
                result_ref=result_ref,
                hypothesis_ids=(),
                proposal_version=4,
            )
        )
    return _Case(
        identity,
        index,
        index_ref,
        coverage,
        coverage_ref,
        plan,
        certificate,
        progress,
        store,
        artifacts,
    )


def test_covered_only_with_connected_three_role_proof_and_no_hold(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    original_v1 = case.artifacts.read(case.coverage_ref)
    original_index = case.artifacts.read(case.index_ref)

    proof = case.evaluate()

    assert proof.complete is True
    payload = proof.to_json()
    assert payload["kind"] == "simple_attack_surface_coverage_v2"
    assert payload["surfaces"][0]["coverage_status"] == "COVERED"
    assert len(payload["surfaces"][0]["verified_roles"]) == 3
    assert payload["surfaces"][0]["path"] == "app.py"
    assert payload["surfaces"][0]["line"] == 4
    assert payload["surfaces"][1]["coverage_status"] == "COVERED"
    assert payload["raw_static_gaps"] == []
    assert payload["effective_python_gaps"] == []
    assert case.artifacts.read(case.coverage_ref) == original_v1
    assert case.artifacts.read(case.index_ref) == original_index


def test_verified_roles_across_inconclusive_parts_can_cover_one_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(surface_enrichment_v4, "_MAX_PART_BYTES", 3000)
    case = _case(tmp_path)
    assert len(case.plan["expected_parts"]) > 1
    assert all(
        row.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
        for row in case.progress.values()
        if row.proposal_version == 4
    )

    proof = case.evaluate()

    assert proof.complete is True
    assert proof.surfaces[0].coverage_status == "COVERED"
    assert {role["part"] for role in proof.surfaces[0].verified_roles} == {
        "ENTRY",
        "TRUST_BOUNDARY",
        "SENSITIVE_OPERATION",
    }


def test_inconclusive_parts_without_sensitive_role_remain_insufficient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(surface_enrichment_v4, "_MAX_PART_BYTES", 3000)
    case = _case(tmp_path, omit_sensitive_role=True)
    assert len(case.plan["expected_parts"]) > 1

    proof = case.evaluate()

    assert proof.complete is False
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CONNECTED_ROLE_PROOF_MISSING" in (proof.surfaces[0].unresolved_reason_codes)


def test_unrelated_role_union_or_prior_hold_stays_insufficient(tmp_path: Path) -> None:
    unrelated = _case(tmp_path / "unrelated", unrelated_role=True)
    held = _case(tmp_path / "held", old_hold=True)

    unrelated_proof = unrelated.evaluate()
    held_proof = held.evaluate()

    assert unrelated_proof.complete is False
    assert unrelated_proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CONNECTED_ROLE_PROOF_MISSING" in (
        unrelated_proof.surfaces[0].unresolved_reason_codes
    )
    assert held_proof.complete is False
    assert held_proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in held_proof.surfaces[0].unresolved_reason_codes


def test_missing_v4_part_or_python_gap_stays_partial(tmp_path: Path) -> None:
    missing = _case(tmp_path / "missing")
    missing.progress.clear()
    with_gap = _case(tmp_path / "gap", python_gap=True)

    missing_proof = missing.evaluate()
    gap_proof = with_gap.evaluate()

    assert missing_proof.complete is False
    assert "SURFACE_PART_PENDING" in missing_proof.surfaces[0].unresolved_reason_codes
    assert gap_proof.complete is False
    assert gap_proof.effective_python_gaps == (
        {
            "path": "app.py",
            "rule_id": "AST",
            "reason": "AST_PARSE_ERROR",
            "engine": "AST",
        },
    )


def test_missing_certificate_cas_or_index_mismatch_blocks_publication(
    tmp_path: Path,
) -> None:
    missing = _case(tmp_path / "missing", persist_certificate=False)
    wrong_index = _case(tmp_path / "wrong")
    wrong_index.index_ref = wrong_index.artifacts.put_json({"kind": "wrong-index"})

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2"):
        missing.evaluate()
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2"):
        wrong_index.evaluate()


def test_python_gap_cannot_be_erased_by_forged_certificate(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path, python_gap=True, forge_gap_clearance=True)

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2"):
        case.evaluate()


def test_python_product_exclusion_cannot_be_erased_by_certificate(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path, python_exclusion=True)

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2"):
        case.evaluate()


def test_mutated_plan_or_missing_old_result_cannot_publish(
    tmp_path: Path,
) -> None:
    changed = _case(tmp_path / "changed")
    changed.plan["reader_revision"] = "unapproved"
    missing_old = _case(
        tmp_path / "missing-old",
        old_hold=True,
        persist_old_result=False,
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2"):
        changed.evaluate()
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2"):
        missing_old.evaluate()


def test_scope_certificate_must_match_the_saved_run_static_refs(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    case.store.save_analysis_run(
        run.model_copy(
            update={"static_coverage_ref": case.artifacts.put_json({"kind": "other"})}
        )
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2"):
        case.evaluate()


def test_pending_children_are_counted_across_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path)
    hypothesis_ids = tuple(f"hypothesis-{index:03d}" for index in range(104))
    seen: list[tuple[str | None, int]] = []

    def page(
        identity: CheckpointIdentity,
        *,
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        assert identity == case.identity
        seen.append((after_id, limit))
        return tuple(
            hypothesis_id
            for hypothesis_id in hypothesis_ids
            if after_id is None or hypothesis_id > after_id
        )[:limit]

    monkeypatch.setattr(case.store, "list_incomplete_hypotheses", page)

    proof = case.evaluate()

    assert proof.pending_child_count == 104
    assert seen == [(None, 100), ("hypothesis-099", 100)]


def test_stale_v1_pending_count_does_not_block_fresh_v2_proof(tmp_path: Path) -> None:
    case = _case(tmp_path)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={"pending_child_count": 9}
                )
            }
        )
    )

    proof = case.evaluate()

    assert proof.pending_child_count == 0
    assert proof.complete is True


def test_crash_between_coverage_artifact_and_terminal_is_idempotent(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    old_bytes = case.artifacts.read(case.coverage_ref)
    first = case.evaluate()
    saved_ref = case.artifacts.put_json(first.to_json())

    second = case.evaluate()

    assert first.to_json() == second.to_json()
    assert case.artifacts.put_json(second.to_json()) == saved_ref
    assert case.artifacts.read(case.coverage_ref) == old_bytes
    assert (
        case.store.require_analysis_run(
            case.identity.analysis_id
        ).candidate_terminal.status
        == "PARTIAL"
    )


def test_v2_terminal_replay_verifies_exact_new_proof(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    proof = case.evaluate()
    proof_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "status": "COMPLETE",
                        "surface_proof_version": 2,
                        "surface_coverage_hash": proof_ref.content_hash,
                        "scope_certificate_hash": (
                            proof.scope_certificate_ref.content_hash
                        ),
                    }
                )
            }
        )
    )

    replayed = case.evaluate()

    assert replayed.to_json() == proof.to_json()
    assert replayed.complete is True


def test_partial_v2_terminal_can_gain_a_missing_completed_part(tmp_path: Path) -> None:
    case = _case(tmp_path)
    part_key = next(
        key for key, row in case.progress.items() if row.proposal_version == 4
    )
    completed_part = case.progress.pop(part_key)
    before = case.evaluate()
    assert before.complete is False
    old_ref = case.artifacts.put_json(before.to_json())
    old_bytes = case.artifacts.read(old_ref)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "surface_proof_version": 2,
                        "surface_coverage_hash": old_ref.content_hash,
                        "scope_certificate_hash": (
                            before.scope_certificate_ref.content_hash
                        ),
                    }
                )
            }
        )
    )
    case.progress[part_key] = completed_part

    after = case.evaluate()

    assert after.complete is True
    assert after.to_json() != before.to_json()
    assert case.artifacts.read(old_ref) == old_bytes


def test_partial_v2_terminal_with_foreign_scope_cannot_recertify(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    stale = case.evaluate().to_json()
    stale["scope_fingerprint"] = "e" * 64
    foreign_ref = case.artifacts.put_json(stale)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "status": "PARTIAL",
                        "surface_proof_version": 2,
                        "surface_coverage_hash": foreign_ref.content_hash,
                        "scope_certificate_hash": case.plan["certificate_hash"],
                    }
                )
            }
        )
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2_TERMINAL_INVALID"):
        case.evaluate()


def test_failed_related_child_is_execution_error_not_partial_proof(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path, old_hold=True)
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    old = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert old is not None
    case.store.save_checkpoint(
        old.model_copy(
            update={"status": StageStatus.FAILED, "verdict": None, "error_code": "TEST"}
        )
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2_CHILD_ERROR"):
        case.evaluate()
