from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.candidates import (
    ingest_static_candidates,
    iter_raw_candidate_pages,
    normalize_candidate_page,
)
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _identity(analysis_id: str = "analysis-1") -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id=analysis_id,
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


def _artifacts(
    tmp_path: Path, identity: CheckpointIdentity
) -> SimpleArtifactRepository:
    return SimpleArtifactRepository(tmp_path / "data", identity)


def _hit(index: int, *, semantic_key: str | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "check_id": "python.eval",
        "path": f"pkg/file_{index % 3}.py",
        "start": {"line": index + 1},
        "end": {"line": index + 1},
        "extra": {"message": f"unsafe call {index}", "lines": f"eval(value_{index})"},
    }
    if semantic_key is not None:
        row["semantic_key"] = semantic_key
    return row


def test_raw_pages_cover_every_result_without_aggregate_limit(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    raw = {"results": [_hit(index) for index in range(600)], "errors": []}
    ref = artifacts.put_bytes(json.dumps(raw).encode(), "application/json")

    pages = list(iter_raw_candidate_pages(artifacts, ref, page_size=47))
    assert sum(len(page.rows) for page in pages) == 600
    assert pages[0].start_offset == 0
    assert pages[-1].end_offset == 600
    lines = []
    for page in pages:
        for row in page.rows:
            start = row["start"]
            assert isinstance(start, dict)
            line = start["line"]
            assert isinstance(line, int)
            lines.append(line)
    assert lines == list(range(1, 601))

    resumed = list(
        iter_raw_candidate_pages(
            artifacts, ref, after_offset=pages[3].end_offset, page_size=47
        )
    )
    assert resumed[0].start_offset == pages[3].end_offset
    assert sum(len(page.rows) for page in resumed) == 600 - pages[3].end_offset


def test_same_evidence_merges_origins_but_distinct_traces_do_not(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    open_ref = artifacts.put_json({"results": [_hit(0, semantic_key="same-call")]})
    sem_ref = artifacts.put_json({"results": [_hit(0, semantic_key="same-call")]})
    left = normalize_candidate_page(
        identity,
        "scope-1",
        "opengrep",
        open_ref,
        (_hit(0, semantic_key="same-call"),),
        0,
    )[0]
    right = normalize_candidate_page(
        identity, "scope-1", "semgrep", sem_ref, (_hit(0, semantic_key="same-call"),), 0
    )[0]
    assert left.candidate_id == right.candidate_id
    assert left.kind == "HINT"
    assert left.evidence_ref == open_ref
    assert left.summary == "unsafe call 0"

    flow = _hit(0)
    flow["extra"] = {
        "message": "flow",
        "dataflow_trace": {
            "taint_source": {"path": "pkg/input.py", "line": 1},
            "intermediate_vars": [{"path": "pkg/left.py", "line": 2}],
            "taint_sink": {"path": "pkg/file_0.py", "line": 1},
        },
    }
    another = json.loads(json.dumps(flow))
    another["extra"]["dataflow_trace"]["intermediate_vars"][0]["path"] = "pkg/right.py"
    flows = normalize_candidate_page(
        identity, "scope-1", "opengrep", open_ref, (flow, another), 0
    )
    assert flows[0].kind == flows[1].kind == "FLOW"
    assert flows[0].candidate_id != flows[1].candidate_id
    assert flows[0].flow_identity != flows[1].flow_identity


def test_candidate_page_and_cursor_commit_together_and_resume(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"results": [_hit(0), _hit(1), _hit(2)]})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    candidates = normalize_candidate_page(
        identity, "scope-1", "opengrep", ref, (_hit(0), _hit(1)), 0
    )
    store.upsert_candidate_page(identity, "scope-1", ref, 0, 2, candidates)
    reopened = SimpleCheckpointStore(store.database_path)
    assert reopened.candidate_cursor(identity, "scope-1", ref) == 2
    assert reopened.candidate_counts(identity, "scope-1") == {
        "PENDING": 2,
        "INCLUDE": 0,
        "EXCLUDE": 0,
        "UNDECIDED": 0,
        "ERROR": 0,
    }

    with pytest.raises(ValueError, match="CANDIDATE_CURSOR_CONFLICT"):
        reopened.upsert_candidate_page(
            identity,
            "scope-1",
            ref,
            3,
            4,
            normalize_candidate_page(
                identity, "scope-1", "opengrep", ref, (_hit(2),), 3
            ),
        )
    assert reopened.candidate_cursor(identity, "scope-1", ref) == 2
    assert len(reopened.list_candidates(identity, "scope-1")) == 2

    final = normalize_candidate_page(
        identity, "scope-1", "opengrep", ref, (_hit(2),), 2
    )
    reopened.upsert_candidate_page(identity, "scope-1", ref, 2, 3, final)
    assert reopened.candidate_cursor(identity, "scope-1", ref) == 3
    assert len(reopened.list_candidates(identity, "scope-1", limit=2)) == 2
    first = reopened.list_candidates(identity, "scope-1", limit=1)[0]
    after = reopened.list_candidates(
        identity, "scope-1", after_id=first.candidate_id, limit=10
    )
    assert len(after) == 2


def test_decision_and_deep_status_are_separate_from_provenance(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    first_ref = artifacts.put_json({"results": [_hit(0, semantic_key="same-call")]})
    second_ref = artifacts.put_json(
        {"results": [_hit(0, semantic_key="same-call")], "engine": "semgrep"}
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    for engine, ref in (("opengrep", first_ref), ("semgrep", second_ref)):
        candidate = normalize_candidate_page(
            identity, "scope-1", engine, ref, (_hit(0, semantic_key="same-call"),), 0
        )
        store.upsert_candidate_page(identity, "scope-1", ref, 0, 1, candidate)
    saved = store.list_candidates(identity, "scope-1")[0]
    assert len(saved.origins) == 2
    assert {origin.engine for origin in saved.origins} == {"opengrep", "semgrep"}

    store.save_candidate_decision(
        identity,
        "scope-1",
        saved.candidate_id,
        "INCLUDE",
        "reachable input",
        evidence_refs=(first_ref,),
        attempt_ref=second_ref,
    )
    store.save_candidate_deep_status(
        identity, "scope-1", saved.candidate_id, "NO_HYPOTHESIS"
    )
    updated = store.list_candidates(identity, "scope-1", status=("INCLUDE",))[0]
    assert updated.decision == "INCLUDE"
    assert updated.deep_status == "NO_HYPOTHESIS"
    assert updated.decision_reason == "reachable input"
    assert len(updated.origins) == 2
    assert store.candidate_counts(identity, "scope-1")["INCLUDE"] == 1


def test_ingest_static_bundle_resumes_each_raw_artifact(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    open_ref = artifacts.put_json({"results": [_hit(i) for i in range(250)]})
    codeql_ref = artifacts.put_json(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL"}},
                    "results": [
                        {
                            "ruleId": "py/insecure",
                            "message": {"text": "security result"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "pkg/codeql.py"},
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )
    ast_ref = artifacts.put_json({"kind": "simple_python_ast", "facts": []})
    merged_ref = artifacts.put_json({"results": []})
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "engine_raw_refs": [open_ref.model_dump(mode="json")],
            "engine_raw_sources": [
                {
                    "ref": open_ref.model_dump(mode="json"),
                    "engine": "opengrep",
                    "verified_pairs": [
                        {"path": "pkg/file_0.py", "rule_id": "python.eval"},
                        {"path": "pkg/file_1.py", "rule_id": "python.eval"},
                        {"path": "pkg/file_2.py", "rule_id": "python.eval"},
                    ],
                }
            ],
            "tool_result_refs": [
                ast_ref.model_dump(mode="json"),
                merged_ref.model_dump(mode="json"),
                codeql_ref.model_dump(mode="json"),
            ],
        }
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")

    assert (
        ingest_static_candidates(
            identity, "scope-1", bundle_ref, artifacts, store, page_size=33
        )
        == 251
    )
    assert (
        ingest_static_candidates(
            identity, "scope-1", bundle_ref, artifacts, store, page_size=33
        )
        == 0
    )
    assert store.candidate_counts(identity, "scope-1")["PENDING"] == 251
    assert store.candidate_cursor(identity, "scope-1", open_ref) == 250
    assert store.candidate_cursor(identity, "scope-1", codeql_ref) == 1


def test_hypotheses_are_paged_and_candidate_links_are_idempotent(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"results": [_hit(0)]})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    candidate = normalize_candidate_page(
        identity, "scope-1", "opengrep", ref, (_hit(0),), 0
    )[0]
    store.upsert_candidate_page(identity, "scope-1", ref, 0, 1, (candidate,))
    for index in range(40):
        store.upsert_hypothesis(identity, f"H-{index:03d}", ref)
        store.link_candidate_hypothesis(
            identity, "scope-1", candidate.candidate_id, f"H-{index:03d}"
        )
    store.link_candidate_hypothesis(
        identity, "scope-1", candidate.candidate_id, "H-000"
    )
    assert store.hypothesis_count(identity) == 40
    assert len(store.list_hypotheses(identity, limit=10)) == 10
    assert store.list_hypotheses(identity, after_id="H-009", limit=2) == (
        "H-010",
        "H-011",
    )
    assert (
        len(
            store.list_candidate_hypothesis_ids(
                identity, "scope-1", candidate.candidate_id, limit=100
            )
        )
        == 40
    )


def test_stable_candidate_identity_excludes_analysis_id(tmp_path: Path) -> None:
    one = _identity("analysis-one")
    two = _identity("analysis-two")
    ref = _artifacts(tmp_path, one).put_json({"results": [_hit(0)]})
    a = normalize_candidate_page(one, "scope-1", "opengrep", ref, (_hit(0),), 0)[0]
    b = normalize_candidate_page(two, "scope-1", "opengrep", ref, (_hit(0),), 0)[0]
    assert a.candidate_id == b.candidate_id
    assert len(a.candidate_id) == 64
    assert a.candidate_id != hashlib.sha256(b"").hexdigest()


def test_ingest_uses_engine_source_metadata_for_semgrep(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    sem_ref = artifacts.put_json({"results": [_hit(0)]})
    ast_ref = artifacts.put_json({"kind": "simple_python_ast", "facts": []})
    merged_ref = artifacts.put_json({"results": []})
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "engine_raw_refs": [sem_ref.model_dump(mode="json")],
            "engine_raw_sources": [
                {
                    "ref": sem_ref.model_dump(mode="json"),
                    "engine": "semgrep",
                    "verified_pairs": [
                        {"path": "pkg/file_0.py", "rule_id": "python.eval"}
                    ],
                }
            ],
            "tool_result_refs": [
                ast_ref.model_dump(mode="json"),
                merged_ref.model_dump(mode="json"),
            ],
        }
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")

    assert (
        ingest_static_candidates(identity, "scope-1", bundle_ref, artifacts, store) == 1
    )
    candidate = store.list_candidates(identity, "scope-1")[0]
    assert candidate.origins[0].engine == "semgrep"


def test_same_raw_artifact_keeps_two_engine_origins(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    raw_ref = artifacts.put_json({"results": [_hit(0, semantic_key="same-call")]})
    ast_ref = artifacts.put_json({"kind": "simple_python_ast", "facts": []})
    merged_ref = artifacts.put_json({"results": []})
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "engine_raw_refs": [raw_ref.model_dump(mode="json")],
            "engine_raw_sources": [
                {
                    "ref": raw_ref.model_dump(mode="json"),
                    "engine": "opengrep",
                    "verified_pairs": [
                        {"path": "pkg/file_0.py", "rule_id": "python.eval"}
                    ],
                },
                {
                    "ref": raw_ref.model_dump(mode="json"),
                    "engine": "semgrep",
                    "verified_pairs": [
                        {"path": "pkg/file_0.py", "rule_id": "python.eval"}
                    ],
                },
            ],
            "tool_result_refs": [
                ast_ref.model_dump(mode="json"),
                merged_ref.model_dump(mode="json"),
            ],
        }
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")

    ingest_static_candidates(identity, "scope-1", bundle_ref, artifacts, store)
    candidate = store.list_candidates(identity, "scope-1")[0]
    assert {origin.engine for origin in candidate.origins} == {"opengrep", "semgrep"}


def test_budget_failure_reopens_only_with_usage_headroom(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"attempt": 1})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    checkpoint = StageCheckpoint(
        identity=identity.model_copy(update={"hypothesis_id": "H-001"}),
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.FAILED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        error_code="LLM_COST_BUDGET_EXHAUSTED",
        retryable=False,
    )
    store.save_checkpoint(checkpoint)
    store.record_llm_attempt(
        attempt_id="attempt-1",
        analysis_id=identity.analysis_id,
        agent="Discovery",
        model="test-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=1000,
        input_tokens=10,
        output_tokens=5,
        cost_cents=50,
        artifact_ref=ref,
    )

    assert (
        store.reopen_budget_failures(
            identity.analysis_id,
            max_tokens=15,
            max_cost_minor_units=50,
            max_elapsed_seconds=1,
        )
        == 0
    )
    failed = store.get(checkpoint.identity, checkpoint.stage)
    assert failed is not None
    assert failed.status is StageStatus.FAILED
    assert (
        store.reopen_budget_failures(
            identity.analysis_id,
            max_tokens=16,
            max_cost_minor_units=51,
            max_elapsed_seconds=2,
        )
        == 1
    )
    pending = store.get(checkpoint.identity, checkpoint.stage)
    assert pending is not None
    assert pending.status is StageStatus.PENDING


def test_hypothesis_chain_metadata_survives_reopen(tmp_path: Path) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.upsert_hypothesis(identity, "H-001")
    store.upsert_hypothesis(
        identity,
        "H-002",
        chain_depth=1,
        parent_hypothesis_ids=("H-001",),
    )
    reopened = SimpleCheckpointStore(store.database_path)

    assert reopened.has_hypothesis(identity, "H-002")
    assert reopened.hypothesis_metadata(identity, "H-002") == (1, ("H-001",))
    assert reopened.hypothesis_metadata(identity, "missing") is None


def test_absolute_scanner_path_is_scoped_to_workspace(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    workspace = tmp_path / "checkout"
    target = workspace / "pkg" / "module.py"
    target.parent.mkdir(parents=True)
    target.write_text("eval(value)", encoding="utf-8")
    row = _hit(0)
    row["path"] = str(target)
    ref = artifacts.put_json({"results": [row]})

    candidate = normalize_candidate_page(
        identity,
        "scope-1",
        "opengrep",
        ref,
        (row,),
        0,
        workspace=workspace,
    )[0]
    assert candidate.path == "pkg/module.py"
    with pytest.raises(ValueError, match="CANDIDATE_PATH_UNSAFE"):
        normalize_candidate_page(
            identity,
            "scope-1",
            "opengrep",
            ref,
            (row,),
            0,
            workspace=tmp_path / "other",
        )


def test_cursor_advances_past_unverified_hits_without_creating_candidates(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"results": [_hit(0), _hit(1)]})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    verified = normalize_candidate_page(
        identity, "scope-1", "opengrep", ref, (_hit(0),), 0
    )

    store.upsert_candidate_page(identity, "scope-1", ref, 0, 2, verified)

    assert store.candidate_cursor(identity, "scope-1", ref) == 2
    assert store.candidate_counts(identity, "scope-1")["PENDING"] == 1


def test_ingest_only_verified_file_rule_hits_from_partial_raw(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    raw_ref = artifacts.put_json({"results": [_hit(0), _hit(1)]})
    ast_ref = artifacts.put_json({"kind": "simple_python_ast", "facts": []})
    merged_ref = artifacts.put_json({"results": []})
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "engine_raw_refs": [raw_ref.model_dump(mode="json")],
            "engine_raw_sources": [
                {
                    "ref": raw_ref.model_dump(mode="json"),
                    "engine": "opengrep",
                    "verified_pairs": [
                        {"path": "pkg/file_0.py", "rule_id": "python.eval"}
                    ],
                }
            ],
            "tool_result_refs": [
                ast_ref.model_dump(mode="json"),
                merged_ref.model_dump(mode="json"),
            ],
        }
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")

    assert (
        ingest_static_candidates(identity, "scope-1", bundle_ref, artifacts, store) == 1
    )
    assert store.candidate_cursor(identity, "scope-1", raw_ref) == 2
    candidates = store.list_candidates(identity, "scope-1")
    assert len(candidates) == 1
    assert candidates[0].path == "pkg/file_0.py"


def test_atomic_candidate_hypothesis_registration_rolls_back_orphan(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"results": [_hit(0)]})
    proposal = artifacts.put_json({"kind": "simple_hypothesis_proposal"})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    candidate = normalize_candidate_page(
        identity, "scope-1", "opengrep", ref, (_hit(0),), 0
    )[0]
    store.upsert_candidate_page(identity, "scope-1", ref, 0, 1, (candidate,))
    store.save_candidate_decision(
        identity,
        "scope-1",
        candidate.candidate_id,
        "INCLUDE",
        "reachable source",
    )

    with pytest.raises(ValueError, match="CANDIDATE_HYPOTHESIS_LINK_INVALID"):
        store.register_candidate_hypothesis(
            identity, "scope-1", "missing", "H-001", proposal
        )
    assert not store.has_hypothesis(identity, "H-001")

    store.register_candidate_hypothesis(
        identity,
        "scope-1",
        candidate.candidate_id,
        "H-001",
        proposal,
        chain_depth=1,
        parent_hypothesis_ids=("H-parent",),
    )
    store.register_candidate_hypothesis(
        identity,
        "scope-1",
        candidate.candidate_id,
        "H-001",
        proposal,
        chain_depth=1,
        parent_hypothesis_ids=("H-parent",),
    )
    assert store.hypothesis_count(identity) == 1
    assert store.hypothesis_metadata(identity, "H-001") == (1, ("H-parent",))
    assert store.list_candidate_hypothesis_ids(
        identity, "scope-1", candidate.candidate_id
    ) == ("H-001",)


def test_incomplete_hypothesis_page_uses_terminal_checkpoint_evidence(
    tmp_path: Path,
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    for hypothesis_id in ("H-001", "H-002", "H-003", "H-004"):
        store.upsert_hypothesis(identity, hypothesis_id)

    def save_terminal(
        hypothesis_id: str,
        stage: SimpleStage,
        *,
        verdict: Literal["TRUE", "FALSE", "HOLD"] | None = None,
        gate_decision: Literal["ACCEPT", "REVISE", "REJECT"] | None = None,
    ) -> None:
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity.model_copy(update={"hypothesis_id": hypothesis_id}),
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                verdict=verdict,
                gate_decision=gate_decision,
            )
        )

    save_terminal("H-001", SimpleStage.REPORT_DONE)
    save_terminal("H-002", SimpleStage.VERIFICATION_FINAL_DONE, verdict="FALSE")
    save_terminal("H-004", SimpleStage.TECH_GATE_DONE, gate_decision="REJECT")

    assert store.list_incomplete_hypotheses(identity, limit=2) == ("H-003",)
    assert store.list_incomplete_hypotheses(identity, after_id="H-002", limit=2) == (
        "H-003",
    )
    assert store.list_incomplete_hypotheses(identity, after_id="H-003", limit=2) == ()


def test_unmet_external_prerequisite_is_not_requeued_as_incomplete(
    tmp_path: Path,
) -> None:
    identity = _identity()
    child = identity.model_copy(update={"hypothesis_id": "H-external"})
    store = SimpleCheckpointStore(
        tmp_path / "ledger.sqlite3", artifact_data_dir=tmp_path / "data"
    )
    store.upsert_hypothesis(identity, "H-external")
    evidence = _artifacts(tmp_path, child).put_json(
        {
            "kind": "simple_initial_verification",
            "attempt_id": "initial-attempt",
            "result": {
                "initial_assessment": "HOLD",
                "unmet_external_prerequisites": ["attacker control unproven"],
            },
        }
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(evidence,),
            attempt_id="initial-attempt",
            verdict="HOLD",
            external_prerequisites_ref=evidence,
        )
    )

    assert store.list_incomplete_hypotheses(identity, limit=1) == ()
    _artifacts(tmp_path, child).artifacts.path_for(evidence.content_hash).unlink()
    assert store.list_incomplete_hypotheses(identity, limit=1) == ("H-external",)


def test_legacy_v2_poc_keeps_completed_candidate_hypothesis_incomplete(
    tmp_path: Path,
) -> None:
    identity = _identity()
    child = identity.model_copy(update={"hypothesis_id": "H-legacy"})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.upsert_hypothesis(identity, "H-legacy")
    for stage in (
        SimpleStage.POC_EXECUTION_DONE,
        SimpleStage.VERIFICATION_FINAL_DONE,
        SimpleStage.REPORT_DONE,
    ):
        store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=stage,
                stage_version=(
                    "2"
                    if stage is SimpleStage.POC_EXECUTION_DONE
                    else STAGE_VERSION[stage]
                ),
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                verdict=(
                    "TRUE" if stage is SimpleStage.VERIFICATION_FINAL_DONE else None
                ),
            )
        )

    assert store.list_incomplete_hypotheses(identity, limit=1) == ("H-legacy",)


def test_verified_relative_dot_path_is_canonicalized_before_proof_match(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    raw_hit = _hit(0)
    raw_hit["path"] = "./pkg/file_0.py"
    raw_ref = artifacts.put_json({"results": [raw_hit]})
    ast_ref = artifacts.put_json({"kind": "simple_python_ast", "facts": []})
    merged_ref = artifacts.put_json({"results": []})
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "engine_raw_refs": [raw_ref.model_dump(mode="json")],
            "engine_raw_sources": [
                {
                    "ref": raw_ref.model_dump(mode="json"),
                    "engine": "opengrep",
                    "verified_pairs": [
                        {"path": "pkg/file_0.py", "rule_id": "python.eval"}
                    ],
                }
            ],
            "tool_result_refs": [
                ast_ref.model_dump(mode="json"),
                merged_ref.model_dump(mode="json"),
            ],
        }
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")

    assert (
        ingest_static_candidates(identity, "scope-1", bundle_ref, artifacts, store) == 1
    )
    assert store.list_candidates(identity, "scope-1")[0].path == "pkg/file_0.py"


def test_codeql_percent_encoded_uri_is_decoded_and_scoped(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"runs": [{"results": []}]})
    artifact_location = {"uri": "pkg/space%20name.py"}
    row = {
        "ruleId": "py/insecure",
        "message": {"text": "unsafe input"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": artifact_location,
                    "region": {"startLine": 3},
                }
            }
        ],
    }
    candidate = normalize_candidate_page(identity, "scope-1", "codeql", ref, (row,), 0)[
        0
    ]
    assert candidate.path == "pkg/space name.py"

    workspace = tmp_path / "checkout"
    target = workspace / "pkg" / "space name.py"
    target.parent.mkdir(parents=True)
    target.write_text("pass", encoding="utf-8")
    artifact_location["uri"] = target.as_uri()
    scoped = normalize_candidate_page(
        identity, "scope-1", "codeql", ref, (row,), 0, workspace=workspace
    )[0]
    assert scoped.path == "pkg/space name.py"

    artifact_location["uri"] = "pkg/%2e%2e/secrets.py"
    with pytest.raises(ValueError, match="CANDIDATE_PATH_UNSAFE"):
        normalize_candidate_page(identity, "scope-1", "codeql", ref, (row,), 0)


def test_flow_semantic_key_does_not_merge_distinct_traces(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"results": []})
    first = _hit(0, semantic_key="same-flow")
    first["extra"] = {
        "dataflow_trace": {
            "taint_source": {"path": "pkg/input.py", "line": 1},
            "intermediate_vars": [{"path": "pkg/left.py", "line": 2}],
            "taint_sink": {"path": "pkg/file_0.py", "line": 1},
        }
    }
    second = json.loads(json.dumps(first))
    second["extra"]["dataflow_trace"]["intermediate_vars"][0]["path"] = "pkg/right.py"
    candidates = normalize_candidate_page(
        identity, "scope-1", "opengrep", ref, (first, second), 0
    )
    assert candidates[0].kind == candidates[1].kind == "FLOW"
    assert candidates[0].candidate_id != candidates[1].candidate_id


def test_same_flow_trace_keeps_distinct_match_conditions(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    first = _hit(0, semantic_key="same-flow")
    first["extra"] = {
        "message": "flow",
        "dataflow_trace": {
            "taint_source": {"path": "pkg/input.py", "line": 1},
            "intermediate_vars": [],
            "taint_sink": {"path": "pkg/file_0.py", "line": 1},
        },
        "metavars": {"$CONDITION": {"abstract_content": "is_admin"}},
    }
    second = json.loads(json.dumps(first))
    second["extra"]["metavars"]["$CONDITION"]["abstract_content"] = "is_guest"
    raw_ref = artifacts.put_json({"results": [first, second]})
    candidates = normalize_candidate_page(
        identity, "scope-1", "opengrep", raw_ref, (first, second), 0
    )

    assert candidates[0].kind == candidates[1].kind == "FLOW"
    assert candidates[0].flow_identity == candidates[1].flow_identity
    assert candidates[0].candidate_id != candidates[1].candidate_id

    semgrep_ref = artifacts.put_json({"results": [first]})
    same_first = normalize_candidate_page(
        identity, "scope-1", "semgrep", semgrep_ref, (first,), 0
    )[0]
    assert same_first.candidate_id == candidates[0].candidate_id

    same_binding = json.loads(json.dumps(first))
    same_binding["extra"]["metavars"]["$CONDITION"]["start"] = {
        "line": 9,
        "col": 4,
    }
    same_binding_ref = artifacts.put_json({"results": [same_binding]})
    same_binding_candidate = normalize_candidate_page(
        identity, "scope-1", "semgrep", same_binding_ref, (same_binding,), 0
    )[0]
    assert same_binding_candidate.candidate_id == candidates[0].candidate_id

    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.upsert_candidate_page(identity, "scope-1", raw_ref, 0, 2, candidates)
    store.upsert_candidate_page(identity, "scope-1", semgrep_ref, 0, 1, (same_first,))
    assert store.candidate_counts(identity, "scope-1")["PENDING"] == 2


def test_same_flow_trace_keeps_distinct_explicit_conditions(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    first = _hit(0, semantic_key="same-flow")
    first["extra"] = {
        "dataflow_trace": {
            "taint_source": {"path": "pkg/input.py", "line": 1},
            "intermediate_vars": [],
            "taint_sink": {"path": "pkg/file_0.py", "line": 1},
        },
        "conditions": {"auth_required": True},
    }
    second = json.loads(json.dumps(first))
    second["extra"]["conditions"]["auth_required"] = False
    raw_ref = artifacts.put_json({"results": [first, second]})
    candidates = normalize_candidate_page(
        identity, "scope-1", "opengrep", raw_ref, (first, second), 0
    )
    assert candidates[0].flow_identity == candidates[1].flow_identity
    assert candidates[0].candidate_id != candidates[1].candidate_id


@pytest.mark.parametrize(
    ("match_field", "first_value", "second_value"),
    (
        (
            "metavars",
            {"$CONDITION": {"abstract_content": "is_admin"}},
            {"$CONDITION": {"abstract_content": "is_guest"}},
        ),
        ("conditions", {"auth_required": True}, {"auth_required": False}),
    ),
)
def test_opengrep_hint_keeps_distinct_match_evidence(
    tmp_path: Path,
    match_field: str,
    first_value: object,
    second_value: object,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    first = _hit(0, semantic_key="same-call")
    extra = first["extra"]
    assert isinstance(extra, dict)
    extra[match_field] = first_value
    second = json.loads(json.dumps(first))
    second["extra"][match_field] = second_value
    duplicate = json.loads(json.dumps(first))
    raw_ref = artifacts.put_json({"results": [first, second, duplicate]})

    candidates = normalize_candidate_page(
        identity, "scope-1", "opengrep", raw_ref, (first, second, duplicate), 0
    )
    assert all(item.kind == "HINT" for item in candidates)
    assert candidates[0].candidate_id != candidates[1].candidate_id
    assert candidates[0].candidate_id == candidates[2].candidate_id

    same_first = normalize_candidate_page(
        identity, "scope-1", "semgrep", raw_ref, (first,), 0
    )[0]
    assert same_first.candidate_id == candidates[0].candidate_id

    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.upsert_candidate_page(identity, "scope-1", raw_ref, 0, 3, candidates)
    saved = store.list_candidates(identity, "scope-1")
    assert len(saved) == 2
    merged = next(
        item for item in saved if item.candidate_id == candidates[0].candidate_id
    )
    assert {origin.result_index for origin in merged.origins} == {0, 2}


def test_entry_point_keeps_distinct_match_evidence_and_merges_exact_duplicates(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    first = _hit(0, semantic_key="same-source")
    extra = first["extra"]
    assert isinstance(extra, dict)
    extra.update(
        {
            "metadata": {"candidate_kind": "ENTRY_POINT"},
            "metavars": {"$VALUE": {"abstract_content": "request.args['a']"}},
            "conditions": {"validated": True},
        }
    )
    different_binding = json.loads(json.dumps(first))
    different_binding["extra"]["metavars"]["$VALUE"]["abstract_content"] = (
        "request.args['b']"
    )
    different_condition = json.loads(json.dumps(first))
    different_condition["extra"]["conditions"]["validated"] = False
    duplicate = json.loads(json.dumps(first))
    rows = (first, different_binding, different_condition, duplicate)
    ref = artifacts.put_json({"results": rows})

    candidates = normalize_candidate_page(identity, "scope-1", "opengrep", ref, rows, 0)
    assert all(item.kind == "ENTRY_POINT" for item in candidates)
    assert len({item.candidate_id for item in candidates}) == 3
    assert candidates[0].candidate_id == candidates[3].candidate_id

    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.upsert_candidate_page(identity, "scope-1", ref, 0, 4, candidates)
    saved = store.list_candidates(identity, "scope-1")
    assert len(saved) == 3
    merged = next(
        item for item in saved if item.candidate_id == candidates[0].candidate_id
    )
    assert {origin.result_index for origin in merged.origins} == {0, 3}


def _pending_pro_con(
    identity: CheckpointIdentity,
    hypothesis_id: str,
    proposal_ref: StoredDataRef,
    static_ref: StoredDataRef,
) -> StageCheckpoint:
    inputs = (proposal_ref, static_ref)
    return StageCheckpoint(
        identity=identity.model_copy(update={"hypothesis_id": hypothesis_id}),
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.PENDING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
    )


def test_candidate_hypothesis_and_pending_checkpoint_commit_atomically(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    raw_ref = artifacts.put_json({"results": [_hit(0)]})
    proposal_ref = artifacts.put_json({"kind": "proposal"})
    static_ref = artifacts.put_json({"kind": "static"})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    candidate = normalize_candidate_page(
        identity, "scope-1", "opengrep", raw_ref, (_hit(0),), 0
    )[0]
    store.upsert_candidate_page(identity, "scope-1", raw_ref, 0, 1, (candidate,))
    store.save_candidate_decision(
        identity, "scope-1", candidate.candidate_id, "INCLUDE", "source"
    )
    pending = _pending_pro_con(identity, "H-001", proposal_ref, static_ref)
    store.register_candidate_hypothesis(
        identity,
        "scope-1",
        candidate.candidate_id,
        "H-001",
        proposal_ref,
        checkpoint=pending,
    )
    assert store.list_candidate_hypothesis_ids(
        identity, "scope-1", candidate.candidate_id
    ) == ("H-001",)
    assert store.get(pending.identity, SimpleStage.PRO_CON_DONE) == pending

    succeeded = pending.model_copy(update={"status": StageStatus.SUCCEEDED})
    store.save_checkpoint(succeeded)
    store.register_candidate_hypothesis(
        identity,
        "scope-1",
        candidate.candidate_id,
        "H-001",
        proposal_ref,
        checkpoint=pending,
    )
    assert store.get(pending.identity, SimpleStage.PRO_CON_DONE) == succeeded

    wrong = pending.model_copy(
        update={"identity": identity.model_copy(update={"hypothesis_id": "H-002"})}
    )
    with pytest.raises(ValueError, match="CANDIDATE_HYPOTHESIS_CHECKPOINT_INVALID"):
        store.register_candidate_hypothesis(
            identity,
            "scope-1",
            candidate.candidate_id,
            "H-003",
            proposal_ref,
            checkpoint=wrong,
        )
    assert not store.has_hypothesis(identity, "H-003")


def test_free_hypothesis_and_pending_checkpoint_commit_atomically(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    proposal_ref = artifacts.put_json({"kind": "proposal"})
    static_ref = artifacts.put_json({"kind": "static"})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    pending = _pending_pro_con(identity, "H-free", proposal_ref, static_ref)

    store.register_free_hypothesis(identity, "H-free", proposal_ref, pending)
    assert store.has_hypothesis(identity, "H-free")
    assert store.get(pending.identity, SimpleStage.PRO_CON_DONE) == pending

    wrong = pending.model_copy(
        update={"identity": identity.model_copy(update={"hypothesis_id": "wrong"})}
    )
    with pytest.raises(ValueError, match="CANDIDATE_HYPOTHESIS_CHECKPOINT_INVALID"):
        store.register_free_hypothesis(identity, "H-orphan", proposal_ref, wrong)
    assert not store.has_hypothesis(identity, "H-orphan")


def test_candidate_hypothesis_batch_rolls_back_all_on_invalid_second_seed(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    raw_ref = artifacts.put_json({"results": [_hit(0)]})
    proposal_one = artifacts.put_json({"kind": "proposal", "number": 1})
    proposal_two = artifacts.put_json({"kind": "proposal", "number": 2})
    static_ref = artifacts.put_json({"kind": "static"})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    candidate = normalize_candidate_page(
        identity, "scope-1", "opengrep", raw_ref, (_hit(0),), 0
    )[0]
    store.upsert_candidate_page(identity, "scope-1", raw_ref, 0, 1, (candidate,))
    store.save_candidate_decision(
        identity, "scope-1", candidate.candidate_id, "INCLUDE", "source"
    )
    first = _pending_pro_con(identity, "H-001", proposal_one, static_ref)
    second = _pending_pro_con(identity, "H-002", proposal_two, static_ref)
    invalid_second = second.model_copy(
        update={"identity": identity.model_copy(update={"hypothesis_id": "wrong"})}
    )

    with pytest.raises(ValueError, match="CANDIDATE_HYPOTHESIS_CHECKPOINT_INVALID"):
        store.register_candidate_hypotheses_batch(
            identity,
            "scope-1",
            candidate.candidate_id,
            (
                ("H-001", proposal_one, first),
                ("H-002", proposal_two, invalid_second),
            ),
        )
    assert store.hypothesis_count(identity) == 0
    assert (
        store.list_candidate_hypothesis_ids(identity, "scope-1", candidate.candidate_id)
        == ()
    )
    assert store.get(first.identity, SimpleStage.PRO_CON_DONE) is None

    registrations = (
        ("H-001", proposal_one, first),
        ("H-002", proposal_two, second),
    )
    store.register_candidate_hypotheses_batch(
        identity, "scope-1", candidate.candidate_id, registrations
    )
    store.register_candidate_hypotheses_batch(
        identity, "scope-1", candidate.candidate_id, registrations
    )
    assert store.hypothesis_count(identity) == 2
    assert store.list_candidate_hypothesis_ids(
        identity, "scope-1", candidate.candidate_id
    ) == ("H-001", "H-002")
    assert store.get(first.identity, SimpleStage.PRO_CON_DONE) == first
    assert store.get(second.identity, SimpleStage.PRO_CON_DONE) == second


def test_same_line_matches_keep_distinct_columns_and_exact_dedup(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    raw_ref = artifacts.put_json({"results": []})
    first = _hit(0, semantic_key="same-call")
    first["start"] = {"line": 7, "col": 1}
    first["end"] = {"line": 7, "col": 7}
    first["extra"] = {"message": "unsafe call", "lines": "eval(a); eval(b)"}
    second = json.loads(json.dumps(first))
    second["start"]["col"] = 10
    second["end"]["col"] = 16

    candidates = normalize_candidate_page(
        identity, "scope-1", "opengrep", raw_ref, (first, second), 0
    )
    assert candidates[0].candidate_id != candidates[1].candidate_id
    assert (candidates[0].start_column, candidates[0].end_column) == (1, 7)
    assert (candidates[1].start_column, candidates[1].end_column) == (10, 16)

    semgrep_ref = artifacts.put_json({"results": [first]})
    same_first = normalize_candidate_page(
        identity, "scope-1", "semgrep", semgrep_ref, (first,), 0
    )[0]
    assert same_first.candidate_id == candidates[0].candidate_id

    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.upsert_candidate_page(identity, "scope-1", raw_ref, 0, 2, candidates)
    store.upsert_candidate_page(identity, "scope-1", semgrep_ref, 0, 1, (same_first,))
    assert store.candidate_counts(identity, "scope-1")["PENDING"] == 2


def test_codeql_same_line_results_keep_distinct_sarif_columns(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"runs": [{"results": []}]})
    first = {
        "ruleId": "py/insecure",
        "message": {"text": "unsafe call"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "pkg/module.py"},
                    "region": {
                        "startLine": 7,
                        "endLine": 7,
                        "startColumn": 1,
                        "endColumn": 7,
                    },
                }
            }
        ],
    }
    second = json.loads(json.dumps(first))
    region = second["locations"][0]["physicalLocation"]["region"]
    region["startColumn"] = 10
    region["endColumn"] = 16

    candidates = normalize_candidate_page(
        identity, "scope-1", "codeql", ref, (first, second), 0
    )
    assert candidates[0].candidate_id != candidates[1].candidate_id
    assert (candidates[0].start_column, candidates[0].end_column) == (1, 7)
    assert (candidates[1].start_column, candidates[1].end_column) == (10, 16)


def test_real_request_source_rule_is_entry_point_and_sink_remains_hint(
    tmp_path: Path,
) -> None:
    import yaml  # type: ignore[import-untyped]

    rules_path = (
        Path(__file__).resolve().parents[3]
        / "config"
        / "static-analysis"
        / "candidate-v1"
        / "opengrep"
        / "rules.yml"
    )
    loaded = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    by_id = {rule["id"]: rule for rule in loaded["rules"]}
    rows = []
    for line, (rule_id, source_line) in enumerate(
        (
            ("sastsimi.python.request-source", "request.args.get('x')"),
            ("sastsimi.python.command-sink", "os.system(command)"),
        ),
        start=1,
    ):
        rule = by_id[rule_id]
        rows.append(
            {
                "check_id": rule_id,
                "path": "pkg/web.py",
                "start": {"line": line},
                "end": {"line": line},
                "extra": {
                    "message": rule["message"],
                    "lines": source_line,
                    "metadata": rule.get("metadata", {}),
                },
            }
        )
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    ref = artifacts.put_json({"results": rows})
    candidates = normalize_candidate_page(identity, "scope-1", "opengrep", ref, rows)
    assert [candidate.kind for candidate in candidates] == ["ENTRY_POINT", "HINT"]


def _sarif_thread(source: str) -> dict[str, object]:
    return {
        "locations": [
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": source},
                        "region": {"startLine": 1},
                    }
                }
            },
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "pkg/sink.py"},
                        "region": {"startLine": 10},
                    }
                }
            },
        ]
    }


def _sarif_result(*flows: dict[str, object]) -> dict[str, object]:
    return {
        "ruleId": "py/taint",
        "message": {"text": "tainted input reaches sink"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "pkg/sink.py"},
                    "region": {"startLine": 10},
                }
            }
        ],
        "codeFlows": list(flows),
    }


@pytest.mark.parametrize(
    ("field", "first_value", "second_value"),
    (
        (
            "locations",
            [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "pkg/sink.py"},
                        "region": {"startLine": 10},
                    }
                },
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "pkg/first.py"},
                        "region": {"startLine": 1},
                    }
                },
            ],
            [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "pkg/sink.py"},
                        "region": {"startLine": 10},
                    }
                },
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "pkg/second.py"},
                        "region": {"startLine": 1},
                    }
                },
            ],
        ),
        (
            "relatedLocations",
            [{"id": 1, "message": {"text": "first guard"}}],
            [{"id": 1, "message": {"text": "second guard"}}],
        ),
        (
            "properties",
            {"matchedCondition": "first guard"},
            {"matchedCondition": "second guard"},
        ),
    ),
)
def test_codeql_hint_keeps_distinct_sarif_evidence_and_merges_exact_duplicates(
    tmp_path: Path,
    field: str,
    first_value: object,
    second_value: object,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    first = _sarif_result()
    first[field] = first_value
    second = json.loads(json.dumps(first))
    second[field] = second_value
    duplicate = json.loads(json.dumps(first))
    ref = artifacts.put_json({"runs": [{"results": [first, second, duplicate]}]})

    candidates = normalize_candidate_page(
        identity, "scope-1", "codeql", ref, (first, second, duplicate), 0
    )
    assert all(item.kind == "HINT" for item in candidates)
    assert candidates[0].candidate_id != candidates[1].candidate_id
    assert candidates[0].candidate_id == candidates[2].candidate_id

    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.upsert_candidate_page(identity, "scope-1", ref, 0, 3, candidates)
    saved = store.list_candidates(identity, "scope-1")
    assert len(saved) == 2
    merged = next(
        item for item in saved if item.candidate_id == candidates[0].candidate_id
    )
    assert {origin.result_index for origin in merged.origins} == {0, 2}


def test_codeql_sarif_splits_each_thread_flow_and_deduplicates_exact_trace(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    first = _sarif_thread("pkg/first.py")
    second = _sarif_thread("pkg/second.py")
    row = _sarif_result(
        {"threadFlows": [first, second, first]},
        {"threadFlows": [_sarif_thread("pkg/third.py")]},
    )
    ref = artifacts.put_json({"runs": [{"results": [row]}]})

    candidates = normalize_candidate_page(identity, "scope-1", "codeql", ref, (row,), 0)
    assert len(candidates) == 3
    assert len({item.candidate_id for item in candidates}) == 3
    assert all(item.kind == "FLOW" for item in candidates)
    assert all(item.origins[0].artifact_ref == ref for item in candidates)
    assert all(item.origins[0].result_index == 0 for item in candidates)
    for item in candidates:
        trace = item.flow_trace
        assert trace is not None
        code_flows = trace["codeFlows"]
        assert isinstance(code_flows, list)
        assert len(code_flows) == 1
        code_flow = code_flows[0]
        assert isinstance(code_flow, dict)
        thread_flows = code_flow["threadFlows"]
        assert isinstance(thread_flows, list)
        assert len(thread_flows) == 1


def test_candidate_page_commits_two_flows_from_one_raw_sarif_row(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    first = _sarif_thread("pkg/first.py")
    second = _sarif_thread("pkg/second.py")
    original = _sarif_result({"threadFlows": [first, second]})
    ref = artifacts.put_json({"runs": [{"results": [original]}]})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    # Both normalized candidates retain the original raw result index.
    candidates = (
        *normalize_candidate_page(
            identity,
            "scope-1",
            "codeql",
            ref,
            (_sarif_result({"threadFlows": [first]}),),
            0,
        ),
        *normalize_candidate_page(
            identity,
            "scope-1",
            "codeql",
            ref,
            (_sarif_result({"threadFlows": [second]}),),
            0,
        ),
    )
    assert len(candidates) == 2
    store.upsert_candidate_page(identity, "scope-1", ref, 0, 1, candidates)
    reopened = SimpleCheckpointStore(store.database_path)
    assert reopened.candidate_cursor(identity, "scope-1", ref) == 1
    assert reopened.candidate_counts(identity, "scope-1")["PENDING"] == 2
    assert len(reopened.list_candidates(identity, "scope-1")) == 2
    reopened.upsert_candidate_page(identity, "scope-1", ref, 0, 1, candidates)
    assert reopened.candidate_counts(identity, "scope-1")["PENDING"] == 2


def test_codeql_single_flow_and_non_flow_keep_expected_kind(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    flowing = _sarif_result({"threadFlows": [_sarif_thread("pkg/input.py")]})
    non_flow = _sarif_result()
    ref = artifacts.put_json({"runs": [{"results": [flowing, non_flow]}]})
    candidates = normalize_candidate_page(
        identity, "scope-1", "codeql", ref, (flowing, non_flow), 0
    )
    assert len(candidates) == 2
    assert [item.kind for item in candidates] == ["FLOW", "HINT"]
    assert [item.origins[0].result_index for item in candidates] == [0, 1]


def test_ingest_codeql_multi_flow_preserves_raw_cursor_and_count(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = _artifacts(tmp_path, identity)
    row = _sarif_result(
        {"threadFlows": [_sarif_thread("pkg/first.py")]},
        {"threadFlows": [_sarif_thread("pkg/second.py")]},
    )
    codeql_ref = artifacts.put_json({"runs": [{"results": [row]}]})
    ast_ref = artifacts.put_json({"kind": "simple_python_ast", "facts": []})
    merged_ref = artifacts.put_json({"results": []})
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "engine_raw_refs": [],
            "engine_raw_sources": [],
            "tool_result_refs": [
                ast_ref.model_dump(mode="json"),
                merged_ref.model_dump(mode="json"),
                codeql_ref.model_dump(mode="json"),
            ],
        }
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    assert (
        ingest_static_candidates(
            identity, "scope-1", bundle_ref, artifacts, store, page_size=1
        )
        == 2
    )
    assert store.candidate_cursor(identity, "scope-1", codeql_ref) == 1
    assert store.candidate_counts(identity, "scope-1")["PENDING"] == 2
    first_page = store.list_candidates(identity, "scope-1", limit=1)
    assert len(first_page) == 1
    second_page = store.list_candidates(
        identity, "scope-1", after_id=first_page[0].candidate_id, limit=1
    )
    assert len(second_page) == 1
    assert first_page[0].candidate_id != second_page[0].candidate_id
    assert all(
        candidate.origins[0].result_index == 0
        for candidate in (*first_page, *second_page)
    )

    assert (
        ingest_static_candidates(
            identity, "scope-1", bundle_ref, artifacts, store, page_size=1
        )
        == 0
    )
    assert store.candidate_counts(identity, "scope-1")["PENDING"] == 2
    store.save_candidate_decision(
        identity, "scope-1", first_page[0].candidate_id, "INCLUDE", "separate flow"
    )
    counts = store.candidate_counts(identity, "scope-1")
    assert counts["INCLUDE"] == 1
    assert counts["PENDING"] == 1
