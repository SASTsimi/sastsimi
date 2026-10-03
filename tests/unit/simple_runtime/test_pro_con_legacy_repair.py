"""Repair only exact, legacy Pro/Con evidence with unsupported citations."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import (
    HypothesisBootstrap,
    RunnerFactory,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    StaticBootstrap,
    StaticBootstrapResult,
    StaticEvidenceInvalid,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.report_currentness import (
    candidate_report_integrity_blocked,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner, StageBlocked
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.unit.simple_runtime.test_candidate_pipeline import (
    _SecondLookHypotheses,
    _setup,
)


def _child(
    analysis_id: str = "analysis-1", hypothesis_id: str = "hypothesis-1"
) -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id=analysis_id,
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=hypothesis_id,
    )


def _run(
    identity: CheckpointIdentity, *, pipeline_version: int = 2
) -> SimpleAnalysisRun:
    return SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="fixture",
        candidate_pipeline_version=pipeline_version,
        candidate_terminal=CandidateTerminal(
            status="COMPLETE",
            bundle_hash="b" * 64,
            scope_fingerprint="scope-1",
            decision_counts={},
            deep_counts={},
            hypothesis_count=2,
            producer_finished=True,
        ),
    )


def _checkpoint(
    artifacts: SimpleArtifactRepository, identity: CheckpointIdentity
) -> StageCheckpoint:
    proposal = artifacts.put_json({"kind": "simple_hypothesis_proposal"})
    context = artifacts.put_json({"kind": "context"})
    pro = artifacts.put_json({"kind": "simple_pro_evidence", "result": {}})
    con = artifacts.put_json({"kind": "simple_con_evidence", "result": {}})
    inputs = (proposal, context)
    return StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=(pro, con),
        attempt_id="attempt-1",
        attempt_number=1,
    )


def test_repair_preserves_unrelated_work_and_valid_role(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    artifacts = SimpleArtifactRepository(data_dir, child)
    checkpoint = _checkpoint(artifacts, child)
    other = _child(hypothesis_id="hypothesis-2")
    other_checkpoint = _checkpoint(SimpleArtifactRepository(data_dir, other), other)
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}),
        child.hypothesis_id or "",
        checkpoint.input_refs[0],
    )
    store.save_checkpoint(checkpoint)
    store.save_checkpoint(other_checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, checkpoint.output_refs[0]
    )
    store.save_pro_con_batch_evidence(
        child, "con", checkpoint.input_hash, checkpoint.output_refs[1]
    )
    downstream = StageCheckpoint(
        identity=child,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=checkpoint.output_refs,
        input_hash=input_reference_hash(checkpoint.output_refs),
    )
    store.save_checkpoint(downstream)

    assert store.repair_legacy_pro_con_evidence(
        checkpoint,
        {"pro": checkpoint.output_refs[0]},
        expected_role_cache={
            "pro": checkpoint.output_refs[0],
            "con": checkpoint.output_refs[1],
        },
    )

    replay = store.require(child, SimpleStage.PRO_CON_DONE)
    assert replay.status is StageStatus.PENDING
    assert replay.input_refs == checkpoint.input_refs
    assert replay.input_hash == checkpoint.input_hash
    assert replay.output_refs == ()
    assert store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE) is None
    assert store.get(other, SimpleStage.PRO_CON_DONE) == other_checkpoint
    assert store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash) is None
    assert (
        store.get_pro_con_batch_evidence(child, "con", checkpoint.input_hash)
        == checkpoint.output_refs[1]
    )
    assert store.require_analysis_run(child.analysis_id).candidate_terminal is None
    assert artifacts.read(checkpoint.output_refs[0])
    assert any(
        event.error_code == "PRO_CON_LEGACY_EVIDENCE_REPAIRED"
        for event in store.stage_activity(child, SimpleStage.PRO_CON_DONE, "attempt-1")
    )


def test_repair_reopens_child_with_denied_admission_and_no_primitive(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    child = _child()
    artifacts = SimpleArtifactRepository(data_dir, child)
    checkpoint = _checkpoint(artifacts, child)
    root = child.model_copy(update={"hypothesis_id": None})
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(root, child.hypothesis_id or "", checkpoint.input_refs[0])
    store.save_checkpoint(checkpoint)
    admission_ref = artifacts.put_json(
        {
            "kind": "simple_primitive_admission",
            "analysis_id": child.analysis_id,
            "hypothesis_id": child.hypothesis_id,
            "decision": "DENY",
        }
    )
    admission = StageCheckpoint(
        identity=child,
        stage=SimpleStage.PRIMITIVE_ADMISSION_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=checkpoint.output_refs,
        input_hash=input_reference_hash(checkpoint.output_refs),
        output_refs=(admission_ref,),
        attempt_id="admission-attempt",
    )
    store.save_checkpoint(admission)

    assert store.repair_legacy_pro_con_evidence(
        checkpoint,
        {"pro": checkpoint.output_refs[0]},
        expected_role_cache={"pro": None, "con": None},
    )
    assert store.require(child, SimpleStage.PRO_CON_DONE).status is StageStatus.PENDING
    assert store.get(child, SimpleStage.PRIMITIVE_ADMISSION_DONE) is None
    assert artifacts.read(admission_ref)


def test_repair_rejects_stale_cache_without_partial_mutation(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    artifacts = SimpleArtifactRepository(data_dir, child)
    checkpoint = _checkpoint(artifacts, child)
    different = artifacts.put_json({"kind": "different"})
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}),
        child.hypothesis_id or "",
        checkpoint.input_refs[0],
    )
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, checkpoint.output_refs[0]
    )
    store.save_pro_con_batch_evidence(child, "con", checkpoint.input_hash, different)

    with pytest.raises(ValueError, match="PRO_CON_LEGACY_REPAIR_STALE"):
        store.repair_legacy_pro_con_evidence(
            checkpoint,
            {"pro": checkpoint.output_refs[0], "con": checkpoint.output_refs[1]},
            expected_role_cache={
                "pro": checkpoint.output_refs[0],
                "con": different,
            },
        )

    assert store.get(child, SimpleStage.PRO_CON_DONE) == checkpoint
    assert (
        store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash)
        == checkpoint.output_refs[0]
    )
    assert (
        store.get_pro_con_batch_evidence(child, "con", checkpoint.input_hash)
        == different
    )
    assert store.require_analysis_run(child.analysis_id).candidate_terminal is not None


def test_repair_rejects_valid_role_cache_inserted_after_audit(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    checkpoint = _checkpoint(SimpleArtifactRepository(data_dir, child), child)
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}),
        child.hypothesis_id or "",
        checkpoint.input_refs[0],
    )
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, checkpoint.output_refs[0]
    )
    # The audit saw no Con cache; another writer inserted it before the repair.
    store.save_pro_con_batch_evidence(
        child, "con", checkpoint.input_hash, checkpoint.output_refs[1]
    )

    with pytest.raises(ValueError, match="PRO_CON_LEGACY_REPAIR_STALE"):
        store.repair_legacy_pro_con_evidence(
            checkpoint,
            {"pro": checkpoint.output_refs[0]},
            expected_role_cache={"pro": checkpoint.output_refs[0], "con": None},
        )

    assert store.get(child, SimpleStage.PRO_CON_DONE) == checkpoint
    assert store.require_analysis_run(child.analysis_id).candidate_terminal is not None


def test_repair_retracts_chained_descendants_but_keeps_unrelated_child(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    root = _child(hypothesis_id="A").model_copy(update={"hypothesis_id": None})
    store.save_analysis_run(_run(_child(hypothesis_id="A")))
    checkpoints: dict[str, StageCheckpoint] = {}
    for hypothesis_id, parents, depth in (
        ("A", (), 0),
        ("B", ("A",), 1),
        ("C", ("B",), 2),
        ("D", (), 0),
    ):
        identity = root.model_copy(update={"hypothesis_id": hypothesis_id})
        artifacts = SimpleArtifactRepository(data_dir, identity)
        checkpoint = _checkpoint(artifacts, identity)
        checkpoints[hypothesis_id] = checkpoint
        store.upsert_hypothesis(
            root,
            hypothesis_id,
            checkpoint.input_refs[0],
            chain_depth=depth,
            parent_hypothesis_ids=parents,
        )
        store.save_checkpoint(checkpoint)
        if hypothesis_id != "A":
            report_ref = artifacts.put_json({"kind": "report"})
            report = StageCheckpoint(
                identity=identity,
                stage=SimpleStage.REPORT_DONE,
                status=StageStatus.SUCCEEDED,
                input_refs=checkpoint.output_refs,
                input_hash=input_reference_hash(checkpoint.output_refs),
                output_refs=(report_ref,),
            )
            store.save_checkpoint(report)
            store.save_pro_con_batch_evidence(
                identity, "pro", checkpoint.input_hash, checkpoint.output_refs[0]
            )
    source = checkpoints["A"]
    source_identity = source.identity
    store.save_pro_con_batch_evidence(
        source_identity, "pro", source.input_hash, source.output_refs[0]
    )

    assert set(store.list_hypotheses(root)) == {"A", "B", "C", "D"}
    store.repair_legacy_pro_con_evidence(
        source,
        {"pro": source.output_refs[0]},
        expected_role_cache={"pro": source.output_refs[0], "con": None},
    )

    assert set(store.list_hypotheses(root)) == {"A", "D"}
    for hypothesis_id in ("B", "C"):
        identity = root.model_copy(update={"hypothesis_id": hypothesis_id})
        assert store.get(identity, SimpleStage.REPORT_DONE) is None
        assert store.get(identity, SimpleStage.PRO_CON_DONE) is None
        assert (
            store.get_pro_con_batch_evidence(
                identity, "pro", checkpoints[hypothesis_id].input_hash
            )
            is None
        )
    assert (
        store.get(
            root.model_copy(update={"hypothesis_id": "D"}), SimpleStage.REPORT_DONE
        )
        is not None
    )
    assert (
        store.require(source_identity, SimpleStage.PRO_CON_DONE).status
        is StageStatus.PENDING
    )


def test_repair_fails_closed_for_co_parent_lineage(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child(hypothesis_id="A")
    root = child.model_copy(update={"hypothesis_id": None})
    checkpoint = _checkpoint(SimpleArtifactRepository(data_dir, child), child)
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(root, "A", checkpoint.input_refs[0])
    store.upsert_hypothesis(root, "D")
    store.upsert_hypothesis(root, "B", chain_depth=1, parent_hypothesis_ids=("A", "D"))
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, checkpoint.output_refs[0]
    )

    with pytest.raises(ValueError, match="PRO_CON_LEGACY_REPAIR_COPARENT"):
        store.repair_legacy_pro_con_evidence(
            checkpoint,
            {"pro": checkpoint.output_refs[0]},
            expected_role_cache={"pro": checkpoint.output_refs[0], "con": None},
        )

    assert store.require(child, SimpleStage.PRO_CON_DONE) == checkpoint
    assert set(store.list_hypotheses(root)) == {"A", "B", "D"}
    assert store.require_analysis_run(child.analysis_id).candidate_terminal is not None


def test_repair_rewinds_surviving_no_child_chaining_and_report(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    source = _child(hypothesis_id="A")
    other = _child(hypothesis_id="D")
    root = source.model_copy(update={"hypothesis_id": None})
    source_artifacts = SimpleArtifactRepository(data_dir, source)
    other_artifacts = SimpleArtifactRepository(data_dir, other)
    source_pro_con = _legacy_checkpoint(source_artifacts, source, invalid_pro=True)
    primitive_ref = source_artifacts.put_json({"kind": "simple_primitive"})
    primitive = StageCheckpoint(
        identity=source,
        stage=SimpleStage.PRIMITIVE_ADMISSION_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=source_pro_con.output_refs,
        input_hash=input_reference_hash(source_pro_con.output_refs),
        output_refs=(source_artifacts.put_json({"kind": "admission"}), primitive_ref),
    )
    other_pro_con = _legacy_checkpoint(other_artifacts, other, invalid_pro=False)
    final = StageCheckpoint(
        identity=other,
        stage=SimpleStage.VERIFICATION_FINAL_DONE,
        stage_version="2",
        status=StageStatus.SUCCEEDED,
        input_refs=other_pro_con.output_refs,
        input_hash=input_reference_hash(other_pro_con.output_refs),
        output_refs=(other_artifacts.put_json({"kind": "verification"}),),
        verdict="TRUE",
    )
    chain_result = other_artifacts.put_json(
        {
            "kind": "simple_chaining_result",
            "analysis_id": source.analysis_id,
            "source_hypothesis_id": other.hypothesis_id,
            "considered_primitive_refs": [primitive_ref.model_dump(mode="json")],
            "status": "NO_MATERIAL_CHILD",
            "children": [],
        }
    )
    chain = StageCheckpoint(
        identity=other,
        stage=SimpleStage.CHAINING_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=other_pro_con.output_refs,
        input_hash=input_reference_hash(other_pro_con.output_refs),
        output_refs=(chain_result,),
    )
    finding = StageCheckpoint(
        identity=other,
        stage=SimpleStage.FINDING_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(chain_result,),
        input_hash=input_reference_hash((chain_result,)),
        output_refs=(other_artifacts.put_json({"kind": "finding"}),),
    )
    report = StageCheckpoint(
        identity=other,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(chain_result,),
        input_hash=input_reference_hash((chain_result,)),
        output_refs=(other_artifacts.put_json({"kind": "report"}),),
    )
    store.save_analysis_run(_run(source))
    store.save_checkpoint(
        StageCheckpoint(
            identity=root,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
        )
    )
    store.upsert_hypothesis(root, "A", source_pro_con.input_refs[0])
    store.upsert_hypothesis(root, "D", other_pro_con.input_refs[0])
    for checkpoint in (
        source_pro_con,
        primitive,
        other_pro_con,
        final,
        chain,
        finding,
        report,
    ):
        store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        source, "pro", source_pro_con.input_hash, source_pro_con.output_refs[0]
    )

    assert store.repair_legacy_pro_con_evidence(
        source_pro_con,
        {"pro": source_pro_con.output_refs[0]},
        expected_role_cache={"pro": source_pro_con.output_refs[0], "con": None},
    )

    assert store.require(source, SimpleStage.PRO_CON_DONE).status is StageStatus.PENDING
    assert store.require(other, SimpleStage.PRO_CON_DONE) == other_pro_con
    assert store.require(other, SimpleStage.VERIFICATION_FINAL_DONE) == final
    for stage in (
        SimpleStage.CHAINING_DONE,
        SimpleStage.FINDING_DONE,
        SimpleStage.REPORT_DONE,
    ):
        assert store.get(other, stage) is None
    assert other.hypothesis_id in store.list_incomplete_hypotheses(root)
    assert store.require_analysis_run(source.analysis_id).candidate_terminal is None
    assert not candidate_report_integrity_blocked(
        store.require_analysis_run(source.analysis_id),
        store.list_checkpoints(source.analysis_id),
    )
    assert other_artifacts.read(report.output_refs[0])


@pytest.mark.parametrize(
    ("status", "children", "register_descendant"),
    [
        ("MATERIAL_CHILD", [{"child": "B"}], False),
        ("NO_MATERIAL_CHILD", [{"child": "B"}], False),
        ("NO_MATERIAL_CHILD", [], True),
    ],
)
def test_repair_keeps_unsafe_dependent_chaining_and_report_fail_closed(
    tmp_path: Path,
    status: str,
    children: list[dict[str, str]],
    register_descendant: bool,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    source = _child(hypothesis_id="A")
    other = _child(hypothesis_id="D")
    root = source.model_copy(update={"hypothesis_id": None})
    source_artifacts = SimpleArtifactRepository(data_dir, source)
    other_artifacts = SimpleArtifactRepository(data_dir, other)
    source_pro_con = _checkpoint(source_artifacts, source)
    primitive_ref = source_artifacts.put_json({"kind": "simple_primitive"})
    primitive = StageCheckpoint(
        identity=source,
        stage=SimpleStage.PRIMITIVE_ADMISSION_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=source_pro_con.output_refs,
        input_hash=input_reference_hash(source_pro_con.output_refs),
        output_refs=(source_artifacts.put_json({"kind": "admission"}), primitive_ref),
    )
    chain_result = other_artifacts.put_json(
        {
            "kind": "simple_chaining_result",
            "analysis_id": source.analysis_id,
            "source_hypothesis_id": other.hypothesis_id,
            "considered_primitive_refs": [primitive_ref.model_dump(mode="json")],
            "status": status,
            "children": children,
        }
    )
    chain = StageCheckpoint(
        identity=other,
        stage=SimpleStage.CHAINING_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(chain_result,),
    )
    report = StageCheckpoint(
        identity=other,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(chain_result,),
        input_hash=input_reference_hash((chain_result,)),
        output_refs=(other_artifacts.put_json({"kind": "report"}),),
    )
    store.save_analysis_run(_run(source))
    store.upsert_hypothesis(root, "A", source_pro_con.input_refs[0])
    store.upsert_hypothesis(root, "D")
    if register_descendant:
        store.upsert_hypothesis(root, "B", chain_depth=1, parent_hypothesis_ids=("D",))
    for checkpoint in (source_pro_con, primitive, chain, report):
        store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        source, "pro", source_pro_con.input_hash, source_pro_con.output_refs[0]
    )

    with pytest.raises(ValueError, match="PRO_CON_LEGACY_REPAIR_DEPENDENT_CHAINING"):
        store.repair_legacy_pro_con_evidence(
            source_pro_con,
            {"pro": source_pro_con.output_refs[0]},
            expected_role_cache={"pro": source_pro_con.output_refs[0], "con": None},
        )

    assert store.require(source, SimpleStage.PRO_CON_DONE) == source_pro_con
    assert store.require(other, SimpleStage.CHAINING_DONE) == chain
    assert store.require(other, SimpleStage.REPORT_DONE) == report
    assert store.require_analysis_run(source.analysis_id).candidate_terminal is not None


def _legacy_checkpoint(
    artifacts: SimpleArtifactRepository,
    identity: CheckpointIdentity,
    *,
    invalid_pro: bool,
    wrong_source: bool = False,
    missing_digest: bool = False,
) -> StageCheckpoint:
    proposal = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
        }
    )
    context = artifacts.put_json({"kind": "context"})
    inputs = (proposal, context)
    source_refs = [ref.model_dump(mode="json") for ref in inputs]
    if wrong_source:
        source_refs = []

    def evidence(role: str, cited: str) -> StoredDataRef:
        result = {
            "claims": ["claim"],
            "evidence_refs": [cited],
            "limitations": [],
            "requested_paths": [],
        }
        payload = {
            "kind": f"simple_{role}_evidence",
            "source_refs": source_refs,
            "result": result,
            "prompt_digest": "a" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(result)).hexdigest(),
            "attempt_id": "attempt-1",
        }
        if missing_digest and role == "pro":
            payload.pop("output_digest")
        return artifacts.put_json(payload)

    pro = evidence("pro", "f" * 64 if invalid_pro else proposal.content_hash)
    con = evidence("con", proposal.content_hash)
    return StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=(pro, con),
        attempt_id="attempt-1",
        attempt_number=1,
    )


def _application(
    data_dir: Path, store: SimpleCheckpointStore
) -> SimpleAnalysisApplication:
    return SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=cast(StaticBootstrap, None),  # audit never reaches bootstrap
        hypothesis_bootstrap=cast(HypothesisBootstrap, None),
        runner_factory=cast(RunnerFactory, None),
    )


def test_resume_audit_repairs_only_semantically_invalid_legacy_role(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    checkpoint = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child), child, invalid_pro=True
    )
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}),
        child.hypothesis_id or "",
        checkpoint.input_refs[0],
    )
    store.save_checkpoint(checkpoint)
    for role, ref in zip(("pro", "con"), checkpoint.output_refs, strict=True):
        store.save_pro_con_batch_evidence(child, role, checkpoint.input_hash, ref)

    asyncio.run(
        _application(data_dir, store)._repair_invalid_saved_pro_con(child.analysis_id)
    )

    replay = store.require(child, SimpleStage.PRO_CON_DONE)
    assert replay.status is StageStatus.PENDING
    assert replay.input_refs == checkpoint.input_refs
    assert store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash) is None
    assert (
        store.get_pro_con_batch_evidence(child, "con", checkpoint.input_hash)
        == checkpoint.output_refs[1]
    )
    assert store.require_analysis_run(child.analysis_id).candidate_terminal is None
    events = store.stage_activity(child, SimpleStage.PRO_CON_DONE, "attempt-1")
    asyncio.run(
        _application(data_dir, store)._repair_invalid_saved_pro_con(child.analysis_id)
    )
    assert store.stage_activity(child, SimpleStage.PRO_CON_DONE, "attempt-1") == events


def test_resume_audit_repairs_role_after_real_blocked_failure_with_evidence_refs(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    original = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child), child, invalid_pro=True
    )
    pending = original.model_copy(
        update={"status": StageStatus.PENDING, "output_refs": ()}
    )
    store.save_analysis_run(_run(child))
    store.save_checkpoint(pending)
    for role, ref in zip(("pro", "con"), original.output_refs, strict=True):
        store.save_pro_con_batch_evidence(child, role, pending.input_hash, ref)
    failed = store.mark_failure(
        pending,
        StageFailure(
            code="PRO_CON_BATCH_EXISTING_INVALID",
            retryable=True,
            safe_message="Stored Pro/Con evidence does not match the child",
            invalid_field="evidence_refs",
            evidence_refs=(original.output_refs[0],),
        ),
        StageStatus.BLOCKED,
    )
    assert failed.output_refs == (original.output_refs[0],)

    asyncio.run(
        _application(data_dir, store)._repair_invalid_saved_pro_con(child.analysis_id)
    )

    replay = store.require(child, SimpleStage.PRO_CON_DONE)
    assert replay.status is StageStatus.PENDING
    assert replay.output_refs == ()
    assert replay.input_refs == pending.input_refs
    assert store.get_pro_con_batch_evidence(child, "pro", pending.input_hash) is None
    assert (
        store.get_pro_con_batch_evidence(child, "con", pending.input_hash)
        == original.output_refs[1]
    )


def test_resume_audit_repairs_successful_role_reused_from_prior_attempt(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    original = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child), child, invalid_pro=True
    )
    checkpoint = original.model_copy(update={"attempt_id": "attempt-2"})
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}),
        child.hypothesis_id or "",
        checkpoint.input_refs[0],
    )
    store.save_checkpoint(checkpoint)
    for role, ref in zip(("pro", "con"), checkpoint.output_refs, strict=True):
        store.save_pro_con_batch_evidence(child, role, checkpoint.input_hash, ref)

    asyncio.run(
        _application(data_dir, store)._repair_invalid_saved_pro_con(child.analysis_id)
    )

    replay = store.require(child, SimpleStage.PRO_CON_DONE)
    assert replay.status is StageStatus.PENDING
    assert replay.input_refs == checkpoint.input_refs
    assert store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash) is None
    assert (
        store.get_pro_con_batch_evidence(child, "con", checkpoint.input_hash)
        == checkpoint.output_refs[1]
    )


@pytest.mark.parametrize("pipeline_version", [1, 2])
@pytest.mark.parametrize("status", [StageStatus.PENDING, StageStatus.BLOCKED])
def test_resume_audit_reopens_invalid_incomplete_role_cache_only(
    tmp_path: Path, pipeline_version: int, status: StageStatus
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    original = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child), child, invalid_pro=True
    )
    checkpoint = original.model_copy(
        update={
            "status": status,
            "output_refs": (),
            "attempt_id": "attempt-1" if status is StageStatus.BLOCKED else None,
            "error_code": "PRO_CON_BATCH_EXISTING_INVALID"
            if status is StageStatus.BLOCKED
            else None,
            "retryable": status is StageStatus.BLOCKED,
        }
    )
    store.save_analysis_run(_run(child, pipeline_version=pipeline_version))
    store.save_checkpoint(checkpoint)
    for role, ref in zip(("pro", "con"), original.output_refs, strict=True):
        store.save_pro_con_batch_evidence(child, role, checkpoint.input_hash, ref)

    asyncio.run(
        _application(data_dir, store)._repair_invalid_saved_pro_con(child.analysis_id)
    )

    replay = store.require(child, SimpleStage.PRO_CON_DONE)
    assert replay.status is StageStatus.PENDING
    assert replay.input_refs == checkpoint.input_refs
    assert replay.input_hash == checkpoint.input_hash
    assert replay.output_refs == ()
    assert store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash) is None
    assert (
        store.get_pro_con_batch_evidence(child, "con", checkpoint.input_hash)
        == original.output_refs[1]
    )


@pytest.mark.parametrize("corruption", ["wrong_source", "missing_digest"])
def test_resume_audit_keeps_corrupt_incomplete_role_cache_fail_closed(
    tmp_path: Path, corruption: str
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    original = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child),
        child,
        invalid_pro=True,
        wrong_source=corruption == "wrong_source",
        missing_digest=corruption == "missing_digest",
    )
    checkpoint = original.model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "output_refs": (),
            "error_code": "PRO_CON_BATCH_EXISTING_INVALID",
            "retryable": True,
        }
    )
    store.save_analysis_run(_run(child))
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, original.output_refs[0]
    )
    store.save_pro_con_batch_evidence(
        child, "con", checkpoint.input_hash, original.output_refs[1]
    )

    with pytest.raises(StaticEvidenceInvalid):
        asyncio.run(
            _application(data_dir, store)._repair_invalid_saved_pro_con(
                child.analysis_id
            )
        )

    assert store.require(child, SimpleStage.PRO_CON_DONE) == checkpoint
    assert (
        store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash)
        == original.output_refs[0]
    )
    assert (
        store.get_pro_con_batch_evidence(child, "con", checkpoint.input_hash)
        == original.output_refs[1]
    )


def test_resume_audit_removes_both_invalid_incomplete_role_caches(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    artifacts = SimpleArtifactRepository(data_dir, child)
    original = _legacy_checkpoint(artifacts, child, invalid_pro=True)
    con_envelope = artifacts.read(original.output_refs[1])
    con_value = json.loads(con_envelope)
    con_value["result"]["evidence_refs"] = ["e" * 64]
    con_value["output_digest"] = hashlib.sha256(
        canonical_bytes(con_value["result"])
    ).hexdigest()
    invalid_con = artifacts.put_json(con_value)
    checkpoint = original.model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "output_refs": (),
            "error_code": "PRO_CON_BATCH_EXISTING_INVALID",
            "retryable": True,
        }
    )
    store.save_analysis_run(_run(child))
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, original.output_refs[0]
    )
    store.save_pro_con_batch_evidence(child, "con", checkpoint.input_hash, invalid_con)

    asyncio.run(
        _application(data_dir, store)._repair_invalid_saved_pro_con(child.analysis_id)
    )

    assert store.require(child, SimpleStage.PRO_CON_DONE).status is StageStatus.PENDING
    assert store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash) is None
    assert store.get_pro_con_batch_evidence(child, "con", checkpoint.input_hash) is None


def test_resume_audit_repairs_incomplete_cache_reused_from_prior_attempt(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    original = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child), child, invalid_pro=True
    )
    checkpoint = original.model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "output_refs": (),
            "attempt_id": "different-attempt",
            "error_code": "PRO_CON_BATCH_EXISTING_INVALID",
            "retryable": True,
        }
    )
    store.save_analysis_run(_run(child))
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, original.output_refs[0]
    )

    asyncio.run(
        _application(data_dir, store)._repair_invalid_saved_pro_con(child.analysis_id)
    )

    replay = store.require(child, SimpleStage.PRO_CON_DONE)
    assert replay.status is StageStatus.PENDING
    assert replay.input_refs == checkpoint.input_refs
    assert store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash) is None


def test_v1_registered_legacy_child_remains_repairable(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    checkpoint = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child), child, invalid_pro=True
    )
    store.save_analysis_run(_run(child, pipeline_version=1))
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}),
        child.hypothesis_id or "",
        checkpoint.input_refs[0],
    )
    store.save_checkpoint(checkpoint)
    asyncio.run(
        _application(data_dir, store)._repair_invalid_saved_pro_con(child.analysis_id)
    )
    assert store.require(child, SimpleStage.PRO_CON_DONE).status is StageStatus.PENDING
    assert (
        store.get_pro_con_batch_evidence(child, "con", checkpoint.input_hash)
        == checkpoint.output_refs[1]
    )


def test_repeated_identical_root_integrity_block_is_idempotent(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    root = _child().model_copy(update={"hypothesis_id": None})
    run = _run(root)
    store.save_analysis_run(run)
    checkpoint = StageCheckpoint(
        identity=root,
        stage=SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="root-attempt-1",
    )
    store.save_checkpoint(checkpoint)
    app = _application(data_dir, store)

    first = app._invalid_hypothesis_resume(run, root)
    events = store.stage_activity(root, SimpleStage.HYPOTHESIS_DONE, "root-attempt-1")
    second = app._invalid_hypothesis_resume(run, root)

    assert first.status == second.status == "BLOCKED"
    assert first.error_code == second.error_code == "HYPOTHESIS_EVIDENCE_INVALID"
    assert (
        store.stage_activity(root, SimpleStage.HYPOTHESIS_DONE, "root-attempt-1")
        == events
    )
    activity = AgentActivityStore(data_dir / "db" / "sastsimi.sqlite3").list_analysis(
        root.analysis_id
    )
    integrity_events = [
        event for event in activity if event.error_code == "HYPOTHESIS_EVIDENCE_INVALID"
    ]
    assert len(integrity_events) == 1


def test_root_integrity_block_after_existing_failure_keeps_prior_activity(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    root = _child().model_copy(update={"hypothesis_id": None})
    run = _run(root)
    store.save_analysis_run(run)
    checkpoint = StageCheckpoint(
        identity=root,
        stage=SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.PENDING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="root-attempt-1",
    )
    store.save_checkpoint(checkpoint)
    store.mark_failure(
        checkpoint,
        StageFailure(code="PRIOR_FAILURE", retryable=False, safe_message="prior"),
        StageStatus.FAILED,
    )
    prior = store.stage_activity(root, SimpleStage.HYPOTHESIS_DONE, "root-attempt-1")

    first = _application(data_dir, store)._invalid_hypothesis_resume(run, root)
    second = _application(data_dir, store)._invalid_hypothesis_resume(run, root)

    assert first.status == second.status == "BLOCKED"
    assert first.error_code == second.error_code == "HYPOTHESIS_EVIDENCE_INVALID"
    assert (
        store.stage_activity(root, SimpleStage.HYPOTHESIS_DONE, "root-attempt-1")
        == prior
    )
    assert (
        store.require(root, SimpleStage.HYPOTHESIS_DONE).attempt_id == "root-attempt-1"
    )
    activity = AgentActivityStore(data_dir / "db" / "sastsimi.sqlite3").list_analysis(
        root.analysis_id
    )
    integrity_events = [
        event for event in activity if event.error_code == "HYPOTHESIS_EVIDENCE_INVALID"
    ]
    assert len(integrity_events) == 1


def test_resume_audit_preserves_provenance_failure(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    checkpoint = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child),
        child,
        invalid_pro=True,
        wrong_source=True,
    )
    store.save_analysis_run(_run(child))
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, checkpoint.output_refs[0]
    )

    with pytest.raises(StaticEvidenceInvalid):
        asyncio.run(
            _application(data_dir, store)._repair_invalid_saved_pro_con(
                child.analysis_id
            )
        )

    assert store.get(child, SimpleStage.PRO_CON_DONE) == checkpoint
    assert (
        store.get_pro_con_batch_evidence(child, "pro", checkpoint.input_hash)
        == checkpoint.output_refs[0]
    )


def test_resume_audit_does_not_repair_missing_digest(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    checkpoint = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child),
        child,
        invalid_pro=True,
        missing_digest=True,
    )
    store.save_analysis_run(_run(child))
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, checkpoint.output_refs[0]
    )

    with pytest.raises(StaticEvidenceInvalid):
        asyncio.run(
            _application(data_dir, store)._repair_invalid_saved_pro_con(
                child.analysis_id
            )
        )

    assert store.get(child, SimpleStage.PRO_CON_DONE) == checkpoint
    assert store.require_analysis_run(child.analysis_id).candidate_terminal is not None


def test_repaired_checkpoint_replays_exact_inputs_via_runner(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child()
    checkpoint = _checkpoint(SimpleArtifactRepository(data_dir, child), child)
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}),
        child.hypothesis_id or "",
        checkpoint.input_refs[0],
    )
    store.save_checkpoint(checkpoint)
    store.repair_legacy_pro_con_evidence(
        checkpoint,
        {"pro": checkpoint.output_refs[0]},
        expected_role_cache={"pro": None, "con": None},
    )
    original = checkpoint
    observed: list[tuple[StoredDataRef, ...]] = []

    async def pro_con(
        checkpoint: StageCheckpoint, prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        del prior
        observed.append(checkpoint.input_refs)
        return StageResult(output_refs=original.output_refs)

    async def stop(
        checkpoint: StageCheckpoint, prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        del checkpoint, prior
        raise StageBlocked(
            StageFailure(code="STOP_AFTER_REPLAY", retryable=False, safe_message="stop")
        )

    runner = SimpleRuntimeRunner(
        store,
        {
            SimpleStage.PRO_CON_DONE: pro_con,
            SimpleStage.VERIFICATION_INITIAL_DONE: stop,
        },
    )
    outcome = asyncio.run(runner.resume_hypothesis(child))
    assert observed == [checkpoint.input_refs]
    assert outcome.error_code == "STOP_AFTER_REPLAY"
    assert (
        store.require(child, SimpleStage.PRO_CON_DONE).status is StageStatus.SUCCEEDED
    )


def test_batch_prewarm_skips_repaired_child_with_valid_legacy_role(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child(hypothesis_id="A")
    sibling = _child(hypothesis_id="B")
    artifacts = SimpleArtifactRepository(data_dir, child)
    checkpoint = _legacy_checkpoint(artifacts, child, invalid_pro=True)
    sibling_proposal = artifacts.put_json({"kind": "proposal", "hypothesis_id": "B"})
    sibling_refs = (sibling_proposal, checkpoint.input_refs[1])
    sibling_pending = StageCheckpoint(
        identity=sibling,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.PENDING,
        input_refs=sibling_refs,
        input_hash=input_reference_hash(sibling_refs),
    )
    store.save_analysis_run(_run(child))
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}), "A", checkpoint.input_refs[0]
    )
    store.upsert_hypothesis(
        child.model_copy(update={"hypothesis_id": None}), "B", sibling_proposal
    )
    store.save_checkpoint(checkpoint)
    store.save_checkpoint(sibling_pending)
    store.save_pro_con_batch_evidence(
        child, "con", checkpoint.input_hash, checkpoint.output_refs[1]
    )
    store.repair_legacy_pro_con_evidence(
        checkpoint,
        {"pro": checkpoint.output_refs[0]},
        expected_role_cache={"pro": None, "con": checkpoint.output_refs[1]},
    )
    app = _application(data_dir, store)

    def unexpected_batch(*_args: object) -> SimpleRuntimeRunner:
        raise AssertionError("legacy cached role must use individual runner")

    app._runner_factory = unexpected_batch
    static = StaticBootstrapResult(
        repository_profile_ref=checkpoint.input_refs[0],
        static_bundle_ref=checkpoint.input_refs[1],
        workspace_path=tmp_path,
    )
    outcome = asyncio.run(
        app._prewarm_pro_con_batches(
            child.model_copy(update={"hypothesis_id": None}),
            static,
            ("A", "B"),
            set(),
        )
    )
    assert outcome is None
    assert store.require(child, SimpleStage.PRO_CON_DONE).status is StageStatus.PENDING


def test_v2_resume_replays_repaired_child_after_durable_batch_marker(
    tmp_path: Path,
) -> None:
    app, store, _client, _hypotheses = _setup(
        tmp_path, pipeline_version=2, with_ast_summary=True, decision="INCLUDE"
    )
    data_dir = tmp_path / "data"
    app._candidate_hypotheses = cast(
        HypothesisBootstrap, _SecondLookHypotheses(data_dir)
    )
    first = asyncio.run(
        app.analyze(
            SimpleAnalysisRequest(
                data_dir=data_dir,
                repository="https://github.com/example/repo",
                commit="a" * 40,
            )
        )
    )
    assert first.status in {"COMPLETE", "BLOCKED"}, first.error_code
    root = _child().model_copy(update={"hypothesis_id": None})
    run = store.require_analysis_run(root.analysis_id)
    assert run.candidate_scope_fingerprint is not None
    markers = store.list_candidate_batch_progress(root, run.candidate_scope_fingerprint)
    assert markers
    child = root.model_copy(update={"hypothesis_id": "A"})
    checkpoint = _legacy_checkpoint(
        SimpleArtifactRepository(data_dir, child), child, invalid_pro=True
    )
    store.upsert_hypothesis(root, "A", checkpoint.input_refs[0])
    store.save_checkpoint(checkpoint)
    store.save_pro_con_batch_evidence(
        child, "pro", checkpoint.input_hash, checkpoint.output_refs[0]
    )
    store.save_pro_con_batch_evidence(
        child, "con", checkpoint.input_hash, checkpoint.output_refs[1]
    )
    sibling = root.model_copy(update={"hypothesis_id": "B"})
    sibling_proposal = SimpleArtifactRepository(data_dir, sibling).put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": root.analysis_id,
            "hypothesis_id": "B",
        }
    )
    sibling_refs = (sibling_proposal, checkpoint.input_refs[1])
    store.upsert_hypothesis(root, "B", sibling_proposal)
    store.save_checkpoint(
        StageCheckpoint(
            identity=sibling,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.PENDING,
            input_refs=sibling_refs,
            input_hash=input_reference_hash(sibling_refs),
        )
    )
    observed: list[tuple[StoredDataRef, ...]] = []
    factory_calls: list[str] = []
    original = checkpoint

    async def pro_con(
        checkpoint: StageCheckpoint, prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        del prior
        observed.append(checkpoint.input_refs)
        assert (
            store.get_pro_con_batch_evidence(child, "pro", original.input_hash) is None
        )
        assert (
            store.get_pro_con_batch_evidence(child, "con", original.input_hash)
            == original.output_refs[1]
        )
        return StageResult(output_refs=original.output_refs)

    async def stop(
        checkpoint: StageCheckpoint, prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        del checkpoint, prior
        raise StageBlocked(
            StageFailure(code="STOP_AFTER_REPLAY", retryable=False, safe_message="stop")
        )

    def runner_factory(
        backing: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        del static
        if identity.hypothesis_id is None:
            raise AssertionError("completed v2 batch should not replay root runner")
        factory_calls.append(identity.hypothesis_id)
        return SimpleRuntimeRunner(
            backing,
            {
                SimpleStage.PRO_CON_DONE: pro_con,
                SimpleStage.VERIFICATION_INITIAL_DONE: stop,
            },
        )

    app._runner_factory = runner_factory
    resumed = asyncio.run(app.resume(root.analysis_id))
    assert resumed.status == "BLOCKED"
    assert observed[0] == checkpoint.input_refs
    assert factory_calls == ["A", "B"]
    assert (
        store.require(child, SimpleStage.PRO_CON_DONE).status is StageStatus.SUCCEEDED
    )
    assert (
        store.list_candidate_batch_progress(root, run.candidate_scope_fingerprint)
        == markers
    )
