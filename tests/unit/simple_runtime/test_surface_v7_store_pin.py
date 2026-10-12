"""The v7 pointer is a CAS over the saved v6 certificate and progress."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_enrichment_v7_bindings import (
    prior_progress_snapshot_hash,
)


def _case(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    CheckpointIdentity,
    SimpleAnalysisRun,
    StoredDataRef,
    str,
    list[dict[str, str]],
]:
    identity = CheckpointIdentity(
        analysis_id="analysis-v7",
        workspace_id="workspace-v7",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    store = SimpleCheckpointStore(
        tmp_path / "ledger.sqlite3", artifact_data_dir=tmp_path / "data"
    )
    index_ref = artifacts.put_json({"kind": "simple_attack_surface_index_v2"})
    coverage_ref = artifacts.put_json({"kind": "simple_surface_coverage_v4"})
    v4_plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    v5_plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v5"})
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v5", "part": 0})
    v6_plan = {
        "kind": "simple_surface_enrichment_plan_v6",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": "candidate",
        "scope_fingerprint": "scope-v7",
        "expected_parts": [
            {
                "surface_id": "surface-v7",
                "context_id": "context-v6",
                "context_hash": context_ref.content_hash,
                "source_sha256": "b" * 64,
            }
        ],
    }
    v6_plan_ref = artifacts.put_json(v6_plan)
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    parent = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_scope_fingerprint="scope-v7",
        surface_enrichment_plan_ref=v4_plan_ref,
        surface_enrichment_v5_plan_ref=v5_plan_ref,
        surface_enrichment_v6_plan_ref=v6_plan_ref,
        python_scope_certificate_ref=certificate_ref,
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash="c" * 64,
            scope_fingerprint="scope-v7",
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_index_hash=index_ref.content_hash,
            surface_coverage_hash=coverage_ref.content_hash,
            surface_proof_version=4,
            scope_certificate_hash=certificate_ref.content_hash,
        ),
    )
    store.save_analysis_run(parent)
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(index_ref, coverage_ref),
        )
    )
    progress_hash = prior_progress_snapshot_hash({})
    missing = [{"surface_id": "surface-v7", "context_id": "context-v6"}]
    plan_ref = artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v7",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "scope": "candidate",
            "scope_fingerprint": "scope-v7",
            "graph_semantics_revision": "v5-source-bound-4",
            "static_bundle_hash": "c" * 64,
            "index_ref": index_ref.model_dump(mode="json"),
            "index_hash": index_ref.content_hash,
            "prior_v6_plan_ref": v6_plan_ref.model_dump(mode="json"),
            "prior_v6_plan_hash": v6_plan_ref.content_hash,
            "prior_v4_coverage_ref": coverage_ref.model_dump(mode="json"),
            "prior_v4_coverage_hash": coverage_ref.content_hash,
            "prior_progress_hash": progress_hash,
            "missing_v6_parts": missing,
        }
    )
    return store, artifacts, identity, parent, plan_ref, progress_hash, missing


def test_v7_pin_is_idempotent_and_preserves_v6_parent(tmp_path: Path) -> None:
    store, artifacts, identity, parent, plan_ref, progress_hash, missing = _case(
        tmp_path
    )

    assert store.pin_surface_enrichment_v7_plan(
        parent, plan_ref, progress_hash, missing
    )
    saved = store.require_analysis_run(parent.analysis_id)
    assert saved.surface_enrichment_v7_plan_ref == plan_ref
    assert saved.surface_enrichment_v6_plan_ref == parent.surface_enrichment_v6_plan_ref
    assert saved.candidate_terminal == parent.candidate_terminal
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v7"})
    assert store.commit_surface_exploration(
        identity,
        "scope-v7",
        "surface-v7",
        "context-v7",
        static_bundle_hash="c" * 64,
        index_hash="d" * 64,
        context_hash="e" * 64,
        source_sha256="b" * 64,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=(),
        proposal_version=7,
    )
    assert not store.pin_surface_enrichment_v7_plan(
        parent, plan_ref, progress_hash, missing
    )


def test_v7_pin_rejects_competing_plan_and_changed_root(tmp_path: Path) -> None:
    store, artifacts, _identity, parent, plan_ref, progress_hash, missing = _case(
        tmp_path
    )
    other_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v7"})
    assert store.pin_surface_enrichment_v7_plan(
        parent, plan_ref, progress_hash, missing
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7_PIN"):
        store.pin_surface_enrichment_v7_plan(parent, other_ref, progress_hash, missing)

    another = _case(tmp_path / "root")
    other_store, other_artifacts, other_identity, other_parent = another[:4]
    other_plan_ref, other_hash, other_missing = another[4:]
    root = other_store.get(other_identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    changed_coverage = other_artifacts.put_json({"kind": "different-coverage"})
    other_store.save_checkpoint(
        root.model_copy(update={"output_refs": (root.output_refs[0], changed_coverage)})
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7_PIN_STALE"):
        other_store.pin_surface_enrichment_v7_plan(
            other_parent, other_plan_ref, other_hash, other_missing
        )


def test_v7_pin_rejects_old_progress_race_and_missing_set_mismatch(
    tmp_path: Path,
) -> None:
    store, artifacts, identity, parent, plan_ref, progress_hash, missing = _case(
        tmp_path
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7_PIN_INVALID"):
        store.pin_surface_enrichment_v7_plan(parent, plan_ref, progress_hash, [])

    context_ref = artifacts.put_json({"kind": "simple_surface_context_v5", "part": 0})
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v6"})
    store.commit_surface_exploration(
        identity,
        "scope-v7",
        "surface-v7",
        "context-v6",
        static_bundle_hash="c" * 64,
        index_hash="d" * 64,
        context_hash=context_ref.content_hash,
        source_sha256="b" * 64,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=(),
        proposal_version=6,
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7_PIN_STALE"):
        store.pin_surface_enrichment_v7_plan(parent, plan_ref, progress_hash, missing)


def test_v7_pin_rejects_corrupt_root_artifact(tmp_path: Path) -> None:
    store, artifacts, identity, parent, plan_ref, progress_hash, missing = _case(
        tmp_path
    )
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    artifacts.artifacts.path_for(root.output_refs[1].content_hash).write_bytes(
        b"corrupt coverage bytes"
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7_PIN_INVALID"):
        store.pin_surface_enrichment_v7_plan(parent, plan_ref, progress_hash, missing)


@pytest.mark.parametrize(
    ("changed_key", "changed_value"),
    [
        ("graph_semantics_revision", "v5-source-bound-3"),
        ("static_bundle_hash", "0" * 64),
    ],
)
def test_v7_pin_rejects_changed_graph_or_static_binding(
    tmp_path: Path, changed_key: str, changed_value: str
) -> None:
    store, artifacts, _identity, parent, plan_ref, progress_hash, missing = _case(
        tmp_path
    )
    changed = json.loads(artifacts.read(plan_ref))
    changed[changed_key] = changed_value
    changed_ref = artifacts.put_json(changed)

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7_PIN_INVALID"):
        store.pin_surface_enrichment_v7_plan(
            parent, changed_ref, progress_hash, missing
        )


def test_v7_progress_is_distinct_and_replays_exactly(tmp_path: Path) -> None:
    store, artifacts, identity, _parent, _plan_ref, _hash, _missing = _case(tmp_path)
    v6_result = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v6"})
    v7_result = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v7"})
    for version, context_id, result_ref in (
        (6, "context-v6", v6_result),
        (7, "context-v7", v7_result),
    ):
        assert store.commit_surface_exploration(
            identity,
            "scope-v7",
            "surface-v7",
            context_id,
            static_bundle_hash="c" * 64,
            index_hash="d" * 64,
            context_hash="e" * 64,
            source_sha256="b" * 64,
            status="NO_HYPOTHESIS",
            result_ref=result_ref,
            registrations=(),
            proposal_version=version,
        )
    saved = store.list_surface_exploration_progress(identity, "scope-v7")
    assert {key[1]: row.proposal_version for key, row in saved.items()} == {
        "context-v6": 6,
        "context-v7": 7,
    }
    assert not store.commit_surface_exploration(
        identity,
        "scope-v7",
        "surface-v7",
        "context-v7",
        static_bundle_hash="c" * 64,
        index_hash="d" * 64,
        context_hash="e" * 64,
        source_sha256="b" * 64,
        status="NO_HYPOTHESIS",
        result_ref=v7_result,
        registrations=(),
        proposal_version=7,
    )


def test_v7_model_requires_v6_pointer_and_accepts_terminal_proof_five(
    tmp_path: Path,
) -> None:
    _store, _artifacts, _identity, parent, plan_ref, _hash, _missing = _case(tmp_path)
    with pytest.raises(ValidationError, match="SURFACE_ENRICHMENT_V7_STATE_UNBOUND"):
        SimpleAnalysisRun.model_validate(
            parent.model_copy(
                update={
                    "surface_enrichment_v6_plan_ref": None,
                    "surface_enrichment_v7_plan_ref": plan_ref,
                }
            ).model_dump()
        )
    assert parent.candidate_terminal is not None
    assert (
        CandidateTerminal.model_validate(
            parent.candidate_terminal.model_copy(update={"surface_proof_version": 5})
        ).surface_proof_version
        == 5
    )
