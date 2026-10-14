"""A v8 review overlays a complete saved v7 parent without changing it."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sastsimi.contracts.canonical_json import canonical_bytes
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
from sastsimi.simple_runtime.surface_enrichment_v9_bindings import (
    prior_v8_progress_snapshot_hash,
)


def _parent_run(
    tmp_path: Path,
) -> tuple[SimpleAnalysisRun, SimpleArtifactRepository, StoredDataRef]:
    identity = CheckpointIdentity(
        analysis_id="analysis-v8",
        workspace_id="workspace-v8",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    v4_plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    v5_plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v5"})
    v6_plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v6"})
    v7_plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v7"})
    v8_plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v8"})
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    parent = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_scope_fingerprint="scope-v8",
        surface_enrichment_plan_ref=v4_plan_ref,
        surface_enrichment_v5_plan_ref=v5_plan_ref,
        surface_enrichment_v6_plan_ref=v6_plan_ref,
        surface_enrichment_v7_plan_ref=v7_plan_ref,
        python_scope_certificate_ref=certificate_ref,
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash="b" * 64,
            scope_fingerprint="scope-v8",
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_index_hash="c" * 64,
            surface_coverage_hash="d" * 64,
            surface_proof_version=5,
            scope_certificate_hash=certificate_ref.content_hash,
        ),
    )
    return parent, artifacts, v8_plan_ref


def test_v8_model_accepts_new_pointer_and_proof_version(tmp_path: Path) -> None:
    parent, _artifacts, v8_plan_ref = _parent_run(tmp_path)
    payload = parent.model_dump()
    payload["surface_enrichment_v8_plan_ref"] = v8_plan_ref.model_dump(mode="json")
    payload["candidate_terminal"]["surface_proof_version"] = 6

    saved = SimpleAnalysisRun.model_validate(payload)

    assert saved.surface_enrichment_v8_plan_ref == v8_plan_ref
    assert saved.candidate_terminal is not None
    assert saved.candidate_terminal.surface_proof_version == 6


def test_v8_model_rejects_missing_v7_parent(tmp_path: Path) -> None:
    parent, _artifacts, v8_plan_ref = _parent_run(tmp_path)
    payload = parent.model_dump()
    payload["surface_enrichment_v7_plan_ref"] = None
    payload["surface_enrichment_v8_plan_ref"] = v8_plan_ref.model_dump(mode="json")

    with pytest.raises(ValidationError, match="SURFACE_ENRICHMENT_V8_STATE_UNBOUND"):
        SimpleAnalysisRun.model_validate(payload)


def _pin_case(
    tmp_path: Path, *, complete_v7: bool = True
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    CheckpointIdentity,
    SimpleAnalysisRun,
    StoredDataRef,
    str,
]:
    parent, artifacts, _unused_v8_ref = _parent_run(tmp_path)
    identity = CheckpointIdentity(
        analysis_id=parent.analysis_id,
        workspace_id=parent.workspace_id,
        commit_id=parent.commit_id,
        hypothesis_id=None,
    )
    store = SimpleCheckpointStore(
        tmp_path / "ledger.sqlite3", artifact_data_dir=tmp_path / "data"
    )
    index_ref = artifacts.put_json({"kind": "simple_attack_surface_index_v2"})
    coverage_ref = artifacts.put_json({"kind": "simple_surface_coverage_v5"})
    context_hash = "e" * 64
    source_sha256 = "f" * 64
    assert parent.surface_enrichment_v6_plan_ref is not None
    v7_part = {
        "surface_id": "surface-v8",
        "context_id": "context-v7",
        "context_hash": context_hash,
        "source_sha256": source_sha256,
        "part_index": 0,
        "part_count": 1,
        "target_path_id": "path-v7",
    }
    v7_plan_ref = artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v7",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "scope": "candidate",
            "scope_fingerprint": "scope-v8",
            "static_bundle_hash": "b" * 64,
            "index_ref": index_ref.model_dump(mode="json"),
            "index_hash": index_ref.content_hash,
            "prior_v6_plan_ref": parent.surface_enrichment_v6_plan_ref.model_dump(
                mode="json"
            ),
            "prior_v6_plan_hash": parent.surface_enrichment_v6_plan_ref.content_hash,
            "expected_parts": [v7_part],
        }
    )
    assert parent.candidate_terminal is not None
    parent = parent.model_copy(
        update={
            "surface_enrichment_v7_plan_ref": v7_plan_ref,
            "candidate_terminal": parent.candidate_terminal.model_copy(
                update={
                    "surface_index_hash": index_ref.content_hash,
                    "surface_coverage_hash": coverage_ref.content_hash,
                }
            ),
        }
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
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v7"})
    progress_rows: list[dict[str, object]] = []
    if complete_v7:
        assert store.commit_surface_exploration(
            identity,
            "scope-v8",
            "surface-v8",
            "context-v7",
            static_bundle_hash="b" * 64,
            index_hash=index_ref.content_hash,
            context_hash=context_hash,
            source_sha256=source_sha256,
            status="NO_HYPOTHESIS",
            result_ref=result_ref,
            registrations=(),
            proposal_version=7,
        )
        progress_rows.append(
            {
                "surface_id": "surface-v8",
                "context_id": "context-v7",
                "static_bundle_hash": "b" * 64,
                "index_hash": index_ref.content_hash,
                "context_hash": context_hash,
                "source_sha256": source_sha256,
                "status": "NO_HYPOTHESIS",
                "proposal_version": 7,
                "result_ref": result_ref.model_dump(mode="json"),
                "hypothesis_ids": [],
            }
        )
    progress_hash = hashlib.sha256(canonical_bytes(progress_rows)).hexdigest()
    plan_ref = artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v8",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "scope": "candidate",
            "scope_fingerprint": "scope-v8",
            "graph_semantics_revision": "v5-source-bound-5",
            "static_bundle_hash": "b" * 64,
            "index_ref": index_ref.model_dump(mode="json"),
            "index_hash": index_ref.content_hash,
            "prior_v7_plan_ref": v7_plan_ref.model_dump(mode="json"),
            "prior_v7_plan_hash": v7_plan_ref.content_hash,
            "prior_v5_coverage_ref": coverage_ref.model_dump(mode="json"),
            "prior_v5_coverage_hash": coverage_ref.content_hash,
            "prior_progress_hash": progress_hash,
            "missing_v7_parts": [],
            "target_surface_ids": ["surface-v8"],
            "targets": [],
            "expected_parts": [],
        }
    )
    return store, artifacts, identity, parent, plan_ref, progress_hash


def test_v8_pin_is_idempotent_and_preserves_v7_parent(tmp_path: Path) -> None:
    store, _artifacts, _identity, parent, plan_ref, progress_hash = _pin_case(tmp_path)

    assert store.pin_surface_enrichment_v8_plan(parent, plan_ref, progress_hash)
    saved = store.require_analysis_run(parent.analysis_id)
    assert saved.surface_enrichment_v8_plan_ref == plan_ref
    assert saved.surface_enrichment_v7_plan_ref == parent.surface_enrichment_v7_plan_ref
    assert saved.candidate_terminal == parent.candidate_terminal
    assert not store.pin_surface_enrichment_v8_plan(parent, plan_ref, progress_hash)


def test_v8_pin_rejects_incomplete_v7_parent(tmp_path: Path) -> None:
    store, _artifacts, _identity, parent, plan_ref, progress_hash = _pin_case(
        tmp_path, complete_v7=False
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V8_PIN"):
        store.pin_surface_enrichment_v8_plan(parent, plan_ref, progress_hash)


def test_v8_progress_requires_pin_and_replays_exactly(tmp_path: Path) -> None:
    store, artifacts, identity, parent, plan_ref, progress_hash = _pin_case(tmp_path)
    terminal = parent.candidate_terminal
    assert terminal is not None
    index_hash = terminal.surface_index_hash
    assert index_hash is not None
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v8"})

    def commit() -> bool:
        return store.commit_surface_exploration(
            identity,
            "scope-v8",
            "surface-v8",
            "context-v8",
            static_bundle_hash="b" * 64,
            index_hash=index_hash,
            context_hash="3" * 64,
            source_sha256="f" * 64,
            status="NO_HYPOTHESIS",
            result_ref=result_ref,
            registrations=(),
            proposal_version=8,
        )

    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_V8_UNPINNED"):
        commit()
    assert store.pin_surface_enrichment_v8_plan(parent, plan_ref, progress_hash)
    assert commit()
    saved = store.list_surface_exploration_progress(identity, "scope-v8")
    assert saved[("surface-v8", "context-v8")].proposal_version == 8
    assert not commit()
    assert not store.pin_surface_enrichment_v8_plan(parent, plan_ref, progress_hash)


def test_v8_pin_rejects_changed_root_and_progress(tmp_path: Path) -> None:
    store, artifacts, identity, parent, plan_ref, progress_hash = _pin_case(tmp_path)
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    different_coverage = artifacts.put_json({"kind": "changed-v5-coverage"})
    store.save_checkpoint(
        root.model_copy(
            update={"output_refs": (root.output_refs[0], different_coverage)}
        )
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V8_PIN_STALE"):
        store.pin_surface_enrichment_v8_plan(parent, plan_ref, progress_hash)

    (
        another_store,
        another_artifacts,
        another_identity,
        another_parent,
        another_plan,
        another_hash,
    ) = _pin_case(tmp_path / "progress")
    extra_result = another_artifacts.put_json(
        {"kind": "simple_surface_hypothesis_result_v6"}
    )
    assert another_store.commit_surface_exploration(
        another_identity,
        "scope-v8",
        "unrelated-surface",
        "context-v6",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="4" * 64,
        source_sha256="f" * 64,
        status="NO_HYPOTHESIS",
        result_ref=extra_result,
        registrations=(),
        proposal_version=6,
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V8_PIN_STALE"):
        another_store.pin_surface_enrichment_v8_plan(
            another_parent, another_plan, another_hash
        )


@pytest.mark.parametrize(
    ("changed_key", "changed_value"),
    [
        ("graph_semantics_revision", "v5-source-bound-4"),
        ("missing_v7_parts", [{"surface_id": "surface-v8"}]),
        ("prior_v5_coverage_hash", "0" * 64),
    ],
)
def test_v8_pin_rejects_changed_plan_binding(
    tmp_path: Path, changed_key: str, changed_value: object
) -> None:
    store, artifacts, _identity, parent, plan_ref, progress_hash = _pin_case(tmp_path)
    altered = json.loads(artifacts.read(plan_ref))
    altered[changed_key] = changed_value
    changed_ref = artifacts.put_json(altered)

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V8_PIN"):
        store.pin_surface_enrichment_v8_plan(parent, changed_ref, progress_hash)


def test_v8_pin_requires_partial_proof_five(tmp_path: Path) -> None:
    store, _artifacts, _identity, parent, plan_ref, progress_hash = _pin_case(tmp_path)
    assert parent.candidate_terminal is not None
    changed = parent.model_copy(
        update={
            "candidate_terminal": parent.candidate_terminal.model_copy(
                update={"surface_proof_version": 4}
            )
        }
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V8_PIN_INVALID"):
        store.pin_surface_enrichment_v8_plan(changed, plan_ref, progress_hash)


def _v9_pin_case(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore, CheckpointIdentity, SimpleAnalysisRun, StoredDataRef, str
]:
    store, artifacts, identity, parent, v8_ref, v7_hash = _pin_case(tmp_path)
    assert store.pin_surface_enrichment_v8_plan(parent, v8_ref, v7_hash)
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    coverage_ref = artifacts.put_json({"kind": "simple_surface_coverage_v6"})
    store.save_checkpoint(
        root.model_copy(update={"output_refs": (root.output_refs[0], coverage_ref)})
    )
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.candidate_terminal is not None
    updated = saved.model_copy(
        update={
            "candidate_terminal": saved.candidate_terminal.model_copy(
                update={
                    "surface_proof_version": 6,
                    "surface_coverage_hash": coverage_ref.content_hash,
                }
            )
        }
    )
    store.save_analysis_run(updated)
    v8_hash = prior_v8_progress_snapshot_hash(
        store.list_surface_exploration_progress(identity, "scope-v8")
    )
    binding = {
        "kind": "simple_surface_enrichment_binding_v9",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": "candidate",
        "scope_fingerprint": "scope-v8",
        "static_bundle_hash": "b" * 64,
        "index_ref": root.output_refs[0].model_dump(mode="json"),
        "index_hash": root.output_refs[0].content_hash,
        "prior_v8_plan_ref": v8_ref.model_dump(mode="json"),
        "prior_v8_coverage_ref": coverage_ref.model_dump(mode="json"),
        "prior_v8_progress_hash": v8_hash,
        "targets": [],
    }
    plan_ref = artifacts.put_json(
        {
            **binding,
            "kind": "simple_surface_enrichment_plan_v9",
            "plan_binding_hash": hashlib.sha256(canonical_bytes(binding)).hexdigest(),
            "expected_parts": [
                {
                    "surface_id": "surface-v8",
                    "context_id": "context-v9",
                    "context_hash": "3" * 64,
                    "context_part": {"source_sha256": "f" * 64},
                }
            ],
        }
    )
    return store, identity, updated, plan_ref, v8_hash


def test_v9_pin_is_idempotent_and_preserves_v8_parent(tmp_path: Path) -> None:
    store, _identity, parent, plan_ref, v8_hash = _v9_pin_case(tmp_path)

    assert store.pin_surface_enrichment_v9_plan(parent, plan_ref, v8_hash)
    saved = store.require_analysis_run(parent.analysis_id)
    assert saved.surface_enrichment_v9_plan_ref == plan_ref
    assert saved.surface_enrichment_v8_plan_ref == parent.surface_enrichment_v8_plan_ref
    assert saved.candidate_terminal == parent.candidate_terminal
    assert not store.pin_surface_enrichment_v9_plan(parent, plan_ref, v8_hash)


def test_v9_pin_rejects_changed_v8_progress(tmp_path: Path) -> None:
    store, identity, parent, plan_ref, v8_hash = _v9_pin_case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v8"})
    assert store.commit_surface_exploration(
        identity,
        "scope-v8",
        "extra-surface",
        "extra-context",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="e" * 64,
        source_sha256="f" * 64,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=(),
        proposal_version=8,
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V9_PIN_STALE"):
        store.pin_surface_enrichment_v9_plan(parent, plan_ref, v8_hash)


def test_v9_progress_requires_exact_plan_part_and_replays(tmp_path: Path) -> None:
    store, identity, parent, plan_ref, v8_hash = _v9_pin_case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    assert parent.candidate_terminal is not None
    index_hash = parent.candidate_terminal.surface_index_hash
    assert index_hash is not None
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v9"})

    def commit(context_id: str, context_hash: str) -> bool:
        return store.commit_surface_exploration(
            identity,
            "scope-v8",
            "surface-v8",
            context_id,
            static_bundle_hash="b" * 64,
            index_hash=index_hash,
            context_hash=context_hash,
            source_sha256="f" * 64,
            status="NO_HYPOTHESIS",
            result_ref=result_ref,
            registrations=(),
            proposal_version=9,
        )

    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_V9_UNPINNED"):
        commit("context-v9", "3" * 64)
    assert store.pin_surface_enrichment_v9_plan(parent, plan_ref, v8_hash)
    assert commit("context-v9", "3" * 64)
    assert not commit("context-v9", "3" * 64)
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_V9_PLAN_MISMATCH"):
        commit("not-planned", "3" * 64)
