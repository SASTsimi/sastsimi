"""Version 2 chaining must use the durable child queue, not the legacy cap."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from sastsimi.simple_runtime.application import (
    HypothesisBootstrap,
    SimpleAnalysisApplication,
    StaticBootstrap,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.chaining import ChainingPoolBatch
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def test_v2_chain_child_is_registered_beyond_legacy_32_limit(tmp_path: Path) -> None:
    root = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    data = tmp_path / "data"
    store = SimpleCheckpointStore(data / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(data, root)
    static_ref = artifacts.put_json({"kind": "simple_static_fact_bundle"})
    static = StaticBootstrapResult(
        repository_profile_ref=artifacts.put_json({"kind": "profile"}),
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )
    run = SimpleAnalysisRun(
        analysis_id=root.analysis_id,
        display_analysis_id="A-001",
        workspace_id=root.workspace_id,
        commit_id=root.commit_id,
        repository="https://github.com/example/repo",
        candidate_pipeline_version=2,
    )
    store.save_analysis_run(run)
    for number in range(32):
        hypothesis_id = f"hypothesis-{number:02d}"
        child = root.model_copy(update={"hypothesis_id": hypothesis_id})
        proposal = artifacts.put_json({"hypothesis_id": hypothesis_id})
        inputs = (proposal, static_ref)
        store.register_free_hypothesis(
            root,
            hypothesis_id,
            proposal,
            StageCheckpoint(
                identity=child,
                stage=SimpleStage.PRO_CON_DONE,
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
            ),
        )
    primitive_refs = []
    for hypothesis_id in ("hypothesis-00", "hypothesis-01"):
        child = root.model_copy(update={"hypothesis_id": hypothesis_id})
        primitive = artifacts.put_json(
            {
                "kind": "simple_primitive",
                "analysis_id": root.analysis_id,
                "workspace_id": root.workspace_id,
                "commit_id": root.commit_id,
                "source_hypothesis_id": hypothesis_id,
            }
        )
        primitive_refs.append(primitive)
        store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=SimpleStage.PRIMITIVE_ADMISSION_DONE,
                stage_version=STAGE_VERSION[SimpleStage.PRIMITIVE_ADMISSION_DONE],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(primitive,),
            )
        )
    upstream, downstream = primitive_refs
    parent = root.model_copy(update={"hypothesis_id": "hypothesis-00"})
    result = artifacts.put_json(
        {
            "kind": "simple_chaining_result",
            "analysis_id": root.analysis_id,
            "source_hypothesis_id": parent.hypothesis_id,
            "considered_primitive_refs": [
                ref.model_dump(mode="json") for ref in primitive_refs
            ],
            "status": "MATERIAL_CHILD",
            "children": [
                {
                    "upstream_primitive_hash": upstream.content_hash,
                    "downstream_primitive_hash": downstream.content_hash,
                    "title": "Composed path",
                    "vulnerability_type": "TEST",
                    "summary": "A reaches B",
                    "rationale": "Material connection",
                    "code_locations": ["app.py:1"],
                    "parent_hypothesis_ids": ["hypothesis-00", "hypothesis-01"],
                    "parent_primitive_refs": [
                        ref.model_dump(mode="json") for ref in primitive_refs
                    ],
                }
            ],
        }
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=parent,
            stage=SimpleStage.CHAINING_DONE,
            stage_version=STAGE_VERSION[SimpleStage.CHAINING_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(result,),
        )
    )
    app = SimpleAnalysisApplication(
        data_dir=data,
        store=store,
        static_bootstrap=cast(StaticBootstrap, object()),
        hypothesis_bootstrap=cast(HypothesisBootstrap, object()),
        runner_factory=lambda *_args: cast(SimpleRuntimeRunner, object()),
    )

    app._register_chain_children(run, parent, static)

    assert store.hypothesis_count(root) == 33
    chain_ids = [
        item
        for item in store.list_hypotheses(root)
        if item.startswith("hypothesis-chain-")
    ]
    assert len(chain_ids) == 1
    assert store.hypothesis_metadata(root, chain_ids[0]) == (
        1,
        ("hypothesis-00", "hypothesis-01"),
    )


@pytest.mark.parametrize("invalid_kind", ("wrong_partition", "incompatible"))
def test_v2_replay_rejects_forged_semantically_invalid_chain_batch(
    tmp_path: Path,
    invalid_kind: str,
) -> None:
    root = CheckpointIdentity(
        analysis_id="analysis-replay",
        workspace_id="workspace-replay",
        commit_id="c" * 40,
        hypothesis_id=None,
    )
    data = tmp_path / "data"
    store = SimpleCheckpointStore(data / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(data, root)
    primitives = tuple(
        artifacts.put_json(
            {
                "kind": "simple_primitive",
                "analysis_id": root.analysis_id,
                "workspace_id": root.workspace_id,
                "commit_id": root.commit_id,
                "source_hypothesis_id": f"parent-{index}",
                "provided_capabilities": ["read"] if index == 0 else [],
                "required_capabilities": ["read"] if index == 1 else ["write"],
            }
        )
        for index in range(3)
    )
    batch = ChainingPoolBatch(
        pool_fingerprint="pool-replay",
        batch_index=0,
        batch_count=1,
        considered_primitive_refs=primitives,
        unconsidered_primitive_refs=(),
        left_primitive_refs=primitives[:2],
        right_primitive_refs=primitives[2:],
        same_block=False,
    )
    downstream = primitives[1] if invalid_kind == "wrong_partition" else primitives[2]
    result = artifacts.put_json(
        {
            "kind": "simple_chaining_result",
            "analysis_id": root.analysis_id,
            "source_hypothesis_id": None,
            "pool_fingerprint": batch.pool_fingerprint,
            "batch_index": batch.batch_index,
            "batch_count": batch.batch_count,
            "considered_primitive_refs": [
                ref.model_dump(mode="json") for ref in primitives
            ],
            "unconsidered_primitive_refs": [],
            "status": "MATERIAL_CHILD",
            "children": [
                {
                    "upstream_primitive_hash": primitives[0].content_hash,
                    "downstream_primitive_hash": downstream.content_hash,
                    "parent_hypothesis_ids": [
                        "parent-0",
                        "parent-1" if invalid_kind == "wrong_partition" else "parent-2",
                    ],
                    "parent_primitive_refs": [
                        primitives[0].model_dump(mode="json"),
                        downstream.model_dump(mode="json"),
                    ],
                }
            ],
        }
    )
    store.save_chaining_pool_batch(root, batch.pool_fingerprint, 0, 1, result)
    persisted = store.list_chaining_pool_batches(root, batch.pool_fingerprint)[0][1]

    with pytest.raises(ValueError, match="CHAINING_POOL_RESULT_INVALID"):
        SimpleAnalysisApplication._chaining_pool_result_valid(
            artifacts, root, batch, primitives, persisted
        )


@pytest.mark.asyncio
async def test_v2_final_pool_reuses_exact_saved_batch_on_resume(tmp_path: Path) -> None:
    root = CheckpointIdentity(
        analysis_id="analysis-2",
        workspace_id="workspace-2",
        commit_id="b" * 40,
        hypothesis_id=None,
    )
    data = tmp_path / "data"
    store = SimpleCheckpointStore(data / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(data, root)
    static = StaticBootstrapResult(
        repository_profile_ref=artifacts.put_json({"kind": "profile"}),
        static_bundle_ref=artifacts.put_json({"kind": "static"}),
        workspace_path=tmp_path,
    )
    run = SimpleAnalysisRun(
        analysis_id=root.analysis_id,
        display_analysis_id="A-002",
        workspace_id=root.workspace_id,
        commit_id=root.commit_id,
        repository="https://github.com/example/repo",
        candidate_pipeline_version=2,
    )
    store.save_analysis_run(run)
    batch = ChainingPoolBatch(
        pool_fingerprint="pool-2",
        batch_index=0,
        batch_count=1,
        considered_primitive_refs=(),
        unconsidered_primitive_refs=(),
        left_primitive_refs=(),
        right_primitive_refs=(),
        same_block=True,
    )

    class FinalPool:
        calls = 0

        def admitted_primitive_refs(self, identity: CheckpointIdentity) -> tuple[()]:
            assert identity == root
            return ()

        def pool_fingerprint(self, identity: CheckpointIdentity) -> str:
            assert identity == root
            return "pool-2"

        def plan_chaining_for_pool(
            self, identity: CheckpointIdentity, fingerprint: str
        ) -> tuple[ChainingPoolBatch, ...]:
            assert identity == root and fingerprint == "pool-2"
            return (batch,)

        async def finalize_chaining_batch(
            self, identity: CheckpointIdentity, planned: ChainingPoolBatch
        ) -> StageResult:
            assert identity == root and planned == batch
            self.calls += 1
            return StageResult(
                output_refs=(
                    artifacts.put_json(
                        {
                            "kind": "simple_chaining_result",
                            "analysis_id": root.analysis_id,
                            "source_hypothesis_id": None,
                            "pool_fingerprint": "pool-2",
                            "batch_index": 0,
                            "batch_count": 1,
                            "considered_primitive_refs": [],
                            "unconsidered_primitive_refs": [],
                            "status": "NO_MATERIAL_CHILD",
                            "children": [],
                        }
                    ),
                )
            )

    stage = FinalPool()

    class Runner:
        handlers = {SimpleStage.CHAINING_DONE: stage}

    app = SimpleAnalysisApplication(
        data_dir=data,
        store=store,
        static_bootstrap=cast(StaticBootstrap, object()),
        hypothesis_bootstrap=cast(HypothesisBootstrap, object()),
        runner_factory=lambda *_args: cast(SimpleRuntimeRunner, Runner()),
    )
    assert (
        await app._run_final_chaining_pool(
            run,
            root,
            static,
            attempted_in_turn=set(),
            turn_id="turn-1",
        )
        is None
    )
    assert store.list_chaining_pool_batches(root, "pool-2")
    assert (
        await app._run_final_chaining_pool(
            run,
            root,
            static,
            attempted_in_turn=set(),
            turn_id="turn-2",
        )
        is None
    )
    assert stage.calls == 1
