"""The final chaining pass covers the exact admitted primitive pool."""

from __future__ import annotations

import json
from dataclasses import replace
from itertools import combinations
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.chaining import SimpleChainingStage
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _ChainClient:
    def __init__(self, children: list[dict[str, JsonValue]] | None = None) -> None:
        self.children = children or []
        self.contexts: list[dict[str, Any]] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        prompt = kwargs["prompt"]
        context = prompt.split(b"<UNTRUSTED_EXACT_INPUTS>\n", 1)[1].split(
            b"\n</UNTRUSTED_EXACT_INPUTS>", 1
        )[0]
        self.contexts.append(json.loads(context))
        return SimpleLLMCallResult(
            value={"children": cast(JsonValue, self.children)},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


def _admit(
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    identity: CheckpointIdentity,
    hypothesis_id: str,
    *,
    provided: tuple[str, ...] = ("read",),
    required: tuple[str, ...] = ("read",),
    stage_version: str | None = None,
    description: str = "",
) -> StoredDataRef:
    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
    if identity == _identity():
        store.upsert_hypothesis(identity, hypothesis_id)
    ref = artifacts.put_json(
        {
            "kind": "simple_primitive",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "source_hypothesis_id": hypothesis_id,
            "required_capabilities": required,
            "provided_capabilities": provided,
            "description": description,
        }
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.PRIMITIVE_ADMISSION_DONE,
            stage_version=stage_version
            or STAGE_VERSION[SimpleStage.PRIMITIVE_ADMISSION_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(ref,),
        )
    )
    return ref


def _stage(
    tmp_path: Path,
    client: _ChainClient,
) -> tuple[SimpleChainingStage, SimpleCheckpointStore, SimpleArtifactRepository]:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    return (
        SimpleChainingStage(store=store, client=client, artifacts=artifacts),
        store,
        artifacts,
    )


@pytest.mark.asyncio
async def test_final_chain_uses_new_primitive_pool_without_speculative_inputs(
    tmp_path: Path,
) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    upstream = _admit(store, artifacts, root, "upstream", required=())
    speculative = artifacts.put_json(
        {"kind": "simple_primitive", "source_hypothesis_id": "speculative"}
    )
    foreign_root = root.model_copy(update={"workspace_id": "other-workspace"})
    foreign_artifacts = SimpleArtifactRepository(tmp_path, foreign_root)
    _admit(store, foreign_artifacts, foreign_root, "foreign")

    first_fingerprint = stage.pool_fingerprint(root)
    first = await stage.finalize_chaining_for_pool(root, first_fingerprint)
    first_result = json.loads(artifacts.read(first.output_refs[0]))
    assert first_result["status"] == "NO_MATERIAL_CHILD"
    assert first_result["considered_primitive_refs"] == [
        upstream.model_dump(mode="json")
    ]
    assert client.contexts == []

    downstream = _admit(store, artifacts, root, "downstream", provided=())
    client.children = [
        {
            "upstream_primitive_hash": upstream.content_hash,
            "downstream_primitive_hash": downstream.content_hash,
            "title": "Combined access",
            "vulnerability_type": "CHAIN",
            "summary": "A read capability feeds the downstream primitive",
            "rationale": "The exact capability intersects",
            "code_locations": ["module.py:1"],
        }
    ]
    second_fingerprint = stage.pool_fingerprint(root)
    assert second_fingerprint != first_fingerprint
    with pytest.raises(ValueError, match="CHAINING_POOL_FINGERPRINT_STALE"):
        await stage.finalize_chaining_for_pool(root, first_fingerprint)

    second = await stage.finalize_chaining_for_pool(root, second_fingerprint)
    second_result = json.loads(artifacts.read(second.output_refs[0]))
    assert second_result["status"] == "MATERIAL_CHILD"
    assert len(second_result["children"]) == 1
    assert second_result["pool_fingerprint"] == second_fingerprint
    assert {
        item["content_hash"] for item in second_result["considered_primitive_refs"]
    } == {
        upstream.content_hash,
        downstream.content_hash,
    }
    assert speculative.content_hash not in {
        item["content_hash"] for item in second_result["considered_primitive_refs"]
    }
    assert len(client.contexts) == 1


@pytest.mark.asyncio
async def test_chaining_never_silently_truncates_model_children(tmp_path: Path) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    upstream = _admit(store, artifacts, root, "upstream-overflow", required=())
    downstream = _admit(store, artifacts, root, "downstream-overflow", provided=())
    client.children = [
        {
            "upstream_primitive_hash": upstream.content_hash,
            "downstream_primitive_hash": downstream.content_hash,
            "title": f"Path {number}",
            "vulnerability_type": "CHAIN",
            "summary": "Material path",
            "rationale": "Capability intersects",
            "code_locations": ["module.py:1"],
        }
        for number in range(5)
    ]

    with pytest.raises(ValueError, match="CHAINING_CHILD_LIMIT_EXCEEDED"):
        await stage.finalize_chaining_for_pool(root, stage.pool_fingerprint(root))


@pytest.mark.parametrize("invalid_kind", ("unknown", "self", "incompatible"))
@pytest.mark.asyncio
async def test_final_chain_rejects_invalid_child_as_unverified_batch(
    tmp_path: Path,
    invalid_kind: str,
) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    upstream = _admit(
        store,
        artifacts,
        root,
        "valid-upstream",
        required=(),
        provided=() if invalid_kind == "incompatible" else ("read",),
    )
    downstream = _admit(store, artifacts, root, "valid-downstream", provided=())
    downstream_hash = {
        "unknown": "f" * 64,
        "self": upstream.content_hash,
        "incompatible": downstream.content_hash,
    }[invalid_kind]
    client.children = [
        {
            "upstream_primitive_hash": upstream.content_hash,
            "downstream_primitive_hash": downstream_hash,
            "title": "Invalid primitive pair",
            "vulnerability_type": "CHAIN",
            "summary": "Invalid",
            "rationale": "Invalid downstream relationship",
            "code_locations": ["module.py:1"],
        }
    ]

    with pytest.raises(StageBlocked) as captured:
        await stage.finalize_chaining_for_pool(root, stage.pool_fingerprint(root))
    assert captured.value.failure.code == "CHAINING_BATCH_RESPONSE_INVALID"


@pytest.mark.asyncio
async def test_final_chain_never_certifies_saturated_child_response(
    tmp_path: Path,
) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    upstream = _admit(store, artifacts, root, "saturated-upstream", required=())
    downstream = _admit(store, artifacts, root, "saturated-downstream", provided=())
    client.children = [
        {
            "upstream_primitive_hash": upstream.content_hash,
            "downstream_primitive_hash": downstream.content_hash,
            "title": f"Path {number}",
            "vulnerability_type": "CHAIN",
            "summary": "Potential material path",
            "rationale": "Capability intersection",
            "code_locations": ["module.py:1"],
        }
        for number in range(4)
    ]

    with pytest.raises(StageBlocked) as captured:
        await stage.finalize_chaining_for_pool(root, stage.pool_fingerprint(root))
    assert captured.value.failure.code == "CHAINING_BATCH_SATURATED"


@pytest.mark.asyncio
async def test_final_chain_rejects_pair_outside_its_partition(tmp_path: Path) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    for index in range(65):
        _admit(store, artifacts, root, f"partition-child-{index:03d}")
    plan = stage.plan_chaining_for_pool(root, stage.pool_fingerprint(root))
    cross = next(batch for batch in plan if not batch.same_block)
    first, second = cross.left_primitive_refs[:2]
    client.children = [
        {
            "upstream_primitive_hash": first.content_hash,
            "downstream_primitive_hash": second.content_hash,
            "title": "Wrong partition",
            "vulnerability_type": "CHAIN",
            "summary": "Both are on the same side",
            "rationale": "This pair belongs to another partition",
            "code_locations": ["module.py:1"],
        }
    ]

    with pytest.raises(StageBlocked) as captured:
        await stage.finalize_chaining_batch(root, cross)
    assert captured.value.failure.code == "CHAINING_BATCH_RESPONSE_INVALID"


@pytest.mark.asyncio
async def test_final_chain_covers_every_pair_beyond_sixty_four_refs(
    tmp_path: Path,
) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    admitted = tuple(
        _admit(
            store,
            artifacts,
            root,
            f"hypothesis-{index:03d}",
            description="x" * 4100,
        )
        for index in range(70)
    )

    result = await stage.finalize_chaining_for_pool(root, stage.pool_fingerprint(root))
    outputs = [json.loads(artifacts.read(ref)) for ref in result.output_refs]
    admitted_hashes = {ref.content_hash for ref in admitted}
    considered_sets = [
        {item["content_hash"] for item in output["considered_primitive_refs"]}
        for output in outputs
    ]

    assert len(admitted_hashes) == 70
    assert len(outputs) > 1
    assert all(len(considered) <= 64 for considered in considered_sets)
    assert all(
        considered
        | {item["content_hash"] for item in output["unconsidered_primitive_refs"]}
        == admitted_hashes
        for considered, output in zip(considered_sets, outputs, strict=True)
    )
    assert all(
        any({left, right} <= considered for considered in considered_sets)
        for left, right in combinations(admitted_hashes, 2)
    )
    assert all(len(context["exact_inputs"]) <= 64 for context in client.contexts)


@pytest.mark.asyncio
async def test_final_chain_redacts_primitive_content_without_losing_the_pair(
    tmp_path: Path,
) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    first = _admit(
        store,
        artifacts,
        root,
        "first",
        description="api_key=supersecret123",
    )
    second = _admit(
        store,
        artifacts,
        root,
        "second",
        description="api_key=othersecret456",
    )
    client.children = [
        {
            "upstream_primitive_hash": first.content_hash,
            "downstream_primitive_hash": second.content_hash,
            "title": "Combined access",
            "vulnerability_type": "CHAIN",
            "summary": "A read capability feeds the downstream primitive",
            "rationale": "The exact capability intersects",
            "code_locations": ["module.py:1"],
        }
    ]

    result = await stage.finalize_chaining_for_pool(root, stage.pool_fingerprint(root))

    value = json.loads(artifacts.read(result.output_refs[0]))
    assert len(value["children"]) == 1
    assert len(client.contexts[0]["exact_inputs"]) == 2
    assert b"supersecret123" not in json.dumps(client.contexts).encode()
    assert b"othersecret456" not in json.dumps(client.contexts).encode()


@pytest.mark.asyncio
async def test_final_chain_batches_can_resume_without_repeating_completed_calls(
    tmp_path: Path,
) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    admitted = tuple(
        _admit(store, artifacts, root, f"hypothesis-{index:03d}") for index in range(65)
    )
    fingerprint = stage.pool_fingerprint(root)

    plan = stage.plan_chaining_for_pool(root, fingerprint)

    assert len(plan) > 1
    assert client.contexts == []
    assert tuple(batch.batch_index for batch in plan) == tuple(range(len(plan)))
    assert {batch.batch_count for batch in plan} == {len(plan)}
    assert {batch.pool_fingerprint for batch in plan} == {fingerprint}
    assert all(
        set(batch.considered_primitive_refs + batch.unconsidered_primitive_refs)
        == set(admitted)
        for batch in plan
    )

    first = await stage.finalize_chaining_batch(root, plan[0])
    first_result = json.loads(artifacts.read(first.output_refs[0]))
    assert first_result["batch_index"] == 0
    assert len(client.contexts) == 1

    resumed_client = _ChainClient()
    resumed = SimpleChainingStage(
        store=store,
        client=resumed_client,
        artifacts=artifacts,
    )
    assert resumed.plan_chaining_for_pool(root, fingerprint) == plan
    second = await resumed.finalize_chaining_batch(root, plan[1])
    second_result = json.loads(artifacts.read(second.output_refs[0]))
    assert second_result["batch_index"] == 1
    assert len(resumed_client.contexts) == 1

    with pytest.raises(ValueError, match="CHAINING_POOL_BATCH_STALE"):
        await resumed.finalize_chaining_batch(
            root,
            replace(plan[1], batch_index=0),
        )
    assert len(resumed_client.contexts) == 1

    _admit(store, artifacts, root, "new-primitive")
    with pytest.raises(ValueError, match="CHAINING_POOL_FINGERPRINT_STALE"):
        await resumed.finalize_chaining_batch(root, plan[2])
    assert len(resumed_client.contexts) == 1


@pytest.mark.asyncio
async def test_final_chain_does_not_replan_entire_pool_per_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    for index in range(65):
        _admit(store, artifacts, root, f"cached-plan-{index:03d}")
    original = stage._bounded_pair_partitions
    calls = 0

    def counted(admitted: tuple[StoredDataRef, ...]) -> Any:
        nonlocal calls
        calls += 1
        return original(admitted)

    monkeypatch.setattr(stage, "_bounded_pair_partitions", counted)
    plan = stage.plan_chaining_for_pool(root, stage.pool_fingerprint(root))
    assert len(plan) > 1
    await stage.finalize_chaining_batch(root, plan[0])
    await stage.finalize_chaining_batch(root, plan[1])
    assert calls == 1


def test_final_chain_plan_rejects_irreducibly_oversized_pair(tmp_path: Path) -> None:
    client = _ChainClient()
    stage, store, artifacts = _stage(tmp_path, client)
    root = _identity()
    _admit(store, artifacts, root, "first", description="x" * 180_000)
    _admit(store, artifacts, root, "second", description="y" * 180_000)

    with pytest.raises(ValueError, match="CHAINING_PAIR_CONTEXT_TOO_LARGE"):
        stage.plan_chaining_for_pool(root, stage.pool_fingerprint(root))
    assert client.contexts == []
