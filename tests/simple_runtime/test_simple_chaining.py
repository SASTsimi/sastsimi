from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.chaining import SimpleChainingStage
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _identity(hypothesis_id: str) -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=hypothesis_id,
    )


class _Client:
    def __init__(self, upstream: str, downstream: str) -> None:
        self._upstream = upstream
        self._downstream = downstream

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult:
        del prompt, output_schema, timeout_ms, agent_name
        return SimpleLLMCallResult(
            value={
                "children": [
                    {
                        "upstream_primitive_hash": self._upstream,
                        "downstream_primitive_hash": self._downstream,
                        "title": "Authentication bypass to admin action",
                        "vulnerability_type": "CHAINED_AUTHZ",
                        "summary": "session capability reaches admin action",
                        "rationale": "provided capability satisfies requirement",
                        "code_locations": ["app.py:10", "admin.py:20"],
                    }
                ]
            },
            prompt_digest="prompt",
            output_digest="output",
        )


def _primitive(
    artifacts: SimpleArtifactRepository,
    hypothesis_id: str,
    *,
    required: tuple[str, ...],
    provided: tuple[str, ...],
) -> StoredDataRef:
    return artifacts.put_json(
        {
            "kind": "simple_primitive",
            "source_hypothesis_id": hypothesis_id,
            "required_capabilities": required,
            "provided_capabilities": provided,
        }
    )


@pytest.mark.asyncio
async def test_exact_primitives_create_one_material_child(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    first_identity = _identity("hypothesis-a")
    second_identity = _identity("hypothesis-b")
    artifacts = SimpleArtifactRepository(tmp_path, first_identity)
    upstream = _primitive(
        artifacts,
        "hypothesis-a",
        required=(),
        provided=("authenticated-session",),
    )
    downstream = _primitive(
        artifacts,
        "hypothesis-b",
        required=("authenticated-session",),
        provided=("admin-action",),
    )
    for identity, primitive in (
        (first_identity, upstream),
        (second_identity, downstream),
    ):
        checkpoint = StageCheckpoint(
            identity=identity,
            stage=SimpleStage.PRIMITIVE_ADMISSION_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(primitive,),
        )
        store.save_checkpoint(checkpoint)
    current = StageCheckpoint(
        identity=second_identity,
        stage=SimpleStage.CHAINING_DONE,
        status=StageStatus.RUNNING,
        input_refs=(downstream,),
        input_hash=input_reference_hash((downstream,)),
        attempt_id="attempt-1",
    )

    result = await SimpleChainingStage(
        store=store,
        client=_Client(upstream.content_hash, downstream.content_hash),
        artifacts=SimpleArtifactRepository(tmp_path, second_identity),
    )(current, {})

    value = json.loads(artifacts.read(result.output_refs[0]))
    assert value["status"] == "MATERIAL_CHILD"
    assert len(value["considered_primitive_refs"]) == 2
    assert value["children"][0]["parent_hypothesis_ids"] == [
        "hypothesis-a",
        "hypothesis-b",
    ]


@pytest.mark.asyncio
async def test_unknown_primitive_reference_never_registers_child(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = _identity("hypothesis-a")
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    first = _primitive(
        artifacts,
        "hypothesis-a",
        required=("x",),
        provided=("y",),
    )
    second = _primitive(
        artifacts,
        "hypothesis-b",
        required=("y",),
        provided=("z",),
    )
    for index, primitive in enumerate((first, second)):
        current_identity = _identity(f"hypothesis-{index}")
        store.save_checkpoint(
            StageCheckpoint(
                identity=current_identity,
                stage=SimpleStage.PRIMITIVE_ADMISSION_DONE,
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(primitive,),
            )
        )
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.CHAINING_DONE,
        status=StageStatus.RUNNING,
        input_refs=(first,),
        input_hash=input_reference_hash((first,)),
        attempt_id="attempt-1",
    )

    result = await SimpleChainingStage(
        store=store,
        client=_Client("f" * 64, second.content_hash),
        artifacts=artifacts,
    )(current, {})

    value = json.loads(artifacts.read(result.output_refs[0]))
    assert value["status"] == "NO_MATERIAL_CHILD"
    assert value["children"] == []
