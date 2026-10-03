"""A batched Pro/Con call keeps each hypothesis's evidence independent."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypedDict, cast

import pytest
from pydantic import JsonValue

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.stages import ProConBatchBlocked, ProConStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _evidence(hypothesis_id: str, label: str) -> dict[str, JsonValue]:
    return {
        "hypothesis_id": hypothesis_id,
        "claims": [f"{label} for {hypothesis_id}"],
        "evidence_refs": [],
        "limitations": [],
        "requested_paths": [],
    }


class _Call(TypedDict):
    agent_name: str
    prompt: bytes


class _Client:
    def __init__(
        self, responses: Mapping[str, list[list[dict[str, JsonValue]]]]
    ) -> None:
        self.responses = {name: list(items) for name, items in responses.items()}
        self.calls: list[_Call] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.calls.append(
            {"agent_name": kwargs["agent_name"], "prompt": kwargs["prompt"]}
        )
        agent = str(kwargs["agent_name"])
        return SimpleLLMCallResult(
            value=cast(dict[str, JsonValue], {"results": self.responses[agent].pop(0)}),
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _SequentialClient:
    def __init__(self, responses: list[SimpleLLMCallResult | StageFailure]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult | StageFailure:
        self.calls.append(str(kwargs["agent_name"]))
        return self.responses.pop(0)


def _legacy_result(label: str) -> SimpleLLMCallResult:
    return SimpleLLMCallResult(
        value={
            "claims": [label],
            "evidence_refs": [],
            "limitations": [],
            "requested_paths": [],
        },
        prompt_digest="a" * 64,
        output_digest="b" * 64,
    )


def _fixture(
    tmp_path: Path,
) -> tuple[SimpleArtifactRepository, StoredDataRef, dict[str, StageCheckpoint]]:
    identity = CheckpointIdentity(
        analysis_id="analysis-batch",
        workspace_id="workspace-batch",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    shared = artifacts.put_json({"kind": "shared_context", "marker": "one-shared-file"})
    static = artifacts.put_json({"kind": "static_bundle"})
    checkpoints: dict[str, StageCheckpoint] = {}
    for hypothesis_id in ("hypothesis-one", "hypothesis-two"):
        proposal = artifacts.put_prompt_proposal(
            {
                "kind": "simple_hypothesis_proposal",
                "analysis_id": identity.analysis_id,
                "hypothesis_id": hypothesis_id,
                "proposal": {"summary": f"path for {hypothesis_id}"},
            }
        )
        refs = (proposal, static)
        checkpoints[hypothesis_id] = StageCheckpoint(
            identity=identity.model_copy(update={"hypothesis_id": hypothesis_id}),
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.PENDING,
            input_refs=refs,
            input_hash=input_reference_hash(refs),
            attempt_id=f"attempt-{hypothesis_id}",
        )
    return artifacts, shared, checkpoints


@pytest.mark.asyncio
async def test_pro_con_batch_has_exact_independent_ids(tmp_path: Path) -> None:
    """Wrong fan-out or duplicated shared context breaks the evidence contract."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    ids = tuple(checkpoints)
    client = _Client(
        {
            "pro_evidence": [[_evidence(item, "support") for item in ids]],
            "con_evidence": [[_evidence(item, "counter") for item in ids]],
        }
    )
    stage = ProConStage(client, artifacts)

    pro = await stage.run_pro_batch(checkpoints, shared)
    con = await stage.run_con_batch(checkpoints, shared)

    assert set(pro) == set(con) == set(ids)
    assert (
        len([call for call in client.calls if call["agent_name"] == "pro_evidence"])
        == 1
    )
    assert (
        len([call for call in client.calls if call["agent_name"] == "con_evidence"])
        == 1
    )
    assert all(call["prompt"].count(b"one-shared-file") == 1 for call in client.calls)
    assert pro[ids[0]] != pro[ids[1]]
    for role, refs in (("pro", pro), ("con", con)):
        for hypothesis_id, ref in refs.items():
            value = json.loads(artifacts.read(ref))
            assert value["kind"] == f"simple_{role}_evidence"
            assert value["analysis_id"] == "analysis-batch"
            assert value["hypothesis_id"] == hypothesis_id
            assert value["input_hash"] == checkpoints[hypothesis_id].input_hash
            assert value["result"]["claims"] == [
                f"{'support' if role == 'pro' else 'counter'} for {hypothesis_id}"
            ]
            response = json.loads(
                artifacts.read(
                    StoredDataRef.model_validate(value["batch_response_ref"])
                )
            )
            assert response["analysis_id"] == "analysis-batch"
            assert (
                response["input_hashes"][hypothesis_id]
                == checkpoints[hypothesis_id].input_hash
            )


@pytest.mark.asyncio
async def test_pro_batch_retries_only_missing_id(tmp_path: Path) -> None:
    """A partial reply cannot cause completed IDs to be regenerated."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first, second = tuple(checkpoints)
    client = _Client(
        {
            "pro_evidence": [
                [_evidence(first, "support")],
                [_evidence(second, "support")],
            ]
        }
    )

    refs = await ProConStage(client, artifacts).run_pro_batch(checkpoints, shared)

    assert set(refs) == {first, second}
    assert len(client.calls) == 2
    first_prompt = client.calls[0]["prompt"]
    retry_prompt = client.calls[1]["prompt"]
    assert first.encode() in first_prompt and second.encode() in first_prompt
    assert first.encode() not in retry_prompt and second.encode() in retry_prompt


@pytest.mark.asyncio
async def test_pro_batch_checkpoints_first_id_before_retrying_second(
    tmp_path: Path,
) -> None:
    """A process interruption during fan-out must not lose earlier child evidence."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first, second = tuple(checkpoints)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")

    class ObserveRetry(_Client):
        async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
            if self.calls:
                assert (
                    store.get_pro_con_batch_evidence(
                        checkpoints[first].identity,
                        "pro",
                        checkpoints[first].input_hash,
                    )
                    is not None
                )
            return await super().call(**kwargs)

    client = ObserveRetry(
        {
            "pro_evidence": [
                [_evidence(first, "support")],
                [_evidence(second, "support")],
            ]
        }
    )

    refs = await ProConStage(client, artifacts, store=store).run_pro_batch(
        checkpoints, shared
    )

    assert set(refs) == {first, second}


@pytest.mark.asyncio
async def test_pro_batch_rejects_foreign_or_duplicate_id(tmp_path: Path) -> None:
    """One malformed row must not be assigned to another child."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    for rows in (
        [_evidence(first, "support"), _evidence(first, "other")],
        [_evidence("unknown-child", "support")],
    ):
        client = _Client({"pro_evidence": [rows]})
        with pytest.raises(StageBlocked) as captured:
            await ProConStage(client, artifacts).run_pro_batch(checkpoints, shared)
        assert captured.value.failure.code == "PRO_CON_BATCH_RESPONSE_INVALID"


@pytest.mark.asyncio
async def test_pro_batch_rejects_cross_hypothesis_private_evidence(
    tmp_path: Path,
) -> None:
    """A row cannot cite another child's private proposal in the same batch."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first, second = tuple(checkpoints)
    row = _evidence(first, "support")
    row["evidence_refs"] = [checkpoints[second].input_refs[0].content_hash]
    client = _Client({"pro_evidence": [[row]]})

    with pytest.raises(StageBlocked) as captured:
        await ProConStage(client, artifacts).run_pro_batch(checkpoints, shared)

    assert captured.value.failure.code == "PRO_CON_BATCH_RESPONSE_INVALID"


@pytest.mark.asyncio
async def test_pro_batch_rejects_mismatched_proposal_identity(tmp_path: Path) -> None:
    """A checkpoint ID cannot borrow a different proposal's content."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first, second = tuple(checkpoints)
    altered = dict(checkpoints)
    refs = (checkpoints[second].input_refs[0], checkpoints[first].input_refs[1])
    altered[first] = checkpoints[first].model_copy(
        update={"input_refs": refs, "input_hash": input_reference_hash(refs)}
    )
    client = _Client({"pro_evidence": []})

    with pytest.raises(ValueError, match="PRO_CON_BATCH_INPUT_INVALID"):
        await ProConStage(client, artifacts).run_pro_batch(altered, shared)
    assert not client.calls


@pytest.mark.asyncio
async def test_pro_batch_requires_proposals_shared_context(tmp_path: Path) -> None:
    """A caller cannot swap the context referenced by a v2 proposal."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    other = artifacts.put_json({"kind": "shared_context", "marker": "other-file"})
    proposal = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": "analysis-batch",
            "hypothesis_id": first,
            "shared_context_ref": other.model_dump(mode="json"),
            "proposal": {"summary": "path for one child"},
        }
    )
    refs = (proposal, checkpoints[first].input_refs[1])
    changed = checkpoints[first].model_copy(
        update={"input_refs": refs, "input_hash": input_reference_hash(refs)}
    )
    client = _Client({"pro_evidence": []})

    with pytest.raises(ValueError, match="PRO_CON_BATCH_INPUT_INVALID"):
        await ProConStage(client, artifacts).run_pro_batch({first: changed}, shared)
    assert not client.calls


@pytest.mark.asyncio
async def test_v2_proposal_keeps_static_and_shared_context_distinct(
    tmp_path: Path,
) -> None:
    """The shared batch context is the child input, not the root static bundle."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    static = artifacts.put_json({"kind": "simple_static_fact_bundle"})
    proposal = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": "analysis-batch",
            "hypothesis_id": first,
            "static_bundle_ref": static.model_dump(mode="json"),
            "shared_context_ref": shared.model_dump(mode="json"),
            "proposal": {"summary": "v2 candidate"},
        }
    )
    refs = (proposal, shared)
    checkpoint = checkpoints[first].model_copy(
        update={"input_refs": refs, "input_hash": input_reference_hash(refs)}
    )
    client = _Client({"pro_evidence": [[_evidence(first, "support")]]})

    results = await ProConStage(client, artifacts).run_pro_batch(
        {first: checkpoint}, shared
    )

    assert set(results) == {first}
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_pro_batch_reuses_only_matching_existing_evidence(tmp_path: Path) -> None:
    """Resume cannot spend a call on a completed ID or accept stale evidence."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first, second = tuple(checkpoints)
    first_client = _Client({"pro_evidence": [[_evidence(first, "support")]]})
    first_ref = (
        await ProConStage(first_client, artifacts).run_pro_batch(
            {first: checkpoints[first]}, shared
        )
    )[first]
    second_client = _Client({"pro_evidence": [[_evidence(second, "support")]]})
    stage = ProConStage(second_client, artifacts)

    refs = await stage.run_pro_batch(checkpoints, shared, existing={first: first_ref})

    assert refs[first] == first_ref
    assert len(second_client.calls) == 1
    assert first.encode() not in second_client.calls[0]["prompt"]
    assert second.encode() in second_client.calls[0]["prompt"]
    assert await stage.run_pro_batch(checkpoints, shared, existing=refs) == refs
    assert len(second_client.calls) == 1
    with pytest.raises(ValueError, match="PRO_CON_BATCH_EXISTING_INVALID"):
        await stage.run_pro_batch(checkpoints, shared, existing={second: first_ref})


@pytest.mark.asyncio
async def test_pro_batch_rejects_evidence_not_bound_to_batch_row(
    tmp_path: Path,
) -> None:
    """A forged per-ID artifact cannot become a reusable batch completion."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    client = _Client({"pro_evidence": [[_evidence(first, "support")]]})
    stage = ProConStage(client, artifacts)
    genuine = (await stage.run_pro_batch({first: checkpoints[first]}, shared))[first]
    forged = json.loads(artifacts.read(genuine))
    forged["result"]["claims"] = ["invented peer evidence"]
    forged_ref = artifacts.put_json(forged)

    with pytest.raises(ValueError, match="PRO_CON_BATCH_EXISTING_INVALID"):
        await stage.run_pro_batch(
            {first: checkpoints[first]}, shared, existing={first: forged_ref}
        )


@pytest.mark.asyncio
async def test_pro_batch_exhaustion_exposes_completed_refs(tmp_path: Path) -> None:
    """A missing ID stays retryable while valid peer evidence remains usable."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first, second = tuple(checkpoints)
    client = _Client({"pro_evidence": [[_evidence(first, "support")], []]})

    with pytest.raises(ProConBatchBlocked) as captured:
        await ProConStage(client, artifacts).run_pro_batch(checkpoints, shared)

    assert captured.value.failure.code == "PRO_CON_BATCH_INCOMPLETE"
    assert captured.value.missing_ids == (second,)
    assert set(captured.value.completed_refs) == {first}
    assert len(client.calls) == 2
    assert first.encode() not in client.calls[1]["prompt"]


@pytest.mark.asyncio
async def test_pro_batch_rejects_unsafe_requested_path(tmp_path: Path) -> None:
    """The batch boundary rejects a path that cannot be retrieved safely."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    for path in ("../outside.py", "C:/outside.py"):
        unsafe = _evidence(first, "support")
        unsafe["requested_paths"] = [path]
        client = _Client({"pro_evidence": [[unsafe]]})
        with pytest.raises(StageBlocked) as captured:
            await ProConStage(client, artifacts).run_pro_batch(
                {first: checkpoints[first]}, shared
            )
        assert captured.value.failure.code == "PRO_CON_BATCH_RESPONSE_INVALID"


@pytest.mark.asyncio
async def test_pro_batch_rejects_non_hash_evidence_ref(tmp_path: Path) -> None:
    """A free-form citation cannot masquerade as an exact artifact hash."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    invalid = _evidence(first, "support")
    invalid["evidence_refs"] = ["unverified citation"]
    client = _Client({"pro_evidence": [[invalid]]})

    with pytest.raises(StageBlocked) as captured:
        await ProConStage(client, artifacts).run_pro_batch(
            {first: checkpoints[first]}, shared
        )
    assert captured.value.failure.code == "PRO_CON_BATCH_RESPONSE_INVALID"


@pytest.mark.asyncio
async def test_pro_batch_rejects_hash_not_supplied_in_context(tmp_path: Path) -> None:
    """Well-formed but invented hashes are not evidence from exact inputs."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    invalid = _evidence(first, "support")
    invalid["evidence_refs"] = ["f" * 64]
    client = _Client({"pro_evidence": [[invalid]]})

    with pytest.raises(StageBlocked) as captured:
        await ProConStage(client, artifacts).run_pro_batch(
            {first: checkpoints[first]}, shared
        )
    assert captured.value.failure.code == "PRO_CON_BATCH_RESPONSE_INVALID"


@pytest.mark.asyncio
async def test_pro_batch_rejects_hash_occurring_only_in_source_text(
    tmp_path: Path,
) -> None:
    """Untrusted source bytes are not an artifact reference allowlist."""

    artifacts, _shared, checkpoints = _fixture(tmp_path)
    injected = "f" * 64
    shared = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v1",
            "source_lines": [{"text": injected}],
        }
    )
    first = next(iter(checkpoints))
    invalid = _evidence(first, "support")
    invalid["evidence_refs"] = [injected]
    client = _Client({"pro_evidence": [[invalid]]})

    with pytest.raises(StageBlocked) as captured:
        await ProConStage(client, artifacts).run_pro_batch(
            {first: checkpoints[first]}, shared
        )
    assert captured.value.failure.code == "PRO_CON_BATCH_RESPONSE_INVALID"


@pytest.mark.asyncio
async def test_pro_batch_accepts_structured_ast_file_reference(tmp_path: Path) -> None:
    artifacts, _shared, checkpoints = _fixture(tmp_path)
    ast_file = artifacts.put_json({"kind": "ast_file_facts"})
    shared = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v1",
            "ast_file_ref": ast_file.model_dump(mode="json"),
        }
    )
    first = next(iter(checkpoints))
    valid = _evidence(first, "support")
    valid["evidence_refs"] = [ast_file.content_hash]
    client = _Client({"pro_evidence": [[valid]]})

    refs = await ProConStage(client, artifacts).run_pro_batch(
        {first: checkpoints[first]}, shared
    )
    assert json.loads(artifacts.read(refs[first]))["result"]["evidence_refs"] == [
        ast_file.content_hash
    ]


@pytest.mark.asyncio
async def test_pro_batch_reports_combined_context_overflow_for_serial_fallback(
    tmp_path: Path,
) -> None:
    artifacts, _shared, checkpoints = _fixture(tmp_path)
    shared = artifacts.put_json({"kind": "shared_context", "content": "x" * 130_000})
    first, second = tuple(checkpoints)
    enlarged: dict[str, StageCheckpoint] = {}
    for hypothesis_id in (first, second):
        proposal = artifacts.put_prompt_proposal(
            {
                "kind": "simple_hypothesis_proposal",
                "analysis_id": "analysis-batch",
                "hypothesis_id": hypothesis_id,
                "proposal": {"summary": "y" * 70_000},
            }
        )
        refs = (proposal, checkpoints[hypothesis_id].input_refs[1])
        enlarged[hypothesis_id] = checkpoints[hypothesis_id].model_copy(
            update={"input_refs": refs, "input_hash": input_reference_hash(refs)}
        )
    client = _Client({"pro_evidence": []})

    with pytest.raises(ValueError, match="PRO_CON_BATCH_CONTEXT_OVERFLOW"):
        await ProConStage(client, artifacts).run_pro_batch(enlarged, shared)
    assert not client.calls


@pytest.mark.asyncio
async def test_pro_batch_accepts_supplied_artifact_hash(tmp_path: Path) -> None:
    """An exact supplied hash remains available as a per-child citation."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    valid = _evidence(first, "support")
    valid["evidence_refs"] = [shared.content_hash]
    client = _Client({"pro_evidence": [[valid]]})

    ref = (
        await ProConStage(client, artifacts).run_pro_batch(
            {first: checkpoints[first]}, shared
        )
    )[first]

    assert json.loads(artifacts.read(ref))["result"]["evidence_refs"] == [
        shared.content_hash
    ]


@pytest.mark.asyncio
async def test_pro_batch_rejects_oversized_shared_context(tmp_path: Path) -> None:
    """A large context must fail explicitly instead of silently truncating."""

    artifacts, _shared, checkpoints = _fixture(tmp_path)
    oversized = artifacts.put_json({"content": "x" * 300_000})
    client = _Client({"pro_evidence": []})

    with pytest.raises(ValueError, match="PRO_CON_BATCH_CONTEXT_INVALID"):
        await ProConStage(client, artifacts).run_pro_batch(checkpoints, oversized)
    assert not client.calls


@pytest.mark.asyncio
async def test_legacy_pro_con_stage_still_calls_each_role(tmp_path: Path) -> None:
    """The existing child runner remains compatible with old checkpoints."""

    artifacts, _shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))

    class _LegacyClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
            self.calls.append(str(kwargs["agent_name"]))
            return SimpleLLMCallResult(
                value={
                    "claims": ["legacy evidence"],
                    "evidence_refs": [],
                    "limitations": [],
                    "requested_paths": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    client = _LegacyClient()
    result = await ProConStage(client, artifacts)(checkpoints[first], {})

    assert client.calls == ["pro_evidence", "con_evidence"]
    assert len(result.output_refs) == 2
    assert json.loads(artifacts.read(result.output_refs[0]))["kind"] == (
        "simple_pro_evidence"
    )


@pytest.mark.asyncio
async def test_store_backed_stage_reuses_pro_after_con_failure(tmp_path: Path) -> None:
    """A successful Pro call survives a failed Con call and is never repeated."""

    artifacts, _shared, checkpoints = _fixture(tmp_path)
    checkpoint = next(iter(checkpoints.values()))
    store = SimpleCheckpointStore(artifacts.paths.database)
    client = _SequentialClient(
        [
            _legacy_result("support"),
            StageFailure(
                code="PROVIDER_UNAVAILABLE",
                retryable=True,
                safe_message="Temporary provider failure",
            ),
            _legacy_result("counter"),
        ]
    )
    stage = ProConStage(client, artifacts, store=store)

    with pytest.raises(StageBlocked):
        await stage(checkpoint, {})
    pro_ref = store.get_pro_con_batch_evidence(
        checkpoint.identity, "pro", checkpoint.input_hash
    )
    assert pro_ref is not None

    result = await stage(checkpoint, {})

    assert client.calls == ["pro_evidence", "con_evidence", "con_evidence"]
    assert result.output_refs[0] == pro_ref
    assert len(result.activity_events) == 2
    assert result.activity_events[0].output_refs == (pro_ref,)
    assert result.activity_events[1].output_refs == (result.output_refs[1],)


@pytest.mark.asyncio
async def test_store_backed_stage_reuses_both_roles(tmp_path: Path) -> None:
    """A completed pair can be rebuilt from durable refs without another call."""

    artifacts, _shared, checkpoints = _fixture(tmp_path)
    checkpoint = next(iter(checkpoints.values()))
    store = SimpleCheckpointStore(artifacts.paths.database)
    client = _SequentialClient([_legacy_result("support"), _legacy_result("counter")])
    stage = ProConStage(client, artifacts, store=store)

    first = await stage(checkpoint, {})
    second = await stage(checkpoint, {})

    assert client.calls == ["pro_evidence", "con_evidence"]
    assert second.output_refs == first.output_refs
    assert len(second.activity_events) == 2


@pytest.mark.asyncio
async def test_store_backed_stage_uses_batched_role_refs(tmp_path: Path) -> None:
    """The legacy runner can consume separately fanned out batch evidence."""

    artifacts, shared, checkpoints = _fixture(tmp_path)
    first = next(iter(checkpoints))
    checkpoint = checkpoints[first]
    batch_client = _Client(
        {
            "pro_evidence": [[_evidence(first, "support")]],
            "con_evidence": [[_evidence(first, "counter")]],
        }
    )
    batch = ProConStage(batch_client, artifacts)
    pro_ref = (await batch.run_pro_batch({first: checkpoint}, shared))[first]
    con_ref = (await batch.run_con_batch({first: checkpoint}, shared))[first]
    store = SimpleCheckpointStore(artifacts.paths.database)
    store.save_pro_con_batch_evidence(
        checkpoint.identity, "pro", checkpoint.input_hash, pro_ref
    )
    store.save_pro_con_batch_evidence(
        checkpoint.identity, "con", checkpoint.input_hash, con_ref
    )
    unused_client = _SequentialClient([])

    result = await ProConStage(unused_client, artifacts, store=store)(checkpoint, {})

    assert result.output_refs == (pro_ref, con_ref)
    assert not unused_client.calls
    assert len(result.activity_events) == 2


@pytest.mark.asyncio
async def test_store_backed_stage_rejects_wrong_cached_role(tmp_path: Path) -> None:
    """An invalid stored ref blocks safely before either role is recalled."""

    artifacts, _shared, checkpoints = _fixture(tmp_path)
    checkpoint = next(iter(checkpoints.values()))
    wrong = artifacts.put_json({"kind": "simple_con_evidence"})
    store = SimpleCheckpointStore(artifacts.paths.database)
    store.save_pro_con_batch_evidence(
        checkpoint.identity, "pro", checkpoint.input_hash, wrong
    )
    client = _SequentialClient([])
    stage = ProConStage(client, artifacts, store=store)

    with pytest.raises(StageBlocked) as captured:
        await stage(checkpoint, {})
    assert captured.value.failure.code == "PRO_CON_BATCH_EXISTING_INVALID"
    assert not client.calls
