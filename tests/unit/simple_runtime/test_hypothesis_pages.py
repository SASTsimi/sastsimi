from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult


class _Client:
    def __init__(self, hypotheses: list[dict[str, Any]] | None = None) -> None:
        self.hypotheses = hypotheses or []
        self.prompts: list[bytes] = []
        self.agent_names: list[str] = []

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult | StageFailure:
        del output_schema, timeout_ms
        self.prompts.append(prompt)
        self.agent_names.append(agent_name)
        return SimpleLLMCallResult(
            value={"hypotheses": self.hypotheses},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _setup(
    tmp_path: Path, files: Mapping[str, str], client: _Client
) -> tuple[
    DirectHypothesisBootstrap,
    CheckpointIdentity,
    StaticBootstrapResult,
    SimpleArtifactRepository,
]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name, source in files.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source.encode("utf-8"))
    identity = CheckpointIdentity(
        analysis_id="analysis-pages",
        workspace_id="workspace-pages",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    manifest_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": sorted(files)}
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
        }
    )
    static = StaticBootstrapResult(
        repository_profile_ref=bundle_ref,
        static_bundle_ref=bundle_ref,
        workspace_path=workspace,
    )
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path, client_factory=lambda _identity, _artifacts: client
    )
    return bootstrap, identity, static, artifacts


def _page(prompt: bytes) -> dict[str, Any]:
    raw = prompt.split(b"<UNTRUSTED_EXACT_INPUTS>\n", 1)[1].split(
        b"\n</UNTRUSTED_EXACT_INPUTS>", 1
    )[0]
    return json.loads(raw)


@pytest.mark.asyncio
async def test_paged_hypothesis_reads_more_than_legacy_context_without_loss(
    tmp_path: Path,
) -> None:
    lines = [
        f"value_{index:04d} = {index}  # " + "x" * 690 + "\n" for index in range(400)
    ]
    source = "".join(lines)
    assert len(source.encode()) > 256 * 1024
    client = _Client()
    bootstrap, identity, static, _ = _setup(tmp_path, {"app.py": source}, client)
    cursor: str | None = None
    received: list[str] = []
    for _ in range(100):
        result = await bootstrap.propose_page(
            identity, static, after_cursor=cursor, page_budget_bytes=32_768
        )
        assert not isinstance(result, StageFailure)
        seeds, cursor = result
        assert seeds == ()
        page = _page(client.prompts[-1])
        for segment in page["segments"]:
            assert segment["path"] == "app.py"
            received.append(segment["code"])
        assert len(client.prompts[-1]) <= 32_768
        if cursor is None:
            break
    else:
        pytest.fail("paged source traversal did not finish")
    assert "".join(received) == source
    assert len(client.prompts) > 1
    assert set(client.agent_names) == {"hypothesis_page"}


@pytest.mark.asyncio
async def test_paged_hypothesis_rejects_invalid_cursor_without_llm_call(
    tmp_path: Path,
) -> None:
    client = _Client()
    bootstrap, identity, static, _ = _setup(
        tmp_path, {"app.py": "print('safe')\n"}, client
    )
    result = await bootstrap.propose_page(
        identity, static, after_cursor="p1:wrong", page_budget_bytes=2048
    )
    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_CURSOR_INVALID"
    assert client.prompts == []


@pytest.mark.asyncio
async def test_paged_hypothesis_rejects_oversized_single_line(
    tmp_path: Path,
) -> None:
    client = _Client()
    bootstrap, identity, static, _ = _setup(
        tmp_path, {"app.py": "x = '" + "a" * 3000 + "'\n"}, client
    )
    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )
    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_LINE_TOO_LARGE"
    assert client.prompts == []


def _proposal(location: str) -> dict[str, Any]:
    return {
        "title": "Untrusted output",
        "vulnerability_type": "XSS",
        "summary": "Input reaches output.",
        "code_locations": [location],
        "source": "request",
        "sink": "response",
        "rationale": "The value is not escaped.",
    }


@pytest.mark.asyncio
async def test_paged_hypothesis_rejects_more_than_twelve_or_out_of_page(
    tmp_path: Path,
) -> None:
    client = _Client([_proposal("app.py:1")] * 13)
    bootstrap, identity, static, _ = _setup(
        tmp_path, {"app.py": "print('one')\nprint('two')\n"}, client
    )
    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )
    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_OUTPUT_INVALID"

    client.hypotheses = [_proposal("app.py:99")]
    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )
    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_OUTPUT_INVALID"


@pytest.mark.asyncio
async def test_paged_hypothesis_stable_seed_and_exact_page_artifacts(
    tmp_path: Path,
) -> None:
    client = _Client([_proposal("app.py:1")])
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": "print('one')\n"}, client
    )
    first = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )
    second = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )
    assert not isinstance(first, StageFailure)
    assert not isinstance(second, StageFailure)
    assert first == second
    seeds, cursor = first
    assert len(seeds) == 1
    assert cursor is None
    proposal = json.loads(artifacts.read(seeds[0].proposal_ref))
    assert proposal["proposal"] == _proposal("app.py:1")
    page_input = json.loads(
        artifacts.read(
            type(seeds[0].proposal_ref).model_validate(proposal["page_input_ref"])
        )
    )
    page_result = json.loads(
        artifacts.read(
            type(seeds[0].proposal_ref).model_validate(proposal["page_result_ref"])
        )
    )
    assert page_input["kind"] == "simple_hypothesis_source_page"
    assert page_result["kind"] == "simple_hypothesis_page_result"
    assert page_result["hypotheses"] == [_proposal("app.py:1")]


@pytest.mark.asyncio
async def test_paged_hypothesis_redacts_model_and_cas_page_without_moving_lines(
    tmp_path: Path,
) -> None:
    secret = "sk-abcdefgh12345678"
    source = f"api_key = '{secret}'\nprint('safe')\n"
    client = _Client([_proposal("app.py:2")])
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": source}, client
    )

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )

    assert not isinstance(result, StageFailure)
    seeds, cursor = result
    assert cursor is None
    assert len(seeds) == 1
    provider_page = _page(client.prompts[0])
    segment = provider_page["segments"][0]
    assert (segment["path"], segment["start_line"], segment["end_line"]) == (
        "app.py",
        1,
        2,
    )
    assert len(segment["code"].splitlines()) == 2
    assert "[REDACTED:CREDENTIAL]" in segment["code"]
    assert secret.encode() not in client.prompts[0]
    proposal = json.loads(artifacts.read(seeds[0].proposal_ref))
    page_ref = type(seeds[0].proposal_ref).model_validate(proposal["page_input_ref"])
    stored = artifacts.read(page_ref)
    page_input = json.loads(stored)
    assert page_input["page"] == provider_page
    assert page_input["prompt"] == client.prompts[0].decode()
    assert secret.encode() not in stored
    assert (static.workspace_path / "app.py").read_text() == source


@pytest.mark.asyncio
async def test_paged_hypothesis_fails_closed_when_redaction_removes_source_lines(
    tmp_path: Path,
) -> None:
    private_key = (
        "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LW1hdGVyaWFs\n-----END PRIVATE KEY-----\n"
    )
    client = _Client()
    bootstrap, identity, static, _ = _setup(tmp_path, {"app.py": private_key}, client)

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_REDACTION_FAILED"
    assert client.prompts == []


@pytest.mark.asyncio
async def test_paged_hypothesis_rejects_cursor_inside_private_key_block(
    tmp_path: Path,
) -> None:
    source = (
        "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LW1hdGVyaWFs\n-----END PRIVATE KEY-----\n"
    )
    client = _Client()
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": source}, client
    )
    bundle = json.loads(artifacts.read(static.static_bundle_ref))
    manifest_hash = bundle["source_manifest_ref"]["content_hash"]
    cursor = f"p1:{static.static_bundle_ref.content_hash}:{manifest_hash}:0:1"

    result = await bootstrap.propose_page(
        identity, static, after_cursor=cursor, page_budget_bytes=2048
    )

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_REDACTION_FAILED"
    assert client.prompts == []


class _OverflowClient(_Client):
    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult | StageFailure:
        if not self.prompts:
            self.prompts.append(prompt)
            return StageFailure(
                code="CONTEXT_LIMIT_EXCEEDED",
                retryable=False,
                safe_message="Model context window exceeded",
            )
        return await super().call(
            prompt=prompt,
            output_schema=output_schema,
            timeout_ms=timeout_ms,
            agent_name=agent_name,
        )


@pytest.mark.asyncio
async def test_paged_hypothesis_splits_again_after_model_context_overflow(
    tmp_path: Path,
) -> None:
    client = _OverflowClient()
    source = "".join("x = " + "a" * 900 + "\n" for _ in range(12))
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": source}, client
    )
    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=16_384
    )
    assert not isinstance(result, StageFailure)
    seeds, cursor = result
    assert seeds == ()
    assert cursor is not None
    assert len(client.prompts) == 2
    assert len(client.prompts[1]) < len(client.prompts[0])
    assert len(client.prompts[1]) <= 8_192
    assert _page(client.prompts[1])["segments"][0]["start_line"] == 1
    assert artifacts.read(static.static_bundle_ref)


@pytest.mark.asyncio
async def test_paged_hypothesis_uses_python_manifest_files_only_and_keeps_order(
    tmp_path: Path,
) -> None:
    client = _Client()
    bootstrap, identity, static, _ = _setup(
        tmp_path,
        {
            "a.py": "a = 1\n",
            "b.py": "b = 2\n",
            "frontend/app.ts": "export const x = 1;\n",
        },
        client,
    )
    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )
    assert not isinstance(result, StageFailure)
    _, cursor = result
    assert cursor is None
    paths = [segment["path"] for segment in _page(client.prompts[0])["segments"]]
    assert paths == ["a.py", "b.py"]


@pytest.mark.asyncio
async def test_paged_hypothesis_reports_missing_source_without_call(
    tmp_path: Path,
) -> None:
    client = _Client()
    bootstrap, identity, static, _ = _setup(tmp_path, {"app.py": "x = 1\n"}, client)
    (static.workspace_path / "app.py").unlink()
    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )
    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_SOURCE_UNAVAILABLE"
    assert client.prompts == []


@pytest.mark.asyncio
async def test_candidate_hypothesis_response_over_batch_limit_is_not_silently_cut(
    tmp_path: Path,
) -> None:
    proposals = [
        {
            "title": f"Hypothesis {index}",
            "vulnerability_type": "SSRF",
            "summary": "Possible user-controlled request",
            "code_locations": ["app.py:1"],
            "source": "request",
            "sink": "fetch",
            "rationale": "Candidate requires verification",
        }
        for index in range(13)
    ]
    client = _Client(proposals)
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": "value = 1\n"}, client
    )
    focused_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "candidate_focus": {"candidate_id": "candidate-1"},
        }
    )
    focused_static = static.model_copy(update={"static_bundle_ref": focused_ref})

    result = await bootstrap.propose(identity, focused_static)

    assert isinstance(result, StageFailure)
    assert result.code == "CANDIDATE_HYPOTHESIS_BATCH_OVERFLOW"
    assert result.retryable is True
    assert client.agent_names == ["hypothesis"]
    assert len(result.evidence_refs) == 1
    overflow = json.loads(artifacts.read(result.evidence_refs[0]))
    assert len(overflow["returned_hypotheses"]) == 13


@pytest.mark.asyncio
async def test_candidate_focused_hypothesis_deduplicates_same_proposal(
    tmp_path: Path,
) -> None:
    first = _proposal("app.py:1")
    distinct = _proposal("app.py:2")
    client = _Client([first, dict(first), distinct])
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": "print('one')\nprint('two')\n"}, client
    )
    focused_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "candidate_focus": {"candidate_id": "candidate-1"},
        }
    )
    focused_static = static.model_copy(update={"static_bundle_ref": focused_ref})

    result = await bootstrap.propose(identity, focused_static)

    assert not isinstance(result, StageFailure)
    assert len(result) == 2
    assert [
        json.loads(artifacts.read(seed.proposal_ref))["proposal"] for seed in result
    ] == [first, distinct]
    client.hypotheses = [first]
    baseline = await bootstrap.propose(identity, focused_static)
    assert not isinstance(baseline, StageFailure)
    assert result[0].hypothesis_id == baseline[0].hypothesis_id
