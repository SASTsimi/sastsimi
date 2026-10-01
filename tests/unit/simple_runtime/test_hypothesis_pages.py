from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypedDict, cast

import pytest
from pydantic import JsonValue

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import hypothesis_pages
from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.hypothesis_pages import SourcePageError, build_source_page
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult


class _Client:
    def __init__(self, hypotheses: list[dict[str, Any]] | None = None) -> None:
        self.hypotheses = cast(list[JsonValue], hypotheses or [])
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


class _ClientAdapter:
    """Accept the full runtime client protocol for focused page test clients."""

    def __init__(self, client: _Client) -> None:
        self.client = client

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult | StageFailure:
        del owner, prompt_bytes, invocation_id
        return await self.client.call(
            prompt=prompt,
            output_schema=output_schema,
            timeout_ms=timeout_ms,
            agent_name=agent_name,
        )


class _PageSegment(TypedDict):
    path: str
    code: str
    start_line: int
    end_line: int


class _Page(TypedDict):
    segments: list[_PageSegment]


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
        data_dir=tmp_path,
        client_factory=lambda _identity, _artifacts: _ClientAdapter(client),
    )
    return bootstrap, identity, static, artifacts


def _page(prompt: bytes) -> _Page:
    raw = prompt.split(b"<UNTRUSTED_EXACT_INPUTS>\n", 1)[1].split(
        b"\n</UNTRUSTED_EXACT_INPUTS>", 1
    )[0]
    return cast(_Page, json.loads(raw))


@pytest.mark.asyncio
async def test_paged_hypothesis_uses_configured_finite_llm_timeout(
    tmp_path: Path,
) -> None:
    class TimedClient(_Client):
        def __init__(self) -> None:
            super().__init__()
            self.timeouts: list[int] = []

        async def call(
            self,
            *,
            prompt: bytes,
            output_schema: Mapping[str, Any],
            timeout_ms: int,
            agent_name: str = "agent",
        ) -> SimpleLLMCallResult | StageFailure:
            self.timeouts.append(timeout_ms)
            return await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
            )

    client = TimedClient()
    _bootstrap, identity, static, _artifacts = _setup(
        tmp_path, {"app.py": "value = 1\n"}, client
    )
    configured = DirectHypothesisBootstrap(
        data_dir=tmp_path,
        client_factory=lambda _identity, _artifacts: _ClientAdapter(client),
        llm_timeout_seconds=300,
    )

    result = await configured.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )

    assert not isinstance(result, StageFailure)
    assert client.timeouts == [300_000]


def test_source_pages_fit_budget_and_preserve_lines_across_number_growth(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "app.py"
    for padding in range(1, 101):
        source = "".join(
            f"value_{index:03d} = {'x' * padding!r}\n" for index in range(1, 121)
        )
        source_path.write_bytes(source.encode("utf-8"))
        cursor: str | None = None
        chunks: list[str] = []
        for _ in range(120):
            page = build_source_page(
                workspace=tmp_path,
                paths=["app.py"],
                bundle_hash="a" * 64,
                manifest_hash="b" * 64,
                after_cursor=cursor,
                page_budget_bytes=2_048,
            )
            assert page is not None
            assert len(page.prompt) <= 2_048
            chunks.extend(str(segment["code"]) for segment in page.payload["segments"])
            cursor = page.next_cursor
            if cursor is None:
                break
        else:
            pytest.fail("Source page cursor did not finish")
        assert "".join(chunks) == source


def test_source_pages_redact_cross_line_credential_before_paginating(
    tmp_path: Path,
) -> None:
    sentinel = "SYNTHETIC_VALUE_NOT_A_TOKEN_7291"
    source = f"API_KEY = (\n  '{sentinel}'\n)\nprint('safe')\n"
    (tmp_path / "app.py").write_bytes(source.encode("utf-8"))
    cursor: str | None = None
    prompts: list[bytes] = []
    chunks: list[str] = []
    for _ in range(3):
        page = build_source_page(
            workspace=tmp_path,
            paths=["app.py"],
            bundle_hash="a" * 64,
            manifest_hash="b" * 64,
            after_cursor=cursor,
            page_budget_bytes=2_048,
        )
        assert page is not None
        prompts.append(page.prompt)
        chunks.extend(str(segment["code"]) for segment in page.payload["segments"])
        assert len(page.prompt) <= 2_048
        cursor = page.next_cursor
        if cursor is None:
            break
    else:
        pytest.fail("Cross-line credential page traversal did not finish")
    assert sentinel.encode() not in b"".join(prompts)
    assert "[REDACTED:CREDENTIAL]" in "".join(chunks)
    assert "".join(chunks).count("\n") == source.count("\n")


def test_source_page_cursor_inside_cross_line_credential_cannot_reveal_value(
    tmp_path: Path,
) -> None:
    sentinel = "SYNTHETIC_VALUE_NOT_A_TOKEN_7291"
    source = f"API_KEY = (\r\n  '{sentinel}'\r\n)\r\nprint('safe')\r\n"
    (tmp_path / "app.py").write_bytes(source.encode("utf-8"))
    page = build_source_page(
        workspace=tmp_path,
        paths=["app.py"],
        bundle_hash="a" * 64,
        manifest_hash="b" * 64,
        after_cursor=f"p1:{'a' * 64}:{'b' * 64}:0:1",
        page_budget_bytes=2_048,
    )
    assert page is not None
    assert len(page.prompt) <= 2_048
    assert sentinel.encode() not in page.prompt
    assert page.payload["segments"][0]["start_line"] == 2
    assert (
        "".join(str(segment["code"]) for segment in page.payload["segments"]).count(
            "\r\n"
        )
        == 3
    )


@pytest.mark.parametrize(
    "source",
    [
        "API_KEY = (\n  'SYNTHETIC_VALUE_7291'\n)\n",
        "API_KEY = make_key(\n  'SYNTHETIC_VALUE_7291'\n)\n",
        "API_KEY = '''SYNTHETIC_VALUE_7291\nsecond line'''\n",
        "API_KEY = \\\n  'SYNTHETIC_VALUE_7291'\n",
        "API_KEY: str = (\n  'SYNTHETIC_VALUE_7291'\n)\n",
        "auth = (\n  'SYNTHETIC_VALUE_7291'\n)\n",
        "api_key[0] = (\n  'SYNTHETIC_VALUE_7291'\n)\n",
        "api_key.value = (\n  'SYNTHETIC_VALUE_7291'\n)\n",
        "config['api_key'][0] = (\n  'SYNTHETIC_VALUE_7291'\n)\n",
        "settings = {'api_key': (\n  'SYNTHETIC_VALUE_7291'\n)}\n",
        "def load(api_key=(\n  'SYNTHETIC_VALUE_7291'\n)):\n  pass\n",
        "type API_KEY = Literal[\n  'SYNTHETIC_VALUE_7291'\n]\n",
        "setattr(settings, 'api_key', (\n  'SYNTHETIC_VALUE_7291'\n))\n",
        "settings.setdefault('api_key', (\n  'SYNTHETIC_VALUE_7291'\n))\n",
        "settings.update([('api_key', (\n  'SYNTHETIC_VALUE_7291'\n))])\n",
        "# api_key:\n#   SYNTHETIC_VALUE_7291\n",
        "# API_KEY = (\n# SYNTHETIC_VALUE_7291\n",
        "API_KEY = get_default()  # actual: SYNTHETIC_VALUE_7291\n",
    ],
)
def test_source_page_masks_valid_python_secret_value_expressions(
    tmp_path: Path, source: str
) -> None:
    (tmp_path / "app.py").write_bytes(source.encode("utf-8"))
    page = build_source_page(
        workspace=tmp_path,
        paths=["app.py"],
        bundle_hash="a" * 64,
        manifest_hash="b" * 64,
        after_cursor=None,
        page_budget_bytes=2_048,
    )
    assert page is not None
    assert b"SYNTHETIC_VALUE_7291" not in page.prompt
    assert len(page.prompt) <= 2_048
    assert "".join(str(segment["code"]) for segment in page.payload["segments"]).count(
        "\n"
    ) == source.count("\n")


def test_source_page_fails_closed_on_unparseable_python(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_bytes(b"API_KEY = (\n  'SYNTHETIC_VALUE_7291'\n")
    with pytest.raises(SourcePageError, match="HYPOTHESIS_PAGE_SOURCE_SYNTAX"):
        build_source_page(
            workspace=tmp_path,
            paths=["app.py"],
            bundle_hash="a" * 64,
            manifest_hash="b" * 64,
            after_cursor=None,
            page_budget_bytes=2_048,
        )


def test_source_page_rejects_file_above_redaction_memory_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_bytes(b"x=1\n" * 30)
    monkeypatch.setattr(hypothesis_pages, "MAX_SOURCE_FILE_BYTES", 100, raising=False)
    with pytest.raises(SourcePageError, match="HYPOTHESIS_PAGE_SOURCE_TOO_LARGE"):
        build_source_page(
            workspace=tmp_path,
            paths=["app.py"],
            bundle_hash="a" * 64,
            manifest_hash="b" * 64,
            after_cursor=None,
            page_budget_bytes=2_048,
        )


def test_source_page_rejects_excessive_line_count_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_bytes(b"x=1\n" * 6)
    monkeypatch.setattr(hypothesis_pages, "MAX_SOURCE_LINES", 5, raising=False)
    with pytest.raises(SourcePageError, match="HYPOTHESIS_PAGE_SOURCE_TOO_LARGE"):
        build_source_page(
            workspace=tmp_path,
            paths=["app.py"],
            bundle_hash="a" * 64,
            manifest_hash="b" * 64,
            after_cursor=None,
            page_budget_bytes=2_048,
        )


def test_source_page_handles_deep_sensitive_assignment_target(
    tmp_path: Path,
) -> None:
    source = "API_KEY" + "[0]" * 1_000 + " = (\n  'SYNTHETIC_VALUE_7291'\n)\n"
    (tmp_path / "app.py").write_bytes(source.encode("utf-8"))
    page = build_source_page(
        workspace=tmp_path,
        paths=["app.py"],
        bundle_hash="a" * 64,
        manifest_hash="b" * 64,
        after_cursor=None,
        page_budget_bytes=16_384,
    )
    assert page is not None
    assert b"SYNTHETIC_VALUE_7291" not in page.prompt


def test_source_page_keeps_nonsecret_session_mapping_flow(
    tmp_path: Path,
) -> None:
    source = "session['role'] = request.headers['X-Role']\n"
    (tmp_path / "app.py").write_bytes(source.encode("utf-8"))
    page = build_source_page(
        workspace=tmp_path,
        paths=["app.py"],
        bundle_hash="a" * 64,
        manifest_hash="b" * 64,
        after_cursor=None,
        page_budget_bytes=2_048,
    )
    assert page is not None
    assert page.payload["segments"][0]["code"] == source


@pytest.mark.parametrize(
    "source",
    [
        "auth['role'] = request.headers['X-Role']\n",
        "auth.permissions = request.permissions\n",
    ],
)
def test_source_page_keeps_nonsecret_auth_mapping_flow(
    tmp_path: Path, source: str
) -> None:
    (tmp_path / "app.py").write_bytes(source.encode("utf-8"))
    page = build_source_page(
        workspace=tmp_path,
        paths=["app.py"],
        bundle_hash="a" * 64,
        manifest_hash="b" * 64,
        after_cursor=None,
        page_budget_bytes=2_048,
    )
    assert page is not None
    assert page.payload["segments"][0]["code"] == source


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
async def test_paged_hypothesis_repairs_invalid_location_with_page_ranges(
    tmp_path: Path,
) -> None:
    class RepairClient(_Client):
        def __init__(self) -> None:
            super().__init__()
            self.responses = [
                [_proposal("invented/app.py:3")],
                [_proposal("app.py:2")],
            ]
            self.raw_ref: StoredDataRef | None = None

        async def call(
            self,
            *,
            prompt: bytes,
            output_schema: Mapping[str, Any],
            timeout_ms: int,
            agent_name: str = "agent",
        ) -> SimpleLLMCallResult | StageFailure:
            del output_schema, timeout_ms, agent_name
            self.prompts.append(prompt)
            return SimpleLLMCallResult(
                value=cast(dict[str, JsonValue], {"hypotheses": self.responses.pop(0)}),
                prompt_digest="a" * 64,
                output_digest="b" * 64,
                raw_output_ref=self.raw_ref if len(self.prompts) == 1 else None,
            )

    client = RepairClient()
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": "first = 1\nsecond = 2\n"}, client
    )
    client.raw_ref = artifacts.put_json({"kind": "raw_invalid_model_output"})

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )

    assert not isinstance(result, StageFailure)
    seeds, cursor = result
    assert cursor is None
    assert len(seeds) == 1
    assert len(client.prompts) == 2
    feedback = json.loads(
        client.prompts[1]
        .split(b"<PAGE_VALIDATION_FEEDBACK>\n", 1)[1]
        .split(b"\n</PAGE_VALIDATION_FEEDBACK>", 1)[0]
    )
    assert feedback["allowed_page_ranges"] == {"app.py": [1, 2]}
    assert feedback["errors"] == [
        {
            "hypothesis_index": 0,
            "errors": ["code location is outside the tracked checkout"],
        }
    ]
    assert feedback["invalid_locations"] == ["invented/app.py:3"]
    proposal = json.loads(artifacts.read_prompt_proposal(seeds[0].proposal_ref))
    assert proposal["proposal"]["code_locations"] == ["app.py:2"]
    successful = json.loads(
        artifacts.read(StoredDataRef.model_validate(proposal["page_result_ref"]))
    )
    assert len(successful["semantic_retry_refs"]) == 1
    invalid = json.loads(
        artifacts.read(
            StoredDataRef.model_validate(successful["semantic_retry_refs"][0])
        )
    )
    assert invalid["validation_status"] == "INVALID"
    assert invalid["hypotheses"] == [_proposal("invented/app.py:3")]
    assert invalid["llm_raw_output_ref"] == client.raw_ref.model_dump(mode="json")


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_code", ["CONTEXT_LIMIT_EXCEEDED", "TIMED_OUT"])
async def test_paged_hypothesis_shrink_resets_page_feedback_but_keeps_evidence(
    tmp_path: Path, failure_code: str
) -> None:
    class ShrinkingRepairClient(_Client):
        def __init__(self) -> None:
            super().__init__()
            self.failure_ref: StoredDataRef | None = None

        async def call(
            self,
            *,
            prompt: bytes,
            output_schema: Mapping[str, Any],
            timeout_ms: int,
            agent_name: str = "agent",
        ) -> SimpleLLMCallResult | StageFailure:
            del output_schema, timeout_ms, agent_name
            self.prompts.append(prompt)
            if len(self.prompts) == 2:
                assert self.failure_ref is not None
                return StageFailure(
                    code=failure_code,
                    retryable=True,
                    safe_message="Repair request was too large",
                    evidence_refs=(self.failure_ref,),
                )
            location = {
                1: "b.py:99",
                3: "b.py:1",
                4: "a.py:1",
            }[len(self.prompts)]
            return SimpleLLMCallResult(
                value=cast(dict[str, JsonValue], {"hypotheses": [_proposal(location)]}),
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    client = ShrinkingRepairClient()
    bootstrap, identity, static, artifacts = _setup(
        tmp_path,
        {
            "a.py": "a = " + "x" * 900 + "\n",
            "b.py": "b = " + "y" * 900 + "\n",
        },
        client,
    )
    client.failure_ref = artifacts.put_json({"kind": "oversized_repair_request"})

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=4096
    )

    assert not isinstance(result, StageFailure)
    seeds, cursor = result
    assert len(seeds) == 1
    assert cursor is not None
    assert len(client.prompts) == 4
    assert [segment["path"] for segment in _page(client.prompts[0])["segments"]] == [
        "a.py",
        "b.py",
    ]
    assert [segment["path"] for segment in _page(client.prompts[2])["segments"]] == [
        "a.py"
    ]
    assert b"<PAGE_VALIDATION_FEEDBACK>" in client.prompts[1]
    assert b"<PAGE_VALIDATION_FEEDBACK>" not in client.prompts[2]
    feedback = json.loads(
        client.prompts[3]
        .split(b"<PAGE_VALIDATION_FEEDBACK>\n", 1)[1]
        .split(b"\n</PAGE_VALIDATION_FEEDBACK>", 1)[0]
    )
    assert feedback["allowed_page_ranges"] == {"a.py": [1, 1]}
    proposal = json.loads(artifacts.read_prompt_proposal(seeds[0].proposal_ref))
    final = json.loads(
        artifacts.read(StoredDataRef.model_validate(proposal["page_result_ref"]))
    )
    assert len(final["semantic_retry_refs"]) == 1
    prior_failures = [
        json.loads(artifacts.read(StoredDataRef.model_validate(ref)))
        for ref in final["retry_failure_refs"]
    ]
    assert {record["kind"] for record in prior_failures} == {
        "simple_hypothesis_page_result",
        "oversized_repair_request",
    }
    assert any(
        record.get("hypotheses") == [_proposal("b.py:99")] for record in prior_failures
    )


@pytest.mark.asyncio
async def test_paged_hypothesis_bounded_invalid_repair_keeps_raw_evidence(
    tmp_path: Path,
) -> None:
    client = _Client([_proposal("invented/app.py:3")])
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": "first = 1\nsecond = 2\n"}, client
    )

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_OUTPUT_INVALID"
    assert not result.retryable
    assert len(client.prompts) == 2
    records = [json.loads(artifacts.read(ref)) for ref in result.evidence_refs]
    invalid = [
        record
        for record in records
        if record.get("kind") == "simple_hypothesis_page_result"
    ]
    assert len(invalid) == 2
    assert all(record["validation_status"] == "INVALID" for record in invalid)
    assert all(
        record["hypotheses"] == [_proposal("invented/app.py:3")] for record in invalid
    )


@pytest.mark.asyncio
async def test_paged_hypothesis_does_not_silently_drop_duplicate_proposals(
    tmp_path: Path,
) -> None:
    client = _Client([_proposal("app.py:1"), _proposal("app.py:1")])
    bootstrap, identity, static, _artifacts = _setup(
        tmp_path, {"app.py": "first = 1\n"}, client
    )

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_PAGE_OUTPUT_INVALID"
    assert len(client.prompts) == 2


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
async def test_paged_hypothesis_redacts_proposal_before_strict_followup_context(
    tmp_path: Path,
) -> None:
    proposal = _proposal("app.py:1")
    proposal["source"] = "access_token = request.args.get('token')"
    client = _Client([proposal])
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": "value = 1\n"}, client
    )

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2048
    )

    assert not isinstance(result, StageFailure)
    seeds, _ = result
    assert len(seeds) == 1
    stored = json.loads(artifacts.read(seeds[0].proposal_ref))
    assert stored["proposal"]["source"] == "[REDACTED:TOKEN]"
    page_ref = type(seeds[0].proposal_ref).model_validate(stored["page_input_ref"])
    artifacts.prompt_context_strict((seeds[0].proposal_ref, page_ref))
    page_result_ref = type(seeds[0].proposal_ref).model_validate(
        stored["page_result_ref"]
    )
    assert json.loads(artifacts.read(page_result_ref))["hypotheses"] == [proposal]


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
@pytest.mark.parametrize("failure_code", ["CONTEXT_LIMIT_EXCEEDED", "TIMED_OUT"])
async def test_paged_hypothesis_success_retains_failed_attempt_evidence(
    tmp_path: Path, failure_code: str
) -> None:
    class FailureOnce(_Client):
        def __init__(self) -> None:
            super().__init__([_proposal("app.py:1")])
            self.failure_refs: tuple[StoredDataRef, ...] = ()

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
                    code=failure_code,
                    retryable=failure_code == "TIMED_OUT",
                    safe_message="First page attempt failed",
                    evidence_refs=self.failure_refs,
                )
            return await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
            )

    client = FailureOnce()
    source = "".join("x = " + "a" * 900 + "\n" for _ in range(12))
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": source}, client
    )
    request_ref = artifacts.put_json({"kind": "failed_llm_request"})
    diagnostic_ref = artifacts.put_json({"kind": "failed_llm_diagnostic"})
    client.failure_refs = (request_ref, diagnostic_ref)

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=16_384
    )

    assert not isinstance(result, StageFailure)
    seeds, _cursor = result
    assert len(seeds) == 1
    proposal = json.loads(artifacts.read(seeds[0].proposal_ref))
    page_result_ref = StoredDataRef.model_validate(proposal["page_result_ref"])
    page_result = json.loads(artifacts.read(page_result_ref))
    assert page_result["retry_failure_refs"] == [
        request_ref.model_dump(mode="json"),
        diagnostic_ref.model_dump(mode="json"),
    ]
    assert len(page_result["attempt_input_refs"]) == 2
    assert "retry_failure_refs" not in proposal
    assert request_ref.content_hash.encode() not in client.prompts[1]
    assert diagnostic_ref.content_hash.encode() not in client.prompts[1]


@pytest.mark.asyncio
async def test_paged_hypothesis_splits_only_unfinished_page_after_timeout(
    tmp_path: Path,
) -> None:
    class TimeoutOnce(_Client):
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
                    code="TIMED_OUT",
                    retryable=True,
                    safe_message="LLM call deadline reached",
                )
            return await super().call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
            )

    client = TimeoutOnce()
    source = "".join("x = " + "a" * 900 + "\n" for _ in range(12))
    bootstrap, identity, static, _artifacts = _setup(
        tmp_path, {"app.py": source}, client
    )

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=16_384
    )

    assert not isinstance(result, StageFailure)
    _seeds, cursor = result
    assert cursor is not None
    assert len(client.prompts) == 2
    assert len(client.prompts[1]) <= 8_192
    assert _page(client.prompts[1])["segments"][0]["start_line"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_code", "expected_code"),
    [
        ("TIMED_OUT", "HYPOTHESIS_PAGE_TIMEOUT_EXHAUSTED"),
        ("CONTEXT_LIMIT_EXCEEDED", "CONTEXT_LIMIT_EXCEEDED"),
    ],
)
async def test_paged_hypothesis_final_size_failure_keeps_all_prior_evidence(
    tmp_path: Path, failure_code: str, expected_code: str
) -> None:
    class AlwaysFails(_Client):
        def __init__(self) -> None:
            super().__init__()
            self.failure_refs: tuple[StoredDataRef, StoredDataRef] | None = None

        async def call(
            self,
            *,
            prompt: bytes,
            output_schema: Mapping[str, Any],
            timeout_ms: int,
            agent_name: str = "agent",
        ) -> SimpleLLMCallResult | StageFailure:
            del output_schema, timeout_ms, agent_name
            self.prompts.append(prompt)
            return StageFailure(
                code=failure_code,
                retryable=True,
                safe_message="Page request failed",
                evidence_refs=(self.failure_refs[len(self.prompts) - 1],)
                if self.failure_refs is not None
                else (),
            )

    client = AlwaysFails()
    bootstrap, identity, static, artifacts = _setup(
        tmp_path, {"app.py": "x = 1\n"}, client
    )
    client.failure_refs = (
        artifacts.put_json({"kind": "first_timed_out_request"}),
        artifacts.put_json({"kind": "second_timed_out_request"}),
    )

    result = await bootstrap.propose_page(
        identity, static, after_cursor=None, page_budget_bytes=2_048
    )

    assert isinstance(result, StageFailure)
    assert result.code == expected_code
    assert result.retryable is (failure_code == "CONTEXT_LIMIT_EXCEEDED")
    assert len(client.prompts) == 2
    assert len(result.evidence_refs) == 3  # Identical page inputs share one artifact.
    assert all(ref in result.evidence_refs for ref in client.failure_refs)


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


@pytest.mark.asyncio
async def test_candidate_hypothesis_redacts_proposal_before_strict_followup_context(
    tmp_path: Path,
) -> None:
    proposal = _proposal("app.py:1")
    proposal["source"] = "access_token = request.args.get('token')"
    client = _Client([proposal])
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

    assert not isinstance(result, StageFailure)
    assert len(result) == 1
    stored = json.loads(artifacts.read(result[0].proposal_ref))
    assert stored["proposal"]["source"] == "[REDACTED:TOKEN]"
    artifacts.prompt_context_strict((result[0].proposal_ref, focused_ref))
    original_ref = type(result[0].proposal_ref).model_validate(
        stored["original_proposal_ref"]
    )
    assert json.loads(artifacts.read(original_ref))["proposal"] == proposal
    artifacts.artifacts.path_for(original_ref.content_hash).unlink()
    with pytest.raises(ValueError, match="HYPOTHESIS_PROPOSAL_ORIGINAL_INVALID"):
        artifacts.prompt_context_strict((result[0].proposal_ref, focused_ref))
