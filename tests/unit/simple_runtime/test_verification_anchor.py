"""Exact hypothesis and pinned source survive downstream prompt budgets."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import JsonValue

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text_preserving_lines,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.hypothesis_pages import redact_source_page_bytes
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageFailed
from sastsimi.simple_runtime.stages import FinalVerificationStage, TechnicalGateStage


class _ContextClient:
    def __init__(self) -> None:
        self.prompts: list[bytes] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        value: dict[str, JsonValue]
        if kwargs["agent_name"] == "verification_result":
            value = {
                "verdict": "HOLD",
                "rationale": "More evidence needed",
                "supporting_refs": [],
                "limitations": [],
                "unresolved_conditions": [],
                "required_capabilities": [],
                "provided_capabilities": [],
                "entities": [],
            }
        else:
            value = {
                "status": "ACCEPT",
                "rationale": "Sufficient evidence",
                "checks": [],
                "revision_requests": [],
            }
        return SimpleLLMCallResult(
            value=value,
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )


def _checkpoint(
    stage: SimpleStage,
    *,
    identity: CheckpointIdentity | None = None,
    inputs: tuple[StoredDataRef, ...] = (),
    outputs: tuple[StoredDataRef, ...] = (),
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity or _identity(),
        stage=stage,
        status=StageStatus.SUCCEEDED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=outputs,
    )


def _anchor_refs(
    artifacts: SimpleArtifactRepository,
    *,
    analysis_id: str = "analysis-1",
    hypothesis_id: str = "hypothesis-1",
    source_lines: list[dict[str, object]] | None = None,
    include_link: bool = True,
) -> tuple[StoredDataRef, StoredDataRef]:
    source_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v1",
            "path": "web.py",
            "source_status": "AVAILABLE",
            "source_sha256": "b" * 64,
            "source_lines": source_lines
            if source_lines is not None
            else [
                {"line": 40, "text": "name = request.form['name']"},
                {"line": 41, "text": "save_comment(name)  # pinned-source-marker"},
            ],
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": analysis_id,
            "hypothesis_id": hypothesis_id,
            **(
                {"shared_context_ref": source_ref.model_dump(mode="json")}
                if include_link
                else {}
            ),
            "proposal": {
                "title": "Stored XSS hypothesis-marker",
                "vulnerability_type": "stored XSS",
                "summary": "A submitted name reaches persisted HTML.",
                "code_locations": ["web.py:41"],
                "source": "request.form['name']",
                "sink": "save_comment",
                "rationale": "The value is rendered without escaping.",
            },
        }
    )
    return proposal_ref, source_ref


@pytest.mark.asyncio
async def test_exact_proposal_pinned_source_poc_and_feedback_precede_bulk(
    tmp_path: Path,
) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    proposal_ref, source_ref = _anchor_refs(artifacts)
    bulk_ref = artifacts.put_json({"kind": "bulk", "content": "x" * 300_000})
    requested_ref = artifacts.put_json(
        {
            "kind": "simple_requested_sources",
            "served": [{"content": "requested-marker"}],
        }
    )
    feedback_ref = artifacts.put_json(
        {
            "kind": "simple_technical_gate",
            "result": {"status": "REVISE", "revision_requests": ["feedback-marker"]},
        }
    )
    candidate_ref = artifacts.put_json({"kind": "simple_poc_candidate"})
    script_ref = artifacts.put_bytes(b"#!/bin/sh\nexit 0\n", "text/x-shellscript")
    execution_ref = artifacts.put_json(
        {"kind": "simple_poc_execution", "result": "current-poc-marker"}
    )
    validated_ref = artifacts.put_json({"kind": "simple_validated_poc"})
    prior = {
        SimpleStage.HYPOTHESIS_DONE: _checkpoint(
            SimpleStage.HYPOTHESIS_DONE, outputs=(bulk_ref,)
        ),
        SimpleStage.PRO_CON_DONE: _checkpoint(
            SimpleStage.PRO_CON_DONE, inputs=(proposal_ref, source_ref)
        ),
        SimpleStage.POC_CANDIDATE_DONE: _checkpoint(
            SimpleStage.POC_CANDIDATE_DONE,
            outputs=(candidate_ref, script_ref, requested_ref, feedback_ref),
        ),
        SimpleStage.POC_EXECUTION_DONE: _checkpoint(
            SimpleStage.POC_EXECUTION_DONE,
            outputs=(execution_ref, validated_ref),
        ).model_copy(update={"validated_poc_ref": validated_ref}),
    }
    client = _ContextClient()
    final = await FinalVerificationStage(client, artifacts)(
        _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE), prior
    )
    prior[SimpleStage.VERIFICATION_FINAL_DONE] = _checkpoint(
        SimpleStage.VERIFICATION_FINAL_DONE, outputs=final.output_refs
    )
    await TechnicalGateStage(client, artifacts)(
        _checkpoint(SimpleStage.TECH_GATE_DONE), prior
    )

    assert final.verdict == "HOLD"
    stored = json.loads(artifacts.read(final.output_refs[0]))
    assert bulk_ref.model_dump(mode="json") not in stored["source_refs"]
    assert len(client.prompts) == 2
    for prompt in client.prompts:
        assert b"Stored XSS hypothesis-marker" in prompt
        assert b"pinned-source-marker" in prompt
        assert b"current-poc-marker" in prompt
        assert b"feedback-marker" in prompt
        assert b"requested-marker" in prompt
        assert b'"line":41' in prompt
        assert prompt.index(b"Stored XSS hypothesis-marker") < prompt.index(
            b"current-poc-marker"
        )
        assert len(prompt) <= 256 * 1024
        assert b'"omitted_optional_refs":' in prompt
        assert b"x" * 300_000 not in prompt


@pytest.mark.asyncio
async def test_missing_optional_ref_is_omitted_and_not_claimed(tmp_path: Path) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    proposal_ref, source_ref = _anchor_refs(artifacts)
    invalid_ref = StoredDataRef.model_validate(
        {
            **source_ref.model_dump(mode="json"),
            "stored_data_id": "f" * 64,
            "content_hash": "f" * 64,
        }
    )
    prior = {
        SimpleStage.PRO_CON_DONE: _checkpoint(
            SimpleStage.PRO_CON_DONE, inputs=(proposal_ref, source_ref)
        ),
        SimpleStage.HYPOTHESIS_DONE: _checkpoint(
            SimpleStage.HYPOTHESIS_DONE, outputs=(invalid_ref,)
        ),
    }
    client = _ContextClient()
    final = await FinalVerificationStage(client, artifacts)(
        _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE), prior
    )
    assert b'"omitted_optional_refs":1' in client.prompts[0]
    stored = json.loads(artifacts.read(final.output_refs[0]))
    assert invalid_ref.model_dump(mode="json") not in stored["source_refs"]


@pytest.mark.asyncio
async def test_nonstatic_proposal_requires_matching_source_ref(tmp_path: Path) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    proposal_ref, source_ref = _anchor_refs(artifacts, include_link=False)
    client = _ContextClient()
    with pytest.raises(StageFailed) as caught:
        await FinalVerificationStage(client, artifacts)(
            _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE),
            {
                SimpleStage.PRO_CON_DONE: _checkpoint(
                    SimpleStage.PRO_CON_DONE, inputs=(proposal_ref, source_ref)
                )
            },
        )
    assert caught.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
    assert client.prompts == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid", ["analysis", "hypothesis", "commit", "corrupt", "source", "redaction"]
)
async def test_invalid_exact_anchor_blocks_before_final_provider(
    tmp_path: Path, invalid: str
) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    source_lines: list[dict[str, object]] | None = (
        []
        if invalid == "source"
        else [{"line": 41, "text": "api_key = 'secret-value-123'"}]
        if invalid == "redaction"
        else None
    )
    proposal_ref, source_ref = _anchor_refs(
        artifacts,
        analysis_id="other-analysis" if invalid == "analysis" else "analysis-1",
        hypothesis_id="other-hypothesis" if invalid == "hypothesis" else "hypothesis-1",
        source_lines=source_lines,
    )
    if invalid == "commit":
        source_ref = source_ref.model_copy(update={"commit_id": "c" * 40})
    if invalid == "corrupt":
        proposal_ref = proposal_ref.model_copy(update={"content_hash": "f" * 64})
    pro = _checkpoint(SimpleStage.PRO_CON_DONE, inputs=(proposal_ref, source_ref))
    client = _ContextClient()
    with pytest.raises(StageFailed) as caught:
        await FinalVerificationStage(client, artifacts)(
            _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE),
            {SimpleStage.PRO_CON_DONE: pro},
        )
    assert caught.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
    assert client.prompts == []


@pytest.mark.asyncio
async def test_required_context_overflow_is_named_and_never_truncated(
    tmp_path: Path,
) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    proposal_ref, source_ref = _anchor_refs(artifacts)
    huge_poc = artifacts.put_json(
        {"kind": "simple_poc_execution", "result": "p" * 300_000}
    )
    pro = _checkpoint(SimpleStage.PRO_CON_DONE, inputs=(proposal_ref, source_ref))
    execution = _checkpoint(SimpleStage.POC_EXECUTION_DONE, outputs=(huge_poc,))
    client = _ContextClient()
    with pytest.raises(StageFailed) as caught:
        await FinalVerificationStage(client, artifacts)(
            _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE),
            {
                SimpleStage.PRO_CON_DONE: pro,
                SimpleStage.POC_EXECUTION_DONE: execution,
            },
        )
    assert caught.value.failure.code == "HYPOTHESIS_CONTEXT_OVERFLOW"
    assert client.prompts == []


@pytest.mark.asyncio
async def test_production_final_requires_pro_con_anchor(tmp_path: Path) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    client = _ContextClient()
    with pytest.raises(StageFailed) as caught:
        await FinalVerificationStage(client, artifacts, require_anchor=True)(
            _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE), {}
        )
    assert caught.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
    assert client.prompts == []


@pytest.mark.asyncio
async def test_pinned_anchor_includes_direct_same_file_http_caller_context(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    pinned = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "\n"
        "def save_comment(value):\n"
        "    return database.execute(value)\n"
        "\n"
        "@app.post('/submit')\n"
        "def submit():\n"
        "    return save_comment(request.form['comment'])\n"
    )
    source_path = checkout / "web.py"
    source_path.write_text(pinned, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "web.py"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode("ascii")
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    source_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v1",
            "path": "web.py",
            "source_status": "AVAILABLE",
            "source_sha256": hashlib.sha256(pinned.encode("utf-8")).hexdigest(),
            "source_lines": [{"line": 5, "text": "    return database.execute(value)"}],
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "shared_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {
                "title": "Stored SQL query",
                "code_locations": ["web.py:5"],
            },
        }
    )
    client = _ContextClient()
    await FinalVerificationStage(
        client,
        artifacts,
        workspace_path=checkout,
        require_anchor=True,
    )(
        _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity),
        {
            SimpleStage.PRO_CON_DONE: _checkpoint(
                SimpleStage.PRO_CON_DONE,
                identity=identity,
                inputs=(proposal_ref, source_ref),
            )
        },
    )

    assert b"request.form['comment']" in client.prompts[0]
    assert b"def submit" in client.prompts[0]


@pytest.mark.asyncio
async def test_redacted_pinned_context_is_verified_against_its_source_commit(
    tmp_path: Path,
) -> None:
    """A safe projected source context must not be mistaken for corruption."""

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    pinned = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "\n"
        "def run_query():\n"
        "    api_key = 'top-secret-value'\n"
        "    return database.execute(request.form['query'])\n"
        "\n"
        "@app.post('/search')\n"
        "def search():\n"
        "    return run_query()\n"
    )
    source_path = checkout / "web.py"
    source_path.write_text(pinned, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "web.py"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode("ascii")
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    raw_context = {
        "kind": "simple_candidate_file_context_v1",
        "path": "web.py",
        "source_status": "AVAILABLE",
        "source_sha256": hashlib.sha256(pinned.encode("utf-8")).hexdigest(),
        "source_lines": [
            {"line": 5, "text": "    api_key = 'top-secret-value'"},
            {"line": 6, "text": "    return database.execute(request.form['query'])"},
        ],
    }
    projected_context = json.loads(
        redact_projected_json(canonical_bytes(raw_context)).data
    )
    assert projected_context != raw_context
    source_ref = artifacts.put_json(projected_context)
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "shared_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {
                "title": "Untrusted query execution",
                "code_locations": ["web.py:6"],
            },
        }
    )
    client = _ContextClient()
    await FinalVerificationStage(
        client,
        artifacts,
        workspace_path=checkout,
        require_anchor=True,
    )(
        _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity),
        {
            SimpleStage.PRO_CON_DONE: _checkpoint(
                SimpleStage.PRO_CON_DONE,
                identity=identity,
                inputs=(proposal_ref, source_ref),
            )
        },
    )

    assert b"[REDACTED:CREDENTIAL]" in client.prompts[0]
    assert b"top-secret-value" not in client.prompts[0]


@pytest.mark.asyncio
async def test_line_preserving_redacted_context_matches_pinned_commit(
    tmp_path: Path,
) -> None:
    """Anchor validation compares a file-context line using its own redactor."""

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    pinned = (
        "user = request.form.get('username')\n"
        "password = 'not-a-real-secret'\n"
        "query = f\"SELECT * FROM users WHERE user='{user}' "
        "AND password='{password}'\"\n"
    )
    source_path = checkout / "web.py"
    source_path.write_text(pinned, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "web.py"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode("ascii")
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    safe_lines = (
        redact_untrusted_text_preserving_lines(pinned.encode("utf-8"))
        .data.decode("utf-8")
        .splitlines()
    )
    assert "not-a-real-secret" not in safe_lines[1]
    source_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v1",
            "path": "web.py",
            "source_status": "AVAILABLE",
            "source_sha256": hashlib.sha256(pinned.encode("utf-8")).hexdigest(),
            "source_lines": [
                {"line": 2, "text": safe_lines[1]},
                {"line": 3, "text": safe_lines[2]},
            ],
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "shared_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {
                "title": "SQL injection",
                "code_locations": ["web.py:3"],
            },
        }
    )
    client = _ContextClient()
    await FinalVerificationStage(
        client,
        artifacts,
        workspace_path=checkout,
        require_anchor=True,
    )(
        _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity),
        {
            SimpleStage.PRO_CON_DONE: _checkpoint(
                SimpleStage.PRO_CON_DONE,
                identity=identity,
                inputs=(proposal_ref, source_ref),
            )
        },
    )

    assert len(client.prompts) == 1
    assert b"[REDACTED:CREDENTIAL]" in client.prompts[0]
    assert b"not-a-real-secret" not in client.prompts[0]


@pytest.mark.asyncio
async def test_source_page_anchor_uses_source_page_redaction_policy(
    tmp_path: Path,
) -> None:
    """A page masks AST-identified secret values before its anchor is checked."""

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    pinned = (
        "settings = {'session': 'not-a-real-secret'}\n"
        "query = f\"SELECT * FROM users WHERE name='{name}'\"\n"
    )
    source_path = checkout / "web.py"
    source_path.write_text(pinned, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "web.py"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode("ascii")
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    manifest_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": ["web.py"]}
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
        }
    )
    safe_code = redact_source_page_bytes(pinned.encode("utf-8")).decode("utf-8")
    assert "not-a-real-secret" not in safe_code
    page_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_source_page",
            "analysis_id": identity.analysis_id,
            "static_bundle_ref": bundle_ref.model_dump(mode="json"),
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "page": {
                "kind": "simple_hypothesis_source_page_v1",
                "static_bundle_hash": bundle_ref.content_hash,
                "source_manifest_hash": manifest_ref.content_hash,
                "segments": [
                    {
                        "path": "web.py",
                        "start_line": 1,
                        "end_line": 2,
                        "code": safe_code,
                    }
                ],
            },
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "page_input_ref": page_ref.model_dump(mode="json"),
            "proposal": {
                "title": "SQL injection",
                "code_locations": ["web.py:2"],
            },
        }
    )
    client = _ContextClient()
    await FinalVerificationStage(
        client,
        artifacts,
        workspace_path=checkout,
        require_anchor=True,
    )(
        _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity),
        {
            SimpleStage.PRO_CON_DONE: _checkpoint(
                SimpleStage.PRO_CON_DONE,
                identity=identity,
                inputs=(proposal_ref, page_ref),
            )
        },
    )

    assert len(client.prompts) == 1
    assert b"[REDACTED:CREDENTIAL]" in client.prompts[0]
    assert b"not-a-real-secret" not in client.prompts[0]


@pytest.mark.asyncio
async def test_gate_cannot_omit_oversized_final_verdict(tmp_path: Path) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    proposal_ref, source_ref = _anchor_refs(artifacts)
    huge_final = artifacts.put_json(
        {"kind": "simple_verification_result", "result": "f" * 300_000}
    )
    prior = {
        SimpleStage.PRO_CON_DONE: _checkpoint(
            SimpleStage.PRO_CON_DONE, inputs=(proposal_ref, source_ref)
        ),
        SimpleStage.VERIFICATION_FINAL_DONE: _checkpoint(
            SimpleStage.VERIFICATION_FINAL_DONE, outputs=(huge_final,)
        ),
    }
    client = _ContextClient()
    with pytest.raises(StageFailed) as caught:
        await TechnicalGateStage(client, artifacts)(
            _checkpoint(SimpleStage.TECH_GATE_DONE), prior
        )
    assert caught.value.failure.code == "HYPOTHESIS_CONTEXT_OVERFLOW"
    assert client.prompts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("source_kind", ["candidate", "surface", "page"])
@pytest.mark.parametrize("source_case", ["valid", "line_mismatch", "hash_mismatch"])
async def test_modern_context_citation_is_commit_pinned(
    tmp_path: Path,
    source_kind: str,
    source_case: str,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    source_path = checkout / "web.py"
    pinned = "name = request.form['name']\nsave_comment(name)  # pinned-modern-marker\n"
    source_path.write_text(pinned, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "web.py"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode("ascii")
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    cited_text = (
        "save_comment(name)  # tampered-context-marker"
        if source_case == "line_mismatch"
        else "save_comment(name)  # pinned-modern-marker"
    )
    source_sha = (
        "f" * 64
        if source_case == "hash_mismatch"
        else hashlib.sha256(pinned.encode("utf-8")).hexdigest()
    )
    link_name = {
        "candidate": "shared_context_ref",
        "surface": "surface_context_ref",
        "page": "page_input_ref",
    }[source_kind]
    source: dict[str, JsonValue]
    if source_kind == "page":
        manifest_ref = artifacts.put_json(
            {"kind": "simple_tracked_sources", "paths": ["web.py"]}
        )
        bundle_ref = artifacts.put_json(
            {
                "kind": "simple_static_fact_bundle",
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            }
        )
        source = {
            "kind": "simple_hypothesis_source_page",
            "analysis_id": identity.analysis_id,
            "static_bundle_ref": bundle_ref.model_dump(mode="json"),
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "page": {
                "kind": "simple_hypothesis_source_page_v1",
                "static_bundle_hash": bundle_ref.content_hash,
                "source_manifest_hash": (
                    "f" * 64
                    if source_case == "hash_mismatch"
                    else manifest_ref.content_hash
                ),
                "segments": [
                    {
                        "path": "web.py",
                        "start_line": 1,
                        "end_line": 2,
                        "code": "name = request.form['name']\n" + cited_text + "\n",
                    }
                ],
            },
        }
    else:
        source = {
            "kind": (
                "simple_candidate_file_context_v1"
                if source_kind == "candidate"
                else "simple_surface_context_v2"
            ),
            "path": "web.py",
            "source_status": "AVAILABLE",
            "source_sha256": source_sha,
            "source_lines": [{"line": 2, "text": cited_text}],
        }
    source_ref = artifacts.put_json(source)
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            link_name: source_ref.model_dump(mode="json"),
            "proposal": {"title": "Modern XSS", "code_locations": ["web.py:2"]},
        }
    )
    source_path.write_text("changed current checkout", encoding="utf-8")
    pro = _checkpoint(
        SimpleStage.PRO_CON_DONE,
        identity=identity,
        inputs=(proposal_ref, source_ref),
    )
    client = _ContextClient()
    final = FinalVerificationStage(
        client, artifacts, workspace_path=checkout, require_anchor=True
    )
    checkpoint = _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity)
    if source_case != "valid":
        with pytest.raises(StageFailed) as caught:
            await final(checkpoint, {SimpleStage.PRO_CON_DONE: pro})
        assert caught.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
        assert client.prompts == []
        return
    await final(checkpoint, {SimpleStage.PRO_CON_DONE: pro})
    assert len(client.prompts) == 1
    assert b"pinned-modern-marker" in client.prompts[0]
    assert b"changed current checkout" not in client.prompts[0]


@pytest.mark.asyncio
async def test_candidate_context_v2_pins_cross_file_call_path(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    routes = (
        "from dao import sink\n"
        "@app.post('/run')\n"
        "def endpoint(name):\n"
        "    return sink(name)  # route-source-marker\n"
    )
    dao = "def sink(name):\n    return connection.execute(name)  # sink-marker\n"
    (checkout / "routes.py").write_text(routes, encoding="utf-8")
    (checkout / "dao.py").write_text(dao, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "routes.py", "dao.py"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode("ascii")
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    source_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v2",
            "path": "dao.py",
            "source_status": "AVAILABLE",
            "source_sha256": hashlib.sha256(dao.encode("utf-8")).hexdigest(),
            "source_lines": [
                {
                    "line": 2,
                    "text": "    return connection.execute(name)  # sink-marker",
                }
            ],
            "related_source_files": [
                {
                    "path": "routes.py",
                    "source_status": "AVAILABLE",
                    "source_sha256": hashlib.sha256(routes.encode("utf-8")).hexdigest(),
                    "source_lines": [
                        {"line": 2, "text": "@app.post('/run')"},
                        {
                            "line": 4,
                            "text": "    return sink(name)  # route-source-marker",
                        },
                    ],
                }
            ],
            "candidate_call_paths": [
                {
                    "candidate_id": "candidate-1",
                    "status": "AVAILABLE",
                    "gaps": [],
                    "paths": [
                        {
                            "kind": "call_path_v1",
                            "provenance": "python_syntax",
                            "assurance": "SYNTACTIC_REACHABILITY",
                            "status": "AVAILABLE",
                            "gaps": [],
                            "steps": [
                                {"role": "ROUTE_ENTRY", "path": "routes.py", "line": 2},
                                {"role": "CALL", "path": "routes.py", "line": 4},
                                {"role": "SINK", "path": "dao.py", "line": 2},
                            ],
                        }
                    ],
                }
            ],
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "candidate_id": "candidate-1",
            "shared_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {"title": "Cross-file flow", "code_locations": ["dao.py:2"]},
        }
    )
    client = _ContextClient()
    await FinalVerificationStage(
        client, artifacts, workspace_path=checkout, require_anchor=True
    )(
        _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity),
        {
            SimpleStage.PRO_CON_DONE: _checkpoint(
                SimpleStage.PRO_CON_DONE,
                identity=identity,
                inputs=(proposal_ref, source_ref),
            )
        },
    )

    assert len(client.prompts) == 1
    assert b"route-source-marker" in client.prompts[0]
    assert b"sink-marker" in client.prompts[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", [False, True])
async def test_commit_pinned_anchor_checks_redacted_source_without_disclosing_secret(
    tmp_path: Path, tamper: bool
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    source_path = checkout / "web.py"
    pinned = (
        "user = request.form.get('username')\n"
        "password = 'not-a-real-secret'\n"
        "query = f\"SELECT * FROM users WHERE user='{user}' "
        "AND password='{password}'\"\n"
    )
    source_path.write_text(pinned, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "web.py"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode()
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    redacted_line = (
        redact_untrusted_text_preserving_lines(pinned.encode())
        .data.decode()
        .splitlines()[2]
    )
    if tamper:
        redacted_line = redacted_line.replace("SELECT", "DELETE")
    source_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v1",
            "path": "web.py",
            "source_status": "AVAILABLE",
            "source_sha256": hashlib.sha256(pinned.encode()).hexdigest(),
            "source_lines": [{"line": 3, "text": redacted_line}],
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "shared_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {"title": "SQL injection", "code_locations": ["web.py:3"]},
        }
    )
    source_path.write_text("changed current checkout", encoding="utf-8")
    client = _ContextClient()
    final = FinalVerificationStage(
        client, artifacts, workspace_path=checkout, require_anchor=True
    )
    checkpoint = _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity)
    prior = {
        SimpleStage.PRO_CON_DONE: _checkpoint(
            SimpleStage.PRO_CON_DONE,
            identity=identity,
            inputs=(proposal_ref, source_ref),
        )
    }
    if tamper:
        with pytest.raises(StageFailed) as caught:
            await final(checkpoint, prior)
        assert caught.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
        assert client.prompts == []
    else:
        await final(checkpoint, prior)
        assert len(client.prompts) == 1
        assert b"[REDACTED:CREDENTIAL]" in client.prompts[0]
        assert b"not-a-real-secret" not in client.prompts[0]
        assert b"changed current checkout" not in client.prompts[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", [False, True])
async def test_commit_pinned_page_anchor_uses_page_redaction_policy(
    tmp_path: Path, tamper: bool
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    source_path = checkout / "web.py"
    pinned = (
        "password = 'not-a-real-secret'\n"
        "query = f\"SELECT * FROM users WHERE password='{password}'\"\n"
    )
    source_path.write_text(pinned, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "web.py"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode()
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    manifest_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": ["web.py"]}
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
        }
    )
    safe_code = redact_source_page_bytes(pinned.encode()).decode()
    if tamper:
        safe_code = safe_code.replace("SELECT", "DELETE")
    page_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_source_page",
            "analysis_id": identity.analysis_id,
            "static_bundle_ref": bundle_ref.model_dump(mode="json"),
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "page": {
                "kind": "simple_hypothesis_source_page_v1",
                "static_bundle_hash": bundle_ref.content_hash,
                "source_manifest_hash": manifest_ref.content_hash,
                "segments": [
                    {
                        "path": "web.py",
                        "start_line": 1,
                        "end_line": 2,
                        "code": safe_code,
                    }
                ],
            },
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "page_input_ref": page_ref.model_dump(mode="json"),
            "proposal": {"title": "SQL injection", "code_locations": ["web.py:2"]},
        }
    )
    source_path.write_text("changed current checkout", encoding="utf-8")
    client = _ContextClient()
    final = FinalVerificationStage(
        client, artifacts, workspace_path=checkout, require_anchor=True
    )
    checkpoint = _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity)
    prior = {
        SimpleStage.PRO_CON_DONE: _checkpoint(
            SimpleStage.PRO_CON_DONE,
            identity=identity,
            inputs=(proposal_ref, page_ref),
        )
    }
    if tamper:
        with pytest.raises(StageFailed) as caught:
            await final(checkpoint, prior)
        assert caught.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
        assert client.prompts == []
    else:
        await final(checkpoint, prior)
        assert len(client.prompts) == 1
        assert b"[REDACTED:CREDENTIAL]" in client.prompts[0]
        assert b"not-a-real-secret" not in client.prompts[0]
        assert b"changed current checkout" not in client.prompts[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source_hash_case",
    [
        "valid",
        "mismatch",
        "missing",
        "v2",
        "v2_unindexed",
        "v3_unindexed",
        "secret_route",
    ],
)
async def test_legacy_static_bundle_uses_commit_pinned_cited_source(
    tmp_path: Path,
    source_hash_case: str,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    source_path = checkout / "web.py"
    if source_hash_case == "secret_route":
        pinned = (
            "def run_query():\n"
            "    api_key = 'not-a-real-secret'\n"
            "    return database.execute(request.form['query'])\n"
            "\n"
            "@app.post('/search')\n"
            "def search():\n"
            "    return run_query()\n"
        )
    elif source_hash_case.endswith("_unindexed"):
        pinned = "def broken(:\nsave_comment(name)  # pinned-legacy-marker\n"
    else:
        pinned = (
            "name = request.form['name']\nsave_comment(name)  # pinned-legacy-marker\n"
        )
    source_path.write_text(pinned, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "add",
            "web.py",
        ],
        cwd=checkout,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=checkout,
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout)
        .decode("ascii")
        .strip()
    )
    identity = _identity().model_copy(update={"commit_id": commit})
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    manifest_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": ["web.py"]}
    )
    source_sha = (
        "f" * 64
        if source_hash_case == "mismatch"
        else hashlib.sha256(pinned.encode("utf-8")).hexdigest()
    )
    ast_version = 2 if source_hash_case in {"v2", "v2_unindexed"} else 3
    ast_file_ref = artifacts.put_json(
        {
            "kind": f"simple_python_ast_file_v{ast_version - 1}",
            "path": "web.py",
            **({"source_sha256": source_sha} if ast_version == 3 else {}),
            "facts": [],
        }
    )
    manifest_entry = {
        "path": "web.py",
        **({"source_sha256": source_sha} if ast_version == 3 else {}),
        "fact_count": 0,
        "ref": ast_file_ref.model_dump(mode="json"),
    }
    if source_hash_case == "missing":
        manifest_entry.pop("source_sha256")
    unindexed = source_hash_case.endswith("_unindexed")
    ast_manifest_ref = artifacts.put_json(
        {
            "kind": f"simple_python_ast_manifest_v{ast_version - 1}",
            "entries": [] if unindexed else [manifest_entry],
            "fact_count": 0,
            "parsed_file_count": 0 if unindexed else 1,
        }
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "ast_summary": {
                "kind": "simple_python_ast",
                "format_version": ast_version,
                "manifest_ref": ast_manifest_ref.model_dump(mode="json"),
                "parsed_file_count": 0 if unindexed else 1,
                "fact_count": 0,
                "truncated": False,
                **({"parse_errors": ["web.py"]} if unindexed else {}),
            },
        }
    )
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "static_bundle_ref": bundle_ref.model_dump(mode="json"),
            "proposal": {
                "title": "Legacy stored XSS",
                "code_locations": [
                    "web.py:3" if source_hash_case == "secret_route" else "web.py:2"
                ],
                "source": "request.form['name']",
                "sink": "save_comment",
            },
        }
    )
    source_path.write_text("changed current checkout", encoding="utf-8")
    pro = _checkpoint(
        SimpleStage.PRO_CON_DONE,
        identity=identity,
        inputs=(proposal_ref, bundle_ref),
    )
    client = _ContextClient()
    final = FinalVerificationStage(client, artifacts, workspace_path=checkout)
    checkpoint = _checkpoint(SimpleStage.VERIFICATION_FINAL_DONE, identity=identity)
    if source_hash_case not in {"valid", "v2", "v2_unindexed", "secret_route"}:
        with pytest.raises(StageFailed) as caught:
            await final(checkpoint, {SimpleStage.PRO_CON_DONE: pro})
        assert caught.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
        assert client.prompts == []
        return
    await final(checkpoint, {SimpleStage.PRO_CON_DONE: pro})
    assert len(client.prompts) == 1
    assert b"Legacy stored XSS" in client.prompts[0]
    if source_hash_case == "secret_route":
        assert b"def search" in client.prompts[0]
        assert b"return run_query()" in client.prompts[0]
        assert b"not-a-real-secret" not in client.prompts[0]
    else:
        assert b"pinned-legacy-marker" in client.prompts[0]
    assert b"changed current checkout" not in client.prompts[0]
