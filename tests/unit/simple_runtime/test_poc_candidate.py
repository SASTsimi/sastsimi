from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.poc import PoCCandidateRejected
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked, StageFailed
from sastsimi.simple_runtime.stages import (
    PoCCandidateStage,
    _require_independent_poc_fixture,
)


class _RepairClient:
    def __init__(self) -> None:
        self.prompts: list[bytes] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\ncookie=never-print-this-cookie\nprintf x\n"
            if len(self.prompts) == 1
            else "#!/bin/sh\nfixture_value=x\nprintf '%s' \"$fixture_value\"\n"
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _HostPathRepairClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\nprintf '%s\\n' '\\\\attacker.example'\n"
            if len(self.prompts) == 1
            else (
                "#!/bin/sh\npython - <<'PY'\n"
                "print(chr(92) * 2 + 'attacker.example')\nPY\n"
            )
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _ExternalUrlRepairClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\nprintf '%s\\n' 'https://attacker.example/path'\n"
            if len(self.prompts) == 1
            else (
                "#!/bin/sh\npython - <<'PY'\n"
                "print('https:' + chr(47) * 2 + 'attacker.example/path')\nPY\n"
            )
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _DollarLiteralRepairClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\npython - <<'PY'\nquery = {'$ne': None}\nPY\n"
            if len(self.prompts) == 1
            else "#!/bin/sh\npython - <<'PY'\nquery = {chr(36) + 'ne': None}\nPY\n"
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _PlaceholderRepairClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\nprintf 'SASTSIMI_POC_INCONCLUSIVE\\n'\nexit 2\n"
            if len(self.prompts) == 1
            else "#!/bin/sh\nprintf 'SASTSIMI_POC_INCONCLUSIVE\\n'\nexit 0\n"
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _ProcessLocalFixtureRepairClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        fixture = (
            "class Fixture:\n    pass\npayload = pickle.dumps(Fixture())\n"
            if len(self.prompts) == 1
            else "payload = pickle.dumps('fixture_value')\n"
        )
        content = (
            "#!/bin/sh\npython3 - <<'PY'\nimport pickle\n"
            + fixture
            + "client = app.test_client()\n"
            "client.set_cookie('value', payload.hex())\n"
            "client.get('/cookie')\nPY\n"
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _AlwaysPlaceholderClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        return SimpleLLMCallResult(
            value={
                "content": (
                    "#!/bin/sh\nif true; then\n"
                    "  printf 'SASTSIMI_POC_INCONCLUSIVE-HIDDEN_SENTINEL\\n'\n"
                    "  exit 2\nfi\n"
                )
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _AlwaysSensitiveClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        return SimpleLLMCallResult(
            value={"content": "#!/bin/sh\ncookie=never-print-this-cookie\nprintf x\n"},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _SourceRecordingClient:
    def __init__(self) -> None:
        self.prompt = b""

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompt = kwargs["prompt"]
        return SimpleLLMCallResult(
            value={"content": "#!/bin/sh\nprintf 'reproduced\\n'\n"},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


@pytest.mark.asyncio
async def test_poc_candidate_receives_pinned_pro_con_source_without_path_request(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    source_ref = artifacts.put_json(
        {
            "kind": "simple_surface_context_v2",
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "path": "main.py",
            "source_status": "AVAILABLE",
            "source_sha256": "b" * 64,
            "source_lines": [
                {"line": 1, "text": "async def get_sql_db():"},
                {
                    "line": 2,
                    "text": "    return await aiosqlite.connect(database='fixture.db')",
                },
            ],
        }
    )
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "surface_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {"code_locations": ["main.py:1"]},
        }
    )
    pro_ref = artifacts.put_json(
        {"kind": "simple_pro_evidence", "result": {"requested_paths": []}}
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref, source_ref),
        input_hash=input_reference_hash((proposal_ref, source_ref)),
        output_refs=(pro_ref,),
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _SourceRecordingClient()

    await PoCCandidateStage(client=client, artifacts=artifacts)(
        checkpoint, {SimpleStage.PRO_CON_DONE: pro_con}
    )

    assert b"aiosqlite.connect(database='fixture.db')" in client.prompt


@pytest.mark.asyncio
async def test_poc_candidate_prompt_separates_target_http_failure_from_harness_failure(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _SourceRecordingClient()

    await PoCCandidateStage(client=client, artifacts=artifacts)(checkpoint, {})

    assert b"normal application error handling" in client.prompt
    assert b"target HTTP 5xx response" in client.prompt
    assert b"do not report it as reproduced" in client.prompt
    assert b"exit 0 for a completed observation" in client.prompt
    assert b"SASTSIMI_POC_INCONCLUSIVE" in client.prompt


@pytest.mark.asyncio
async def test_poc_candidate_excludes_other_candidate_shared_batch_source(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    current_source = (
        'def current_route():\n    return "CURRENT_CANDIDATE_ROUTE_MARKER"\n'
    )
    other_source = 'def other_route():\n    return "OTHER_CANDIDATE_ROUTE_MARKER"\n'
    (workspace / "current.py").write_text(current_source, encoding="utf-8")
    (workspace / "other.py").write_text(other_source, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(
        ["git", "-C", str(workspace), "add", "current.py", "other.py"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=SASTSIMI Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "pinned fixture",
        ],
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"])
        .decode("ascii")
        .strip()
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id=commit,
        hypothesis_id="hypothesis-current",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    shared_ref = artifacts.put_json(
        {
            "kind": "simple_candidate_file_context_v2",
            "workspace_id": identity.workspace_id,
            "commit_id": commit,
            "path": "current.py",
            "source_status": "AVAILABLE",
            "source_sha256": hashlib.sha256(current_source.encode()).hexdigest(),
            "source_lines": [
                {"line": line, "text": text}
                for line, text in enumerate(current_source.splitlines(), start=1)
            ],
            "related_source_files": [
                {
                    "path": "other.py",
                    "source_status": "AVAILABLE",
                    "source_sha256": hashlib.sha256(other_source.encode()).hexdigest(),
                    "source_lines": [
                        {"line": line, "text": text}
                        for line, text in enumerate(other_source.splitlines(), start=1)
                    ],
                }
            ],
            "candidate_call_paths": [
                {
                    "candidate_id": "C-000",
                    "status": "AVAILABLE",
                    "gaps": [],
                    "paths": [
                        {
                            "kind": "call_path_v1",
                            "steps": [
                                {"role": "ROUTE_ENTRY", "path": "other.py", "line": 1}
                            ],
                        }
                    ],
                },
                {
                    "candidate_id": "C-001",
                    "status": "AVAILABLE",
                    "gaps": [],
                    "paths": [
                        {
                            "kind": "call_path_v1",
                            "steps": [
                                {"role": "ROUTE_ENTRY", "path": "current.py", "line": 1}
                            ],
                        }
                    ],
                },
            ],
        }
    )
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": commit,
            "hypothesis_id": identity.hypothesis_id,
            "candidate_id": "C-001",
            "shared_context_ref": shared_ref.model_dump(mode="json"),
            "proposal": {"code_locations": ["current.py:1"]},
        }
    )
    pro_con_inputs = (proposal_ref, shared_ref)
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=pro_con_inputs,
        input_hash=input_reference_hash(pro_con_inputs),
        output_refs=(),
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(shared_ref,),
        input_hash=input_reference_hash((shared_ref,)),
        attempt_id="attempt-1",
    )
    client = _SourceRecordingClient()

    result = await PoCCandidateStage(
        client=client, artifacts=artifacts, workspace_path=workspace
    )(checkpoint, {SimpleStage.PRO_CON_DONE: pro_con})

    assert b"CURRENT_CANDIDATE_ROUTE_MARKER" in client.prompt
    assert b"OTHER_CANDIDATE_ROUTE_MARKER" not in client.prompt
    prompt_context = json.loads(
        client.prompt.split(b"<UNTRUSTED_EXACT_INPUTS>\n", 1)[1].split(
            b"\n</UNTRUSTED_EXACT_INPUTS>", 1
        )[0]
    )
    prompt_refs = [
        StoredDataRef.model_validate(item["reference"])
        for item in prompt_context["exact_inputs"]
    ]
    assert proposal_ref in prompt_refs
    assert shared_ref not in prompt_refs
    stored = json.loads(artifacts.read(result.output_refs[0]))
    saved_refs = [StoredDataRef.model_validate(raw) for raw in stored["source_refs"]]
    assert proposal_ref in saved_refs
    assert shared_ref not in saved_refs
    assert all(
        b"OTHER_CANDIDATE_ROUTE_MARKER" not in artifacts.read(ref) for ref in saved_refs
    )


@pytest.mark.asyncio
async def test_poc_candidate_rejects_cross_hypothesis_pro_con_source(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    source_ref = artifacts.put_json(
        {
            "kind": "simple_surface_context_v2",
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "path": "main.py",
            "source_status": "AVAILABLE",
            "source_sha256": "b" * 64,
            "source_lines": [{"line": 1, "text": "cross-hypothesis-marker"}],
        }
    )
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": "other-hypothesis",
            "surface_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {"code_locations": ["main.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref, source_ref),
        input_hash=input_reference_hash((proposal_ref, source_ref)),
        output_refs=(),
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _SourceRecordingClient()

    with pytest.raises(StageFailed) as failure:
        await PoCCandidateStage(client=client, artifacts=artifacts)(
            checkpoint, {SimpleStage.PRO_CON_DONE: pro_con}
        )

    assert failure.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
    assert client.prompt == b""


@pytest.mark.asyncio
async def test_poc_candidate_rejects_partial_pro_con_anchor_before_llm(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    proposal_ref = artifacts.put_json(
        {"kind": "simple_hypothesis_proposal", "hypothesis_id": identity.hypothesis_id}
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
        output_refs=(),
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _SourceRecordingClient()

    with pytest.raises(StageFailed) as failure:
        await PoCCandidateStage(client=client, artifacts=artifacts)(
            checkpoint, {SimpleStage.PRO_CON_DONE: pro_con}
        )

    assert failure.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
    assert client.prompt == b""


@pytest.mark.asyncio
@pytest.mark.parametrize("at_capacity", [False, True])
async def test_poc_candidate_keeps_current_repair_metadata_when_history_is_large(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    at_capacity: bool,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    source_ref = artifacts.put_json(
        {
            "kind": "simple_surface_context_v2",
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "path": "main.py",
            "source_status": "AVAILABLE",
            "source_sha256": "b" * 64,
            "source_lines": [{"line": 1, "text": "route_marker = True"}],
        }
    )
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "surface_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {"code_locations": ["main.py:1"]},
        }
    )
    pro_ref = artifacts.put_json(
        {"kind": "simple_pro_evidence", "result": {"requested_paths": []}}
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref, source_ref),
        input_hash=input_reference_hash((proposal_ref, source_ref)),
        output_refs=(pro_ref,),
    )

    def attempt_refs(attempt_id: str) -> tuple[StoredDataRef, ...]:
        content = b"#!/bin/sh\n#" + attempt_id.encode("ascii")
        if attempt_id == "old-attempt":
            content += b"x " * 3_250
        content_ref = artifacts.put_bytes(content, "text/x-shellscript")
        stderr = attempt_id.encode("ascii")
        if attempt_id == "current-attempt":
            stderr += b"z " * 2_000
            stderr += (
                b"\nRuntimeError: CURRENT_RUNTIME_ERROR_MARKER "
                b"password=supersecretvalue"
            )
        stderr_ref = artifacts.put_bytes(stderr, "text/plain")
        stdout_ref = artifacts.put_bytes(b"", "text/plain")
        candidate_ref = artifacts.put_json(
            {
                "kind": "simple_poc_candidate",
                "source_refs": [],
                "content_ref": content_ref.model_dump(mode="json"),
                "content_digest": hashlib.sha256(content).hexdigest(),
                "prompt_digest": "a" * 64,
                "output_digest": "b" * 64,
                "llm_request_ref": None,
                "llm_response_ref": None,
                "attempt_id": attempt_id,
            }
        )
        execution_ref = artifacts.put_json(
            {
                "kind": "simple_poc_execution",
                "candidate_ref": candidate_ref.model_dump(mode="json"),
                "content_ref": content_ref.model_dump(mode="json"),
                "stdout_ref": stdout_ref.model_dump(mode="json"),
                "stderr_ref": stderr_ref.model_dump(mode="json"),
                "exit_code": 2,
                "timed_out": False,
                "container_id": "fixture-container",
                "image_digest": None,
                "attempt_id": attempt_id,
            }
        )
        return candidate_ref, content_ref, execution_ref, stdout_ref, stderr_ref

    old_refs = attempt_refs("old-attempt")
    current_refs = attempt_refs("current-attempt")
    gate_ref = artifacts.put_json(
        {"kind": "simple_technical_gate", "marker": "GATE_REPAIR_MARKER"}
    )
    decision_ref = artifacts.put_json(
        {"kind": "simple_recovery_decision", "marker": "CURRENT_REPAIR_MARKER"}
    )
    inputs = (gate_ref,) + old_refs + current_refs + (decision_ref,)
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        attempt_id="attempt-3",
        recovery_decision_refs=(decision_ref,),
    ).model_copy(update={"gate_revision_count": 1})
    original_context = artifacts.prompt_context_prioritized

    def is_diagnostic(ref: StoredDataRef) -> bool:
        try:
            record = json.loads(artifacts.read(ref))
        except ValueError:
            return False
        return isinstance(record, dict) and record.get("kind") == (
            "simple_poc_repair_diagnostic"
        )

    def bounded_context(
        required: tuple[StoredDataRef, ...],
        optional: tuple[StoredDataRef, ...],
    ) -> bytes:
        max_bytes = 10_000
        if at_capacity:
            diagnostic_refs = tuple(
                ref for ref in required + optional if is_diagnostic(ref)
            )
            assert len(diagnostic_refs) == 1
            without_diagnostic = tuple(
                ref for ref in required if ref not in diagnostic_refs
            )
            max_bytes = (
                len(original_context(without_diagnostic, (), max_bytes=1_000_000)) + 100
            )
        return original_context(required, optional, max_bytes=max_bytes)

    monkeypatch.setattr(
        artifacts,
        "prompt_context_prioritized",
        bounded_context,
    )
    client = _SourceRecordingClient()

    if at_capacity:
        with pytest.raises(StageFailed) as failure:
            await PoCCandidateStage(client=client, artifacts=artifacts)(
                checkpoint, {SimpleStage.PRO_CON_DONE: pro_con}
            )
        assert failure.value.failure.code == "HYPOTHESIS_CONTEXT_OVERFLOW"
        assert client.prompt == b""
        return

    result = await PoCCandidateStage(client=client, artifacts=artifacts)(
        checkpoint, {SimpleStage.PRO_CON_DONE: pro_con}
    )

    assert b"CURRENT_REPAIR_MARKER" in client.prompt
    assert b"GATE_REPAIR_MARKER" in client.prompt
    assert b"CURRENT_RUNTIME_ERROR_MARKER" in client.prompt
    assert b"supersecretvalue" not in client.prompt
    assert b"z " * 1_500 not in client.prompt
    assert current_refs[0].content_hash.encode("ascii") in client.prompt
    assert current_refs[2].content_hash.encode("ascii") in client.prompt
    stored = json.loads(artifacts.read(result.output_refs[0]))
    assert old_refs[1].model_dump(mode="json") not in stored["source_refs"]
    assert old_refs[4].model_dump(mode="json") not in stored["source_refs"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("padding", "evidence_padding", "expected_overflow"),
    [
        (150_000, 60_000, False),
        (200_000, 0, False),
        (200_000, 60_000, True),
        (270_000, 0, True),
    ],
)
async def test_poc_candidate_handles_source_context_budget_without_truncating_helper(
    tmp_path: Path,
    padding: int,
    evidence_padding: int,
    expected_overflow: bool,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source_lines = [
        "async def route():",
        "    return 1",
        *("# small context" for _ in range(16)),
        "#" + "x" * padding,
        "async def get_sql_db():",
        "    return await aiosqlite.connect(database='fixture.db')",
    ]
    source = "\n".join(source_lines) + "\n"
    (workspace / "main.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "add", "main.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=SASTSIMI Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "pinned fixture",
        ],
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"])
        .decode("ascii")
        .strip()
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id=commit,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    source_ref = artifacts.put_json(
        {
            "kind": "simple_surface_context_v2",
            "workspace_id": identity.workspace_id,
            "commit_id": commit,
            "path": "main.py",
            "source_status": "AVAILABLE",
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "source_lines": [
                {"line": number, "text": text}
                for number, text in enumerate(source_lines, start=1)
            ],
        }
    )
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": commit,
            "hypothesis_id": identity.hypothesis_id,
            "surface_context_ref": source_ref.model_dump(mode="json"),
            "proposal": {"code_locations": ["main.py:1"]},
        }
    )
    pro_ref = artifacts.put_json(
        {
            "kind": "simple_pro_evidence",
            "result": {
                "evidence": "x" * evidence_padding + "PRO_END_MARKER",
                "requested_paths": [],
            },
        }
    )
    initial_ref = artifacts.put_json(
        {"kind": "simple_initial_verification", "marker": "INITIAL_MARKER"}
    )
    feedback_ref = artifacts.put_json(
        {
            "kind": "simple_technical_gate",
            "result": {"revision_requests": ["GATE_MARKER"]},
        }
    )
    repair_ref = artifacts.put_json(
        {"kind": "simple_current_repair_context", "marker": "REPAIR_MARKER"}
    )
    recipe_ref = artifacts.put_json(
        {"kind": "simple_container_recipe", "marker": "RECIPE_MARKER"}
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref, source_ref),
        input_hash=input_reference_hash((proposal_ref, source_ref)),
        output_refs=(pro_ref,),
    )
    initial = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(initial_ref,),
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(feedback_ref, repair_ref),
        input_hash=input_reference_hash((feedback_ref, repair_ref)),
        attempt_id="attempt-1",
        recipe_ref=recipe_ref,
    ).model_copy(update={"gate_revision_count": 1})
    client = _SourceRecordingClient()

    stage = PoCCandidateStage(
        client=client, artifacts=artifacts, workspace_path=workspace
    )
    prior = {
        SimpleStage.PRO_CON_DONE: pro_con,
        SimpleStage.VERIFICATION_INITIAL_DONE: initial,
    }
    if expected_overflow:
        with pytest.raises(StageFailed) as failure:
            await stage(checkpoint, prior)
        assert failure.value.failure.code == "HYPOTHESIS_CONTEXT_OVERFLOW"
        assert client.prompt == b""
    else:
        await stage(checkpoint, prior)
        assert b"aiosqlite.connect(database='fixture.db')" in client.prompt
        assert b"PRO_END_MARKER" in client.prompt
        assert b"INITIAL_MARKER" in client.prompt
        assert b"GATE_MARKER" in client.prompt
        assert b"REPAIR_MARKER" in client.prompt
        assert b"RECIPE_MARKER" in client.prompt
        assert proposal_ref.content_hash.encode("ascii") in client.prompt


@pytest.mark.asyncio
async def test_poc_candidate_receives_requested_tracked_source_with_provenance(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "pkg").mkdir(parents=True)
    (workspace / "pkg" / "watch.py").write_text(
        "class Watch:\n    def __init__(self, **kwargs):\n"
        "        self.datastore = kwargs['datastore']\n",
        encoding="utf-8",
    )
    (workspace / "pkg" / "oversize.py").write_text("x" * 140_000, encoding="utf-8")
    storage_source = (
        "async def get_sql_db():\n"
        "    return await aiosqlite.connect(database='fixture.db')\n"
    )
    (workspace / "pkg" / "storage.py").write_text(storage_source, encoding="utf-8")
    (workspace / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    (workspace / "private.txt").write_text("private-marker", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "add",
            "pkg/watch.py",
            "pkg/storage.py",
            "pkg/oversize.py",
            "Dockerfile",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=SASTSIMI Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "pinned fixture",
        ],
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"])
        .decode("ascii")
        .strip()
    )
    (workspace / "pkg" / "watch.py").write_text(
        "class Watch:\n    # dirty-workspace-marker\n",
        encoding="utf-8",
    )
    (workspace / "pkg" / "storage.py").write_text(
        "# dirty-storage-marker\n", encoding="utf-8"
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id=commit,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    manifest_ref = artifacts.put_json(
        {
            "kind": "simple_tracked_sources",
            "paths": ["pkg/watch.py", "pkg/oversize.py"],
        }
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "poc_source_manifest_ref": artifacts.put_json(
                {
                    "kind": "simple_tracked_sources",
                    "paths": [
                        "pkg/watch.py",
                        "pkg/storage.py",
                        "pkg/oversize.py",
                        "Dockerfile",
                    ],
                }
            ).model_dump(mode="json"),
        }
    )
    oversized_prior_ref = artifacts.put_json(
        {"kind": "oversized_prior_context", "content": "x" * 300_000}
    )
    pro_ref = artifacts.put_json(
        {
            "kind": "simple_pro_evidence",
            "result": {
                "requested_paths": [
                    "pkg/watch.py",
                    "Dockerfile",
                    "pkg/oversize.py",
                    "private.txt",
                    "../outside",
                ]
            },
        }
    )
    con_ref = artifacts.put_json(
        {"kind": "simple_con_evidence", "result": {"requested_paths": []}}
    )
    source_context_ref = artifacts.put_json(
        {
            "kind": "simple_surface_context_v2",
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "path": "pkg/storage.py",
            "source_status": "AVAILABLE",
            "source_sha256": hashlib.sha256(storage_source.encode()).hexdigest(),
            "source_lines": [
                {"line": number, "text": text}
                for number, text in enumerate(storage_source.splitlines(), start=1)
            ],
        }
    )
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "surface_context_ref": source_context_ref.model_dump(mode="json"),
            "proposal": {"code_locations": ["pkg/storage.py:1"]},
        }
    )
    verification_ref = artifacts.put_json(
        {"kind": "simple_initial_verification", "marker": "core-verification-marker"}
    )
    prior = {
        SimpleStage.HYPOTHESIS_DONE: StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(bundle_ref,),
            input_hash=input_reference_hash((bundle_ref,)),
            output_refs=(oversized_prior_ref,),
        ),
        SimpleStage.PRO_CON_DONE: StageCheckpoint(
            identity=identity,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(proposal_ref, source_context_ref),
            input_hash=input_reference_hash((proposal_ref, source_context_ref)),
            output_refs=(pro_ref, con_ref),
        ),
        SimpleStage.VERIFICATION_INITIAL_DONE: StageCheckpoint(
            identity=identity,
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(bundle_ref,),
            input_hash=input_reference_hash((bundle_ref,)),
            output_refs=(verification_ref,),
        ),
    }
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(bundle_ref,),
        input_hash=input_reference_hash((bundle_ref,)),
        attempt_id="attempt-1",
    )
    client = _SourceRecordingClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=artifacts,
        workspace_path=workspace,
        static_bundle_ref=bundle_ref,
    )

    result = await stage(checkpoint, prior)

    assert b"def __init__(self, **kwargs)" in client.prompt
    assert b"FROM python:3.12-slim" in client.prompt
    assert b"dirty-workspace-marker" not in client.prompt
    assert b"core-verification-marker" in client.prompt
    assert b"simple_pro_evidence" in client.prompt
    assert b"private-marker" not in client.prompt
    assert b"aiosqlite.connect(database='fixture.db')" in client.prompt
    assert b"dirty-storage-marker" not in client.prompt
    prompt_context = json.loads(
        client.prompt.split(b"<UNTRUSTED_EXACT_INPUTS>\n", 1)[1].split(
            b"\n</UNTRUSTED_EXACT_INPUTS>", 1
        )[0]
    )
    context_refs = [
        StoredDataRef.model_validate(item["reference"])
        for item in prompt_context["exact_inputs"]
    ]
    assert source_context_ref in context_refs
    assert oversized_prior_ref not in context_refs
    assert prompt_context["omitted_optional_refs"] >= 1
    assert b"Treat /workspace as\nimmutable product source" in client.prompt
    assert b"runtime storage" in client.prompt
    assert b"__file__-derived workspace path" in client.prompt
    assert b"temporary runtime wrapper" in client.prompt
    assert b"entire PoC execution" in client.prompt
    assert b"copy the existing database" in client.prompt
    assert b"multiple or dynamic" in client.prompt
    assert b"restore the original operation after startup" not in client.prompt
    assert b"ModuleNotFoundError" in client.prompt
    assert b"exc.name" in client.prompt
    assert b"safe dotted module identifier" in b" ".join(client.prompt.split())
    assert b"one coherent import root" in client.prompt
    assert b"Do not put both /workspace and a child source directory" in client.prompt
    assert b"For a Python NameError" in client.prompt
    assert b"safe simple identifier" in client.prompt
    assert b"transitive closure" in client.prompt
    assert b"Keep the working directory at /workspace" in client.prompt
    assert b"relative static" in client.prompt
    assert b"For a Python AttributeError" in client.prompt
    assert b"module-level setter" in client.prompt
    candidate = json.loads(artifacts.read(result.output_refs[0]))
    assert oversized_prior_ref.model_dump(mode="json") not in candidate["source_refs"]
    source_records = [
        json.loads(artifacts.read(StoredDataRef.model_validate(raw_ref)))
        for raw_ref in candidate["source_refs"]
    ]
    retrieved = next(
        record
        for record in source_records
        if record.get("kind") == "simple_requested_sources"
    )
    source_ref = next(
        StoredDataRef.model_validate(raw_ref)
        for raw_ref in candidate["source_refs"]
        if json.loads(artifacts.read(StoredDataRef.model_validate(raw_ref))).get("kind")
        == "simple_requested_sources"
    )
    assert source_ref in result.output_refs[2:]
    assert [item["path"] for item in retrieved["served"]] == [
        "pkg/watch.py",
        "Dockerfile",
    ]
    assert {item["reason"] for item in retrieved["refused"]} == {
        "TOTAL_BUDGET_EXHAUSTED",
        "NOT_TRACKED",
        "PATH_OUTSIDE_REPOSITORY",
    }


@pytest.mark.asyncio
async def test_gate_feedback_precedes_bulk_context_and_is_forwarded(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    bulk_ref = artifacts.put_json({"kind": "bulk", "content": "x" * 300_000})
    feedback_ref = artifacts.put_json(
        {
            "kind": "simple_technical_gate",
            "result": {
                "status": "REVISE",
                "revision_requests": ["production-route-marker"],
            },
        }
    )
    prior = {
        SimpleStage.HYPOTHESIS_DONE: StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(bulk_ref,),
        )
    }
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(feedback_ref,),
        input_hash=input_reference_hash((feedback_ref,)),
        attempt_id="revised-poc",
    ).model_copy(update={"gate_revision_count": 1})
    client = _SourceRecordingClient()

    result = await PoCCandidateStage(client=client, artifacts=artifacts)(
        checkpoint, prior
    )

    assert b"production-route-marker" in client.prompt
    assert feedback_ref in result.output_refs[2:]


@pytest.mark.asyncio
async def test_poc_candidate_rejects_truncated_core_without_pro_con_anchor(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    core_ref = artifacts.put_json(
        {
            "kind": "simple_initial_verification",
            "evidence": "x" * 270_000 + "INITIAL_END_MARKER",
        }
    )
    initial = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(core_ref,),
    )
    feedback_ref = artifacts.put_json(
        {"kind": "simple_technical_gate", "marker": "GATE_MARKER"}
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(feedback_ref,),
        input_hash=input_reference_hash((feedback_ref,)),
        attempt_id="attempt-1",
    ).model_copy(update={"gate_revision_count": 1})
    client = _SourceRecordingClient()

    with pytest.raises(StageFailed) as failure:
        await PoCCandidateStage(client=client, artifacts=artifacts)(
            checkpoint, {SimpleStage.VERIFICATION_INITIAL_DONE: initial}
        )

    assert failure.value.failure.code == "HYPOTHESIS_CONTEXT_OVERFLOW"
    assert client.prompt == b""


@pytest.mark.asyncio
async def test_sensitive_candidate_repair_explains_secret_shaped_names(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _RepairClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"concise error type and traceback to stderr" in client.prompts[0]
    assert b"secret-shaped identifiers" in client.prompts[1]
    assert b"cookie, session, token" in client.prompts[1]
    assert b"COOKIE" in client.prompts[1]
    assert b"line 2" in client.prompts[1]
    assert b"never-print-this-cookie" not in client.prompts[1]


@pytest.mark.asyncio
async def test_second_sensitive_rejection_persists_only_category_and_line(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    client = _AlwaysSensitiveClient()

    with pytest.raises(StageBlocked) as blocked:
        await PoCCandidateStage(client=client, artifacts=artifacts)(checkpoint, {})

    assert blocked.value.failure.code == "POC_SENSITIVE_CONTENT"
    assert len(client.prompts) == 2
    assert all(b"never-print-this-cookie" not in prompt for prompt in client.prompts)
    assert len(blocked.value.failure.evidence_refs) == 1
    diagnostic = json.loads(artifacts.read(blocked.value.failure.evidence_refs[0]))
    assert diagnostic["reason"] == "SENSITIVE_CONTENT"
    assert diagnostic["sensitive_category"] == "COOKIE"
    assert diagnostic["sensitive_line"] == 2
    assert "never-print-this-cookie" not in json.dumps(diagnostic)


@pytest.mark.asyncio
async def test_host_path_repair_explains_how_to_build_backslash_url_fixtures(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _HostPathRepairClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"external-looking and backslash-confused URL fixtures" in client.prompts[0]
    assert b"construct them at runtime" in client.prompts[0]
    assert b"construct backslash-confused URL fixtures at runtime" in client.prompts[1]
    assert b"chr(92)" in client.prompts[1]


@pytest.mark.asyncio
async def test_external_url_repair_keeps_network_off_and_builds_fixture_at_runtime(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _ExternalUrlRepairClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"external-looking and backslash-confused URL fixtures" in client.prompts[0]
    assert b"construct them at runtime" in client.prompts[0]
    assert b"must not make an external network request" in client.prompts[1]
    assert b"construct the URL fixture at runtime" in client.prompts[1]


@pytest.mark.asyncio
async def test_literal_dollar_data_key_guidance_preserves_candidate_guard(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _DollarLiteralRepairClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"chr(36)" in client.prompts[0]
    assert b"POC_UNDECLARED_INPUT" in client.prompts[1]
    assert b"chr(36)" in client.prompts[1]


@pytest.mark.asyncio
async def test_placeholder_repair_guidance_distinguishes_observation_from_runtime_error(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _PlaceholderRepairClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"POC_PLACEHOLDER_FORBIDDEN" in client.prompts[1]
    assert b"exit 0 for a completed inconclusive observation" in client.prompts[1]
    assert b"exit 2 only for a real harness/runtime error" in client.prompts[1]


@pytest.mark.asyncio
async def test_poc_candidate_repairs_process_local_pickle_fixture(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _ProcessLocalFixtureRepairClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"POC_PROCESS_LOCAL_FIXTURE_UNVERIFIED" in client.prompts[1]
    assert b"PoC-only class" in client.prompts[1]


def test_unresolved_local_pickle_sent_to_test_client_is_rejected() -> None:
    content = (
        b"#!/bin/sh\npython3 - <<'PY'\n"
        b"import pickle\n"
        b"class LocalOnly: pass\n"
        b"body = pickle.dumps(LocalOnly()).hex()\n"
        b"client = app.test_client()\n"
        b"client.post('/ingest', json={'payload': body})\n"
        b"PY\n"
    )

    with pytest.raises(
        PoCCandidateRejected, match="POC_PROCESS_LOCAL_FIXTURE_UNVERIFIED"
    ):
        _require_independent_poc_fixture(content)


@pytest.mark.asyncio
async def test_second_candidate_rejection_persists_only_safe_diagnostic(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)

    with pytest.raises(StageBlocked) as blocked:
        await PoCCandidateStage(client=_AlwaysPlaceholderClient(), artifacts=artifacts)(
            checkpoint, {}
        )

    assert blocked.value.failure.code == "POC_PLACEHOLDER_FORBIDDEN"
    assert len(blocked.value.failure.evidence_refs) == 1
    diagnostic = json.loads(artifacts.read(blocked.value.failure.evidence_refs[0]))
    assert diagnostic == {
        "kind": "simple_poc_candidate_rejection_diagnostic",
        "reason": "INCONCLUSIVE_EXIT2_UNPROVEN",
        "line_count": 5,
        "branch_count": 1,
        "inconclusive_line_count": 1,
        "exit_two_line_count": 1,
        "exit_zero_line_count": 0,
    }
    assert "HIDDEN_SENTINEL" not in json.dumps(diagnostic)
