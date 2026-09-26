from __future__ import annotations

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
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.stages import PoCCandidateStage


class _RepairClient:
    def __init__(self) -> None:
        self.prompts: list[bytes] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\ncookie=fixture_value\nprintf x\n"
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
    (workspace / "private.txt").write_text("private-marker", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(
        ["git", "-C", str(workspace), "add", "pkg/watch.py", "pkg/oversize.py"],
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
            input_refs=(bundle_ref,),
            input_hash=input_reference_hash((bundle_ref,)),
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
    assert b"dirty-workspace-marker" not in client.prompt
    assert b"core-verification-marker" in client.prompt
    assert b"simple_pro_evidence" in client.prompt
    assert b"private-marker" not in client.prompt
    candidate = json.loads(artifacts.read(result.output_refs[0]))
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
    assert [item["path"] for item in retrieved["served"]] == ["pkg/watch.py"]
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
