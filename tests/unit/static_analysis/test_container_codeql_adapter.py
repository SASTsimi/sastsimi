"""Container CodeQL process adapter closes identity before Docker execution."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    StaticRuleMapping,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.static_analysis.codeql_adapter import decode_codeql_sarif, digest_path
from sastsimi.static_analysis.codeql_registry import (
    CodeQLDatabaseIdentity,
    publish_codeql_database,
)
from sastsimi.static_analysis.container_codeql import ContainerCodeQLSpec
from sastsimi.static_analysis.container_codeql_adapter import (
    ContainerCodeQLAdapterInputs,
    ContainerCodeQLProcessAdapter,
)
from sastsimi.static_analysis.container_codeql_runtime import CodeQLArtifactIdentity
from tests.contract.domain.canonical_fixtures import host_ref, make
from tests.contract.domain.fixtures import meta
from tests.contract.domain.fixtures import ref as fixture_ref
from tests.unit.static_analysis.test_container_codeql_runtime import FakeDockerPort

_COMMIT_ID = "a" * 40
_MANIFEST_SHA256 = "b" * 64
_REPOSITORY_URL = "https://example.invalid/owner/repository.git"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _profile(executable: Path, *, query_pack_sha256: str) -> StaticToolProfile:
    profile_meta = meta("static_tool_profile", attempt=None)
    profile_meta.update(
        commit_id=_COMMIT_ID,
        created_at=datetime(2026, 9, 19, tzinfo=UTC),
    )
    return StaticToolProfile.model_validate(
        {
            "meta": profile_meta,
            "host_id": "host1",
            "profile_key": "container-codeql-production",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": "CODEQL",
            "tool_name": "CODEQL",
            "tool_kind": "RULE_BASED",
            "executable_key": "docker",
            "executable_sha256": _sha256(executable),
            "expected_version": "2.20.0",
            "capability_evidence_ref": host_ref("tool_capability_evidence"),
            "codeql_boundary": {
                "quota_backend_key": "CONTAINER_TMPFS_CAP_PLUS_ONE",
                "quota_enforcement_identity_sha256": content_hash(
                    {
                        "image_digest": "sha256:" + "e" * 64,
                        "user": "65532:65532",
                        "pids_limit": 64,
                        "memory_limit_bytes": 536_870_912,
                        "nano_cpus": 500_000_000,
                        "database_limit_bytes": 268_435_456,
                        "output_limit_bytes": 16_777_216,
                    }
                ),
                "database_limit_bytes": 268_435_456,
                "execution_limit_bytes": 16_777_216,
                "database_provider_key": "controlled-provider",
                "database_provider_revision": "2026-09-19.1",
                "database_provider_evidence_sha256": "d" * 64,
                "image_digest": "sha256:" + "e" * 64,
                "expected_codeql_version": "2.20.0",
                "query_pack_sha256": query_pack_sha256,
                "container_user": "65532:65532",
                "pids_limit": 64,
                "memory_limit_bytes": 536_870_912,
                "nano_cpus": 500_000_000,
                "supported_languages": ("PYTHON",),
                "prebuilt_database_only": True,
            },
            "probe_timeout_ms": 1_000,
            "run_timeout_ms": 5_000,
            "stdout_limit_bytes": 65_536,
            "stderr_limit_bytes": 1_024,
            "max_attempt_output_bytes": 16_777_216,
            "max_output_file_bytes": 65_536,
            "max_artifact_read_bytes": 65_536,
        }
    )


def _request(
    profile: StaticToolProfile,
) -> tuple[CodeWorkspace, StaticToolRequest, StoredDataRef, StoredDataRef]:
    workspace_data = make("CodeWorkspace")
    workspace_data.update(
        workspace_id="ws1",
        repository_url=_REPOSITORY_URL,
        commit_id=_COMMIT_ID,
        status="READY",
    )
    workspace = CodeWorkspace.model_validate_json(json.dumps(workspace_data))
    workspace_ref = reference(workspace)
    profile_ref = cast(HostConfigurationRef, reference(profile))
    analysis_data = fixture_ref("analysis_config") | {"commit_id": _COMMIT_ID}
    catalog_data = fixture_ref("rule_catalog") | {"commit_id": _COMMIT_ID}
    analysis_ref = StoredDataRef.model_validate(analysis_data)
    catalog_ref = StoredDataRef.model_validate(catalog_data)
    action_data = make("ActionRequest", "action_request")
    action_data["meta"].update(commit_id=_COMMIT_ID, attempt_id="at1")
    action_data.update(
        requested_by="STATIC_ANALYSIS",
        action_type="RUN_TOOL",
        tool_name="CODEQL",
        file_paths=("src/app.py", "src/mid.py", "src/sink.py"),
        input_refs=tuple(
            item.model_dump(mode="json")
            for item in (workspace_ref, profile_ref, analysis_ref, catalog_ref)
        ),
    )
    action = ActionRequest.model_validate_json(json.dumps(action_data))
    return (
        workspace,
        StaticToolRequest(
            action=action,
            workspace=workspace,
            tool_profile_ref=profile_ref,
            analysis_config_ref=analysis_ref,
            rule_catalog_ref=catalog_ref,
        ),
        analysis_ref,
        catalog_ref,
    )


def _sarif() -> bytes:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "version": "2.20.0",
                            "rules": [{"id": "R1"}, {"id": "R2"}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "R2",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {
                                            "startLine": 7,
                                            "startColumn": 1,
                                            "endLine": 7,
                                            "endColumn": 2,
                                        },
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
        separators=(",", ":"),
    ).encode()


def _deadline(action_id: str) -> MonotonicActionDeadline:
    return MonotonicActionDeadline(
        action_id=action_id,
        started_ns=0,
        expires_ns=10**18,
    )


def test_public_sarif_decoder_reuses_the_codeql_contract() -> None:
    """Keeps the container adapter off CodeQL decoder implementation details."""

    rules, facts, relations, gaps = decode_codeql_sarif(
        _sarif(),
        rule_catalog=(
            StaticRuleMapping("R1", "SINK", "SOURCE", True),
            StaticRuleMapping("R2", "VALIDATOR", None, False),
        ),
        selected_rule_ids=("R1", "R2"),
        tracked_paths=("src/app.py", "src/mid.py", "src/sink.py"),
        expected_version="2.20.0",
    )

    assert [(item.rule_id, item.hit_count) for item in rules] == [
        ("R1", 0),
        ("R2", 1),
    ]
    assert [item.fact_kind for item in facts] == ["VALIDATOR"]
    assert relations == ()
    assert gaps == ()


def test_public_sarif_decoder_accepts_codeql_semantic_version() -> None:
    payload = json.loads(_sarif())
    driver = payload["runs"][0]["tool"]["driver"]
    driver["semanticVersion"] = driver.pop("version")

    rules, facts, relations, gaps = decode_codeql_sarif(
        json.dumps(payload, separators=(",", ":")).encode(),
        rule_catalog=(
            StaticRuleMapping("R1", "SINK", "SOURCE", True),
            StaticRuleMapping("R2", "VALIDATOR", None, False),
        ),
        selected_rule_ids=("R1", "R2"),
        tracked_paths=("src/app.py", "src/mid.py", "src/sink.py"),
        expected_version="2.20.0",
    )

    assert [(item.rule_id, item.hit_count) for item in rules] == [("R1", 0), ("R2", 1)]
    assert [item.fact_kind for item in facts] == ["VALIDATOR"]
    assert relations == ()
    assert gaps == ()


@pytest.fixture
def adapter_fixture(tmp_path: Path) -> dict[str, Any]:
    docker = tmp_path / "docker-approved"
    docker.write_bytes(b"approved-docker-capability")
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    query_pack = tmp_path / "query-pack"
    query_pack.mkdir()
    (query_pack / "query.ql").write_text("select 1", encoding="utf-8")
    database_source = tmp_path / "database-source"
    database_source.mkdir()
    (database_source / "codeql-database.yml").write_text(
        "primaryLanguage: python\n", encoding="utf-8"
    )
    registry = tmp_path / "registry"
    registry.mkdir()
    database_identity = CodeQLDatabaseIdentity(
        repository_url=_REPOSITORY_URL,
        commit_id=_COMMIT_ID,
        language="python",
        tracked_manifest_sha256=_MANIFEST_SHA256,
        provider_key="controlled-provider",
        provider_revision="2026-09-19.1",
        provider_evidence_sha256="d" * 64,
    )
    database = publish_codeql_database(
        registry_root=registry,
        database_root=database_source,
        identity=database_identity,
    )
    tool_profile = _profile(docker, query_pack_sha256=digest_path(query_pack))
    workspace, request, analysis_ref, catalog_ref = _request(tool_profile)
    artifact_identity = CodeQLArtifactIdentity(
        database_digest="sha256:" + database.database_digest,
        tracked_manifest_digest="sha256:" + _MANIFEST_SHA256,
        query_digest="sha256:" + digest_path(query_pack),
    )
    spec = ContainerCodeQLSpec(
        docker_executable=docker,
        image_digest="sha256:" + "e" * 64,
        database_source=database.database_root,
        query_pack_source=query_pack,
        workspace_root=workspace_root,
        action_id=str(request.action.action_id),
        attempt_id="at1",
        user="65532:65532",
        pids_limit=64,
        memory_limit_bytes=536_870_912,
        cpu_limit_millicores=500,
        database_limit_bytes=268_435_456,
        output_limit_bytes=16_777_216,
    )
    inputs = ContainerCodeQLAdapterInputs(
        database=database,
        spec=spec,
        artifact_identity=artifact_identity,
        analysis_config_ref=analysis_ref,
        rule_catalog_ref=catalog_ref,
        rule_catalog=(
            StaticRuleMapping("R1", "SINK", "SOURCE", True),
            StaticRuleMapping("R2", "VALIDATOR", None, False),
        ),
        selected_rule_ids=("R1", "R2"),
        selected_rule_packs=("fixture/security",),
        tracked_files=tuple(
            TrackedFile(path, "100644", f"blob-{index}", 1)
            for index, path in enumerate(("src/app.py", "src/mid.py", "src/sink.py"))
        ),
    )
    port = FakeDockerPort(spec)
    port.stdout_chunks = (_sarif(),)
    adapter = ContainerCodeQLProcessAdapter(
        executable=docker,
        executable_key="docker",
        inputs=inputs,
        port=port,
    )
    return {
        "adapter": adapter,
        "inputs": inputs,
        "port": port,
        "profile": tool_profile,
        "request": request,
        "workspace": workspace,
        "workspace_root": workspace_root,
        "executable": docker,
    }


@pytest.mark.asyncio
async def test_success_decodes_only_bound_sarif_into_static_observation(
    adapter_fixture: dict[str, Any],
) -> None:
    """Catches returning opaque SARIF or treating a real hit as zero hits."""

    adapter = cast(ContainerCodeQLProcessAdapter, adapter_fixture["adapter"])
    request = cast(StaticToolRequest, adapter_fixture["request"])
    profile = cast(StaticToolProfile, adapter_fixture["profile"])
    workspace_root = cast(Path, adapter_fixture["workspace_root"])
    port = cast(FakeDockerPort, adapter_fixture["port"])

    observed = await adapter.execute(
        request,
        workspace_root,
        profile,
        _deadline(str(request.action.action_id)),
    )

    assert observed.status == "SUCCEEDED"
    assert observed.raw_output == _sarif()
    assert observed.raw_media_type == "application/sarif+json"
    assert [(item.rule_id, item.hit_count) for item in observed.rules] == [
        ("R1", 0),
        ("R2", 1),
    ]
    assert [item.fact_kind for item in observed.facts] == ["VALIDATOR"]
    assert [operation for operation, _value in port.operations] == [
        "create",
        "inspect",
        "start",
        "wait",
        "logs",
        "remove",
    ]


@pytest.mark.asyncio
async def test_started_container_run_emits_one_exact_execution_receipt(
    adapter_fixture: dict[str, Any],
) -> None:
    inputs = cast(ContainerCodeQLAdapterInputs, adapter_fixture["inputs"])
    request = cast(StaticToolRequest, adapter_fixture["request"])
    profile = cast(StaticToolProfile, adapter_fixture["profile"])
    workspace_root = cast(Path, adapter_fixture["workspace_root"])
    executable = cast(Path, adapter_fixture["executable"])
    port = cast(FakeDockerPort, adapter_fixture["port"])
    receipts: list[tuple[str, int]] = []
    adapter = ContainerCodeQLProcessAdapter(
        executable=executable,
        executable_key="docker",
        inputs=inputs,
        port=port,
        execution_receipt=lambda result, elapsed_ms: receipts.append(
            (result.status.value, elapsed_ms)
        ),
    )

    observed = await adapter.execute(
        request,
        workspace_root,
        profile,
        _deadline(str(request.action.action_id)),
    )

    assert observed.status == "SUCCEEDED"
    assert len(receipts) == 1
    assert receipts[0][0] == "SUCCEEDED"
    assert receipts[0][1] >= 0


@pytest.mark.asyncio
async def test_nonzero_container_result_is_failure_not_zero_hits(
    adapter_fixture: dict[str, Any],
) -> None:
    """Catches a failed CodeQL run being represented as an empty success."""

    adapter = cast(ContainerCodeQLProcessAdapter, adapter_fixture["adapter"])
    request = cast(StaticToolRequest, adapter_fixture["request"])
    profile = cast(StaticToolProfile, adapter_fixture["profile"])
    workspace_root = cast(Path, adapter_fixture["workspace_root"])
    port = cast(FakeDockerPort, adapter_fixture["port"])
    port.exit_code = 9

    observed = await adapter.execute(
        request,
        workspace_root,
        profile,
        _deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert observed.raw_output is None
    assert observed.gaps[0].code == "CODEQL_CONTAINER_EXIT_NONZERO"
    assert observed.errors[0].code == "CODEQL_CONTAINER_EXIT_NONZERO"
    assert all(item.execution_status == "NOT_EXECUTED" for item in observed.rules)
    assert all(item.hit_count is None for item in observed.rules)


@pytest.mark.asyncio
async def test_malformed_sarif_uses_contractual_tool_failure_rule_reason(
    adapter_fixture: dict[str, Any],
) -> None:
    adapter = cast(ContainerCodeQLProcessAdapter, adapter_fixture["adapter"])
    request = cast(StaticToolRequest, adapter_fixture["request"])
    profile = cast(StaticToolProfile, adapter_fixture["profile"])
    workspace_root = cast(Path, adapter_fixture["workspace_root"])
    port = cast(FakeDockerPort, adapter_fixture["port"])
    port.stdout_chunks = (b"{}",)

    observed = await adapter.execute(
        request,
        workspace_root,
        profile,
        _deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert observed.gaps[0].code == "CODEQL_CONTAINER_SARIF_MALFORMED"
    assert all(item.reason == "TOOL_FAILURE" for item in observed.rules)


@pytest.mark.asyncio
@pytest.mark.parametrize("mixed", ["attempt", "profile", "workspace"])
async def test_mixed_request_identity_is_blocked_before_docker(
    adapter_fixture: dict[str, Any], mixed: str, tmp_path: Path
) -> None:
    """Catches cross-attempt, profile, or workspace material reaching Docker."""

    adapter = cast(ContainerCodeQLProcessAdapter, adapter_fixture["adapter"])
    request = cast(StaticToolRequest, adapter_fixture["request"])
    profile = cast(StaticToolProfile, adapter_fixture["profile"])
    workspace_root = cast(Path, adapter_fixture["workspace_root"])
    port = cast(FakeDockerPort, adapter_fixture["port"])
    if mixed == "attempt":
        request = replace(
            request,
            action=request.action.model_copy(
                update={
                    "meta": request.action.meta.model_copy(
                        update={"attempt_id": "another-attempt"}
                    )
                }
            ),
        )
    elif mixed == "profile":
        request = replace(request, tool_profile_ref=request.analysis_config_ref)
    else:
        workspace_root = tmp_path / "another-workspace"
        workspace_root.mkdir()

    observed = await adapter.execute(
        request,
        workspace_root,
        profile,
        _deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert observed.gaps[0].code == "CODEQL_CONTAINER_INPUT_MISMATCH"
    assert observed.errors[0].code == "CODEQL_CONTAINER_INPUT_MISMATCH"
    assert all(item.reason == "TOOL_FAILURE" for item in observed.rules)
    assert port.operations == []


@pytest.mark.asyncio
async def test_same_digest_different_executable_is_blocked_before_docker(
    adapter_fixture: dict[str, Any], tmp_path: Path
) -> None:
    """Catches a substituted executable even when its bytes match Docker."""

    inputs = cast(ContainerCodeQLAdapterInputs, adapter_fixture["inputs"])
    request = cast(StaticToolRequest, adapter_fixture["request"])
    profile = cast(StaticToolProfile, adapter_fixture["profile"])
    workspace_root = cast(Path, adapter_fixture["workspace_root"])
    original = inputs.spec.docker_executable
    substitute = tmp_path / "same-bytes-wrong-executable"
    substitute.write_bytes(original.read_bytes())
    port = FakeDockerPort(inputs.spec)
    adapter = ContainerCodeQLProcessAdapter(
        executable=substitute,
        executable_key="docker",
        inputs=inputs,
        port=port,
    )

    observed = await adapter.execute(
        request,
        workspace_root,
        profile,
        _deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert observed.gaps[0].code == "CODEQL_CONTAINER_PROFILE_MISMATCH"
    assert port.operations == []


class _BlockingDockerPort(FakeDockerPort):
    def __init__(self, spec: ContainerCodeQLSpec) -> None:
        super().__init__(spec)
        self.wait_started = asyncio.Event()

    async def wait(self, container_name: str) -> int:
        self.operations.append(("wait", container_name))
        self.wait_started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_timeout_is_a_retryable_gap_not_zero_hits(
    adapter_fixture: dict[str, Any],
) -> None:
    """Catches a timed-out CodeQL run being represented as no findings."""

    inputs = cast(ContainerCodeQLAdapterInputs, adapter_fixture["inputs"])
    request = cast(StaticToolRequest, adapter_fixture["request"])
    profile = cast(StaticToolProfile, adapter_fixture["profile"])
    workspace_root = cast(Path, adapter_fixture["workspace_root"])
    executable = cast(Path, adapter_fixture["executable"])
    port = _BlockingDockerPort(inputs.spec)
    adapter = ContainerCodeQLProcessAdapter(
        executable=executable,
        executable_key="docker",
        inputs=inputs,
        port=port,
        monotonic_ns=lambda: 10**18 - 1_000_000,
    )

    observed = await adapter.execute(
        request,
        workspace_root,
        profile,
        _deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert observed.gaps[0].code == "CODEQL_CONTAINER_TIMEOUT"
    assert observed.gaps[0].retryable is True
    assert observed.errors[0].code == "CODEQL_CONTAINER_TIMEOUT"
    assert all(item.execution_status == "NOT_EXECUTED" for item in observed.rules)
    assert all(item.hit_count is None for item in observed.rules)


@pytest.mark.asyncio
async def test_cancel_targets_only_the_exact_active_attempt(
    adapter_fixture: dict[str, Any],
) -> None:
    """Catches cancellation of an unrelated or global CodeQL execution."""

    inputs = cast(ContainerCodeQLAdapterInputs, adapter_fixture["inputs"])
    executable = cast(Path, adapter_fixture["executable"])
    request = cast(StaticToolRequest, adapter_fixture["request"])
    profile = cast(StaticToolProfile, adapter_fixture["profile"])
    workspace_root = cast(Path, adapter_fixture["workspace_root"])
    port = _BlockingDockerPort(inputs.spec)
    adapter = ContainerCodeQLProcessAdapter(
        executable=executable,
        executable_key="docker",
        inputs=inputs,
        port=port,
    )
    running = asyncio.create_task(
        adapter.execute(
            request,
            workspace_root,
            profile,
            _deadline(str(request.action.action_id)),
        )
    )
    await asyncio.wait_for(port.wait_started.wait(), timeout=1)

    unrelated = await adapter.cancel("another-attempt")
    assert unrelated.cancelled is False
    assert not running.done()
    cancelled = await adapter.cancel("at1")
    observed = await asyncio.wait_for(running, timeout=1)

    assert cancelled.cancelled is True
    assert observed.status == "SKIPPED"
    assert observed.gaps[0].code == "STATIC_TOOL_CANCELLED"
    assert port.operations[-1][0] == "remove"
