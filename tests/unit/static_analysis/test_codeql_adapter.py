from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.ports.dto import (
    CancellationResult,
    MonotonicActionDeadline,
    PrebuiltCodeQLDatabase,
    ProcessReceipt,
    ProcessResult,
    ProcessSpec,
    StaticRuleMapping,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.static_analysis.process import process_command_fingerprint
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta
from tests.contract.domain.fixtures import ref as fixture_ref


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _replace_distinct_file(source: Path, destination: Path) -> bool:
    """Replace an open file without relying on Windows symlink privileges."""

    if os.name != "nt":
        os.replace(source, destination)
        return True
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    replace_file = kernel32.ReplaceFileW
    replace_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    replace_file.restype = ctypes.c_int
    return bool(replace_file(str(destination), str(source), None, 0, None, None))


def process_result(
    spec: ProcessSpec,
    *,
    outcome: str = "SUCCEEDED",
    return_code: int | None = 0,
    stdout: bytes = b"",
) -> ProcessResult:
    receipt = ProcessReceipt(
        action_id=spec.deadline.action_id,
        invocation_id=spec.invocation_id,
        command_kind=spec.command_kind,
        attempt_id=spec.attempt_id,
        command_fingerprint=process_command_fingerprint(spec),
        outcome=outcome,  # type: ignore[arg-type]
        return_code=return_code,
        stdout_name="stdout",
        stdout_size=len(stdout),
        stdout_sha256=sha256(stdout),
        stderr_name="stderr",
        stderr_size=0,
        stderr_sha256=sha256(b""),
        elapsed_ms=1,
    )
    return ProcessResult(
        outcome=outcome,  # type: ignore[arg-type]
        return_code=return_code,
        stdout=stdout,
        stderr_tail=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        elapsed_ms=1,
        receipt=receipt,
        receipt_path=spec.attempt_output_dir / "receipt.json",
    )


class FakeRunner:
    def __init__(
        self,
        *,
        version: str = "2.20.0",
        sarif: bytes | None = None,
        outcome: str = "SUCCEEDED",
        return_code: int | None = 0,
        writer: Callable[[Path], None] | None = None,
        block_after_write: bool = False,
    ) -> None:
        self.version = version
        self.sarif = sarif
        self.outcome = outcome
        self.return_code = return_code
        self.writer = writer
        self.block_after_write = block_after_write
        self.calls: list[ProcessSpec] = []
        self.cancelled: list[str] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        if spec.argv[1:3] == ("version", "--format=json"):
            return process_result(
                spec, stdout=canonical_bytes({"version": self.version})
            )
        output_arg = next(value for value in spec.argv if value.startswith("--output="))
        output = Path(output_arg.split("=", 1)[1])
        if self.writer is not None:
            self.writer(output)
        elif self.sarif is not None:
            output.write_bytes(self.sarif)
        self.started.set()
        if self.block_after_write:
            await self.release.wait()
        return process_result(spec, outcome=self.outcome, return_code=self.return_code)

    async def cancel(self, attempt_id: str) -> CancellationResult:
        self.cancelled.append(attempt_id)
        self.release.set()
        return CancellationResult(True, None)


class RunnerFactory:
    def __init__(self, runner: FakeRunner) -> None:
        self.runner = runner
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> FakeRunner:
        self.calls.append(kwargs)
        return self.runner


def profile(executable: Path, **changes: object) -> StaticToolProfile:
    profile_meta = meta("static_tool_profile", attempt=None)
    profile_meta["created_at"] = datetime(2026, 9, 8, tzinfo=UTC)
    value: dict[str, object] = {
        "meta": profile_meta,
        "profile_key": "codeql-fixture",
        "purpose": "FIXTURE",
        "status": "APPROVED",
        "adapter_key": "CODEQL",
        "tool_name": "CODEQL",
        "tool_kind": "RULE_BASED",
        "executable_key": "trusted-codeql",
        "executable_sha256": sha256(executable.read_bytes())
        if executable.exists()
        else "a" * 64,
        "expected_version": "2.20.0",
        "capability_evidence_ref": None,
        "probe_timeout_ms": 1_000,
        "run_timeout_ms": 5_000,
        "stdout_limit_bytes": 1_024,
        "stderr_limit_bytes": 1_024,
        "max_attempt_output_bytes": 100_000,
        "max_output_file_bytes": 50_000,
        "max_artifact_read_bytes": 50_000,
    }
    value.update(changes)
    return StaticToolProfile.model_validate(value)


def workspace_and_request(
    tool_profile: StaticToolProfile,
) -> tuple[CodeWorkspace, StaticToolRequest]:
    workspace = CodeWorkspace.model_validate_json(
        json.dumps(
            make("CodeWorkspace")
            | {"workspace_id": "ws1", "commit_id": "c1", "status": "READY"}
        )
    )
    profile_ref = cast(StoredDataRef, reference(tool_profile))
    workspace_ref = cast(StoredDataRef, reference(workspace))
    analysis_config_ref = StoredDataRef.model_validate(
        fixture_ref("analysis_config")
    )
    rule_catalog_ref = StoredDataRef.model_validate(fixture_ref("rule_catalog"))
    action_data = make("ActionRequest", "action_request")
    action = ActionRequest.model_validate_json(
        json.dumps(
            action_data
            | {
                "requested_by": "STATIC_ANALYSIS",
                "action_type": "RUN_TOOL",
                "tool_name": "CODEQL",
                "file_paths": ("src/app.py",),
                "input_refs": tuple(
                    item.model_dump(mode="json")
                    for item in (
                        workspace_ref,
                        profile_ref,
                        analysis_config_ref,
                        rule_catalog_ref,
                    )
                ),
            }
        )
    )
    return workspace, StaticToolRequest(
        action=action,
        workspace=workspace,
        tool_profile_ref=profile_ref,
        analysis_config_ref=analysis_config_ref,
        rule_catalog_ref=rule_catalog_ref,
    )


def deadline(action_id: str = "action-1") -> MonotonicActionDeadline:
    return MonotonicActionDeadline(action_id=action_id, started_ns=0, expires_ns=10**12)


def fixture_workspace(value: dict[str, Any]) -> Path:
    root = value["workspace_root"]
    assert isinstance(root, Path)
    return root


def sarif(
    *,
    results: list[dict[str, Any]] | None = None,
    metadata: list[str] | None = None,
) -> bytes:
    return canonical_bytes(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "version": "2.20.0",
                            "rules": [
                                {"id": rule_id}
                                for rule_id in (metadata or ["R1", "R2"])
                            ],
                        }
                    },
                    "results": results or [],
                }
            ],
        }
    )


def physical(path: str, line: int) -> dict[str, object]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {
                "startLine": line,
                "startColumn": 1,
                "endLine": line,
                "endColumn": 2,
            },
        }
    }


def flow_result(locations: list[dict[str, object]]) -> dict[str, object]:
    return {
        "ruleId": "R1",
        "locations": [physical("src/sink.py", 30)],
        "codeFlows": [{"threadFlows": [{"locations": locations}]}],
    }


@pytest.fixture
def codeql_fixture(tmp_path: Path) -> dict[str, Any]:
    from sastsimi.static_analysis.codeql_adapter import (
        CodeQLExecutionInputs,
        digest_path,
    )

    executable = tmp_path / "codeql.exe"
    executable.write_bytes(b"trusted-codeql")
    database = tmp_path / "database"
    database.mkdir()
    (database / "codeql-database.yml").write_text("primaryLanguage: python")
    query_pack = tmp_path / "query-pack"
    query_pack.mkdir()
    (query_pack / "qlpack.yml").write_text("name: fixture")
    (query_pack / "sastsimi-selection.json").write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "rule_ids": ["R1", "R2"],
                "rule_packs": ["fixture/security"],
            }
        )
    )
    attempt_root = tmp_path / "attempt"
    attempt_root.mkdir()
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    mappings = (
        StaticRuleMapping("R1", "SINK", "SOURCE", True),
        StaticRuleMapping("R2", "VALIDATOR", None, False),
        StaticRuleMapping("R3", "OTHER", None, False),
    )
    analysis_config_ref = StoredDataRef.model_validate(fixture_ref("analysis_config"))
    rule_catalog_ref = StoredDataRef.model_validate(fixture_ref("rule_catalog"))
    inputs = CodeQLExecutionInputs(
        database=PrebuiltCodeQLDatabase(
            "ws1", "c1", "python", database, digest_path(database)
        ),
        query_pack_root=query_pack,
        query_pack_digest=digest_path(query_pack),
        analysis_config_ref=analysis_config_ref,
        rule_catalog_ref=rule_catalog_ref,
        rule_catalog=mappings,
        selected_rule_ids=("R1", "R2"),
        selected_rule_packs=("fixture/security",),
        tracked_files=tuple(
            TrackedFile(path, "100644", f"blob-{index}", 1)
            for index, path in enumerate(("src/app.py", "src/mid.py", "src/sink.py"))
        ),
        attempt_root=attempt_root,
        attempt_id="at1",
    )
    return {
        "executable": executable,
        "inputs": inputs,
        "workspace_root": workspace_root,
    }


@pytest.mark.asyncio
async def test_probe_uses_only_exact_version_command_and_profile_digest(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    assert isinstance(executable, Path)
    runner = FakeRunner()
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )
    observed = await adapter.probe(profile(executable), deadline())
    assert observed.available
    assert runner.calls[0].argv[1:] == ("version", "--format=json")
    assert dict(runner.calls[0].env) == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["missing", "digest", "version", "key"])
async def test_probe_fails_closed_without_analysis(
    codeql_fixture: dict[str, Any], case: str
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    runner = FakeRunner(version="0.0.0" if case == "version" else "2.20.0")
    factory = RunnerFactory(runner)
    selected = executable.with_name("missing.exe") if case == "missing" else executable
    adapter = CodeQLProcessAdapter(
        executable=selected,
        executable_key="wrong" if case == "key" else "trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=factory,
    )
    expected = (
        profile(executable, executable_sha256="b" * 64)
        if case == "digest"
        else profile(executable)
    )
    observed = await adapter.probe(expected, deadline())
    assert not observed.available
    if case in {"missing", "digest", "key"}:
        assert runner.calls == []


def test_command_policy_accepts_only_version_and_analyze_families(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.codeql_adapter import validate_codeql_command

    executable = tmp_path / "codeql"
    database = tmp_path / "db"
    pack = tmp_path / "pack"
    output = tmp_path / "out" / "codeql-result.sarif"
    valid = (
        str(executable),
        "database",
        "analyze",
        str(database),
        str(pack),
        "--format=sarifv2.1.0",
        f"--output={output}",
    )
    validate_codeql_command(valid, executable, database, pack, output)
    forbidden = (
        (str(executable), "database", "create", str(database)),
        (str(executable), "database", "trace-command", str(database)),
        valid + ("--command=npm install",),
        (str(executable), "autobuild"),
        (str(executable), "npm", "install"),
        (str(executable), "mvn", "package"),
    )
    for argv in forbidden:
        with pytest.raises(ValueError, match="CODEQL_COMMAND_FORBIDDEN"):
            validate_codeql_command(argv, executable, database, pack, output)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["database", "pack", "workspace", "commit"])
async def test_execute_rejects_stale_or_wrong_digest_inputs_before_spawn(
    codeql_fixture: dict[str, Any], case: str
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    workspace, request = workspace_and_request(tool_profile)
    if case == "database":
        inputs = replace(
            inputs, database=replace(inputs.database, database_digest="b" * 64)
        )
    elif case == "pack":
        inputs = replace(inputs, query_pack_digest="b" * 64)
    elif case == "workspace":
        inputs = replace(
            inputs, database=replace(inputs.database, workspace_id="other")
        )
    else:
        inputs = replace(inputs, database=replace(inputs.database, commit_id="other"))
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    assert observed.status in {"SKIPPED", "FAILED"}
    assert runner.calls == []


@pytest.mark.asyncio
async def test_execute_rejects_wrong_exact_profile_reference_before_spawn(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    request = replace(
        request,
        tool_profile_ref=request.tool_profile_ref.model_copy(
            update={"content_hash": "b" * 64}
        ),
    )
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert runner.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "manifest_value",
    [
        {
            "schema_version": 1,
            "rule_ids": ["R1"],
            "rule_packs": ["fixture/security"],
        },
        {
            "schema_version": True,
            "rule_ids": ["R1", "R2"],
            "rule_packs": ["fixture/security"],
        },
    ],
)
async def test_selection_manifest_must_exactly_match_selected_rules_and_packs(
    codeql_fixture: dict[str, Any], manifest_value: dict[str, Any]
) -> None:
    from sastsimi.static_analysis.codeql_adapter import (
        CodeQLProcessAdapter,
        digest_path,
    )

    inputs = codeql_fixture["inputs"]
    manifest = inputs.query_pack_root / "sastsimi-selection.json"
    manifest.write_bytes(canonical_bytes(manifest_value))
    inputs = replace(inputs, query_pack_digest=digest_path(inputs.query_pack_root))
    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert runner.calls == []


@pytest.mark.asyncio
async def test_decodes_rule_telemetry_and_ordered_code_flow(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    result = flow_result(
        [
            physical("src/app.py", 10),
            physical("src/mid.py", 20),
            physical("src/sink.py", 30),
        ]
    )
    payload = sarif(
        results=[result, {"ruleId": "R1", "locations": [physical("src/sink.py", 31)]}]
    )
    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    workspace, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=payload)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    assert observed.status == "PARTIAL"
    assert observed.raw_output == payload
    rules = {item.rule_id: item for item in observed.rules}
    assert (rules["R1"].execution_status, rules["R1"].hit_count) == ("EXECUTED", 2)
    assert (rules["R2"].execution_status, rules["R2"].hit_count) == ("EXECUTED", 0)
    assert (rules["R3"].selection_status, rules["R3"].reason) == (
        "NOT_SELECTED",
        "NOT_SELECTED",
    )
    assert [
        (item.from_location.file_path, item.to_location.file_path)
        for item in observed.relations
    ] == [
        ("src/app.py", "src/mid.py"),
        ("src/mid.py", "src/sink.py"),
    ]
    assert {(item.fact_kind, item.location.file_path) for item in observed.facts} >= {
        ("SOURCE", "src/app.py"),
        ("SINK", "src/sink.py"),
    }
    analyze_argv = runner.calls[1].argv
    assert analyze_argv[1:3] == ("database", "analyze")
    assert analyze_argv[3] == str(codeql_fixture["inputs"].database.database_root)
    assert analyze_argv[4] == str(codeql_fixture["inputs"].query_pack_root)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "locations,expected_edges",
    [
        ([], 0),
        ([physical("src/app.py", 1)], 0),
        ([physical("../foreign.py", 1), physical("src/sink.py", 2)], 0),
        ([physical("src/app.py", 1), {}, physical("src/sink.py", 2)], 0),
    ],
)
async def test_unresolved_required_flow_adds_gap_without_jump_edge(
    codeql_fixture: dict[str, Any],
    tmp_path: Path,
    locations: list[dict[str, object]],
    expected_edges: int,
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    workspace, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=sarif(results=[flow_result(locations)]))
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    assert len(observed.relations) == expected_edges
    assert any(gap.code == "STATIC_DATA_FLOW_UNRESOLVED" for gap in observed.gaps)


@pytest.mark.asyncio
async def test_one_valid_flow_does_not_hide_a_second_unsafe_flow(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    result = flow_result([physical("src/app.py", 1), physical("src/sink.py", 2)])
    code_flows = result["codeFlows"]
    assert isinstance(code_flows, list)
    code_flows.append(
        {
            "threadFlows": [
                {
                    "locations": [
                        physical("src/app.py", 1),
                        physical("../foreign.py", 2),
                        physical("src/sink.py", 3),
                    ]
                }
            ]
        }
    )
    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=sarif(results=[result]))
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "PARTIAL"
    assert len(observed.relations) == 1
    assert any(gap.code == "STATIC_DATA_FLOW_UNRESOLVED" for gap in observed.gaps)


@pytest.mark.asyncio
async def test_each_valid_flow_keeps_its_own_endpoint_fact_provenance(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    result = flow_result([physical("src/app.py", 1), physical("src/sink.py", 2)])
    result["locations"] = []
    code_flows = result["codeFlows"]
    assert isinstance(code_flows, list)
    code_flows.append(
        {
            "threadFlows": [
                {
                    "locations": [
                        physical("src/mid.py", 3),
                        physical("src/sink.py", 4),
                    ]
                }
            ]
        }
    )
    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(FakeRunner(sarif=sarif(results=[result]))),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    flow_facts = [item for item in observed.facts if ":flow:" in item.source_key]
    assert [item.source_key for item in flow_facts] == [
        "codeql:R1:result:0:flow:0:0:endpoint",
        "codeql:R1:result:0:flow:0:0:start",
        "codeql:R1:result:0:flow:1:0:endpoint",
        "codeql:R1:result:0:flow:1:0:start",
    ]
    assert [(item.fact_kind, item.location.start_line) for item in flow_facts] == [
        ("SINK", 2),
        ("SOURCE", 1),
        ("SINK", 4),
        ("SOURCE", 3),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hit",
    [
        {"ruleId": "R2"},
        {"ruleId": "R2", "locations": []},
        {"ruleId": "R2", "locations": [{}]},
    ],
)
async def test_hit_without_valid_location_keeps_count_and_adds_gap(
    codeql_fixture: dict[str, Any], hit: dict[str, Any]
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(FakeRunner(sarif=sarif(results=[hit]))),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    rule = next(item for item in observed.rules if item.rule_id == "R2")
    assert (rule.execution_status, rule.hit_count) == ("EXECUTED", 1)
    assert any(gap.code == "STATIC_LOCATION_UNRESOLVED" for gap in observed.gaps)
    assert all(item.rule_id != "R2" for item in observed.facts)


@pytest.mark.asyncio
@pytest.mark.parametrize("outside", ["metadata", "result"])
async def test_sarif_rule_outside_selected_set_is_rejected(
    codeql_fixture: dict[str, Any], outside: str
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    payload = (
        sarif(metadata=["R1", "R2", "R3"])
        if outside == "metadata"
        else sarif(results=[{"ruleId": "R3", "locations": [physical("src/app.py", 1)]}])
    )
    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(FakeRunner(sarif=payload)),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert observed.facts == () and observed.relations == ()
    assert any(error.code == "STATIC_OUTPUT_MALFORMED" for error in observed.errors)


@pytest.mark.asyncio
async def test_missing_rule_metadata_is_unknown_not_zero(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    workspace, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=sarif(metadata=["R1"]))
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    rule = next(item for item in observed.rules if item.rule_id == "R2")
    assert (rule.execution_status, rule.hit_count, rule.reason) == (
        "UNKNOWN",
        None,
        "TELEMETRY_MISSING",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome,return_code,payload,expected_status,expected_code",
    [
        ("SUCCEEDED", 1, sarif(), "FAILED", "STATIC_TOOL_FAILED"),
        ("TIMED_OUT", None, None, "FAILED", "STATIC_TOOL_TIMEOUT"),
        ("CANCELLED", None, None, "SKIPPED", "STATIC_TOOL_CANCELLED"),
        ("SUCCEEDED", 0, b"{", "FAILED", "STATIC_OUTPUT_MALFORMED"),
    ],
)
async def test_process_and_decode_failures_never_become_partial_evidence(
    codeql_fixture: dict[str, Any],
    tmp_path: Path,
    outcome: str,
    return_code: int | None,
    payload: bytes | None,
    expected_status: str,
    expected_code: str,
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    workspace, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=payload, outcome=outcome, return_code=return_code)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    assert observed.status == expected_status
    assert expected_code in {item.code for item in observed.gaps} | {
        item.code for item in observed.errors
    }
    assert observed.facts == () and observed.relations == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cap_name", ["max_output_file_bytes", "max_artifact_read_bytes"]
)
async def test_complete_sarif_cap_plus_one_is_never_parsed(
    codeql_fixture: dict[str, Any], tmp_path: Path, cap_name: str
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    payload = sarif()
    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable, **{cap_name: len(payload) - 1})
    workspace, request = workspace_and_request(tool_profile)
    parsed = False

    def parser(data: bytes) -> object:
        nonlocal parsed
        parsed = True
        return json.loads(data)

    runner = FakeRunner(sarif=payload)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
        sarif_loader=parser,
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    assert observed.status == "FAILED"
    assert not parsed
    assert "STATIC_OUTPUT_LIMIT" in {item.code for item in observed.gaps} | {
        item.code for item in observed.errors
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cap_name",
    [
        "max_attempt_output_bytes",
        "max_output_file_bytes",
        "max_artifact_read_bytes",
    ],
)
async def test_complete_sarif_at_each_exact_cap_is_accepted(
    codeql_fixture: dict[str, Any], cap_name: str
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    payload = sarif()
    executable = codeql_fixture["executable"]
    tool_profile = profile(executable, **{cap_name: len(payload)})
    _, request = workspace_and_request(tool_profile)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(FakeRunner(sarif=payload)),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "SUCCEEDED"
    assert observed.raw_output == payload


@pytest.mark.asyncio
async def test_directory_quota_watcher_cancels_running_process(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    payload = sarif()
    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable, max_attempt_output_bytes=len(payload))
    workspace, request = workspace_and_request(tool_profile)

    def write_over_quota(output: Path) -> None:
        output.write_bytes(payload)
        (output.parent / "unexpected.bin").write_bytes(b"x")

    runner = FakeRunner(writer=write_over_quota, block_after_write=True)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
        quota_poll_seconds=0.001,
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    assert runner.cancelled == ["at1"]
    assert observed.status == "FAILED"
    assert "STATIC_OUTPUT_LIMIT" in {item.code for item in observed.gaps} | {
        item.code for item in observed.errors
    }


@pytest.mark.asyncio
async def test_preexisting_or_linked_output_is_rejected(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    assert isinstance(executable, Path)
    (inputs.attempt_root / "codeql-run").mkdir()
    tool_profile = profile(executable)
    workspace, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    assert observed.status == "FAILED" and runner.calls == []


@pytest.mark.asyncio
async def test_attempt_output_root_inside_workspace_is_rejected_before_spawn(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    inputs = replace(
        codeql_fixture["inputs"],
        attempt_root=fixture_workspace(codeql_fixture),
    )
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert runner.calls == []


@pytest.mark.asyncio
async def test_linked_attempt_output_directory_is_rejected_before_spawn(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    inputs = codeql_fixture["inputs"]
    external = tmp_path / "external-output"
    external.mkdir()
    try:
        (inputs.attempt_root / "codeql-run").symlink_to(
            external, target_is_directory=True
        )
    except OSError:
        pytest.skip("directory symlink/reparse creation is unavailable")
    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert runner.calls == []


@pytest.mark.skipif(os.name != "nt", reason="Windows junction/reparse boundary")
@pytest.mark.asyncio
async def test_windows_junction_attempt_root_is_rejected_before_spawn_or_parse(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    inputs = codeql_fixture["inputs"]
    attempt_root = inputs.attempt_root
    attempt_root.rmdir()
    external = tmp_path / "junction-target"
    external.mkdir()
    windows_root = os.environ.get("SystemRoot", r"C:\Windows")
    cmd = Path(windows_root) / "System32" / "cmd.exe"
    created = subprocess.run(
        [str(cmd), "/d", "/c", "mklink", "/J", str(attempt_root), str(external)],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    assert created.returncode == 0, created.stderr or created.stdout
    assert attempt_root.is_junction()
    parsed = False

    def parser(data: bytes) -> object:
        nonlocal parsed
        parsed = True
        return json.loads(data)

    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
        sarif_loader=parser,
    )

    try:
        observed = await adapter.execute(
            request,
            fixture_workspace(codeql_fixture),
            tool_profile,
            deadline(str(request.action.action_id)),
        )
    finally:
        attempt_root.rmdir()

    assert observed.status == "FAILED"
    assert runner.calls == []
    assert not parsed


@pytest.mark.asyncio
async def test_symlink_sarif_output_is_never_parsed(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    external = tmp_path / "external.sarif"
    external.write_bytes(sarif())

    def link_output(output: Path) -> None:
        try:
            output.symlink_to(external)
        except OSError:
            pytest.skip("file symlink creation is unavailable")

    parsed = False

    def parser(data: bytes) -> object:
        nonlocal parsed
        parsed = True
        return json.loads(data)

    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(FakeRunner(writer=link_output)),
        sarif_loader=parser,
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert not parsed


@pytest.mark.asyncio
async def test_sarif_changed_during_bounded_read_is_rejected(
    codeql_fixture: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sastsimi.static_analysis.codeql_adapter as codeql_adapter

    payload = sarif()
    replacement = tmp_path / "replacement.sarif"
    replacement.write_bytes(b"x" * len(payload))
    real_read = os.read
    replaced = False
    parsed = False

    def changing_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        data = real_read(descriptor, size)
        path = (
            codeql_fixture["inputs"].attempt_root / "codeql-run" / "codeql-result.sarif"
        )
        if not replaced and path.exists():
            replaced = _replace_distinct_file(replacement, path)
        return data

    def parser(data: bytes) -> object:
        nonlocal parsed
        parsed = True
        return json.loads(data)

    monkeypatch.setattr(os, "read", changing_read)
    executable = codeql_fixture["executable"]
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=payload)
    adapter = codeql_adapter.CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
        sarif_loader=parser,
    )

    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )

    assert observed.status == "FAILED"
    assert replaced
    assert not parsed
    assert len(runner.calls) == 2
    assert observed.raw_output is None
    assert observed.facts == () and observed.relations == ()


@pytest.mark.asyncio
async def test_hard_link_sarif_is_not_accepted_when_supported(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    external = tmp_path / "external.sarif"
    external.write_bytes(sarif())

    def hard_link(output: Path) -> None:
        try:
            os.link(external, output)
        except OSError:
            pytest.skip("hard links unavailable")

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    workspace, request = workspace_and_request(tool_profile)
    runner = FakeRunner(writer=hard_link)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    observed = await adapter.execute(
        request,
        fixture_workspace(codeql_fixture),
        tool_profile,
        deadline(str(request.action.action_id)),
    )
    assert observed.status == "FAILED"
    assert "STATIC_OUTPUT_LIMIT" in {item.code for item in observed.gaps} | {
        item.code for item in observed.errors
    }
