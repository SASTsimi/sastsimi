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
from typing import Any, Protocol, TypedDict, cast

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.ports.dto import (
    CancellationResult,
    MonotonicActionDeadline,
    PrebuiltCodeQLDatabase,
    ProcessReceipt,
    ProcessResult,
    ProcessSpec,
    StaticOutputQuotaBinding,
    StaticRuleMapping,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.static_analysis.process import process_command_fingerprint
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta
from tests.contract.domain.fixtures import ref as fixture_ref


class _WindowsFunction(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *args: object) -> int | None: ...


class _Kernel32(Protocol):
    ReplaceFileW: _WindowsFunction


class VersionRunnerChanges(TypedDict, total=False):
    version: str
    version_outcome: str
    version_return_code: int | None
    version_stdout: bytes | None
    version_stdout_truncated: bool
    version_stderr_truncated: bool


def _platform_attribute(owner: object, name: str) -> object:
    return getattr(owner, name)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _replace_distinct_file(source: Path, destination: Path) -> bool:
    """Replace an open file without relying on Windows symlink privileges."""

    if os.name != "nt":
        os.replace(source, destination)
        return True
    load_library = cast(Callable[..., object], _platform_attribute(ctypes, "WinDLL"))
    kernel32 = cast(_Kernel32, load_library("kernel32", use_last_error=True))
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
    stderr: bytes = b"",
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
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
        stderr_size=len(stderr),
        stderr_sha256=sha256(stderr),
        elapsed_ms=1,
    )
    return ProcessResult(
        outcome=outcome,  # type: ignore[arg-type]
        return_code=return_code,
        stdout=stdout,
        stderr_tail=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
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
        version_outcome: str = "SUCCEEDED",
        version_return_code: int | None = 0,
        version_stdout: bytes | None = None,
        version_stdout_truncated: bool = False,
        version_stderr_truncated: bool = False,
        block_version: bool = False,
        version_error: Exception | None = None,
        analyze_return_callback: Callable[[], None] | None = None,
        analyze_callback: Callable[[ProcessSpec], None] | None = None,
    ) -> None:
        self.version = version
        self.sarif = sarif
        self.outcome = outcome
        self.return_code = return_code
        self.writer = writer
        self.block_after_write = block_after_write
        self.version_outcome = version_outcome
        self.version_return_code = version_return_code
        self.version_stdout = version_stdout
        self.version_stdout_truncated = version_stdout_truncated
        self.version_stderr_truncated = version_stderr_truncated
        self.block_version = block_version
        self.version_error = version_error
        self.analyze_return_callback = analyze_return_callback
        self.analyze_callback = analyze_callback
        self.calls: list[ProcessSpec] = []
        self.cancelled: list[str] = []
        self.started = asyncio.Event()
        self.version_started = asyncio.Event()
        self.analyze_started = asyncio.Event()
        self.release = asyncio.Event()
        self.version_finished = asyncio.Event()
        self.analyze_finished = asyncio.Event()

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        try:
            self.calls.append(spec)
            if spec.argv[1:3] == ("version", "--format=json"):
                self.started.set()
                self.version_started.set()
                if self.block_version:
                    await self.release.wait()
                if self.version_error is not None:
                    raise self.version_error
                return process_result(
                    spec,
                    outcome=self.version_outcome,
                    return_code=self.version_return_code,
                    stdout=(
                        canonical_bytes({"version": self.version})
                        if self.version_stdout is None
                        else self.version_stdout
                    ),
                    stdout_truncated=self.version_stdout_truncated,
                    stderr_truncated=self.version_stderr_truncated,
                )
            output_arg = next(
                value for value in spec.argv if value.startswith("--output=")
            )
            output = Path(output_arg.split("=", 1)[1])
            if self.analyze_callback is not None:
                self.analyze_callback(spec)
            if self.writer is not None:
                self.writer(output)
            elif self.sarif is not None:
                output.write_bytes(self.sarif)
            self.started.set()
            self.analyze_started.set()
            if self.block_after_write:
                await self.release.wait()
            return process_result(
                spec, outcome=self.outcome, return_code=self.return_code
            )
        finally:
            if spec.argv[1:3] == ("version", "--format=json"):
                self.version_finished.set()
            else:
                if self.analyze_return_callback is not None:
                    self.analyze_return_callback()
                self.analyze_finished.set()

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


class DelayedCancelRunner(FakeRunner):
    """Keep cancellation open so a second outer cancellation is deterministic."""

    def __init__(self, *, sarif: bytes, block_after_write: bool) -> None:
        super().__init__(sarif=sarif, block_after_write=block_after_write)
        self.cancel_started = asyncio.Event()
        self.finish_cancel = asyncio.Event()

    async def cancel(self, attempt_id: str) -> CancellationResult:
        self.cancelled.append(attempt_id)
        self.cancel_started.set()
        await self.finish_cancel.wait()
        self.release.set()
        return CancellationResult(True, None)


class HardQuotaGuard:
    """Trusted fixture proof for a write-denying attempt-output lease."""

    def __init__(self, *, active: bool = True) -> None:
        self.active = active
        self.limit_breached = False
        self.breach_evidence: str | None = None
        self.calls: list[
            tuple[str, str, str, StoredDataRef | HostConfigurationRef, Path, int]
        ] = []

    def verify(
        self,
        *,
        lease_id: str,
        action_id: str,
        attempt_id: str,
        profile_ref: StoredDataRef | HostConfigurationRef,
        root: Path,
        limit_bytes: int,
    ) -> StaticOutputQuotaBinding:
        self.calls.append(
            (lease_id, action_id, attempt_id, profile_ref, root, limit_bytes)
        )
        if not self.active:
            raise ValueError("ATTEMPT_OUTPUT_QUOTA_UNENFORCEABLE")
        return StaticOutputQuotaBinding(
            binding_id="binding-at1",
            lease_id=lease_id,
            backend_key="fixture-write-denying-quota",
            enforcement_evidence="fixture-enforcement-proof",
            root=root,
            action_id=action_id,
            attempt_id=attempt_id,
            profile_ref=profile_ref,
            effective_limit_bytes=limit_bytes,
            hard_enforced=True,
            limit_breached=self.limit_breached,
            breach_evidence=self.breach_evidence,
        )


def test_static_output_quota_binding_exposes_sticky_breach_state() -> None:
    assert "limit_breached" in StaticOutputQuotaBinding.__dataclass_fields__
    assert "breach_evidence" in StaticOutputQuotaBinding.__dataclass_fields__


@pytest.mark.parametrize("shared_part", ["root", "lease"])
def test_codeql_inputs_require_probe_quota_isolation(
    codeql_fixture: dict[str, Any], shared_part: str
) -> None:
    inputs = codeql_fixture["inputs"]

    with pytest.raises(ValueError, match="CODEQL_INPUT_CLOSURE_INVALID"):
        replace(
            inputs,
            **(
                {"probe_root": inputs.attempt_root}
                if shared_part == "root"
                else {"probe_output_quota_lease_id": inputs.output_quota_lease_id}
            ),
        )


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
    analysis_config_ref = StoredDataRef.model_validate(fixture_ref("analysis_config"))
    rule_catalog_ref = StoredDataRef.model_validate(fixture_ref("rule_catalog"))
    action_data = make("ActionRequest", "action_request")
    action = ActionRequest.model_validate_json(
        json.dumps(
            action_data
            | {
                "requested_by": "STATIC_ANALYSIS",
                "action_type": "RUN_TOOL",
                "tool_name": "CODEQL",
                "file_paths": ("src/app.py", "src/mid.py", "src/sink.py"),
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


def copied_codeql_input_bytes(inputs: Any) -> int:
    return sum(
        path.stat().st_size
        for root in (inputs.database.database_root, inputs.query_pack_root)
        for path in root.rglob("*")
        if path.is_file()
    )


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
    probe_root = tmp_path / "probe"
    probe_root.mkdir()
    output_quota = HardQuotaGuard()
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
        output_quota_lease_id="quota-at1",
        probe_root=probe_root,
        probe_output_quota_lease_id="quota-probe-at1",
        output_quota=output_quota,
    )
    return {
        "executable": executable,
        "inputs": inputs,
        "workspace_root": workspace_root,
        "output_quota": output_quota,
    }


@pytest.mark.asyncio
async def test_execute_fails_before_spawn_without_enforced_output_quota(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    workspace_root = codeql_fixture["workspace_root"]
    assert isinstance(executable, Path)
    assert isinstance(workspace_root, Path)
    inputs.output_quota.active = False
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    observed = await adapter.execute(
        request, workspace_root, tool_profile, deadline(str(request.action.action_id))
    )

    assert observed.status == "FAILED"
    assert observed.errors[0].code == "CODEQL_OUTPUT_QUOTA_UNENFORCEABLE"
    assert not runner.calls


@pytest.mark.asyncio
async def test_execute_fails_before_spawn_for_already_breached_output_quota(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    workspace_root = codeql_fixture["workspace_root"]
    output_quota = codeql_fixture["output_quota"]
    assert isinstance(executable, Path)
    assert isinstance(workspace_root, Path)
    assert isinstance(output_quota, HardQuotaGuard)
    output_quota.limit_breached = True
    output_quota.breach_evidence = "fixture-denied-write"
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    observed = await adapter.execute(
        request, workspace_root, tool_profile, deadline(str(request.action.action_id))
    )

    assert observed.status == "FAILED"
    assert observed.raw_output is None
    assert {item.code for item in observed.errors} == {"STATIC_OUTPUT_LIMIT"}
    assert not runner.calls


@pytest.mark.asyncio
async def test_execute_rejects_inconsistent_output_quota_status_before_spawn(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    workspace_root = codeql_fixture["workspace_root"]
    output_quota = codeql_fixture["output_quota"]
    assert isinstance(executable, Path)
    assert isinstance(workspace_root, Path)
    assert isinstance(output_quota, HardQuotaGuard)
    output_quota.breach_evidence = "evidence-without-a-breach"
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    observed = await adapter.execute(
        request, workspace_root, tool_profile, deadline(str(request.action.action_id))
    )

    assert observed.status == "FAILED"
    assert {item.code for item in observed.errors} == {
        "CODEQL_OUTPUT_QUOTA_UNENFORCEABLE"
    }
    assert not runner.calls


@pytest.mark.asyncio
async def test_probe_fails_before_spawn_without_enforced_output_quota(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    assert isinstance(executable, Path)
    inputs.output_quota.active = False
    runner = FakeRunner()
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )

    observed = await adapter.probe(profile(executable), deadline("quota-probe"))

    assert not observed.available
    assert observed.reason_code == "CODEQL_OUTPUT_QUOTA_UNENFORCEABLE"
    assert not runner.calls


@pytest.mark.asyncio
async def test_probe_discards_capability_if_output_quota_is_revoked_after_process(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    output_quota = codeql_fixture["output_quota"]
    assert isinstance(executable, Path)
    assert isinstance(output_quota, HardQuotaGuard)

    class RevokingProbeRunner(FakeRunner):
        async def run(self, spec: ProcessSpec) -> ProcessResult:
            result = await super().run(spec)
            output_quota.active = False
            return result

    runner = RevokingProbeRunner()
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )

    observed = await adapter.probe(profile(executable), deadline("revoked-probe"))

    assert not observed.available
    assert observed.reason_code == "CODEQL_OUTPUT_QUOTA_UNENFORCEABLE"
    assert len(runner.calls) == 1


@pytest.mark.asyncio
async def test_execute_rechecks_exact_hard_quota_after_process(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    workspace_root = codeql_fixture["workspace_root"]
    output_quota = codeql_fixture["output_quota"]
    assert isinstance(executable, Path)
    assert isinstance(workspace_root, Path)
    assert isinstance(output_quota, HardQuotaGuard)
    runner = FakeRunner(sarif=sarif())
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    observed = await adapter.execute(
        request, workspace_root, tool_profile, deadline(str(request.action.action_id))
    )

    assert observed.status == "SUCCEEDED", observed
    expected_call = (
        "quota-at1",
        str(request.action.action_id),
        "at1",
        request.tool_profile_ref,
        inputs.attempt_root.resolve(),
        100_000,
    )
    assert output_quota.calls == [expected_call] * 4


@pytest.mark.asyncio
async def test_execute_uses_attempt_owned_database_pack_cache_and_cwd(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    workspace_root = codeql_fixture["workspace_root"]
    assert isinstance(executable, Path)
    assert isinstance(workspace_root, Path)
    seen: dict[str, Path] = {}

    def inspect_and_mutate_working_copy(spec: ProcessSpec) -> None:
        seen["database"] = Path(spec.argv[3])
        seen["query_pack"] = Path(spec.argv[4])
        cache_arg = next(
            item for item in spec.argv if item.startswith("--common-caches=")
        )
        seen["cache"] = Path(cache_arg.split("=", 1)[1])
        seen["logs"] = Path(
            next(item for item in spec.argv if item.startswith("--logdir=")).split(
                "=", 1
            )[1]
        )
        seen["temporary"] = Path(dict(spec.env)["TEMP"])
        assert dict(spec.env) == {
            "TEMP": str(seen["temporary"]),
            "TMP": str(seen["temporary"]),
            "TMPDIR": str(seen["temporary"]),
        }
        seen["cwd"] = spec.cwd
        assert any(item.startswith("--max-disk-cache=") for item in spec.argv)
        seen["database"].joinpath("results-written-by-codeql").write_text("ok")

    runner = FakeRunner(sarif=sarif(), analyze_callback=inspect_and_mutate_working_copy)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=RunnerFactory(runner),
    )
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    observed = await adapter.execute(
        request, workspace_root, tool_profile, deadline(str(request.action.action_id))
    )

    assert observed.status == "SUCCEEDED", observed
    assert seen["database"] != inputs.database.database_root
    assert seen["query_pack"] != inputs.query_pack_root
    assert seen["cwd"] != workspace_root
    for path in seen.values():
        path.resolve().relative_to(inputs.attempt_root.resolve())
    assert not inputs.database.database_root.joinpath(
        "results-written-by-codeql"
    ).exists()


@pytest.mark.asyncio
async def test_execute_discards_results_if_working_query_pack_changes(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    workspace_root = codeql_fixture["workspace_root"]
    assert isinstance(executable, Path)
    assert isinstance(workspace_root, Path)

    def mutate_working_query_pack(spec: ProcessSpec) -> None:
        Path(spec.argv[4]).joinpath("changed-during-analysis.txt").write_text(
            "changed", encoding="utf-8"
        )

    runner = FakeRunner(sarif=sarif(), analyze_callback=mutate_working_query_pack)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    observed = await adapter.execute(
        request, workspace_root, tool_profile, deadline(str(request.action.action_id))
    )

    assert observed.status == "FAILED"
    assert observed.raw_output is None
    assert observed.facts == () and observed.relations == ()
    assert {item.code for item in observed.errors} == {
        "CODEQL_QUERY_PACK_DIGEST_MISMATCH"
    }


@pytest.mark.asyncio
async def test_revoked_output_quota_discards_completed_sarif(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    workspace_root = codeql_fixture["workspace_root"]
    output_quota = codeql_fixture["output_quota"]
    assert isinstance(executable, Path)
    assert isinstance(workspace_root, Path)
    assert isinstance(output_quota, HardQuotaGuard)

    def revoke_quota(_spec: ProcessSpec) -> None:
        output_quota.active = False

    runner = FakeRunner(sarif=sarif(), analyze_callback=revoke_quota)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    observed = await adapter.execute(
        request, workspace_root, tool_profile, deadline(str(request.action.action_id))
    )

    assert observed.status == "FAILED"
    assert observed.raw_output is None
    assert {item.code for item in observed.errors} == {"STATIC_OUTPUT_LIMIT"}


@pytest.mark.asyncio
async def test_breached_output_quota_discards_completed_sarif(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    workspace_root = codeql_fixture["workspace_root"]
    output_quota = codeql_fixture["output_quota"]
    assert isinstance(executable, Path)
    assert isinstance(workspace_root, Path)
    assert isinstance(output_quota, HardQuotaGuard)

    def record_denied_write(_spec: ProcessSpec) -> None:
        output_quota.limit_breached = True
        output_quota.breach_evidence = "fixture-denied-write"

    parsed = False

    def parser(data: bytes) -> object:
        nonlocal parsed
        parsed = True
        return json.loads(data)

    runner = FakeRunner(sarif=sarif(), analyze_callback=record_denied_write)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
        sarif_loader=parser,
    )
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    observed = await adapter.execute(
        request, workspace_root, tool_profile, deadline(str(request.action.action_id))
    )

    assert observed.status == "FAILED"
    assert observed.raw_output is None
    assert {item.code for item in observed.errors} == {"STATIC_OUTPUT_LIMIT"}
    assert not parsed


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
    tool_profile = profile(executable)
    probe_deadline = deadline()
    observed = await adapter.probe(tool_profile, probe_deadline)
    assert observed.available
    assert runner.calls[0].argv[1:] == ("version", "--format=json")
    expected_quota_check = (
        "quota-probe-at1",
        probe_deadline.action_id,
        probe_deadline.action_id,
        reference(tool_profile),
        inputs.probe_root.resolve(),
        tool_profile.max_attempt_output_bytes,
    )
    assert inputs.output_quota.calls == [expected_quota_check] * 2
    probe_temp = Path(dict(runner.calls[0].env)["TEMP"])
    assert dict(runner.calls[0].env) == {
        "TEMP": str(probe_temp),
        "TMP": str(probe_temp),
        "TMPDIR": str(probe_temp),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["duplicate", "factory", "command"])
async def test_probe_setup_failure_removes_only_exact_owned_directory(
    codeql_fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    import sastsimi.static_analysis.codeql_adapter as codeql_module
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    assert isinstance(executable, Path)
    sibling = inputs.probe_root / "keep-sibling"
    sibling.mkdir()
    runner = FakeRunner()

    if failure == "factory":

        def broken_factory(**_kwargs: object) -> FakeRunner:
            raise RuntimeError("factory failed")

        runner_factory: Any = broken_factory
    else:
        runner_factory = RunnerFactory(runner)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=inputs,
        runner_factory=runner_factory,
    )
    probe_deadline = deadline(f"probe-setup-{failure}")

    if failure == "duplicate":

        def duplicate_runner(**_kwargs: object) -> FakeRunner:
            raise ValueError("CODEQL_ATTEMPT_ALREADY_ACTIVE")

        monkeypatch.setattr(adapter, "_make_runner", duplicate_runner)
    elif failure == "command":

        def invalid_command(*_args: object, **_kwargs: object) -> None:
            raise ValueError("CODEQL_COMMAND_FORBIDDEN")

        monkeypatch.setattr(codeql_module, "validate_codeql_command", invalid_command)

    if failure == "duplicate":
        observed = await adapter.probe(profile(executable), probe_deadline)
        assert observed.reason_code == "CODEQL_PROBE_ALREADY_ACTIVE"
    else:
        with pytest.raises((RuntimeError, ValueError)):
            await adapter.probe(profile(executable), probe_deadline)

    assert list(inputs.probe_root.iterdir()) == [sibling]
    assert not (await adapter.cancel(probe_deadline.action_id)).cancelled


@pytest.mark.asyncio
async def test_repeated_probe_uses_fresh_owned_directories(
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
    probe_deadline = deadline("repeat-codeql-probe")

    first = await adapter.probe(profile(executable), probe_deadline)
    second = await adapter.probe(profile(executable), probe_deadline)

    assert first == second
    assert first.available
    assert len(runner.calls) == 2
    assert runner.calls[0].cwd != runner.calls[1].cwd
    assert runner.calls[0].attempt_output_dir != runner.calls[1].attempt_output_dir


@pytest.mark.asyncio
async def test_concurrent_probe_with_same_action_fails_closed_without_overwrite(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    runner = FakeRunner(
        block_version=True,
        version_outcome="CANCELLED",
        version_return_code=None,
    )
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    probe_deadline = deadline("same-codeql-probe")
    first_probe = asyncio.create_task(
        adapter.probe(profile(executable), probe_deadline)
    )
    await runner.version_started.wait()

    second = await adapter.probe(profile(executable), probe_deadline)
    cancelled = await adapter.cancel(probe_deadline.action_id)
    first = await first_probe

    assert not second.available
    assert second.reason_code == "CODEQL_PROBE_ALREADY_ACTIVE"
    assert cancelled.cancelled
    assert runner.cancelled == [probe_deadline.action_id]
    assert first.reason_code == "CODEQL_PROBE_CANCELLED"


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "runner_changes,expected_reason",
    [
        (
            {"version_outcome": "CANCELLED", "version_return_code": None},
            "CODEQL_PROBE_CANCELLED",
        ),
        (
            {"version_outcome": "TIMED_OUT", "version_return_code": None},
            "CODEQL_PROBE_TIMEOUT",
        ),
        ({"version_stdout_truncated": True}, "CODEQL_PROBE_OUTPUT_TRUNCATED"),
        ({"version_stderr_truncated": True}, "CODEQL_PROBE_OUTPUT_TRUNCATED"),
        ({"version_stdout": b"not-json"}, "CODEQL_VERSION_INVALID"),
        ({"version": "0.0.0"}, "CODEQL_VERSION_MISMATCH"),
    ],
)
async def test_probe_preserves_version_failure_semantics(
    codeql_fixture: dict[str, Any],
    runner_changes: VersionRunnerChanges,
    expected_reason: str,
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    runner = FakeRunner(**runner_changes)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )

    observed = await adapter.probe(profile(executable), deadline("probe-action"))

    assert not observed.available
    assert observed.reason_code == expected_reason


@pytest.mark.asyncio
async def test_probe_uses_deadline_action_id_as_cancellation_identifier(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    runner = FakeRunner(
        version_outcome="CANCELLED",
        version_return_code=None,
        block_version=True,
    )
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    probe = asyncio.create_task(
        adapter.probe(profile(executable), deadline("probe-action"))
    )
    await runner.started.wait()

    cancelled = await adapter.cancel("probe-action")
    # Always release the fake runner so a failed cancellation assertion cannot hang.
    runner.release.set()
    observed = await probe

    assert cancelled.cancelled
    assert runner.cancelled == ["probe-action"]
    assert runner.calls[0].attempt_id == "probe-action"
    assert observed.reason_code == "CODEQL_PROBE_CANCELLED"


def test_command_policy_accepts_only_version_and_analyze_families(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.codeql_adapter import validate_codeql_command

    executable = tmp_path / "codeql"
    database = tmp_path / "db"
    pack = tmp_path / "pack"
    output = tmp_path / "out" / "codeql-result.sarif"
    common_cache = tmp_path / "out" / "common-cache"
    logs = tmp_path / "out" / "logs"
    max_disk_cache_mb = 1
    valid = (
        str(executable),
        "database",
        "analyze",
        str(database),
        str(pack),
        "--format=sarifv2.1.0",
        f"--output={output}",
        f"--common-caches={common_cache}",
        f"--logdir={logs}",
        f"--max-disk-cache={max_disk_cache_mb}",
    )
    validate_codeql_command(
        valid,
        executable,
        database,
        pack,
        output,
        common_cache,
        logs,
        max_disk_cache_mb,
    )
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
            validate_codeql_command(
                argv,
                executable,
                database,
                pack,
                output,
                common_cache,
                logs,
                max_disk_cache_mb,
            )


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
@pytest.mark.parametrize(
    ("changed_input", "expected_code"),
    [
        ("database", "CODEQL_DATABASE_DIGEST_MISMATCH"),
        ("query_pack", "CODEQL_QUERY_PACK_DIGEST_MISMATCH"),
    ],
)
async def test_execute_discards_results_when_bound_inputs_change_during_analysis(
    codeql_fixture: dict[str, Any], changed_input: str, expected_code: str
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    inputs = codeql_fixture["inputs"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)

    def write_then_mutate(output: Path) -> None:
        output.write_bytes(sarif())
        if changed_input == "database":
            target = next(
                item
                for item in inputs.database.database_root.rglob("*")
                if item.is_file()
            )
        else:
            target = inputs.query_pack_root / "changed-after-start.txt"
        target.write_text("changed", encoding="utf-8")

    runner = FakeRunner(writer=write_then_mutate)
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
    assert observed.raw_output is None
    assert observed.facts == () and observed.relations == ()
    assert {gap.code for gap in observed.gaps} == {expected_code}


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
    attempt_root = codeql_fixture["inputs"].attempt_root
    assert analyze_argv[3] == str(attempt_root / "codeql-run" / "database")
    assert analyze_argv[4] == str(attempt_root / "codeql-run" / "query-pack")


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
    "runner_changes,expected_status,expected_code",
    [
        (
            {"version_outcome": "CANCELLED", "version_return_code": None},
            "SKIPPED",
            "STATIC_TOOL_CANCELLED",
        ),
        (
            {"version_outcome": "TIMED_OUT", "version_return_code": None},
            "FAILED",
            "STATIC_TOOL_TIMEOUT",
        ),
        ({"version_stdout_truncated": True}, "FAILED", "STATIC_OUTPUT_LIMIT"),
        ({"version_stderr_truncated": True}, "FAILED", "STATIC_OUTPUT_LIMIT"),
        ({"version_return_code": 1}, "FAILED", "STATIC_TOOL_FAILED"),
        (
            {"version_stdout": b"not-json"},
            "FAILED",
            "STATIC_TOOL_VERSION_INVALID",
        ),
        ({"version": "0.0.0"}, "FAILED", "STATIC_TOOL_VERSION_MISMATCH"),
    ],
)
async def test_version_stage_preserves_process_failure_semantics(
    codeql_fixture: dict[str, Any],
    runner_changes: VersionRunnerChanges,
    expected_status: str,
    expected_code: str,
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = FakeRunner(sarif=sarif(), **runner_changes)
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
    if expected_code == "STATIC_TOOL_CANCELLED":
        assert observed.errors == ()
        assert {
            item.reason
            for item in observed.rules
            if item.selection_status == "SELECTED"
        } == {"CANCELLED"}
    if expected_code == "STATIC_TOOL_TIMEOUT":
        assert observed.errors and observed.errors[0].retryable


@pytest.mark.asyncio
async def test_version_stage_cancellation_propagates_and_removes_active_attempt(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = FakeRunner(block_version=True)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    execution = asyncio.create_task(
        adapter.execute(
            request,
            fixture_workspace(codeql_fixture),
            tool_profile,
            deadline(str(request.action.action_id)),
        )
    )
    await runner.version_started.wait()

    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution

    assert runner.version_finished.is_set()
    assert not (await adapter.cancel("at1")).cancelled


@pytest.mark.asyncio
async def test_version_stage_exception_removes_active_attempt(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = FakeRunner(version_error=RuntimeError("version failed"))
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )

    with pytest.raises(RuntimeError, match="version failed"):
        await adapter.execute(
            request,
            fixture_workspace(codeql_fixture),
            tool_profile,
            deadline(str(request.action.action_id)),
        )

    assert runner.version_finished.is_set()
    assert not (await adapter.cancel("at1")).cancelled


@pytest.mark.asyncio
async def test_analyze_cancellation_stops_and_awaits_child_under_second_cancel(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    runner = DelayedCancelRunner(sarif=sarif(), block_after_write=True)
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    execution = asyncio.create_task(
        adapter.execute(
            request,
            fixture_workspace(codeql_fixture),
            tool_profile,
            deadline(str(request.action.action_id)),
        )
    )
    await runner.analyze_started.wait()

    execution.cancel()
    cancel_started = asyncio.create_task(runner.cancel_started.wait())
    completed, _ = await asyncio.wait(
        (execution, cancel_started), return_when=asyncio.FIRST_COMPLETED
    )
    try:
        assert cancel_started in completed
        execution.cancel()
        runner.finish_cancel.set()
        with pytest.raises(asyncio.CancelledError):
            await execution
    finally:
        cancel_started.cancel()
        runner.finish_cancel.set()
        runner.release.set()
        await asyncio.gather(cancel_started, execution, return_exceptions=True)

    assert runner.cancelled == ["at1"]
    assert runner.analyze_finished.is_set()
    assert not (await adapter.cancel("at1")).cancelled


@pytest.mark.asyncio
async def test_completed_analyze_wins_race_with_late_caller_cancellation(
    codeql_fixture: dict[str, Any],
) -> None:
    from sastsimi.static_analysis.codeql_adapter import CodeQLProcessAdapter

    executable = codeql_fixture["executable"]
    assert isinstance(executable, Path)
    tool_profile = profile(executable)
    _, request = workspace_and_request(tool_profile)
    execution: asyncio.Task[Any] | None = None

    def cancel_owner_after_result() -> None:
        assert execution is not None
        asyncio.get_running_loop().call_soon(execution.cancel)

    runner = FakeRunner(
        sarif=sarif(), analyze_return_callback=cancel_owner_after_result
    )
    adapter = CodeQLProcessAdapter(
        executable=executable,
        executable_key="trusted-codeql",
        inputs=codeql_fixture["inputs"],
        runner_factory=RunnerFactory(runner),
    )
    execution = asyncio.create_task(
        adapter.execute(
            request,
            fixture_workspace(codeql_fixture),
            tool_profile,
            deadline(str(request.action.action_id)),
        )
    )

    observed = await execution

    assert observed.status == "SUCCEEDED"
    assert runner.cancelled == []
    assert runner.calls[-1].command_kind == "codeql-analyze"


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
    cap = len(payload) - 1
    if cap_name == "max_attempt_output_bytes":
        cap += copied_codeql_input_bytes(codeql_fixture["inputs"])
    tool_profile = profile(executable, **{cap_name: cap})
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
    cap = len(payload)
    if cap_name == "max_attempt_output_bytes":
        cap += copied_codeql_input_bytes(codeql_fixture["inputs"])
    tool_profile = profile(executable, **{cap_name: cap})
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
    tool_profile = profile(
        executable,
        max_attempt_output_bytes=(
            copied_codeql_input_bytes(codeql_fixture["inputs"]) + len(payload)
        ),
    )
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


@pytest.mark.skipif(os.name != "nt", reason="Windows junction/reparse boundary")
def test_quota_binding_rejects_junction_parent_before_backend_lookup(
    codeql_fixture: dict[str, Any], tmp_path: Path
) -> None:
    inputs = codeql_fixture["inputs"]
    output_quota = codeql_fixture["output_quota"]
    external = tmp_path / "quota-parent-target"
    external_attempt = external / "attempt"
    external_attempt.mkdir(parents=True)
    junction = tmp_path / "quota-parent-link"
    windows_root = os.environ.get("SystemRoot", r"C:\Windows")
    cmd = Path(windows_root) / "System32" / "cmd.exe"
    created = subprocess.run(
        [str(cmd), "/d", "/c", "mklink", "/J", str(junction), str(external)],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    assert created.returncode == 0, created.stderr or created.stdout
    linked_attempt = junction / "attempt"
    tool_profile = profile(codeql_fixture["executable"])

    try:
        with pytest.raises(ValueError, match="CODEQL_OUTPUT_QUOTA_UNENFORCEABLE"):
            inputs.output_quota_binding(
                action_id="action-through-junction",
                attempt_id=inputs.attempt_id,
                profile_ref=reference(tool_profile),
                root=linked_attempt,
                lease_id=inputs.output_quota_lease_id,
                limit_bytes=tool_profile.max_attempt_output_bytes,
            )
    finally:
        junction.rmdir()

    assert output_quota.calls == []


def test_quota_binding_rejects_generic_reparse_parent_before_backend_lookup(
    codeql_fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-junction Windows reparse ancestor must fail before quota lookup."""

    inputs = codeql_fixture["inputs"]
    output_quota = codeql_fixture["output_quota"]
    marked_parent = inputs.attempt_root.parent
    real_lstat = Path.lstat

    class ReparseStat:
        st_file_attributes = 0x400
        st_reparse_tag = 1

        def __init__(self, value: os.stat_result) -> None:
            self._value = value

        def __getattr__(self, name: str) -> object:
            return getattr(self._value, name)

    def simulated_lstat(path: Path) -> os.stat_result:
        value = real_lstat(path)
        if path == marked_parent:
            return cast(os.stat_result, ReparseStat(value))
        return value

    tool_profile = profile(codeql_fixture["executable"])
    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", simulated_lstat)
        with pytest.raises(ValueError, match="CODEQL_OUTPUT_QUOTA_UNENFORCEABLE"):
            inputs.output_quota_binding(
                action_id="action-through-reparse",
                attempt_id=inputs.attempt_id,
                profile_ref=reference(tool_profile),
                root=inputs.attempt_root,
                lease_id=inputs.output_quota_lease_id,
                limit_bytes=tool_profile.max_attempt_output_bytes,
            )

    assert output_quota.calls == []


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
            codeql_fixture["inputs"].attempt_root
            / "codeql-run"
            / "output"
            / "codeql-result.sarif"
        )
        descriptor_stat = os.fstat(descriptor)
        path_stat = path.stat() if path.exists() else None
        if (
            not replaced
            and path_stat is not None
            and (descriptor_stat.st_dev, descriptor_stat.st_ino)
            == (path_stat.st_dev, path_stat.st_ino)
        ):
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


def test_attempt_tree_rejects_descendant_hard_link_when_supported(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.codeql_adapter import _directory_size

    root = tmp_path / "attempt"
    nested = root / "nested"
    nested.mkdir(parents=True)
    external = tmp_path / "external.bin"
    external.write_bytes(b"outside")
    try:
        os.link(external, nested / "linked.bin")
    except OSError:
        pytest.skip("hard links unavailable")

    with pytest.raises(ValueError, match="CODEQL_OUTPUT_NOT_REGULAR"):
        _directory_size(root, 10_000)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction/reparse boundary")
def test_attempt_tree_rejects_descendant_junction(tmp_path: Path) -> None:
    from sastsimi.static_analysis.codeql_adapter import _directory_size

    root = tmp_path / "attempt"
    root.mkdir()
    external = tmp_path / "junction-target"
    external.mkdir()
    (external / "outside.bin").write_bytes(b"outside")
    junction = root / "linked-directory"
    windows_root = os.environ.get("SystemRoot", r"C:\Windows")
    cmd = Path(windows_root) / "System32" / "cmd.exe"
    created = subprocess.run(
        [str(cmd), "/d", "/c", "mklink", "/J", str(junction), str(external)],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    assert created.returncode == 0, created.stderr or created.stdout
    assert junction.is_junction()

    try:
        with pytest.raises(ValueError, match="CODEQL_OUTPUT_NOT_REGULAR"):
            _directory_size(root, 10_000)
    finally:
        junction.rmdir()
