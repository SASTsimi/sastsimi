from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from collections.abc import Callable, Generator, Sequence
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


@pytest.fixture
def tmp_path(request: pytest.FixtureRequest) -> Generator[Path, None, None]:
    """Use a workspace-local root because the host pytest temp ACL is broken."""

    suffix = hashlib.sha256(
        f"{request.node.nodeid}:{uuid.uuid4().hex}".encode()
    ).hexdigest()[:16]
    path = Path.cwd() / ".t08-opengrep-tests" / suffix
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _process_result(
    spec: ProcessSpec,
    *,
    stdout: bytes = b"",
    outcome: str = "SUCCEEDED",
    return_code: int | None = 0,
    truncated: bool = False,
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
        stdout_sha256=_sha256(stdout),
        stderr_name="stderr",
        stderr_size=0,
        stderr_sha256=_sha256(b""),
        elapsed_ms=1,
    )
    return ProcessResult(
        outcome=outcome,  # type: ignore[arg-type]
        return_code=return_code,
        stdout=stdout,
        stderr_tail=b"",
        stdout_truncated=truncated,
        stderr_truncated=False,
        elapsed_ms=1,
        receipt=receipt,
        receipt_path=spec.attempt_output_dir / "receipt.json",
    )


class FakeRunner:
    def __init__(
        self,
        outputs: list[dict[str, object]] | None = None,
        *,
        version: str = "1.8.0",
        after_scan: Callable[[int], None] | None = None,
    ) -> None:
        self.outputs = list(outputs or [])
        self.version = version
        self.after_scan = after_scan
        self.calls: list[ProcessSpec] = []
        self.cancelled: list[str] = []
        self.scan_count = 0

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        if spec.argv[1:] == ("--version",):
            return _process_result(spec, stdout=(self.version + "\n").encode())
        output = self.outputs.pop(0)
        self.scan_count += 1
        if self.after_scan is not None:
            self.after_scan(self.scan_count)
        return _process_result(
            spec,
            stdout=cast(bytes, output.get("stdout", b"")),
            outcome=cast(str, output.get("outcome", "SUCCEEDED")),
            return_code=cast(int | None, output.get("return_code", 0)),
            truncated=cast(bool, output.get("truncated", False)),
        )

    async def cancel(self, attempt_id: str) -> CancellationResult:
        self.cancelled.append(attempt_id)
        return CancellationResult(True, None)


class RunnerFactory:
    def __init__(self, runner: FakeRunner) -> None:
        self.runner = runner
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> FakeRunner:
        self.calls.append(kwargs)
        return self.runner


def _profile(executable: Path, **changes: object) -> StaticToolProfile:
    profile_meta = meta("static_tool_profile", attempt=None)
    profile_meta["created_at"] = datetime(2026, 9, 8, tzinfo=UTC)
    value: dict[str, object] = {
        "meta": profile_meta,
        "profile_key": "opengrep-fixture",
        "purpose": "FIXTURE",
        "status": "APPROVED",
        "adapter_key": "OPENGREP",
        "tool_name": "OPENGREP",
        "tool_kind": "RULE_BASED",
        "executable_key": "trusted-opengrep",
        "executable_sha256": _sha256(executable.read_bytes()),
        "expected_version": "1.8.0",
        "capability_evidence_ref": None,
        "probe_timeout_ms": 1_000,
        "run_timeout_ms": 5_000,
        "stdout_limit_bytes": 100_000,
        "stderr_limit_bytes": 1_024,
        "max_attempt_output_bytes": 400_000,
        "max_output_file_bytes": 100_000,
        "max_artifact_read_bytes": 100_000,
    }
    value.update(changes)
    return StaticToolProfile.model_validate(value)


def _deadline(action_id: str = "action-1") -> MonotonicActionDeadline:
    return MonotonicActionDeadline(action_id, 0, 10**15)


def _output(
    *,
    paths: tuple[str, ...] = ("src/a.py",),
    telemetry: Sequence[object] | None = None,
    results: list[dict[str, object]] | None = None,
) -> bytes:
    return canonical_bytes(
        {
            "version": "1.8.0",
            "results": results or [],
            "errors": [],
            "paths": {"scanned": list(paths), "skipped": []},
            "time": {
                "rules": telemetry
                if telemetry is not None
                else [{"id": "R1"}, {"id": "R2"}]
            },
        }
    )


def _finding(rule_id: str, path: str, line: int = 1) -> dict[str, object]:
    return {
        "check_id": rule_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 2},
        "extra": {
            "message": "untrusted severity is not a verdict",
            "severity": "ERROR",
        },
    }


@pytest.fixture
def opengrep_fixture(tmp_path: Path) -> dict[str, object]:
    from sastsimi.static_analysis.open_grep_adapter import OpenGrepExecutionInputs

    executable = tmp_path / "opengrep.exe"
    executable.write_bytes(b"trusted-opengrep")
    config = tmp_path / "trusted-rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    paths = (
        "src/a.py",
        "src/b.py",
        "src/c.py",
        "-option.py",
    )
    tracked: list[TrackedFile] = []
    for index, path in enumerate(paths):
        target = workspace_root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"value_{index} = {index}\n", encoding="utf-8")
        tracked.append(
            TrackedFile(path, "100644", f"blob-{index}", target.stat().st_size)
        )
    attempt_root = tmp_path / "attempt"
    attempt_root.mkdir(exist_ok=True)
    mappings = (
        StaticRuleMapping("R1", "SOURCE", None, False),
        StaticRuleMapping("R2", "SINK", None, False),
        StaticRuleMapping("R3", "SANITIZER", None, False),
        StaticRuleMapping("R4", "VALIDATOR", None, False),
        StaticRuleMapping("R5", "AUTH_CHECK", None, False),
        StaticRuleMapping("R6", "PERMISSION_CHECK", None, False),
        StaticRuleMapping("R7", "OTHER", None, False),
        StaticRuleMapping("R8", "OTHER", None, False),
    )
    selected = ("R1", "R2")
    tool_profile = _profile(executable)
    profile_ref = cast(StoredDataRef, reference(tool_profile))
    analysis_config_ref = StoredDataRef.model_validate(
        profile_ref.model_dump()
        | {
            "stored_data_id": "cfg",
            "data_kind": "analysis_config",
            "record_id": "cfg",
        }
    )
    catalog_ref = StoredDataRef.model_validate(
        profile_ref.model_dump()
        | {
            "stored_data_id": "catalog",
            "data_kind": "rule_catalog",
            "record_id": "catalog",
        }
    )
    inputs = OpenGrepExecutionInputs(
        config_path=config,
        config_digest=_sha256(config.read_bytes()),
        analysis_config_ref=analysis_config_ref,
        rule_catalog_ref=catalog_ref,
        rule_catalog=mappings,
        selected_rule_ids=selected,
        selected_rule_packs=("fixture/web",),
        tracked_files=tuple(tracked),
        attempt_root=attempt_root,
        attempt_id="at1",
    )
    workspace = CodeWorkspace.model_validate_json(
        json.dumps(
            make("CodeWorkspace")
            | {"workspace_id": "ws1", "commit_id": "c1", "status": "READY"}
        )
    )
    action_data = make("ActionRequest", "action_request")
    action = ActionRequest.model_validate_json(
        json.dumps(
            action_data
            | {
                "requested_by": "STATIC_ANALYSIS",
                "action_type": "RUN_TOOL",
                "tool_name": "OPENGREP",
                "file_paths": paths,
                "input_refs": tuple(
                    ref.model_dump(mode="json")
                    for ref in (profile_ref, analysis_config_ref, catalog_ref)
                ),
            }
        )
    )
    request = StaticToolRequest(
        action=action,
        workspace=workspace,
        tool_profile_ref=profile_ref,
        analysis_config_ref=analysis_config_ref,
        rule_catalog_ref=catalog_ref,
    )
    return {
        "executable": executable,
        "config": config,
        "root": workspace_root,
        "profile": tool_profile,
        "inputs": inputs,
        "request": request,
    }


def _adapter(
    value: dict[str, object],
    runner: FakeRunner,
    **changes: object,
) -> Any:
    from sastsimi.static_analysis.open_grep_adapter import OpenGrepProcessAdapter

    kwargs: dict[str, object] = {
        "executable": value["executable"],
        "executable_key": "trusted-opengrep",
        "inputs": value["inputs"],
        "runner_factory": RunnerFactory(runner),
    }
    kwargs.update(changes)
    return cast(Any, OpenGrepProcessAdapter)(**kwargs)


def _one_target_limit(value: dict[str, object]) -> int:
    from sastsimi.static_analysis.open_grep_adapter import encoded_command_cost

    request = cast(StaticToolRequest, value["request"])
    base = (
        str(value["executable"]),
        "scan",
        "--config",
        str(value["config"]),
        "--json",
        "--time",
        "--disable-version-check",
        "--",
    )
    paths = tuple(sorted(request.action.file_paths))
    single = max(
        encoded_command_cost((*base, path), (), platform="posix") for path in paths
    )
    pair = min(
        encoded_command_cost((*base, left, right), (), platform="posix")
        for index, left in enumerate(paths)
        for right in paths[index + 1 :]
    )
    assert single < pair
    return single


@pytest.mark.asyncio
async def test_probe_uses_only_exact_executable_version_and_digest(
    opengrep_fixture: dict[str, object],
) -> None:
    runner = FakeRunner()
    adapter = _adapter(opengrep_fixture, runner)
    observed = await adapter.probe(opengrep_fixture["profile"], _deadline())
    assert observed.available
    assert len(runner.calls) == 1
    assert runner.calls[0].argv[1:] == ("--version",)
    assert runner.calls[0].env == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["version", "digest", "key", "profile_ref", "config", "catalog", "workspace"],
)
async def test_preflight_mismatch_invokes_no_scan(
    opengrep_fixture: dict[str, object], case: str
) -> None:
    tool_profile = cast(StaticToolProfile, opengrep_fixture["profile"])
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    inputs = opengrep_fixture["inputs"]
    changes: dict[str, object] = {}
    if case == "version":
        tool_profile = tool_profile.model_copy(update={"expected_version": "9.9.9"})
    elif case == "digest":
        tool_profile = tool_profile.model_copy(update={"executable_sha256": "f" * 64})
    elif case == "key":
        changes["executable_key"] = "wrong"
    elif case == "profile_ref":
        request = replace(request, tool_profile_ref=request.analysis_config_ref)
    elif case == "config":
        Path(cast(Any, inputs).config_path).write_text("changed: true\n")
    elif case == "catalog":
        request = replace(request, rule_catalog_ref=request.analysis_config_ref)
    else:
        request = replace(
            request,
            workspace=request.workspace.model_copy(
                update={"status": "FAILED", "commit_id": None}
            ),
        )
    runner = FakeRunner()
    adapter = _adapter(opengrep_fixture, runner, **changes)
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        tool_profile,
        _deadline(str(request.action.action_id)),
    )
    assert result.status in {"FAILED", "SKIPPED"}
    assert runner.calls == []
    assert result.gaps


@pytest.mark.asyncio
async def test_scan_uses_fixed_options_explicit_targets_and_deterministic_batches(
    opengrep_fixture: dict[str, object],
) -> None:
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    outputs: list[dict[str, object]] = [
        {"stdout": _output(paths=(path,))} for path in sorted(request.action.file_paths)
    ]
    runner = FakeRunner(outputs)
    adapter = _adapter(
        opengrep_fixture,
        runner,
        _test_command_limit_bytes=_one_target_limit(opengrep_fixture),
        platform="posix",
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    scans = runner.calls[1:]
    assert len(scans) == 4, (result.status, result.errors, result.gaps, runner.calls)
    assert result.status == "SUCCEEDED"
    flattened: list[str] = []
    for spec in scans:
        assert spec.argv[1:8] == (
            "scan",
            "--config",
            str(opengrep_fixture["config"]),
            "--json",
            "--time",
            "--disable-version-check",
            "--",
        )
        flattened.extend(spec.argv[8:])
        assert spec.deadline is scans[0].deadline
    assert flattened == sorted(request.action.file_paths)
    assert "-option.py" in flattened


def test_platform_command_cost_is_exact_and_test_limit_can_only_reduce(
    opengrep_fixture: dict[str, object],
) -> None:
    from sastsimi.static_analysis.open_grep_adapter import encoded_command_cost

    windows_ascii = encoded_command_cost(("tool", "a b"), (), platform="win32")
    windows_multibyte = encoded_command_cost(("tool", "가 b"), (), platform="win32")
    posix = encoded_command_cost(("tool", "a b"), (("K", "값"),), platform="posix")
    assert windows_ascii == len('tool "a b"'.encode("utf-16-le")) + 2
    assert windows_multibyte == len('tool "가 b"'.encode("utf-16-le")) + 2
    assert posix == len(b"tool\0a b\0K=\xea\xb0\x92\0") + 5 * 8

    runner = FakeRunner([])
    adapter = _adapter(opengrep_fixture, runner, _test_command_limit_bytes=10**9)
    assert adapter.command_limit_bytes < 10**9


@pytest.mark.asyncio
async def test_cancelled_second_batch_keeps_first_and_never_starts_third(
    opengrep_fixture: dict[str, object],
) -> None:
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    runner = FakeRunner(
        [
            {
                "stdout": _output(
                    paths=("-option.py",), results=[_finding("R1", "-option.py")]
                )
            },
            {"stdout": b'{"partial":', "outcome": "CANCELLED", "return_code": None},
            {"stdout": _output(paths=("src/b.py",))},
        ]
    )
    adapter = _adapter(
        opengrep_fixture,
        runner,
        _test_command_limit_bytes=_one_target_limit(opengrep_fixture),
        platform="posix",
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    assert len(runner.calls) == 3  # version plus two batches
    assert result.status == "PARTIAL"
    assert [fact.location.file_path for fact in result.facts] == ["-option.py"]
    assert any(gap.code == "STATIC_TOOL_CANCELLED" for gap in result.gaps)


@pytest.mark.asyncio
async def test_one_deadline_prevents_next_batch_after_expiry(
    opengrep_fixture: dict[str, object],
) -> None:
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    ticks = iter((0, 0, 2_000_000))
    runner = FakeRunner([{"stdout": _output(paths=("-option.py",))}])
    adapter = _adapter(
        opengrep_fixture,
        runner,
        _test_command_limit_bytes=_one_target_limit(opengrep_fixture),
        platform="posix",
        monotonic_ns=lambda: next(ticks, 2_000_000),
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        MonotonicActionDeadline(str(request.action.action_id), 0, 1_000_000),
    )
    assert len(runner.calls) == 2
    assert result.status == "PARTIAL"
    assert any(gap.reason == "TIMEOUT" for gap in result.gaps)


@pytest.mark.asyncio
async def test_exact_telemetry_is_the_only_proof_of_selected_zero_hits(
    opengrep_fixture: dict[str, object],
) -> None:
    runner = FakeRunner([{"stdout": _output(paths=("src/a.py",))}])
    adapter = _adapter(opengrep_fixture, runner)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request,
        action=request.action.model_copy(update={"file_paths": ("src/a.py",)}),
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    selected = {
        item.rule_id: item
        for item in result.rules
        if item.selection_status == "SELECTED"
    }
    assert result.status == "SUCCEEDED"
    assert set(selected) == {"R1", "R2"}
    assert all(item.execution_status == "EXECUTED" for item in selected.values())
    assert all(item.hit_count == 0 for item in selected.values())


@pytest.mark.asyncio
async def test_cross_batch_telemetry_gap_invalidates_affected_rule_only(
    opengrep_fixture: dict[str, object],
) -> None:
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request,
        action=request.action.model_copy(
            update={"file_paths": ("src/a.py", "src/b.py")}
        ),
    )
    runner = FakeRunner(
        [
            {
                "stdout": _output(
                    paths=("src/a.py",), results=[_finding("R1", "src/a.py")]
                )
            },
            {"stdout": _output(paths=("src/b.py",), telemetry=[{"id": "R2"}])},
        ]
    )
    adapter = _adapter(
        opengrep_fixture,
        runner,
        _test_command_limit_bytes=_one_target_limit(opengrep_fixture),
        platform="posix",
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    rules = {item.rule_id: item for item in result.rules}
    assert result.status == "PARTIAL"
    assert rules["R1"].execution_status == "UNKNOWN"
    assert rules["R1"].hit_count is None
    assert rules["R2"].execution_status == "EXECUTED"
    assert rules["R2"].hit_count == 0
    assert not any(fact.rule_id == "R1" for fact in result.facts)


@pytest.mark.asyncio
async def test_attempt_owned_output_and_shell_metacharacter_target_are_closed_argv(
    opengrep_fixture: dict[str, object],
) -> None:
    root = cast(Path, opengrep_fixture["root"])
    target_path = "src/space name;$(not-a-shell).py"
    target = root.joinpath(*target_path.split("/"))
    target.write_text("value = 1\n", encoding="utf-8")
    inputs = cast(Any, opengrep_fixture["inputs"])
    opengrep_fixture["inputs"] = replace(
        inputs,
        tracked_files=inputs.tracked_files
        + (TrackedFile(target_path, "100644", "blob-meta", target.stat().st_size),),
    )
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request,
        action=request.action.model_copy(update={"file_paths": (target_path,)}),
    )
    runner = FakeRunner([{"stdout": _output(paths=(target_path,))}])
    adapter = _adapter(opengrep_fixture, runner)
    result = await adapter.execute(
        request,
        root,
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    scan = runner.calls[1]
    assert result.status == "SUCCEEDED"
    assert scan.argv[-1] == target_path
    assert (
        scan.attempt_output_dir
        == cast(Any, opengrep_fixture["inputs"]).attempt_root / "opengrep-run"
    )
    assert scan.cwd == root


@pytest.mark.asyncio
async def test_one_target_that_cannot_fit_fails_before_probe_or_scan(
    opengrep_fixture: dict[str, object],
) -> None:
    from sastsimi.static_analysis.open_grep_adapter import encoded_command_cost

    base = (
        str(opengrep_fixture["executable"]),
        "scan",
        "--config",
        str(opengrep_fixture["config"]),
        "--json",
        "--time",
        "--disable-version-check",
        "--",
    )
    runner = FakeRunner([])
    adapter = _adapter(
        opengrep_fixture,
        runner,
        _test_command_limit_bytes=encoded_command_cost(base, (), platform="posix"),
        platform="posix",
    )
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request,
        action=request.action.model_copy(update={"file_paths": ("src/a.py",)}),
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    assert result.status == "FAILED"
    assert runner.calls == []
    assert any(gap.code == "OPENGREP_TARGET_TOO_LONG" for gap in result.gaps)


@pytest.mark.asyncio
async def test_all_catalog_fact_kinds_and_raw_duplicate_counts_are_preserved(
    opengrep_fixture: dict[str, object],
) -> None:
    inputs = cast(Any, opengrep_fixture["inputs"])
    inputs = replace(inputs, selected_rule_ids=tuple(f"R{i}" for i in range(1, 8)))
    opengrep_fixture["inputs"] = inputs
    telemetry = [{"id": f"R{i}"} for i in range(1, 8)]
    results = [_finding(f"R{i}", "src/a.py", i) for i in range(1, 8)]
    results.append(_finding("R1", "src/a.py", 1))
    runner = FakeRunner([{"stdout": _output(telemetry=telemetry, results=results)}])
    adapter = _adapter(opengrep_fixture, runner)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request, action=request.action.model_copy(update={"file_paths": ("src/a.py",)})
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    assert [fact.fact_kind for fact in result.facts] == [
        "SOURCE",
        "SINK",
        "SANITIZER",
        "VALIDATOR",
        "AUTH_CHECK",
        "PERMISSION_CHECK",
        "OTHER",
        "SOURCE",
    ]
    rules = {item.rule_id: item for item in result.rules}
    assert rules["R1"].hit_count == 2
    assert rules["R8"].execution_status == "NOT_EXECUTED"
    assert rules["R8"].reason == "NOT_SELECTED"
    assert "TRUE" not in repr(result) and "CWE" not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("telemetry", "unknown"),
    [
        ([{"id": "R2"}], {"R1"}),
        ([{"id": "R1"}, {"id": "R1"}, {"id": "R2"}], {"R1"}),
        ([{"id": 1}, {"id": "R2"}], {"R1", "R2"}),
        ([{"id": "UNKNOWN"}, {"id": "R1"}, {"id": "R2"}], {"R1", "R2"}),
        ([{"id": "R3"}, {"id": "R1"}, {"id": "R2"}], {"R1", "R2"}),
    ],
)
async def test_untrusted_rule_telemetry_never_proves_execution_or_zero_hits(
    opengrep_fixture: dict[str, object], telemetry: list[object], unknown: set[str]
) -> None:
    runner = FakeRunner([{"stdout": _output(telemetry=telemetry)}])
    adapter = _adapter(opengrep_fixture, runner)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request, action=request.action.model_copy(update={"file_paths": ("src/a.py",)})
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    rules = {item.rule_id: item for item in result.rules}
    for rule_id in unknown:
        assert rules[rule_id].execution_status == "UNKNOWN"
        assert rules[rule_id].reason == "TELEMETRY_MISSING"
        assert rules[rule_id].hit_count is None
    assert result.status == "PARTIAL"
    assert any(gap.code == "STATIC_RULE_TELEMETRY_MISSING" for gap in result.gaps)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output",
    [
        {"stdout": b"not-json"},
        {"stdout": _output(), "truncated": True},
    ],
)
async def test_malformed_or_truncated_batch_is_never_parsed(
    opengrep_fixture: dict[str, object], output: dict[str, object]
) -> None:
    runner = FakeRunner([output])
    adapter = _adapter(opengrep_fixture, runner)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request, action=request.action.model_copy(update={"file_paths": ("src/a.py",)})
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    assert result.facts == ()
    assert result.status == "FAILED"
    assert result.raw_output is None


@pytest.mark.asyncio
async def test_nonzero_exit_with_complete_json_is_usable_partial_evidence(
    opengrep_fixture: dict[str, object],
) -> None:
    runner = FakeRunner(
        [
            {
                "stdout": _output(results=[_finding("R1", "src/a.py")]),
                "outcome": "FAILED",
                "return_code": 2,
            }
        ]
    )
    adapter = _adapter(opengrep_fixture, runner)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request, action=request.action.model_copy(update={"file_paths": ("src/a.py",)})
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    assert result.status == "PARTIAL"
    assert len(result.facts) == 1
    assert result.errors and result.gaps


@pytest.mark.asyncio
async def test_aggregate_raw_envelope_over_artifact_cap_is_never_published(
    opengrep_fixture: dict[str, object],
) -> None:
    runner = FakeRunner(
        [{"stdout": _output(paths=("src/a.py",), results=[_finding("R1", "src/a.py")])}]
    )
    adapter = _adapter(opengrep_fixture, runner)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request,
        action=request.action.model_copy(update={"file_paths": ("src/a.py",)}),
    )
    profile = cast(StaticToolProfile, opengrep_fixture["profile"]).model_copy(
        update={"max_output_file_bytes": 64}
    )
    # Keep the action's exact profile reference synchronized with the smaller cap.
    profile_ref = cast(StoredDataRef, reference(profile))
    request = replace(
        request,
        tool_profile_ref=profile_ref,
        action=request.action.model_copy(
            update={
                "input_refs": (
                    profile_ref,
                    request.analysis_config_ref,
                    request.rule_catalog_ref,
                )
            }
        ),
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        profile,
        _deadline(str(request.action.action_id)),
    )
    assert result.status == "FAILED"
    assert result.raw_output is None
    assert result.facts == ()
    assert any(gap.code == "STATIC_OUTPUT_LIMIT" for gap in result.gaps)


@pytest.mark.asyncio
async def test_raw_batch_over_cap_is_rejected_before_json_decode(
    opengrep_fixture: dict[str, object],
) -> None:
    compact = _output(
        paths=("src/a.py",), results=[_finding("R1", "src/a.py")]
    )
    raw = (b" " * 2_048) + compact
    assert len(compact) < 1_024 < len(raw)
    runner = FakeRunner([{"stdout": raw}])
    adapter = _adapter(opengrep_fixture, runner)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request,
        action=request.action.model_copy(update={"file_paths": ("src/a.py",)}),
    )
    profile = cast(StaticToolProfile, opengrep_fixture["profile"]).model_copy(
        update={"max_output_file_bytes": 1_024}
    )
    profile_ref = cast(StoredDataRef, reference(profile))
    request = replace(
        request,
        tool_profile_ref=profile_ref,
        action=request.action.model_copy(
            update={
                "input_refs": (
                    profile_ref,
                    request.analysis_config_ref,
                    request.rule_catalog_ref,
                )
            }
        ),
    )

    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        profile,
        _deadline(str(request.action.action_id)),
    )

    assert result.status == "FAILED"
    assert result.raw_output is None
    assert result.facts == ()
    assert any(gap.code == "STATIC_OUTPUT_LIMIT" for gap in result.gaps)


@pytest.mark.asyncio
async def test_file_replaced_during_scan_discards_all_evidence(
    opengrep_fixture: dict[str, object],
) -> None:
    target = cast(Path, opengrep_fixture["root"]) / "src" / "a.py"

    def replace_target(_: int) -> None:
        replacement = target.with_suffix(".new")
        replacement.write_bytes(b"X" * target.stat().st_size)
        replacement.replace(target)

    runner = FakeRunner(
        [{"stdout": _output(results=[_finding("R1", "src/a.py")])}],
        after_scan=replace_target,
    )
    adapter = _adapter(opengrep_fixture, runner)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request, action=request.action.model_copy(update={"file_paths": ("src/a.py",)})
    )
    result = await adapter.execute(
        request,
        cast(Path, opengrep_fixture["root"]),
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    assert result.status == "FAILED"
    assert result.facts == ()
    assert any(gap.code == "STATIC_MANIFEST_CHANGED" for gap in result.gaps)


@pytest.mark.asyncio
async def test_lfs_pointer_and_gitlink_are_excluded_before_process(
    opengrep_fixture: dict[str, object],
) -> None:
    inputs = cast(Any, opengrep_fixture["inputs"])
    root = cast(Path, opengrep_fixture["root"])
    lfs = root / "large.py"
    lfs.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:0123456789abcdef\nsize 1\n",
        encoding="utf-8",
    )
    opengrep_fixture["inputs"] = replace(
        inputs,
        tracked_files=inputs.tracked_files
        + (
            TrackedFile("large.py", "100644", "lfs", lfs.stat().st_size),
            TrackedFile("vendor", "160000", "submodule", 0),
        ),
    )
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request,
        action=request.action.model_copy(update={"file_paths": ("large.py", "vendor")}),
    )
    runner = FakeRunner([])
    adapter = _adapter(opengrep_fixture, runner)
    result = await adapter.execute(
        request,
        root,
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    assert runner.calls == []
    assert result.status == "SKIPPED"
    assert set(result.skipped_paths) == {"large.py", "vendor"}


@pytest.mark.asyncio
async def test_symlink_and_gitlink_are_excluded_before_process(
    opengrep_fixture: dict[str, object], tmp_path: Path
) -> None:
    inputs = cast(Any, opengrep_fixture["inputs"])
    root = cast(Path, opengrep_fixture["root"])
    outside = tmp_path / "outside.py"
    outside.write_text("danger = 1\n")
    linked = root / "linked.py"
    try:
        linked.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    tracked = inputs.tracked_files + (
        TrackedFile("linked.py", "120000", "link", outside.stat().st_size),
        TrackedFile("vendor", "160000", "submodule", 0),
    )
    opengrep_fixture["inputs"] = replace(inputs, tracked_files=tracked)
    request = cast(StaticToolRequest, opengrep_fixture["request"])
    request = replace(
        request,
        action=request.action.model_copy(
            update={"file_paths": ("linked.py", "vendor")}
        ),
    )
    runner = FakeRunner([])
    adapter = _adapter(opengrep_fixture, runner)
    result = await adapter.execute(
        request,
        root,
        cast(StaticToolProfile, opengrep_fixture["profile"]),
        _deadline(str(request.action.action_id)),
    )
    assert runner.calls == []
    assert result.status == "SKIPPED"
    assert set(result.skipped_paths) == {"linked.py", "vendor"}
