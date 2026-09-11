from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import sys
import time
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

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
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.static_analysis.process import process_command_fingerprint
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref


class FixedWorkspaceLocator:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.checks = 0
        self.root_calls = 0

    def root_for(self, workspace: CodeWorkspace) -> Path:
        del workspace
        self.root_calls += 1
        return self.root

    async def assert_unchanged(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        del workspace, deadline, attempt_id, check_id
        self.checks += 1
        return ()

    def validate_integrity_receipts(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_ids: tuple[str, ...],
        receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        del workspace, deadline, attempt_id, check_ids, receipts


class FixedOutputRunner:
    def __init__(
        self,
        root: Path,
        payload: dict[str, Any],
        before_return: Callable[[], None] | None = None,
    ) -> None:
        self.attempt_id = "at1"
        self.output_root = root / "attempt"
        self.output_root.mkdir(exist_ok=True)
        self.workspace_root = root
        self.payload = payload
        self.before_return = before_return
        self.calls: list[ProcessSpec] = []

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        if self.before_return is not None:
            self.before_return()
        raw = json.dumps(self.payload, sort_keys=True).encode()
        receipt = ProcessReceipt(
            action_id=spec.deadline.action_id,
            invocation_id=spec.invocation_id,
            command_kind=spec.command_kind,
            attempt_id=spec.attempt_id,
            command_fingerprint=process_command_fingerprint(spec),
            outcome="SUCCEEDED",
            return_code=0,
            stdout_name="stdout.bin",
            stdout_size=len(raw),
            stdout_sha256=hashlib.sha256(raw).hexdigest(),
            stderr_name="stderr.bin",
            stderr_size=0,
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            elapsed_ms=1,
        )
        return ProcessResult(
            outcome="SUCCEEDED",
            return_code=0,
            stdout=raw,
            stderr_tail=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            elapsed_ms=1,
            receipt=receipt,
            receipt_path=self.output_root / "receipt.json",
        )

    async def cancel(self, attempt_id: str) -> CancellationResult:
        del attempt_id
        return CancellationResult(cancelled=False, reason="NOT_RUNNING")


class FixedRunnerFactory:
    def __init__(self, runner: Any) -> None:
        self.runner = runner

    def __call__(self, **values: object) -> Any:
        del values
        return self.runner


class SafeRunnerFactory:
    def __call__(
        self,
        *,
        action_id: str,
        attempt_id: str,
        workspace_root: Path,
        output_root: Path,
        executable: Path,
        output_limit_bytes: int,
    ) -> Any:
        from sastsimi.static_analysis.process import (
            AttemptOutputBudget,
            SafeProcessRunner,
        )

        return SafeProcessRunner(
            action_id=action_id,
            attempt_id=attempt_id,
            workspace_root=workspace_root,
            output_root=output_root,
            executable=executable,
            output_budget=AttemptOutputBudget(
                attempt_id=attempt_id, limit_bytes=output_limit_bytes
            ),
        )


def _empty_worker_payload(paths: tuple[str, ...]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "parser_version": platform.python_version(),
        "files": list(paths),
        "analyzed_paths": list(paths),
        "skipped_paths": [],
        "symbols": [],
        "facts": [],
        "relations": [],
        "gaps": [],
        "errors": [],
    }


def _profile(executable: Path) -> StaticToolProfile:
    return StaticToolProfile.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("static_tool_profile", attempt=None),
                "profile_key": "python-ast-test",
                "purpose": "FIXTURE",
                "status": "APPROVED",
                "adapter_key": "PYTHON_AST",
                "tool_name": "AST",
                "tool_kind": "STRUCTURE",
                "executable_key": "fixture-python",
                "executable_sha256": hashlib.sha256(
                    executable.read_bytes()
                ).hexdigest(),
                "expected_version": platform.python_version(),
                "capability_evidence_ref": None,
                "probe_timeout_ms": 10_000,
                "run_timeout_ms": 10_000,
                "stdout_limit_bytes": 512_000,
                "stderr_limit_bytes": 32_000,
                "max_attempt_output_bytes": 1_000_000,
                "max_output_file_bytes": 512_000,
                "max_artifact_read_bytes": 512_000,
            }
        )
    )


def _request(paths: tuple[str, ...]) -> StaticToolRequest:
    action_data = make("ActionRequest", "action_request")
    action = ActionRequest.model_validate_json(
        canonical_bytes(
            action_data
            | {
                "action_id": "ast-action",
                "requested_by": "STATIC_ANALYSIS",
                "action_type": "RUN_TOOL",
                "work_ref": ref("work_execution_state"),
                "expected_state_version": 1,
                "tool_name": "AST",
                "file_paths": paths,
            }
        )
    )
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            make("CodeWorkspace")
            | {
                "repository_url": "https://example.test/repository.git",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    profile_ref = StoredDataRef.model_validate(ref("static_tool_profile"))
    config_ref = StoredDataRef.model_validate(ref("analysis_configuration"))
    return StaticToolRequest(
        action=action,
        workspace=workspace,
        tool_profile_ref=profile_ref,
        analysis_config_ref=config_ref,
        rule_catalog_ref=None,
    )


def _manifest(root: Path, paths: tuple[str, ...]) -> tuple[TrackedFile, ...]:
    result = []
    for path in paths:
        target = root / path
        size = target.lstat().st_size if target.exists() or target.is_symlink() else 0
        result.append(
            TrackedFile(
                git_path=path,
                git_mode="100644",
                blob_id=hashlib.sha256(path.encode()).hexdigest(),
                size_bytes=size,
            )
        )
    return tuple(result)


async def _run(
    tmp_path: Path,
    paths: tuple[str, ...],
    *,
    manifest_paths: tuple[str, ...] | None = None,
) -> tuple[StaticToolObservation, FixedWorkspaceLocator]:
    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter
    from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner

    root = tmp_path / "workspace"
    output = tmp_path / "attempt"
    output.mkdir(exist_ok=True)
    executable = Path(sys.executable)
    locator = FixedWorkspaceLocator(root)
    runner = SafeProcessRunner(
        action_id="ast-action",
        attempt_id="at1",
        workspace_root=root,
        output_root=output,
        executable=executable,
        output_budget=AttemptOutputBudget(attempt_id="at1", limit_bytes=1_000_000),
    )
    adapter = PythonAstProcessAdapter(
        executable=executable,
        worker_path=Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py",
        process_runner=runner,
        probe_runner_factory=FixedRunnerFactory(runner),
        probe_root=output,
        workspace_locator=locator,
        tracked_files=_manifest(root, manifest_paths or paths),
        monotonic_ns=time.monotonic_ns,
    )
    deadline = MonotonicActionDeadline(
        action_id="ast-action",
        started_ns=time.monotonic_ns(),
        expires_ns=time.monotonic_ns() + 10_000_000_000,
    )
    observation = await adapter.execute(
        _request(paths), root, _profile(executable), deadline
    )
    return observation, locator


def _fixed_adapter(
    root: Path,
    payload: dict[str, Any],
    *,
    tracked_files: tuple[TrackedFile, ...] | None = None,
) -> tuple[Any, FixedWorkspaceLocator, FixedOutputRunner, StaticToolProfile]:
    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter

    executable = Path(sys.executable)
    locator = FixedWorkspaceLocator(root)
    runner = FixedOutputRunner(root, payload)
    adapter = PythonAstProcessAdapter(
        executable=executable,
        worker_path=Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py",
        process_runner=runner,
        probe_runner_factory=FixedRunnerFactory(runner),
        probe_root=runner.output_root,
        workspace_locator=locator,
        tracked_files=tracked_files or _manifest(root, ("app.py",)),
        monotonic_ns=time.monotonic_ns,
    )
    return adapter, locator, runner, _profile(executable)


def _deadline() -> MonotonicActionDeadline:
    return MonotonicActionDeadline(
        action_id="ast-action",
        started_ns=time.monotonic_ns(),
        expires_ns=time.monotonic_ns() + 10_000_000_000,
    )


def test_ast_constructor_rejects_generic_reparse_probe_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lexical probe path is checked before it is resolved or used."""

    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter

    root = tmp_path / "workspace"
    root.mkdir()
    output_parent = tmp_path / "output-parent"
    output_parent.mkdir()
    output = output_parent / "attempt"
    output.mkdir()
    runner = FixedOutputRunner(root, _empty_worker_payload(()))
    executable = Path(sys.executable)
    worker_path = (
        Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py"
    )
    real_lstat = Path.lstat

    class ReparseStat:
        st_file_attributes = 0x400
        st_reparse_tag = 1

        def __init__(self, value: object) -> None:
            self._value = value

        def __getattr__(self, name: str) -> object:
            return getattr(self._value, name)

    def simulated_lstat(path: Path) -> object:
        value = real_lstat(path)
        return ReparseStat(value) if path == output_parent else value

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", simulated_lstat)
        with pytest.raises(ValueError, match="STATIC_AST_PROBE_ROOT_INVALID"):
            PythonAstProcessAdapter(
                executable=executable,
                worker_path=worker_path,
                process_runner=runner,
                probe_runner_factory=FixedRunnerFactory(runner),
                probe_root=output,
                workspace_locator=FixedWorkspaceLocator(root),
                tracked_files=(),
            )


@pytest.mark.asyncio
async def test_parse_only_worker_extracts_symbols_calls_routes_and_two_step_flow(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    sentinel = tmp_path / "executed"
    source = """\
from framework import app
raise RuntimeError('target module must never execute')

def source():
    return 'input'

def sink(value):
    return None

class Controller:
    @app.get('/items')
    async def handler(self):
        value = source()
        sink(value)
"""
    (root / "app.py").write_text(source, encoding="utf-8")

    observation, locator = await _run(tmp_path, ("app.py",))

    assert observation.status == "SUCCEEDED"
    assert not sentinel.exists()
    assert locator.checks == 2
    assert {item.symbol_kind for item in observation.symbols} >= {
        "FILE",
        "MODULE",
        "TYPE",
        "CALLABLE",
        "DATA",
        "ROUTE",
    }
    assert any(
        item.relation_kind == "CALL"
        and item.from_symbol_source_key is not None
        and "handler" in item.from_symbol_source_key
        and item.to_symbol_source_key is not None
        and "source" in item.to_symbol_source_key
        for item in observation.relations
    )
    route = next(
        item for item in observation.relations if item.relation_kind == "ROUTE_BINDING"
    )
    assert route.from_symbol_source_key is not None
    assert route.to_symbol_source_key is not None
    assert "GET /items" in route.from_symbol_source_key
    assert "handler" in route.to_symbol_source_key
    flows = [
        item for item in observation.relations if item.relation_kind == "DATA_FLOW"
    ]
    assert len(flows) == 2
    assert [
        (item.from_location.start_line, item.to_location.start_line) for item in flows
    ] == [
        (13, 13),
        (13, 14),
    ]
    assert all(item.rule_id is None for item in observation.relations)
    assert observation.raw_output is not None
    raw = json.loads(observation.raw_output)
    assert raw["files"] == ["app.py"]


@pytest.mark.asyncio
async def test_unicode_byte_offsets_are_converted_to_one_based_codepoint_columns(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "unicode.py").write_text(
        "def handler():\n    value = source()\n    sink('한', value)\n",
        encoding="utf-8",
    )

    observation, _ = await _run(tmp_path, ("unicode.py",))

    use = next(
        item
        for item in observation.relations
        if item.relation_kind == "DATA_FLOW" and item.to_location.start_line == 3
    )
    assert use.to_location.start_column == 15
    assert use.to_location.end_column == 20


@pytest.mark.asyncio
async def test_parse_error_and_unsupported_extension_are_partial(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "good.py").write_text("# intentionally empty\n", encoding="utf-8")
    (root / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    (root / "notes.txt").write_text("not Python", encoding="utf-8")
    observation, _ = await _run(tmp_path, ("good.py", "bad.py", "notes.txt"))

    assert observation.status == "PARTIAL"
    assert observation.analyzed_paths == ("good.py",)
    assert observation.skipped_paths == ("bad.py", "notes.txt")
    codes = {item.code for item in observation.gaps}
    assert {
        "STATIC_PARSE_FAILED",
        "STATIC_LANGUAGE_UNSUPPORTED",
    } <= codes
    assert observation.raw_output is not None
    raw = json.loads(observation.raw_output)
    assert raw["files"] == ["bad.py", "good.py"]


@pytest.mark.asyncio
async def test_symlink_is_rejected_without_opening_its_target(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("raise RuntimeError('must not be read')\n", encoding="utf-8")
    link = root / "link.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("file symlink creation is unavailable")

    observation, _ = await _run(tmp_path, ("link.py",))

    assert observation.status == "PARTIAL"
    assert observation.analyzed_paths == ()
    assert observation.skipped_paths == ("link.py",)
    assert any(item.code == "STATIC_PATH_UNSAFE" for item in observation.gaps)
    assert observation.raw_output is not None
    assert str(outside) not in observation.raw_output.decode("utf-8")


@pytest.mark.asyncio
async def test_untracked_request_path_never_reaches_worker(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "tracked.py").write_text("value = 1\n", encoding="utf-8")
    (root / "untracked.py").write_text("value = 2\n", encoding="utf-8")

    observation, _ = await _run(
        tmp_path,
        ("tracked.py", "untracked.py"),
        manifest_paths=("tracked.py",),
    )

    assert observation.status == "PARTIAL"
    assert observation.analyzed_paths == ("tracked.py",)
    assert observation.skipped_paths == ("untracked.py",)
    assert any(item.code == "STATIC_MANIFEST_MISMATCH" for item in observation.gaps)
    assert observation.raw_output is not None
    assert json.loads(observation.raw_output)["files"] == ["tracked.py"]


@pytest.mark.asyncio
async def test_empty_success_is_structure_only_and_not_a_vulnerability_verdict(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "empty.py").write_text(
        "# no symbols beyond file/module\n", encoding="utf-8"
    )

    observation, _ = await _run(tmp_path, ("empty.py",))

    assert observation.status == "SUCCEEDED"
    assert observation.tool_kind == "STRUCTURE"
    assert observation.raw_output is not None
    assert "findings" not in json.loads(observation.raw_output)


@pytest.mark.asyncio
async def test_annotated_assignment_and_reassignment_replace_the_last_definition(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "flow.py").write_text(
        "def handler():\n"
        "    value: str = first()\n"
        "    value = second()\n"
        "    sink(value)\n",
        encoding="utf-8",
    )

    observation, _ = await _run(tmp_path, ("flow.py",))

    flows = [
        item for item in observation.relations if item.relation_kind == "DATA_FLOW"
    ]
    assert [
        (item.from_location.start_line, item.to_location.start_line) for item in flows
    ] == [
        (2, 2),
        (3, 3),
        (3, 4),
    ]
    assert all(
        not (item.from_location.start_line == 2 and item.to_location.start_line == 4)
        for item in flows
    )


AMBIGUOUS_CASES = (
    "if flag:\n    sink(value)",
    "for item in items:\n    sink(value)",
    "try:\n    sink(value)\nexcept Exception:\n    pass",
    "with manager():\n    sink(value)",
    "items = [value for item in values]",
    "left, right = pair",
    "obj.value = source()",
    "obj[0] = source()",
    "global value",
    "nonlocal value",
    "value.append('x')",
    "eval('value')",
)


@pytest.mark.parametrize("ambiguous", AMBIGUOUS_CASES)
@pytest.mark.asyncio
async def test_ambiguous_construct_clears_flow_and_never_creates_jump_edge(
    tmp_path: Path, ambiguous: str
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    body = "\n".join(f"    {line}" for line in ambiguous.splitlines())
    (root / "ambiguous.py").write_text(
        f"def handler():\n    value = source()\n{body}\n    sink(value)\n",
        encoding="utf-8",
    )

    observation, _ = await _run(tmp_path, ("ambiguous.py",))

    assert any(item.code == "STATIC_DATA_FLOW_INCOMPLETE" for item in observation.gaps)
    final_line = len((root / "ambiguous.py").read_text(encoding="utf-8").splitlines())
    assert all(
        not (
            item.relation_kind == "DATA_FLOW"
            and item.to_location.start_line == final_line
        )
        for item in observation.relations
    )


@pytest.mark.asyncio
async def test_reaching_definitions_never_cross_callable_boundaries(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "scope.py").write_text(
        "def first():\n    value = source()\n\ndef second():\n    sink(value)\n",
        encoding="utf-8",
    )

    observation, _ = await _run(tmp_path, ("scope.py",))

    assert all(
        not (
            item.relation_kind == "DATA_FLOW"
            and item.from_location.start_line == 2
            and item.to_location.start_line == 5
        )
        for item in observation.relations
    )


@pytest.mark.asyncio
async def test_probe_reports_exact_python_parser_capability(tmp_path: Path) -> None:
    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter
    from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner

    root = tmp_path / "workspace"
    root.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    unrelated = output / "unrelated.txt"
    unrelated.write_text("keep", encoding="utf-8")
    executable = Path(sys.executable)
    locator = FixedWorkspaceLocator(root)
    runner = SafeProcessRunner(
        action_id="probe-action",
        attempt_id="at1",
        workspace_root=root,
        output_root=output,
        executable=executable,
        output_budget=AttemptOutputBudget(attempt_id="at1", limit_bytes=1_000_000),
    )
    adapter = PythonAstProcessAdapter(
        executable=executable,
        worker_path=Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py",
        process_runner=runner,
        probe_runner_factory=SafeRunnerFactory(),
        probe_root=output,
        workspace_locator=locator,
        tracked_files=(),
        monotonic_ns=time.monotonic_ns,
    )
    deadline = MonotonicActionDeadline(
        action_id="probe-action",
        started_ns=time.monotonic_ns(),
        expires_ns=time.monotonic_ns() + 10_000_000_000,
    )

    capabilities = (
        await adapter.probe(_profile(executable), deadline),
        await adapter.probe(_profile(executable), deadline),
    )

    assert all(capability.available for capability in capabilities)
    capability = capabilities[0]
    assert capability.tool_name == "AST"
    assert capability.tool_kind == "STRUCTURE"
    assert (
        capability.observed_executable_sha256
        == hashlib.sha256(executable.read_bytes()).hexdigest()
    )
    assert capability.observed_version == platform.python_version()
    assert capability.reason_code is None
    assert not list(output.glob("ast-probe-*"))
    assert unrelated.read_text(encoding="utf-8") == "keep"


@pytest.mark.asyncio
async def test_ast_concurrent_probe_rejects_duplicate_and_cancels_exact_action(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter

    class BlockingProbeRunner:
        def __init__(self, **values: object) -> None:
            self.attempt_id = str(values["attempt_id"])
            self.output_root = Path(str(values["output_root"]))
            self.workspace_root = Path(str(values["workspace_root"]))
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.was_cancelled = False

        async def run(self, request: ProcessSpec) -> ProcessResult:
            self.started.set()
            await self.release.wait()
            raw = platform.python_version().encode()
            receipt = ProcessReceipt(
                action_id=request.deadline.action_id,
                invocation_id=request.invocation_id,
                command_kind=request.command_kind,
                attempt_id=request.attempt_id,
                command_fingerprint=process_command_fingerprint(request),
                outcome="CANCELLED" if self.was_cancelled else "SUCCEEDED",
                return_code=None if self.was_cancelled else 0,
                stdout_name="stdout.bin",
                stdout_size=len(raw),
                stdout_sha256=hashlib.sha256(raw).hexdigest(),
                stderr_name="stderr.bin",
                stderr_size=0,
                stderr_sha256=hashlib.sha256(b"").hexdigest(),
                elapsed_ms=1,
            )
            return ProcessResult(
                outcome=receipt.outcome,
                return_code=receipt.return_code,
                stdout=raw,
                stderr_tail=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                elapsed_ms=1,
                receipt=receipt,
                receipt_path=self.output_root / "receipt.json",
            )

        async def cancel(self, attempt_id: str) -> CancellationResult:
            assert attempt_id == self.attempt_id
            self.was_cancelled = True
            self.release.set()
            return CancellationResult(True, None)

    class BlockingProbeFactory:
        def __init__(self) -> None:
            self.runner: BlockingProbeRunner | None = None

        def __call__(self, **values: object) -> BlockingProbeRunner:
            self.runner = BlockingProbeRunner(**values)
            return self.runner

    root = tmp_path / "workspace"
    root.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = Path(sys.executable)
    execution_runner = FixedOutputRunner(root, _empty_worker_payload(()))
    factory = BlockingProbeFactory()
    adapter = PythonAstProcessAdapter(
        executable=executable,
        worker_path=Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py",
        process_runner=execution_runner,
        probe_runner_factory=factory,
        probe_root=output,
        workspace_locator=FixedWorkspaceLocator(root),
        tracked_files=(),
    )
    probe_deadline = MonotonicActionDeadline(
        action_id="exact-probe-action",
        started_ns=time.monotonic_ns(),
        expires_ns=time.monotonic_ns() + 10_000_000_000,
    )
    first_probe = asyncio.create_task(
        adapter.probe(_profile(executable), probe_deadline)
    )
    while factory.runner is None:
        await asyncio.sleep(0)
    await factory.runner.started.wait()

    second = await adapter.probe(_profile(executable), probe_deadline)
    cancelled = await adapter.cancel(probe_deadline.action_id)
    first = await first_probe

    assert second.reason_code == "STATIC_AST_PROBE_ALREADY_ACTIVE"
    assert cancelled.cancelled
    assert first.reason_code == "STATIC_AST_CAPABILITY_UNAVAILABLE"
    assert factory.runner.attempt_id == probe_deadline.action_id
    assert not list(output.glob("ast-probe-*"))


@pytest.mark.asyncio
async def test_ast_probe_cleans_owned_directory_when_runner_factory_fails(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter

    class FailingProbeFactory:
        def __call__(self, **values: object) -> Any:
            del values
            raise RuntimeError("runner construction failed")

    root = tmp_path / "workspace"
    root.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    unrelated = output / "unrelated.txt"
    unrelated.write_text("keep", encoding="utf-8")
    executable = Path(sys.executable)
    adapter = PythonAstProcessAdapter(
        executable=executable,
        worker_path=Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py",
        process_runner=FixedOutputRunner(root, _empty_worker_payload(())),
        probe_runner_factory=FailingProbeFactory(),
        probe_root=output,
        workspace_locator=FixedWorkspaceLocator(root),
        tracked_files=(),
    )
    deadline = MonotonicActionDeadline(
        action_id="factory-failure",
        started_ns=time.monotonic_ns(),
        expires_ns=time.monotonic_ns() + 10_000_000_000,
    )

    with pytest.raises(RuntimeError, match="runner construction failed"):
        await adapter.probe(_profile(executable), deadline)

    assert not list(output.glob("ast-probe-*"))
    assert unrelated.read_text(encoding="utf-8") == "keep"


@pytest.mark.asyncio
async def test_post_decode_workspace_mutation_discards_observation(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter
    from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner

    class MutatingLocator(FixedWorkspaceLocator):
        async def assert_unchanged(
            self,
            workspace: CodeWorkspace,
            deadline: MonotonicActionDeadline,
            *,
            attempt_id: str,
            check_id: str,
        ) -> tuple[ProcessReceipt, ...]:
            receipts = await super().assert_unchanged(
                workspace,
                deadline,
                attempt_id=attempt_id,
                check_id=check_id,
            )
            if self.checks == 2:
                raise ValueError("WORKSPACE_MUTATED")
            return receipts

    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    output = tmp_path / "attempt"
    output.mkdir()
    executable = Path(sys.executable)
    locator = MutatingLocator(root)
    runner = SafeProcessRunner(
        action_id="ast-action",
        attempt_id="at1",
        workspace_root=root,
        output_root=output,
        executable=executable,
        output_budget=AttemptOutputBudget(attempt_id="at1", limit_bytes=1_000_000),
    )
    adapter = PythonAstProcessAdapter(
        executable=executable,
        worker_path=Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py",
        process_runner=runner,
        probe_runner_factory=FixedRunnerFactory(runner),
        probe_root=output,
        workspace_locator=locator,
        tracked_files=_manifest(root, ("app.py",)),
        monotonic_ns=time.monotonic_ns,
    )
    deadline = MonotonicActionDeadline(
        action_id="ast-action",
        started_ns=time.monotonic_ns(),
        expires_ns=time.monotonic_ns() + 10_000_000_000,
    )

    with pytest.raises(ValueError, match="WORKSPACE_MUTATED"):
        await adapter.execute(
            _request(("app.py",)), root, _profile(executable), deadline
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "preparing",
        "failed",
        "null_commit",
        "analysis_mismatch",
        "commit_mismatch",
        "workspace_mismatch",
    ],
)
async def test_workspace_must_be_exact_ready_scope_before_locator_or_spawn(
    tmp_path: Path, case: str
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    payload = _empty_worker_payload(("app.py",))
    adapter, locator, runner, tool_profile = _fixed_adapter(root, payload)
    request = _request(("app.py",))
    if case == "preparing":
        workspace = request.workspace.model_copy(
            update={"status": "PREPARING", "commit_id": None}
        )
        request = replace(request, workspace=workspace)
    elif case == "failed":
        request = replace(
            request, workspace=request.workspace.model_copy(update={"status": "FAILED"})
        )
    elif case == "null_commit":
        request = replace(
            request, workspace=request.workspace.model_copy(update={"commit_id": None})
        )
    elif case in {"analysis_mismatch", "commit_mismatch"}:
        field = "analysis_id" if case == "analysis_mismatch" else "commit_id"
        value = "a2" if case == "analysis_mismatch" else "c2"
        action = request.action.model_copy(
            update={"meta": request.action.meta.model_copy(update={field: value})}
        )
        request = replace(request, action=action)
    else:
        action = request.action.model_copy(
            update={
                "meta": request.action.meta.model_copy(update={"workspace_id": "ws2"})
            }
        )
        request = replace(request, action=action)

    with pytest.raises(ValueError, match="STATIC_AST_EXECUTION_MISMATCH"):
        await adapter.execute(request, root, tool_profile, _deadline())
    assert locator.root_calls == 0
    assert locator.checks == 0
    assert runner.calls == []


@pytest.mark.asyncio
async def test_requested_manifest_duplicate_is_rejected_before_spawn(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    payload = _empty_worker_payload(("app.py",))
    adapter, _, runner, tool_profile = _fixed_adapter(root, payload)

    with pytest.raises(ValueError, match="STATIC_AST_MANIFEST_MISMATCH"):
        await adapter.execute(
            _request(("app.py", "app.py")), root, tool_profile, _deadline()
        )
    assert runner.calls == []


@pytest.mark.asyncio
async def test_tracked_size_mismatch_is_blocked_before_spawn(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "app.py"
    target.write_text("value = 1\n", encoding="utf-8")
    payload = _empty_worker_payload(("app.py",))
    tracked = (
        replace(_manifest(root, ("app.py",))[0], size_bytes=target.stat().st_size + 1),
    )
    adapter, _, runner, tool_profile = _fixed_adapter(
        root, payload, tracked_files=tracked
    )

    observed = await adapter.execute(
        _request(("app.py",)), root, tool_profile, _deadline()
    )
    assert observed.status == "SKIPPED"
    assert observed.analyzed_paths == ()
    assert observed.skipped_paths == ("app.py",)
    assert {gap.code for gap in observed.gaps} == {"STATIC_MANIFEST_MISMATCH"}
    assert runner.calls == []


@pytest.mark.asyncio
async def test_bound_file_size_change_during_worker_run_discards_output(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter

    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "app.py"
    target.write_text("value = 1\n", encoding="utf-8")
    payload = _empty_worker_payload(("app.py",))
    executable = Path(sys.executable)
    locator = FixedWorkspaceLocator(root)

    def change_size() -> None:
        target.write_text("value = 123456\n", encoding="utf-8")

    runner = FixedOutputRunner(
        root,
        payload,
        before_return=change_size,
    )
    adapter = PythonAstProcessAdapter(
        executable=executable,
        worker_path=Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py",
        process_runner=runner,
        probe_runner_factory=FixedRunnerFactory(runner),
        probe_root=runner.output_root,
        workspace_locator=locator,
        tracked_files=_manifest(root, ("app.py",)),
        monotonic_ns=time.monotonic_ns,
    )

    observed = await adapter.execute(
        _request(("app.py",)), root, _profile(executable), _deadline()
    )
    assert observed.status == "FAILED"
    assert {error.code for error in observed.errors} == {"STATIC_AST_OUTPUT_INVALID"}


def _foreign_location() -> dict[str, Any]:
    return {
        "file_path": "foreign.py",
        "start_line": 1,
        "start_column": 1,
        "end_line": 1,
        "end_column": 2,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "files_foreign",
        "files_missing",
        "files_duplicate",
        "partition_overlap",
        "partition_incomplete",
        "partition_duplicate",
        "symbol_foreign",
        "fact_foreign",
        "relation_foreign",
        "gap_path_foreign",
        "gap_location_foreign",
    ],
)
async def test_worker_output_must_be_exact_complete_safe_manifest_partition(
    tmp_path: Path, case: str
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    payload = deepcopy(_empty_worker_payload(("app.py",)))
    location = _foreign_location()
    if case == "files_foreign":
        payload["files"] = ["foreign.py"]
    elif case == "files_missing":
        payload["files"] = []
    elif case == "files_duplicate":
        payload["files"] = ["app.py", "app.py"]
    elif case == "partition_overlap":
        payload["skipped_paths"] = ["app.py"]
    elif case == "partition_incomplete":
        payload["analyzed_paths"] = []
    elif case == "partition_duplicate":
        payload["analyzed_paths"] = ["app.py", "app.py"]
    elif case == "symbol_foreign":
        payload["symbols"] = [
            {
                "source_key": "symbol",
                "symbol_kind": "FILE",
                "native_kind": "PYTHON_FILE",
                "name": "foreign.py",
                "location": location,
            }
        ]
    elif case == "fact_foreign":
        payload["facts"] = [
            {
                "source_key": "fact",
                "fact_kind": "SOURCE",
                "symbol_source_key": None,
                "location": location,
                "rule_id": None,
            }
        ]
    elif case == "relation_foreign":
        payload["relations"] = [
            {
                "source_key": "relation",
                "relation_kind": "DATA_FLOW",
                "from_symbol_source_key": None,
                "from_location": location,
                "to_symbol_source_key": None,
                "to_location": location,
                "rule_id": None,
            }
        ]
    elif case == "gap_path_foreign":
        payload["gaps"] = [
            {
                "stage": "STATIC_ANALYSIS",
                "code": "STATIC_PARSE_FAILED",
                "reason": "FAILED",
                "description": "bad",
                "affected_paths": ["foreign.py"],
                "affected_languages": ["Python"],
                "affected_locations": [],
                "retryable": False,
            }
        ]
    else:
        payload["gaps"] = [
            {
                "stage": "STATIC_ANALYSIS",
                "code": "STATIC_PARSE_FAILED",
                "reason": "FAILED",
                "description": "bad",
                "affected_paths": ["app.py"],
                "affected_languages": ["Python"],
                "affected_locations": [location],
                "retryable": False,
            }
        ]
    adapter, _, runner, tool_profile = _fixed_adapter(root, payload)

    observed = await adapter.execute(
        _request(("app.py",)), root, tool_profile, _deadline()
    )
    assert len(runner.calls) == 1
    assert observed.status == "FAILED"
    assert observed.symbols == ()
    assert observed.facts == ()
    assert observed.relations == ()
    assert {error.code for error in observed.errors} == {"STATIC_AST_OUTPUT_INVALID"}
