from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from pathlib import Path

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref


class FixedWorkspaceLocator:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.checks = 0

    def root_for(self, workspace: CodeWorkspace) -> Path:
        del workspace
        return self.root

    async def assert_unchanged(
        self, workspace: CodeWorkspace, deadline: MonotonicActionDeadline
    ) -> None:
        del workspace, deadline
        self.checks += 1


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
        workspace_locator=locator,
        tracked_files=(),
        monotonic_ns=time.monotonic_ns,
    )
    deadline = MonotonicActionDeadline(
        action_id="probe-action",
        started_ns=time.monotonic_ns(),
        expires_ns=time.monotonic_ns() + 10_000_000_000,
    )

    capability = await adapter.probe(_profile(executable), deadline)

    assert capability.available
    assert capability.tool_name == "AST"
    assert capability.tool_kind == "STRUCTURE"
    assert (
        capability.observed_executable_sha256
        == hashlib.sha256(executable.read_bytes()).hexdigest()
    )
    assert capability.observed_version == platform.python_version()
    assert capability.reason_code is None


@pytest.mark.asyncio
async def test_post_decode_workspace_mutation_discards_observation(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter
    from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner

    class MutatingLocator(FixedWorkspaceLocator):
        async def assert_unchanged(
            self, workspace: CodeWorkspace, deadline: MonotonicActionDeadline
        ) -> None:
            await super().assert_unchanged(workspace, deadline)
            if self.checks == 2:
                raise ValueError("WORKSPACE_MUTATED")

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
