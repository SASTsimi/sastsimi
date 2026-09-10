"""Cross-adapter contract checks for exact public raw replay."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import platform
import shutil
import sys
import time
import uuid
from collections.abc import Awaitable, Callable, Generator
from dataclasses import replace
from pathlib import Path
from typing import Literal, cast

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import (
    CodeWorkspace,
    RuleExecutionItem,
    RuleExecutionRecord,
    StaticToolProfile,
    ToolCoverage,
    ToolRunResult,
)
from sastsimi.ports.dto import (
    CancellationResult,
    MonotonicActionDeadline,
    PrebuiltCodeQLDatabase,
    ProcessReceipt,
    ProcessResult,
    ProcessSpec,
    StaticRuleMapping,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.ports.static_tool import StaticProcessAdapter
from sastsimi.static_analysis.ast_adapter import (
    PythonAstProcessAdapter,
    replay_python_ast_raw,
)
from sastsimi.static_analysis.codeql_adapter import (
    CodeQLExecutionInputs,
    CodeQLProcessAdapter,
    digest_path,
    replay_codeql_raw,
)
from sastsimi.static_analysis.coordinator import StaticToolCoordinator
from sastsimi.static_analysis.normalizer import (
    StaticNormalizationInput,
    StaticNormalizer,
    StaticRawReplayInput,
    decoder_key,
)
from sastsimi.static_analysis.open_grep_adapter import (
    OpenGrepExecutionInputs,
    OpenGrepProcessAdapter,
    replay_opengrep_raw,
)
from sastsimi.static_analysis.process import process_command_fingerprint
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta


def _profile(
    adapter_key: str,
    tool_name: str,
    tool_kind: str,
    *,
    executable: Path | None = None,
    version: str | None = None,
) -> StaticToolProfile:
    values = meta("static_tool_profile", attempt=None)
    values.update(
        record_id=f"profile-{adapter_key.lower()}",
        logical_record_id=f"profile-{adapter_key.lower()}",
    )
    return StaticToolProfile.model_validate_json(
        canonical_bytes(
            {
            "meta": values,
            "profile_key": f"{adapter_key.lower()}-fixture",
            "purpose": "FIXTURE",
            "status": "APPROVED",
            "adapter_key": adapter_key,
            "tool_name": tool_name,
            "tool_kind": tool_kind,
            "executable_key": f"trusted-{adapter_key.lower()}",
            "executable_sha256": (
                hashlib.sha256(executable.read_bytes()).hexdigest()
                if executable is not None
                else "a" * 64
            ),
            "expected_version": version
            or (platform.python_version() if tool_name == "AST" else "1.0"),
            "capability_evidence_ref": None,
            "probe_timeout_ms": 5_000,
            "run_timeout_ms": 5_000,
            "stdout_limit_bytes": 10_000,
            "stderr_limit_bytes": 1_000,
            "max_attempt_output_bytes": 20_000,
            "max_output_file_bytes": 10_000,
            "max_artifact_read_bytes": 10_000,
            }
        )
    )


def _record_ref(kind: str, key: str) -> StoredDataRef:
    digest = hashlib.sha256(key.encode()).hexdigest()
    return StoredDataRef.model_validate(
        {
            "stored_data_id": digest,
            "data_kind": kind,
            "record_id": f"{kind}-{key}",
            "content_hash": digest,
            "workspace_id": "ws1",
            "commit_id": "c1",
        }
    )


def _artifact_ref(raw: bytes) -> StoredDataRef:
    digest = hashlib.sha256(raw).hexdigest()
    return StoredDataRef.model_validate(
        {
            "stored_data_id": digest,
            "data_kind": "artifact",
            "record_id": None,
            "content_hash": digest,
            "workspace_id": "ws1",
            "commit_id": "c1",
        }
    )


def _result(
    profile: StaticToolProfile,
    raw: bytes,
    *,
    paths: tuple[str, ...],
    rule: RuleExecutionRecord | None = None,
) -> ToolRunResult:
    result_meta = meta("tool_run_result")
    result_meta.update(
        record_id=f"result-{profile.adapter_key.lower()}",
        logical_record_id=f"result-{profile.adapter_key.lower()}",
    )
    rule_ref = reference(rule) if rule is not None else None
    return ToolRunResult.model_validate_json(
        canonical_bytes(
            {
            "meta": result_meta,
            "tool_name": profile.tool_name,
            "tool_version": profile.expected_version,
            "tool_kind": profile.tool_kind,
            "status": "SUCCEEDED",
            "coverage": ToolCoverage(
                analyzed_paths=paths,
                skipped_paths=(),
                analyzed_languages=("Python",),
                skipped_languages=(),
                notes=(),
            ),
            "rule_execution_ref": rule_ref,
            "raw_result_ref": _artifact_ref(raw),
            "gaps": (),
            "errors": (),
            "started_at": "2026-09-08T00:00:00Z",
            "finished_at": "2026-09-08T00:00:00Z",
            "elapsed_ms": 0,
            }
        )
    )


def _rule_execution(
    profile: StaticToolProfile, catalog_ids: tuple[str, ...]
) -> RuleExecutionRecord:
    rule_meta = meta("rule_execution_record")
    rule_meta.update(
        record_id=f"rules-{profile.adapter_key.lower()}",
        logical_record_id=f"rules-{profile.adapter_key.lower()}",
    )
    return RuleExecutionRecord.model_validate_json(
        canonical_bytes(
            {
            "meta": rule_meta,
            "tool_name": profile.tool_name,
            "tool_version": profile.expected_version,
            "analysis_config_ref": _artifact_ref(b"config"),
            "rule_catalog_ref": _artifact_ref(b"catalog"),
            "selected_rule_packs": ("fixture/web",),
            "rules": tuple(
                RuleExecutionItem(
                    rule_id=rule_id,
                    selection_status="SELECTED",
                    execution_status="EXECUTED",
                    hit_count=0,
                    reason=None,
                    detail=None,
                ).model_dump(mode="json")
                for rule_id in catalog_ids
            ),
            }
        )
    )


class _Profiles:
    def __init__(self, values: dict[StoredDataRef, StaticToolProfile]) -> None:
        self.values = values

    def resolve(self, profile_ref: StoredDataRef) -> StaticToolProfile:
        try:
            return self.values[profile_ref]
        except KeyError as error:
            raise ValueError("STATIC_TOOL_PROFILE_INVALID") from error


class _Workspace:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.checks: list[tuple[str, str]] = []

    def root_for(self, workspace: CodeWorkspace) -> Path:
        del workspace
        return self.root

    async def assert_unchanged(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        del workspace, deadline
        self.checks.append((attempt_id, check_id))
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


class _Runner:
    def __init__(
        self,
        *,
        attempt_id: str,
        workspace_root: Path,
        output_root: Path,
        ast_raw: bytes,
        codeql_raw: bytes,
        opengrep_raw: bytes,
        block_kind: str | None = None,
    ) -> None:
        self.attempt_id = attempt_id
        self.workspace_root = workspace_root
        self.output_root = output_root
        self.ast_raw = ast_raw
        self.codeql_raw = codeql_raw
        self.opengrep_raw = opengrep_raw
        self.block_kind = block_kind
        self.calls: list[ProcessSpec] = []
        self.cancelled: list[str] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        if spec.command_kind == "ast-probe":
            stdout = (platform.python_version() + "\n").encode()
        elif spec.command_kind == "ast-parse":
            stdout = self.ast_raw
        elif spec.command_kind == "codeql-version":
            stdout = canonical_bytes({"version": "1.0"})
        elif spec.command_kind == "codeql-analyze":
            output = next(value for value in spec.argv if value.startswith("--output="))
            Path(output.split("=", 1)[1]).write_bytes(self.codeql_raw)
            stdout = b""
        elif spec.command_kind == "opengrep-version":
            stdout = b"1.0\n"
        elif spec.command_kind.startswith("opengrep-batch-"):
            stdout = self.opengrep_raw
        else:
            raise AssertionError(f"unexpected process kind: {spec.command_kind}")
        outcome: Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"] = (
            "SUCCEEDED"
        )
        return_code: int | None = 0
        if spec.command_kind == self.block_kind:
            self.started.set()
            await self.release.wait()
            if spec.attempt_id in self.cancelled:
                outcome = "CANCELLED"
                return_code = None
        receipt = ProcessReceipt(
            action_id=spec.deadline.action_id,
            invocation_id=spec.invocation_id,
            command_kind=spec.command_kind,
            attempt_id=spec.attempt_id,
            command_fingerprint=process_command_fingerprint(spec),
            outcome=outcome,
            return_code=return_code,
            stdout_name="stdout.bin",
            stdout_size=len(stdout),
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_name="stderr.bin",
            stderr_size=0,
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            elapsed_ms=1,
        )
        return ProcessResult(
            outcome=outcome,
            return_code=return_code,
            stdout=stdout,
            stderr_tail=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            elapsed_ms=1,
            receipt=receipt,
            receipt_path=spec.attempt_output_dir / "receipt.json",
        )

    async def cancel(self, attempt_id: str) -> CancellationResult:
        self.cancelled.append(attempt_id)
        self.release.set()
        return CancellationResult(True, None)


class _RunnerFactory:
    def __init__(self, runner: _Runner) -> None:
        self.runner = runner

    def __call__(self, **values: object) -> _Runner:
        del values
        return self.runner


class _External:
    def __init__(self) -> None:
        self.observations: dict[str, StaticToolObservation] = {}
        self.rules: dict[str, RuleExecutionRecord] = {}

    async def invoke(
        self,
        request: StaticToolRequest,
        profile: StaticToolProfile,
        operation: Callable[
            [MonotonicActionDeadline], Awaitable[StaticToolObservation]
        ],
    ) -> ToolRunResult:
        started = time.monotonic_ns()
        deadline = MonotonicActionDeadline(
            str(request.action.action_id),
            started,
            started + profile.run_timeout_ms * 1_000_000,
        )
        observation = await operation(deadline)
        self.observations[profile.adapter_key] = observation
        if observation.status == "SKIPPED":
            return cast(ToolRunResult, object())
        assert observation.status == "SUCCEEDED", observation
        assert isinstance(request.action.meta, RecordMeta)
        rule: RuleExecutionRecord | None = None
        if observation.tool_kind == "RULE_BASED":
            assert request.rule_catalog_ref is not None
            rule_meta = meta("rule_execution_record")
            rule_meta.update(
                record_id=f"rule-{profile.adapter_key.lower()}",
                logical_record_id=f"rule-{profile.adapter_key.lower()}",
                attempt_id=str(request.action.meta.attempt_id),
            )
            rule = RuleExecutionRecord.model_validate_json(
                canonical_bytes(
                    {
                        "meta": rule_meta,
                        "tool_name": observation.tool_name,
                        "tool_version": observation.tool_version,
                        "analysis_config_ref": request.analysis_config_ref,
                        "rule_catalog_ref": request.rule_catalog_ref,
                        "selected_rule_packs": observation.selected_rule_packs,
                        "rules": tuple(item.__dict__ for item in observation.rules),
                    }
                )
            )
            self.rules[profile.adapter_key] = rule
        result_meta = meta("tool_run_result")
        result_meta.update(
            record_id=f"result-{profile.adapter_key.lower()}",
            logical_record_id=f"result-{profile.adapter_key.lower()}",
            attempt_id=str(request.action.meta.attempt_id),
        )
        return ToolRunResult.model_validate_json(
            canonical_bytes(
                {
                    "meta": result_meta,
                    "tool_name": observation.tool_name,
                    "tool_version": observation.tool_version,
                    "tool_kind": observation.tool_kind,
                    "status": observation.status,
                    "coverage": {
                        "analyzed_paths": observation.analyzed_paths,
                        "skipped_paths": observation.skipped_paths,
                        "analyzed_languages": observation.analyzed_languages,
                        "skipped_languages": observation.skipped_languages,
                        "notes": observation.notes,
                    },
                    "rule_execution_ref": reference(rule) if rule else None,
                    "raw_result_ref": (
                        _artifact_ref(observation.raw_output)
                        if observation.raw_output is not None
                        else None
                    ),
                    "gaps": (),
                    "errors": (),
                    "started_at": "2026-09-08T00:00:00Z",
                    "finished_at": "2026-09-08T00:00:00Z",
                    "elapsed_ms": 0,
                }
            )
        )


@pytest.fixture
def case_root() -> Generator[Path, None, None]:
    root = Path.cwd() / ".t08-real-adapter-tests" / uuid.uuid4().hex
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _request(
    workspace: CodeWorkspace,
    profile: StaticToolProfile,
    config_ref: StoredDataRef,
    catalog_ref: StoredDataRef | None,
    *,
    attempt_id: str,
) -> StaticToolRequest:
    action_data = make("ActionRequest", "action_request")
    action_data["meta"].update(
        record_id=f"action-{attempt_id}",
        logical_record_id=f"action-{attempt_id}",
        attempt_id=attempt_id,
    )
    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    input_refs = (
        profile_ref,
        config_ref,
    )
    if catalog_ref is not None:
        input_refs = (*input_refs, catalog_ref)
    action = ActionRequest.model_validate_json(
        canonical_bytes(
            action_data
            | {
                "action_id": f"action-{attempt_id}",
                "requested_by": "STATIC_ANALYSIS",
                "action_type": "RUN_TOOL",
                "work_ref": _record_ref("work_execution_state", attempt_id),
                "expected_state_version": 1,
                "tool_name": profile.tool_name,
                "file_paths": ("src/app.py",),
                "input_refs": tuple(
                    item.model_dump(mode="json") for item in input_refs
                ),
            }
        )
    )
    return StaticToolRequest(
        action=action,
        workspace=workspace,
        tool_profile_ref=profile_ref,
        analysis_config_ref=config_ref,
        rule_catalog_ref=catalog_ref,
    )


def test_ast_public_raw_replay_is_pure_and_bound_to_committed_scope() -> None:
    profile = _profile("PYTHON_AST", "AST", "STRUCTURE")
    raw = canonical_bytes(
        {
            "schema_version": 1,
            "parser_version": profile.expected_version,
            "files": ["src/app.py"],
            "analyzed_paths": ["src/app.py"],
            "skipped_paths": [],
            "symbols": [],
            "facts": [],
            "relations": [],
            "gaps": [],
            "errors": [],
        }
    )
    result = _result(profile, raw, paths=("src/app.py",))
    replay_input = StaticRawReplayInput(
        result=result,
        profile=profile,
        rule_execution=None,
        rule_mappings=(),
        authorized_paths=("src/app.py",),
    )

    observation = replay_python_ast_raw(raw, replay_input)

    assert observation.raw_output == raw
    assert observation.analyzed_paths == result.coverage.analyzed_paths
    with pytest.raises(ValueError, match="STATIC_RAW_REPLAY_SCOPE_MISMATCH"):
        replay_python_ast_raw(
            raw,
            replay_input.__class__(
                result=result,
                profile=profile,
                rule_execution=None,
                rule_mappings=(),
                authorized_paths=("src/other.py",),
            ),
        )


def test_codeql_public_raw_replay_uses_exact_mapping_and_rule_execution() -> None:
    profile = _profile("CODEQL", "CODEQL", "RULE_BASED")
    raw = canonical_bytes(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "version": "1.0",
                            "rules": [{"id": "R1"}],
                        }
                    },
                    "results": [],
                }
            ],
        }
    )
    rule = _rule_execution(profile, ("R1",))
    result = _result(profile, raw, paths=("src/app.py",), rule=rule)
    replay_input = StaticRawReplayInput(
        result=result,
        profile=profile,
        rule_execution=rule,
        rule_mappings=(StaticRuleMapping("R1", "SINK", None, False),),
        authorized_paths=("src/app.py",),
    )

    observation = replay_codeql_raw(raw, replay_input)

    assert observation.rules[0].rule_id == "R1"
    assert observation.selected_rule_packs == ("fixture/web",)
    wrong = replay_input.__class__(
        result=result,
        profile=profile,
        rule_execution=rule,
        rule_mappings=(StaticRuleMapping("R2", "SOURCE", None, False),),
        authorized_paths=("src/app.py",),
    )
    with pytest.raises(ValueError, match="STATIC_RAW_REPLAY_CATALOG_MISMATCH"):
        replay_codeql_raw(raw, wrong)


def test_opengrep_public_raw_replay_verifies_envelope_and_batch_digest() -> None:
    profile = _profile("OPENGREP", "OPENGREP", "RULE_BASED")
    batch = canonical_bytes(
        {
            "version": "1.0",
            "results": [],
            "errors": [],
            "paths": {"scanned": ["src/app.py"], "skipped": []},
            "time": {"rules": [{"id": "R1"}]},
        }
    )
    envelope = {
        "schema_version": 1,
        "tool_name": "OPENGREP",
        "tool_version": "1.0",
        "batches": [
            {
                "paths": ["src/app.py"],
                "stdout_base64": base64.b64encode(batch).decode("ascii"),
                "stdout_sha256": hashlib.sha256(batch).hexdigest(),
            }
        ],
    }
    raw = canonical_bytes(envelope)
    rule = _rule_execution(profile, ("R1",))
    result = _result(profile, raw, paths=("src/app.py",), rule=rule)
    replay_input = StaticRawReplayInput(
        result=result,
        profile=profile,
        rule_execution=rule,
        rule_mappings=(StaticRuleMapping("R1", "SOURCE", None, False),),
        authorized_paths=("src/app.py",),
    )

    observation = replay_opengrep_raw(raw, replay_input)

    assert observation.raw_output == raw
    assert observation.analyzed_paths == ("src/app.py",)
    damaged = json.loads(raw)
    damaged["batches"][0]["stdout_sha256"] = "0" * 64
    damaged_raw = canonical_bytes(damaged)
    damaged_replay = replay_input.__class__(
        result=_result(profile, damaged_raw, paths=("src/app.py",), rule=rule),
        profile=profile,
        rule_execution=rule,
        rule_mappings=replay_input.rule_mappings,
        authorized_paths=replay_input.authorized_paths,
    )
    with pytest.raises(ValueError, match="STATIC_RAW_REPLAY_ENVELOPE_INVALID"):
        replay_opengrep_raw(damaged_raw, damaged_replay)


@pytest.mark.asyncio
async def test_actual_three_adapter_public_bridge_and_exact_replay(
    case_root: Path,
) -> None:
    workspace_root = case_root / "workspace"
    workspace_root.joinpath("src").mkdir(parents=True)
    source = workspace_root / "src" / "app.py"
    source.write_text("value = input()\nprint(value)\n", encoding="utf-8")
    tracked = (TrackedFile("src/app.py", "100644", "blob-app", source.stat().st_size),)
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            make("CodeWorkspace")
            | {
                "workspace_id": "ws1",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    config_ref = _record_ref("analysis_config", "fixture")
    catalog_ref = _record_ref("rule_catalog", "fixture")
    mappings = (StaticRuleMapping("R1", "SOURCE", None, False),)

    ast_raw = canonical_bytes(
        {
            "schema_version": 1,
            "parser_version": platform.python_version(),
            "files": ["src/app.py"],
            "analyzed_paths": ["src/app.py"],
            "skipped_paths": [],
            "symbols": [],
            "facts": [],
            "relations": [],
            "gaps": [],
            "errors": [],
        }
    )
    codeql_raw = canonical_bytes(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "version": "1.0",
                            "rules": [{"id": "R1"}],
                        }
                    },
                    "results": [],
                }
            ],
        }
    )
    opengrep_raw = canonical_bytes(
        {
            "version": "1.0",
            "results": [],
            "errors": [],
            "paths": {"scanned": ["src/app.py"], "skipped": []},
            "time": {"rules": [{"id": "R1"}]},
        }
    )

    ast_runner = _Runner(
        attempt_id="attempt-ast",
        workspace_root=workspace_root,
        output_root=case_root / "attempt-ast",
        ast_raw=ast_raw,
        codeql_raw=codeql_raw,
        opengrep_raw=opengrep_raw,
    )
    ast_runner.output_root.mkdir()
    codeql_runner = _Runner(
        attempt_id="attempt-codeql",
        workspace_root=workspace_root,
        output_root=case_root / "attempt-codeql",
        ast_raw=ast_raw,
        codeql_raw=codeql_raw,
        opengrep_raw=opengrep_raw,
    )
    codeql_runner.output_root.mkdir()
    opengrep_runner = _Runner(
        attempt_id="attempt-opengrep",
        workspace_root=workspace_root,
        output_root=case_root / "attempt-opengrep",
        ast_raw=ast_raw,
        codeql_raw=codeql_raw,
        opengrep_raw=opengrep_raw,
    )
    opengrep_runner.output_root.mkdir()

    codeql_executable = case_root / "codeql.exe"
    codeql_executable.write_bytes(b"trusted-codeql")
    opengrep_executable = case_root / "opengrep.exe"
    opengrep_executable.write_bytes(b"trusted-opengrep")
    ast_profile = _profile(
        "PYTHON_AST",
        "AST",
        "STRUCTURE",
        executable=Path(sys.executable),
        version=platform.python_version(),
    )
    codeql_profile = _profile(
        "CODEQL",
        "CODEQL",
        "RULE_BASED",
        executable=codeql_executable,
        version="1.0",
    )
    opengrep_profile = _profile(
        "OPENGREP",
        "OPENGREP",
        "RULE_BASED",
        executable=opengrep_executable,
        version="1.0",
    )

    database_root = case_root / "codeql-database"
    database_root.mkdir()
    database_root.joinpath("codeql-database.yml").write_text(
        "primaryLanguage: python\n", encoding="utf-8"
    )
    query_pack = case_root / "query-pack"
    query_pack.mkdir()
    query_pack.joinpath("qlpack.yml").write_text(
        "name: fixture\n", encoding="utf-8"
    )
    query_pack.joinpath("sastsimi-selection.json").write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "rule_ids": ["R1"],
                "rule_packs": ["fixture/web"],
            }
        )
    )
    opengrep_config = case_root / "opengrep.yml"
    opengrep_config.write_text("rules: []\n", encoding="utf-8")
    locator = _Workspace(workspace_root)
    adapters: dict[str, StaticProcessAdapter] = {
        "PYTHON_AST": PythonAstProcessAdapter(
            executable=Path(sys.executable),
            worker_path=Path(__file__).parents[2]
            / "src"
            / "sastsimi"
            / "static_analysis"
            / "python_ast_worker.py",
            process_runner=ast_runner,
            workspace_locator=locator,
            tracked_files=tracked,
        ),
        "CODEQL": CodeQLProcessAdapter(
            executable=codeql_executable,
            executable_key=codeql_profile.executable_key,
            inputs=CodeQLExecutionInputs(
                database=PrebuiltCodeQLDatabase(
                    "ws1",
                    "c1",
                    "Python",
                    database_root,
                    digest_path(database_root),
                ),
                query_pack_root=query_pack,
                query_pack_digest=digest_path(query_pack),
                analysis_config_ref=config_ref,
                rule_catalog_ref=catalog_ref,
                rule_catalog=mappings,
                selected_rule_ids=("R1",),
                selected_rule_packs=("fixture/web",),
                tracked_files=tracked,
                attempt_root=codeql_runner.output_root,
                attempt_id="attempt-codeql",
            ),
            runner_factory=_RunnerFactory(codeql_runner),
        ),
        "OPENGREP": OpenGrepProcessAdapter(
            executable=opengrep_executable,
            executable_key=opengrep_profile.executable_key,
            inputs=OpenGrepExecutionInputs(
                config_path=opengrep_config,
                config_digest=hashlib.sha256(opengrep_config.read_bytes()).hexdigest(),
                analysis_config_ref=config_ref,
                rule_catalog_ref=catalog_ref,
                rule_catalog=mappings,
                selected_rule_ids=("R1",),
                selected_rule_packs=("fixture/web",),
                tracked_files=tracked,
                attempt_root=opengrep_runner.output_root,
                attempt_id="attempt-opengrep",
            ),
            runner_factory=_RunnerFactory(opengrep_runner),
        ),
    }
    profiles = (ast_profile, codeql_profile, opengrep_profile)
    profile_refs = tuple(cast(StoredDataRef, reference(item)) for item in profiles)
    external = _External()
    resolver = _Profiles(dict(zip(profile_refs, profiles, strict=True)))
    coordinator = StaticToolCoordinator(
        resolver,
        adapters,
        external,
        locator,
        {
            ast_profile.executable_key: Path(sys.executable),
            codeql_profile.executable_key: codeql_executable,
            opengrep_profile.executable_key: opengrep_executable,
        },
        prohibited_workspace_roots=(workspace_root,),
    )

    capabilities = tuple(
        [await coordinator.probe(profile_ref) for profile_ref in profile_refs]
    )
    assert all(item.available for item in capabilities)
    requests = (
        _request(
            workspace,
            ast_profile,
            config_ref,
            None,
            attempt_id="attempt-ast",
        ),
        _request(
            workspace,
            codeql_profile,
            config_ref,
            catalog_ref,
            attempt_id="attempt-codeql",
        ),
        _request(
            workspace,
            opengrep_profile,
            config_ref,
            catalog_ref,
            attempt_id="attempt-opengrep",
        ),
    )
    results = tuple([await coordinator.run(request) for request in requests])
    assert tuple(item.status for item in results) == (
        "SUCCEEDED",
        "SUCCEEDED",
        "SUCCEEDED",
    )
    assert (await coordinator.cancel("not-active")).cancelled is False

    decoders = {
        decoder_key(profile_refs[0], "AST", ast_profile.expected_version): (
            replay_python_ast_raw
        ),
        decoder_key(profile_refs[1], "CODEQL", "1.0"): replay_codeql_raw,
        decoder_key(profile_refs[2], "OPENGREP", "1.0"): replay_opengrep_raw,
    }
    materials = tuple(
        StaticNormalizationInput(
            result_ref=cast(StoredDataRef, reference(result)),
            result=result,
            profile_ref=profile_ref,
            profile=profile,
            analysis_config_ref=config_ref,
            rule_catalog_ref=(
                None if profile.tool_kind == "STRUCTURE" else catalog_ref
            ),
            raw_bytes=external.observations[profile.adapter_key].raw_output,
            authorized_paths=("src/app.py",),
            rule_execution=external.rules.get(profile.adapter_key),
            catalog_rule_ids=(() if profile.tool_kind == "STRUCTURE" else ("R1",)),
            rule_mappings=(() if profile.tool_kind == "STRUCTURE" else mappings),
        )
        for result, profile_ref, profile in zip(
            results, profile_refs, profiles, strict=True
        )
    )
    bundle_meta = meta("static_fact_bundle", attempt=None)
    bundle = StaticNormalizer(decoders).normalize(
        bundle_meta=type(profiles[0].meta).model_validate_json(
            canonical_bytes(bundle_meta)
        ),
        workspace=workspace,
        materials=materials,
    )
    assert tuple(item.tool_name for item in bundle.tool_runs) == (
        "AST",
        "CODEQL",
        "OPENGREP",
    )

    async def assert_active_cancel(
        index: int, runner: _Runner, command_kind: str
    ) -> None:
        for child in runner.output_root.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        runner.block_kind = command_kind
        runner.started = asyncio.Event()
        runner.release = asyncio.Event()
        runner.cancelled.clear()
        active = asyncio.create_task(coordinator.run(requests[index]))
        await asyncio.wait_for(runner.started.wait(), timeout=1)
        attempt = profiles[index].adapter_key.lower().replace("python_", "")
        cancellation = await coordinator.cancel(f"attempt-{attempt}")
        await asyncio.wait_for(active, timeout=1)
        assert cancellation.cancelled is True
        assert runner.cancelled == [str(requests[index].action.meta.attempt_id)]

    await assert_active_cancel(0, ast_runner, "ast-parse")
    await assert_active_cancel(1, codeql_runner, "codeql-analyze")
    await assert_active_cancel(2, opengrep_runner, "opengrep-batch-0000")

    process_count = sum(
        len(runner.calls) for runner in (ast_runner, codeql_runner, opengrep_runner)
    )
    for profile_ref in profile_refs:
        stale = profile_ref.model_copy(update={"content_hash": "0" * 64})
        with pytest.raises(ValueError, match="STATIC_TOOL_PROFILE_INVALID"):
            await coordinator.probe(stale)
    assert sum(
        len(runner.calls) for runner in (ast_runner, codeql_runner, opengrep_runner)
    ) == process_count

    stale = profile_refs[0].model_copy(update={"content_hash": "0" * 64})
    resolver.values[stale] = ast_profile
    with pytest.raises(ValueError, match="STATIC_TOOL_PROFILE_INVALID"):
        await coordinator.probe(stale)
    resolver.values[profile_refs[0]] = codeql_profile
    with pytest.raises(ValueError, match="STATIC_TOOL_PROFILE_INVALID"):
        await coordinator.probe(profile_refs[0])
    resolver.values[profile_refs[0]] = ast_profile
    assert sum(
        len(runner.calls) for runner in (ast_runner, codeql_runner, opengrep_runner)
    ) == process_count

    for request in requests:
        wrong_inputs = request.action.model_copy(update={"input_refs": ()})
        with pytest.raises(
            ValueError, match="STATIC_TOOL_PROFILE_BINDING_MISMATCH"
        ):
            await coordinator.run(replace(request, action=wrong_inputs))
        no_work = request.action.model_copy(
            update={"work_ref": None, "expected_state_version": None}
        )
        with pytest.raises(
            ValueError, match="STATIC_TOOL_PROFILE_BINDING_MISMATCH"
        ):
            await coordinator.run(replace(request, action=no_work))
    assert sum(
        len(runner.calls) for runner in (ast_runner, codeql_runner, opengrep_runner)
    ) == process_count

    for index, (request, profile, adapter, runner) in enumerate(
        zip(
            requests,
            profiles,
            adapters.values(),
            (ast_runner, codeql_runner, opengrep_runner),
            strict=True,
        )
    ):
        assert isinstance(request.action.meta, RecordMeta)
        wrong_meta = request.action.meta.model_copy(
            update={"attempt_id": f"wrong-attempt-{index}"}
        )
        wrong_attempt = replace(
            request,
            action=request.action.model_copy(update={"meta": wrong_meta}),
        )
        before = len(runner.calls)
        deadline = MonotonicActionDeadline(
            str(wrong_attempt.action.action_id), 0, 10**18
        )
        try:
            rejected = await adapter.execute(
                wrong_attempt, workspace_root, profile, deadline
            )
        except ValueError:
            pass
        else:
            assert rejected.status == "FAILED"
        assert len(runner.calls) == before

    wrong_ref = _record_ref("analysis_config", "wrong")
    for index in (1, 2):
        adapter = tuple(adapters.values())[index]
        runner = (codeql_runner, opengrep_runner)[index - 1]
        before = len(runner.calls)
        request = replace(requests[index], analysis_config_ref=wrong_ref)
        rejected = await adapter.execute(
            request,
            workspace_root,
            profiles[index],
            MonotonicActionDeadline(str(request.action.action_id), 0, 10**18),
        )
        assert rejected.status == "FAILED"
        assert len(runner.calls) == before

    before = len(codeql_runner.calls)
    wrong_paths = requests[1].action.model_copy(
        update={"file_paths": ("src/not-requested.py",)}
    )
    path_mismatch = replace(requests[1], action=wrong_paths)
    rejected = await adapters["CODEQL"].execute(
        path_mismatch,
        workspace_root,
        codeql_profile,
        MonotonicActionDeadline(
            str(path_mismatch.action.action_id), 0, 10**18
        ),
    )
    assert rejected.status == "FAILED"
    assert len(codeql_runner.calls) == before

    codeql_process_count = len(codeql_runner.calls)
    codeql_executable.write_bytes(b"changed-after-registration")
    with pytest.raises(ValueError, match="STATIC_EXECUTABLE_INVALID"):
        await coordinator.probe(profile_refs[1])
    assert len(codeql_runner.calls) == codeql_process_count
