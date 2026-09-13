from __future__ import annotations

import hashlib
import platform
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.orchestration.production_static_adapters import (
    ProductionStaticAdapterFactory,
    StaticAdapterCancellationRouter,
    StaticAttemptAdapterDispatch,
    classify_codeql_language,
    codeql_database_create_argv,
)
from sastsimi.orchestration.production_t08_builder import (
    ApprovedStaticRuleClosure,
    StaticAdapterBuildContext,
)
from sastsimi.orchestration.static_work_handlers import StaticToolRoute
from sastsimi.ports.dto import (
    CancellationResult,
    MonotonicActionDeadline,
    ProcessReceipt,
    StaticRuleMapping,
    TrackedFile,
)
from sastsimi.ports.static_tool import StaticProcessAdapter
from sastsimi.ports.workspace import WorkspaceLocatorPort
from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter
from tests.contract.domain.fixtures import meta
from tests.unit.static_analysis.test_ast_adapter import _request


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact(payload: bytes) -> StoredDataRef:
    digest = hashlib.sha256(payload).hexdigest()
    return StoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=None,
    )


def _rule_payloads() -> tuple[
    bytes, bytes, bytes, ApprovedStaticRuleClosure
]:
    mapping = StaticRuleMapping("R1", "SINK", "SOURCE", True)
    catalog = canonical_bytes({"schema_version": 1, "rule_ids": ["R1"]})
    selection = canonical_bytes(
        {"schema_version": 1, "rule_ids": ["R1"], "rule_packs": ["web"]}
    )
    mappings = canonical_bytes(
        {
            "schema_version": 1,
            "mappings": [
                {
                    "rule_id": "R1",
                    "result_fact_kind": "SINK",
                    "flow_start_fact_kind": "SOURCE",
                    "requires_code_flow": True,
                }
            ],
        }
    )
    closure = ApprovedStaticRuleClosure(
        catalog_sha256=hashlib.sha256(catalog).hexdigest(),
        selection_sha256=hashlib.sha256(selection).hexdigest(),
        mapping_sha256=hashlib.sha256(mappings).hexdigest(),
        catalog_rule_ids=("R1",),
        selected_rule_ids=("R1",),
        mappings=(mapping,),
    )
    return catalog, selection, mappings, closure


def _evidence_ref(name: str) -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId(name),
        data_kind="tool_capability_evidence",
        content_hash="c" * 64,
        host_id="host-one",
        publication_analysis_id=AnalysisId("a1"),
        publication_workspace_id=WorkspaceId("ws1"),
        publication_commit_id=CommitId("c1"),
        record_id=RecordId(name),
    )


def _ast_profile(executable: Path) -> StaticToolProfile:
    record_meta = meta("static_tool_profile", hypothesis=None, attempt=None)
    record_meta["created_at"] = datetime(2026, 9, 13, tzinfo=UTC)
    return StaticToolProfile.model_validate(
        {
            "meta": record_meta,
            "host_id": "host-one",
            "profile_key": "python-ast-production",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": "PYTHON_AST",
            "tool_name": "AST",
            "tool_kind": "STRUCTURE",
            "executable_key": "python",
            "executable_sha256": _digest(executable),
            "expected_version": platform.python_version(),
            "capability_evidence_ref": _evidence_ref("ast-capability"),
            "probe_timeout_ms": 10_000,
            "run_timeout_ms": 10_000,
            "stdout_limit_bytes": 512_000,
            "stderr_limit_bytes": 32_000,
            "max_attempt_output_bytes": 1_000_000,
            "max_output_file_bytes": 512_000,
            "max_artifact_read_bytes": 512_000,
        }
    )


def _rule_profile(executable: Path, tool: str) -> StaticToolProfile:
    if tool == "OPENGREP":
        values = {
            "adapter_key": "OPENGREP",
            "tool_name": "OPENGREP",
            "tool_kind": "RULE_BASED",
            "executable_key": "opengrep",
            "expected_version": "1.0.0",
        }
    else:
        values = {
            "adapter_key": "CODEQL",
            "tool_name": "CODEQL",
            "tool_kind": "RULE_BASED",
            "executable_key": "codeql",
            "expected_version": "2.0.0",
        }
    return _ast_profile(executable).model_copy(update=values)


class _Locator:
    def __init__(self, root: Path, tracked: tuple[TrackedFile, ...]) -> None:
        self.root = root
        self.tracked = tracked
        self.manifest_reads = 0

    def root_for(self, workspace: CodeWorkspace) -> Path:
        assert workspace.workspace_id == WorkspaceId("ws1")
        return self.root

    async def assert_unchanged(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        assert workspace.commit_id == CommitId("c1")
        assert deadline.action_id == "ast-action"
        assert attempt_id == "at1"
        assert check_id
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
        raise AssertionError((workspace, deadline, attempt_id, check_ids, receipts))

    def tracked_files_for(self, workspace: CodeWorkspace) -> tuple[TrackedFile, ...]:
        assert workspace.commit_id == CommitId("c1")
        self.manifest_reads += 1
        return self.tracked


@pytest.mark.asyncio
async def test_ast_adapter_is_built_from_current_manifest_at_execute_time(
    tmp_path: Path,
) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    source = workspace_root / "app.py"
    source.write_text("value = input()\nprint(value)\n", encoding="utf-8")
    tracked = (
        TrackedFile("app.py", "100644", "blob-app", source.stat().st_size),
    )
    locator = _Locator(workspace_root, tracked)
    executable = Path(sys.executable).resolve(strict=True)
    worker = (
        Path(__file__).parents[3]
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py"
    ).resolve(strict=True)
    profile = _ast_profile(executable)
    profile_ref = cast(HostConfigurationRef, reference(profile))
    config = b'{"schema_version":1,"tool":"AST"}'
    config_ref = _artifact(config)
    factory = ProductionStaticAdapterFactory(
        executables={"PYTHON_AST": executable},
        python_ast_worker=worker,
        python_ast_worker_sha256=_digest(worker),
    )
    context = StaticAdapterBuildContext(
        data_dir=tmp_path,
        workspace_locator=cast(WorkspaceLocatorPort, locator),
        tracked_files_for=locator.tracked_files_for,
        routes={"AST": StaticToolRoute(profile_ref, config_ref, None)},
        profiles={"AST": profile},
        evidence={config_ref.content_hash: config},
        rule_closures={},
    )

    adapters = factory(context)

    assert locator.manifest_reads == 0
    adapter = adapters["PYTHON_AST"]
    assert not isinstance(adapter, PythonAstProcessAdapter)
    request = replace(
        _request(("app.py",)),
        tool_profile_ref=profile_ref,
        analysis_config_ref=config_ref,
    )
    deadline = MonotonicActionDeadline(
        action_id="ast-action",
        started_ns=time.monotonic_ns(),
        expires_ns=time.monotonic_ns() + 10_000_000_000,
    )

    observation = await adapter.execute(request, workspace_root, profile, deadline)

    assert locator.manifest_reads == 1
    assert observation.status == "SUCCEEDED"
    assert observation.analyzed_paths == ("app.py",)


def test_codeql_database_create_is_no_build_and_exact_language(tmp_path: Path) -> None:
    executable = tmp_path / "codeql"
    workspace = tmp_path / "workspace"
    database = tmp_path / "database"

    argv = codeql_database_create_argv(
        executable=executable,
        database_root=database,
        workspace_root=workspace,
        language="python",
    )

    assert argv == (
        str(executable),
        "database",
        "create",
        str(database),
        "--language=python",
        "--build-mode=none",
        f"--source-root={workspace}",
    )


def test_codeql_language_scope_never_guesses_a_mixed_request() -> None:
    with pytest.raises(ValueError, match="CODEQL_LANGUAGE_SCOPE_AMBIGUOUS"):
        classify_codeql_language(("src/app.py", "web/app.js"))


def test_opengrep_material_is_bound_to_exact_approved_evidence(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "opengrep.exe"
    executable.write_bytes(b"trusted-opengrep")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    locator = _Locator(workspace, ())
    profile = _rule_profile(executable, "OPENGREP")
    profile_ref = cast(HostConfigurationRef, reference(profile))
    config = b"rules: []\n"
    config_digest = hashlib.sha256(config).hexdigest()
    manifest = canonical_bytes(
        {
            "schema_version": 1,
            "tools": {"OPENGREP": {"config_sha256": config_digest}},
        }
    )
    manifest_ref = _artifact(manifest)
    catalog, selection, mappings, closure = _rule_payloads()
    catalog_ref = _artifact(catalog)
    route = StaticToolRoute(
        profile_ref, manifest_ref, catalog_ref, closure.catalog_rule_ids
    )
    evidence = {
        item.content_hash: payload
        for item, payload in (
            (manifest_ref, manifest),
            (catalog_ref, catalog),
            (_artifact(selection), selection),
            (_artifact(mappings), mappings),
            (_artifact(config), config),
        )
    }
    factory = ProductionStaticAdapterFactory(
        executables={"OPENGREP": executable},
        python_ast_worker=executable,
        python_ast_worker_sha256=_digest(executable),
    )
    context = StaticAdapterBuildContext(
        data_dir=tmp_path,
        workspace_locator=cast(WorkspaceLocatorPort, locator),
        tracked_files_for=locator.tracked_files_for,
        routes={"OPENGREP": route},
        profiles={"OPENGREP": profile},
        evidence=evidence,
        rule_closures={"OPENGREP": closure},
    )

    adapters = factory(context)

    assert set(adapters) == {"OPENGREP"}
    materialized = (
        tmp_path
        / "static-material"
        / manifest_ref.content_hash
        / "opengrep"
        / "config.yml"
    )
    assert materialized.read_bytes() == config


def test_codeql_activation_requires_a_real_hard_quota_port(tmp_path: Path) -> None:
    executable = tmp_path / "codeql.exe"
    executable.write_bytes(b"trusted-codeql")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    locator = _Locator(workspace, ())
    profile = _rule_profile(executable, "CODEQL")
    profile_ref = cast(HostConfigurationRef, reference(profile))
    query_file = b"name: approved/query-pack\n"
    query_digest = hashlib.sha256(query_file).hexdigest()
    manifest = canonical_bytes(
        {
            "schema_version": 1,
            "tools": {
                "CODEQL": {
                    "query_pack_sha256": "a" * 64,
                    "files": [{"path": "qlpack.yml", "sha256": query_digest}],
                }
            },
        }
    )
    manifest_ref = _artifact(manifest)
    catalog, selection, mappings, closure = _rule_payloads()
    catalog_ref = _artifact(catalog)
    evidence = {
        hashlib.sha256(payload).hexdigest(): payload
        for payload in (
            manifest,
            catalog,
            selection,
            mappings,
            query_file,
        )
    }
    context = StaticAdapterBuildContext(
        data_dir=tmp_path,
        workspace_locator=cast(WorkspaceLocatorPort, locator),
        tracked_files_for=locator.tracked_files_for,
        routes={
            "CODEQL": StaticToolRoute(
                profile_ref,
                manifest_ref,
                catalog_ref,
                closure.catalog_rule_ids,
            )
        },
        profiles={"CODEQL": profile},
        evidence=evidence,
        rule_closures={"CODEQL": closure},
    )
    factory = ProductionStaticAdapterFactory(
        executables={"CODEQL": executable},
        python_ast_worker=executable,
        python_ast_worker_sha256=_digest(executable),
    )

    with pytest.raises(ValueError, match="PRODUCTION_CODEQL_HARD_QUOTA_REQUIRED"):
        factory(context)


@pytest.mark.asyncio
async def test_static_cancellation_uses_exact_durable_attempt_dispatch(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"trusted-python")
    profile = _ast_profile(executable)

    class Adapter:
        def __init__(self, executable_path: Path) -> None:
            self.executable = executable_path
            self.cancelled: list[str] = []

        async def cancel(self, attempt_id: str) -> CancellationResult:
            self.cancelled.append(attempt_id)
            return CancellationResult(True, None)

    adapter = Adapter(executable)
    dispatch = StaticAttemptAdapterDispatch(
        action_id="action-1",
        attempt_id="attempt-1",
        adapter_key="PYTHON_AST",
        tool_profile_ref=cast(HostConfigurationRef, reference(profile)),
        state="DISPATCHED",
    )
    router = StaticAdapterCancellationRouter(
        adapters={"PYTHON_AST": cast(StaticProcessAdapter, adapter)},
        profiles={"PYTHON_AST": profile},
        dispatch_for_attempt=lambda attempt_id: (
            dispatch if attempt_id == "attempt-1" else None
        ),
    )

    result = await router.cancel("attempt-1")

    assert result.cancelled
    assert adapter.cancelled == ["attempt-1"]
    assert not (await router.cancel("other-attempt")).cancelled
