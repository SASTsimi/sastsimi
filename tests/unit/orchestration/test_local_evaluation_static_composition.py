from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.composition.local_evaluation_static import (
    LocalEvaluationStaticBlocked,
    LocalEvaluationStaticInputs,
    LocalEvaluationStaticServices,
    build_local_evaluation_static,
)
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.orchestration.static_work_handlers import StaticToolRoute
from sastsimi.ports.dto import (
    CancellationResult,
    MonotonicActionDeadline,
    RepositoryPreparation,
    StaticCapabilityObservation,
    StaticToolObservation,
    StaticToolRequest,
)
from sastsimi.static_analysis.coordinator import StaticToolCoordinator
from sastsimi.static_analysis.repository_loader import RepositoryLoader
from sastsimi.static_analysis.repository_profile import RepositoryProfiler
from tests.contract.domain.fixtures import meta


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _host_ref(kind: str, key: str, digest: str = "a" * 64) -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId(key),
        data_kind=kind,
        content_hash=digest,
        host_id="host-one",
        publication_analysis_id=AnalysisId("a1"),
        publication_workspace_id=WorkspaceId("ws1"),
        publication_commit_id=CommitId("c1"),
        record_id=RecordId(key),
    )


def _profile_meta(kind: str) -> dict[str, object]:
    value = meta(kind, hypothesis=None, attempt=None)
    value["created_at"] = datetime(2026, 9, 20, tzinfo=UTC)
    return value


def _git_profile(
    git: Path, *, key: str = "git-local-evaluation-v1"
) -> RuntimeCapabilityProfile:
    return RuntimeCapabilityProfile.model_validate(
        {
            "meta": _profile_meta("runtime_capability_profile"),
            "host_id": "host-one",
            "profile_key": key,
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "capability_kind": "GIT",
            "subject_key": git.stem,
            "expected_version": "approved-version",
            "subject_sha256": _digest(git),
            "operating_system": "windows" if os.name == "nt" else "linux",
            "architecture": "x86_64",
            "languages": ("ANY",),
            "operations": ("CLONE", "CHECKOUT"),
            "capability_evidence_ref": _host_ref(
                "tool_capability_evidence", "git-evidence"
            ),
        }
    )


def _ast_profile(executable: Path) -> StaticToolProfile:
    return StaticToolProfile.model_validate(
        {
            "meta": _profile_meta("static_tool_profile"),
            "host_id": "host-one",
            "profile_key": "python-ast-local-evaluation-v1",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": "PYTHON_AST",
            "tool_name": "AST",
            "tool_kind": "STRUCTURE",
            "executable_key": "python",
            "executable_sha256": _digest(executable),
            "expected_version": "approved-version",
            "capability_evidence_ref": _host_ref(
                "tool_capability_evidence", "ast-evidence"
            ),
            "probe_timeout_ms": 1_000,
            "run_timeout_ms": 1_000,
            "stdout_limit_bytes": 1_024,
            "stderr_limit_bytes": 1_024,
            "max_attempt_output_bytes": 4_096,
            "max_output_file_bytes": 2_048,
            "max_artifact_read_bytes": 2_048,
        }
    )


class _Configuration:
    def __init__(self, profiles: dict[HostConfigurationRef, object]) -> None:
        self._profiles = profiles

    def resolve_pinned_active_profile(self, ref: HostConfigurationRef) -> object:
        return self._profiles[ref]


class _ProcessAdapter:
    def __init__(self, executable: Path) -> None:
        self.executable = executable

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        return StaticCapabilityObservation(
            available=True,
            tool_name=profile.tool_name,
            tool_kind=profile.tool_kind,
            executable_key=profile.executable_key,
            observed_executable_sha256=profile.executable_sha256,
            observed_version=profile.expected_version,
            expected_version=profile.expected_version,
            reason_code=None,
        )

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        raise AssertionError((request, workspace_root, profile, deadline))

    async def cancel(self, attempt_id: str) -> CancellationResult:
        return CancellationResult(False, attempt_id)


def _inputs(
    tmp_path: Path, *, git_key: str = "git-local-evaluation-v1"
) -> LocalEvaluationStaticInputs:
    git_name = shutil.which("git")
    assert git_name is not None
    git = Path(git_name).resolve(strict=True)
    git_profile = _git_profile(git, key=git_key)
    ast_profile = _ast_profile(git)
    git_ref = cast(HostConfigurationRef, reference(git_profile))
    ast_ref = cast(HostConfigurationRef, reference(ast_profile))
    analysis_config = b'{"schema_version":1}'
    config_digest = hashlib.sha256(analysis_config).hexdigest()
    config_ref = StoredDataRef(
        stored_data_id=StoredDataId(config_digest),
        data_kind="artifact",
        content_hash=config_digest,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=None,
    )
    return LocalEvaluationStaticInputs(
        data_dir=tmp_path,
        host_id="host-one",
        capability_keys=SimpleNamespace(
            git_profile_key="git-local-evaluation-v1",
            python_ast_profile_key="python-ast-local-evaluation-v1",
            opengrep_profile_key="opengrep-local-evaluation-v1",
            codeql_profile_key="codeql-local-evaluation-v1",
        ),
        capability_resolver=cast(
            Any, _Configuration({git_ref: git_profile, ast_ref: ast_profile})
        ),
        storage=cast(Any, SimpleNamespace()),
        workspace_locator=cast(
            Any,
            SimpleNamespace(
                tracked_files_for=lambda _workspace: (),
                register=lambda _outcome: None,
            ),
        ),
        repository_process_runner_factory=cast(Any, lambda *_values: None),
        external_execution=cast(Any, SimpleNamespace()),
        git_executable=git,
        git_profile_ref=git_ref,
        static_profile_refs={"AST": ast_ref},
        routes={"AST": StaticToolRoute(ast_ref, config_ref, None)},
        evidence={config_digest: analysis_config},
        rule_closures={},
        build_static_adapters=lambda _context: {"PYTHON_AST": _ProcessAdapter(git)},
        allow_local_repository=True,
    )


def _scratch(name: str) -> Path:
    root = Path("runtime-data/local-static-composition-tests") / name
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve(strict=True)


def test_builds_real_repository_profiler_and_static_coordinator() -> None:
    services = build_local_evaluation_static(_inputs(_scratch("build")))

    assert isinstance(services.loader, RepositoryLoader)
    assert isinstance(services.profiler, RepositoryProfiler)
    assert isinstance(services.tools, StaticToolCoordinator)
    assert tuple(services.profile_refs) == ("AST",)


def test_rejects_profile_key_mismatch_before_creating_runtime_directories() -> None:
    root = _scratch("key-mismatch")
    before = set(root.rglob("*"))

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_GIT_CAPABILITY_INVALID"):
        build_local_evaluation_static(_inputs(root, git_key="wrong-git-key"))

    assert set(root.rglob("*")) == before


@pytest.mark.asyncio
async def test_repository_failure_blocks_without_security_verdict() -> None:
    failed = RepositoryPreparation(
        analysis_id="a1",
        workspace_id="ws1",
        repository_url="https://example.invalid/repository.git",
        requested_ref="c1",
        status="FAILED",
        resolved_commit_id=None,
        root=None,
        tracked_files=(),
        gaps=(),
        errors=(),
    )

    async def prepare(**_values: object) -> RepositoryPreparation:
        return failed

    services = LocalEvaluationStaticServices(
        loader=SimpleNamespace(prepare=prepare),
        profiler=RepositoryProfiler(),
        tools=SimpleNamespace(),
        profile_refs={},
        workspace_locator=cast(Any, SimpleNamespace(register=lambda _value: None)),
    )

    with pytest.raises(
        LocalEvaluationStaticBlocked,
        match="LOCAL_EVALUATION_REPOSITORY_PREPARATION_BLOCKED",
    ) as raised:
        await services.prepare_repository(
            submitted_source="https://example.invalid/repository.git",
            requested_ref="c1",
            analysis_id="a1",
            workspace_id="ws1",
            attempt_id="at1",
            policy_ref=cast(Any, None),
            policy=cast(Any, None),
            deadline=cast(Any, None),
        )

    assert not hasattr(raised.value, "verdict")


@pytest.mark.asyncio
async def test_static_cancellation_is_not_relabelled_as_tool_failure() -> None:
    profile_ref = _host_ref("static_tool_profile", "ast-profile")

    class _CancelledTools:
        async def probe(self, _ref: object) -> object:
            return SimpleNamespace(available=True)

        async def run(self, _request: object) -> object:
            raise asyncio.CancelledError

    services = LocalEvaluationStaticServices(
        loader=cast(Any, SimpleNamespace()),
        profiler=RepositoryProfiler(),
        tools=cast(Any, _CancelledTools()),
        profile_refs={"AST": profile_ref},
        workspace_locator=cast(Any, SimpleNamespace()),
    )
    request = cast(StaticToolRequest, SimpleNamespace(tool_profile_ref=profile_ref))

    with pytest.raises(asyncio.CancelledError):
        await services.run_tools((request,))
