"""T16 real-repository matrix for ingress, profiling, and tool selection."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.capabilities import CapabilityApprovalEvidence
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    LogicalRecordId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import (
    RepositoryExecutionSelection,
    RepositoryProfile,
)
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    RepositoryPreparation,
    WorkspaceStorageLease,
    WorkspaceStoragePolicy,
)
from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner
from sastsimi.static_analysis.repository_loader import RepositoryLoader
from sastsimi.static_analysis.repository_profile import (
    RepositoryExecutionSelector,
    RepositoryProfiler,
)
from sastsimi.static_analysis.workspace_storage import FixtureQuotaWorkspaceStorage
from tests.integration.storage.test_production_capability_registry import (
    _approval,
    _runtime,
    _runtime_profile,
)
from tests.unit.static_analysis.test_repository_profile import _Resolver

NOW = datetime(2026, 9, 13, tzinfo=UTC)
ANALYSIS_ID = AnalysisId("t16-analysis")
WORKSPACE_ID = WorkspaceId("t16-workspace")
ATTEMPT_ID = AttemptId("t16-attempt")


def _meta(kind: str, name: str, *, commit_id: str) -> RecordMeta:
    return RecordMeta(
        record_id=RecordId(name),
        logical_record_id=LogicalRecordId(name),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=NOW,
        analysis_id=ANALYSIS_ID,
        workspace_id=WORKSPACE_ID,
        commit_id=CommitId(commit_id),
        hypothesis_id=None,
        attempt_id=ATTEMPT_ID,
    )


def _workspace_ref() -> RunStoredDataRef:
    return RunStoredDataRef(
        stored_data_id=StoredDataId("workspace-record"),
        data_kind="code_workspace",
        content_hash="b" * 64,
        analysis_id=ANALYSIS_ID,
        record_id=RecordId("workspace-record"),
    )


def _decision_ref(commit_id: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId("repository-profile-decision"),
        data_kind="action_decision",
        content_hash="c" * 64,
        workspace_id=WORKSPACE_ID,
        commit_id=CommitId(commit_id),
        record_id=RecordId("repository-profile-decision"),
    )


def _quota_ref() -> RunStoredDataRef:
    return RunStoredDataRef(
        stored_data_id=StoredDataId("d" * 64),
        data_kind="artifact",
        content_hash="d" * 64,
        analysis_id=ANALYSIS_ID,
        record_id=None,
    )


def _git(root: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git is not installed")
    return subprocess.run(
        (executable, *args),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _source_repository(
    root: Path,
    *,
    tracked: dict[str, str],
    untracked: dict[str, str] | None = None,
) -> tuple[Path, str]:
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "fixture@example.invalid")
    _git(root, "config", "user.name", "T16 Fixture")
    for name, contents in tracked.items():
        target = root.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    _git(root, "add", "--", *tracked)
    _git(root, "commit", "-qm", "fixture")
    commit_id = _git(root, "rev-parse", "HEAD")
    for name, contents in (untracked or {}).items():
        target = root.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    return root, commit_id


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


async def _prepare(
    root: Path, source: Path, commit_id: str, git_executable: Path
) -> RepositoryPreparation:
    output = root / "process-output"
    output.mkdir(parents=True)
    storage = FixtureQuotaWorkspaceStorage(root / "leases", capacity_bytes=80_000_000)
    budget = AttemptOutputBudget(
        attempt_id=str(ATTEMPT_ID), limit_bytes=4 * 1024 * 1024
    )

    def runner(
        lease: WorkspaceStorageLease,
        deadline: MonotonicActionDeadline,
        attempt_output: Path,
    ) -> SafeProcessRunner:
        return SafeProcessRunner(
            action_id=deadline.action_id,
            attempt_id=str(ATTEMPT_ID),
            workspace_root=lease.root,
            output_root=attempt_output,
            executable=git_executable,
            output_budget=budget,
        )

    loader = RepositoryLoader(
        storage=storage,
        process_runner_factory=runner,
        git_executable=git_executable,
        output_dir=output,
        allow_local_file=True,
    )
    loader.verify_git_capability(
        git_executable.resolve().stem.lower(), _sha256(git_executable.resolve())
    )
    now = time.monotonic_ns()
    return await loader.prepare(
        submitted_source=source.as_uri(),
        requested_ref=commit_id,
        analysis_id=str(ANALYSIS_ID),
        workspace_id=str(WORKSPACE_ID),
        attempt_id=str(ATTEMPT_ID),
        policy_ref=_quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 30_000_000, 30_000_000, 1_000, 1),
        deadline=MonotonicActionDeadline(
            "t16-repository-load", now, now + 60_000_000_000
        ),
    )


def _profile(preparation: RepositoryPreparation) -> RepositoryProfile:
    assert preparation.root is not None
    assert preparation.resolved_commit_id is not None
    return RepositoryProfiler().build(
        preparation,
        meta=_meta(
            "repository_profile",
            "repository-profile",
            commit_id=preparation.resolved_commit_id,
        ),
        workspace_ref=_workspace_ref(),
        action_decision_ref=_decision_ref(preparation.resolved_commit_id),
    )


def _selection(
    profile: RepositoryProfile,
    resolver: _Resolver,
) -> RepositoryExecutionSelection:
    git_ref = resolver.git_ref
    return RepositoryExecutionSelector(
        cast(ProductionCapabilityResolverPort, resolver),
        operating_system="windows",
        architecture="x86_64",
    ).select(
        profile,
        meta=_meta(
            "repository_execution_selection",
            "repository-selection",
            commit_id=str(profile.commit_id),
        ),
        repository_profile_ref=cast(StoredDataRef, reference(profile)),
        git_clone_profile_ref=git_ref,
        git_checkout_profile_ref=git_ref,
    )


@pytest.mark.asyncio
async def test_real_python_and_javascript_repositories_reach_tool_selection(
    tmp_path: Path,
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")
    git_executable = Path(git)
    resolver = _Resolver()
    cases = (
        (
            "python",
            {
                "src/app.py": "from fastapi import FastAPI\n",
                "requirements.txt": "fastapi>=0.100\n",
                "pyproject.toml": (
                    '[project]\nname="fixture"\ndependencies=["fastapi"]\n'
                    '[project.scripts]\nstart="src.app:main"\n'
                ),
                "Dockerfile": "FROM python:3.12-slim\n",
            },
            {"package.json": '{"dependencies":{"express":"*"}}'},
            ("PYTHON",),
            ("DOCKERFILE", "PYPROJECT", "REQUIREMENTS"),
            ("CODEQL", "OPENGREP", "PYTHON_AST"),
        ),
        (
            "javascript",
            {
                "src/server.js": "export const server = true;\n",
                "package.json": (
                    '{"dependencies":{"express":"^5.0.0"},'
                    '"scripts":{"start":"node src/server.js"}}'
                ),
            },
            {"requirements.txt": "flask\n"},
            ("JAVASCRIPT",),
            ("PACKAGE_JSON",),
            ("CODEQL", "OPENGREP"),
        ),
    )
    for name, tracked, untracked, languages, config_kinds, adapters in cases:
        source, commit_id = _source_repository(
            tmp_path / name / "source", tracked=tracked, untracked=untracked
        )
        preparation = await _prepare(
            tmp_path / name / "analysis", source, commit_id, git_executable
        )
        assert preparation.status == "READY", preparation.errors
        assert preparation.resolved_commit_id == commit_id
        assert preparation.root is not None
        assert _git(preparation.root, "rev-parse", "HEAD") == commit_id
        assert _git(preparation.root, "branch", "--show-current") == ""
        profile = _profile(preparation)
        assert profile.status == "READY"
        assert tuple(item.name for item in profile.languages) == languages
        assert tuple(item.kind for item in profile.config_files) == config_kinds
        assert {item.git_path for item in profile.tracked_files} == set(tracked)
        assert not ({item.git_path for item in profile.tracked_files} & set(untracked))
        selection = _selection(profile, resolver)
        assert selection.status == "READY"
        assert tuple(item.adapter_key for item in selection.selected_tools) == adapters


@pytest.mark.asyncio
async def test_unconfirmed_repository_is_blocked_without_a_false_verdict(
    tmp_path: Path,
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")
    git_executable = Path(git)
    resolver = _Resolver()
    source, commit_id = _source_repository(
        tmp_path / "unknown" / "source",
        tracked={"README.md": "custom build instructions\n"},
        untracked={"app.py": "print('untracked')\n"},
    )

    preparation = await _prepare(
        tmp_path / "unknown" / "analysis", source, commit_id, git_executable
    )
    profile = _profile(preparation)
    selection = _selection(profile, resolver)

    assert profile.status == "NEEDS_CONFIRMATION"
    assert profile.languages == ()
    assert set(profile.confirmation_reasons) == {
        "BUILD_OR_START_UNCONFIRMED",
        "LANGUAGE_UNCONFIRMED",
    }
    assert selection.status == "BLOCKED"
    assert selection.selected_tools == ()
    assert selection.errors == ()
    assert not hasattr(preparation, "verdict")
    assert not hasattr(profile, "verdict")
    assert not hasattr(selection, "verdict")


def test_unapproved_or_failed_probe_cannot_activate_a_production_capability(
    tmp_path: Path,
) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    profile = _runtime_profile()
    approval = _approval(profile, raw_ref)

    with pytest.raises(ValueError, match="CAPABILITY_APPROVAL_REQUIRED"):
        runtime.configuration.register_capability_approval(approval)
    with pytest.raises(ValueError, match="CAPABILITY_EVIDENCE_REQUIRED"):
        runtime.configuration.register_runtime_capability(profile)

    rejected = CapabilityApprovalEvidence.model_validate(
        approval.model_dump()
        | {
            "probe_status": "FAILED",
            "decision": "REJECT",
            "safe_summary": "The exact capability probe failed.",
        }
    )
    evidence.capability_approvals.add(content_hash(rejected))
    rejected_ref = runtime.configuration.register_capability_approval(rejected)
    with pytest.raises(ValueError, match="CAPABILITY_APPROVAL_DECISION_MISMATCH"):
        runtime.configuration.register_runtime_capability(
            profile.model_copy(update={"capability_evidence_ref": rejected_ref})
        )
    with pytest.raises(LookupError, match="CAPABILITY_ROUTE_NOT_ACTIVE"):
        runtime.configuration.resolve_active_capability(
            capability_kind="PACKAGE_MANAGER",
            language="PYTHON",
            operation="PACKAGE_INSTALL",
            operating_system="windows",
            architecture="x86_64",
        )
