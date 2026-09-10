"""Exact Git checkout, manifest and shared-deadline repository behavior."""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, StoredDataId
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    ProcessReceipt,
    ProcessResult,
    ProcessSpec,
    WorkspaceStorageLease,
    WorkspaceStoragePolicy,
)
from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner
from sastsimi.static_analysis.repository_loader import RepositoryLoader, WorkspaceGuard
from sastsimi.static_analysis.workspace_storage import FixtureQuotaWorkspaceStorage
from tests.integration.runtime_support import metadata


def quota_ref() -> RunStoredDataRef:
    raw = canonical_bytes(
        {
            "kind": "workspace_storage_policy",
            "schema_version": "1.0",
            "max_git_bytes": 1_000_000,
            "max_checkout_bytes": 1_000_000,
            "max_file_count": 100,
            "min_free_bytes": 1,
        }
    )
    digest = hashlib.sha256(raw).hexdigest()
    return RunStoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        analysis_id=AnalysisId("analysis"),
        record_id=None,
    )


def result(
    spec: ProcessSpec, stdout: bytes = b"", outcome: str = "SUCCEEDED"
) -> ProcessResult:
    receipt = ProcessReceipt(
        invocation_id=spec.invocation_id,
        attempt_id=spec.attempt_id,
        command_fingerprint=hashlib.sha256(canonical_bytes(spec.argv)).hexdigest(),
        outcome=outcome,  # type: ignore[arg-type]
        return_code=0 if outcome == "SUCCEEDED" else 1,
        stdout_name="stdout",
        stdout_size=len(stdout),
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_name="stderr",
        stderr_size=0,
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        elapsed_ms=1,
    )
    return ProcessResult(
        outcome=receipt.outcome,
        return_code=receipt.return_code,
        stdout=stdout,
        stderr_tail=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        elapsed_ms=1,
        receipt=receipt,
        receipt_path=spec.attempt_output_dir / f"{spec.invocation_id}.json",
    )


@dataclass
class FakeRunner:
    outputs: list[bytes | str]
    specs: list[ProcessSpec]
    cancelled: bool = False

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.specs.append(spec)
        if "clone" in spec.argv:
            (spec.cwd / ".git").mkdir(exist_ok=True)
        if "checkout" in spec.argv:
            (spec.cwd / "src").mkdir(exist_ok=True)
            (spec.cwd / "src" / "app.py").write_text("value = 1", encoding="utf-8")
            (spec.cwd / "safe.py").write_text("value = 1", encoding="utf-8")
            (spec.cwd / ".env").write_text("SECRET=x", encoding="utf-8")
        item = self.outputs.pop(0)
        return result(
            spec,
            item if isinstance(item, bytes) else b"",
            item if isinstance(item, str) else "SUCCEEDED",
        )

    async def cancel(self, attempt_id: str) -> object:
        self.cancelled = True
        return object()


class QuotaCrossingRunner:
    """Write one byte beyond checkout quota and remain active until cancelled."""

    def __init__(self) -> None:
        self.specs: list[ProcessSpec] = []
        self.cancelled = False
        self._cancelled = asyncio.Event()

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.specs.append(spec)
        (spec.cwd / "cap-plus-one.bin").write_bytes(b"x" * 21)
        try:
            await asyncio.wait_for(self._cancelled.wait(), timeout=0.1)
        except TimeoutError:
            pass
        return result(spec, outcome="CANCELLED" if self.cancelled else "SUCCEEDED")

    async def cancel(self, attempt_id: str) -> object:
        assert attempt_id == "attempt"
        self.cancelled = True
        self._cancelled.set()
        return object()


class FailingAllocationStorage(FixtureQuotaWorkspaceStorage):
    def allocate(self, **values: object) -> WorkspaceStorageLease:
        del values
        raise ValueError("WORKSPACE_RESERVE_INSUFFICIENT")


class TrackingStorage(FixtureQuotaWorkspaceStorage):
    def __init__(self, root: Path, *, occupy: bool = False) -> None:
        super().__init__(root, capacity_bytes=3_000_001)
        self.occupy = occupy
        self.cleaned = False

    def allocate(self, **values: object) -> WorkspaceStorageLease:
        lease = super().allocate(**values)  # type: ignore[arg-type]
        if self.occupy:
            (lease.root / "unexpected").write_bytes(b"x")
        return lease

    def cleanup_or_quarantine(self, lease: WorkspaceStorageLease) -> None:
        self.cleaned = True
        super().cleanup_or_quarantine(lease)


def loader(
    tmp_path: Path, outputs: list[bytes | str]
) -> tuple[RepositoryLoader, FakeRunner]:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"fixture")
    output = tmp_path / "output"
    output.mkdir()
    runner = FakeRunner(outputs, [])
    storage = FixtureQuotaWorkspaceStorage(
        tmp_path / "leases", capacity_bytes=3_000_001
    )
    return (
        RepositoryLoader(
            storage=storage,
            process_runner_factory=lambda _lease, _deadline, _output: runner,
            git_executable=executable,
            output_dir=output,
            allow_local_file=True,
        ),
        runner,
    )


@pytest.mark.asyncio
async def test_repository_resolves_once_and_checks_out_detached_commit(
    tmp_path: Path,
) -> None:
    """Using the moving branch after resolution would analyze a different revision."""
    commit = "a" * 40
    manifest = b"100644 " + b"b" * 40 + b" 0\tsrc/app.py\0"
    subject, runner = loader(
        tmp_path,
        [b"", (commit + "\n").encode(), b"", (commit + "\n").encode(), manifest],
    )
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    now = time.monotonic_ns()
    deadline = MonotonicActionDeadline("action", now, now + 10_000_000_000)
    prepared = await subject.prepare(
        submitted_source=source_repo.as_uri(),
        requested_ref="moving",
        analysis_id="analysis",
        workspace_id="workspace",
        attempt_id="attempt",
        policy_ref=quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 1_000_000, 1_000_000, 100, 1),
        deadline=deadline,
    )

    assert prepared.status == "READY"
    assert prepared.resolved_commit_id == commit
    assert [spec.deadline for spec in runner.specs] == [deadline] * 5
    attempt_outputs = {spec.attempt_output_dir for spec in runner.specs}
    assert len(attempt_outputs) == 1
    assert attempt_outputs != {tmp_path / "output"}
    assert next(iter(attempt_outputs)).parent == tmp_path / "output"
    assert runner.specs[1].argv[-2:] == ("--end-of-options", "moving^{commit}")
    assert runner.specs[2].argv[-2:] == ("--detach", commit)
    assert prepared.tracked_files[0].git_path == "src/app.py"


@pytest.mark.asyncio
async def test_repository_failure_or_cancel_prevents_later_git_commands(
    tmp_path: Path,
) -> None:
    """Continuing after one failed command could publish an unverified workspace."""
    subject, runner = loader(tmp_path, [b"", "TIMED_OUT"])
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    prepared = await subject.prepare(
        submitted_source=source_repo.as_uri(),
        requested_ref="HEAD",
        analysis_id="analysis",
        workspace_id="workspace",
        attempt_id="attempt",
        policy_ref=quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 1_000_000, 1_000_000, 100, 1),
        deadline=MonotonicActionDeadline(
            "action", time.monotonic_ns(), time.monotonic_ns() + 10_000_000_000
        ),
    )
    assert prepared.status == "FAILED"
    assert len(runner.specs) == 2
    assert not prepared.tracked_files
    assert prepared.errors[0].code == "GIT_COMMAND_FAILED"


@pytest.mark.asyncio
async def test_checkout_cap_plus_one_cancels_active_git_immediately(
    tmp_path: Path,
) -> None:
    """Post-command measurement would allow an over-quota Git process to continue."""
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"fixture")
    output = tmp_path / "output"
    output.mkdir()
    runner = QuotaCrossingRunner()
    storage = FixtureQuotaWorkspaceStorage(
        tmp_path / "leases", capacity_bytes=1_000_000
    )
    subject = RepositoryLoader(
        storage=storage,
        process_runner_factory=lambda _lease, _deadline, _output: runner,
        git_executable=executable,
        output_dir=output,
        allow_local_file=True,
    )
    source = tmp_path / "source"
    source.mkdir()
    now = time.monotonic_ns()

    prepared = await subject.prepare(
        submitted_source=source.as_uri(),
        requested_ref="HEAD",
        analysis_id="analysis",
        workspace_id="workspace",
        attempt_id="attempt",
        policy_ref=quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 100, 20, 10, 1),
        deadline=MonotonicActionDeadline("action", now, now + 1_000_000_000),
    )

    assert prepared.status == "FAILED"
    assert runner.cancelled
    assert len(runner.specs) == 1


@pytest.mark.asyncio
async def test_allocation_failure_returns_typed_failed_preparation(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"fixture")
    output = tmp_path / "output"
    output.mkdir()
    storage = FailingAllocationStorage(tmp_path / "leases", capacity_bytes=1)
    subject = RepositoryLoader(
        storage=storage,
        process_runner_factory=lambda _lease, _deadline, _output: FakeRunner([], []),
        git_executable=executable,
        output_dir=output,
        allow_local_file=True,
    )
    source = tmp_path / "source"
    source.mkdir()
    now = time.monotonic_ns()

    prepared = await subject.prepare(
        submitted_source=source.as_uri(),
        requested_ref="HEAD",
        analysis_id="analysis",
        workspace_id="workspace",
        attempt_id="attempt",
        policy_ref=quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 100, 20, 10, 1),
        deadline=MonotonicActionDeadline("action", now, now + 1_000_000_000),
    )

    assert prepared.status == "FAILED"
    assert prepared.root is None
    assert prepared.errors[0].code == "GIT_COMMAND_FAILED"


@pytest.mark.asyncio
async def test_invalid_destination_is_cleaned_and_returns_typed_failure(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"fixture")
    output = tmp_path / "output"
    output.mkdir()
    storage = TrackingStorage(tmp_path / "leases", occupy=True)
    subject = RepositoryLoader(
        storage=storage,
        process_runner_factory=lambda _lease, _deadline, _output: FakeRunner([], []),
        git_executable=executable,
        output_dir=output,
        allow_local_file=True,
    )
    source = tmp_path / "source"
    source.mkdir()
    now = time.monotonic_ns()

    prepared = await subject.prepare(
        submitted_source=source.as_uri(),
        requested_ref="HEAD",
        analysis_id="analysis",
        workspace_id="workspace",
        attempt_id="attempt",
        policy_ref=quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 100, 20, 10, 1),
        deadline=MonotonicActionDeadline("action", now, now + 1_000_000_000),
    )

    assert prepared.status == "FAILED"
    assert storage.cleaned


@pytest.mark.asyncio
async def test_runner_factory_failure_cleans_lease_and_returns_typed_failure(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"fixture")
    output = tmp_path / "output"
    output.mkdir()
    storage = TrackingStorage(tmp_path / "leases")

    def fail_factory(
        _lease: WorkspaceStorageLease,
        _deadline: MonotonicActionDeadline,
        _output: Path,
    ) -> FakeRunner:
        raise ValueError("PROCESS_FACTORY_FAILED")

    subject = RepositoryLoader(
        storage=storage,
        process_runner_factory=fail_factory,
        git_executable=executable,
        output_dir=output,
        allow_local_file=True,
    )
    source = tmp_path / "source"
    source.mkdir()
    now = time.monotonic_ns()

    prepared = await subject.prepare(
        submitted_source=source.as_uri(),
        requested_ref="HEAD",
        analysis_id="analysis",
        workspace_id="workspace",
        attempt_id="attempt",
        policy_ref=quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 100, 20, 10, 1),
        deadline=MonotonicActionDeadline("action", now, now + 1_000_000_000),
    )

    assert prepared.status == "FAILED"
    assert storage.cleaned


@pytest.mark.asyncio
async def test_manifest_excludes_git_links_submodules_lfs_and_unsafe_paths(
    tmp_path: Path,
) -> None:
    """Special Git entries must not escape the regular-file manifest."""
    commit = "a" * 40
    manifest = b"".join(
        (
            b"100644 " + b"1" * 40 + b" 0\tsafe.py\0",
            b"120000 " + b"2" * 40 + b" 0\tlinked.py\0",
            b"160000 " + b"3" * 40 + b" 0\tvendor/sub\0",
            b"100644 " + b"4" * 40 + b" 0\t.env\0",
        )
    )
    subject, runner = loader(
        tmp_path,
        [b"", (commit + "\n").encode(), b"", (commit + "\n").encode(), manifest],
    )
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    prepared = await subject.prepare(
        submitted_source=source_repo.as_uri(),
        requested_ref="HEAD",
        analysis_id="analysis",
        workspace_id="workspace",
        attempt_id="attempt",
        policy_ref=quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 1_000_000, 1_000_000, 100, 1),
        deadline=MonotonicActionDeadline(
            "action", time.monotonic_ns(), time.monotonic_ns() + 10_000_000_000
        ),
    )
    # Materialize files after the fake checkout and parse the manifest directly.
    root = prepared.root
    assert root is not None
    (root / "safe.py").write_text("print('safe')", encoding="utf-8")
    (root / ".env").write_text("SECRET=x", encoding="utf-8")
    reparsed = subject.build_manifest(root, manifest)
    assert tuple(item.git_path for item in reparsed[0]) == ("safe.py",)
    assert {gap.code for gap in reparsed[1]} == {
        "SYMLINK_EXCLUDED",
        "SUBMODULE_UNAVAILABLE",
        "SENSITIVE_PATH_EXCLUDED",
    }
    assert len(runner.specs) == 5


@pytest.mark.asyncio
async def test_real_local_git_prepares_the_exact_detached_commit(
    tmp_path: Path,
) -> None:
    """The real shell-free boundary must preserve the resolved object and manifest."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run((git, "init", "-q"), cwd=source, check=True)
    subprocess.run(
        (git, "config", "user.email", "fixture@example.invalid"), cwd=source, check=True
    )
    subprocess.run((git, "config", "user.name", "Fixture"), cwd=source, check=True)
    (source / "app.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run((git, "add", "app.py"), cwd=source, check=True)
    subprocess.run((git, "commit", "-qm", "first"), cwd=source, check=True)
    first = subprocess.run(
        (git, "rev-parse", "HEAD"),
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (source / "app.py").write_text("value = 2\n", encoding="utf-8")
    subprocess.run((git, "commit", "-qam", "second"), cwd=source, check=True)

    output = tmp_path / "output"
    output.mkdir()
    storage = FixtureQuotaWorkspaceStorage(
        tmp_path / "leases", capacity_bytes=20_000_001
    )
    budget = AttemptOutputBudget(attempt_id="attempt", limit_bytes=4 * 1024 * 1024)

    marker = tmp_path / "malicious-hook-ran"

    class HookInjectingRunner:
        def __init__(self, delegate: SafeProcessRunner) -> None:
            self.delegate = delegate

        async def run(self, spec: ProcessSpec) -> ProcessResult:
            completed = await self.delegate.run(spec)
            if "clone" in spec.argv and completed.outcome == "SUCCEEDED":
                hook = spec.cwd / ".git" / "hooks" / "post-checkout"
                hook.write_text(
                    f"#!/bin/sh\nprintf hook-ran > '{marker.as_posix()}'\n",
                    encoding="utf-8",
                )
                hook.chmod(0o700)
            return completed

        async def cancel(self, attempt_id: str) -> object:
            return await self.delegate.cancel(attempt_id)

    def process_factory(
        lease: WorkspaceStorageLease,
        deadline: MonotonicActionDeadline,
        attempt_output: Path,
    ) -> HookInjectingRunner:
        root = lease.root
        return HookInjectingRunner(
            SafeProcessRunner(
                action_id=deadline.action_id,
                attempt_id="attempt",
                workspace_root=root,
                output_root=attempt_output,
                executable=Path(git),
                output_budget=budget,
            )
        )

    subject = RepositoryLoader(
        storage=storage,
        process_runner_factory=process_factory,
        git_executable=Path(git),
        output_dir=output,
        allow_local_file=True,
    )
    now = time.monotonic_ns()
    prepared = await subject.prepare(
        submitted_source=source.as_uri(),
        requested_ref=first,
        analysis_id="analysis",
        workspace_id="workspace",
        attempt_id="attempt",
        policy_ref=quota_ref(),
        policy=WorkspaceStoragePolicy("1.0", 10_000_000, 10_000_000, 100, 1),
        deadline=MonotonicActionDeadline("action", now, now + 30_000_000_000),
    )

    assert prepared.status == "READY", prepared.errors
    assert prepared.resolved_commit_id == first
    assert prepared.root is not None
    assert (prepared.root / "app.py").read_text(encoding="utf-8") == "value = 1\n"
    assert (
        subprocess.run(
            (git, "-C", str(prepared.root), "rev-parse", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        == first
    )
    assert tuple(item.git_path for item in prepared.tracked_files) == ("app.py",)
    assert not marker.exists()


@pytest.mark.asyncio
async def test_workspace_guard_rejects_head_and_tracked_manifest_drift(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"fixture")
    commit = "a" * 40
    blob = "b" * 40
    manifest = f"100644 {blob} 0\tapp.py\0".encode()
    fixture_root = tmp_path / "manifest-fixture"
    fixture_root.mkdir()
    subject, _ = loader(fixture_root, [])
    tracked, _ = subject.build_manifest(root, manifest)
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            {
                "meta": metadata("code_workspace", "workspace-record"),
                "workspace_id": "workspace",
                "analysis_id": "a1",
                "repository_url": "https://example.invalid/team/repo.git",
                "commit_id": commit,
                "status": "READY",
            }
        )
    )
    active_runner = FakeRunner([(commit + "\n").encode(), b"", b"", manifest], [])
    guard = WorkspaceGuard(
        roots={"workspace": root},
        manifests={"workspace": tracked},
        process_runner_factory=lambda _root, _deadline: active_runner,
        git_executable=executable,
        output_dir=output,
    )
    now = time.monotonic_ns()
    deadline = MonotonicActionDeadline("guard", now, now + 1_000_000_000)
    await guard.assert_unchanged(workspace, deadline)

    moved_runner = FakeRunner([("c" * 40 + "\n").encode()], [])
    moved = WorkspaceGuard(
        roots={"workspace": root},
        manifests={"workspace": tracked},
        process_runner_factory=lambda _root, _deadline: moved_runner,
        git_executable=executable,
        output_dir=output,
    )
    with pytest.raises(ValueError, match="WORKSPACE_MUTATED"):
        await moved.assert_unchanged(workspace, deadline)
