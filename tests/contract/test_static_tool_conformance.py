from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.ports.dto import (
    CancellationResult,
    CandidateGap,
    CandidateLocation,
    CandidateRelation,
    MonotonicActionDeadline,
    ProcessReceipt,
    StaticCapabilityObservation,
    StaticToolObservation,
    StaticToolRequest,
    ToolRunResult,
)
from sastsimi.static_analysis.coordinator import StaticToolCoordinator
from tests.contract.domain.fixtures import meta


def _profile(executable: Path, **changes: object) -> StaticToolProfile:
    values: dict[str, object] = {
        "meta": meta("static_tool_profile", attempt=None),
        "profile_key": "ast-fixture",
        "purpose": "FIXTURE",
        "status": "APPROVED",
        "adapter_key": "PYTHON_AST",
        "tool_name": "AST",
        "tool_kind": "STRUCTURE",
        "executable_key": "fixture-python",
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "expected_version": "3.12",
        "capability_evidence_ref": None,
        "probe_timeout_ms": 100,
        "run_timeout_ms": 200,
        "stdout_limit_bytes": 1024,
        "stderr_limit_bytes": 1024,
        "max_attempt_output_bytes": 4096,
        "max_output_file_bytes": 2048,
        "max_artifact_read_bytes": 2048,
    }
    return StaticToolProfile.model_validate_json(canonical_bytes(values | changes))


class _Profiles:
    def __init__(self, profile: StaticToolProfile) -> None:
        self.profile = profile

    def resolve(self, profile_ref: StoredDataRef) -> StaticToolProfile:
        del profile_ref
        return self.profile


class _Adapter:
    def __init__(
        self, observation: StaticCapabilityObservation, executable: Path
    ) -> None:
        self.observation = observation
        self.executable = executable
        self.probes = 0

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        assert (
            deadline.expires_ns - deadline.started_ns
            == profile.probe_timeout_ms * 1_000_000
        )
        self.probes += 1
        return self.observation

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        del request, workspace_root, profile, deadline
        raise AssertionError("probe must not execute")

    async def cancel(self, attempt_id: str) -> CancellationResult:
        return CancellationResult(True, attempt_id)


class _BlockingAdapter(_Adapter):
    def __init__(
        self, observation: StaticCapabilityObservation, executable: Path
    ) -> None:
        super().__init__(observation, executable)
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled: list[str] = []

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        del profile, deadline
        self.probes += 1
        self.started.set()
        await self.release.wait()
        return self.observation

    async def cancel(self, attempt_id: str) -> CancellationResult:
        self.cancelled.append(attempt_id)
        self.release.set()
        return CancellationResult(True, None)


class _External:
    async def invoke(
        self,
        request: StaticToolRequest,
        profile: StaticToolProfile,
        operation: Callable[
            [MonotonicActionDeadline], Awaitable[StaticToolObservation]
        ],
    ) -> ToolRunResult:
        del request, profile, operation
        raise AssertionError("probe must not enter operational execution")


class _Workspace:
    def root_for(self, workspace: CodeWorkspace) -> Path:
        raise AssertionError("probe must not touch a workspace")

    async def assert_unchanged(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        del workspace, deadline, attempt_id, check_id
        raise AssertionError("probe must not touch a workspace")

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
        raise AssertionError("probe must not validate workspace receipts")


@pytest.mark.asyncio
async def test_probe_exactly_resolves_executable_and_lower_adapter(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "fixture-python"
    executable.write_bytes(b"bounded fixture")
    profile = _profile(executable)
    observation = StaticCapabilityObservation(
        available=True,
        tool_name="AST",
        tool_kind="STRUCTURE",
        executable_key="fixture-python",
        observed_executable_sha256=profile.executable_sha256,
        observed_version="3.12",
        expected_version="3.12",
        reason_code=None,
    )
    adapter = _Adapter(observation, executable)
    coordinator = StaticToolCoordinator(
        _Profiles(profile),
        {"PYTHON_AST": adapter},
        _External(),
        _Workspace(),
        {"fixture-python": executable},
        monotonic_ns=lambda: 10,
    )

    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    result = await coordinator.probe(profile_ref)

    assert result.ref == profile_ref
    assert result.available is True
    assert adapter.probes == 1


@pytest.mark.asyncio
async def test_probe_task_cancellation_is_forwarded_with_exact_action_id(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "fixture-python"
    executable.write_bytes(b"bounded fixture")
    profile = _profile(executable)
    observation = StaticCapabilityObservation(
        available=True,
        tool_name="AST",
        tool_kind="STRUCTURE",
        executable_key="fixture-python",
        observed_executable_sha256=profile.executable_sha256,
        observed_version="3.12",
        expected_version="3.12",
        reason_code=None,
    )
    adapter = _BlockingAdapter(observation, executable)
    coordinator = StaticToolCoordinator(
        _Profiles(profile),
        {"PYTHON_AST": adapter},
        _External(),
        _Workspace(),
        {"fixture-python": executable},
        monotonic_ns=lambda: 10,
    )
    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)

    running = asyncio.create_task(coordinator.probe(profile_ref))
    await adapter.started.wait()
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    assert adapter.cancelled == [f"probe-{profile.meta.record_id}"]


@pytest.mark.asyncio
async def test_probe_rejects_mismatched_lower_observation(tmp_path: Path) -> None:
    executable = tmp_path / "fixture-python"
    executable.write_bytes(b"bounded fixture")
    profile = _profile(executable)
    adapter = _Adapter(
        StaticCapabilityObservation(
            available=True,
            tool_name="CODEQL",
            tool_kind="RULE_BASED",
            executable_key="fixture-python",
            observed_executable_sha256=profile.executable_sha256,
            observed_version="3.12",
            expected_version="3.12",
            reason_code=None,
        ),
        executable,
    )
    coordinator = StaticToolCoordinator(
        _Profiles(profile),
        {"PYTHON_AST": adapter},
        _External(),
        _Workspace(),
        {"fixture-python": executable},
    )

    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    with pytest.raises(ValueError, match="STATIC_CAPABILITY_OBSERVATION_MISMATCH"):
        await coordinator.probe(profile_ref)


@pytest.mark.asyncio
async def test_probe_rejects_adapter_bound_to_a_different_executable(
    tmp_path: Path,
) -> None:
    registered = tmp_path / "registered-python"
    registered.write_bytes(b"same bounded fixture")
    adapter_executable = tmp_path / "adapter-python"
    adapter_executable.write_bytes(registered.read_bytes())
    profile = _profile(registered)
    observation = StaticCapabilityObservation(
        available=True,
        tool_name="AST",
        tool_kind="STRUCTURE",
        executable_key="fixture-python",
        observed_executable_sha256=profile.executable_sha256,
        observed_version="3.12",
        expected_version="3.12",
        reason_code=None,
    )
    adapter = _Adapter(observation, adapter_executable)
    coordinator = StaticToolCoordinator(
        _Profiles(profile),
        {"PYTHON_AST": adapter},
        _External(),
        _Workspace(),
        {"fixture-python": registered},
    )

    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    with pytest.raises(ValueError, match="STATIC_EXECUTABLE_INVALID"):
        await coordinator.probe(profile_ref)
    assert adapter.probes == 0


@pytest.mark.asyncio
async def test_probe_rejects_an_executable_from_a_prohibited_workspace(
    tmp_path: Path,
) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    executable = workspace_root / "python"
    executable.write_bytes(b"untrusted workspace executable")
    profile = _profile(executable)
    observation = StaticCapabilityObservation(
        available=True,
        tool_name="AST",
        tool_kind="STRUCTURE",
        executable_key="fixture-python",
        observed_executable_sha256=profile.executable_sha256,
        observed_version="3.12",
        expected_version="3.12",
        reason_code=None,
    )
    adapter = _Adapter(observation, executable)
    coordinator = StaticToolCoordinator(
        _Profiles(profile),
        {"PYTHON_AST": adapter},
        _External(),
        _Workspace(),
        {"fixture-python": executable},
        prohibited_workspace_roots=(workspace_root,),
    )

    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    with pytest.raises(ValueError, match="STATIC_EXECUTABLE_INVALID"):
        await coordinator.probe(profile_ref)
    assert adapter.probes == 0


def test_observation_rejects_unsafe_nested_paths_and_diagnostics(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "fixture-python"
    executable.write_bytes(b"bounded fixture")
    profile = _profile(executable)
    unsafe = CandidateLocation("../outside.py", 1, None, 1, None)
    observation = StaticToolObservation(
        tool_name="AST",
        tool_version="3.12",
        tool_kind="STRUCTURE",
        status="PARTIAL",
        raw_output=b"{}",
        raw_media_type="application/json",
        analyzed_paths=("src/app.py",),
        skipped_paths=(),
        analyzed_languages=("python",),
        skipped_languages=(),
        notes=("bounded",),
        selected_rule_packs=(),
        rules=(),
        symbols=(),
        facts=(),
        relations=(CandidateRelation("r", "CALL", None, unsafe, None, unsafe, None),),
        gaps=(
            CandidateGap(
                "STATIC_ANALYSIS",
                "STATIC_GAP",
                "MISSING",
                "authorization: secret",
                ("src/app.py",),
                (),
                (),
                False,
            ),
        ),
        errors=(),
        started_monotonic_ms=1,
        finished_monotonic_ms=2,
    )

    with pytest.raises(ValueError, match="STATIC_TOOL_OBSERVATION_INVALID"):
        StaticToolCoordinator._validate_observation(
            profile, observation, ("src/app.py",)
        )


def test_observation_paths_must_exactly_partition_requested_files(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "fixture-python"
    executable.write_bytes(b"bounded fixture")
    profile = _profile(executable)
    observation = StaticToolObservation(
        tool_name="AST",
        tool_version="3.12",
        tool_kind="STRUCTURE",
        status="SUCCEEDED",
        raw_output=b"{}",
        raw_media_type="application/json",
        analyzed_paths=("src/other.py",),
        skipped_paths=(),
        analyzed_languages=("python",),
        skipped_languages=(),
        notes=(),
        selected_rule_packs=(),
        rules=(),
        symbols=(),
        facts=(),
        relations=(),
        gaps=(),
        errors=(),
        started_monotonic_ms=1,
        finished_monotonic_ms=2,
    )

    with pytest.raises(ValueError, match="STATIC_TOOL_OBSERVATION_INVALID"):
        StaticToolCoordinator._validate_observation(
            profile, observation, ("src/app.py",)
        )

    omitted = replace(
        observation,
        analyzed_paths=(),
        skipped_paths=(),
    )
    with pytest.raises(ValueError, match="STATIC_TOOL_OBSERVATION_INVALID"):
        StaticToolCoordinator._validate_observation(profile, omitted, ("src/app.py",))


def test_usable_evidence_cannot_point_into_skipped_partition(tmp_path: Path) -> None:
    executable = tmp_path / "fixture-python"
    executable.write_bytes(b"bounded fixture")
    profile = _profile(executable)
    skipped = CandidateLocation("src/skipped.py", 1, None, 1, None)
    observation = StaticToolObservation(
        tool_name="AST",
        tool_version="3.12",
        tool_kind="STRUCTURE",
        status="PARTIAL",
        raw_output=b"{}",
        raw_media_type="application/json",
        analyzed_paths=("src/app.py",),
        skipped_paths=("src/skipped.py",),
        analyzed_languages=("python",),
        skipped_languages=("python",),
        notes=(),
        selected_rule_packs=(),
        rules=(),
        symbols=(),
        facts=(),
        relations=(CandidateRelation("r", "CALL", None, skipped, None, skipped, None),),
        gaps=(),
        errors=(),
        started_monotonic_ms=1,
        finished_monotonic_ms=2,
    )

    with pytest.raises(ValueError, match="STATIC_TOOL_OBSERVATION_INVALID"):
        StaticToolCoordinator._validate_observation(
            profile, observation, ("src/app.py", "src/skipped.py")
        )


def test_ast_cancellation_is_normalized_to_public_canonical_status() -> None:
    lower = StaticToolObservation(
        tool_name="AST",
        tool_version="3.12",
        tool_kind="STRUCTURE",
        status="SKIPPED",
        raw_output=None,
        raw_media_type=None,
        analyzed_paths=(),
        skipped_paths=("src/app.py",),
        analyzed_languages=(),
        skipped_languages=("Python",),
        notes=(),
        selected_rule_packs=(),
        rules=(),
        symbols=(),
        facts=(),
        relations=(),
        gaps=(
            CandidateGap(
                "STATIC_ANALYSIS",
                "STATIC_AST_CANCELLED",
                "FAILED",
                "File was not passed to the Python AST worker.",
                ("<python-manifest>",),
                ("Python",),
                (),
                False,
            ),
        ),
        errors=(),
        started_monotonic_ms=1,
        finished_monotonic_ms=2,
    )

    canonical = StaticToolCoordinator._canonical_cancellation(lower, ("src/app.py",))

    assert canonical.status == "SKIPPED"
    assert tuple((gap.code, gap.reason) for gap in canonical.gaps) == (
        ("STATIC_TOOL_CANCELLED", "BLOCKED"),
    )
    assert canonical.gaps[0].affected_paths == ("src/app.py",)
