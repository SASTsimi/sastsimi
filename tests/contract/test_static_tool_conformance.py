from __future__ import annotations

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
    def __init__(self, observation: StaticCapabilityObservation) -> None:
        self.observation = observation
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
        self, workspace: CodeWorkspace, deadline: MonotonicActionDeadline
    ) -> None:
        del workspace, deadline
        raise AssertionError("probe must not touch a workspace")


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
    adapter = _Adapter(observation)
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
        )
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
