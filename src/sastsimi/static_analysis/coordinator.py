"""Pure selection and validation for one exact static-tool profile."""

from __future__ import annotations

import hashlib
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

from pydantic import TypeAdapter

from sastsimi.contracts._domain import SafeDiagnostic
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, validate_exact_ref
from sastsimi.contracts.static import StaticToolProfile, git_path
from sastsimi.ports.dto import (
    CancellationResult,
    MonotonicActionDeadline,
    StaticCapabilityObservation,
    StaticToolObservation,
    StaticToolRequest,
    ToolCapabilityResult,
    ToolRunResult,
)
from sastsimi.ports.static_tool import (
    StaticExternalExecutionPort,
    StaticProcessAdapter,
    StaticToolProfileResolverPort,
)
from sastsimi.ports.workspace import WorkspaceLocatorPort


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


class StaticToolCoordinator:
    """Expose the public adapter while keeping runtime/storage authority outside."""

    def __init__(
        self,
        profile_resolver: StaticToolProfileResolverPort,
        adapters: Mapping[str, StaticProcessAdapter],
        external_execution: StaticExternalExecutionPort,
        workspace_locator: WorkspaceLocatorPort,
        executables: Mapping[str, Path],
        *,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        prohibited_workspace_roots: Sequence[Path] = (),
    ) -> None:
        if len(adapters) != len(set(adapters)) or len(executables) != len(
            set(executables)
        ):
            raise ValueError("STATIC_TOOL_REGISTRY_INVALID")
        self._profiles = profile_resolver
        self._adapters = MappingProxyType(dict(adapters))
        self._external = external_execution
        self._workspace = workspace_locator
        self._executables = MappingProxyType(dict(executables))
        self._monotonic_ns = monotonic_ns
        self._prohibited_roots = tuple(
            root.resolve() for root in prohibited_workspace_roots
        )
        self._active: dict[str, StaticProcessAdapter] = {}

    def _resolve(
        self, profile_ref: StoredDataRef
    ) -> tuple[StaticToolProfile, StaticProcessAdapter]:
        try:
            profile = self._profiles.resolve(profile_ref)
            validate_exact_ref(
                profile_ref,
                profile.meta,
                content_hash(profile),
                analysis_id=profile.meta.analysis_id,
            )
        except (KeyError, ValueError) as error:
            raise ValueError("STATIC_TOOL_PROFILE_INVALID") from error
        if profile.status != "APPROVED" or profile.purpose not in {
            "FIXTURE",
            "EVALUATION",
        }:
            raise ValueError("STATIC_TOOL_PROFILE_INVALID")
        try:
            adapter = self._adapters[profile.adapter_key]
            executable = self._executables[profile.executable_key]
        except KeyError as error:
            raise ValueError("STATIC_TOOL_PROFILE_INVALID") from error
        self._verify_executable(executable, profile.executable_sha256)
        return profile, adapter

    def _verify_executable(self, executable: Path, expected_digest: str) -> None:
        try:
            before = executable.lstat()
            resolved = executable.resolve(strict=True)
            after = resolved.stat()
        except OSError as error:
            raise ValueError("STATIC_EXECUTABLE_INVALID") from error
        attributes = getattr(before, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(before.st_mode)
            or executable.is_symlink()
            or attributes & 0x400
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or any(_is_within(resolved, root) for root in self._prohibited_roots)
            or _digest(resolved) != expected_digest
        ):
            raise ValueError("STATIC_EXECUTABLE_INVALID")

    async def probe(self, profile_ref: StoredDataRef) -> ToolCapabilityResult:
        profile, adapter = self._resolve(profile_ref)
        started = int(self._monotonic_ns())
        deadline = MonotonicActionDeadline(
            action_id=f"probe-{profile.meta.record_id}",
            started_ns=started,
            expires_ns=started + profile.probe_timeout_ms * 1_000_000,
        )
        try:
            observation = await adapter.probe(profile, deadline)
        except TimeoutError:
            await adapter.cancel(deadline.action_id)
            observation = StaticCapabilityObservation(
                available=False,
                tool_name=profile.tool_name,
                tool_kind=profile.tool_kind,
                executable_key=profile.executable_key,
                observed_executable_sha256=None,
                observed_version=None,
                expected_version=profile.expected_version,
                reason_code="STATIC_PROBE_TIMEOUT",
            )
        self._validate_capability(profile, observation)
        return ToolCapabilityResult(ref=profile_ref, **observation.__dict__)

    async def run(self, request: StaticToolRequest) -> ToolRunResult:
        profile, adapter = self._resolve(request.tool_profile_ref)
        if request.action.tool_name != profile.tool_name:
            raise ValueError("STATIC_TOOL_PROFILE_BINDING_MISMATCH")
        if not isinstance(request.action.meta, RecordMeta):
            raise ValueError("STATIC_TOOL_ATTEMPT_INVALID")
        action_meta = request.action.meta
        attempt_id = action_meta.attempt_id
        if attempt_id is None or str(attempt_id) in self._active:
            raise ValueError("STATIC_TOOL_ATTEMPT_INVALID")

        async def operation(
            deadline: MonotonicActionDeadline,
        ) -> StaticToolObservation:
            if (
                request.workspace.status != "READY"
                or request.workspace.commit_id is None
                or request.workspace.analysis_id != action_meta.analysis_id
                or request.workspace.workspace_id != action_meta.workspace_id
                or request.workspace.commit_id != action_meta.commit_id
            ):
                raise ValueError("WORKSPACE_NOT_READY")
            root = self._workspace.root_for(request.workspace)
            if not root.is_dir():
                raise ValueError("WORKSPACE_NOT_READY")
            await self._workspace.assert_unchanged(request.workspace, deadline)
            observation = await adapter.execute(request, root, profile, deadline)
            await self._workspace.assert_unchanged(request.workspace, deadline)
            self._validate_observation(profile, observation)
            return observation

        self._active[str(attempt_id)] = adapter
        try:
            return await self._external.invoke(request, profile, operation)
        finally:
            self._active.pop(str(attempt_id), None)

    async def cancel(self, attempt_id: str) -> CancellationResult:
        adapter = self._active.get(attempt_id)
        if adapter is None:
            return CancellationResult(False, "STATIC_TOOL_ATTEMPT_NOT_ACTIVE")
        return await adapter.cancel(attempt_id)

    @staticmethod
    def _validate_capability(
        profile: StaticToolProfile, observation: StaticCapabilityObservation
    ) -> None:
        if (
            observation.tool_name != profile.tool_name
            or observation.tool_kind != profile.tool_kind
            or observation.executable_key != profile.executable_key
            or observation.expected_version != profile.expected_version
            or (
                observation.observed_executable_sha256 is not None
                and observation.observed_executable_sha256 != profile.executable_sha256
            )
            or (
                observation.observed_version is not None
                and observation.observed_version != profile.expected_version
            )
            or (
                observation.available
                and (
                    observation.observed_executable_sha256 != profile.executable_sha256
                    or observation.observed_version != profile.expected_version
                    or observation.reason_code is not None
                )
            )
        ):
            raise ValueError("STATIC_CAPABILITY_OBSERVATION_MISMATCH")

    @staticmethod
    def _validate_observation(
        profile: StaticToolProfile, observation: StaticToolObservation
    ) -> None:
        if (
            (observation.tool_name, observation.tool_version, observation.tool_kind)
            != (profile.tool_name, profile.expected_version, profile.tool_kind)
            or observation.finished_monotonic_ms < observation.started_monotonic_ms
            or (
                observation.raw_output is not None
                and len(observation.raw_output) > profile.max_attempt_output_bytes
            )
            or (observation.raw_output is None) != (observation.raw_media_type is None)
        ):
            raise ValueError("STATIC_TOOL_OBSERVATION_INVALID")
        for path in (*observation.analyzed_paths, *observation.skipped_paths):
            try:
                git_path(path)
            except ValueError as error:
                raise ValueError("STATIC_TOOL_OBSERVATION_INVALID") from error
        locations = (
            tuple(item.location for item in observation.symbols)
            + tuple(item.location for item in observation.facts)
            + tuple(
                location
                for item in observation.relations
                for location in (item.from_location, item.to_location)
            )
            + tuple(
                location
                for item in observation.gaps
                for location in item.affected_locations
            )
        )
        try:
            for location in locations:
                git_path(location.file_path)
                if (
                    location.start_line <= 0
                    or location.end_line < location.start_line
                    or (location.start_column is None) != (location.end_column is None)
                    or (
                        location.start_line == location.end_line
                        and location.start_column is not None
                        and location.end_column is not None
                        and location.end_column <= location.start_column
                    )
                ):
                    raise ValueError
            for gap in observation.gaps:
                for path in gap.affected_paths:
                    git_path(path)
            diagnostics = (
                *observation.notes,
                *(gap.description for gap in observation.gaps),
                *(error.safe_message for error in observation.errors),
            )
            validator = TypeAdapter(SafeDiagnostic)
            for diagnostic in diagnostics:
                validator.validate_python(diagnostic, strict=True)
        except ValueError as error:
            raise ValueError("STATIC_TOOL_OBSERVATION_INVALID") from error
