"""Pure selection and validation for one exact static-tool profile."""

from __future__ import annotations

import hashlib
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

from pydantic import TypeAdapter

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    RunStoredDataRef,
    StoredDataRef,
    reference,
    validate_exact_ref,
)
from sastsimi.contracts.static import SafeDiagnostic, StaticToolProfile, git_path
from sastsimi.ports.dto import (
    CancellationResult,
    CandidateGap,
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
        registered_executable = self._verify_executable(
            executable, profile.executable_sha256
        )
        adapter_executable = self._verify_executable(
            adapter.executable, profile.executable_sha256
        )
        if registered_executable != adapter_executable:
            raise ValueError("STATIC_EXECUTABLE_INVALID")
        return profile, adapter

    def _verify_executable(
        self,
        executable: Path,
        expected_digest: str,
        *,
        additional_prohibited_roots: Sequence[Path] = (),
    ) -> Path:
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
            or any(
                _is_within(resolved, root)
                for root in (*self._prohibited_roots, *additional_prohibited_roots)
            )
            or _digest(resolved) != expected_digest
        ):
            raise ValueError("STATIC_EXECUTABLE_INVALID")
        return resolved

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
        self._validate_request_binding(request, profile)
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
            registered_executable = self._verify_executable(
                self._executables[profile.executable_key],
                profile.executable_sha256,
                additional_prohibited_roots=(root,),
            )
            adapter_executable = self._verify_executable(
                adapter.executable,
                profile.executable_sha256,
                additional_prohibited_roots=(root,),
            )
            if registered_executable != adapter_executable:
                raise ValueError("STATIC_EXECUTABLE_INVALID")
            await self._workspace.assert_unchanged(
                request.workspace,
                deadline,
                attempt_id=str(attempt_id),
                check_id="coordinator-pre-execute",
            )
            observation = await adapter.execute(request, root, profile, deadline)
            await self._workspace.assert_unchanged(
                request.workspace,
                deadline,
                attempt_id=str(attempt_id),
                check_id="coordinator-post-execute",
            )
            observation = self._canonical_cancellation(
                observation, request.action.file_paths
            )
            self._validate_observation(profile, observation, request.action.file_paths)
            return observation

        self._active[str(attempt_id)] = adapter
        try:
            return await self._external.invoke(request, profile, operation)
        finally:
            self._active.pop(str(attempt_id), None)

    @staticmethod
    def _validate_request_binding(
        request: StaticToolRequest, profile: StaticToolProfile
    ) -> None:
        """Close a public request over exactly the inputs its action authorized."""

        action = request.action
        action_meta = action.meta
        workspace_ref = reference(request.workspace)
        if not isinstance(workspace_ref, (RunStoredDataRef, StoredDataRef)):
            raise ValueError("STATIC_TOOL_PROFILE_BINDING_MISMATCH")
        expected_refs = {
            workspace_ref,
            request.tool_profile_ref,
            request.analysis_config_ref,
        }
        if request.rule_catalog_ref is not None:
            expected_refs.add(request.rule_catalog_ref)
        if (
            not isinstance(action_meta, RecordMeta)
            or action_meta.analysis_id != request.workspace.analysis_id
            or action_meta.workspace_id != request.workspace.workspace_id
            or action_meta.commit_id != request.workspace.commit_id
            or action.work_ref is None
            or action.requested_by != "STATIC_ANALYSIS"
            or action.action_type != "RUN_TOOL"
            or action.tool_name != profile.tool_name
            or not action.file_paths
            or len(action.file_paths) != len(set(action.file_paths))
            or len(action.input_refs) != len(expected_refs)
            or set(action.input_refs) != expected_refs
            or (profile.tool_kind == "RULE_BASED")
            != (request.rule_catalog_ref is not None)
        ):
            raise ValueError("STATIC_TOOL_PROFILE_BINDING_MISMATCH")

    async def cancel(self, attempt_id: str) -> CancellationResult:
        adapter = self._active.get(attempt_id)
        if adapter is None:
            return CancellationResult(False, "STATIC_TOOL_ATTEMPT_NOT_ACTIVE")
        return await adapter.cancel(attempt_id)

    @staticmethod
    def _canonical_cancellation(
        observation: StaticToolObservation,
        requested_paths: tuple[str, ...],
    ) -> StaticToolObservation:
        if observation.status != "SKIPPED" or not any(
            gap.code == "STATIC_AST_CANCELLED" for gap in observation.gaps
        ):
            return observation
        return StaticToolObservation(
            tool_name=observation.tool_name,
            tool_version=observation.tool_version,
            tool_kind=observation.tool_kind,
            status="SKIPPED",
            raw_output=None,
            raw_media_type=None,
            analyzed_paths=(),
            skipped_paths=requested_paths,
            analyzed_languages=(),
            skipped_languages=observation.skipped_languages,
            notes=("The static tool attempt was cancelled by the caller.",),
            selected_rule_packs=observation.selected_rule_packs,
            rules=observation.rules,
            symbols=(),
            facts=(),
            relations=(),
            gaps=(
                CandidateGap(
                    "STATIC_ANALYSIS",
                    "STATIC_TOOL_CANCELLED",
                    "BLOCKED",
                    "The static tool attempt was cancelled by the caller.",
                    requested_paths,
                    (),
                    (),
                    True,
                ),
            ),
            errors=(),
            started_monotonic_ms=observation.started_monotonic_ms,
            finished_monotonic_ms=observation.finished_monotonic_ms,
        )

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
        profile: StaticToolProfile,
        observation: StaticToolObservation,
        requested_paths: tuple[str, ...],
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
        if (
            len(requested_paths) != len(set(requested_paths))
            or len(observation.analyzed_paths) != len(set(observation.analyzed_paths))
            or len(observation.skipped_paths) != len(set(observation.skipped_paths))
            or set(observation.analyzed_paths).intersection(observation.skipped_paths)
            or set(observation.analyzed_paths).union(observation.skipped_paths)
            != set(requested_paths)
        ):
            raise ValueError("STATIC_TOOL_OBSERVATION_INVALID")
        for path in (*observation.analyzed_paths, *observation.skipped_paths):
            try:
                git_path(path)
            except ValueError as error:
                raise ValueError("STATIC_TOOL_OBSERVATION_INVALID") from error
        evidence_locations = (
            tuple(item.location for item in observation.symbols)
            + tuple(item.location for item in observation.facts)
            + tuple(
                location
                for item in observation.relations
                for location in (item.from_location, item.to_location)
            )
        )
        gap_locations = tuple(
            location
            for item in observation.gaps
            for location in item.affected_locations
        )
        try:
            for location in evidence_locations:
                git_path(location.file_path)
                if location.file_path not in observation.analyzed_paths:
                    raise ValueError
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
            for location in gap_locations:
                git_path(location.file_path)
                if location.file_path not in requested_paths:
                    raise ValueError
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
                    if path not in requested_paths:
                        raise ValueError
            diagnostics = (
                *observation.notes,
                *(gap.description for gap in observation.gaps),
                *(error.safe_message for error in observation.errors),
                *(rule.detail for rule in observation.rules if rule.detail is not None),
            )
            validator = TypeAdapter(SafeDiagnostic)
            for diagnostic in diagnostics:
                validator.validate_python(diagnostic, strict=True)
        except ValueError as error:
            raise ValueError("STATIC_TOOL_OBSERVATION_INVALID") from error
