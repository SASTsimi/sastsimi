"""Static-process adapter for one exact registered container CodeQL attempt."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.ports.dto import (
    CancellationResult,
    CandidateError,
    CandidateFact,
    CandidateGap,
    CandidateRelation,
    CandidateRule,
    MonotonicActionDeadline,
    StaticCapabilityObservation,
    StaticRuleMapping,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.static_analysis.codeql_adapter import (
    decode_codeql_sarif,
    digest_path,
)
from sastsimi.static_analysis.codeql_registry import (
    PublishedCodeQLDatabase,
    read_codeql_database_manifest,
)
from sastsimi.static_analysis.container_codeql import ContainerCodeQLSpec
from sastsimi.static_analysis.container_codeql_runtime import (
    CodeQLArtifactIdentity,
    CodeQLContainerRunResult,
    CodeQLContainerRunStatus,
    ContainerCodeQLDockerPort,
    run_container_codeql,
)


@dataclass(frozen=True, slots=True)
class ContainerCodeQLAdapterInputs:
    """Already-resolved exact inputs; this adapter never provisions them."""

    database: PublishedCodeQLDatabase
    spec: ContainerCodeQLSpec
    artifact_identity: CodeQLArtifactIdentity
    analysis_config_ref: StoredDataRef
    rule_catalog_ref: StoredDataRef
    rule_catalog: tuple[StaticRuleMapping, ...]
    selected_rule_ids: tuple[str, ...]
    selected_rule_packs: tuple[str, ...]
    tracked_files: tuple[TrackedFile, ...]


class ContainerCodeQLProcessAdapter:
    """Run an approved CodeQL image without creating a database or build."""

    def __init__(
        self,
        *,
        executable: Path,
        executable_key: str,
        inputs: ContainerCodeQLAdapterInputs,
        port: ContainerCodeQLDockerPort,
        execution_receipt: (
            Callable[[CodeQLContainerRunResult, int], None] | None
        ) = None,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        monotonic_ms: Callable[[], int] = lambda: time.monotonic_ns() // 1_000_000,
    ) -> None:
        self.executable = executable
        self.executable_key = executable_key
        self.inputs = inputs
        self.port = port
        self.execution_receipt = execution_receipt
        self.monotonic_ns = monotonic_ns
        self.monotonic_ms = monotonic_ms
        self._active: dict[str, asyncio.Task[CodeQLContainerRunResult]] = {}

    def _executable_digest(self) -> str | None:
        try:
            if (
                not self.executable.is_absolute()
                or not self.executable.is_file()
                or self.executable.is_symlink()
                or self.executable.resolve(strict=True) != self.executable.absolute()
            ):
                return None
            digest = hashlib.sha256()
            with self.executable.open("rb") as stream:
                for chunk in iter(lambda: stream.read(64 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return None

    def _profile_error(self, profile: StaticToolProfile) -> str | None:
        digest = self._executable_digest()
        boundary = profile.codeql_boundary
        identity = self.inputs.database.identity
        language = "PYTHON" if identity.language == "python" else "JAVASCRIPT"
        try:
            exact_docker_executable = self.executable.resolve(
                strict=True
            ) == self.inputs.spec.docker_executable.resolve(strict=True)
        except OSError:
            exact_docker_executable = False
        if (
            profile.status != "ACTIVE"
            or profile.purpose != "PRODUCTION"
            or profile.adapter_key != "CODEQL"
            or profile.tool_name != "CODEQL"
            or profile.tool_kind != "RULE_BASED"
            or profile.executable_key != self.executable_key
            or digest is None
            or digest != profile.executable_sha256
            or not exact_docker_executable
            or boundary is None
            or boundary.database_provider_key != identity.provider_key
            or boundary.database_provider_revision != identity.provider_revision
            or str(boundary.database_provider_evidence_sha256)
            != identity.provider_evidence_sha256
            or boundary.database_limit_bytes != self.inputs.spec.database_limit_bytes
            or boundary.execution_limit_bytes != self.inputs.spec.output_limit_bytes
            or boundary.quota_backend_key != "CONTAINER_TMPFS_CAP_PLUS_ONE"
            or boundary.quota_enforcement_identity_sha256
            != content_hash(
                {
                    "image_digest": self.inputs.spec.image_digest,
                    "user": self.inputs.spec.user,
                    "pids_limit": self.inputs.spec.pids_limit,
                    "memory_limit_bytes": self.inputs.spec.memory_limit_bytes,
                    "nano_cpus": self.inputs.spec.cpu_limit_millicores * 1_000_000,
                    "database_limit_bytes": self.inputs.spec.database_limit_bytes,
                    "output_limit_bytes": self.inputs.spec.output_limit_bytes,
                }
            )
            or boundary.image_digest != self.inputs.spec.image_digest
            or boundary.expected_codeql_version != profile.expected_version
            or boundary.query_pack_sha256
            != self.inputs.artifact_identity.query_digest.removeprefix("sha256:")
            or boundary.container_user != self.inputs.spec.user
            or boundary.pids_limit != self.inputs.spec.pids_limit
            or boundary.memory_limit_bytes != self.inputs.spec.memory_limit_bytes
            or boundary.nano_cpus != self.inputs.spec.cpu_limit_millicores * 1_000_000
            or language not in boundary.supported_languages
            or boundary.prebuilt_database_only is not True
        ):
            return "CODEQL_CONTAINER_PROFILE_MISMATCH"
        return None

    def _injected_error(self) -> str | None:
        inputs = self.inputs
        database = inputs.database
        identity = database.identity
        spec = inputs.spec
        artifact = inputs.artifact_identity
        mapping_ids = tuple(item.rule_id for item in inputs.rule_catalog)
        tracked_paths = tuple(item.git_path for item in inputs.tracked_files)
        try:
            manifest = read_codeql_database_manifest(database.artifact_root)
            valid = (
                database.artifact_key == identity.artifact_key
                and database.manifest_path
                == database.artifact_root / "sastsimi-codeql-database.json"
                and database.database_root == spec.database_source
                and database.database_digest == manifest["database_digest"]
                and digest_path(database.database_root) == database.database_digest
                and artifact.database_digest == "sha256:" + database.database_digest
                and artifact.tracked_manifest_digest
                == "sha256:" + identity.tracked_manifest_sha256
                and artifact.query_digest
                == "sha256:" + digest_path(spec.query_pack_source)
                and spec.query_pack_source.is_dir()
                and mapping_ids
                and len(mapping_ids) == len(set(mapping_ids))
                and len(inputs.selected_rule_ids) == len(set(inputs.selected_rule_ids))
                and set(inputs.selected_rule_ids).issubset(mapping_ids)
                and inputs.selected_rule_packs
                and len(inputs.selected_rule_packs)
                == len(set(inputs.selected_rule_packs))
                and tracked_paths
                and len(tracked_paths) == len(set(tracked_paths))
            )
        except (KeyError, OSError, TypeError, ValueError):
            return "CODEQL_CONTAINER_INPUT_MISMATCH"
        return None if valid else "CODEQL_CONTAINER_INPUT_MISMATCH"

    def _request_error(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> str | None:
        profile_error = self._profile_error(profile)
        if profile_error is not None:
            return profile_error
        injected_error = self._injected_error()
        if injected_error is not None:
            return injected_error
        inputs = self.inputs
        action = request.action
        meta = action.meta
        workspace = request.workspace
        tracked_paths = tuple(item.git_path for item in inputs.tracked_files)
        expected_refs = (
            request.tool_profile_ref,
            inputs.analysis_config_ref,
            inputs.rule_catalog_ref,
            reference(workspace),
        )
        try:
            exact_workspace_root = workspace_root.resolve(strict=True)
            exact_spec_workspace = inputs.spec.workspace_root.resolve(strict=True)
        except OSError:
            return "CODEQL_CONTAINER_INPUT_MISMATCH"
        if (
            not isinstance(meta, RecordMeta)
            or request.tool_profile_ref != reference(profile)
            or request.analysis_config_ref != inputs.analysis_config_ref
            or request.rule_catalog_ref != inputs.rule_catalog_ref
            or any(action.input_refs.count(item) != 1 for item in expected_refs)
            or action.action_type != "RUN_TOOL"
            or action.tool_name != "CODEQL"
            or str(action.action_id) != inputs.spec.action_id
            or str(meta.attempt_id) != inputs.spec.attempt_id
            or deadline.action_id != inputs.spec.action_id
            or meta.analysis_id != workspace.analysis_id
            or meta.workspace_id != workspace.workspace_id
            or meta.commit_id != workspace.commit_id
            or workspace.status != "READY"
            or workspace.commit_id is None
            or workspace.repository_url != inputs.database.identity.repository_url
            or str(workspace.commit_id) != inputs.database.identity.commit_id
            or exact_workspace_root != exact_spec_workspace
            or len(action.file_paths) != len(set(action.file_paths))
            or set(action.file_paths) != set(tracked_paths)
        ):
            return "CODEQL_CONTAINER_INPUT_MISMATCH"
        return None

    def _rules_not_executed(self, reason: str) -> tuple[CandidateRule, ...]:
        selected = set(self.inputs.selected_rule_ids)
        return tuple(
            CandidateRule(
                rule_id=item.rule_id,
                selection_status=(
                    "SELECTED" if item.rule_id in selected else "NOT_SELECTED"
                ),
                execution_status="NOT_EXECUTED",
                hit_count=None,
                reason=reason if item.rule_id in selected else "NOT_SELECTED",
                detail=None,
            )
            for item in sorted(
                self.inputs.rule_catalog, key=lambda value: value.rule_id
            )
        )

    def _observation(
        self,
        profile: StaticToolProfile,
        *,
        status: Literal["SUCCEEDED", "PARTIAL", "FAILED", "SKIPPED"],
        started: int,
        raw: bytes | None = None,
        rules: tuple[CandidateRule, ...] | None = None,
        facts: tuple[CandidateFact, ...] = (),
        relations: tuple[CandidateRelation, ...] = (),
        gaps: tuple[CandidateGap, ...] = (),
        errors: tuple[CandidateError, ...] = (),
    ) -> StaticToolObservation:
        completed = status in {"SUCCEEDED", "PARTIAL"}
        tracked = tuple(sorted(item.git_path for item in self.inputs.tracked_files))
        return StaticToolObservation(
            tool_name="CODEQL",
            tool_version=profile.expected_version,
            tool_kind="RULE_BASED",
            status=status,
            raw_output=raw,
            raw_media_type="application/sarif+json" if raw is not None else None,
            analyzed_paths=tracked if completed else (),
            skipped_paths=() if completed else tracked,
            analyzed_languages=(self.inputs.database.identity.language,)
            if completed
            else (),
            skipped_languages=(),
            notes=(
                "Container analyze used an exact registered prebuilt CodeQL database.",
            ),
            selected_rule_packs=self.inputs.selected_rule_packs,
            rules=(
                rules if rules is not None else self._rules_not_executed("TOOL_FAILURE")
            ),
            symbols=(),
            facts=facts,
            relations=relations,
            gaps=gaps,
            errors=errors,
            started_monotonic_ms=started,
            finished_monotonic_ms=self.monotonic_ms(),
        )

    @staticmethod
    def _gap(code: str, reason: str, message: str, *, retryable: bool) -> CandidateGap:
        return CandidateGap(
            stage="STATIC_ANALYSIS",
            code=code,
            reason=reason,
            description=message,
            affected_paths=(),
            affected_languages=(),
            affected_locations=(),
            retryable=retryable,
        )

    @staticmethod
    def _error(code: str, message: str, *, retryable: bool) -> CandidateError:
        return CandidateError(
            stage="STATIC_ANALYSIS",
            code=code,
            safe_message=message,
            retryable=retryable,
        )

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        del deadline
        reason = self._profile_error(profile) or self._injected_error()
        digest = self._executable_digest()
        return StaticCapabilityObservation(
            available=reason is None,
            tool_name="CODEQL",
            tool_kind="RULE_BASED",
            executable_key=self.executable_key,
            observed_executable_sha256=digest,
            observed_version=profile.expected_version if reason is None else None,
            expected_version=profile.expected_version,
            reason_code=reason,
        )

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        started = self.monotonic_ms()
        mismatch = self._request_error(request, workspace_root, profile, deadline)
        if mismatch is not None:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    self._gap(
                        mismatch,
                        "FAILED",
                        "CodeQL container inputs did not match the authorized attempt.",
                        retryable=False,
                    ),
                ),
                errors=(
                    self._error(
                        mismatch,
                        "CodeQL container input integrity failed.",
                        retryable=False,
                    ),
                ),
            )
        attempt_id = self.inputs.spec.attempt_id
        if attempt_id in self._active:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    self._gap(
                        "CODEQL_CONTAINER_ATTEMPT_ACTIVE",
                        "BLOCKED",
                        "The exact CodeQL attempt is already active.",
                        retryable=True,
                    ),
                ),
                errors=(
                    self._error(
                        "CODEQL_CONTAINER_ATTEMPT_ACTIVE",
                        "The exact CodeQL attempt is already active.",
                        retryable=True,
                    ),
                ),
            )
        remaining_seconds = deadline.remaining_ms(self.monotonic_ns()) / 1000
        timeout_seconds = min(profile.run_timeout_ms / 1000, remaining_seconds)
        if timeout_seconds <= 0:
            result = CodeQLContainerRunResult(
                status=CodeQLContainerRunStatus.TIMED_OUT,
                raw_sarif=None,
                reason="CODEQL_CONTAINER_TIMEOUT",
                image_digest=self.inputs.spec.image_digest,
                database_digest=self.inputs.artifact_identity.database_digest,
                tracked_manifest_digest=(
                    self.inputs.artifact_identity.tracked_manifest_digest
                ),
                query_digest=self.inputs.artifact_identity.query_digest,
            )
        else:
            task = asyncio.create_task(
                run_container_codeql(
                    port=self.port,
                    spec=self.inputs.spec,
                    artifact_identity=self.inputs.artifact_identity,
                    timeout_seconds=timeout_seconds,
                    stdout_limit_bytes=min(
                        profile.stdout_limit_bytes,
                        profile.max_output_file_bytes,
                        profile.max_artifact_read_bytes,
                        self.inputs.spec.output_limit_bytes,
                    ),
                )
            )
            self._active[attempt_id] = task
            try:
                result = await task
            finally:
                if self._active.get(attempt_id) is task:
                    self._active.pop(attempt_id, None)
            if self.execution_receipt is not None:
                self.execution_receipt(
                    result,
                    max(0, self.monotonic_ms() - started),
                )
        if result.status is CodeQLContainerRunStatus.CANCELLED:
            return self._observation(
                profile,
                status="SKIPPED",
                started=started,
                rules=self._rules_not_executed("CANCELLED"),
                gaps=(
                    self._gap(
                        "STATIC_TOOL_CANCELLED",
                        "BLOCKED",
                        "The CodeQL container attempt was cancelled.",
                        retryable=True,
                    ),
                ),
            )
        if result.status is not CodeQLContainerRunStatus.SUCCEEDED:
            reason = result.reason or "CODEQL_CONTAINER_RUNTIME_ERROR"
            retryable = result.status is CodeQLContainerRunStatus.TIMED_OUT
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                rules=self._rules_not_executed("TOOL_FAILURE"),
                gaps=(
                    self._gap(
                        reason,
                        "TIMEOUT" if retryable else "FAILED",
                        "The CodeQL container did not produce verified SARIF.",
                        retryable=retryable,
                    ),
                ),
                errors=(
                    self._error(
                        reason,
                        "The CodeQL container did not produce verified SARIF.",
                        retryable=retryable,
                    ),
                ),
            )
        raw = result.raw_sarif
        if raw is None:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    self._gap(
                        "STATIC_OUTPUT_MALFORMED",
                        "FAILED",
                        "CodeQL did not return SARIF.",
                        retryable=False,
                    ),
                ),
                errors=(
                    self._error(
                        "STATIC_OUTPUT_MALFORMED",
                        "CodeQL did not return SARIF.",
                        retryable=False,
                    ),
                ),
            )
        try:
            rules, facts, relations, gaps = decode_codeql_sarif(
                raw,
                rule_catalog=self.inputs.rule_catalog,
                selected_rule_ids=self.inputs.selected_rule_ids,
                tracked_paths=tuple(
                    item.git_path for item in self.inputs.tracked_files
                ),
                expected_version=profile.expected_version,
            )
        except ValueError:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                raw=raw,
                gaps=(
                    self._gap(
                        "STATIC_OUTPUT_MALFORMED",
                        "FAILED",
                        "CodeQL SARIF was malformed.",
                        retryable=False,
                    ),
                ),
                errors=(
                    self._error(
                        "STATIC_OUTPUT_MALFORMED",
                        "CodeQL SARIF was malformed.",
                        retryable=False,
                    ),
                ),
            )
        return self._observation(
            profile,
            status="PARTIAL" if gaps else "SUCCEEDED",
            started=started,
            raw=raw,
            rules=rules,
            facts=facts,
            relations=relations,
            gaps=gaps,
        )

    async def cancel(self, attempt_id: str) -> CancellationResult:
        task = self._active.get(attempt_id)
        if task is None:
            return CancellationResult(False, "Attempt is not active")
        task.cancel()
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            pass
        return CancellationResult(True, None)


__all__ = ["ContainerCodeQLAdapterInputs", "ContainerCodeQLProcessAdapter"]
