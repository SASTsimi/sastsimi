"""Bounded live validation for the official Claude Code LOCAL_EVALUATION route.

This module intentionally does not participate in Production PVD, recommendation,
or approval.  It proves only the small capability subset used by the explicit local
evaluation command and keeps the resulting supported profile paired with the exact
experimental executable binding that was probed.
"""

from __future__ import annotations

import asyncio
import hashlib
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import RecordId
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    Environment,
    InvocationStatus,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.records import RecordMeta, validate_revision
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator

from .base import CodexProcessRequest, CodexProcessResult, CodexProcessRunner
from .claude_subscription import (
    ApprovedClaudeExecutable,
    ApprovedClaudeExecutionBinding,
    ClaudeCliProcessRunner,
)

_PROBE_OUTPUT = canonical_bytes({"status": "ok"})
_PROBE_SCHEMA = canonical_bytes(
    {
        "type": "object",
        "properties": {"status": {"type": "string", "const": "ok"}},
        "required": ["status"],
        "additionalProperties": False,
    }
)
_IDENTITY_FIELDS = (
    "profile_key",
    "provider",
    "product",
    "transport",
    "model",
    "environment",
    "auth_mode",
    "client_name",
    "client_version",
    "credential_source",
    "validation_evidence_ref",
    "client_execution_profile_ref",
)


class LocalClaudeValidationError(RuntimeError):
    """A safe local-only reason why Claude Code cannot be enabled for this run."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _ProbeRunner(Protocol):
    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult: ...


class LocalClaudeBindingSource(Protocol):
    @property
    def validation(self) -> ProviderValidationEvidence: ...
    @property
    def client(self) -> ClientExecutionProfile: ...
    @property
    def provider(self) -> ProviderProfile: ...
    @property
    def binding(self) -> ApprovedClaudeExecutionBinding: ...


@dataclass(frozen=True, slots=True)
class LocalValidatedClaudeExecutionBinding:
    """Local support proof paired with the exact experimental process binding."""

    experimental_binding: ApprovedClaudeExecutionBinding
    provider_profile: ProviderProfile
    local_evidence_ref: StoredDataRef

    def __post_init__(self) -> None:
        experimental = self.experimental_binding.provider_profile
        try:
            validate_revision(experimental.meta, self.provider_profile.meta)
        except ValueError as error:
            raise LocalClaudeValidationError(
                "LOCAL_CLAUDE_SUPPORTED_REVISION_INVALID"
            ) from error
        if (
            experimental.support_status != "EXPERIMENTAL"
            or self.provider_profile.support_status != "SUPPORTED"
            or any(
                getattr(experimental, field) != getattr(self.provider_profile, field)
                for field in _IDENTITY_FIELDS
            )
            or self.local_evidence_ref.data_kind != "artifact"
            or self.local_evidence_ref.record_id is not None
            or self.local_evidence_ref.workspace_id
            != self.provider_profile.meta.workspace_id
            or self.local_evidence_ref.commit_id != self.provider_profile.meta.commit_id
            or "LOCAL_EVALUATION_ONLY" not in self.provider_profile.limitations
            or "LOCAL_VALIDATION_NOT_PRODUCTION_PVD"
            not in self.provider_profile.limitations
            or "PRODUCTION_APPROVAL_NOT_GRANTED"
            not in self.provider_profile.limitations
            or self.experimental_binding.provider_validation_evidence is not None
        ):
            raise LocalClaudeValidationError("LOCAL_CLAUDE_SUPPORTED_BINDING_INVALID")

    @property
    def client_execution_profile(self) -> ClientExecutionProfile:
        return self.experimental_binding.client_execution_profile

    @property
    def executable(self) -> ApprovedClaudeExecutable:
        return self.experimental_binding.executable

    @property
    def claude_config_dir(self) -> Path:
        return self.experimental_binding.claude_config_dir

    @property
    def runtime_environment(self) -> Environment:
        return self.experimental_binding.runtime_environment


@dataclass(frozen=True, slots=True)
class LocalClaudeValidationResult:
    """Locally supported revision and its exact secret-free probe receipt."""

    provider: ProviderProfile
    evidence_ref: StoredDataRef
    binding: LocalValidatedClaudeExecutionBinding


class LocalEvaluationClaudeProcessRunner:
    """Run a supported local profile through the exact binding that was probed."""

    def __init__(
        self,
        *,
        binding: LocalValidatedClaudeExecutionBinding,
        inner: CodexProcessRunner | None = None,
    ) -> None:
        self.binding = binding
        self._inner = inner or ClaudeCliProcessRunner(
            binding=binding.experimental_binding
        )
        supported_ref = reference(binding.provider_profile)
        experimental_ref = reference(binding.experimental_binding.provider_profile)
        if not isinstance(supported_ref, StoredDataRef) or not isinstance(
            experimental_ref, StoredDataRef
        ):
            raise LocalClaudeValidationError("LOCAL_CLAUDE_ROUTE_MISMATCH")
        self._supported_ref = supported_ref
        self._experimental_ref = experimental_ref

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        if (
            request.provider_profile_ref != self._supported_ref
            or request.model != self.binding.provider_profile.model
        ):
            raise LocalClaudeValidationError("LOCAL_CLAUDE_ROUTE_MISMATCH")
        exact_request = replace(
            request,
            provider_profile_ref=self._experimental_ref,
        )
        return await self._inner.execute(exact_request)


async def validate_local_claude_binding(
    *,
    records: LocalClaudeBindingSource,
    artifacts: ArtifactStore,
    ids: IdGenerator,
    clock: Clock,
    probe_timeout_ms: int,
    live_runner: _ProbeRunner | None = None,
    unauthenticated_runner: _ProbeRunner | None = None,
) -> LocalClaudeValidationResult:
    """Promote one exact local route only after bounded live checks pass."""
    if (
        isinstance(probe_timeout_ms, bool)
        or not 100 <= probe_timeout_ms <= 120_000
        or records.provider.support_status != "EXPERIMENTAL"
        or records.binding.provider_profile != records.provider
        or records.binding.client_execution_profile != records.client
        or records.binding.provider_validation_evidence is not None
        or records.validation.checked_by != "LOCAL_EVALUATION_OPERATOR"
        or records.validation.tests
        or records.provider.validation_evidence_ref != reference(records.validation)
    ):
        raise LocalClaudeValidationError("LOCAL_CLAUDE_VALIDATION_INPUT_INVALID")

    runner = live_runner or ClaudeCliProcessRunner(binding=records.binding)
    if unauthenticated_runner is None:
        with tempfile.TemporaryDirectory(prefix="sastsimi-claude-auth-probe-") as root:
            # An empty credential directory must classify as AUTH_REQUIRED rather
            # than fall back to any ambient credential.
            isolated_binding = ApprovedClaudeExecutionBinding(
                provider_profile=records.provider,
                client_execution_profile=records.client,
                executable=records.binding.executable,
                claude_config_dir=Path(root).resolve(),
                runtime_environment=records.binding.runtime_environment,
                provider_validation_evidence=None,
            )
            auth_runner = ClaudeCliProcessRunner(binding=isolated_binding)
            return await _validate_with_runners(
                records=records,
                artifacts=artifacts,
                ids=ids,
                clock=clock,
                live_runner=runner,
                unauthenticated_runner=auth_runner,
                probe_timeout_ms=probe_timeout_ms,
            )
    return await _validate_with_runners(
        records=records,
        artifacts=artifacts,
        ids=ids,
        clock=clock,
        live_runner=runner,
        unauthenticated_runner=unauthenticated_runner,
        probe_timeout_ms=probe_timeout_ms,
    )


async def _validate_with_runners(
    *,
    records: LocalClaudeBindingSource,
    artifacts: ArtifactStore,
    ids: IdGenerator,
    clock: Clock,
    live_runner: _ProbeRunner,
    unauthenticated_runner: _ProbeRunner,
    probe_timeout_ms: int,
) -> LocalClaudeValidationResult:
    provider_ref = reference(records.provider)
    if not isinstance(provider_ref, StoredDataRef):
        raise LocalClaudeValidationError("LOCAL_CLAUDE_VALIDATION_INPUT_INVALID")

    def request(invocation_id: str, timeout_ms: int) -> CodexProcessRequest:
        return CodexProcessRequest(
            invocation_id=invocation_id,
            provider_profile_ref=provider_ref,
            model=records.provider.model,
            prompt=b'Return exactly {"status":"ok"}.',
            output_schema=_PROBE_SCHEMA,
            timeout_ms=timeout_ms,
        )

    try:
        async with asyncio.timeout((probe_timeout_ms * 4) / 1_000):
            first, second = await asyncio.gather(
                live_runner.execute(
                    request("local-claude-new-session-a", probe_timeout_ms)
                ),
                live_runner.execute(
                    request("local-claude-new-session-b", probe_timeout_ms)
                ),
            )
            timeout = await live_runner.execute(
                request("local-claude-timeout-probe", 1)
            )
            authentication = await unauthenticated_runner.execute(
                request("local-claude-auth-probe", probe_timeout_ms)
            )
    except TimeoutError:
        raise LocalClaudeValidationError(
            "LOCAL_CLAUDE_PROBE_DEADLINE_EXCEEDED"
        ) from None
    except asyncio.CancelledError:
        raise
    except Exception as error:
        if isinstance(error, LocalClaudeValidationError):
            raise
        raise LocalClaudeValidationError(
            "LOCAL_CLAUDE_PROBE_EXECUTION_FAILED"
        ) from None

    if not _valid_success(first) or not _valid_success(second):
        raise LocalClaudeValidationError("LOCAL_CLAUDE_STRUCTURED_PROBE_FAILED")
    if first.provider_session_id == second.provider_session_id:
        raise LocalClaudeValidationError("LOCAL_CLAUDE_NEW_SESSION_PROBE_FAILED")
    if not _failure_is(timeout, "TIMED_OUT"):
        raise LocalClaudeValidationError("LOCAL_CLAUDE_TIMEOUT_PROBE_FAILED")
    if not _failure_is(authentication, "AUTH_REQUIRED"):
        raise LocalClaudeValidationError("LOCAL_CLAUDE_AUTH_PROBE_FAILED")

    checked_at = clock.now()
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise LocalClaudeValidationError("LOCAL_CLAUDE_VALIDATION_CLOCK_INVALID")
    evidence_ref = artifacts.commit(
        artifacts.stage_bytes(
            canonical_bytes(
                {
                    "schema_version": 1,
                    "purpose": "LOCAL_EVALUATION",
                    "evidence_kind": "local_claude_live_probe",
                    "experimental_provider_profile_ref": provider_ref.model_dump(
                        mode="json"
                    ),
                    "provider_profile_logical_record_id": str(
                        records.provider.meta.logical_record_id
                    ),
                    "supported_revision_number": records.provider.meta.revision_number
                    + 1,
                    "executable_sha256": records.binding.executable.sha256,
                    "model": records.provider.model,
                    "checked_at": checked_at.isoformat(),
                    "checks": {
                        "non_interactive_structured_output": "PASS",
                        "distinct_new_sessions": "PASS",
                        "parallel_new_sessions": "PASS",
                        "bounded_timeout_classification": "PASS",
                        "auth_failure_classification": "PASS",
                    },
                    "session_hashes": sorted(
                        (
                            _digest_session(first.provider_session_id),
                            _digest_session(second.provider_session_id),
                        )
                    ),
                    "production_pvd": False,
                    "production_approval": False,
                }
            ),
            "application/json",
        )
    )
    next_meta = RecordMeta.model_validate(
        records.provider.meta.model_copy(
            update={
                "record_id": ids.new(RecordId),
                "revision_number": records.provider.meta.revision_number + 1,
                "previous_record_id": records.provider.meta.record_id,
                "created_at": checked_at,
            }
        )
    )
    capabilities = records.provider.capabilities.model_copy(
        update={
            "non_interactive": "SUPPORTED",
            "structured_output": "SUPPORTED",
            "new_session": "SUPPORTED",
            "parallel_calls": "SUPPORTED",
            "timeout_detection": "SUPPORTED",
            "auth_expiry_detection": "SUPPORTED",
            "session_metadata": "SUPPORTED",
        }
    )
    limitations = tuple(
        dict.fromkeys(
            (
                *records.provider.limitations,
                "LOCAL_EVALUATION_ONLY",
                "LOCAL_VALIDATION_NOT_PRODUCTION_PVD",
                "PRODUCTION_APPROVAL_NOT_GRANTED",
                "RESUME_SESSION_UNSUPPORTED",
            )
        )
    )
    supported = ProviderProfile.model_validate(
        records.provider.model_copy(
            update={
                "meta": next_meta,
                "capabilities": capabilities,
                "support_status": "SUPPORTED",
                "limitations": limitations,
                "checked_at": checked_at,
            }
        )
    )
    binding = LocalValidatedClaudeExecutionBinding(
        experimental_binding=records.binding,
        provider_profile=supported,
        local_evidence_ref=evidence_ref,
    )
    return LocalClaudeValidationResult(
        provider=supported,
        evidence_ref=evidence_ref,
        binding=binding,
    )


def _valid_success(result: CodexProcessResult) -> bool:
    return (
        result.status == "SUCCEEDED"
        and result.final_message == _PROBE_OUTPUT
        and bool(result.provider_session_id)
    )


def _failure_is(result: CodexProcessResult, status: InvocationStatus) -> bool:
    return (
        result.status == status
        and result.final_message is None
        and result.provider_session_id is None
    )


def _digest_session(session_id: str | None) -> str:
    if not session_id:
        raise LocalClaudeValidationError("LOCAL_CLAUDE_NEW_SESSION_PROBE_FAILED")
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


__all__ = [
    "LocalClaudeBindingSource",
    "LocalClaudeValidationError",
    "LocalClaudeValidationResult",
    "LocalEvaluationClaudeProcessRunner",
    "LocalValidatedClaudeExecutionBinding",
    "validate_local_claude_binding",
]
