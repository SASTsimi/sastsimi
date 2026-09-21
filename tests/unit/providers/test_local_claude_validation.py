from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.composition.local_claude_binding import LocalClaudeBindingRecords
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import OpaqueId
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import StagedArtifact
from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.providers.claude_subscription import (
    ApprovedClaudeExecutable,
    ApprovedClaudeExecutionBinding,
)
from sastsimi.providers.local_claude_validation import (
    LocalClaudeValidationError,
    LocalEvaluationClaudeProcessRunner,
    validate_local_claude_binding,
)
from sastsimi.providers.local_evaluation_claude import (
    build_local_evaluation_claude_call_service,
)
from tests.contract.domain.canonical_fixtures import make

_MODEL = "claude-haiku-4-5-20251001"
_CLIENT_VERSION = "2.1.197"


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"local-claude-validation-{kind.__name__.lower()}-{self.value}")


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

    def monotonic_ms(self) -> int:
        return 0


class _Artifacts:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        assert media_type == "application/json"
        return StagedArtifact(data=data, media_type=media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        digest = hashlib.sha256(staged.data).hexdigest()
        self.values[digest] = staged.data
        return StoredDataRef.model_validate(
            {
                "stored_data_id": digest,
                "data_kind": "artifact",
                "content_hash": digest,
                "workspace_id": "ws1",
                "commit_id": "c1",
                "record_id": None,
            }
        )

    def open_verified(self, ref: StoredDataRef) -> object:
        raise AssertionError(ref)


class _ProbeRunner:
    def __init__(
        self,
        *,
        sessions: tuple[str, str] = ("session-a", "session-b"),
        timeout_status: str = "TIMED_OUT",
        auth_status: str = "AUTH_REQUIRED",
    ) -> None:
        self.sessions = iter(sessions)
        self.timeout_status = timeout_status
        self.auth_status = auth_status
        self.requests: list[CodexProcessRequest] = []

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        self.requests.append(request)
        if request.invocation_id == "local-claude-timeout-probe":
            return CodexProcessResult(self.timeout_status, None, None)  # type: ignore[arg-type]
        if request.invocation_id == "local-claude-auth-probe":
            return CodexProcessResult(self.auth_status, None, None)  # type: ignore[arg-type]
        return CodexProcessResult(
            "SUCCEEDED",
            canonical_bytes({"status": "ok"}),
            next(self.sessions),
        )


def _ref(kind: str, digest: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": f"{kind}-stored",
            "data_kind": kind,
            "content_hash": digest * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
            "record_id": f"{kind}-record",
        }
    )


def _records() -> LocalClaudeBindingRecords:
    validation_ref = _ref("provider_validation_evidence", "a")
    validation = ProviderValidationEvidence.model_validate_json(
        canonical_bytes(
            make("ProviderValidationEvidence")
            | {
                "meta": make("ProviderValidationEvidence")["meta"]
                | {"record_id": validation_ref.record_id},
                "provider": "ANTHROPIC",
                "product": "CLAUDE_CODE",
                "transport": "CLAUDE_CODE_CLIENT",
                "model": _MODEL,
                "auth_mode": "SUBSCRIPTION_LOGIN",
                "client_name": "claude-code",
                "client_version": _CLIENT_VERSION,
                "tests": (),
                "checked_by": "LOCAL_EVALUATION_OPERATOR",
            }
        )
    )
    resolved_validation_ref = reference(validation)
    assert isinstance(resolved_validation_ref, StoredDataRef)
    validation_ref = resolved_validation_ref
    client = ClientExecutionProfile.model_validate_json(
        canonical_bytes(
            make("ClientExecutionProfile")
            | {
                "environment_variable_allowlist": (
                    "CLAUDE_CONFIG_DIR",
                    "SYSTEMROOT",
                    "WINDIR",
                    "COMSPEC",
                    "TEMP",
                    "TMP",
                ),
                "verification_evidence_ref": validation_ref.model_dump(mode="json"),
            }
        )
    )
    client_ref = reference(client)
    assert isinstance(client_ref, StoredDataRef)
    profile = ProviderProfile.model_validate_json(
        canonical_bytes(
            make("ProviderProfile")
            | {
                "provider": "ANTHROPIC",
                "product": "CLAUDE_CODE",
                "transport": "CLAUDE_CODE_CLIENT",
                "model": _MODEL,
                "auth_mode": "SUBSCRIPTION_LOGIN",
                "credential_source": "OFFICIAL_CLIENT_SESSION",
                "client_name": "claude-code",
                "client_version": _CLIENT_VERSION,
                "support_status": "EXPERIMENTAL",
                "validation_evidence_ref": validation_ref.model_dump(mode="json"),
                "client_execution_profile_ref": client_ref.model_dump(mode="json"),
                "limitations": (
                    "LOCAL_EVALUATION_ONLY",
                    "PRODUCTION_APPROVAL_NOT_GRANTED",
                ),
                # Mirror what build_local_claude_binding actually issues.
                "capabilities": make("ProviderCapabilities")
                | {
                    "resume_session": "UNSUPPORTED",
                    "request_id": "UNSUPPORTED",
                    "runtime_tool_loop": "UNSUPPORTED",
                },
            }
        )
    )
    executable_path = Path(__file__).resolve()
    binding = ApprovedClaudeExecutionBinding(
        provider_profile=profile,
        client_execution_profile=client,
        executable=ApprovedClaudeExecutable(
            path=executable_path,
            sha256=hashlib.sha256(executable_path.read_bytes()).hexdigest(),
        ),
        claude_config_dir=executable_path.parent,
        runtime_environment="PERSONAL_LOCAL",
    )
    return LocalClaudeBindingRecords(validation, client, profile, binding)


@pytest.mark.asyncio
async def test_bounded_local_probes_create_only_local_supported_revision() -> None:
    records = _records()
    artifacts = _Artifacts()

    result = await validate_local_claude_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )

    assert result.provider.support_status == "SUPPORTED"
    assert (
        result.provider.meta.logical_record_id
        == records.provider.meta.logical_record_id
    )
    assert result.provider.meta.previous_record_id == records.provider.meta.record_id
    assert result.provider.meta.revision_number == 2
    assert result.binding.provider_profile == result.provider
    assert result.binding.local_evidence_ref == result.evidence_ref
    assert "LOCAL_VALIDATION_NOT_PRODUCTION_PVD" in result.provider.limitations
    assert "PRODUCTION_APPROVAL_NOT_GRANTED" in result.provider.limitations
    assert result.provider.capabilities.parallel_calls == "SUPPORTED"
    assert result.provider.capabilities.resume_session == "UNSUPPORTED"
    assert result.provider.capabilities.runtime_tool_loop == "UNSUPPORTED"
    assert not hasattr(result, "evaluation_recommendation")
    assert not hasattr(result, "production_approval")

    evidence = json.loads(artifacts.values[result.evidence_ref.content_hash])
    assert evidence["purpose"] == "LOCAL_EVALUATION"
    assert evidence["evidence_kind"] == "local_claude_live_probe"
    assert evidence["production_pvd"] is False
    assert evidence["production_approval"] is False
    # The receipt keeps only hashed session identifiers.
    assert "session-a" not in json.dumps(evidence)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("runner_kwargs", "reason"),
    [
        ({"sessions": ("same", "same")}, "LOCAL_CLAUDE_NEW_SESSION_PROBE_FAILED"),
        ({"timeout_status": "SUCCEEDED"}, "LOCAL_CLAUDE_TIMEOUT_PROBE_FAILED"),
        ({"timeout_status": "FAILED"}, "LOCAL_CLAUDE_TIMEOUT_PROBE_FAILED"),
    ],
)
async def test_local_validation_fails_closed_without_supported_profile(
    runner_kwargs: dict[str, Any], reason: str
) -> None:
    with pytest.raises(LocalClaudeValidationError, match=reason):
        await validate_local_claude_binding(
            records=_records(),
            artifacts=_Artifacts(),  # type: ignore[arg-type]
            ids=_Ids(),
            clock=_Clock(),
            live_runner=_ProbeRunner(**runner_kwargs),
            unauthenticated_runner=_ProbeRunner(),
            probe_timeout_ms=500,
        )


@pytest.mark.asyncio
async def test_an_authenticated_empty_credential_probe_must_fail_closed() -> None:
    # If an empty credential directory still answers, an ambient credential
    # reached the child and the route must not be promoted.
    with pytest.raises(
        LocalClaudeValidationError, match="LOCAL_CLAUDE_AUTH_PROBE_FAILED"
    ):
        await validate_local_claude_binding(
            records=_records(),
            artifacts=_Artifacts(),  # type: ignore[arg-type]
            ids=_Ids(),
            clock=_Clock(),
            live_runner=_ProbeRunner(),
            unauthenticated_runner=_ProbeRunner(auth_status="SUCCEEDED"),
            probe_timeout_ms=500,
        )


@pytest.mark.asyncio
async def test_local_runner_maps_supported_revision_to_probed_binding() -> None:
    records = _records()
    validated = await validate_local_claude_binding(
        records=records,
        artifacts=_Artifacts(),  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    inner = _ProbeRunner()
    runner = LocalEvaluationClaudeProcessRunner(
        binding=validated.binding, inner=cast(Any, inner)
    )
    supported_ref = reference(validated.provider)
    assert isinstance(supported_ref, StoredDataRef)

    await runner.execute(
        CodexProcessRequest(
            invocation_id="call-1",
            provider_profile_ref=supported_ref,
            model=_MODEL,
            prompt=b"prompt",
            output_schema=b'{"type":"object"}',
            timeout_ms=1000,
        )
    )

    # The child always runs against the exact experimental revision that was
    # pinned and probed, never the promoted one.
    assert inner.requests[0].provider_profile_ref == reference(records.provider)


@pytest.mark.asyncio
async def test_local_runner_rejects_wrong_profile_before_spawn() -> None:
    records = _records()
    validated = await validate_local_claude_binding(
        records=records,
        artifacts=_Artifacts(),  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    inner = _ProbeRunner()
    runner = LocalEvaluationClaudeProcessRunner(
        binding=validated.binding, inner=cast(Any, inner)
    )
    experimental_ref = reference(records.provider)
    assert isinstance(experimental_ref, StoredDataRef)

    with pytest.raises(LocalClaudeValidationError, match="LOCAL_CLAUDE_ROUTE_MISMATCH"):
        await runner.execute(
            CodexProcessRequest(
                invocation_id="call-1",
                provider_profile_ref=experimental_ref,
                model=_MODEL,
                prompt=b"prompt",
                output_schema=b'{"type":"object"}',
                timeout_ms=1000,
            )
        )

    assert inner.requests == []


@pytest.mark.asyncio
async def test_call_service_uses_local_validated_runner_for_supported_profile() -> None:
    validated = await validate_local_claude_binding(
        records=_records(),
        artifacts=_Artifacts(),  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )

    service = build_local_evaluation_claude_call_service(
        binding=validated.binding,
        prompt_resolver=cast(Any, None),
        session_store=cast(Any, None),
        output_schema_validator=cast(Any, None),
        result_builder=cast(Any, None),
        clock=cast(Any, None),
    )

    assert isinstance(
        service.adapter.process_runner, LocalEvaluationClaudeProcessRunner
    )
    assert service.provider_profile_ref == reference(validated.provider)
