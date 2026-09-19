from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.composition.local_codex_binding import LocalCodexBindingRecords
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
from sastsimi.providers.codex_subscription import (
    ApprovedCodexExecutable,
    ApprovedCodexExecutionBinding,
)
from sastsimi.providers.local_codex_validation import (
    LocalCodexValidationError,
    LocalEvaluationCodexProcessRunner,
    validate_local_codex_binding,
)
from sastsimi.providers.local_evaluation_codex import (
    build_local_evaluation_codex_call_service,
)
from tests.contract.domain.canonical_fixtures import make


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"local-validation-{kind.__name__.lower()}-{self.value}")


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 20, 12, 0, tzinfo=UTC)

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
        self.active = 0
        self.peak = 0

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        self.requests.append(request)
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            if request.invocation_id == "local-codex-timeout-probe":
                return CodexProcessResult(self.timeout_status, None, None)  # type: ignore[arg-type]
            if request.invocation_id == "local-codex-auth-probe":
                return CodexProcessResult(self.auth_status, None, None)  # type: ignore[arg-type]
            await _yield_once()
            return CodexProcessResult(
                "SUCCEEDED",
                canonical_bytes({"status": "ok"}),
                next(self.sessions),
            )
        finally:
            self.active -= 1


async def _yield_once() -> None:
    import asyncio

    await asyncio.sleep(0)


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


def _records() -> LocalCodexBindingRecords:
    validation_ref = _ref("provider_validation_evidence", "a")
    validation = ProviderValidationEvidence.model_validate_json(
        canonical_bytes(
            make("ProviderValidationEvidence")
            | {
                "meta": make("ProviderValidationEvidence")["meta"]
                | {"record_id": validation_ref.record_id},
                "provider": "OPENAI",
                "product": "CODEX",
                "transport": "CODEX_CLIENT",
                "model": "gpt-5.6-sol",
                "auth_mode": "SUBSCRIPTION_LOGIN",
                "client_name": "codex-cli",
                "client_version": "0.152.1",
                "tests": (),
                "checked_by": "LOCAL_EVALUATION_OPERATOR",
            }
        )
    )
    # Use the record-derived exact reference rather than the helper's digest.
    resolved_validation_ref = reference(validation)
    assert isinstance(resolved_validation_ref, StoredDataRef)
    validation_ref = resolved_validation_ref
    client = ClientExecutionProfile.model_validate_json(
        canonical_bytes(
            make("ClientExecutionProfile")
            | {
                "environment_variable_allowlist": (
                    "CODEX_HOME",
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
                "provider": "OPENAI",
                "product": "CODEX",
                "transport": "CODEX_CLIENT",
                "model": "gpt-5.6-sol",
                "auth_mode": "SUBSCRIPTION_LOGIN",
                "credential_source": "OFFICIAL_CLIENT_SESSION",
                "client_name": "codex-cli",
                "client_version": "0.152.1",
                "support_status": "EXPERIMENTAL",
                "validation_evidence_ref": validation_ref.model_dump(mode="json"),
                "client_execution_profile_ref": client_ref.model_dump(mode="json"),
                "limitations": (
                    "LOCAL_EVALUATION_ONLY",
                    "PRODUCTION_APPROVAL_NOT_GRANTED",
                ),
            }
        )
    )
    executable_path = Path(__file__).resolve()
    binding = ApprovedCodexExecutionBinding(
        provider_profile=profile,
        client_execution_profile=client,
        executable=ApprovedCodexExecutable(
            path=executable_path,
            sha256=hashlib.sha256(executable_path.read_bytes()).hexdigest(),
        ),
        codex_home=executable_path.parent,
        runtime_environment="PERSONAL_LOCAL",
    )
    return LocalCodexBindingRecords(validation, client, profile, binding)


@pytest.mark.asyncio
async def test_bounded_local_probes_create_only_local_supported_revision() -> None:
    records = _records()
    artifacts = _Artifacts()
    live = _ProbeRunner()
    unauthenticated = _ProbeRunner()

    result = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=live,
        unauthenticated_runner=unauthenticated,
        probe_timeout_ms=500,
    )

    assert result.provider.support_status == "SUPPORTED"
    assert (
        result.provider.meta.logical_record_id
        == records.provider.meta.logical_record_id
    )
    assert result.provider.meta.previous_record_id == records.provider.meta.record_id
    assert result.provider.meta.revision_number == 2
    assert result.provider.validation_evidence_ref == reference(records.validation)
    assert result.binding.provider_profile == result.provider
    assert result.binding.local_evidence_ref == result.evidence_ref
    assert "LOCAL_VALIDATION_NOT_PRODUCTION_PVD" in result.provider.limitations
    assert "PRODUCTION_APPROVAL_NOT_GRANTED" in result.provider.limitations
    assert not hasattr(result, "evaluation_recommendation")
    assert not hasattr(result, "production_approval")
    assert live.peak == 2

    evidence = json.loads(artifacts.values[result.evidence_ref.content_hash])
    assert evidence["purpose"] == "LOCAL_EVALUATION"
    assert evidence["production_pvd"] is False
    assert evidence["production_approval"] is False
    assert evidence["checks"] == {
        "auth_failure_classification": "PASS",
        "bounded_timeout_classification": "PASS",
        "distinct_new_sessions": "PASS",
        "non_interactive_structured_output": "PASS",
        "parallel_new_sessions": "PASS",
    }
    evidence_text = artifacts.values[result.evidence_ref.content_hash].decode()
    assert "session-a" not in evidence_text
    assert "session-b" not in evidence_text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("live", "unauthenticated", "reason"),
    [
        (
            _ProbeRunner(sessions=("same", "same")),
            _ProbeRunner(),
            "LOCAL_CODEX_NEW_SESSION_PROBE_FAILED",
        ),
        (
            _ProbeRunner(timeout_status="FAILED"),
            _ProbeRunner(),
            "LOCAL_CODEX_TIMEOUT_PROBE_FAILED",
        ),
        (
            _ProbeRunner(),
            _ProbeRunner(auth_status="FAILED"),
            "LOCAL_CODEX_AUTH_PROBE_FAILED",
        ),
    ],
)
async def test_local_validation_fails_closed_without_supported_profile(
    live: _ProbeRunner,
    unauthenticated: _ProbeRunner,
    reason: str,
) -> None:
    artifacts = _Artifacts()

    with pytest.raises(LocalCodexValidationError, match=reason):
        await validate_local_codex_binding(
            records=_records(),
            artifacts=artifacts,  # type: ignore[arg-type]
            ids=_Ids(),
            clock=_Clock(),
            live_runner=live,
            unauthenticated_runner=unauthenticated,
            probe_timeout_ms=500,
        )

    assert artifacts.values == {}


@pytest.mark.asyncio
async def test_local_runner_maps_supported_revision_to_probed_binding() -> None:
    records = _records()
    artifacts = _Artifacts()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    inner = _ProbeRunner()
    runner = LocalEvaluationCodexProcessRunner(binding=validated.binding, inner=inner)
    supported_ref = reference(validated.provider)
    experimental_ref = reference(records.provider)
    assert isinstance(supported_ref, StoredDataRef)
    assert isinstance(experimental_ref, StoredDataRef)
    request = CodexProcessRequest(
        invocation_id="runtime-call",
        provider_profile_ref=supported_ref,
        model=validated.provider.model,
        prompt=b"return status",
        output_schema=canonical_bytes(
            {
                "type": "object",
                "properties": {"status": {"type": "string"}},
                "required": ["status"],
                "additionalProperties": False,
            }
        ),
        timeout_ms=500,
    )

    result = await runner.execute(request)

    assert result.status == "SUCCEEDED"
    assert inner.requests[0].provider_profile_ref == experimental_ref
    assert inner.requests[0].invocation_id == request.invocation_id


@pytest.mark.asyncio
async def test_local_runner_rejects_wrong_profile_before_spawn() -> None:
    records = _records()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=_Artifacts(),  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    inner = _ProbeRunner()
    runner = LocalEvaluationCodexProcessRunner(binding=validated.binding, inner=inner)
    request = CodexProcessRequest(
        invocation_id="runtime-call",
        provider_profile_ref=_ref("provider_profile", "f"),
        model=validated.provider.model,
        prompt=b"return status",
        output_schema=b"{}",
        timeout_ms=500,
    )

    with pytest.raises(LocalCodexValidationError, match="LOCAL_CODEX_ROUTE_MISMATCH"):
        await runner.execute(request)

    assert inner.requests == []


@pytest.mark.asyncio
async def test_call_service_uses_local_validated_runner_for_supported_profile() -> None:
    records = _records()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=_Artifacts(),  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )

    service = build_local_evaluation_codex_call_service(
        binding=validated.binding,
        prompt_resolver=cast(Any, object()),
        session_store=cast(Any, object()),
        output_schema_validator=cast(Any, object()),
        result_builder=cast(Any, object()),
        clock=cast(Any, object()),
    )

    assert service.binding is validated.binding
    assert isinstance(service.adapter.process_runner, LocalEvaluationCodexProcessRunner)
    assert service.adapter.provider_profile_ref == reference(validated.provider)
