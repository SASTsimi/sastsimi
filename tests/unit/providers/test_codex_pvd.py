"""Truthful official-Codex subscription PVD evidence generation."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

import sastsimi.providers.codex_pvd as codex_pvd_module
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, LogicalRecordId, RecordId, WorkspaceId
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.providers.codex_pvd import (
    CodexAuthenticationPreflightCheck,
    CodexClientIsolationCheck,
    CodexEnvironmentBindingCheck,
    CodexErrorClassificationCheck,
    CodexFailoverLifecycleCheck,
    CodexModelSelectionCheck,
    CodexNewSessionIsolationCheck,
    CodexObservationSurfaceCheck,
    CodexParallelNewSessionCheck,
    CodexPVDCheckObservation,
    CodexPVDTestId,
    CodexRedactionBoundaryCheck,
    CodexRepairLifecycleCheck,
    CodexResumeCapabilityCheck,
    CodexRuntimeCallTrace,
    CodexStructuredOutputCheck,
    CodexSubscriptionPVDProbeRunner,
    CodexTermsApproval,
    CodexTimeoutCancellationCheck,
    CodexUnprovenRuntimeCheck,
)
from sastsimi.providers.codex_subscription import (
    CodexCliProcessRunner,
    CodexSubscriptionAdapter,
)
from sastsimi.runtime.system_support import SystemClock
from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.contract.domain.canonical_fixtures import make

_COMMIT_ID = "b" * 40
_CHECKED_AT = datetime(2026, 9, 19, 8, 0, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return _CHECKED_AT

    def monotonic_ms(self) -> int:
        return 0


def _artifact_ref(digest: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": digest,
            "data_kind": "artifact",
            "content_hash": digest,
            "workspace_id": "workspace-1",
            "commit_id": _COMMIT_ID,
            "record_id": None,
        }
    )


def _candidate() -> ProviderValidationEvidence:
    recycled = _artifact_ref("d" * 64)
    return ProviderValidationEvidence.model_validate(
        {
            "meta": {
                "record_id": "codex-pvd-evidence",
                "logical_record_id": "codex-pvd-evidence",
                "record_type": "provider_validation_evidence",
                "schema_version": "1.0.0",
                "revision_number": 1,
                "previous_record_id": None,
                "created_at": datetime(2026, 9, 19, 7, 0, tzinfo=UTC),
                "analysis_id": "analysis-1",
                "workspace_id": "workspace-1",
                "commit_id": _COMMIT_ID,
                "hypothesis_id": None,
                "attempt_id": None,
            },
            "profile_key": "codex-subscription-primary",
            "provider": "OPENAI",
            "product": "CODEX",
            "transport": "CODEX_CLIENT",
            "model": "gpt-5.6-sol",
            "environment": "PERSONAL_LOCAL",
            "auth_mode": "SUBSCRIPTION_LOGIN",
            "client_name": "codex-cli",
            "client_version": "0.152.1",
            "tests": tuple(
                {
                    "test_id": f"PVD-{index:02d}",
                    "result": "PASS",
                    "evidence_refs": (recycled,),
                    "safe_summary": "unexecuted caller assertion",
                }
                for index in range(1, 16)
            ),
            "checked_at": datetime(2026, 9, 19, 7, 0, tzinfo=UTC),
            "checked_by": "capability-operator",
        }
    )


def _exact_binding() -> object:
    profile = type(
        "Profile",
        (),
        {
            "auth_mode": "SUBSCRIPTION_LOGIN",
            "client_name": "codex-cli",
            "client_version": "0.152.1",
            "environment": "PERSONAL_LOCAL",
            "model": "gpt-5.6-sol",
            "product": "CODEX",
            "profile_key": "codex-subscription-primary",
            "provider": "OPENAI",
            "transport": "CODEX_CLIENT",
        },
    )()
    client = type(
        "ClientProfile",
        (),
        {
            "working_directory_mode": "ISOLATED_EMPTY",
            "filesystem_mode": "NO_REPOSITORY_ACCESS",
            "tool_mode": "DISABLED",
            "mcp_mode": "DISABLED",
            "hooks_mode": "DISABLED",
            "plugin_mode": "DISABLED",
            "instruction_sources": "EXPLICIT_SASTSIMI_PAYLOAD_ONLY",
            "provider_fallback": "DISABLED",
        },
    )()
    return type(
        "Binding",
        (),
        {
            "provider_profile": profile,
            "client_execution_profile": client,
            "runtime_environment": "PERSONAL_LOCAL",
        },
    )()


@dataclass
class RecordingCheck:
    test_id: CodexPVDTestId
    seen: list[CodexPVDTestId]
    evidence: dict[str, object]

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        self.seen.append(self.test_id)
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=f"{self.test_id} executed for exact Codex candidate",
            evidence=canonical_bytes(self.evidence),
        )


def _terms_approval() -> CodexTermsApproval:
    return CodexTermsApproval(
        approved_by="human-security-owner",
        approved_at=_CHECKED_AT,
        valid_until=_CHECKED_AT + timedelta(days=30),
        official_terms_url="https://openai.com/policies/terms-of-use/",
        intended_use="User-initiated internal source-code security analysis",
        account_scope="The approving user's own ChatGPT subscription",
    )


@pytest.mark.asyncio
async def test_probe_replaces_prefilled_results_and_requires_explicit_terms_approval(
    tmp_path: Path,
) -> None:
    executable_digest = "a" * 64
    checks = tuple(
        CodexUnprovenRuntimeCheck(
            test_id=cast(CodexPVDTestId, f"PVD-{index:02d}"),
            reason_code="CODEX_RUNTIME_EVIDENCE_REQUIRED",
            safe_summary="Exact runtime evidence was not supplied",
        )
        for index in range(1, 15)
    )
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts", WorkspaceId("workspace-1"), CommitId(_COMMIT_ID)
    )
    runner = CodexSubscriptionPVDProbeRunner(
        checks=checks,
        artifacts=cast(ArtifactStore, artifacts),
        clock=FixedClock(),
        per_check_timeout_ms=100,
        executable_sha256=executable_digest,
        terms_approval=_terms_approval(),
    )

    result = await runner.run(_candidate(), object())

    assert result.evidence.checked_at == _CHECKED_AT
    by_id = {test.test_id: test for test in result.evidence.tests}
    assert all(
        by_id[cast(CodexPVDTestId, f"PVD-{index:02d}")].result == "FAIL"
        for index in range(1, 15)
    )
    assert by_id["PVD-15"].result == "PASS"
    assert all(
        test.evidence_refs != (_artifact_ref("d" * 64),)
        for test in result.evidence.tests
    )
    with artifacts.open_verified(by_id["PVD-15"].evidence_refs[0]) as stream:
        receipt = json.loads(stream.read())
    assert receipt["observation"]["approved_by"] == "human-security-owner"
    assert receipt["observation"]["intended_use"] == (
        "User-initiated internal source-code security analysis"
    )


@pytest.mark.asyncio
async def test_probe_rejects_a_substitute_check_for_a_concrete_test_id(
    tmp_path: Path,
) -> None:
    seen: list[CodexPVDTestId] = []
    runner = CodexSubscriptionPVDProbeRunner(
        checks=(RecordingCheck("PVD-01", seen, {"forged": True}),),
        artifacts=cast(
            ArtifactStore,
            LocalArtifactStore(
                tmp_path / "artifacts",
                WorkspaceId("workspace-1"),
                CommitId(_COMMIT_ID),
            ),
        ),
        clock=FixedClock(),
        per_check_timeout_ms=100,
        executable_sha256="a" * 64,
        terms_approval=None,
    )

    result = await runner.run(_candidate(), object())

    by_id = {test.test_id: test for test in result.evidence.tests}
    assert by_id["PVD-01"].result == "FAIL"
    assert seen == []


@pytest.mark.asyncio
async def test_subscription_pvd_checks_run_serially(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    active = [0]
    peak = [0]

    async def execute(
        check: CodexUnprovenRuntimeCheck,
        candidate: ProviderValidationEvidence,
        adapter: object,
    ) -> CodexPVDCheckObservation:
        del candidate, adapter
        active[0] += 1
        peak[0] = max(peak[0], active[0])
        await asyncio.sleep(0)
        active[0] -= 1
        return CodexPVDCheckObservation(
            test_id=check.test_id,
            result="FAIL",
            safe_summary="Exact runtime evidence was not supplied",
            evidence=canonical_bytes({"reason_code": "CODEX_RUNTIME_UNPROVEN"}),
        )

    monkeypatch.setattr(CodexUnprovenRuntimeCheck, "execute", execute)
    checks = tuple(
        CodexUnprovenRuntimeCheck(
            test_id=cast(CodexPVDTestId, f"PVD-{index:02d}"),
            reason_code="CODEX_RUNTIME_UNPROVEN",
            safe_summary="Exact runtime evidence was not supplied",
        )
        for index in range(1, 15)
    )
    runner = CodexSubscriptionPVDProbeRunner(
        checks=checks,
        artifacts=cast(
            ArtifactStore,
            LocalArtifactStore(
                tmp_path / "artifacts",
                WorkspaceId("workspace-1"),
                CommitId(_COMMIT_ID),
            ),
        ),
        clock=FixedClock(),
        per_check_timeout_ms=100,
        executable_sha256="a" * 64,
        terms_approval=None,
    )

    await runner.run(_candidate(), object())

    assert peak == [1]


@pytest.mark.asyncio
async def test_probe_runs_optional_dynamic_tool_loop_check_when_configured(
    tmp_path: Path,
) -> None:
    seen: list[CodexPVDTestId] = []
    checks = tuple(
        RecordingCheck(
            cast(CodexPVDTestId, f"PVD-{index:02d}"),
            seen,
            {"executed": True},
        )
        for index in range(1, 15)
    ) + (RecordingCheck("PVD-16", seen, {"runtime_tool_loop": "SUPPORTED"}),)
    runner = CodexSubscriptionPVDProbeRunner(
        checks=checks,
        artifacts=cast(
            ArtifactStore,
            LocalArtifactStore(
                tmp_path / "artifacts",
                WorkspaceId("workspace-1"),
                CommitId(_COMMIT_ID),
            ),
        ),
        clock=FixedClock(),
        per_check_timeout_ms=100,
        executable_sha256="a" * 64,
        terms_approval=None,
    )

    result = await runner.run(_candidate(), object())

    by_id = {test.test_id: test for test in result.evidence.tests}
    assert by_id["PVD-16"].result == "PASS"
    assert "PVD-16" in seen


@pytest.mark.asyncio
async def test_probe_never_auto_passes_terms_or_model_binding(tmp_path: Path) -> None:
    seen: list[CodexPVDTestId] = []
    checks = tuple(
        RecordingCheck(
            cast(CodexPVDTestId, f"PVD-{index:02d}"),
            seen,
            (
                {
                    "executable_sha256": "a" * 64,
                    "explicit_model_argument": "gpt-5.6-sol",
                    "invalid_model_rejected": True,
                    "provider_model_reported": False,
                    "strict_structured_output_succeeded": True,
                    "limitation": (
                        "Official Codex JSON event stream does not report model "
                        "identity; exact client binding used."
                    ),
                }
                if index == 2
                else {"executed": True}
            ),
        )
        for index in range(1, 15)
    )
    runner = CodexSubscriptionPVDProbeRunner(
        checks=checks,
        artifacts=cast(
            ArtifactStore,
            LocalArtifactStore(
                tmp_path / "artifacts",
                WorkspaceId("workspace-1"),
                CommitId(_COMMIT_ID),
            ),
        ),
        clock=SystemClock(),
        per_check_timeout_ms=100,
        executable_sha256="a" * 64,
        terms_approval=None,
    )

    result = await runner.run(_candidate(), object())

    by_id = {test.test_id: test for test in result.evidence.tests}
    assert by_id["PVD-02"].result == "FAIL"
    assert by_id["PVD-02"].safe_summary == (
        "Codex PVD evidence did not use the trusted concrete check"
    )
    assert by_id["PVD-15"].result == "FAIL"
    assert by_id["PVD-15"].safe_summary == (
        "Current Codex subscription terms approval is missing or expired"
    )
    assert "unexecuted caller assertion" not in result.evidence.model_dump_json()


@pytest.mark.asyncio
async def test_probe_fails_closed_when_any_required_check_is_missing(
    tmp_path: Path,
) -> None:
    runner = CodexSubscriptionPVDProbeRunner(
        checks=(),
        artifacts=cast(
            ArtifactStore,
            LocalArtifactStore(
                tmp_path / "artifacts",
                WorkspaceId("workspace-1"),
                CommitId(_COMMIT_ID),
            ),
        ),
        clock=SystemClock(),
        per_check_timeout_ms=100,
        executable_sha256="a" * 64,
        terms_approval=_terms_approval(),
    )

    result = await runner.run(_candidate(), object())

    by_id = {test.test_id: test for test in result.evidence.tests}
    assert all(
        by_id[cast(CodexPVDTestId, f"PVD-{index:02d}")].result == "FAIL"
        for index in range(1, 15)
    )
    assert by_id["PVD-15"].result == "PASS"


@pytest.mark.asyncio
async def test_probe_rejects_expired_human_terms_approval(tmp_path: Path) -> None:
    approval = CodexTermsApproval(
        approved_by="human-security-owner",
        approved_at=_CHECKED_AT - timedelta(days=2),
        valid_until=_CHECKED_AT - timedelta(days=1),
        official_terms_url="https://openai.com/policies/terms-of-use/",
        intended_use="User-initiated internal source-code security analysis",
        account_scope="The approving user's own ChatGPT subscription",
    )
    runner = CodexSubscriptionPVDProbeRunner(
        checks=(),
        artifacts=cast(
            ArtifactStore,
            LocalArtifactStore(
                tmp_path / "artifacts",
                WorkspaceId("workspace-1"),
                CommitId(_COMMIT_ID),
            ),
        ),
        clock=FixedClock(),
        per_check_timeout_ms=100,
        executable_sha256="a" * 64,
        terms_approval=approval,
    )

    result = await runner.run(_candidate(), object())

    by_id = {test.test_id: test for test in result.evidence.tests}
    assert by_id["PVD-15"].result == "FAIL"
    assert by_id["PVD-15"].safe_summary == (
        "Current Codex subscription terms approval is missing or expired"
    )


@pytest.mark.asyncio
async def test_adapter_accepts_model_binding_only_from_the_trusted_codex_runner(
    tmp_path: Path,
) -> None:
    seen: list[CodexPVDTestId] = []
    executable = tmp_path / "codex"
    executable.write_bytes(b"official-codex-fixture")
    executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    provider_ref = StoredDataRef.model_validate(
        {
            "stored_data_id": "provider-profile",
            "data_kind": "provider_profile",
            "content_hash": "c" * 64,
            "workspace_id": "workspace-1",
            "commit_id": _COMMIT_ID,
            "record_id": "provider-profile-record",
        }
    )
    valid_request = CodexProcessRequest(
        invocation_id="pvd-model-valid",
        provider_profile_ref=provider_ref,
        model="gpt-5.6-sol",
        prompt=b'Return {"status":"ok"}.',
        output_schema=canonical_bytes(
            {
                "additionalProperties": False,
                "properties": {"status": {"const": "ok", "type": "string"}},
                "required": ["status"],
                "type": "object",
            }
        ),
        timeout_ms=1000,
    )
    process_runner = object.__new__(CodexCliProcessRunner)
    process_runner.executable = cast(
        Any, type("Executable", (), {"path": executable, "sha256": executable_digest})()
    )
    process_runner.binding = cast(Any, _exact_binding())

    async def execute(request: CodexProcessRequest) -> CodexProcessResult:
        if request.model != "gpt-5.6-sol":
            return CodexProcessResult("FAILED", None, None)
        return CodexProcessResult("SUCCEEDED", b'{"status":"ok"}', "session-1")

    def execution_argv(
        request: CodexProcessRequest,
        work_directory: Path,
        schema_path: Path,
        output_path: Path,
    ) -> tuple[str, ...]:
        del work_directory, schema_path, output_path
        return (str(executable), "exec", "--model", request.model, "--json", "-")

    process_runner.execute = execute  # type: ignore[method-assign]
    process_runner.execution_argv = execution_argv  # type: ignore[method-assign]
    checks: tuple[codex_pvd_module.CodexPVDCheck, ...] = tuple(
        CodexModelSelectionCheck(valid_request=valid_request)
        if index == 2
        else RecordingCheck(
            cast(CodexPVDTestId, f"PVD-{index:02d}"), seen, {"executed": True}
        )
        for index in range(1, 15)
    )
    runner = CodexSubscriptionPVDProbeRunner(
        checks=checks,
        artifacts=cast(
            ArtifactStore,
            LocalArtifactStore(
                tmp_path / "artifacts",
                WorkspaceId("workspace-1"),
                CommitId(_COMMIT_ID),
            ),
        ),
        clock=FixedClock(),
        per_check_timeout_ms=100,
        executable_sha256=executable_digest,
        terms_approval=_terms_approval(),
    )
    provider = CodexSubscriptionAdapter(
        provider_profile_ref=provider_ref,
        model="gpt-5.6-sol",
        prompt_resolver=cast(Any, object()),
        process_runner=process_runner,
        session_store=cast(Any, object()),
        output_schema_validator=cast(Any, object()),
        result_builder=cast(Any, object()),
        clock=FixedClock(),
        probe_runner=runner,
    )

    result = await provider.probe(_candidate())

    assert {test.test_id: test.result for test in result.evidence.tests}[
        "PVD-02"
    ] == "PASS"


@pytest.mark.asyncio
async def test_model_check_derives_binding_evidence_from_exact_codex_runner(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"official-codex-fixture")
    executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    provider_ref = StoredDataRef.model_validate(
        {
            "stored_data_id": "provider-profile",
            "data_kind": "provider_profile",
            "content_hash": "c" * 64,
            "workspace_id": "workspace-1",
            "commit_id": _COMMIT_ID,
            "record_id": "provider-profile-record",
        }
    )
    valid_request = CodexProcessRequest(
        invocation_id="pvd-model-valid",
        provider_profile_ref=provider_ref,
        model="gpt-5.6-sol",
        prompt=b'Return {"status":"ok"}.',
        output_schema=canonical_bytes(
            {
                "additionalProperties": False,
                "properties": {"status": {"const": "ok", "type": "string"}},
                "required": ["status"],
                "type": "object",
            }
        ),
        timeout_ms=1000,
    )
    runner = object.__new__(CodexCliProcessRunner)
    runner.executable = cast(
        Any, type("Executable", (), {"path": executable, "sha256": executable_digest})()
    )
    runner.binding = cast(Any, _exact_binding())
    runner.codex_home = tmp_path / "codex-home"
    seen: list[CodexProcessRequest] = []

    async def execute(request: CodexProcessRequest) -> CodexProcessResult:
        seen.append(request)
        if request.model != "gpt-5.6-sol":
            return CodexProcessResult("FAILED", None, None)
        return CodexProcessResult("SUCCEEDED", b'{"status":"ok"}', "session-1")

    runner.execute = execute  # type: ignore[method-assign]
    adapter = cast(Any, type("Adapter", (), {})())
    adapter.model = "gpt-5.6-sol"
    adapter.provider_profile_ref = provider_ref
    adapter.process_runner = runner
    check = CodexModelSelectionCheck(valid_request=valid_request)

    observation = await check.execute(_candidate(), adapter)

    assert observation.result == "PASS"
    payload = json.loads(observation.evidence)
    assert payload == {
        "executable_sha256": executable_digest,
        "explicit_model_argument": "gpt-5.6-sol",
        "invalid_model_rejected": True,
        "limitation": (
            "Official Codex JSON event stream does not report model identity; "
            "the exact executable and explicit model argument are bound instead."
        ),
        "output_schema_sha256": hashlib.sha256(valid_request.output_schema).hexdigest(),
        "provider_model_reported": False,
        "strict_structured_output_succeeded": True,
    }
    assert [item.model for item in seen] == [
        "gpt-5.6-sol",
        "sastsimi-invalid-model-control",
    ]

    mismatched = await check.execute(
        _candidate().model_copy(update={"environment": "TEAM_LOCAL"}), adapter
    )
    assert mismatched.result == "FAIL"
    assert json.loads(mismatched.evidence)["reason_code"] == (
        "CODEX_MODEL_CHECK_BINDING_INVALID"
    )


def _process_runner_for_pvd(
    tmp_path: Path,
    results: dict[str, CodexProcessResult],
) -> tuple[CodexCliProcessRunner, object, list[CodexProcessRequest]]:
    executable = tmp_path / "codex"
    executable.write_bytes(b"official-codex-fixture")
    executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    runner = object.__new__(CodexCliProcessRunner)
    runner.executable = cast(
        Any, type("Executable", (), {"path": executable, "sha256": executable_digest})()
    )
    runner.binding = cast(Any, _exact_binding())
    runner.codex_home = tmp_path / "codex-home"
    seen: list[CodexProcessRequest] = []

    async def execute(request: CodexProcessRequest) -> CodexProcessResult:
        seen.append(request)
        return results[request.invocation_id]

    runner.execute = execute  # type: ignore[method-assign]
    adapter = cast(Any, type("Adapter", (), {})())
    adapter.model = "gpt-5.6-sol"
    adapter.provider_profile_ref = _provider_ref()
    adapter.process_runner = runner
    return runner, adapter, seen


def _provider_ref() -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": "provider-profile",
            "data_kind": "provider_profile",
            "content_hash": "c" * 64,
            "workspace_id": "workspace-1",
            "commit_id": _COMMIT_ID,
            "record_id": "provider-profile-record",
        }
    )


def _process_request(invocation_id: str, prompt: bytes) -> CodexProcessRequest:
    return CodexProcessRequest(
        invocation_id=invocation_id,
        provider_profile_ref=_provider_ref(),
        model="gpt-5.6-sol",
        prompt=prompt,
        output_schema=canonical_bytes(
            {
                "additionalProperties": False,
                "properties": {"status": {"type": "string"}},
                "required": ["status"],
                "type": "object",
            }
        ),
        timeout_ms=1_000,
    )


@pytest.mark.asyncio
async def test_authentication_check_requires_a_successful_exact_codex_call(
    tmp_path: Path,
) -> None:
    request = _process_request("pvd-auth", b"Return the authentication probe JSON.")
    _runner, adapter, seen = _process_runner_for_pvd(
        tmp_path,
        {
            "pvd-auth": CodexProcessResult(
                "SUCCEEDED", b'{"status":"authenticated"}', "session-auth"
            )
        },
    )

    passed = await CodexAuthenticationPreflightCheck(request).execute(
        _candidate(), adapter
    )

    assert passed.result == "PASS"
    assert seen == [request]
    assert json.loads(passed.evidence) == {
        "client_version": "0.152.1",
        "login_state": "AUTHENTICATED",
        "process_status": "SUCCEEDED",
        "sensitive_material_recorded": False,
    }

    _runner, adapter, _seen = _process_runner_for_pvd(
        tmp_path,
        {"pvd-auth": CodexProcessResult("AUTH_REQUIRED", None, None)},
    )
    failed = await CodexAuthenticationPreflightCheck(request).execute(
        _candidate(), adapter
    )
    assert failed.result == "FAIL"
    assert json.loads(failed.evidence)["reason_code"] == "CODEX_AUTH_REQUIRED"


@pytest.mark.asyncio
async def test_structured_output_check_requires_exact_canonical_semantic_output(
    tmp_path: Path,
) -> None:
    request = _process_request("pvd-structured", b"Return the schema fixture.")
    expected = canonical_bytes({"status": "ok"})
    _runner, adapter, _seen = _process_runner_for_pvd(
        tmp_path,
        {
            "pvd-structured": CodexProcessResult(
                "SUCCEEDED", expected, "session-structured"
            )
        },
    )

    passed = await CodexStructuredOutputCheck(request, expected).execute(
        _candidate(), adapter
    )
    assert passed.result == "PASS"
    payload = json.loads(passed.evidence)
    assert payload["parsed"] is True
    assert payload["semantic_validation_succeeded"] is True
    assert payload["output_sha256"] == hashlib.sha256(expected).hexdigest()

    _runner, adapter, _seen = _process_runner_for_pvd(
        tmp_path,
        {
            "pvd-structured": CodexProcessResult(
                "SUCCEEDED", b'{"status":"wrong"}', "session-structured"
            )
        },
    )
    failed = await CodexStructuredOutputCheck(request, expected).execute(
        _candidate(), adapter
    )
    assert failed.result == "FAIL"


@pytest.mark.asyncio
async def test_new_and_parallel_checks_require_distinct_new_sessions(
    tmp_path: Path,
) -> None:
    first = _process_request("pvd-new-a", b"probe-a-only")
    second = _process_request("pvd-new-b", b"probe-b-only")
    first_output = canonical_bytes({"status": "probe-a-only"})
    second_output = canonical_bytes({"status": "probe-b-only"})
    _runner, adapter, seen = _process_runner_for_pvd(
        tmp_path,
        {
            first.invocation_id: CodexProcessResult(
                "SUCCEEDED", first_output, "session-a"
            ),
            second.invocation_id: CodexProcessResult(
                "SUCCEEDED", second_output, "session-b"
            ),
        },
    )

    isolated = await CodexNewSessionIsolationCheck(
        first_request=first,
        second_request=second,
        first_marker=b"probe-a-only",
        second_marker=b"probe-b-only",
        first_expected_output=first_output,
        second_expected_output=second_output,
    ).execute(_candidate(), adapter)
    assert isolated.result == "PASS"

    parallel_first = _process_request("pvd-parallel-a", b"same-input")
    parallel_second = _process_request("pvd-parallel-b", b"same-input")
    parallel_output = canonical_bytes({"status": "ok"})
    _runner, adapter, _parallel_seen = _process_runner_for_pvd(
        tmp_path,
        {
            parallel_first.invocation_id: CodexProcessResult(
                "SUCCEEDED", parallel_output, "parallel-a"
            ),
            parallel_second.invocation_id: CodexProcessResult(
                "SUCCEEDED", parallel_output, "parallel-b"
            ),
        },
    )
    parallel = await CodexParallelNewSessionCheck(
        parallel_first, parallel_second, parallel_output
    ).execute(_candidate(), adapter)
    assert parallel.result == "PASS"
    assert [item.invocation_id for item in seen] == ["pvd-new-a", "pvd-new-b"]


@pytest.mark.asyncio
async def test_unproven_runtime_check_can_never_create_pass_evidence() -> None:
    check = CodexUnprovenRuntimeCheck(
        test_id="PVD-09",
        reason_code="CODEX_REPAIR_RUNTIME_EVIDENCE_REQUIRED",
        safe_summary="Repair lifecycle evidence was not supplied",
    )

    observation = await check.execute(_candidate(), object())

    assert observation.result == "FAIL"
    assert json.loads(observation.evidence) == {
        "reason_code": "CODEX_REPAIR_RUNTIME_EVIDENCE_REQUIRED"
    }


@pytest.mark.asyncio
async def test_redaction_observation_isolation_and_environment_checks(
    tmp_path: Path,
) -> None:
    request = _process_request("pvd-boundary", b"safe boundary fixture")
    output = canonical_bytes({"status": "ok"})
    runner, adapter, _seen = _process_runner_for_pvd(
        tmp_path,
        {
            request.invocation_id: CodexProcessResult(
                "SUCCEEDED", output, "opaque-provider-handle"
            )
        },
    )
    source_environment = {
        "CODEX_HOME": "ignored-untrusted-home",
        "OPENAI_API_KEY": "sk-secret-must-not-cross-boundary",
        "SASTSIMI_PVD_SECRET": "secret-canary",
        "SYSTEMROOT": "safe-system-root-token",
    }

    redaction = await CodexRedactionBoundaryCheck(
        request=request,
        expected_output=output,
        source_environment=source_environment,
    ).execute(_candidate(), adapter)
    observation = await CodexObservationSurfaceCheck(
        request=request,
        expected_output=output,
    ).execute(_candidate(), adapter)
    isolation = await CodexClientIsolationCheck(
        request=request,
        expected_output=output,
        source_environment=source_environment,
    ).execute(_candidate(), adapter)
    environment = await CodexEnvironmentBindingCheck(request).execute(
        _candidate(), adapter
    )

    assert redaction.result == "PASS"
    assert observation.result == "PASS"
    assert isolation.result == "PASS"
    assert environment.result == "PASS"
    assert "OPENAI_API_KEY" not in runner.child_environment(source_environment)
    serialized = b"".join(
        item.evidence for item in (redaction, observation, isolation, environment)
    )
    assert b"sk-secret" not in serialized
    assert b"opaque-provider-handle" not in serialized
    assert b"codex-home" not in serialized


@pytest.mark.asyncio
async def test_resume_timeout_cancel_and_error_classification_use_adapter_results() -> (
    None
):
    from tests.integration.providers.test_codex_subscription import (
        BlockingCodexProcessRunner,
        FakeCodexProcessRunner,
    )
    from tests.integration.providers.test_codex_subscription import (
        adapter as invocation_adapter,
    )
    from tests.integration.providers.test_openai_api import request

    base = request().model_copy(update={"model": "gpt-5.6-sol"})
    resume = base.model_copy(
        update={
            "llm_call_id": "pvd-resume",
            "session_policy": "RESUME",
            "parent_session_ref": "exact-parent-handle",
        }
    )
    resume_runner = FakeCodexProcessRunner(
        CodexProcessResult("SUCCEEDED", b'{"decision":"accept"}', "unexpected")
    )
    resume_adapter, _sessions = invocation_adapter(resume, resume_runner)
    resumed = await CodexResumeCapabilityCheck(resume).execute(
        _candidate(), resume_adapter
    )
    assert resumed.result == "PASS"
    assert resume_runner.requests == []

    timeout = base.model_copy(update={"llm_call_id": "pvd-timeout", "timeout_ms": 10})
    cancelled = base.model_copy(update={"llm_call_id": "pvd-cancel"})
    timing_adapter, _sessions = invocation_adapter(
        timeout, BlockingCodexProcessRunner()
    )
    cancellation_adapter, _sessions = invocation_adapter(
        cancelled, BlockingCodexProcessRunner()
    )
    timed = await CodexTimeoutCancellationCheck(
        timeout, cancelled, cancellation_adapter
    ).execute(_candidate(), timing_adapter)
    assert timed.result == "FAIL"

    auth_adapter, _sessions = invocation_adapter(
        base,
        FakeCodexProcessRunner(CodexProcessResult("AUTH_REQUIRED", None, None)),
    )
    rate_adapter, _sessions = invocation_adapter(
        base,
        FakeCodexProcessRunner(CodexProcessResult("RATE_LIMITED", None, None)),
    )
    classified = await CodexErrorClassificationCheck(
        auth_request=base.model_copy(update={"llm_call_id": "pvd-auth-failure"}),
        rate_limit_request=base.model_copy(update={"llm_call_id": "pvd-rate"}),
        rate_limit_adapter=rate_adapter,
    ).execute(_candidate(), auth_adapter)
    assert classified.result == "FAIL"


@pytest.mark.asyncio
async def test_error_classification_rejects_a_codex_runner_subclass(
    tmp_path: Path,
) -> None:
    from tests.integration.providers.test_codex_subscription import (
        adapter as invocation_adapter,
    )
    from tests.integration.providers.test_openai_api import request

    class ForgedCodexRunner(CodexCliProcessRunner):
        async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
            del self, request
            return CodexProcessResult("AUTH_REQUIRED", None, None)

    base = request().model_copy(update={"model": "gpt-5.6-sol"})
    auth_request = base.model_copy(update={"llm_call_id": "pvd-subclass-auth"})
    rate_request = base.model_copy(update={"llm_call_id": "pvd-subclass-rate"})
    seed, _adapter, _seen = _process_runner_for_pvd(
        tmp_path,
        {
            "pvd-subclass-rate": CodexProcessResult("RATE_LIMITED", None, None),
        },
    )
    forged = object.__new__(ForgedCodexRunner)
    forged.executable = seed.executable
    forged.binding = seed.binding
    forged.codex_home = seed.codex_home
    auth_adapter, _sessions = invocation_adapter(auth_request, forged)
    rate_adapter, _sessions = invocation_adapter(rate_request, seed)

    observation = await CodexErrorClassificationCheck(
        auth_request=auth_request,
        rate_limit_request=rate_request,
        rate_limit_adapter=rate_adapter,
    ).execute(_candidate(), auth_adapter)

    assert observation.result == "FAIL"


def _trace(
    *,
    call_id: str,
    attempt_id: str,
    status: str,
    action_digest: str,
    retry_of: str | None = None,
    failover_from: str | None = None,
    provider_digest: str = "a",
    model: str = "gpt-5.6-sol",
    repair_attempts: int = 0,
    provider_ref: StoredDataRef | None = None,
) -> CodexRuntimeCallTrace:
    request_data = make("LLMInvocationRequest")
    request_data["llm_call_id"] = call_id
    request_data["model"] = model
    request_data["meta"]["record_type"] = "llm_invocation_request"
    request_data["meta"]["attempt_id"] = attempt_id
    request_data["action_decision_ref"]["content_hash"] = action_digest * 64
    request_data["action_decision_ref"]["stored_data_id"] = f"action-{action_digest}"
    request_data["action_decision_ref"]["record_id"] = f"action-{action_digest}"
    if provider_ref is None:
        request_data["provider_profile_ref"]["content_hash"] = provider_digest * 64
    else:
        request_data["provider_profile_ref"] = provider_ref.model_dump(mode="json")
    request = LLMInvocationRequest.model_validate_json(canonical_bytes(request_data))

    result_data = make("LLMInvocationResult")
    result_data["llm_call_id"] = call_id
    result_data["model"] = model
    result_data["provider"] = "OPENAI"
    result_data["meta"]["record_type"] = "llm_invocation_result"
    result_data["meta"]["attempt_id"] = attempt_id
    result_data["status"] = status
    if status == "SUCCEEDED":
        response_ref = _artifact_ref("e" * 64).model_dump(mode="json")
        response_ref.update({"workspace_id": "ws1", "commit_id": "c1"})
        parsed_ref = _artifact_ref("f" * 64).model_dump(mode="json")
        parsed_ref.update({"workspace_id": "ws1", "commit_id": "c1"})
        result_data["response_ref"] = response_ref
        result_data["parsed_output_ref"] = parsed_ref
        result_data["session_ref"] = f"local-handle-{call_id}"
        result_data["safe_error"] = None
    else:
        result_data["response_ref"] = None
        result_data["parsed_output_ref"] = None
        result_data["session_ref"] = None
        result_data["safe_error"] = f"{status}: controlled PVD outcome"
    result = LLMInvocationResult.model_validate_json(canonical_bytes(result_data))

    log_data = make("LLMInvocationLog")
    log_data["llm_call_id"] = call_id
    log_data["model"] = model
    log_data["provider"] = "OPENAI"
    log_data["meta"]["record_type"] = "llm_invocation_log"
    log_data["meta"]["attempt_id"] = attempt_id
    log_data["action_decision_ref"] = request.action_decision_ref.model_dump(
        mode="json"
    )
    log_data["provider_profile_ref"] = request.provider_profile_ref.model_dump(
        mode="json"
    )
    log_data["status"] = status
    log_data["retry_of_llm_call_id"] = retry_of
    log_data["failover_from_llm_call_id"] = failover_from
    log_data["repair_attempts"] = repair_attempts
    if status == "SUCCEEDED":
        assert result.response_ref is not None
        assert result.parsed_output_ref is not None
        log_data["exposed_response_ref"] = result.response_ref.model_dump(mode="json")
        log_data["parsed_output_ref"] = result.parsed_output_ref.model_dump(mode="json")
        log_data["session_ref"] = result.session_ref
        log_data["safe_error"] = None
    else:
        log_data["exposed_response_ref"] = None
        log_data["parsed_output_ref"] = None
        log_data["session_ref"] = None
        log_data["safe_error"] = result.safe_error
    log = LLMInvocationLog.model_validate_json(canonical_bytes(log_data))
    return CodexRuntimeCallTrace(request=request, result=result, log=log)


class _DurableTraceStore:
    def __init__(self, records: tuple[object, ...]) -> None:
        self._records = {
            cast(StoredDataRef, reference(cast(Any, record))): record
            for record in records
        }

    def get_exact(self, ref: StoredDataRef) -> object:
        return self._records[ref]

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]:
        return tuple(
            record
            for record in self._records.values()
            if str(cast(Any, record).meta.analysis_id) == analysis_id
            and cast(Any, record).meta.record_type == kind
        )


def _durable_refs(
    trace: CodexRuntimeCallTrace,
) -> codex_pvd_module.CodexRuntimeCallTraceRefs:
    return codex_pvd_module.CodexRuntimeCallTraceRefs(
        request_ref=cast(StoredDataRef, reference(trace.request)),
        result_ref=cast(StoredDataRef, reference(trace.result)),
        log_ref=cast(StoredDataRef, reference(trace.log)),
    )


def _durable_store(
    *traces: CodexRuntimeCallTrace, extra_records: tuple[object, ...] = ()
) -> _DurableTraceStore:
    return _DurableTraceStore(
        extra_records
        + tuple(
            record
            for trace in traces
            for record in (trace.request, trace.result, trace.log)
        )
    )


@pytest.mark.asyncio
async def test_repair_and_failover_checks_require_exact_new_call_lineage() -> None:
    initial = _trace(
        call_id="repair-initial",
        attempt_id="attempt-1",
        status="INVALID_OUTPUT",
        action_digest="b",
    )
    repaired = _trace(
        call_id="repair-second",
        attempt_id="attempt-2",
        status="SUCCEEDED",
        action_digest="c",
        retry_of="repair-initial",
        repair_attempts=1,
    )
    repaired_check = await CodexRepairLifecycleCheck(initial, repaired).execute(
        _candidate(), object()
    )
    assert repaired_check.result == "FAIL"

    source = _trace(
        call_id="failover-source",
        attempt_id="attempt-3",
        status="RATE_LIMITED",
        action_digest="d",
    )
    fallback = _trace(
        call_id="failover-target",
        attempt_id="attempt-4",
        status="SUCCEEDED",
        action_digest="e",
        failover_from="failover-source",
        provider_digest="b",
        model="gpt-5.6-terra",
    )
    failover_check = await CodexFailoverLifecycleCheck(source, fallback).execute(
        _candidate(), object()
    )
    assert failover_check.result == "FAIL"

    broken = CodexRuntimeCallTrace(
        request=fallback.request,
        result=fallback.result,
        log=fallback.log.model_copy(update={"failover_from_llm_call_id": None}),
    )
    rejected = await CodexFailoverLifecycleCheck(source, broken).execute(
        _candidate(), object()
    )
    assert rejected.result == "FAIL"


@pytest.mark.asyncio
async def test_repair_lifecycle_passes_only_for_current_durable_same_scope_records(
    tmp_path: Path,
) -> None:
    from tests.integration.providers.test_codex_subscription import (
        adapter as invocation_adapter,
    )
    from tests.security_negative.test_codex_subscription_boundary import (
        _supported_records,
    )

    provider, _client, _validation = _supported_records()
    provider = provider.model_copy(
        update={
            "model": "gpt-5.6-sol",
            "profile_key": "codex-subscription-primary",
        }
    )
    provider_ref = cast(StoredDataRef, reference(provider))
    initial = _trace(
        call_id="durable-repair-initial",
        attempt_id="attempt-durable-1",
        status="INVALID_OUTPUT",
        action_digest="1",
        provider_ref=provider_ref,
    )
    repaired = _trace(
        call_id="durable-repair-second",
        attempt_id="attempt-durable-2",
        status="SUCCEEDED",
        action_digest="2",
        retry_of="durable-repair-initial",
        repair_attempts=1,
        provider_ref=provider_ref,
    )
    process_runner, _adapter, _seen = _process_runner_for_pvd(tmp_path, {})
    adapter, _sessions = invocation_adapter(initial.request, process_runner)
    store = _durable_store(initial, repaired, extra_records=(provider,))

    observation = await codex_pvd_module.CodexRepairLifecycleCheck(
        initial=_durable_refs(initial),
        repair=_durable_refs(repaired),
        records=store,
    ).execute(_candidate(), adapter)

    assert observation.result == "PASS"


@pytest.mark.asyncio
async def test_repair_lifecycle_rejects_an_unresolved_provider_binding(
    tmp_path: Path,
) -> None:
    from tests.integration.providers.test_codex_subscription import (
        adapter as invocation_adapter,
    )

    initial = _trace(
        call_id="unbound-repair-initial",
        attempt_id="attempt-unbound-1",
        status="INVALID_OUTPUT",
        action_digest="3",
    )
    repaired = _trace(
        call_id="unbound-repair-second",
        attempt_id="attempt-unbound-2",
        status="SUCCEEDED",
        action_digest="4",
        retry_of="unbound-repair-initial",
        repair_attempts=1,
    )
    process_runner, _adapter, _seen = _process_runner_for_pvd(tmp_path, {})
    adapter, _sessions = invocation_adapter(initial.request, process_runner)

    observation = await codex_pvd_module.CodexRepairLifecycleCheck(
        initial=_durable_refs(initial),
        repair=_durable_refs(repaired),
        records=_durable_store(initial, repaired),
    ).execute(_candidate(), adapter)

    assert observation.result == "FAIL"


@pytest.mark.asyncio
async def test_failover_lifecycle_resolves_both_current_provider_bindings(
    tmp_path: Path,
) -> None:
    from tests.integration.providers.test_codex_subscription import (
        adapter as invocation_adapter,
    )
    from tests.security_negative.test_codex_subscription_boundary import (
        _supported_records,
    )

    source_provider, _client, _validation = _supported_records()
    source_provider = source_provider.model_copy(
        update={
            "model": "gpt-5.6-sol",
            "profile_key": "codex-subscription-primary",
        }
    )
    fallback_provider = source_provider.model_copy(
        update={
            "meta": source_provider.meta.model_copy(
                update={
                    "record_id": RecordId("fallback-provider-r1"),
                    "logical_record_id": LogicalRecordId("fallback-provider-l1"),
                }
            ),
            "model": "gpt-5.6-terra",
            "profile_key": "codex-subscription-fallback",
        }
    )
    source_ref = cast(StoredDataRef, reference(source_provider))
    fallback_ref = cast(StoredDataRef, reference(fallback_provider))
    source = _trace(
        call_id="durable-failover-source",
        attempt_id="attempt-failover-1",
        status="RATE_LIMITED",
        action_digest="5",
        provider_ref=source_ref,
    )
    fallback = _trace(
        call_id="durable-failover-target",
        attempt_id="attempt-failover-2",
        status="SUCCEEDED",
        action_digest="6",
        failover_from="durable-failover-source",
        model="gpt-5.6-terra",
        provider_ref=fallback_ref,
    )
    process_runner, _adapter, _seen = _process_runner_for_pvd(tmp_path, {})
    adapter, _sessions = invocation_adapter(source.request, process_runner)
    store = _durable_store(
        source,
        fallback,
        extra_records=(source_provider, fallback_provider),
    )

    observation = await codex_pvd_module.CodexFailoverLifecycleCheck(
        source=_durable_refs(source),
        fallback=_durable_refs(fallback),
        records=store,
    ).execute(_candidate(), adapter)

    assert observation.result == "PASS"
