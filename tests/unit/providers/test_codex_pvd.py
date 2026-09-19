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

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.llm import ProviderValidationEvidence
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.providers.codex_pvd import (
    CodexModelSelectionCheck,
    CodexPVDCheckObservation,
    CodexPVDTestId,
    CodexSubscriptionPVDProbeRunner,
    CodexTermsApproval,
)
from sastsimi.providers.codex_subscription import (
    CodexCliProcessRunner,
    CodexSubscriptionAdapter,
)
from sastsimi.runtime.system_support import SystemClock
from sastsimi.storage.artifact_store import LocalArtifactStore

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
    return type("Binding", (), {"provider_profile": profile})()


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


@dataclass
class SerialCheck:
    test_id: CodexPVDTestId
    active: list[int]
    peak: list[int]

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        del candidate, adapter
        self.active[0] += 1
        self.peak[0] = max(self.peak[0], self.active[0])
        await asyncio.sleep(0)
        self.active[0] -= 1
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                f"{self.test_id} ran without sharing subscription refresh state"
            ),
            evidence=canonical_bytes({"executed": True}),
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
    seen: list[CodexPVDTestId] = []
    executable_digest = "a" * 64
    checks = tuple(
        RecordingCheck(
            cast(CodexPVDTestId, f"PVD-{index:02d}"),
            seen,
            (
                {
                    "executable_sha256": executable_digest,
                    "explicit_model_argument": "gpt-5.6-sol",
                    "invalid_model_rejected": True,
                    "provider_model_reported": False,
                    "strict_structured_output_succeeded": True,
                    "limitation": (
                        "Official Codex JSON event stream does not report model "
                        "identity; the exact executable and explicit model argument "
                        "are bound instead."
                    ),
                }
                if index == 2
                else {"executed": True, "test_id": f"PVD-{index:02d}"}
            ),
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

    assert sorted(seen) == [f"PVD-{index:02d}" for index in range(1, 15) if index != 2]
    assert result.evidence.checked_at == _CHECKED_AT
    by_id = {test.test_id: test for test in result.evidence.tests}
    assert by_id["PVD-02"].result == "FAIL"
    assert all(
        test.result == "PASS" for test_id, test in by_id.items() if test_id != "PVD-02"
    )
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
async def test_subscription_pvd_checks_run_serially(tmp_path: Path) -> None:
    active = [0]
    peak = [0]
    checks = tuple(
        SerialCheck(cast(CodexPVDTestId, f"PVD-{index:02d}"), active, peak)
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
    ) + (
        RecordingCheck("PVD-16", seen, {"runtime_tool_loop": "SUPPORTED"}),
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
        "Codex model selection evidence did not use the trusted live check"
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
    assert all(by_id[f"PVD-{index:02d}"].result == "FAIL" for index in range(1, 15))
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
    checks = tuple(
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
    seen: list[CodexProcessRequest] = []

    async def execute(request: CodexProcessRequest) -> CodexProcessResult:
        seen.append(request)
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

    runner.execute = execute  # type: ignore[method-assign]
    runner.execution_argv = execution_argv  # type: ignore[method-assign]
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
