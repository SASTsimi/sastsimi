"""Fail-closed PVD evidence runner for the official Codex subscription client."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Literal, Protocol, cast
from urllib.parse import urlsplit

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderProfile,
    ProviderValidationEvidence,
    ProviderValidationTest,
)
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import CancellationResult, CapabilityProbeResult

from .base import CODEX_PVD_RUNNER_MARKER, CodexProcessRequest, CodexProcessResult

type CodexPVDTestId = Literal[
    "PVD-01",
    "PVD-02",
    "PVD-03",
    "PVD-04",
    "PVD-05",
    "PVD-06",
    "PVD-07",
    "PVD-08",
    "PVD-09",
    "PVD-10",
    "PVD-11",
    "PVD-12",
    "PVD-13",
    "PVD-14",
    "PVD-16",
]
type PVDResult = Literal["PASS", "FAIL"]

_AUTOMATED_TEST_IDS: tuple[CodexPVDTestId, ...] = tuple(
    cast(CodexPVDTestId, f"PVD-{index:02d}") for index in range(1, 15)
)
_OPTIONAL_DYNAMIC_TEST_ID: CodexPVDTestId = "PVD-16"
_MAX_CHECK_TIMEOUT_MS = 300_000
_CHECK_CLEANUP_TIMEOUT_SECONDS = 0.1
_MODEL_LIMITATION = "does not report model identity"
_MODEL_OUTPUT_SCHEMA = canonical_bytes(
    {
        "additionalProperties": False,
        "properties": {"status": {"const": "ok", "type": "string"}},
        "required": ["status"],
        "type": "object",
    }
)
_MODEL_OUTPUT_SCHEMA_SHA256 = hashlib.sha256(_MODEL_OUTPUT_SCHEMA).hexdigest()


@dataclass(frozen=True)
class CodexPVDCheckObservation:
    test_id: CodexPVDTestId
    result: PVDResult
    safe_summary: str
    evidence: bytes


class CodexPVDCheck(Protocol):
    @property
    def test_id(self) -> CodexPVDTestId: ...

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation: ...


class _ExecutableBinding(Protocol):
    path: Path
    sha256: str


class _RunnerBinding(Protocol):
    provider_profile: object
    client_execution_profile: object
    runtime_environment: object


class _ExactCodexRunner(Protocol):
    executable: _ExecutableBinding
    binding: _RunnerBinding

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult: ...

    def child_environment(self, source: Mapping[str, str]) -> dict[str, str]: ...

    def execution_argv(
        self,
        request: CodexProcessRequest,
        work_directory: Path,
        schema_path: Path,
        output_path: Path,
    ) -> tuple[str, ...]: ...


class _ExactInvocationAdapter(Protocol):
    provider_profile_ref: StoredDataRef
    model: str
    process_runner: _ExactCodexRunner

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult: ...

    async def cancel(self, invocation_id: str) -> CancellationResult: ...


class _RuntimeTraceRecords(Protocol):
    def get_exact(self, ref: StoredDataRef) -> object: ...

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]: ...


@dataclass(frozen=True)
class CodexModelSelectionCheck:
    """Observe exact executable/model binding without trusting event model fields.

    The official Codex JSON event stream currently does not expose a provider-
    reported model identifier. Passing PVD-02 therefore requires the exact
    executable digest, the explicit ``--model`` argument, a successful strict
    structured-output call, and rejection of a deliberately invalid model.
    """

    valid_request: CodexProcessRequest
    test_id: CodexPVDTestId = "PVD-02"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        from .codex_subscription import CodexCliProcessRunner

        runner = getattr(adapter, "process_runner", None)
        adapter_model = getattr(adapter, "model", None)
        adapter_profile_ref = getattr(adapter, "provider_profile_ref", None)
        bound_profile = getattr(
            getattr(runner, "binding", None), "provider_profile", None
        )
        if (
            not isinstance(runner, CodexCliProcessRunner)
            or adapter_model != candidate.model
            or adapter_profile_ref != self.valid_request.provider_profile_ref
            or self.valid_request.model != candidate.model
            or self.valid_request.output_schema != _MODEL_OUTPUT_SCHEMA
            or self.valid_request.timeout_ms <= 0
            or bound_profile is None
            or any(
                getattr(bound_profile, field, None) != getattr(candidate, field)
                for field in (
                    "auth_mode",
                    "client_name",
                    "client_version",
                    "environment",
                    "model",
                    "product",
                    "profile_key",
                    "provider",
                    "transport",
                )
            )
        ):
            return _failure(
                self.test_id,
                "Codex model selection check was not bound to the exact adapter",
                "CODEX_MODEL_CHECK_BINDING_INVALID",
            )
        try:
            executable_path = runner.executable.path
            approved_digest = runner.executable.sha256
            actual_digest = _sha256_file(executable_path)
            root = executable_path.parent.resolve(strict=True)
            argv = runner.execution_argv(
                self.valid_request,
                root,
                root / "pvd-output-schema.json",
                root / "pvd-last-message.json",
            )
        except (AttributeError, OSError, TypeError, ValueError):
            return _failure(
                self.test_id,
                "Codex executable or model argument could not be verified",
                "CODEX_MODEL_EXECUTABLE_UNVERIFIED",
            )
        explicit_model = _explicit_model_argument(argv)
        valid = await runner.execute(self.valid_request)
        invalid = await runner.execute(
            replace(
                self.valid_request,
                invocation_id=f"{self.valid_request.invocation_id}-invalid-model",
                model="sastsimi-invalid-model-control",
            )
        )
        structured = _strict_probe_output(valid.final_message)
        invalid_rejected = (
            invalid.status == "FAILED"
            and invalid.final_message is None
            and invalid.provider_session_id is None
        )
        passed = (
            approved_digest == actual_digest
            and _is_sha256(actual_digest)
            and explicit_model == candidate.model
            and valid.status == "SUCCEEDED"
            and bool(valid.provider_session_id)
            and structured
            and invalid_rejected
        )
        evidence = canonical_bytes(
            {
                "executable_sha256": actual_digest,
                "explicit_model_argument": explicit_model,
                "invalid_model_rejected": invalid_rejected,
                "limitation": (
                    "Official Codex JSON event stream does not report model "
                    "identity; the exact executable and explicit model argument "
                    "are bound instead."
                ),
                "output_schema_sha256": _MODEL_OUTPUT_SCHEMA_SHA256,
                "provider_model_reported": False,
                "strict_structured_output_succeeded": structured,
            }
        )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS" if passed else "FAIL",
            safe_summary=(
                "Exact Codex executable and explicit model binding passed both controls"
                if passed
                else "Codex model selection controls did not all pass"
            ),
            evidence=evidence,
        )


@dataclass(frozen=True)
class CodexAuthenticationPreflightCheck:
    """Prove that the exact official client can authenticate without exporting it."""

    request: CodexProcessRequest
    test_id: CodexPVDTestId = "PVD-01"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        runner = _exact_process_runner(candidate, adapter, self.request)
        if runner is None:
            return _failure(
                self.test_id,
                "Codex authentication preflight was not bound to the exact client",
                "CODEX_AUTH_BINDING_INVALID",
            )
        result = await runner.execute(self.request)
        if result.status == "AUTH_REQUIRED":
            return _failure(
                self.test_id,
                "Codex authentication is missing or expired",
                "CODEX_AUTH_REQUIRED",
            )
        passed = (
            result.status == "SUCCEEDED"
            and result.final_message is not None
            and bool(result.provider_session_id)
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex authentication preflight did not complete safely",
                "CODEX_AUTH_PREFLIGHT_FAILED",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary="Exact Codex client authentication preflight succeeded",
            evidence=canonical_bytes(
                {
                    "client_version": candidate.client_version,
                    "sensitive_material_recorded": False,
                    "login_state": "AUTHENTICATED",
                    "process_status": result.status,
                }
            ),
        )


@dataclass(frozen=True)
class CodexStructuredOutputCheck:
    """Require one live call to return the exact canonical schema fixture."""

    request: CodexProcessRequest
    expected_output: bytes
    test_id: CodexPVDTestId = "PVD-03"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        runner = _exact_process_runner(candidate, adapter, self.request)
        if runner is None or not _canonical_json_document(self.expected_output):
            return _failure(
                self.test_id,
                "Codex structured-output check was not bound to an exact fixture",
                "CODEX_STRUCTURED_OUTPUT_BINDING_INVALID",
            )
        result = await runner.execute(self.request)
        passed = (
            result.status == "SUCCEEDED"
            and bool(result.provider_session_id)
            and result.final_message == self.expected_output
            and _canonical_json_document(result.final_message)
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex did not return the exact canonical structured-output fixture",
                "CODEX_STRUCTURED_OUTPUT_INVALID",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary="Codex output passed exact parse and semantic fixture checks",
            evidence=canonical_bytes(
                {
                    "output_schema_sha256": hashlib.sha256(
                        self.request.output_schema
                    ).hexdigest(),
                    "output_sha256": hashlib.sha256(self.expected_output).hexdigest(),
                    "parsed": True,
                    "semantic_validation_succeeded": True,
                }
            ),
        )


@dataclass(frozen=True)
class CodexNewSessionIsolationCheck:
    """Use two live NEW calls and require isolated markers and session IDs."""

    first_request: CodexProcessRequest
    second_request: CodexProcessRequest
    first_marker: bytes
    second_marker: bytes
    first_expected_output: bytes
    second_expected_output: bytes
    test_id: CodexPVDTestId = "PVD-04"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        runner = _exact_process_runner(candidate, adapter, self.first_request)
        shape_valid = (
            runner is not None
            and _request_matches_candidate(self.second_request, candidate, adapter)
            and self.first_request.invocation_id != self.second_request.invocation_id
            and bool(self.first_marker)
            and bool(self.second_marker)
            and self.first_marker != self.second_marker
            and self.first_marker in self.first_request.prompt
            and self.first_marker not in self.second_request.prompt
            and self.second_marker in self.second_request.prompt
            and self.second_marker not in self.first_request.prompt
            and _canonical_json_document(self.first_expected_output)
            and _canonical_json_document(self.second_expected_output)
        )
        if not shape_valid or runner is None:
            return _failure(
                self.test_id,
                "Codex NEW-session isolation fixtures were not exact and independent",
                "CODEX_NEW_SESSION_FIXTURE_INVALID",
            )
        first = await runner.execute(self.first_request)
        second = await runner.execute(self.second_request)
        passed = (
            _matches_success(first, self.first_expected_output)
            and _matches_success(second, self.second_expected_output)
            and first.provider_session_id != second.provider_session_id
            and self.first_marker in self.first_expected_output
            and self.first_marker not in self.second_expected_output
            and self.second_marker in self.second_expected_output
            and self.second_marker not in self.first_expected_output
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex NEW calls did not prove independent session context",
                "CODEX_NEW_SESSION_NOT_ISOLATED",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Two exact Codex NEW calls kept their contexts and sessions separate"
            ),
            evidence=canonical_bytes(
                {
                    "distinct_context_handles": True,
                    "distinct_invocation_ids": True,
                    "first_prompt_sha256": hashlib.sha256(
                        self.first_request.prompt
                    ).hexdigest(),
                    "second_prompt_sha256": hashlib.sha256(
                        self.second_request.prompt
                    ).hexdigest(),
                }
            ),
        )


@dataclass(frozen=True)
class CodexParallelNewSessionCheck:
    """Run the same input concurrently in two independent official-client calls."""

    first_request: CodexProcessRequest
    second_request: CodexProcessRequest
    expected_output: bytes
    test_id: CodexPVDTestId = "PVD-06"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        runner = _exact_process_runner(candidate, adapter, self.first_request)
        shape_valid = (
            runner is not None
            and _request_matches_candidate(self.second_request, candidate, adapter)
            and self.first_request.invocation_id != self.second_request.invocation_id
            and self.first_request.prompt == self.second_request.prompt
            and self.first_request.output_schema == self.second_request.output_schema
            and _canonical_json_document(self.expected_output)
        )
        if not shape_valid or runner is None:
            return _failure(
                self.test_id,
                "Codex parallel-session fixtures were not the same exact input",
                "CODEX_PARALLEL_FIXTURE_INVALID",
            )
        first_task = asyncio.create_task(runner.execute(self.first_request))
        second_task = asyncio.create_task(runner.execute(self.second_request))
        try:
            first, second = await asyncio.gather(first_task, second_task)
        except BaseException:
            for task in (first_task, second_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(first_task, second_task, return_exceptions=True)
            raise
        passed = (
            _matches_success(first, self.expected_output)
            and _matches_success(second, self.expected_output)
            and first.provider_session_id != second.provider_session_id
        )
        if not passed:
            return _failure(
                self.test_id,
                "Concurrent Codex calls did not preserve independent NEW sessions",
                "CODEX_PARALLEL_SESSION_INVALID",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Concurrent Codex calls used the same input and separate sessions"
            ),
            evidence=canonical_bytes(
                {
                    "concurrent_calls": 2,
                    "distinct_context_handles": True,
                    "input_sha256": hashlib.sha256(
                        self.first_request.prompt
                    ).hexdigest(),
                    "call_mode": "NEW",
                }
            ),
        )


@dataclass(frozen=True)
class CodexUnprovenRuntimeCheck:
    """Fail closed for a PVD scenario whose exact runtime trace is unavailable."""

    test_id: CodexPVDTestId
    reason_code: str
    safe_summary: str

    def __post_init__(self) -> None:
        if (
            self.test_id
            not in {*_AUTOMATED_TEST_IDS, _OPTIONAL_DYNAMIC_TEST_ID}
            or not self.reason_code.startswith("CODEX_")
            or not self.safe_summary.strip()
        ):
            raise ValueError("CODEX_UNPROVEN_CHECK_INVALID")

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        del candidate, adapter
        return _failure(self.test_id, self.safe_summary, self.reason_code)


@dataclass(frozen=True)
class CodexResumeCapabilityCheck:
    """Prove the current adapter rejects unsupported RESUME before transport."""

    request: LLMInvocationRequest
    test_id: CodexPVDTestId = "PVD-05"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        provider = _exact_invocation_adapter(candidate, adapter, self.request)
        if (
            provider is None
            or self.request.session_policy != "RESUME"
            or not self.request.parent_session_ref
        ):
            return _failure(
                self.test_id,
                "Codex RESUME rejection check was not bound to an exact parent",
                "CODEX_RESUME_FIXTURE_INVALID",
            )
        result = await provider.invoke(self.request)
        passed = (
            result.status == "FAILED"
            and result.actual_session_mode == "NEW"
            and result.session_ref is None
            and result.response_ref is None
            and result.parsed_output_ref is None
            and result.safe_error
            == "FAILED: authorized Codex request inputs did not match"
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex RESUME did not produce the explicit unsupported result",
                "CODEX_RESUME_REJECTION_INVALID",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Codex RESUME is explicitly unsupported and rejected before transport"
            ),
            evidence=canonical_bytes(
                {
                    "explicit_failure_status": "FAILED",
                    "parent_reference_supplied": True,
                    "resume_supported": False,
                    "transport_invoked": False,
                }
            ),
        )


@dataclass(frozen=True)
class CodexTimeoutCancellationCheck:
    """Exercise both runtime timeout and user cancellation normalization."""

    timeout_request: LLMInvocationRequest
    cancellation_request: LLMInvocationRequest
    cancellation_adapter: object
    test_id: CodexPVDTestId = "PVD-07"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        provider = _exact_live_invocation_adapter(
            candidate, adapter, self.timeout_request
        )
        cancel_provider = _exact_live_invocation_adapter(
            candidate, self.cancellation_adapter, self.cancellation_request
        )
        if (
            provider is None
            or cancel_provider is None
            or not _same_exact_runner_binding(provider, cancel_provider)
            or self.timeout_request.llm_call_id == self.cancellation_request.llm_call_id
        ):
            return _failure(
                self.test_id,
                "Codex timeout and cancellation fixtures were not independent",
                "CODEX_TIMING_FIXTURE_INVALID",
            )
        timed = await provider.invoke(self.timeout_request)
        active = asyncio.create_task(cancel_provider.invoke(self.cancellation_request))
        # Let the invocation enter the adapter's cancellation guard before
        # requesting cancellation.  Cancelling before that guard exists would
        # only cancel the caller task and would not prove child cleanup.
        await asyncio.sleep(0.05)
        cancellation = await cancel_provider.cancel(
            self.cancellation_request.llm_call_id
        )
        cancelled = await active
        passed = (
            timed.status == "TIMED_OUT"
            and timed.response_ref is None
            and timed.parsed_output_ref is None
            and cancellation.cancelled
            and cancelled.status == "CANCELLED"
            and cancelled.response_ref is None
            and cancelled.parsed_output_ref is None
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex timeout or cancellation did not reach the required common state",
                "CODEX_TIMEOUT_CANCELLATION_INVALID",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Codex timeout and cancellation produced distinct safe terminal states"
            ),
            evidence=canonical_bytes(
                {
                    "cancel_status": "CANCELLED",
                    "timeout_status": "TIMED_OUT",
                    "verdict_created": False,
                }
            ),
        )


@dataclass(frozen=True)
class CodexErrorClassificationCheck:
    """Require controlled live adapters for auth and usage-limit outcomes."""

    auth_request: LLMInvocationRequest
    rate_limit_request: LLMInvocationRequest
    rate_limit_adapter: object
    test_id: CodexPVDTestId = "PVD-08"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        auth_provider = _exact_live_invocation_adapter(
            candidate, adapter, self.auth_request
        )
        rate_provider = _exact_live_invocation_adapter(
            candidate, self.rate_limit_adapter, self.rate_limit_request
        )
        if (
            auth_provider is None
            or rate_provider is None
            or not _same_exact_runner_binding(auth_provider, rate_provider)
            or self.auth_request.llm_call_id == self.rate_limit_request.llm_call_id
        ):
            return _failure(
                self.test_id,
                "Codex failure-classification fixtures were not exactly bound",
                "CODEX_FAILURE_CLASSIFICATION_FIXTURE_INVALID",
            )
        auth = await auth_provider.invoke(self.auth_request)
        limited = await rate_provider.invoke(self.rate_limit_request)
        passed = (
            auth.status == "AUTH_REQUIRED"
            and limited.status == "RATE_LIMITED"
            and all(
                item.response_ref is None
                and item.parsed_output_ref is None
                and item.session_ref is None
                for item in (auth, limited)
            )
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex authentication and usage-limit failures were not distinguished",
                "CODEX_FAILURE_CLASSIFICATION_INVALID",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Codex authentication and usage-limit failures stayed distinct"
            ),
            evidence=canonical_bytes(
                {
                    "authentication_status": "AUTH_REQUIRED",
                    "rate_status": "RATE_LIMITED",
                    "verdict_created": False,
                }
            ),
        )


@dataclass(frozen=True)
class CodexRuntimeCallTrace:
    """Exact request, result and durable log from one Runtime-owned call."""

    request: LLMInvocationRequest
    result: LLMInvocationResult
    log: LLMInvocationLog

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "request", LLMInvocationRequest.model_validate(self.request)
        )
        object.__setattr__(
            self, "result", LLMInvocationResult.model_validate(self.result)
        )
        object.__setattr__(self, "log", LLMInvocationLog.model_validate(self.log))


@dataclass(frozen=True)
class CodexRuntimeCallTraceRefs:
    """Exact durable references for one Runtime-owned invocation trace."""

    request_ref: StoredDataRef
    result_ref: StoredDataRef
    log_ref: StoredDataRef

    def __post_init__(self) -> None:
        if (
            self.request_ref.data_kind != LLMInvocationRequest.KIND
            or self.result_ref.data_kind != LLMInvocationResult.KIND
            or self.log_ref.data_kind != LLMInvocationLog.KIND
            or any(
                ref.record_id is None
                for ref in (self.request_ref, self.result_ref, self.log_ref)
            )
        ):
            raise ValueError("CODEX_RUNTIME_TRACE_REFERENCE_INVALID")


@dataclass(frozen=True)
class CodexRepairLifecycleCheck:
    """Verify an invalid output repair used a new linked Runtime call."""

    initial: CodexRuntimeCallTraceRefs | CodexRuntimeCallTrace
    repair: CodexRuntimeCallTraceRefs | CodexRuntimeCallTrace
    records: _RuntimeTraceRecords | None = None
    test_id: CodexPVDTestId = "PVD-09"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        initial = _resolve_runtime_trace(self.initial, self.records)
        repair = _resolve_runtime_trace(self.repair, self.records)
        initial_provider = _resolve_runtime_provider(initial, self.records)
        repair_provider = _resolve_runtime_provider(repair, self.records)
        passed = (
            initial is not None
            and repair is not None
            and initial_provider is not None
            and repair_provider is not None
            and _provider_matches_candidate(initial_provider, candidate)
            and _exact_live_invocation_adapter(candidate, adapter, initial.request)
            is not None
            and _valid_runtime_trace(initial)
            and _valid_runtime_trace(repair)
            and _same_runtime_scope(initial, repair)
            and initial.request.model == candidate.model
            and initial.result.status == "INVALID_OUTPUT"
            and repair.result.status == "SUCCEEDED"
            and initial.request.provider_profile_ref
            == repair.request.provider_profile_ref
            and initial.request.model == repair.request.model
            and initial.request.llm_call_id != repair.request.llm_call_id
            and initial.request.action_decision_ref
            != repair.request.action_decision_ref
            and initial.request.meta.attempt_id != repair.request.meta.attempt_id
            and initial.log.retry_of_llm_call_id is None
            and repair.log.retry_of_llm_call_id == initial.request.llm_call_id
            and repair.log.failover_from_llm_call_id is None
            and repair.log.repair_attempts == initial.log.repair_attempts + 1
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex invalid-output repair did not preserve exact new-call lineage",
                "CODEX_REPAIR_LINEAGE_INVALID",
            )
        assert initial is not None and repair is not None
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Codex invalid output was repaired by a new linked call and attempt"
            ),
            evidence=canonical_bytes(
                {
                    "initial_call": initial.request.llm_call_id,
                    "new_action": True,
                    "new_attempt": True,
                    "repair_call": repair.request.llm_call_id,
                    "repair_link_preserved": True,
                }
            ),
        )


@dataclass(frozen=True)
class CodexFailoverLifecycleCheck:
    """Verify explicit failover preserves the source and creates a new call."""

    source: CodexRuntimeCallTraceRefs | CodexRuntimeCallTrace
    fallback: CodexRuntimeCallTraceRefs | CodexRuntimeCallTrace
    records: _RuntimeTraceRecords | None = None
    test_id: CodexPVDTestId = "PVD-10"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        source = _resolve_runtime_trace(self.source, self.records)
        fallback = _resolve_runtime_trace(self.fallback, self.records)
        source_provider = _resolve_runtime_provider(source, self.records)
        fallback_provider = _resolve_runtime_provider(fallback, self.records)
        passed = (
            source is not None
            and fallback is not None
            and source_provider is not None
            and fallback_provider is not None
            and _provider_matches_candidate(source_provider, candidate)
            and _exact_live_invocation_adapter(candidate, adapter, source.request)
            is not None
            and _valid_runtime_trace(source)
            and _valid_runtime_trace(fallback)
            and _same_runtime_scope(source, fallback)
            and source.request.model == candidate.model
            and source.result.status
            in {"AUTH_REQUIRED", "RATE_LIMITED", "TIMED_OUT", "FAILED"}
            and source.request.llm_call_id != fallback.request.llm_call_id
            and source.request.action_decision_ref
            != fallback.request.action_decision_ref
            and source.request.meta.attempt_id != fallback.request.meta.attempt_id
            and (
                source.request.provider_profile_ref
                != fallback.request.provider_profile_ref
                or source.request.model != fallback.request.model
            )
            and source.log.failover_from_llm_call_id is None
            and fallback.log.failover_from_llm_call_id
            == source.request.llm_call_id
            and fallback.log.retry_of_llm_call_id is None
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex failover did not preserve exact source and target lineage",
                "CODEX_FAILOVER_LINEAGE_INVALID",
            )
        assert source is not None and fallback is not None
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Codex failover preserved the source and used a new approved call"
            ),
            evidence=canonical_bytes(
                {
                    "fallback_call": fallback.request.llm_call_id,
                    "new_action": True,
                    "new_attempt": True,
                    "source_call": source.request.llm_call_id,
                    "source_preserved": True,
                }
            ),
        )


@dataclass(frozen=True)
class CodexRedactionBoundaryCheck:
    """Prove safe request/result bytes and removal of ambient sensitive values."""

    request: CodexProcessRequest
    expected_output: bytes
    source_environment: Mapping[str, str]
    test_id: CodexPVDTestId = "PVD-11"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        runner = _exact_process_runner(candidate, adapter, self.request)
        if runner is None or not _canonical_json_document(self.expected_output):
            return _failure(
                self.test_id,
                "Codex redaction check was not bound to an exact safe fixture",
                "CODEX_REDACTION_BINDING_INVALID",
            )
        try:
            prompt = redact_untrusted_text(self.request.prompt)
            schema = redact_projected_json(self.request.output_schema)
            expected = redact_projected_json(self.expected_output)
            child_environment = runner.child_environment(self.source_environment)
        except (UnicodeError, TypeError, ValueError):
            return _failure(
                self.test_id,
                "Codex request material failed the redaction boundary",
                "CODEX_REDACTION_INPUT_UNSAFE",
            )
        source_by_upper = {
            key.upper(): value for key, value in self.source_environment.items()
        }
        allowed = {"CODEX_HOME", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"}
        environment_safe = (
            set(child_environment) <= allowed
            and all(
                key not in child_environment
                for key in source_by_upper
                if key not in allowed
            )
            and child_environment.get("CODEX_HOME") != source_by_upper.get("CODEX_HOME")
        )
        input_safe = all(
            not item.categories and item.data == original
            for item, original in (
                (prompt, self.request.prompt),
                (schema, self.request.output_schema),
                (expected, self.expected_output),
            )
        )
        result = await runner.execute(self.request)
        output_safe = False
        if result.final_message is not None:
            try:
                checked = redact_projected_json(result.final_message)
                output_safe = (
                    not checked.categories
                    and checked.data == result.final_message
                    and result.final_message == self.expected_output
                )
            except (TypeError, ValueError):
                output_safe = False
        passed = (
            input_safe
            and environment_safe
            and output_safe
            and result.status == "SUCCEEDED"
            and bool(result.provider_session_id)
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex request, result, or child environment crossed the safe boundary",
                "CODEX_REDACTION_BOUNDARY_FAILED",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Codex request, result, and child environment were safely bounded"
            ),
            evidence=canonical_bytes(
                {
                    "host_location_recorded": False,
                    "output_sha256": hashlib.sha256(self.expected_output).hexdigest(),
                    "prompt_sha256": hashlib.sha256(self.request.prompt).hexdigest(),
                    "sensitive_material_recorded": False,
                }
            ),
        )


@dataclass(frozen=True)
class CodexObservationSurfaceCheck:
    """Record only metadata the official Codex boundary actually exposes."""

    request: CodexProcessRequest
    expected_output: bytes
    test_id: CodexPVDTestId = "PVD-12"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        runner = _exact_process_runner(candidate, adapter, self.request)
        if runner is None or not _canonical_json_document(self.expected_output):
            return _failure(
                self.test_id,
                "Codex observation check was not bound to an exact live call",
                "CODEX_OBSERVATION_BINDING_INVALID",
            )
        result = await runner.execute(self.request)
        passed = _matches_success(result, self.expected_output) and not any(
            hasattr(result, field) for field in ("request_id", "usage")
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex observation surface contained unverified or incomplete values",
                "CODEX_OBSERVATION_SURFACE_INVALID",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Only metadata exposed by the official Codex client was used"
            ),
            evidence=canonical_bytes(
                {
                    "context_handle_available": True,
                    "request_identifier": None,
                    "usage": None,
                    "unpublished_values_inferred": False,
                }
            ),
        )


@dataclass(frozen=True)
class CodexClientIsolationCheck:
    """Verify the exact no-repository, no-tools official-client boundary."""

    request: CodexProcessRequest
    expected_output: bytes
    source_environment: Mapping[str, str]
    test_id: CodexPVDTestId = "PVD-13"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        from .codex_subscription import _DISABLED_FEATURES

        runner = _exact_process_runner(candidate, adapter, self.request)
        if runner is None:
            return _failure(
                self.test_id,
                "Codex isolation check was not bound to the exact official client",
                "CODEX_ISOLATION_BINDING_INVALID",
            )
        client = getattr(runner.binding, "client_execution_profile", None)
        boundary = {
            "working_directory_mode": "ISOLATED_EMPTY",
            "filesystem_mode": "NO_REPOSITORY_ACCESS",
            "tool_mode": "DISABLED",
            "mcp_mode": "DISABLED",
            "hooks_mode": "DISABLED",
            "plugin_mode": "DISABLED",
            "instruction_sources": "EXPLICIT_SASTSIMI_PAYLOAD_ONLY",
            "provider_fallback": "DISABLED",
        }
        try:
            root = runner.executable.path.parent.resolve(strict=True)
            argv = runner.execution_argv(
                self.request,
                root,
                root / "pvd-output-schema.json",
                root / "pvd-last-message.json",
            )
            child_environment = runner.child_environment(self.source_environment)
        except (AttributeError, OSError, TypeError, ValueError):
            return _failure(
                self.test_id,
                "Codex isolation controls could not be inspected",
                "CODEX_ISOLATION_UNVERIFIED",
            )
        disabled = {
            argv[index + 1]
            for index, value in enumerate(argv[:-1])
            if value == "--disable"
        }
        configurations = {
            argv[index + 1]
            for index, value in enumerate(argv[:-1])
            if value == "--config"
        }
        boundary_valid = (
            client is not None
            and all(
                getattr(client, key, None) == value for key, value in boundary.items()
            )
            and _argv_pair(argv, "--sandbox", "read-only")
            and all(
                flag in argv
                for flag in (
                    "--ephemeral",
                    "--ignore-user-config",
                    "--ignore-rules",
                    "--strict-config",
                )
            )
            and set(_DISABLED_FEATURES) <= disabled
            and {"mcp_servers={}", "hooks={}"} <= configurations
            and set(child_environment)
            <= {"CODEX_HOME", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"}
        )
        result = await runner.execute(self.request)
        passed = boundary_valid and _matches_success(result, self.expected_output)
        if not passed:
            return _failure(
                self.test_id,
                "Codex no-repository or no-tools boundary was not fully enforced",
                "CODEX_ISOLATION_BOUNDARY_FAILED",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Codex ran with repository, tools, extensions and ambient data disabled"
            ),
            evidence=canonical_bytes(
                {
                    "ambient_values_available": False,
                    "extension_sources_enabled": False,
                    "repository_access": False,
                    "tool_execution_enabled": False,
                }
            ),
        )


@dataclass(frozen=True)
class CodexEnvironmentBindingCheck:
    """Verify exact local environment binding and fail-before-call mismatch."""

    request: CodexProcessRequest
    test_id: CodexPVDTestId = "PVD-14"

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation:
        runner = _exact_process_runner(candidate, adapter, self.request)
        if runner is None:
            return _failure(
                self.test_id,
                "Codex environment did not match the exact approved profile",
                "CODEX_ENVIRONMENT_BINDING_INVALID",
            )
        alternatives = {
            "PERSONAL_LOCAL",
            "TEAM_LOCAL",
            "PRIVATE_CI",
            "SHARED_SERVER",
        } - {str(candidate.environment)}
        mismatch_rejected = all(
            _exact_process_runner(
                candidate.model_copy(update={"environment": environment}),
                adapter,
                self.request,
            )
            is None
            for environment in alternatives
        )
        passed = (
            getattr(runner.binding, "runtime_environment", None)
            == candidate.environment
            and mismatch_rejected
        )
        if not passed:
            return _failure(
                self.test_id,
                "Codex environment mismatch was not rejected before a call",
                "CODEX_ENVIRONMENT_MISMATCH_NOT_REJECTED",
            )
        return CodexPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary=(
                "Codex was bound to one exact environment and rejected alternatives"
            ),
            evidence=canonical_bytes(
                {
                    "bound_environment": candidate.environment,
                    "mismatch_rejected_before_call": True,
                    "profile_identity_sha256": _candidate_identity_digest(candidate),
                }
            ),
        )


@dataclass(frozen=True)
class CodexTermsApproval:
    """Explicit human attestation; this record is never inferred from a live call."""

    approved_by: str
    approved_at: datetime
    valid_until: datetime
    official_terms_url: str
    intended_use: str
    account_scope: str

    def __post_init__(self) -> None:
        endpoint = urlsplit(self.official_terms_url)
        if (
            not self.approved_by.strip()
            or self.approved_at.tzinfo is None
            or self.approved_at.utcoffset() is None
            or self.valid_until.tzinfo is None
            or self.valid_until.utcoffset() is None
            or self.approved_at >= self.valid_until
            or endpoint.scheme != "https"
            or endpoint.hostname not in {"openai.com", "www.openai.com"}
            or endpoint.username is not None
            or endpoint.password is not None
            or not self.intended_use.strip()
            or not self.account_scope.strip()
        ):
            raise ValueError("CODEX_TERMS_APPROVAL_INVALID")


class CodexSubscriptionPVDProbeRunner:
    """Execute exact Codex PVD checks and commit new, secret-free receipts.

    PVD-01 through PVD-14 must each have one trusted executable check. PVD-15
    is deliberately excluded from automation and can pass only when the caller
    supplies an explicit human terms approval. Caller-authored results and
    evidence references on the candidate are always discarded.
    """

    trusted_runner_marker: ClassVar[object] = CODEX_PVD_RUNNER_MARKER

    def __init__(
        self,
        *,
        checks: tuple[CodexPVDCheck, ...],
        artifacts: ArtifactStore,
        clock: Clock,
        per_check_timeout_ms: int,
        executable_sha256: str,
        terms_approval: CodexTermsApproval | None,
    ) -> None:
        if (
            isinstance(per_check_timeout_ms, bool)
            or not 1 <= per_check_timeout_ms <= _MAX_CHECK_TIMEOUT_MS
            or not _is_sha256(executable_sha256)
        ):
            raise ValueError("CODEX_PVD_CONFIGURATION_INVALID")
        self._checks = checks
        self._artifacts = artifacts
        self._clock = clock
        self._per_check_timeout_ms = per_check_timeout_ms
        self._executable_sha256 = executable_sha256
        self._terms_approval = terms_approval

    async def run(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CapabilityProbeResult:
        candidate = ProviderValidationEvidence.model_validate(candidate)
        identity_digest = _candidate_identity_digest(candidate)
        checks, invalid_configuration = _index_checks(self._checks)
        candidate_valid = (
            candidate.provider == "OPENAI"
            and candidate.product == "CODEX"
            and candidate.transport == "CODEX_CLIENT"
            and candidate.auth_mode == "SUBSCRIPTION_LOGIN"
        )
        run_test_ids = _AUTOMATED_TEST_IDS + (
            (_OPTIONAL_DYNAMIC_TEST_ID,) if checks[_OPTIONAL_DYNAMIC_TEST_ID] else ()
        )
        # Subscription clients can share one rotating login credential.  Run
        # checks in a deterministic sequence so concurrent child refreshes
        # cannot invalidate the same account session.
        automated = tuple(
            [
                await self._run_test(
                    test_id,
                    candidate,
                    adapter,
                    checks.get(test_id, ()),
                    identity_digest,
                    invalid_configuration=invalid_configuration,
                    candidate_valid=candidate_valid,
                )
                for test_id in run_test_ids
            ]
        )

        checked_at = self._clock.now()
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise ValueError("CODEX_PVD_CLOCK_INVALID")
        terms = self._terms_test(candidate, identity_digest, checked_at)
        evidence = ProviderValidationEvidence.model_validate(
            candidate.model_copy(
                update={"tests": (*automated, terms), "checked_at": checked_at}
            )
        )
        return CapabilityProbeResult(evidence=evidence)

    async def _run_test(
        self,
        test_id: CodexPVDTestId,
        candidate: ProviderValidationEvidence,
        adapter: object,
        checks: tuple[CodexPVDCheck, ...],
        identity_digest: str,
        *,
        invalid_configuration: bool,
        candidate_valid: bool,
    ) -> ProviderValidationTest:
        if invalid_configuration:
            observation = _failure(
                test_id,
                "PVD check configuration contains an unknown test",
                "PVD_CHECK_CONFIGURATION_INVALID",
            )
        elif not candidate_valid:
            observation = _failure(
                test_id,
                "PVD candidate does not describe an official Codex subscription client",
                "PVD_ADAPTER_IDENTITY_MISMATCH",
            )
        elif not checks:
            observation = _failure(
                test_id,
                "PVD check implementation was not configured",
                "PVD_CHECK_MISSING",
            )
        elif len(checks) != 1:
            observation = _failure(
                test_id,
                "PVD check implementation is not unique",
                "PVD_CHECK_DUPLICATE",
            )
        elif test_id in _AUTOMATED_TEST_IDS and not _trusted_check_implementation(
            test_id, checks[0]
        ):
            observation = _failure(
                test_id,
                "Codex PVD evidence did not use the trusted concrete check",
                "CODEX_TRUSTED_CHECK_REQUIRED",
            )
        else:
            observation = await self._execute_bounded(
                test_id, checks[0], candidate, adapter
            )
        result, summary, payload = _validate_observation(test_id, observation)
        if test_id == "PVD-02" and result == "PASS":
            if not _valid_model_selection(
                payload,
                candidate=candidate,
                executable_sha256=self._executable_sha256,
            ):
                result = "FAIL"
                summary = (
                    "Codex model selection evidence did not satisfy the exact "
                    "binding checks"
                )
                payload = {"reason_code": "CODEX_MODEL_BINDING_UNPROVEN"}
        return self._commit_test(
            test_id,
            result,
            summary,
            payload,
            identity_digest,
            candidate,
        )

    async def _execute_bounded(
        self,
        test_id: CodexPVDTestId,
        check: CodexPVDCheck,
        candidate: ProviderValidationEvidence,
        adapter: object,
    ) -> CodexPVDCheckObservation:
        work = asyncio.create_task(check.execute(candidate, adapter))
        try:
            done, _pending = await asyncio.wait(
                (work,), timeout=self._per_check_timeout_ms / 1_000
            )
        except asyncio.CancelledError:
            work.cancel()
            await _bounded_cleanup(work)
            raise
        if not done:
            work.cancel()
            await _bounded_cleanup(work)
            return _failure(
                test_id,
                "PVD check exceeded its configured deadline",
                "PVD_CHECK_TIMED_OUT",
            )
        try:
            return work.result()
        except asyncio.CancelledError:
            return _failure(
                test_id,
                "PVD check was cancelled before producing evidence",
                "PVD_CHECK_CANCELLED",
            )
        except Exception:
            return _failure(
                test_id,
                "PVD check failed without safe evidence",
                "PVD_CHECK_FAILED",
            )

    def _terms_test(
        self,
        candidate: ProviderValidationEvidence,
        identity_digest: str,
        checked_at: datetime,
    ) -> ProviderValidationTest:
        approval = self._terms_approval
        if approval is None or not (
            approval.approved_at <= checked_at < approval.valid_until
        ):
            result: PVDResult = "FAIL"
            summary = "Current Codex subscription terms approval is missing or expired"
            payload: dict[str, object] = {
                "reason_code": "CODEX_TERMS_HUMAN_APPROVAL_REQUIRED"
            }
        else:
            result = "PASS"
            summary = "A human approved the exact Codex subscription use scope"
            payload = {
                "account_scope": approval.account_scope,
                "approved_at": approval.approved_at.isoformat(),
                "approved_by": approval.approved_by,
                "intended_use": approval.intended_use,
                "official_terms_url": approval.official_terms_url,
                "valid_until": approval.valid_until.isoformat(),
            }
        return self._commit_test(
            "PVD-15",
            result,
            summary,
            payload,
            identity_digest,
            candidate,
        )

    def _commit_test(
        self,
        test_id: str,
        result: PVDResult,
        summary: str,
        observation: dict[str, object],
        identity_digest: str,
        candidate: ProviderValidationEvidence,
    ) -> ProviderValidationTest:
        receipt = canonical_bytes(
            {
                "candidate_identity_sha256": identity_digest,
                "observation": observation,
                "result": result,
                "safe_summary": summary,
                "schema_version": "1.0.0",
                "test_id": test_id,
            }
        )
        evidence_ref = self._commit_checked(receipt, candidate)
        if evidence_ref is None:
            return ProviderValidationTest.model_validate(
                {
                    "test_id": test_id,
                    "result": "FAIL",
                    "evidence_refs": (),
                    "safe_summary": "PVD evidence could not be committed safely",
                }
            )
        return ProviderValidationTest.model_validate(
            {
                "test_id": test_id,
                "result": result,
                "evidence_refs": (evidence_ref,),
                "safe_summary": summary,
            }
        )

    def _commit_checked(
        self, receipt: bytes, candidate: ProviderValidationEvidence
    ) -> StoredDataRef | None:
        try:
            safe = redact_projected_json(receipt)
            if safe.categories or safe.data != receipt:
                return None
            staged = self._artifacts.stage_bytes(receipt, "application/json")
            ref = self._artifacts.commit(staged)
            if (
                ref.record_id is not None
                or ref.data_kind != "artifact"
                or ref.workspace_id != candidate.meta.workspace_id
                or ref.commit_id != candidate.meta.commit_id
                or ref.content_hash != hashlib.sha256(receipt).hexdigest()
            ):
                return None
            with self._artifacts.open_verified(ref) as stream:
                if stream.read() != receipt:
                    return None
            return ref
        except (LookupError, OSError, TypeError, ValueError):
            return None


def build_fail_closed_codex_pvd_runner(
    *,
    artifacts: ArtifactStore,
    clock: Clock,
    executable_sha256: str,
) -> CodexSubscriptionPVDProbeRunner:
    """Install the trusted PVD runner without manufacturing live observations.

    Production composition has the exact client binding but no scenario fixtures
    or durable invocation lineage at construction time.  Each automated test is
    therefore represented by the built-in fail-closed check until an exact
    trusted check can be supplied by the validation workflow.
    """

    checks = tuple(
        CodexUnprovenRuntimeCheck(
            test_id=test_id,
            reason_code="CODEX_RUNTIME_EVIDENCE_REQUIRED",
            safe_summary="Exact Codex runtime evidence was not supplied",
        )
        for test_id in _AUTOMATED_TEST_IDS
    )
    return CodexSubscriptionPVDProbeRunner(
        checks=checks,
        artifacts=artifacts,
        clock=clock,
        per_check_timeout_ms=1_000,
        executable_sha256=executable_sha256,
        terms_approval=None,
    )


def _valid_model_selection(
    payload: dict[str, object],
    *,
    candidate: ProviderValidationEvidence,
    executable_sha256: str,
) -> bool:
    limitation = payload.get("limitation")
    return (
        payload.get("executable_sha256") == executable_sha256
        and payload.get("explicit_model_argument") == candidate.model
        and payload.get("invalid_model_rejected") is True
        and payload.get("strict_structured_output_succeeded") is True
        and payload.get("output_schema_sha256") == _MODEL_OUTPUT_SCHEMA_SHA256
        and payload.get("provider_model_reported") is False
        and isinstance(limitation, str)
        and _MODEL_LIMITATION in limitation
    )


def _trusted_check_implementation(
    test_id: CodexPVDTestId, check: CodexPVDCheck
) -> bool:
    """Admit only the exact built-in implementation for each automated test."""

    if type(check) is CodexUnprovenRuntimeCheck:
        return check.test_id == test_id
    expected: dict[CodexPVDTestId, type[object]] = {
        "PVD-01": CodexAuthenticationPreflightCheck,
        "PVD-02": CodexModelSelectionCheck,
        "PVD-03": CodexStructuredOutputCheck,
        "PVD-04": CodexNewSessionIsolationCheck,
        "PVD-05": CodexResumeCapabilityCheck,
        "PVD-06": CodexParallelNewSessionCheck,
        "PVD-07": CodexTimeoutCancellationCheck,
        "PVD-08": CodexErrorClassificationCheck,
        "PVD-09": CodexRepairLifecycleCheck,
        "PVD-10": CodexFailoverLifecycleCheck,
        "PVD-11": CodexRedactionBoundaryCheck,
        "PVD-12": CodexObservationSurfaceCheck,
        "PVD-13": CodexClientIsolationCheck,
        "PVD-14": CodexEnvironmentBindingCheck,
    }
    return type(check) is expected.get(test_id)


def _exact_process_runner(
    candidate: ProviderValidationEvidence,
    adapter: object,
    request: CodexProcessRequest,
) -> _ExactCodexRunner | None:
    from .codex_subscription import CodexCliProcessRunner

    runner = getattr(adapter, "process_runner", None)
    if type(runner) is not CodexCliProcessRunner:
        return None
    if not _request_matches_candidate(request, candidate, adapter):
        return None
    bound_profile = getattr(getattr(runner, "binding", None), "provider_profile", None)
    try:
        executable_path = runner.executable.path
        approved_digest = runner.executable.sha256
        actual_digest = _sha256_file(executable_path)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if (
        bound_profile is None
        or approved_digest != actual_digest
        or not _is_sha256(actual_digest)
        or any(
            getattr(bound_profile, field, None) != getattr(candidate, field)
            for field in (
                "auth_mode",
                "client_name",
                "client_version",
                "environment",
                "model",
                "product",
                "profile_key",
                "provider",
                "transport",
            )
        )
    ):
        return None
    return cast(_ExactCodexRunner, runner)


def _request_matches_candidate(
    request: CodexProcessRequest,
    candidate: ProviderValidationEvidence,
    adapter: object,
) -> bool:
    return (
        request.model == candidate.model
        and getattr(adapter, "model", None) == candidate.model
        and request.provider_profile_ref
        == getattr(adapter, "provider_profile_ref", None)
        and request.timeout_ms > 0
        and bool(request.invocation_id.strip())
        and bool(request.prompt)
        and bool(request.output_schema)
    )


def _exact_invocation_adapter(
    candidate: ProviderValidationEvidence,
    adapter: object,
    request: LLMInvocationRequest,
) -> _ExactInvocationAdapter | None:
    from .codex_subscription import CodexSubscriptionAdapter

    if (
        not isinstance(adapter, CodexSubscriptionAdapter)
        or candidate.provider != "OPENAI"
        or candidate.product != "CODEX"
        or candidate.transport != "CODEX_CLIENT"
        or candidate.auth_mode != "SUBSCRIPTION_LOGIN"
        or adapter.model != candidate.model
        or request.model != candidate.model
        or request.provider_profile_ref != adapter.provider_profile_ref
    ):
        return None
    return cast(_ExactInvocationAdapter, adapter)


def _exact_live_invocation_adapter(
    candidate: ProviderValidationEvidence,
    adapter: object,
    request: LLMInvocationRequest,
) -> _ExactInvocationAdapter | None:
    """Require an invocation adapter backed by the exact hash-pinned client."""

    provider = _exact_invocation_adapter(candidate, adapter, request)
    runner = getattr(adapter, "process_runner", None)
    from .codex_subscription import CodexCliProcessRunner

    if provider is None or type(runner) is not CodexCliProcessRunner:
        return None
    bound_profile = getattr(getattr(runner, "binding", None), "provider_profile", None)
    if (
        bound_profile is None
        or getattr(runner.binding, "runtime_environment", None)
        != candidate.environment
        or any(
            getattr(bound_profile, field, None) != getattr(candidate, field)
            for field in (
                "auth_mode",
                "client_name",
                "client_version",
                "environment",
                "model",
                "product",
                "profile_key",
                "provider",
                "transport",
            )
        )
    ):
        return None
    try:
        if (
            runner.executable.sha256 != _sha256_file(runner.executable.path)
            or not _is_sha256(runner.executable.sha256)
        ):
            return None
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    return provider


def _same_exact_runner_binding(
    left: _ExactInvocationAdapter, right: _ExactInvocationAdapter
) -> bool:
    left_runner = left.process_runner
    right_runner = right.process_runner
    return (
        left_runner.executable == right_runner.executable
        and left_runner.binding.provider_profile
        == right_runner.binding.provider_profile
        and left_runner.binding.client_execution_profile
        == right_runner.binding.client_execution_profile
        and left_runner.binding.runtime_environment
        == right_runner.binding.runtime_environment
    )


def _resolve_runtime_trace(
    refs: CodexRuntimeCallTraceRefs | CodexRuntimeCallTrace,
    records: _RuntimeTraceRecords | None,
) -> CodexRuntimeCallTrace | None:
    if records is None or not isinstance(refs, CodexRuntimeCallTraceRefs):
        return None
    try:
        request = records.get_exact(refs.request_ref)
        result = records.get_exact(refs.result_ref)
        log = records.get_exact(refs.log_ref)
        if (
            not isinstance(request, LLMInvocationRequest)
            or not isinstance(result, LLMInvocationResult)
            or not isinstance(log, LLMInvocationLog)
            or reference(request) != refs.request_ref
            or reference(result) != refs.result_ref
            or reference(log) != refs.log_ref
        ):
            return None
        for record, ref in (
            (request, refs.request_ref),
            (result, refs.result_ref),
            (log, refs.log_ref),
        ):
            current = records.current_records(
                str(record.meta.analysis_id), record.meta.record_type
            )
            if not any(item == record and reference(item) == ref for item in current):
                return None
        return CodexRuntimeCallTrace(request=request, result=result, log=log)
    except (AttributeError, LookupError, TypeError, ValueError):
        return None


def _same_runtime_scope(
    left: CodexRuntimeCallTrace, right: CodexRuntimeCallTrace
) -> bool:
    scope = ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
    return all(
        getattr(left.request.meta, field) == getattr(right.request.meta, field)
        for field in scope
    ) and (
        left.request.agent_role,
        left.request.task_kind,
        left.request.purpose,
    ) == (
        right.request.agent_role,
        right.request.task_kind,
        right.request.purpose,
    )


def _resolve_runtime_provider(
    trace: CodexRuntimeCallTrace | None,
    records: _RuntimeTraceRecords | None,
) -> ProviderProfile | None:
    if trace is None or records is None:
        return None
    provider_ref = trace.request.provider_profile_ref
    try:
        provider = records.get_exact(provider_ref)
        if (
            not isinstance(provider, ProviderProfile)
            or reference(provider) != provider_ref
            or provider.model != trace.request.model
            or provider.provider != trace.result.provider
            or provider.provider != trace.log.provider
            or any(
                getattr(provider.meta, field) != getattr(trace.request.meta, field)
                for field in ("analysis_id", "workspace_id", "commit_id")
            )
        ):
            return None
        current = records.current_records(
            str(provider.meta.analysis_id), provider.meta.record_type
        )
        if not any(
            item == provider and reference(item) == provider_ref for item in current
        ):
            return None
        return provider
    except (AttributeError, LookupError, TypeError, ValueError):
        return None


def _provider_matches_candidate(
    provider: ProviderProfile, candidate: ProviderValidationEvidence
) -> bool:
    return all(
        getattr(provider, field) == getattr(candidate, field)
        for field in (
            "auth_mode",
            "client_name",
            "client_version",
            "environment",
            "model",
            "product",
            "profile_key",
            "provider",
            "transport",
        )
    )


def _valid_runtime_trace(trace: CodexRuntimeCallTrace) -> bool:
    request = trace.request
    result = trace.result
    log = trace.log
    scope = ("analysis_id", "workspace_id", "commit_id", "hypothesis_id", "attempt_id")
    return (
        request.llm_call_id == result.llm_call_id == log.llm_call_id
        and all(
            getattr(request.meta, field)
            == getattr(result.meta, field)
            == getattr(log.meta, field)
            for field in scope
        )
        and request.purpose == result.purpose == log.purpose
        and request.model == result.model == log.model
        and result.provider == log.provider
        and result.status == log.status
        and request.action_decision_ref == log.action_decision_ref
        and request.call_spec_ref == log.call_spec_ref
        and request.provider_profile_ref == log.provider_profile_ref
        and request.session_policy == log.session_policy
        and request.parent_session_ref == log.parent_session_ref
        and request.prompt_registry_entry_ref == log.prompt_registry_entry_ref
        and request.prompt_key == log.prompt_key
        and request.prompt_template_ref == log.prompt_template_ref
        and request.prompt_template_version == log.prompt_template_version
        and request.prompt_payload_ref == log.prompt_payload_ref
        and request.execution_limits_ref == log.execution_limits_ref
        and request.retry_policy_ref == log.retry_policy_ref
        and request.tool_policy_ref == log.tool_policy_ref
        and request.redaction_policy_ref == log.redaction_policy_ref
        and request.semantic_validator_ref == log.semantic_validator_ref
        and request.output_schema_ref == log.output_schema_ref
        and request.context_refs == log.context_refs
        and result.session_ref == log.session_ref
        and result.parsed_output_ref == log.parsed_output_ref
        and result.usage == log.usage
        and result.safe_error == log.safe_error
    )


def _canonical_json_document(value: bytes | None) -> bool:
    if value is None:
        return False
    try:
        parsed = json.loads(value)
    except (UnicodeError, json.JSONDecodeError, TypeError):
        return False
    return isinstance(parsed, (dict, list)) and canonical_bytes(parsed) == value


def _matches_success(result: CodexProcessResult, expected_output: bytes) -> bool:
    return (
        result.status == "SUCCEEDED"
        and result.final_message == expected_output
        and bool(result.provider_session_id)
        and _canonical_json_document(result.final_message)
    )


def _argv_pair(argv: tuple[str, ...], name: str, value: str) -> bool:
    return any(
        item == name and index + 1 < len(argv) and argv[index + 1] == value
        for index, item in enumerate(argv)
    )


def _validate_observation(
    test_id: CodexPVDTestId, observation: object
) -> tuple[PVDResult, str, dict[str, object]]:
    invalid = _failure(
        test_id,
        "PVD check returned invalid or unsafe evidence",
        "PVD_OBSERVATION_INVALID",
    )
    if not isinstance(observation, CodexPVDCheckObservation):
        observation = invalid
    if (
        observation.test_id != test_id
        or observation.result not in {"PASS", "FAIL"}
        or not observation.safe_summary.strip()
        or not observation.evidence
    ):
        observation = invalid
    try:
        summary = observation.safe_summary.encode("utf-8")
        summary_redaction = redact_untrusted_text(summary)
        evidence_redaction = redact_projected_json(observation.evidence)
        payload = json.loads(observation.evidence)
        if (
            summary_redaction.categories
            or summary_redaction.data != summary
            or evidence_redaction.categories
            or evidence_redaction.data != observation.evidence
            or not isinstance(payload, dict)
        ):
            raise ValueError("PVD_OBSERVATION_UNSAFE")
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        observation = _failure(
            test_id,
            "PVD check returned invalid or unsafe evidence",
            "PVD_OBSERVATION_UNSAFE",
        )
        payload = json.loads(observation.evidence)
    return (
        observation.result,
        observation.safe_summary,
        cast(dict[str, object], payload),
    )


def _index_checks(
    checks: tuple[CodexPVDCheck, ...],
) -> tuple[dict[CodexPVDTestId, tuple[CodexPVDCheck, ...]], bool]:
    indexed: dict[CodexPVDTestId, list[CodexPVDCheck]] = {
        test_id: [] for test_id in (*_AUTOMATED_TEST_IDS, _OPTIONAL_DYNAMIC_TEST_ID)
    }
    invalid = False
    for check in checks:
        try:
            test_id = check.test_id
        except (AttributeError, TypeError, ValueError):
            invalid = True
            continue
        if test_id not in indexed:
            invalid = True
            continue
        indexed[test_id].append(check)
    return {key: tuple(values) for key, values in indexed.items()}, invalid


def _candidate_identity_digest(candidate: ProviderValidationEvidence) -> str:
    return hashlib.sha256(
        canonical_bytes(
            {
                "auth_mode": candidate.auth_mode,
                "client_name": candidate.client_name,
                "client_version": candidate.client_version,
                "environment": candidate.environment,
                "model": candidate.model,
                "product": candidate.product,
                "profile_key": candidate.profile_key,
                "provider": candidate.provider,
                "transport": candidate.transport,
            }
        )
    ).hexdigest()


def _failure(
    test_id: CodexPVDTestId, summary: str, reason_code: str
) -> CodexPVDCheckObservation:
    return CodexPVDCheckObservation(
        test_id=test_id,
        result="FAIL",
        safe_summary=summary,
        evidence=canonical_bytes({"reason_code": reason_code}),
    )


def _is_sha256(value: str) -> bool:
    return (
        len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _explicit_model_argument(argv: tuple[str, ...]) -> str | None:
    positions = tuple(index for index, value in enumerate(argv) if value == "--model")
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        return None
    return argv[positions[0] + 1]


def _strict_probe_output(value: bytes | None) -> bool:
    if value is None:
        return False
    try:
        parsed = json.loads(value)
    except (UnicodeError, json.JSONDecodeError, TypeError):
        return False
    return parsed == {"status": "ok"} and canonical_bytes(parsed) == value


async def _bounded_cleanup(task: asyncio.Task[object]) -> None:
    if not task.done():
        done, _pending = await asyncio.wait(
            (task,), timeout=_CHECK_CLEANUP_TIMEOUT_SECONDS
        )
        if not done:
            task.add_done_callback(_consume_task_result)
            return
    _consume_task_result(task)


def _consume_task_result(task: asyncio.Task[object]) -> None:
    if not task.done() or task.cancelled():
        return
    try:
        task.result()
    except BaseException:
        return


__all__ = [
    "CodexAuthenticationPreflightCheck",
    "CodexClientIsolationCheck",
    "CodexEnvironmentBindingCheck",
    "CodexErrorClassificationCheck",
    "CodexFailoverLifecycleCheck",
    "CodexModelSelectionCheck",
    "CodexNewSessionIsolationCheck",
    "CodexObservationSurfaceCheck",
    "CodexParallelNewSessionCheck",
    "CodexPVDCheck",
    "CodexPVDCheckObservation",
    "CodexPVDTestId",
    "CodexRedactionBoundaryCheck",
    "CodexRepairLifecycleCheck",
    "CodexResumeCapabilityCheck",
    "CodexRuntimeCallTrace",
    "CodexRuntimeCallTraceRefs",
    "CodexStructuredOutputCheck",
    "CodexSubscriptionPVDProbeRunner",
    "CodexTermsApproval",
    "CodexTimeoutCancellationCheck",
    "CodexUnprovenRuntimeCheck",
    "build_fail_closed_codex_pvd_runner",
]
