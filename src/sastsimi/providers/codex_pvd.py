"""Fail-closed PVD evidence runner for the official Codex subscription client."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol, cast
from urllib.parse import urlsplit

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    ProviderValidationEvidence,
    ProviderValidationTest,
)
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import CapabilityProbeResult

from .base import CodexProcessRequest

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
    test_id: CodexPVDTestId

    async def execute(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CodexPVDCheckObservation: ...


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
            (_OPTIONAL_DYNAMIC_TEST_ID,)
            if checks[_OPTIONAL_DYNAMIC_TEST_ID]
            else ()
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
        elif test_id == "PVD-02" and not isinstance(
            checks[0], CodexModelSelectionCheck
        ):
            observation = _failure(
                test_id,
                "Codex model selection evidence did not use the trusted live check",
                "CODEX_MODEL_CHECK_REQUIRED",
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
        test_id: []
        for test_id in (*_AUTOMATED_TEST_IDS, _OPTIONAL_DYNAMIC_TEST_ID)
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
    "CodexModelSelectionCheck",
    "CodexPVDCheck",
    "CodexPVDCheckObservation",
    "CodexPVDTestId",
    "CodexSubscriptionPVDProbeRunner",
    "CodexTermsApproval",
]
