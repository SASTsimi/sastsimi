"""Bounded Provider Verification Dataset runner for OpenAI Responses."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from typing import Literal, Protocol, cast

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

from .openai_api import OpenAIResponsesApiAdapter

type PVDTestId = Literal[
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
    "PVD-15",
]
type PVDResult = Literal["PASS", "FAIL", "NOT_APPLICABLE"]

_PVD_TEST_IDS: tuple[PVDTestId, ...] = (
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
    "PVD-15",
)
_CHECK_CLEANUP_TIMEOUT_SECONDS = 0.1
_MAX_CHECK_TIMEOUT_MS = 300_000


@dataclass(frozen=True)
class OpenAIPVDCheckObservation:
    test_id: PVDTestId
    result: PVDResult
    safe_summary: str
    evidence: bytes


class OpenAIPVDCheck(Protocol):
    test_id: PVDTestId

    async def execute(
        self,
        candidate: ProviderValidationEvidence,
        adapter: OpenAIResponsesApiAdapter,
    ) -> OpenAIPVDCheckObservation: ...


class OpenAIResponsesPVDProbeRunner:
    """Run all API PVD checks and replace caller assertions with new receipts.

    Check implementations own their real provider/runtime scenario.  This runner
    owns the trust boundary around their observations: every required check is
    awaited, bounded, identity-bound, secret-scanned and committed as a new
    artifact.  A caller-supplied PASS or evidence reference is never reused.
    """

    def __init__(
        self,
        *,
        checks: tuple[OpenAIPVDCheck, ...],
        artifacts: ArtifactStore,
        clock: Clock,
        per_check_timeout_ms: int,
    ) -> None:
        if (
            isinstance(per_check_timeout_ms, bool)
            or per_check_timeout_ms < 1
            or per_check_timeout_ms > _MAX_CHECK_TIMEOUT_MS
        ):
            raise ValueError("OPENAI_PVD_TIMEOUT_INVALID")
        self._checks = checks
        self._artifacts = artifacts
        self._clock = clock
        self._per_check_timeout_ms = per_check_timeout_ms

    async def run(
        self,
        candidate: ProviderValidationEvidence,
        adapter: object,
    ) -> CapabilityProbeResult:
        candidate = ProviderValidationEvidence.model_validate(candidate)
        identity_digest = _candidate_identity_digest(candidate)
        checks, invalid_configuration = _index_checks(self._checks)
        adapter_valid = (
            isinstance(adapter, OpenAIResponsesApiAdapter)
            and candidate.provider == "OPENAI"
            and candidate.product == "OPENAI_API"
            and candidate.transport == "RESPONSES_API"
            and candidate.auth_mode == "API_KEY"
            and adapter.model == candidate.model
        )

        tasks = tuple(
            asyncio.create_task(
                self._run_test(
                    test_id,
                    candidate,
                    cast(OpenAIResponsesApiAdapter, adapter)
                    if adapter_valid
                    else None,
                    checks.get(test_id, ()),
                    identity_digest,
                    invalid_configuration=invalid_configuration,
                )
            )
            for test_id in _PVD_TEST_IDS
        )
        try:
            tests = tuple(await asyncio.gather(*tasks))
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        checked_at = self._clock.now()
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise ValueError("OPENAI_PVD_CLOCK_INVALID")
        evidence = ProviderValidationEvidence.model_validate(
            candidate.model_copy(
                update={
                    "tests": tests,
                    "checked_at": checked_at,
                }
            )
        )
        return CapabilityProbeResult(evidence=evidence)

    async def _run_test(
        self,
        test_id: PVDTestId,
        candidate: ProviderValidationEvidence,
        adapter: OpenAIResponsesApiAdapter | None,
        checks: tuple[OpenAIPVDCheck, ...],
        identity_digest: str,
        *,
        invalid_configuration: bool,
    ) -> ProviderValidationTest:
        if invalid_configuration:
            outcome = _failure_outcome(
                test_id,
                "PVD check configuration contains an unknown test",
                "PVD_CHECK_CONFIGURATION_INVALID",
            )
        elif adapter is None:
            outcome = _failure_outcome(
                test_id,
                "PVD candidate does not match the OpenAI Responses adapter",
                "PVD_ADAPTER_IDENTITY_MISMATCH",
            )
        elif not checks:
            outcome = _failure_outcome(
                test_id,
                "PVD check implementation was not configured",
                "PVD_CHECK_MISSING",
            )
        elif len(checks) != 1:
            outcome = _failure_outcome(
                test_id,
                "PVD check implementation is not unique",
                "PVD_CHECK_DUPLICATE",
            )
        else:
            outcome = await self._execute_bounded(
                test_id, checks[0], candidate, adapter
            )

        result, summary, observation = _validate_observation(test_id, outcome)
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

    async def _execute_bounded(
        self,
        test_id: PVDTestId,
        check: OpenAIPVDCheck,
        candidate: ProviderValidationEvidence,
        adapter: OpenAIResponsesApiAdapter,
    ) -> OpenAIPVDCheckObservation:
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
            return _failure_outcome(
                test_id,
                "PVD check exceeded its configured deadline",
                "PVD_CHECK_TIMED_OUT",
            )
        try:
            return work.result()
        except asyncio.CancelledError:
            return _failure_outcome(
                test_id,
                "PVD check was cancelled before producing evidence",
                "PVD_CHECK_CANCELLED",
            )
        except Exception:
            return _failure_outcome(
                test_id,
                "PVD check failed without safe evidence",
                "PVD_CHECK_FAILED",
            )

    def _commit_checked(
        self, receipt: bytes, candidate: ProviderValidationEvidence
    ) -> StoredDataRef | None:
        try:
            safe_receipt = redact_projected_json(receipt)
            if safe_receipt.categories or safe_receipt.data != receipt:
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


def _index_checks(
    checks: tuple[OpenAIPVDCheck, ...],
) -> tuple[dict[PVDTestId, tuple[OpenAIPVDCheck, ...]], bool]:
    indexed: dict[PVDTestId, list[OpenAIPVDCheck]] = {
        test_id: [] for test_id in _PVD_TEST_IDS
    }
    invalid_configuration = False
    for check in checks:
        try:
            test_id = check.test_id
        except (AttributeError, TypeError, ValueError):
            invalid_configuration = True
            continue
        if test_id not in indexed:
            invalid_configuration = True
            continue
        indexed[test_id].append(check)
    return {test_id: tuple(values) for test_id, values in indexed.items()}, (
        invalid_configuration
    )


def _candidate_identity_digest(candidate: ProviderValidationEvidence) -> str:
    identity = canonical_bytes(
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
    return hashlib.sha256(identity).hexdigest()


def _failure_outcome(
    test_id: PVDTestId, summary: str, reason_code: str
) -> OpenAIPVDCheckObservation:
    return OpenAIPVDCheckObservation(
        test_id=test_id,
        result="FAIL",
        safe_summary=summary,
        evidence=canonical_bytes({"reason_code": reason_code}),
    )


def _validate_observation(
    test_id: PVDTestId, observation: object
) -> tuple[PVDResult, str, dict[str, object]]:
    invalid = _failure_outcome(
        test_id,
        "PVD check returned invalid or unsafe evidence",
        "PVD_OBSERVATION_INVALID",
    )
    if not isinstance(observation, OpenAIPVDCheckObservation):
        observation = invalid
    if (
        observation.test_id != test_id
        or observation.result not in {"PASS", "FAIL", "NOT_APPLICABLE"}
        or not isinstance(observation.safe_summary, str)
        or not observation.safe_summary.strip()
        or not isinstance(observation.evidence, bytes)
        or not observation.evidence
    ):
        observation = invalid
    if (test_id == "PVD-13") != (observation.result == "NOT_APPLICABLE"):
        observation = _failure_outcome(
            test_id,
            "PVD result is not valid for the OpenAI API transport",
            "PVD_RESULT_INVALID",
        )
    try:
        summary_redaction = redact_untrusted_text(
            observation.safe_summary.encode("utf-8")
        )
        evidence_redaction = redact_projected_json(observation.evidence)
        evidence = json.loads(observation.evidence)
        if (
            summary_redaction.categories
            or summary_redaction.data != observation.safe_summary.encode("utf-8")
            or evidence_redaction.categories
            or evidence_redaction.data != observation.evidence
            or not isinstance(evidence, dict)
        ):
            raise ValueError("PVD_OBSERVATION_UNSAFE")
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        observation = _failure_outcome(
            test_id,
            "PVD check returned invalid or unsafe evidence",
            "PVD_OBSERVATION_UNSAFE",
        )
        evidence = json.loads(observation.evidence)
    return (
        observation.result,
        observation.safe_summary,
        cast(dict[str, object], evidence),
    )


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
    "OpenAIPVDCheck",
    "OpenAIPVDCheckObservation",
    "OpenAIResponsesPVDProbeRunner",
    "PVDResult",
    "PVDTestId",
]
