"""Deterministic reference-only fake; invocation is wrapped by runtime dispatch."""

from collections.abc import Mapping
from datetime import timedelta
from types import MappingProxyType

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import RecordId, StoredDataId
from sastsimi.contracts.llm import ProviderValidationEvidence
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.ports.dto import (
    BoundaryRecord,
    CancellationResult,
    CapabilityProbeResult,
    LLMInvocationRequest,
    LLMInvocationResult,
)


class FakeProviderAdapter:
    def __init__(self, results: Mapping[RecordRef, LLMInvocationResult]) -> None:
        self.results = MappingProxyType(dict(results))
        self._probe_fixture: tuple[RecordRef, LLMInvocationResult] | None = None

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        request_ref = (
            request.ref if isinstance(request, BoundaryRecord) else reference(request)
        )
        if self._probe_fixture is not None and request_ref == self._probe_fixture[0]:
            return self._probe_fixture[1]
        try:
            return self.results[request_ref]
        except KeyError as error:
            raise ValueError("FAKE_INVOCATION_NOT_CONFIGURED") from error

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        probe_ref = self._probe_ref(candidate, "probe-payload")
        request = LLMInvocationRequest.model_validate(
            {
                "meta": candidate.meta.model_copy(
                    update={
                        "record_id": f"{candidate.meta.record_id}-probe-request",
                        "logical_record_id": (
                            f"{candidate.meta.logical_record_id}-probe-request"
                        ),
                        "record_type": "llm_invocation_request",
                    }
                ),
                "llm_call_id": f"probe-{candidate.meta.record_id}",
                "action_decision_ref": self._probe_ref(candidate, "action_decision"),
                "call_spec_ref": self._probe_ref(candidate, "llm_call_spec"),
                "agent_role": "VERIFICATION",
                "task_kind": "PROVIDER_PROBE",
                "purpose": "EVALUATION",
                "provider_profile_ref": self._probe_ref(candidate, "provider_profile"),
                "model": candidate.model,
                "session_policy": "NEW",
                "parent_session_ref": None,
                "context_refs": (probe_ref,),
                "prompt_registry_entry_ref": self._probe_ref(
                    candidate, "prompt_registry_entry"
                ),
                "prompt_key": "deterministic-provider-probe",
                "prompt_template_ref": probe_ref,
                "prompt_template_version": "1",
                "prompt_payload_ref": self._probe_ref(candidate, "prompt_payload"),
                "execution_limits_ref": self._probe_ref(candidate, "execution_limits"),
                "retry_policy_ref": self._probe_ref(candidate, "llm_retry_policy"),
                "tool_policy_ref": self._probe_ref(candidate, "llm_tool_policy"),
                "redaction_policy_ref": self._probe_ref(
                    candidate, "prompt_redaction_policy"
                ),
                "semantic_validator_ref": self._probe_ref(
                    candidate, "semantic_validator_spec"
                ),
                "output_schema_ref": self._probe_ref(candidate, "output_schema_spec"),
                "output_schema": "{}",
                "token_budget": 1,
                "timeout_ms": 1_000,
            }
        )
        expected = LLMInvocationResult.model_validate(
            {
                "meta": candidate.meta.model_copy(
                    update={
                        "record_id": f"{candidate.meta.record_id}-probe-result",
                        "logical_record_id": (
                            f"{candidate.meta.logical_record_id}-probe-result"
                        ),
                        "record_type": "llm_invocation_result",
                    }
                ),
                "llm_call_id": request.llm_call_id,
                "purpose": "EVALUATION",
                "status": "SUCCEEDED",
                "provider": candidate.provider,
                "model": candidate.model,
                "actual_session_mode": "NEW",
                "session_ref": f"probe-session-{candidate.meta.record_id}",
                "response_ref": probe_ref,
                "parsed_output_ref": probe_ref,
                "usage": None,
                "started_at": candidate.checked_at,
                "finished_at": candidate.checked_at + timedelta(milliseconds=1),
                "elapsed_ms": 1,
                "safe_error": None,
            }
        )
        outcomes: dict[str, bool] = {}
        failure_fixtures = {
            "PVD-01": "AUTH_REQUIRED",
            "PVD-07": "TIMED_OUT",
            "PVD-08": "RATE_LIMITED",
            "PVD-09": "INVALID_OUTPUT",
            "PVD-10": "FAILED",
        }
        for test in candidate.tests:
            call_id = f"{request.llm_call_id}-{test.test_id}"
            fixture_request = request.model_copy(update={"llm_call_id": call_id})
            status = failure_fixtures.get(test.test_id, "SUCCEEDED")
            fixture_result = LLMInvocationResult.model_validate(
                expected.model_dump()
                | {
                    "llm_call_id": call_id,
                    "session_ref": f"probe-session-{call_id}",
                    "status": status,
                    "safe_error": None
                    if status == "SUCCEEDED"
                    else "Deterministic local error fixture",
                }
            )
            self._probe_fixture = (reference(fixture_request), fixture_result)
            try:
                observed = await self.invoke(fixture_request)
                outcomes[test.test_id] = observed == fixture_result
            except Exception:
                outcomes[test.test_id] = False
            finally:
                self._probe_fixture = None
        # Unsupported controls are exercised as negative fixtures, never promoted.
        try:
            cancellation = await self.cancel(request.llm_call_id)
            outcomes["PVD-07"] = outcomes.get("PVD-07", False) and (
                not cancellation.cancelled and cancellation.reason is not None
            )
            await self.invoke(
                request.model_copy(
                    update={
                        "session_policy": "RESUME",
                        "parent_session_ref": "unsupported-parent",
                    }
                )
            )
        except ValueError as error:
            outcomes["PVD-05"] = (
                outcomes.get("PVD-05", False)
                and str(error) == "FAKE_INVOCATION_NOT_CONFIGURED"
            )
        except Exception:
            outcomes["PVD-05"] = False
        else:
            outcomes["PVD-05"] = False
        tests = tuple(
            test.model_copy(
                update={
                    "result": (
                        "FAIL"
                        if not outcomes.get(test.test_id, False)
                        else "NOT_APPLICABLE"
                        if test.test_id == "PVD-13"
                        else "PASS"
                    ),
                    "safe_summary": (
                        "Deterministic fake adapter invoke probe failed"
                        if not outcomes.get(test.test_id, False)
                        else "API subscription isolation is not applicable"
                        if test.test_id == "PVD-13"
                        else f"Observed {test.test_id} local fixture passed"
                    ),
                }
            )
            for test in candidate.tests
        )
        evidence = candidate.model_copy(update={"tests": tests})
        return CapabilityProbeResult(evidence=evidence)

    @staticmethod
    def _probe_ref(candidate: ProviderValidationEvidence, label: str) -> StoredDataRef:
        return StoredDataRef(
            stored_data_id=StoredDataId(f"{candidate.meta.record_id}-{label}"),
            data_kind=label,
            record_id=RecordId(f"{candidate.meta.record_id}-{label}-record"),
            content_hash=content_hash(
                [str(candidate.meta.record_id), label, candidate.model]
            ),
            workspace_id=candidate.meta.workspace_id,
            commit_id=candidate.meta.commit_id,
        )

    async def cancel(self, invocation_id: str) -> CancellationResult:
        return CancellationResult(False, "No asynchronous external fake process exists")
