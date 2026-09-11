"""Trusted finalization for content-only Technical Gate output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import BinaryIO, Literal, Protocol

from pydantic import ValidationError

from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation


@dataclass(frozen=True)
class TechnicalCallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True)
class TechnicalAgentOutcome:
    review: TechnicalEvidenceReview
    invocation: PersistedLLMInvocation


class MetadataFactory(Protocol):
    def __call__(
        self, source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta: ...


class LLMCallInvoker(Protocol):
    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


class RecordStore(Protocol):
    def stage_record(self, record: Record) -> RecordRef: ...


class ArtifactReader(Protocol):
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...


class _TechnicalContent(ContractModel):
    status: Literal["ACCEPT", "REVISE", "REJECT"]
    evidence_verdict_alignment: NonEmptyStr
    code_flow_linkage: NonEmptyStr
    dynamic_linkage: NonEmptyStr
    cwe_assessment: NonEmptyStr
    restriction_assessment: NonEmptyStr
    revision_requests: tuple[NonEmptyStr, ...]
    verification_requests: tuple[NonEmptyStr, ...]
    rationale: NonEmptyStr


class TechnicalGateAgent:
    """Invoke the Technical Gate prompt without accepting runtime-owned fields."""

    def __init__(
        self,
        *,
        llm_calls: LLMCallInvoker,
        records: RecordStore,
        artifacts: ArtifactReader,
        metadata_factory: MetadataFactory,
    ) -> None:
        self._llm_calls = llm_calls
        self._records = records
        self._artifacts = artifacts
        self._metadata = metadata_factory

    async def review(
        self,
        *,
        work: WorkExecutionState,
        verification_ref: StoredDataRef,
        cwe_label_ref: StoredDataRef,
        required_context: tuple[StoredDataRef, ...],
        call: TechnicalCallRefs,
    ) -> TechnicalAgentOutcome:
        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        payload = self._payload(
            invocation,
            work=work,
            call=call,
            required_context=required_context,
        )
        try:
            content = _TechnicalContent.model_validate_json(canonical_bytes(payload))
        except ValidationError as error:
            raise ValueError("TECHNICAL_OUTPUT_INVALID") from error
        review = TechnicalEvidenceReview.model_validate(
            {
                "meta": self._trusted_meta(work, "technical_evidence_review"),
                "action_decision_ref": invocation.request.action_decision_ref,
                "verification_result_ref": verification_ref,
                "cwe_label_ref": cwe_label_ref,
                "status": content.status,
                "evidence_verdict_alignment": content.evidence_verdict_alignment,
                "code_flow_linkage": content.code_flow_linkage,
                "dynamic_linkage": content.dynamic_linkage,
                "cwe_assessment": content.cwe_assessment,
                "restriction_assessment": content.restriction_assessment,
                "handoff_readiness": (
                    "READY" if content.status == "ACCEPT" else "NOT_READY"
                ),
                "revision_requests": content.revision_requests,
                "verification_requests": content.verification_requests,
                "rationale": content.rationale,
            }
        )
        self._stage_exact(review)
        return TechnicalAgentOutcome(review, invocation)

    def _payload(
        self,
        invocation: PersistedLLMInvocation,
        *,
        work: WorkExecutionState,
        call: TechnicalCallRefs,
        required_context: tuple[StoredDataRef, ...],
    ) -> object:
        request, result = invocation.request, invocation.result
        if (
            result.status != "SUCCEEDED"
            or result.parsed_output_ref is None
            or result.response_ref != result.parsed_output_ref
        ):
            raise ValueError("LLM_INVOCATION_NOT_SUCCEEDED")
        if (
            not isinstance(work.meta, RecordMeta)
            or not isinstance(request.meta, RecordMeta)
            or not isinstance(result.meta, RecordMeta)
            or request.agent_role != "TECHNICAL_GATE"
            or request.task_kind != "REVIEW_TECHNICAL"
            or request.call_spec_ref != call.call_spec_ref
            or request.action_decision_ref.data_kind != "action_decision"
            or request.action_decision_ref.workspace_id != work.meta.workspace_id
            or request.action_decision_ref.commit_id != work.meta.commit_id
            or request.llm_call_id != result.llm_call_id
            or request.meta.attempt_id != work.active_attempt_id
            or result.meta.attempt_id != work.active_attempt_id
            or request.meta.analysis_id != work.meta.analysis_id
            or request.meta.workspace_id != work.meta.workspace_id
            or request.meta.commit_id != work.meta.commit_id
            or request.meta.hypothesis_id != work.meta.hypothesis_id
            or result.meta.analysis_id != work.meta.analysis_id
            or result.meta.workspace_id != work.meta.workspace_id
            or result.meta.commit_id != work.meta.commit_id
            or result.meta.hypothesis_id != work.meta.hypothesis_id
            or not self._authorized_context(
                request.context_refs, required_context, work
            )
        ):
            raise ValueError("TECHNICAL_INVOCATION_CLOSURE_MISMATCH")
        try:
            with self._artifacts.open_verified(result.parsed_output_ref) as stream:
                raw = stream.read()
            payload = json.loads(raw)
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("TECHNICAL_OUTPUT_ARTIFACT_INVALID") from error
        if not isinstance(payload, dict) or canonical_bytes(payload) != raw:
            raise ValueError("TECHNICAL_OUTPUT_ARTIFACT_INVALID")
        return payload

    @staticmethod
    def _authorized_context(
        actual: tuple[StoredDataRef, ...],
        required: tuple[StoredDataRef, ...],
        work: WorkExecutionState,
    ) -> bool:
        if len(actual) != len(set(actual)) or len(required) != len(set(required)):
            return False
        required_set = set(required)
        allowed = required_set | {
            ref for ref in work.input_refs if isinstance(ref, StoredDataRef)
        }
        actual_set = set(actual)
        return required_set.issubset(actual_set) and actual_set.issubset(allowed)

    def _trusted_meta(self, work: WorkExecutionState, kind: str) -> RecordMeta:
        assert isinstance(work.meta, RecordMeta)
        meta = self._metadata(work.meta, kind, work.active_attempt_id)
        if (
            meta.record_type != kind
            or meta.attempt_id != work.active_attempt_id
            or meta.analysis_id != work.meta.analysis_id
            or meta.workspace_id != work.meta.workspace_id
            or meta.commit_id != work.meta.commit_id
            or meta.hypothesis_id != work.meta.hypothesis_id
        ):
            raise ValueError("RUNTIME_METADATA_SCOPE_MISMATCH")
        return meta

    def _stage_exact(self, record: Record) -> None:
        if self._records.stage_record(record) != reference(record):
            raise ValueError("DOMAIN_RECORD_STAGE_MISMATCH")


__all__ = ["TechnicalAgentOutcome", "TechnicalCallRefs", "TechnicalGateAgent"]
