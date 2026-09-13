"""Trusted finalization for content-only CWE Labeling output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import BinaryIO, Protocol

from pydantic import ValidationError, model_validator

from sastsimi.contracts.actions import ActionType, RequesterRole
from sastsimi.contracts.base import ContractModel, NonEmptyStr, NonNegativeInt
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.gates import CWELabel
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkType
from sastsimi.ports.dto import Record
from sastsimi.ports.llm_invocation import (
    LLMInvocationExpectation,
    LLMInvocationProvenanceValidator,
    PersistedLLMInvocation,
)


@dataclass(frozen=True)
class CWECallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True)
class CWEAgentOutcome:
    label: CWELabel
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

    def get_exact(self, ref: RecordRef) -> object: ...


class ArtifactReader(Protocol):
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...


class _CWEContent(ContractModel):
    primary: NonEmptyStr | None
    alternatives: tuple[NonEmptyStr, ...]
    rationale: NonEmptyStr
    evidence_indexes: tuple[NonNegativeInt, ...]
    uncertainty: NonEmptyStr | None

    @model_validator(mode="after")
    def unique_selection(self) -> _CWEContent:
        if len(self.evidence_indexes) != len(set(self.evidence_indexes)):
            raise ValueError("duplicate evidence index")
        return self


class CWELabelingAgent:
    """Invoke the CWE prompt and inject every authoritative field at runtime."""

    def __init__(
        self,
        *,
        llm_calls: LLMCallInvoker,
        records: RecordStore,
        artifacts: ArtifactReader,
        metadata_factory: MetadataFactory,
        provenance_validator: LLMInvocationProvenanceValidator,
    ) -> None:
        self._llm_calls = llm_calls
        self._records = records
        self._artifacts = artifacts
        self._metadata = metadata_factory
        self._validate_provenance = provenance_validator

    async def classify(
        self,
        *,
        work: WorkExecutionState,
        verification_ref: StoredDataRef,
        verification_generation: int,
        taxonomy_version: str,
        allowed_evidence: tuple[StoredDataRef, ...],
        required_context: tuple[StoredDataRef, ...],
        requester_identity_ref: BudgetScopeRef,
        call: CWECallRefs,
    ) -> CWEAgentOutcome:
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
            requester_identity_ref=requester_identity_ref,
        )
        try:
            content = _CWEContent.model_validate_json(canonical_bytes(payload))
        except ValidationError as error:
            raise ValueError("CWE_OUTPUT_INVALID") from error
        try:
            evidence_refs = tuple(
                allowed_evidence[index] for index in content.evidence_indexes
            )
        except IndexError as error:
            raise ValueError("CWE_EVIDENCE_INDEX_INVALID") from error
        if not evidence_refs:
            raise ValueError("CWE_EVIDENCE_REQUIRED")
        label = CWELabel.model_validate(
            {
                "meta": self._trusted_meta(work, "cwe_label"),
                "verification_result_ref": verification_ref,
                "verification_generation": verification_generation,
                "cwe_labeling_work_id": work.work_id,
                "llm_call_id": invocation.request.llm_call_id,
                "primary": content.primary,
                "alternatives": content.alternatives,
                "taxonomy_version": taxonomy_version,
                "rationale": content.rationale,
                "evidence_refs": evidence_refs,
                "uncertainty": content.uncertainty,
            }
        )
        self._stage_exact(label)
        return CWEAgentOutcome(label, invocation)

    def _payload(
        self,
        invocation: PersistedLLMInvocation,
        *,
        work: WorkExecutionState,
        call: CWECallRefs,
        required_context: tuple[StoredDataRef, ...],
        requester_identity_ref: BudgetScopeRef,
    ) -> object:
        request, result = invocation.request, invocation.result
        self._validate_provenance(
            records=self._records,
            work=work,
            issued_decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            invocation=invocation,
            expectation=LLMInvocationExpectation(
                work_type=WorkType.CWE_LABEL,
                action_type=ActionType.CALL_LLM,
                requested_by=RequesterRole.CWE_LABELING,
                requester_identity_ref=requester_identity_ref,
                agent_role="CWE_LABELING",
                task_kind="CLASSIFY_CWE",
                required_context=required_context,
            ),
        )
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
            or request.agent_role != "CWE_LABELING"
            or request.task_kind != "CLASSIFY_CWE"
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
            raise ValueError("CWE_INVOCATION_CLOSURE_MISMATCH")
        try:
            with self._artifacts.open_verified(result.parsed_output_ref) as stream:
                raw = stream.read()
            payload = json.loads(raw)
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("CWE_OUTPUT_ARTIFACT_INVALID") from error
        if not isinstance(payload, dict) or canonical_bytes(payload) != raw:
            raise ValueError("CWE_OUTPUT_ARTIFACT_INVALID")
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


__all__ = ["CWEAgentOutcome", "CWECallRefs", "CWELabelingAgent"]
