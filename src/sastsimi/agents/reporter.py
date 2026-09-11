"""Trusted finalization for content-only Reporter Agent output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts._domain import DomainRecord
from sastsimi.contracts.actions import ActionType, RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.gates import RuleScopeImpactReview, TechnicalEvidenceReview
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.reporting import (
    Finding,
    FindingIndexState,
    ReportDraft,
    validate_finding_conditions,
    validate_report_closure,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.record_store import RecordStore
from sastsimi.reporting.content_validation import ReportContent, validate_report_content
from sastsimi.reporting.readiness import ReportingReadinessService
from sastsimi.runtime.llm_call_service import (
    InvocationMetadataFactory,
    PersistedLLMInvocation,
)
from sastsimi.runtime.llm_invocation_provenance import (
    LLMInvocationExpectation,
    validate_llm_invocation_provenance,
)


class LLMCallInvoker(Protocol):
    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


@dataclass(frozen=True)
class ReporterCallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True)
class ReporterInputs:
    finding_ref: StoredDataRef
    finding_index_ref: StoredDataRef
    verification_ref: StoredDataRef
    technical_review_ref: StoredDataRef
    rule_scope_review_ref: StoredDataRef
    run_policy_state_ref: StoredDataRef
    condition_records: tuple[tuple[StoredDataRef, DomainRecord], ...]


@dataclass(frozen=True)
class ReporterOutcome:
    draft: ReportDraft
    draft_ref: StoredDataRef
    invocation: PersistedLLMInvocation
    save_input_refs: tuple[RecordRef, ...]


class ReporterAgent:
    """Create an internal draft; submission and disclosure are intentionally absent."""

    def __init__(
        self,
        *,
        llm_calls: LLMCallInvoker,
        records: RecordStore,
        artifacts: ArtifactStore,
        metadata_factory: InvocationMetadataFactory,
        identity_ref: BudgetScopeRef,
        readiness: ReportingReadinessService | None = None,
    ) -> None:
        self._llm_calls = llm_calls
        self._records = records
        self._artifacts = artifacts
        self._metadata = metadata_factory
        self._identity_ref = identity_ref
        self._readiness = readiness or ReportingReadinessService()

    async def create_draft(
        self,
        *,
        work: WorkExecutionState,
        inputs: ReporterInputs,
        call: ReporterCallRefs,
    ) -> ReporterOutcome:
        self._require_running(work)
        finding = self._exact(inputs.finding_ref, Finding)
        index = self._exact(inputs.finding_index_ref, FindingIndexState)
        verification = self._exact(inputs.verification_ref, VerificationResult)
        technical = self._exact(inputs.technical_review_ref, TechnicalEvidenceReview)
        scope = self._exact(inputs.rule_scope_review_ref, RuleScopeImpactReview)
        state = self._exact(inputs.run_policy_state_ref, RunPolicyState)
        condition_refs = tuple(ref for ref, _ in inputs.condition_records)
        if len(set(condition_refs)) != len(condition_refs):
            raise ValueError("REPORT_CONDITION_INPUT_DUPLICATED")
        expected_inputs = {
            inputs.finding_ref,
            inputs.finding_index_ref,
            inputs.verification_ref,
            finding.dynamic_result_ref,
            finding.poc_ref,
            finding.cwe_label_ref,
            inputs.technical_review_ref,
            inputs.rule_scope_review_ref,
            inputs.run_policy_state_ref,
            finding.policy_collection_result_ref,
            *condition_refs,
        }
        if finding.policy_record_ref is not None:
            expected_inputs.add(finding.policy_record_ref)
        if (
            len(set(work.input_refs)) != len(work.input_refs)
            or set(work.input_refs) != expected_inputs
        ):
            raise ValueError("REPORT_WORK_INPUT_CLOSURE_MISMATCH")
        readiness = self._readiness.evaluate(
            finding=finding,
            index=index,
            verification=verification,
            technical=technical,
            scope=scope,
            policy_state=state,
        )
        if not readiness.ready:
            raise ValueError("REPORT_NOT_READY:" + ",".join(readiness.reasons))

        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        content, claimed_decision_ref, save_input_refs = self._content(
            invocation, work=work, call=call
        )
        allowed_locations = tuple(
            location
            for claim in (
                *verification.supporting_evidence,
                *verification.counter_evidence,
            )
            for location in claim.code_locations
        )
        safe_content = validate_report_content(
            content.model_dump(mode="json"), allowed_locations=allowed_locations
        )
        content_ref = self._artifacts.commit(
            self._artifacts.stage_bytes(safe_content, "application/json")
        )
        restrictions, limitations, unresolved = validate_finding_conditions(
            finding, tuple(inputs.condition_records)
        )
        meta = self._metadata(
            self._record_meta(work), "report_draft", work.active_attempt_id
        )
        draft = ReportDraft(
            meta=meta,
            action_decision_ref=claimed_decision_ref,
            finding_ref=inputs.finding_ref,
            verification_result_ref=inputs.verification_ref,
            technical_review_ref=inputs.technical_review_ref,
            rule_scope_impact_review_ref=inputs.rule_scope_review_ref,
            cwe_label_ref=finding.cwe_label_ref,
            run_policy_state_ref=inputs.run_policy_state_ref,
            policy_record_ref=self._policy_ref(finding),
            dynamic_result_ref=finding.dynamic_result_ref,
            poc_ref=finding.poc_ref,
            content_ref=content_ref,
            restrictions=restrictions,
            limitations=limitations,
            unresolved_conditions=unresolved,
            redaction_status="PASSED",
            draft_status="DRAFTED",
        )
        validate_report_closure(
            draft,
            finding,
            index,
            verification,
            technical,
            scope,
            state,
            content_locations=content.citations,
            condition_records=tuple(inputs.condition_records),
        )
        staged = self._records.stage_record(draft)
        if not isinstance(staged, StoredDataRef) or staged != reference(draft):
            raise ValueError("REPORT_DRAFT_STAGE_MISMATCH")
        return ReporterOutcome(draft, staged, invocation, save_input_refs)

    def _content(
        self,
        invocation: PersistedLLMInvocation,
        *,
        work: WorkExecutionState,
        call: ReporterCallRefs,
    ) -> tuple[ReportContent, StoredDataRef, tuple[RecordRef, ...]]:
        result = invocation.result
        validated = validate_llm_invocation_provenance(
            records=self._records,
            work=work,
            issued_decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            invocation=invocation,
            expectation=LLMInvocationExpectation(
                work_type=WorkType.REPORT_DRAFT,
                action_type=ActionType.CREATE_REPORT_DRAFT,
                requested_by=RequesterRole.REPORTER,
                requester_identity_ref=self._identity_ref,
                agent_role="REPORTER",
                task_kind="CREATE_DRAFT",
                required_context=work.input_refs,
            ),
        )
        if not isinstance(result.parsed_output_ref, StoredDataRef):
            raise ValueError("REPORTER_INVOCATION_CLOSURE_MISMATCH")
        try:
            with self._artifacts.open_verified(result.parsed_output_ref) as stream:
                raw = stream.read()
            content = ReportContent.model_validate_json(raw)
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("REPORTER_OUTPUT_ARTIFACT_INVALID") from error
        if canonical_bytes(content) != raw:
            raise ValueError("REPORTER_OUTPUT_ARTIFACT_INVALID")
        claimed_ref = reference(validated.claimed_decision)
        if not isinstance(claimed_ref, StoredDataRef):
            raise ValueError("REPORTER_INVOCATION_CLOSURE_MISMATCH")
        return content, claimed_ref, validated.save_input_refs

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:
            raise ValueError("REPORT_UPSTREAM_CLOSURE_MISMATCH")
        return value

    @staticmethod
    def _require_running(work: WorkExecutionState) -> None:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.work_type != WorkType.REPORT_DRAFT
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or work.meta.hypothesis_id is None
        ):
            raise ValueError("REPORT_WORK_NOT_ACTIVE")

    @staticmethod
    def _record_meta(work: WorkExecutionState) -> RecordMeta:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("REPORT_WORK_NOT_ACTIVE")
        return work.meta

    @staticmethod
    def _policy_ref(finding: Finding) -> StoredDataRef:
        if finding.policy_record_ref is None:
            raise ValueError("CURRENT_POLICY_REQUIRED")
        return finding.policy_record_ref


__all__ = [
    "ReporterAgent",
    "ReporterCallRefs",
    "ReporterInputs",
    "ReporterOutcome",
]
