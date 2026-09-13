"""Claimed-work handlers for Finding normalization and Reporter execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.agents.reporter import (
    ReporterAgent,
    ReporterCallRefs,
)
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.domain import DomainRecord
from sastsimi.contracts.gates import RuleScopeImpactReview, TechnicalEvidenceReview
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.reporting import (
    Finding,
    FindingIndexState,
    ReportDraft,
    validate_finding_conditions,
    validate_report_closure,
    validate_report_content,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import (
    AttemptStatus,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.llm_invocation import (
    InvocationMetadataFactory,
    PersistedLLMInvocation,
)
from sastsimi.ports.record_store import RecordStore
from sastsimi.reporting.finding_normalization import FindingNormalizationService
from sastsimi.reporting.readiness import ReportingReadinessService


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


class ReporterInputResolver(Protocol):
    def __call__(
        self, context: WorkContext
    ) -> tuple[ReporterInputs, ReporterCallRefs]: ...


class ReporterCallResolver(Protocol):
    def __call__(self, context: WorkContext) -> ReporterCallRefs: ...


class StoredReporterInputResolver:
    """Resolve exact report inputs while keeping post-claim call refs separate."""

    def __init__(
        self, *, records: RecordStore, resolve_call: ReporterCallResolver
    ) -> None:
        self._records = records
        self.resolve_call = resolve_call

    def __call__(self, context: WorkContext) -> tuple[ReporterInputs, ReporterCallRefs]:
        _require_claimed(context, WorkType.REPORT_DRAFT)
        finding_ref = _one(context, "finding")
        finding = self._exact(finding_ref, Finding)
        condition_refs = tuple(
            dict.fromkeys(source.source_ref for source in finding.condition_sources)
        )
        conditions = tuple(
            (ref, self._exact(ref, DomainRecord)) for ref in condition_refs
        )
        inputs = ReporterInputs(
            finding_ref=finding_ref,
            finding_index_ref=_one(context, "finding_index_state"),
            verification_ref=_one(context, "verification_result"),
            technical_review_ref=_one(context, "technical_evidence_review"),
            rule_scope_review_ref=_one(context, "rule_scope_impact_review"),
            run_policy_state_ref=_one(context, "run_policy_state"),
            condition_records=conditions,
        )
        return inputs, self.resolve_call(context)

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:
            raise ValueError("REPORT_UPSTREAM_CLOSURE_MISMATCH")
        return value


class FindingNormalizeHandler:
    def __init__(
        self, *, service: FindingNormalizationService, records: RecordStore
    ) -> None:
        self._service = service
        self._records = records

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        _require_claimed(context, WorkType.FINDING_NORMALIZE)
        finding = self._service.assemble(
            work=context.work,
            verification_ref=_one(context, "verification_result"),
            cwe_label_ref=_one(context, "cwe_label"),
            technical_review_ref=_one(context, "technical_evidence_review"),
            rule_scope_review_ref=_one(context, "rule_scope_impact_review"),
        )
        ref = self._records.stage_record(finding)
        if not isinstance(ref, StoredDataRef) or ref != reference(finding):
            raise ValueError("FINDING_STAGE_MISMATCH")
        return WorkHandlerResult((ref,))


class ReporterDraftWorkflow:
    """Fail closed before invocation and finalize one exact current TRUE draft."""

    def __init__(
        self,
        *,
        agent: ReporterAgent,
        records: RecordStore,
        artifacts: ArtifactStore,
        metadata_factory: InvocationMetadataFactory,
        readiness: ReportingReadinessService | None = None,
    ) -> None:
        self._agent = agent
        self._records = records
        self._artifacts = artifacts
        self._metadata = metadata_factory
        self._readiness = readiness or ReportingReadinessService()

    async def create_draft(
        self,
        *,
        work: WorkExecutionState,
        inputs: ReporterInputs,
        call: ReporterCallRefs,
    ) -> ReporterOutcome:
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

        proposal = await self._agent.propose_content(work=work, call=call)
        allowed_locations = tuple(
            location
            for claim in (
                *verification.supporting_evidence,
                *verification.counter_evidence,
            )
            for location in claim.code_locations
        )
        safe_content = validate_report_content(
            proposal.content.model_dump(mode="json"),
            allowed_locations=allowed_locations,
        )
        content_ref = self._artifacts.commit(
            self._artifacts.stage_bytes(safe_content, "application/json")
        )
        if content_ref != proposal.content_ref:
            raise ValueError("REPORTER_OUTPUT_ARTIFACT_INVALID")
        restrictions, limitations, unresolved = validate_finding_conditions(
            finding, tuple(inputs.condition_records)
        )
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("REPORT_WORK_NOT_ACTIVE")
        draft = ReportDraft(
            meta=self._metadata(work.meta, "report_draft", work.active_attempt_id),
            action_decision_ref=proposal.action_decision_ref,
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
            content_locations=proposal.content.citations,
            condition_records=tuple(inputs.condition_records),
        )
        staged = self._records.stage_record(draft)
        if not isinstance(staged, StoredDataRef) or staged != reference(draft):
            raise ValueError("REPORT_DRAFT_STAGE_MISMATCH")
        return ReporterOutcome(
            draft=draft,
            draft_ref=staged,
            invocation=proposal.invocation,
            save_input_refs=proposal.save_input_refs,
        )

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:
            raise ValueError("REPORT_UPSTREAM_CLOSURE_MISMATCH")
        return value

    @staticmethod
    def _policy_ref(finding: Finding) -> StoredDataRef:
        if finding.policy_record_ref is None:
            raise ValueError("CURRENT_POLICY_REQUIRED")
        return finding.policy_record_ref


class ReporterWorkHandler:
    def __init__(
        self, *, workflow: ReporterDraftWorkflow, resolve_inputs: ReporterInputResolver
    ) -> None:
        self._workflow = workflow
        self.resolve_inputs = resolve_inputs

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        _require_claimed(context, WorkType.REPORT_DRAFT)
        inputs, call = self.resolve_inputs(context)
        outcome = await self._workflow.create_draft(
            work=context.work, inputs=inputs, call=call
        )
        return WorkHandlerResult(
            (outcome.draft_ref,), action_input_refs=outcome.save_input_refs
        )


def _require_claimed(context: WorkContext, expected: WorkType) -> None:
    work, attempt = context.work, context.attempt
    if (
        work.work_type != expected
        or work.status != WorkStatus.RUNNING
        or attempt.status != AttemptStatus.RUNNING
        or work.active_attempt_id is None
        or work.active_attempt_id != attempt.attempt_id
        or work.work_id != attempt.work_id
        or work.input_hash != attempt.input_hash
        or work.input_hash != content_hash(work.input_refs)
        or work.meta.analysis_id != attempt.meta.analysis_id
    ):
        raise ValueError("WORK_CONTEXT_NOT_CURRENT")


def _one(context: WorkContext, kind: str) -> StoredDataRef:
    matches = tuple(
        ref
        for ref in context.work.input_refs
        if isinstance(ref, StoredDataRef) and ref.data_kind == kind
    )
    if len(matches) != 1:
        raise ValueError("REPORT_INPUT_CARDINALITY_MISMATCH")
    return matches[0]


__all__ = [
    "FindingNormalizeHandler",
    "ReporterCallResolver",
    "ReporterDraftWorkflow",
    "ReporterInputResolver",
    "ReporterInputs",
    "ReporterOutcome",
    "ReporterWorkHandler",
    "StoredReporterInputResolver",
]
