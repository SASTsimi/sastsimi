"""Trusted normalization of one exact accepted TRUE chain into a Finding."""

from __future__ import annotations

from collections.abc import Callable

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.domain import DomainRecord, exact_set
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.reporting import (
    Finding,
    condition_sources,
    evidence_closure,
    validate_finding_closure,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.record_store import RecordStore

type CurrentRecords = Callable[[str, str], tuple[object, ...]]
type PublishedRecords = Callable[[str], tuple[object, ...]]


class FindingNormalizationService:
    """Create no semantic claims; only freeze an already-proven exact closure."""

    def __init__(
        self,
        *,
        records: RecordStore,
        current_records: CurrentRecords,
        published_records: PublishedRecords,
        ids: IdGenerator,
        clock: Clock,
    ) -> None:
        self._records = records
        self._current = current_records
        self._published = published_records
        self._ids = ids
        self._clock = clock

    def assemble(
        self,
        *,
        work: WorkExecutionState,
        verification_ref: StoredDataRef,
        cwe_label_ref: StoredDataRef,
        technical_review_ref: StoredDataRef,
        rule_scope_review_ref: StoredDataRef,
    ) -> Finding:
        self._require_running(work)
        verification = self._exact(verification_ref, VerificationResult)
        label = self._exact(cwe_label_ref, CWELabel)
        technical = self._exact(technical_review_ref, TechnicalEvidenceReview)
        scope = self._exact(rule_scope_review_ref, RuleScopeImpactReview)
        if verification.dynamic_result_ref is None or verification.poc_ref is None:
            raise ValueError("VALIDATED_POC_REQUIRED")
        dynamic = self._exact(
            verification.dynamic_result_ref, DynamicReproductionResult
        )
        poc = self._exact(verification.poc_ref, PoCBundle)
        state = self._exact(scope.run_policy_state_ref, RunPolicyState)
        collection = self._exact(
            scope.policy_collection_result_ref, PolicyCollectionResult
        )
        if collection.status == "COLLECTION_FAILED":
            raise ValueError("POLICY_COLLECTION_FAILED")
        policy = (
            self._exact(scope.policy_record_ref, ProgramPolicyRecord)
            if scope.policy_record_ref is not None
            else None
        )
        process = self._current_process(work, verification_ref)

        published = tuple(
            item
            for item in self._published(str(work.meta.analysis_id))
            if isinstance(item, DomainRecord)
        )
        resolved = {
            canonical_bytes(ref): item
            for item in published
            if isinstance((ref := reference(item)), StoredDataRef)
        }
        evidence_refs = evidence_closure(verification, resolved)
        required_refs: list[StoredDataRef] = [
            self._stored(reference(process)),
            verification_ref,
            verification.dynamic_result_ref,
            verification.poc_ref,
            cwe_label_ref,
            technical_review_ref,
            rule_scope_review_ref,
            scope.run_policy_state_ref,
            scope.policy_collection_result_ref,
            *evidence_refs,
        ]
        if scope.policy_record_ref is not None:
            required_refs.append(scope.policy_record_ref)
        exact_set(work.input_refs, required_refs)

        pairs: list[tuple[StoredDataRef, DomainRecord]] = [
            (verification_ref, verification),
            (verification.dynamic_result_ref, dynamic),
            (verification.poc_ref, poc),
            (cwe_label_ref, label),
            (technical_review_ref, technical),
            (rule_scope_review_ref, scope),
            (scope.policy_collection_result_ref, collection),
        ]
        if policy is not None and scope.policy_record_ref is not None:
            pairs.append((scope.policy_record_ref, policy))
        seen = {canonical_bytes(ref) for ref, _ in pairs}
        for ref in evidence_refs:
            if ref.record_id is not None and canonical_bytes(ref) not in seen:
                pairs.append((ref, resolved[canonical_bytes(ref)]))
                seen.add(canonical_bytes(ref))

        finding = Finding(
            meta=self._meta(work),
            verification_result_ref=verification_ref,
            dynamic_result_ref=verification.dynamic_result_ref,
            poc_ref=verification.poc_ref,
            cwe_label_ref=cwe_label_ref,
            technical_review_ref=technical_review_ref,
            rule_scope_impact_review_ref=rule_scope_review_ref,
            policy_collection_result_ref=scope.policy_collection_result_ref,
            policy_record_ref=scope.policy_record_ref,
            evidence_refs=evidence_refs,
            condition_sources=condition_sources(tuple(pairs)),
        )
        validate_finding_closure(
            finding,
            verification,
            dynamic,
            poc,
            label,
            technical,
            scope,
            state,
            collection,
            policy,
            generation=process.verification_generation,
            resolved_evidence=resolved,
            upstream_conditions=tuple(pairs),
        )
        return finding

    def _current_process(
        self, work: WorkExecutionState, verification_ref: StoredDataRef
    ) -> HypothesisProcessState:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("FINDING_WORK_NOT_ACTIVE")
        candidates = tuple(
            item
            for item in self._current(
                str(work.meta.analysis_id), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
            and item.meta.hypothesis_id == work.meta.hypothesis_id
        )
        if (
            len(candidates) != 1
            or candidates[0].status != "TERMINAL"
            or candidates[0].verification_result_ref != verification_ref
            or candidates[0].verification_generation != work.work_generation
        ):
            raise ValueError("STALE_RESULT")
        return candidates[0]

    def _meta(self, work: WorkExecutionState) -> RecordMeta:
        if not isinstance(work.meta, RecordMeta) or work.active_attempt_id is None:
            raise ValueError("FINDING_WORK_NOT_ACTIVE")
        record_id = self._ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type="finding",
            schema_version=work.meta.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock.now(),
            analysis_id=work.meta.analysis_id,
            workspace_id=work.meta.workspace_id,
            commit_id=work.meta.commit_id,
            hypothesis_id=work.meta.hypothesis_id,
            attempt_id=work.active_attempt_id,
        )

    @staticmethod
    def _require_running(work: WorkExecutionState) -> None:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.work_type != WorkType.FINDING_NORMALIZE
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or work.meta.hypothesis_id is None
            or work.work_generation < 1
        ):
            raise ValueError("FINDING_WORK_NOT_ACTIVE")

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model):
            raise ValueError("FINDING_UPSTREAM_CLOSURE_MISMATCH")
        return value

    @staticmethod
    def _stored(value: object) -> StoredDataRef:
        if not isinstance(value, StoredDataRef):
            raise ValueError("FINDING_UPSTREAM_CLOSURE_MISMATCH")
        return value
