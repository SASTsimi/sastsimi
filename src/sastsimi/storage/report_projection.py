"""Report drafts are accepted only from the exact current finding closure."""

from sqlalchemy import Connection

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.domain import DomainRecord
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.policy import PolicyCollectionResult, RunPolicyState
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import (
    Finding,
    FindingIndexState,
    ReportDraft,
    validate_report_closure,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record

from .run_states import get_run
from .stage_policy import resolved
from .verification_projection import current_scoped
from .work_service import WorkService


def validate_report_output(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
) -> None:
    drafts = [item for item in outputs if isinstance(item, ReportDraft)]
    if not drafts:
        return
    if len(drafts) != 1 or len(outputs) != 1 or work.work_type != "REPORT_DRAFT":
        raise ValueError("REPORT_EXACT_OUTPUT_REQUIRED")
    draft = drafts[0]
    finding = resolved(works.records, connection, draft.finding_ref, Finding)
    indexes = current_scoped(
        works, connection, work, "finding_index_state", FindingIndexState
    )
    if len(indexes) != 1:
        raise ValueError("FINDING_INDEX_REQUIRED")
    verification = resolved(
        works.records, connection, draft.verification_result_ref, VerificationResult
    )
    technical = resolved(
        works.records,
        connection,
        draft.technical_review_ref,
        TechnicalEvidenceReview,
    )
    scope = resolved(
        works.records,
        connection,
        draft.rule_scope_impact_review_ref,
        RuleScopeImpactReview,
    )
    run = get_run(connection, str(work.meta.analysis_id))
    if run.run_policy_state_ref is None:
        raise ValueError("FROZEN_POLICY_REQUIRED")
    state = resolved(
        works.records, connection, run.run_policy_state_ref, RunPolicyState
    )
    if draft.run_policy_state_ref != run.run_policy_state_ref:
        raise ValueError("REPORT_POLICY_CLOSURE_MISMATCH")
    condition_records = _condition_records(works, connection, finding)
    validate_report_closure(
        draft,
        finding,
        indexes[0],
        verification,
        technical,
        scope,
        state,
        content_locations=(),
        condition_records=condition_records,
    )


def _condition_records(
    works: WorkService, connection: Connection, finding: Finding
) -> tuple[tuple[StoredDataRef, DomainRecord], ...]:
    pairs: list[tuple[StoredDataRef, DomainRecord]] = []
    specifications: tuple[tuple[StoredDataRef, type[DomainRecord]], ...] = (
        (finding.verification_result_ref, VerificationResult),
        (finding.dynamic_result_ref, DynamicReproductionResult),
        (finding.poc_ref, PoCBundle),
        (finding.cwe_label_ref, CWELabel),
        (finding.technical_review_ref, TechnicalEvidenceReview),
        (finding.rule_scope_impact_review_ref, RuleScopeImpactReview),
        (finding.policy_collection_result_ref, PolicyCollectionResult),
    )
    for ref, model in specifications:
        record = works.records.resolve(connection, ref)
        if not isinstance(record, model):
            raise ValueError("REPORT_UPSTREAM_CLOSURE_MISMATCH")
        pairs.append((ref, record))
    seen = {canonical_bytes(ref) for ref, _ in pairs}
    for ref in finding.evidence_refs:
        if ref.record_id is None or canonical_bytes(ref) in seen:
            continue
        record = works.records.resolve(connection, ref)
        if not isinstance(record, DomainRecord):
            raise ValueError("REPORT_UPSTREAM_CLOSURE_MISMATCH")
        pairs.append((ref, record))
        seen.add(canonical_bytes(ref))
    return tuple(pairs)
