"""Report drafts are accepted only from the exact current finding closure."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    CheckType,
    Decision,
    RequesterRole,
    UseStatus,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.domain import DomainRecord
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.policy import PolicyCollectionResult, RunPolicyState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import (
    Finding,
    FindingIndexState,
    ReportDraft,
    parse_validated_report_content,
    validate_report_closure,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dto import Record

from . import models
from .codec import reference
from .run_states import get_run
from .stage_policy import resolved
from .verification_projection import current_scoped
from .work_service import WorkService


def validate_report_output(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
    artifacts: ArtifactStore,
) -> None:
    drafts = [item for item in outputs if isinstance(item, ReportDraft)]
    if not drafts:
        return
    if len(drafts) != 1 or len(outputs) != 1 or work.work_type != "REPORT_DRAFT":
        raise ValueError("REPORT_EXACT_OUTPUT_REQUIRED")
    draft = drafts[0]
    if not isinstance(work.meta, RecordMeta):
        raise ValueError("REPORT_WORK_SCOPE_MISMATCH")
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
    allowed_locations = tuple(
        location
        for claim in (
            *verification.supporting_evidence,
            *verification.counter_evidence,
        )
        for location in claim.code_locations
    )
    if (
        draft.content_ref.workspace_id != work.meta.workspace_id
        or draft.content_ref.commit_id != work.meta.commit_id
    ):
        raise ValueError("REPORT_CONTENT_ARTIFACT_INVALID")
    if (
        draft.content_ref.record_id is not None
        or draft.content_ref.data_kind != "artifact"
        or str(draft.content_ref.stored_data_id) != draft.content_ref.content_hash
    ):
        raise ValueError("REPORT_CONTENT_ARTIFACT_INVALID")
    try:
        with artifacts.open_verified(draft.content_ref) as stream:
            raw = stream.read()
        content = parse_validated_report_content(
            raw, allowed_locations=allowed_locations
        )
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("REPORT_CONTENT_ARTIFACT_INVALID") from error
    validate_report_closure(
        draft,
        finding,
        indexes[0],
        verification,
        technical,
        scope,
        state,
        content_locations=content.citations,
        condition_records=condition_records,
    )
    report_creation_decision(works, connection, work, draft)


def report_creation_decision(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    draft: ReportDraft,
) -> ActionDecision:
    exact_decision = resolved(
        works.records, connection, draft.action_decision_ref, ActionDecision
    )
    payload = connection.execute(
        select(models.action_decisions.c.payload).where(
            models.action_decisions.c.decision_id == str(exact_decision.decision_id)
        )
    ).scalar_one_or_none()
    if payload is None:
        raise ValueError("REPORT_CREATE_DECISION_NOT_USED")
    decision = ActionDecision.model_validate_json(payload)
    action = resolved(works.records, connection, decision.action_ref, ActionRequest)
    if not isinstance(decision.meta, RecordMeta) or not isinstance(
        action.meta, RecordMeta
    ):
        raise ValueError("REPORT_CREATE_DECISION_MISMATCH")
    redaction = tuple(
        check
        for check in decision.check_results
        if check.check_type == CheckType.REDACTION
    )
    if (
        reference(exact_decision) != draft.action_decision_ref
        or decision.decision != Decision.ALLOW
        or decision.use_status != UseStatus.USED
        or len(redaction) != 1
        or redaction[0].result != CheckResult.PASS
        or action.action_type != ActionType.CREATE_REPORT_DRAFT
        or action.requested_by != RequesterRole.VERIFICATION
        or action.work_ref != reference(work)
        or action.expected_state_version != work.state_version
        or decision.checked_state_version != work.state_version
        or decision.meta.attempt_id != work.active_attempt_id
        or action.meta.attempt_id != work.active_attempt_id
        or reference(draft) in decision.outcome_refs
    ):
        raise ValueError("REPORT_CREATE_DECISION_MISMATCH")
    return decision


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
