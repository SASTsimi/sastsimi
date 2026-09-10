"""Trusted Finding normalization closure and current index projection."""

from sqlalchemy import Connection

from sastsimi.contracts.domain import DomainRecord
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import (
    Finding,
    FindingIndexState,
    validate_finding_closure,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import TransitionCommit, WorkExecutionState
from sastsimi.ports.dto import Record

from .codec import reference
from .records import next_meta
from .run_states import get_run
from .stage_policy import resolved
from .verification_projection import current_scoped
from .work_service import WorkService


def validate_finding_output(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
) -> Finding | None:
    findings = [item for item in outputs if isinstance(item, Finding)]
    if not findings:
        return None
    if len(findings) != 1 or len(outputs) != 1 or work.work_type != "FINDING_NORMALIZE":
        raise ValueError("FINDING_EXACT_OUTPUT_REQUIRED")
    finding = findings[0]
    process = current_scoped(
        works,
        connection,
        work,
        "hypothesis_process_state",
        HypothesisProcessState,
    )
    if (
        len(process) != 1
        or process[0].verification_result_ref != finding.verification_result_ref
    ):
        raise ValueError("STALE_RESULT: current Verification required")
    verification = resolved(
        works.records, connection, finding.verification_result_ref, VerificationResult
    )
    dynamic = resolved(
        works.records, connection, finding.dynamic_result_ref, DynamicReproductionResult
    )
    poc = resolved(works.records, connection, finding.poc_ref, PoCBundle)
    label = resolved(works.records, connection, finding.cwe_label_ref, CWELabel)
    technical = resolved(
        works.records, connection, finding.technical_review_ref, TechnicalEvidenceReview
    )
    scope = resolved(
        works.records,
        connection,
        finding.rule_scope_impact_review_ref,
        RuleScopeImpactReview,
    )
    collection = resolved(
        works.records,
        connection,
        finding.policy_collection_result_ref,
        PolicyCollectionResult,
    )
    run_state = get_run(connection, str(work.meta.analysis_id))
    if run_state.run_policy_state_ref is None:
        raise ValueError("FROZEN_POLICY_REQUIRED")
    state = resolved(
        works.records, connection, run_state.run_policy_state_ref, RunPolicyState
    )
    policy = (
        resolved(
            works.records, connection, finding.policy_record_ref, ProgramPolicyRecord
        )
        if finding.policy_record_ref is not None
        else None
    )
    pairs: list[tuple[StoredDataRef, DomainRecord]] = []
    for item in (verification, dynamic, poc, label, technical, scope, collection):
        item_ref = reference(item)
        if not isinstance(item_ref, StoredDataRef):
            raise ValueError("FINDING_SCOPE_MISMATCH")
        pairs.append((item_ref, item))
    evidence: dict[bytes, DomainRecord] = {}
    evidence_pairs = []
    from sastsimi.contracts.canonical_json import canonical_bytes

    for ref in finding.evidence_refs:
        if ref.record_id is None:
            continue
        evidence_record = works.records.resolve(connection, ref)
        if isinstance(evidence_record, DomainRecord):
            evidence[canonical_bytes(ref)] = evidence_record
            evidence_pairs.append((ref, evidence_record))
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
        generation=process[0].verification_generation,
        resolved_evidence=evidence,
        upstream_conditions=(*pairs, *evidence_pairs),
    )
    return finding


def finding_index_projection(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    finding: Finding,
    committed: TransitionCommit,
) -> FindingIndexState:
    indexes = current_scoped(
        works, connection, work, "finding_index_state", FindingIndexState
    )
    if len(indexes) != 1 or indexes[0].status not in {"EMPTY", "STALE"}:
        raise ValueError("FINDING_INDEX_CONFLICT")
    old = indexes[0]
    return FindingIndexState.model_validate(
        old.model_dump()
        | dict(
            meta=next_meta(old.meta, works.clock, works.ids),
            state_version=old.state_version + 1,
            status="CURRENT",
            finding_ref=reference(finding),
            stale_finding_ref=None,
            normalization_work_ref=reference(work),
            last_transition_commit_ref=reference(committed),
            invalidated_by_refs=(),
        )
    )
