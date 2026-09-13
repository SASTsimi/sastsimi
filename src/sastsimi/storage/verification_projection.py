"""A final result and its process/index projections form one terminal commit."""

from sqlalchemy import Connection, select

from sastsimi.contracts.chaining import PrimitiveIndexState
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionState,
    PoCBundle,
)
from sastsimi.contracts.gates import validate_true_dynamic
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.reporting import FindingIndexState, ReportProcessState
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    PlaybookApplication,
    PlaybookPolicy,
    ProEvidenceResult,
    VerificationInitialAssessment,
    VerificationPlaybook,
    VerificationResult,
    validate_dynamic_verdict,
    validate_playbook_application,
    validate_verification_closure,
)
from sastsimi.contracts.work import WorkExecutionState, WorkType
from sastsimi.ports.dto import Record

from . import models
from .action_context import current_process
from .codec import REF_ADAPTER, reference
from .committed_outputs import require_committed
from .intermediate_policy import prepublished_output
from .records import fresh_meta, next_meta
from .run_states import get_run
from .stage_policy import resolved
from .work_service import WorkService


def current_scoped[T: Record](
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    kind: str,
    model: type[T],
) -> tuple[T, ...]:
    result = []
    for wire in connection.execute(
        select(models.records.c.ref)
        .join(
            models.current_records,
            models.current_records.c.record_id == models.records.c.record_id,
        )
        .where(models.records.c.kind == kind)
    ).scalars():
        value = works.records.resolve(connection, REF_ADAPTER.validate_json(wire))
        if isinstance(value, model) and all(
            getattr(value.meta, name, None) == getattr(work.meta, name, None)
            for name in ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        ):
            result.append(value)
    return tuple(result)


def verification_projection(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
    *,
    publish: bool,
) -> tuple[Record, ...]:
    finals = [record for record in outputs if isinstance(record, VerificationResult)]
    if not finals:
        return ()
    if len(finals) != 1 or work.work_type != "VERIFICATION":
        raise ValueError("VERIFICATION_WORK_REQUIRED")
    final = finals[0]
    records = works.records
    process = current_process(records, connection, work)
    if process.status != "VERIFYING" or process.verification_work_ref != reference(
        work
    ):
        raise ValueError("STALE_RESULT: current Verification work required")
    application = resolved(
        records, connection, final.playbook_application_ref, PlaybookApplication
    )
    hypothesis = resolved(
        records, connection, application.hypothesis_ref, VulnerabilityHypothesis
    )
    proposal = resolved(
        records, connection, application.proposal_ref, HypothesisProposal
    )
    policy = resolved(records, connection, application.policy_ref, PlaybookPolicy)
    book = resolved(records, connection, application.playbook_ref, VerificationPlaybook)
    required_inputs = {
        reference(item) for item in (hypothesis, proposal, policy, book, application)
    }
    if not required_inputs.issubset(work.input_refs):
        raise ValueError("VERIFICATION_INPUT_CLOSURE_REQUIRED")
    validate_playbook_application(application, hypothesis, proposal, policy, book)
    pro = (
        resolved(records, connection, final.pro_evidence_ref, ProEvidenceResult)
        if final.pro_evidence_ref
        else None
    )
    con = (
        resolved(records, connection, final.con_evidence_ref, ConEvidenceResult)
        if final.con_evidence_ref
        else None
    )
    validate_verification_closure(
        final,
        hypothesis,
        proposal,
        application,
        pro,
        con,
        current_work_id=work.work_id,
        current_generation=process.verification_generation,
        purpose=get_run(connection, str(work.meta.analysis_id)).purpose.value,
    )
    if pro is not None:
        require_committed(records, connection, pro, WorkType.PRO_EVIDENCE)
    if con is not None:
        require_committed(records, connection, con, WorkType.CON_EVIDENCE)
    assessments = [
        item
        for item in current_scoped(
            works,
            connection,
            work,
            "verification_initial_assessment",
            VerificationInitialAssessment,
        )
        if item.verification_work_id == work.work_id
        and item.verification_generation == work.work_generation
    ]
    if len(assessments) != 1:
        raise ValueError("INITIAL_ASSESSMENT_REQUIRED")
    assessment = assessments[0]
    prepublished_output(records, connection, reference(assessment), work)
    if (
        assessment.hypothesis_ref,
        assessment.policy_ref,
        assessment.playbook_ref,
        assessment.playbook_application_ref,
        assessment.pro_evidence_ref,
        assessment.con_evidence_ref,
        assessment.proposed_verdict,
    ) != (
        reference(hypothesis),
        reference(policy),
        reference(book),
        reference(application),
        final.pro_evidence_ref,
        final.con_evidence_ref,
        final.initial_verdict,
    ):
        raise ValueError("INITIAL_ASSESSMENT_CLOSURE_MISMATCH")
    states = current_scoped(
        works, connection, work, "dynamic_reproduction_state", DynamicReproductionState
    )
    if len(states) != 1 or states[0].verification_generation != work.work_generation:
        raise ValueError("DYNAMIC_STATE_REQUIRED")
    dynamic_state = states[0]
    if final.dynamic_request_ref is None:
        if (
            assessment.next_step != "FINALIZE_WITHOUT_DYNAMIC"
            or dynamic_state.status != "NOT_REQUESTED"
        ):
            raise ValueError("INITIAL_ASSESSMENT_ROUTE_MISMATCH")
    else:
        request = resolved(
            records, connection, final.dynamic_request_ref, DynamicReproductionRequest
        )
        dynamic = resolved(
            records, connection, final.dynamic_result_ref, DynamicReproductionResult
        )
        poc = (
            resolved(records, connection, final.poc_ref, PoCBundle)
            if final.poc_ref
            else None
        )
        if (
            assessment.next_step != request.purpose
            or request.verification_assignment_ref
            != process.verification_assignment_ref
            or (
                dynamic_state.dynamic_result_ref != final.dynamic_result_ref
                or dynamic_state.request_ref != final.dynamic_request_ref
            )
        ):
            raise ValueError("DYNAMIC_STATE_REQUIRED")
        validate_dynamic_verdict(
            final, request, dynamic, poc, generation=work.work_generation
        )
        require_committed(records, connection, dynamic, WorkType.DYNAMIC_REPRO)
        if final.verdict == "TRUE":
            if poc is None:
                raise ValueError("VALIDATED_POC_REQUIRED")
            require_committed(records, connection, poc, WorkType.DYNAMIC_REPRO)
            validate_true_dynamic(final, dynamic, poc)
    if not publish:
        return ()
    terminal = HypothesisProcessState.model_validate(
        process.model_dump()
        | dict(
            meta=next_meta(process.meta, works.clock, works.ids),
            status="TERMINAL",
            verification_work_ref=None,
            verification_result_ref=reference(final),
            finished_at=works.clock.now(),
        )
    )
    prior_indices = current_scoped(
        works, connection, work, "primitive_index_state", PrimitiveIndexState
    )
    if len(prior_indices) > 1:
        raise ValueError("PRIMITIVE_INDEX_CONFLICT")
    meta = (
        next_meta(prior_indices[0].meta, works.clock, works.ids)
        if prior_indices
        else fresh_meta(
            final.meta, "primitive_index_state", works.clock, works.ids, attempt_id=None
        )
    )
    primitive_index = PrimitiveIndexState.model_validate(
        dict(
            meta=meta,
            current_verification_ref=reference(final),
            primitive_refs=(),
            updated_at=works.clock.now(),
        )
    )
    report_states = current_scoped(
        works, connection, work, "report_process_state", ReportProcessState
    )
    if len(report_states) != 1:
        raise ValueError("REPORT_PROCESS_STATE_REQUIRED")
    report_state = report_states[0]
    reset_report_state = ReportProcessState.model_validate(
        dict(
            meta=next_meta(report_state.meta, works.clock, works.ids),
            status="NOT_REQUESTED",
            report_draft_ref=None,
            started_at=None,
            finished_at=None,
            elapsed_ms=0,
        )
    )
    projections: list[Record] = [terminal, primitive_index, reset_report_state]
    finding_indices = current_scoped(
        works, connection, work, "finding_index_state", FindingIndexState
    )
    if len(finding_indices) != 1:
        raise ValueError("FINDING_INDEX_REQUIRED")
    index = finding_indices[0]
    if index.status != "EMPTY":
        stale = FindingIndexState.model_validate(
            index.model_dump()
            | dict(
                meta=next_meta(index.meta, works.clock, works.ids),
                state_version=index.state_version + 1,
                status="STALE",
                finding_ref=None,
                stale_finding_ref=index.finding_ref or index.stale_finding_ref,
                invalidated_by_refs=(*index.invalidated_by_refs, reference(final)),
            )
        )
        projections.append(stale)
    return tuple(projections)
