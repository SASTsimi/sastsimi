"""Work-handler adapter for one already-running TECHNICAL_GATE attempt."""

from __future__ import annotations

from dataclasses import dataclass

from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import AttemptStatus, WorkStatus, WorkType
from sastsimi.ports.dto import WorkContext, WorkHandlerResult

from .cwe_service import GateCallRefs
from .technical_service import TechnicalGateService


@dataclass(frozen=True)
class TechnicalGateHandler:
    service: TechnicalGateService

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        work, attempt = context.work, context.attempt
        if (
            work.work_type != WorkType.TECHNICAL_GATE
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id != attempt.attempt_id
            or work.work_id != attempt.work_id
            or attempt.status != AttemptStatus.RUNNING
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        result = await self.service.review(
            work=work,
            process_ref=_one(work.input_refs, "hypothesis_process_state"),
            assignment_ref=_one(work.input_refs, "verification_assignment"),
            verification_ref=_one(work.input_refs, "verification_result"),
            dynamic_result_ref=_one(work.input_refs, "dynamic_reproduction_result"),
            poc_ref=_one(work.input_refs, "poc_bundle"),
            cwe_label_ref=_one(work.input_refs, "cwe_label"),
            budget_binding_ref=_one(work.input_refs, "budget_profile_binding"),
            call=GateCallRefs(
                decision_ref=_one(work.input_refs, "action_decision"),
                reservation_ref=_one_record(work.input_refs, "budget_reservation"),
                call_spec_ref=_one(work.input_refs, "llm_call_spec"),
            ),
        )
        output_ref = reference(result.review)
        if not isinstance(output_ref, StoredDataRef):
            raise ValueError("TECHNICAL_OUTPUT_SCOPE_MISMATCH")
        return WorkHandlerResult((output_ref,))


def _one(refs: tuple[RecordRef, ...], kind: str) -> StoredDataRef:
    values = tuple(ref for ref in refs if ref.data_kind == kind)
    if len(values) != 1 or not isinstance(values[0], StoredDataRef):
        raise ValueError(f"STALE_RESULT: exactly one {kind} input required")
    return values[0]


def _one_record(refs: tuple[RecordRef, ...], kind: str) -> RecordRef:
    values = tuple(ref for ref in refs if ref.data_kind == kind)
    if len(values) != 1:
        raise ValueError(f"STALE_RESULT: exactly one {kind} input required")
    return values[0]


__all__ = ["TechnicalGateHandler"]
