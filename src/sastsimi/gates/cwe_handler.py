"""Work-handler adapter for one already-running CWE_LABEL attempt."""

from __future__ import annotations

from dataclasses import dataclass

from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import AttemptStatus, WorkStatus, WorkType
from sastsimi.ports.dto import WorkContext, WorkHandlerResult

from .cwe_service import CWELabelingService, GateCallRefs


@dataclass(frozen=True)
class CWELabelingHandler:
    service: CWELabelingService

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        work, attempt = context.work, context.attempt
        if (
            work.work_type != WorkType.CWE_LABEL
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id != attempt.attempt_id
            or work.work_id != attempt.work_id
            or attempt.status != AttemptStatus.RUNNING
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        result = await self.service.label(
            work=work,
            process_ref=_one(work.input_refs, "hypothesis_process_state"),
            verification_ref=_one(work.input_refs, "verification_result"),
            dynamic_result_ref=_one(work.input_refs, "dynamic_reproduction_result"),
            poc_ref=_one(work.input_refs, "poc_bundle"),
            call=GateCallRefs(
                decision_ref=_one(work.input_refs, "action_decision"),
                reservation_ref=_one_record(work.input_refs, "budget_reservation"),
                call_spec_ref=_one(work.input_refs, "llm_call_spec"),
            ),
        )
        output_ref = reference(result.label)
        if not isinstance(output_ref, StoredDataRef):
            raise ValueError("CWE_OUTPUT_SCOPE_MISMATCH")
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


__all__ = ["CWELabelingHandler"]
