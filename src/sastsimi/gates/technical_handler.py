"""Work-handler adapter for one already-running TECHNICAL_GATE attempt."""

from __future__ import annotations

from dataclasses import dataclass

from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkType
from sastsimi.ports.dto import WorkContext, WorkHandlerResult

from .cwe_handler import GateCallResolver, _require_claimed
from .technical_service import TechnicalGateService


@dataclass(frozen=True)
class TechnicalGateHandler:
    service: TechnicalGateService
    resolve_call: GateCallResolver

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        _require_claimed(context, WorkType.TECHNICAL_GATE)
        work = context.work
        result = await self.service.review(
            work=work,
            process_ref=_one(work.input_refs, "hypothesis_process_state"),
            assignment_ref=_one(work.input_refs, "verification_assignment"),
            verification_ref=_one(work.input_refs, "verification_result"),
            dynamic_result_ref=_one(work.input_refs, "dynamic_reproduction_result"),
            poc_ref=_one(work.input_refs, "poc_bundle"),
            cwe_label_ref=_one(work.input_refs, "cwe_label"),
            budget_binding_ref=_one(work.input_refs, "budget_profile_binding"),
            call=self.resolve_call(context),
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


__all__ = ["TechnicalGateHandler"]
