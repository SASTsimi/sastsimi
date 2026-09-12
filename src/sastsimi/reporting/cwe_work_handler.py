"""Work-handler adapter for one already-running CWE_LABEL attempt."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import AttemptStatus, WorkStatus, WorkType
from sastsimi.ports.dto import WorkContext, WorkHandlerResult

from .cwe_workflow import CWELabelingService, GateCallRefs


class GateCallResolver(Protocol):
    """Prepare the exact call only after the scheduler has claimed this attempt."""

    def __call__(self, context: WorkContext) -> GateCallRefs: ...


@dataclass(frozen=True)
class CWELabelingHandler:
    service: CWELabelingService
    resolve_call: GateCallResolver

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        _require_claimed(context, WorkType.CWE_LABEL)
        work = context.work
        result = await self.service.label(
            work=work,
            process_ref=_one(work.input_refs, "hypothesis_process_state"),
            verification_ref=_one(work.input_refs, "verification_result"),
            dynamic_result_ref=_one(work.input_refs, "dynamic_reproduction_result"),
            poc_ref=_one(work.input_refs, "poc_bundle"),
            call=self.resolve_call(context),
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


__all__ = ["CWELabelingHandler", "GateCallResolver"]
