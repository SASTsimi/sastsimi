"""Claimed-work handlers for Finding normalization and Reporter execution."""

from __future__ import annotations

from typing import Protocol

from sastsimi.agents.reporter import (
    ReporterAgent,
    ReporterCallRefs,
    ReporterInputs,
)
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import AttemptStatus, WorkStatus, WorkType
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.record_store import RecordStore
from sastsimi.reporting.finding_normalization import FindingNormalizationService


class ReporterInputResolver(Protocol):
    def __call__(
        self, context: WorkContext
    ) -> tuple[ReporterInputs, ReporterCallRefs]: ...


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


class ReporterWorkHandler:
    def __init__(
        self, *, agent: ReporterAgent, resolve_inputs: ReporterInputResolver
    ) -> None:
        self._agent = agent
        self._resolve_inputs = resolve_inputs

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        _require_claimed(context, WorkType.REPORT_DRAFT)
        inputs, call = self._resolve_inputs(context)
        outcome = await self._agent.create_draft(
            work=context.work, inputs=inputs, call=call
        )
        return WorkHandlerResult((outcome.draft_ref,))


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
    "ReporterInputResolver",
    "ReporterWorkHandler",
]
