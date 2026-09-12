"""Content-only Reporter Agent invocation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.actions import ActionType, RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.reporting import ReportContent
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.llm_invocation import (
    LLMInvocationExpectation,
    LLMInvocationProvenanceValidator,
    PersistedLLMInvocation,
)
from sastsimi.ports.record_store import RecordStore


class LLMCallInvoker(Protocol):
    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


class ReporterOwnerResolver(Protocol):
    def __call__(self, work: WorkExecutionState) -> BudgetScopeRef: ...


@dataclass(frozen=True)
class ReporterCallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True)
class ReporterProposal:
    """Untrusted content proposal plus its exact authorized-call provenance."""

    content: ReportContent
    content_ref: StoredDataRef
    action_decision_ref: StoredDataRef
    invocation: PersistedLLMInvocation
    save_input_refs: tuple[RecordRef, ...]


class ReporterAgent:
    """Ask the LLM for report content; trusted code decides whether to save a draft."""

    def __init__(
        self,
        *,
        llm_calls: LLMCallInvoker,
        records: RecordStore,
        artifacts: ArtifactStore,
        provenance_validator: LLMInvocationProvenanceValidator,
        owner_resolver: ReporterOwnerResolver,
    ) -> None:
        self._llm_calls = llm_calls
        self._records = records
        self._artifacts = artifacts
        self._validate_provenance = provenance_validator
        self._owner_resolver = owner_resolver

    async def propose_content(
        self, *, work: WorkExecutionState, call: ReporterCallRefs
    ) -> ReporterProposal:
        self._require_running(work)
        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        content, content_ref, decision_ref, save_input_refs = self._content(
            invocation, work=work, call=call
        )
        return ReporterProposal(
            content=content,
            content_ref=content_ref,
            action_decision_ref=decision_ref,
            invocation=invocation,
            save_input_refs=save_input_refs,
        )

    def _content(
        self,
        invocation: PersistedLLMInvocation,
        *,
        work: WorkExecutionState,
        call: ReporterCallRefs,
    ) -> tuple[ReportContent, StoredDataRef, StoredDataRef, tuple[RecordRef, ...]]:
        result = invocation.result
        validated = self._validate_provenance(
            records=self._records,
            work=work,
            issued_decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            invocation=invocation,
            expectation=LLMInvocationExpectation(
                work_type=WorkType.REPORT_DRAFT,
                action_type=ActionType.CREATE_REPORT_DRAFT,
                requested_by=RequesterRole.VERIFICATION,
                requester_identity_ref=self._owner_resolver(work),
                agent_role="REPORTER",
                task_kind="CREATE_DRAFT",
                required_context=work.input_refs,
            ),
        )
        content_ref = result.parsed_output_ref
        if not isinstance(content_ref, StoredDataRef):
            raise ValueError("REPORTER_INVOCATION_CLOSURE_MISMATCH")
        try:
            with self._artifacts.open_verified(content_ref) as stream:
                raw = stream.read()
            content = ReportContent.model_validate_json(raw)
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("REPORTER_OUTPUT_ARTIFACT_INVALID") from error
        if canonical_bytes(content) != raw:
            raise ValueError("REPORTER_OUTPUT_ARTIFACT_INVALID")
        claimed_ref = reference(validated.claimed_decision)
        if not isinstance(claimed_ref, StoredDataRef):
            raise ValueError("REPORTER_INVOCATION_CLOSURE_MISMATCH")
        return content, content_ref, claimed_ref, validated.save_input_refs

    @staticmethod
    def _require_running(work: WorkExecutionState) -> None:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.work_type != WorkType.REPORT_DRAFT
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or work.meta.hypothesis_id is None
        ):
            raise ValueError("REPORT_WORK_NOT_ACTIVE")


__all__ = [
    "ReporterAgent",
    "ReporterCallRefs",
    "ReporterOwnerResolver",
    "ReporterProposal",
]
