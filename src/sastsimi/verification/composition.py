"""Explicit production composition for the T10 LLM verification slice."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from sastsimi.agents.hypothesis import HypothesisAgent
from sastsimi.agents.verification import VerificationAgent
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.ids import AttemptId, LogicalRecordId, RecordId, WorkId
from sastsimi.contracts.llm import LLMInvocationLog
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.verification import ConEvidenceResult, ProEvidenceResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.hypothesis_workflow import HypothesisWorkflow
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.prompts.builder import PromptBuilder
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .debate_service import DebateService
from .revision_workflow import RevisionWorkflow
from .service import VerificationService
from .verdict_router import VerdictRouter


@dataclass(frozen=True)
class T10Services:
    hypothesis: HypothesisWorkflow
    debate: DebateService
    verification: VerificationService
    verdict_router: VerdictRouter
    revision: RevisionWorkflow


def compose_t10_services(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    clock: Clock,
    ids: IdGenerator,
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef],
) -> T10Services:
    """Compose real T09-backed roles without selecting a Provider or model."""

    records = runtime.unit_of_work.records
    artifacts = runtime.unit_of_work.artifacts

    def metadata(
        source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        return RecordMeta(
            record_id=ids.new(RecordId),
            logical_record_id=ids.new(LogicalRecordId),
            record_type=record_type,
            schema_version=source.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id,
            attempt_id=attempt_id,
        )

    def resolve_work(work_id: WorkId) -> WorkExecutionState | None:
        try:
            return runtime.work.get(str(work_id))
        except LookupError:
            return None

    def evidence_session(
        llm_call_id: str, analysis_id: str
    ) -> tuple[str, Literal["NEW", "RESUME"]]:
        logs = tuple(
            item
            for item in runtime.queries.published_records(analysis_id)
            if isinstance(item, LLMInvocationLog)
            and item.llm_call_id == llm_call_id
            and item.agent_role in {"PRO", "CON"}
        )
        if len(logs) != 1 or logs[0].session_ref is None:
            raise ValueError("EVIDENCE_INVOCATION_LOG_REQUIRED")
        return logs[0].session_ref, "NEW"

    def publish_evidence(
        work: WorkExecutionState,
        output: ProEvidenceResult | ConEvidenceResult,
        invocation: PersistedLLMInvocation,
    ) -> StoredDataRef:
        role = RequesterRole(output.role)
        identity = role_identity_refs.get(role)
        if identity is None:
            raise ValueError(f"{role.value}_IDENTITY_REQUIRED")
        request_ref = reference(invocation.request)
        result_ref = reference(invocation.result)
        if not isinstance(request_ref, StoredDataRef) or not isinstance(
            result_ref, StoredDataRef
        ):
            raise ValueError("EVIDENCE_INVOCATION_PROVENANCE_MISMATCH")
        persisted_request = records.get_exact(request_ref)
        persisted_result = records.get_exact(result_ref)
        persisted_log = records.get_exact(invocation.log_ref)
        if (
            persisted_request != invocation.request
            or persisted_result != invocation.result
            or not isinstance(persisted_log, LLMInvocationLog)
            or reference(persisted_log) != invocation.log_ref
            or invocation.result.parsed_output_ref is None
            or output.llm_call_id != invocation.request.llm_call_id
        ):
            raise ValueError("EVIDENCE_INVOCATION_PROVENANCE_MISMATCH")
        completed = runner.complete(
            work,
            identity,
            role.value,
            (output,),
            action_input_refs=(
                *work.input_refs,
                request_ref,
                result_ref,
                invocation.log_ref,
                invocation.result.parsed_output_ref,
            ),
        )
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise TypeError("EVIDENCE_OUTPUT_SCOPE_MISMATCH")
        return output_ref

    hypothesis_agent = HypothesisAgent(
        prompt_builder=PromptBuilder(artifacts),
        llm_calls=runtime.llm_calls,
        artifacts=artifacts,
        ids=ids,
        clock=clock,
    )
    hypothesis = HypothesisWorkflow(
        agent=hypothesis_agent,
        runner=runner,
        records=records,
    )
    debate = DebateService(
        records=records,
        artifacts=artifacts,
        llm_calls=runtime.llm_calls,
        metadata_factory=metadata,
        claim_id_factory=lambda role: str(ids.new(RecordId)),
        publish_result=publish_evidence,
    )
    verification_agent = VerificationAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata,
        work_resolver=resolve_work,
        evidence_session_resolver=evidence_session,
    )
    return T10Services(
        hypothesis=hypothesis,
        debate=debate,
        verification=VerificationService(verification_agent),
        verdict_router=VerdictRouter(records),
        revision=RevisionWorkflow(
            registrar=runtime.verification_registration,
            records=records,
        ),
    )


__all__ = ["T10Services", "compose_t10_services"]
