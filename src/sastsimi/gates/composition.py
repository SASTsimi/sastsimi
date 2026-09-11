"""Production composition for CWE, both Gates, Finding, and Reporter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from sastsimi.agents.cwe_labeling import CWELabelingAgent
from sastsimi.agents.reporter import ReporterAgent
from sastsimi.agents.rule_scope_gate import RuleScopeGateAgent
from sastsimi.agents.technical_gate import TechnicalGateAgent
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VerificationAssignment,
)
from sastsimi.contracts.ids import AttemptId, LogicalRecordId, RecordId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.gates.cwe_handler import CWELabelingHandler, GateCallResolver
from sastsimi.gates.cwe_service import CWELabelingService
from sastsimi.gates.rule_scope_handler import (
    RuleScopeCallResolver,
    RuleScopeGateHandler,
    StoredRuleScopeInputResolver,
    WorkflowRuleScopePublisher,
)
from sastsimi.gates.rule_scope_service import (
    ExactRuleScopePromptGuard,
    RuleScopeGateService,
)
from sastsimi.gates.technical_handler import TechnicalGateHandler
from sastsimi.gates.technical_service import TechnicalGateService
from sastsimi.orchestration.primitive_handoff import PrimitiveUpdateHandoff
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.reporting.finding_normalization import FindingNormalizationService
from sastsimi.reporting.work_handlers import (
    FindingNormalizeHandler,
    ReporterCallResolver,
    ReporterWorkHandler,
    StoredReporterInputResolver,
)
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.verification.composition import T10Services


@dataclass(frozen=True)
class T12Services:
    cwe: CWELabelingHandler
    technical: TechnicalGateHandler
    rule_scope: RuleScopeGateHandler
    finding: FindingNormalizeHandler
    reporter: ReporterWorkHandler
    primitive_handoff: PrimitiveUpdateHandoff


def compose_t12_services(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    clock: Clock,
    ids: IdGenerator,
    t10_services: T10Services,
    taxonomy_version: str,
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef],
    cwe_call_resolver: GateCallResolver,
    technical_call_resolver: GateCallResolver,
    rule_scope_call_resolver: RuleScopeCallResolver,
    reporter_call_resolver: ReporterCallResolver,
) -> T12Services:
    """Wire T12 over exact runtime refs; Provider/model selection stays in T09."""

    records = runtime.unit_of_work.records
    artifacts = runtime.unit_of_work.artifacts

    def metadata(
        source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        record_id = ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
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

    def identity(role: RequesterRole) -> BudgetScopeRef:
        value = role_identity_refs.get(role)
        if value is None:
            raise ValueError(f"{role.value}_IDENTITY_REQUIRED")
        return value

    def stored_identity(role: RequesterRole) -> StoredDataRef:
        value = identity(role)
        if not isinstance(value, StoredDataRef):
            raise ValueError(f"{role.value}_CODE_SCOPE_IDENTITY_REQUIRED")
        return value

    def current_owner(verification: VerificationResult) -> StoredDataRef:
        candidates = tuple(
            item
            for item in runtime.queries.current_records(
                str(verification.meta.analysis_id), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
            and item.meta.hypothesis_id == verification.meta.hypothesis_id
        )
        if (
            len(candidates) != 1
            or candidates[0].status != "TERMINAL"
            or candidates[0].verification_result_ref != reference(verification)
            or candidates[0].verification_assignment_ref is None
        ):
            raise ValueError("STALE_VERIFICATION_OWNER")
        assignment_ref = candidates[0].verification_assignment_ref
        assignment = records.get_exact(assignment_ref)
        if (
            not isinstance(assignment, VerificationAssignment)
            or reference(assignment) != assignment_ref
            or assignment.status != "ACTIVE"
        ):
            raise ValueError("STALE_VERIFICATION_OWNER")
        return assignment.owner_identity_ref

    def current_policy_state(analysis_id: str) -> StoredDataRef:
        state_ref = runtime.budget_registry.current_state(
            analysis_id
        ).run_policy_state_ref
        if not isinstance(state_ref, StoredDataRef):
            raise ValueError("CURRENT_RUN_POLICY_STATE_REQUIRED")
        return state_ref

    cwe_agent = CWELabelingAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata,
    )
    cwe_service = CWELabelingService(
        agent=cwe_agent,
        publisher=runner,
        records=records,
        identity_ref=identity(RequesterRole.CWE_LABELING),
        taxonomy_version=taxonomy_version,
    )
    technical_agent = TechnicalGateAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata,
    )
    technical_service = TechnicalGateService(
        agent=technical_agent,
        publisher=runner,
        records=records,
        identity_ref=identity(RequesterRole.TECHNICAL_GATE),
        orchestration_identity_ref=identity(RequesterRole.ORCHESTRATION),
        t10_services=t10_services,
        ready_work=runner,
    )
    rule_scope_agent = RuleScopeGateAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
    )
    rule_scope_service = RuleScopeGateService(
        agent=rule_scope_agent,
        execution_factory=None,
        publisher=WorkflowRuleScopePublisher(runner),
        metadata_factory=metadata,
        id_factory=lambda _prefix: str(ids.new(RecordId)),
        current_owner=current_owner,
        current_policy_state=current_policy_state,
        prompt_guard=ExactRuleScopePromptGuard(records=records, artifacts=artifacts),
    )
    rule_scope_inputs = StoredRuleScopeInputResolver(
        records=records,
        artifacts=artifacts,
        resolve_call=rule_scope_call_resolver,
        current_owner=current_owner,
        gate_identity_ref=stored_identity(RequesterRole.RULE_SCOPE_GATE),
    )
    finding_service = FindingNormalizationService(
        records=records,
        current_records=runtime.queries.current_records,
        published_records=runtime.queries.published_records,
        ids=ids,
        clock=clock,
    )
    reporter_agent = ReporterAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata,
        identity_ref=identity(RequesterRole.REPORTER),
    )
    reporter_inputs = StoredReporterInputResolver(
        records=records, resolve_call=reporter_call_resolver
    )
    return T12Services(
        cwe=CWELabelingHandler(cwe_service, cwe_call_resolver),
        technical=TechnicalGateHandler(technical_service, technical_call_resolver),
        rule_scope=RuleScopeGateHandler(
            rule_scope_service, resolve_inputs=rule_scope_inputs
        ),
        finding=FindingNormalizeHandler(service=finding_service, records=records),
        reporter=ReporterWorkHandler(
            agent=reporter_agent, resolve_inputs=reporter_inputs
        ),
        primitive_handoff=PrimitiveUpdateHandoff(
            records=records, current=runtime.queries, ready_work=runner
        ),
    )


__all__ = ["T12Services", "compose_t12_services"]
