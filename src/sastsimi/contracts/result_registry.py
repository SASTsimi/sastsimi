"""Version 1 immutable §08 result-owner inventory and authority checks."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ._domain import exact, same_scope
from .actions import RequesterRole
from .analysis import AnalysisRunState
from .base import ContractModel
from .budget import BudgetLedgerEntry, BudgetReservation
from .chaining import ChainingResult, Primitive, PrimitiveAdmissionDecision
from .dynamic import (
    AgentLog,
    CleanupResult,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCBundle,
    PoCCandidate,
    ReproductionPlan,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPolicyDecision,
)
from .evaluation import AnalysisRunResult, EvaluationRecommendation, EvaluationRunResult
from .gates import CWELabel, RuleScopeImpactReview, TechnicalEvidenceReview
from .hypothesis import (
    HypothesisDuplicateReview,
    HypothesisProcessState,
    HypothesisProposal,
    ProposalProcessState,
    VerificationAssignment,
)
from .policy import (
    PolicyCacheRecord,
    PolicyCollectionResult,
    PolicyParserResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from .refs import StoredDataRef
from .reporting import Finding, ReportDraft
from .static import (
    CodeContextResponse,
    CodeWorkspace,
    RuleExecutionRecord,
    StaticFactBundle,
    ToolRunResult,
)
from .verification import (
    ConEvidenceResult,
    ProEvidenceResult,
    VerificationInitialAssessment,
    VerificationResult,
)


@dataclass(frozen=True)
class ResultBinding:
    model: type[ContractModel]
    owner: RequesterRole
    schema_name: str


def build_registry(
    entries: Iterable[tuple[str, type[ContractModel], RequesterRole]],
) -> Mapping[str, ResultBinding]:
    bindings = {}
    for kind, model, owner in entries:
        if kind in bindings:
            raise ValueError("DUPLICATE_RESULT_KIND")
        name = (
            "EvidenceAgentResult"
            if model in {ProEvidenceResult, ConEvidenceResult}
            else model.__name__
        )
        bindings[kind] = ResultBinding(model, owner, name)
    return MappingProxyType(bindings)


RESULT_REGISTRY = build_registry(
    (
        ("analysis_run_state", AnalysisRunState, RequesterRole.ORCHESTRATION),
        (
            "hypothesis_process_state",
            HypothesisProcessState,
            RequesterRole.ORCHESTRATION,
        ),
        (
            "verification_assignment",
            VerificationAssignment,
            RequesterRole.ORCHESTRATION,
        ),
        ("code_workspace", CodeWorkspace, RequesterRole.REPOSITORY_LOADER),
        (
            "code_context_response",
            CodeContextResponse,
            RequesterRole.CONTEXT_RETRIEVAL_SERVICE,
        ),
        ("tool_run_result", ToolRunResult, RequesterRole.STATIC_ANALYSIS),
        ("static_fact_bundle", StaticFactBundle, RequesterRole.STATIC_ANALYSIS),
        ("rule_execution_record", RuleExecutionRecord, RequesterRole.STATIC_ANALYSIS),
        ("hypothesis_proposal", HypothesisProposal, RequesterRole.ORCHESTRATION),
        (
            "proposal_process_state",
            ProposalProcessState,
            RequesterRole.ORCHESTRATION,
        ),
        (
            "hypothesis_duplicate_review",
            HypothesisDuplicateReview,
            RequesterRole.HYPOTHESIS,
        ),
        ("pro_evidence_result", ProEvidenceResult, RequesterRole.PRO),
        ("con_evidence_result", ConEvidenceResult, RequesterRole.CON),
        ("verification_result", VerificationResult, RequesterRole.VERIFICATION),
        (
            "verification_initial_assessment",
            VerificationInitialAssessment,
            RequesterRole.VERIFICATION,
        ),
        (
            "dynamic_reproduction_tool_request",
            DynamicReproductionToolRequest,
            RequesterRole.DYNAMIC_REPRODUCTION,
        ),
        (
            "primitive_admission_decision",
            PrimitiveAdmissionDecision,
            RequesterRole.PRIMITIVE_ADMISSION_RUNTIME,
        ),
        ("primitive", Primitive, RequesterRole.PRIMITIVE_ADMISSION_RUNTIME),
        ("chaining_result", ChainingResult, RequesterRole.CHAINING),
        (
            "dynamic_reproduction_request",
            DynamicReproductionRequest,
            RequesterRole.VERIFICATION,
        ),
        (
            "environment_requirements",
            EnvironmentRequirements,
            RequesterRole.DYNAMIC_REPRODUCTION,
        ),
        ("reproduction_plan", ReproductionPlan, RequesterRole.DYNAMIC_REPRODUCTION),
        (
            "environment_recipe",
            EnvironmentRecipe,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
        ),
        (
            "sandbox_environment",
            SandboxEnvironment,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
        ),
        ("cleanup_result", CleanupResult, RequesterRole.REPRODUCTION_SETUP_AUTOMATION),
        (
            "sandbox_policy_decision",
            SandboxPolicyDecision,
            RequesterRole.SANDBOX_CONTROLLER,
        ),
        (
            "sandbox_command_record",
            SandboxCommandRecord,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
        ),
        ("poc_candidate", PoCCandidate, RequesterRole.DYNAMIC_REPRODUCTION),
        (
            "dynamic_reproduction_conclusion",
            DynamicReproductionConclusion,
            RequesterRole.DYNAMIC_REPRODUCTION,
        ),
        ("agent_log", AgentLog, RequesterRole.REPRODUCTION_SESSION_MANAGER),
        ("poc_bundle", PoCBundle, RequesterRole.REPRODUCTION_SESSION_MANAGER),
        (
            "dynamic_reproduction_result",
            DynamicReproductionResult,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
        ),
        ("cwe_label", CWELabel, RequesterRole.CWE_LABELING),
        ("run_policy_state", RunPolicyState, RequesterRole.POLICY_COLLECTOR),
        ("policy_cache_record", PolicyCacheRecord, RequesterRole.POLICY_COLLECTOR),
        ("policy_parser_result", PolicyParserResult, RequesterRole.POLICY_PARSER),
        (
            "policy_collection_result",
            PolicyCollectionResult,
            RequesterRole.POLICY_COLLECTOR,
        ),
        ("program_policy_record", ProgramPolicyRecord, RequesterRole.POLICY_COLLECTOR),
        (
            "technical_evidence_review",
            TechnicalEvidenceReview,
            RequesterRole.TECHNICAL_GATE,
        ),
        (
            "rule_scope_impact_review",
            RuleScopeImpactReview,
            RequesterRole.RULE_SCOPE_GATE,
        ),
        ("finding", Finding, RequesterRole.VERIFICATION),
        ("report_draft", ReportDraft, RequesterRole.REPORTER),
        ("budget_reservation", BudgetReservation, RequesterRole.BUDGET_RUNTIME),
        ("budget_ledger_entry", BudgetLedgerEntry, RequesterRole.BUDGET_RUNTIME),
        (
            "evaluation_run_result",
            EvaluationRunResult,
            RequesterRole.R8_EVALUATION_RUNTIME,
        ),
        (
            "evaluation_recommendation",
            EvaluationRecommendation,
            RequesterRole.R8_EVALUATION_RUNTIME,
        ),
        ("analysis_run_result", AnalysisRunResult, RequesterRole.ORCHESTRATION),
    )
)


def validate_result_owner(
    kind: str,
    candidate: ContractModel,
    requested_by: RequesterRole,
    *,
    requester_identity_ref: StoredDataRef | None = None,
    finding_service_identity_ref: StoredDataRef | None = None,
    active_assignment_owner_ref: StoredDataRef | None = None,
    finding_assignment: VerificationAssignment | None = None,
    expected_assignment_ref: StoredDataRef | None = None,
) -> None:
    binding = RESULT_REGISTRY.get(kind)
    if binding is None or binding.owner != requested_by:
        raise ValueError("RESULT_OWNER_MISMATCH")
    # Revalidate to reject model_construct/model_copy bypasses at trust boundaries.
    validated = binding.model.model_validate_json(candidate.model_dump_json())
    if validated.model_dump()["meta"]["record_type"] != kind:
        raise ValueError("RECORD_KIND_MISMATCH")
    if kind == "finding" and (
        requester_identity_ref is None
        or finding_service_identity_ref is None
        or active_assignment_owner_ref is None
        or requester_identity_ref != finding_service_identity_ref
        or finding_assignment is None
        or expected_assignment_ref is None
        or finding_assignment.status != "ACTIVE"
        or finding_assignment.owner_identity_ref != active_assignment_owner_ref
    ):
        raise ValueError("FINDING_NORMALIZER_AUTHORITY_REQUIRED")
    if isinstance(validated, Finding):
        assert finding_assignment is not None and expected_assignment_ref is not None
        exact(expected_assignment_ref, finding_assignment, validated.meta)
        same_scope(validated.meta, finding_assignment.meta)
