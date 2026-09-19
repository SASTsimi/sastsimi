"""Executable, content-only prompt catalog for LOCAL_EVALUATION.

The catalog is deliberately derived from the models consumed by each Agent.
It does not grant Production approval and it omits the resumable dynamic tool
loop, which the official local Codex route cannot currently execute safely.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import TypeAdapter, ValidationError

from sastsimi.agents import chaining as chaining_agent
from sastsimi.agents import cwe_labeling as cwe_agent
from sastsimi.agents import dynamic_reproduction as dynamic_agent
from sastsimi.agents import hypothesis as hypothesis_agent
from sastsimi.agents import policy_parser as policy_agent
from sastsimi.agents import pro as evidence_agent
from sastsimi.agents import rule_scope_gate as scope_agent
from sastsimi.agents import technical_gate as technical_agent
from sastsimi.agents import verification as verification_agent
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMRole, PromptInputSlot
from sastsimi.contracts.reporting import ReportContent

from .local_evaluation import REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES

_FIELD_ALL = ("$",)


def _slot(
    name: str,
    kind: str,
    cardinality: str = "REQUIRED_ONE",
    fields: tuple[str, ...] = _FIELD_ALL,
) -> PromptInputSlot:
    return PromptInputSlot.model_validate(
        {
            "slot": name,
            "data_kind": kind,
            "field_paths": fields,
            "cardinality": cardinality,
            "trust_class": "UNTRUSTED_DATA",
        }
    )


_DEBATE_PUBLIC = (
    _slot("hypothesis", "vulnerability_hypothesis"),
    _slot("proposal", "hypothesis_proposal"),
    _slot("playbook_policy", "playbook_policy"),
    _slot("playbook", "verification_playbook"),
    _slot("facts", "static_fact_bundle"),
    _slot("playbook_application", "playbook_application"),
)
_VERIFICATION_PUBLIC = tuple(
    slot for slot in _DEBATE_PUBLIC if str(slot.data_kind) != "hypothesis_proposal"
)
_DEBATE_RESULTS = (
    _slot("pro_evidence", "pro_evidence_result"),
    _slot("con_evidence", "con_evidence_result"),
)
_EVIDENCE_OPTIONAL = (
    _slot("evidence_hypotheses", "vulnerability_hypothesis", "OPTIONAL_MANY"),
    _slot("evidence_proposals", "hypothesis_proposal", "OPTIONAL_MANY"),
    _slot("evidence_policies", "playbook_policy", "OPTIONAL_MANY"),
    _slot("evidence_playbooks", "verification_playbook", "OPTIONAL_MANY"),
    _slot("evidence_applications", "playbook_application", "OPTIONAL_MANY"),
    _slot("evidence_facts", "static_fact_bundle", "OPTIONAL_MANY"),
    _slot("tool_results", "tool_run_result", "OPTIONAL_MANY"),
    _slot("rule_runs", "rule_execution_record", "OPTIONAL_MANY"),
    _slot("code_context", "code_context_response", "OPTIONAL_MANY"),
    _slot("observations", "artifact", "OPTIONAL_MANY"),
    _slot("agent_logs", "agent_log", "OPTIONAL_MANY"),
    _slot("sandbox_commands", "sandbox_command_record", "OPTIONAL_MANY"),
    _slot("tool_requests", "dynamic_reproduction_tool_request", "OPTIONAL_MANY"),
    _slot("dynamic_conclusions", "dynamic_reproduction_conclusion", "OPTIONAL_MANY"),
    _slot("environment_recipes", "environment_recipe", "OPTIONAL_MANY"),
    _slot("sandbox_environments", "sandbox_environment", "OPTIONAL_MANY"),
)


@dataclass(frozen=True, slots=True)
class LocalEvaluationPromptSpec:
    role: LLMRole
    task_kind: str
    result_kind: str
    template_path: str
    input_slots: tuple[PromptInputSlot, ...]


_INPUTS: dict[tuple[str, str], tuple[PromptInputSlot, ...]] = {
    ("HYPOTHESIS", "GENERATE_INITIAL"): (
        _slot(
            "facts",
            "static_fact_bundle",
            fields=(
                "/entities",
                "/locations",
                "/source_candidates",
                "/sink_candidates",
                "/sanitizer_candidates",
                "/validator_candidates",
                "/auth_and_permission_checks",
                "/other_facts",
                "/call_edges",
                "/data_flow_candidates",
                "/route_bindings",
                "/tool_runs",
                "/gaps",
                "/errors",
            ),
        ),
    ),
    ("PRO", "COLLECT_SUPPORT"): _DEBATE_PUBLIC,
    ("CON", "COLLECT_COUNTEREVIDENCE"): _DEBATE_PUBLIC,
    ("VERIFICATION", "ASSESS_INITIAL"): (*_VERIFICATION_PUBLIC, *_DEBATE_RESULTS),
    ("VERIFICATION", "CREATE_DYNAMIC_REQUEST"): (
        *_VERIFICATION_PUBLIC,
        *_DEBATE_RESULTS,
        _slot("initial_assessment", "verification_initial_assessment"),
        _slot("sandbox_profile", "sandbox_profile"),
    ),
    ("VERIFICATION", "FINAL_VERDICT"): (
        *_VERIFICATION_PUBLIC,
        *_DEBATE_RESULTS,
        _slot("initial_assessment", "verification_initial_assessment"),
        _slot("dynamic_request", "dynamic_reproduction_request", "OPTIONAL_ONE"),
        _slot("dynamic_result", "dynamic_reproduction_result", "OPTIONAL_ONE"),
        _slot("validated_poc", "poc_bundle", "OPTIONAL_ONE"),
    ),
    ("DYNAMIC_REPRODUCTION", "DERIVE_ENVIRONMENT"): (
        _slot("dynamic_request", "dynamic_reproduction_request"),
    ),
    ("DYNAMIC_REPRODUCTION", "PLAN_REPRODUCTION"): (
        _slot("dynamic_request", "dynamic_reproduction_request"),
        _slot("environment_requirements", "environment_requirements"),
    ),
    ("DYNAMIC_REPRODUCTION", "CREATE_POC_CANDIDATE"): (
        _slot("dynamic_request", "dynamic_reproduction_request"),
        _slot("reproduction_plan", "reproduction_plan"),
        _slot("sandbox_environment", "sandbox_environment"),
        _slot("code_context", "code_context_response", "REQUIRED_MANY"),
        _slot(
            "code_fragments",
            "artifact",
            "REQUIRED_MANY",
            fields=("/redacted_body",),
        ),
    ),
    ("DYNAMIC_REPRODUCTION", "INTERPRET_ATTEMPT"): (
        _slot("dynamic_request", "dynamic_reproduction_request"),
        _slot("reproduction_plan", "reproduction_plan"),
        _slot("sandbox_environment", "sandbox_environment"),
        _slot("poc_candidate", "poc_candidate", "OPTIONAL_ONE"),
        _slot("agent_log", "agent_log"),
        _slot("observations", "artifact", "REQUIRED_MANY"),
    ),
    ("CWE_LABELING", "CLASSIFY_CWE"): (
        _slot("verification", "verification_result"),
        _slot("dynamic_result", "dynamic_reproduction_result"),
        _slot("validated_poc", "poc_bundle"),
        _slot("process", "hypothesis_process_state"),
        *_EVIDENCE_OPTIONAL,
    ),
    ("TECHNICAL_GATE", "REVIEW_TECHNICAL"): (
        _slot("verification", "verification_result"),
        _slot("dynamic_result", "dynamic_reproduction_result"),
        _slot("validated_poc", "poc_bundle"),
        _slot("cwe_label", "cwe_label"),
        _slot("process", "hypothesis_process_state"),
        _slot("assignment", "verification_assignment"),
        _slot("budget", "budget_profile_binding"),
        *_EVIDENCE_OPTIONAL,
    ),
    ("RULE_SCOPE_GATE", "REVIEW"): (
        _slot("verification", "verification_result"),
        _slot("cwe_label", "cwe_label"),
        _slot("technical_review", "technical_evidence_review"),
        _slot("policy_state", "run_policy_state"),
        _slot("policy_collection", "policy_collection_result"),
        _slot("policy", "program_policy_record", "OPTIONAL_ONE"),
        _slot("dynamic_result", "dynamic_reproduction_result"),
        _slot("validated_poc", "poc_bundle"),
        *_EVIDENCE_OPTIONAL,
    ),
    ("REPORTER", "CREATE_DRAFT"): (
        _slot("finding", "finding"),
        _slot("finding_index", "finding_index_state"),
        _slot("verification", "verification_result"),
        _slot("dynamic_result", "dynamic_reproduction_result"),
        _slot("validated_poc", "poc_bundle"),
        _slot("cwe_label", "cwe_label"),
        _slot("technical_review", "technical_evidence_review"),
        _slot("rule_scope_review", "rule_scope_impact_review"),
        _slot("policy_state", "run_policy_state"),
        _slot("policy_collection", "policy_collection_result"),
        _slot("policy", "program_policy_record", "OPTIONAL_ONE"),
    ),
    ("POLICY_PARSER", "PARSE_OFFICIAL_POLICY"): (
        _slot("official_policy", "artifact", fields=("/redacted_body",)),
    ),
    ("CHAINING", "MATCH_PRIMITIVES"): (
        _slot("indexes", "primitive_index_state", "REQUIRED_MANY"),
        _slot("considered", "primitive", "REQUIRED_MANY"),
        _slot(
            "prepared_input",
            "artifact",
            fields=("/redacted_body",),
        ),
    ),
}


LOCAL_EVALUATION_PROMPT_SPECS = tuple(
    LocalEvaluationPromptSpec(
        role=route.role,
        task_kind=route.task_kind,
        result_kind=route.result_kind,
        template_path=route.template_path.as_posix(),
        input_slots=_INPUTS[(str(route.role), route.task_kind)],
    )
    for route in REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES
)


_OUTPUTS: dict[tuple[str, str], TypeAdapter[Any]] = {
    ("HYPOTHESIS", "GENERATE_INITIAL"): TypeAdapter(
        tuple[hypothesis_agent._ProposalContent, ...]  # noqa: SLF001
    ),
    ("PRO", "COLLECT_SUPPORT"): TypeAdapter(evidence_agent._EvidenceOutputContent),  # noqa: SLF001
    ("CON", "COLLECT_COUNTEREVIDENCE"): TypeAdapter(
        evidence_agent._EvidenceOutputContent  # noqa: SLF001
    ),
    ("VERIFICATION", "ASSESS_INITIAL"): TypeAdapter(
        verification_agent._InitialContent  # noqa: SLF001
    ),
    ("VERIFICATION", "CREATE_DYNAMIC_REQUEST"): TypeAdapter(
        verification_agent._DynamicRequestContent  # noqa: SLF001
    ),
    ("VERIFICATION", "FINAL_VERDICT"): TypeAdapter(
        verification_agent._FinalContent  # noqa: SLF001
    ),
    ("DYNAMIC_REPRODUCTION", "DERIVE_ENVIRONMENT"): TypeAdapter(
        dynamic_agent._EnvironmentRequirementsContent  # noqa: SLF001
    ),
    ("DYNAMIC_REPRODUCTION", "PLAN_REPRODUCTION"): TypeAdapter(
        dynamic_agent._ReproductionPlanContent  # noqa: SLF001
    ),
    ("DYNAMIC_REPRODUCTION", "CREATE_POC_CANDIDATE"): TypeAdapter(
        dynamic_agent._PoCCandidateContent  # noqa: SLF001
    ),
    ("DYNAMIC_REPRODUCTION", "INTERPRET_ATTEMPT"): TypeAdapter(
        dynamic_agent._ConclusionContent  # noqa: SLF001
    ),
    ("CWE_LABELING", "CLASSIFY_CWE"): TypeAdapter(cwe_agent._CWEContent),  # noqa: SLF001
    ("TECHNICAL_GATE", "REVIEW_TECHNICAL"): TypeAdapter(
        technical_agent._TechnicalContent  # noqa: SLF001
    ),
    ("RULE_SCOPE_GATE", "REVIEW"): TypeAdapter(scope_agent.RuleScopeProposal),
    ("REPORTER", "CREATE_DRAFT"): TypeAdapter(ReportContent),
    ("POLICY_PARSER", "PARSE_OFFICIAL_POLICY"): TypeAdapter(
        policy_agent.ParsedPolicyContent
    ),
    ("CHAINING", "MATCH_PRIMITIVES"): TypeAdapter(chaining_agent._OutputContent),  # noqa: SLF001
}


def _adapter(role: str, task_kind: str) -> TypeAdapter[Any]:
    try:
        return _OUTPUTS[(role, task_kind)]
    except KeyError:
        raise ValueError("LOCAL_EVALUATION_OUTPUT_ROUTE_UNAVAILABLE") from None


def local_output_schema(role: str, task_kind: str) -> str:
    """Return the canonical content-only JSON schema consumed by the Agent."""

    return canonical_bytes(_adapter(role, task_kind).json_schema()).decode("utf-8")


def validate_local_output(role: str, task_kind: str, value: object) -> None:
    """Apply the same content shape that the downstream Agent will parse."""

    try:
        _adapter(role, task_kind).validate_json(canonical_bytes(value), strict=True)
    except (TypeError, ValidationError, ValueError):
        raise ValueError("LOCAL_EVALUATION_OUTPUT_INVALID") from None


__all__ = [
    "LOCAL_EVALUATION_PROMPT_SPECS",
    "LocalEvaluationPromptSpec",
    "local_output_schema",
    "validate_local_output",
]
