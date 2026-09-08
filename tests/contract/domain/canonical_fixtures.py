"""Wire fixtures derived from §08 blocks, not production model introspection."""

import re
from typing import Any

from .fixtures import (
    bundle,
    dynamic_failure,
    dynamic_request,
    event,
    evidence,
    location,
    meta,
    proposal,
    ref,
    tool,
    verification,
)
from .test_inventory import canonical_fields

BLOCKS = canonical_fields()
NOW = "2026-09-08T00:00:00Z"
REF_KINDS = {
    "action_decision_ref": "action_decision",
    "verification_result_ref": "verification_result",
    "source_verification_ref": "verification_result",
    "current_verification_ref": "verification_result",
    "hypothesis_ref": "vulnerability_hypothesis",
    "proposal_ref": "hypothesis_proposal",
    "playbook_ref": "verification_playbook",
    "playbook_application_ref": "playbook_application",
    "pro_evidence_ref": "pro_evidence_result",
    "con_evidence_ref": "con_evidence_result",
    "request_ref": "dynamic_reproduction_request",
    "reproduction_plan_ref": "reproduction_plan",
    "environment_requirements_ref": "environment_requirements",
    "requirements_ref": "environment_requirements",
    "environment_recipe_ref": "environment_recipe",
    "environment_ref": "sandbox_environment",
    "agent_log_ref": "agent_log",
    "candidate_ref": "poc_candidate",
    "poc_ref": "poc_bundle",
    "technical_review_ref": "technical_evidence_review",
    "cwe_label_ref": "cwe_label",
    "rule_scope_impact_review_ref": "rule_scope_impact_review",
    "policy_collection_result_ref": "policy_collection_result",
    "policy_record_ref": "program_policy_record",
    "run_policy_state_ref": "run_policy_state",
    "resource_profile_ref": "dynamic_reproduction_lifecycle_profile",
    "policy_work_ref": "work_execution_state",
    "tool_request_ref": "dynamic_reproduction_tool_request",
    "dynamic_result_ref": "dynamic_reproduction_result",
    "evaluation_result_ref": "evaluation_run_result",
    "sandbox_profile_ref": "sandbox_profile",
    "collection_result_ref": "policy_collection_result",
    "finding_ref": "finding",
}


def kind_name(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def make(name: str, kind: str | None = None) -> dict[str, Any]:
    if name == "StaticFactBundle":
        return bundle()
    if name == "ToolRunResult":
        return tool()
    if name == "HypothesisProposal":
        return proposal()
    if name == "EvidenceAgentResult":
        return evidence("CON" if kind == "con_evidence_result" else "PRO")
    if name == "VerificationResult":
        return verification()
    if name == "DynamicReproductionRequest":
        return dynamic_request()
    if name == "DynamicReproductionResult":
        return dynamic_failure()
    if name == "CodeLocation":
        return location()
    kind = kind or kind_name(name)
    value: dict[str, Any] = {}
    for field, spec in BLOCKS[name].items():
        if field == "meta":
            hypothesis = (
                None
                if "without hypothesis" in spec
                or "hypothesis_id null" in spec
                or name in {"RunPolicyState", "StaticFactBundle", "ChainingResult"}
                else "h1"
            )
            attempt = (
                None
                if "attempt_id null" in spec or "without hypothesis/attempt" in spec
                else "at1"
            )
            if spec == "RunMeta":
                value[field] = meta(kind, run=True)
            elif spec == "PolicyCacheMeta":
                value[field] = {
                    key: item
                    for key, item in meta(kind, run=True).items()
                    if key != "analysis_id"
                } | {"program_id": "program1"}
            else:
                value[field] = meta(kind, hypothesis=hypothesis, attempt=attempt)
        elif " | null" in spec:
            value[field] = None
        elif spec.startswith("["):
            value[field] = []
        elif "StoredDataRef" in spec:
            value[field] = ref(REF_KINDS.get(field, field.removesuffix("_ref")))
            if spec.startswith("RunStoredDataRef"):
                value[field] = {
                    key: item
                    for key, item in value[field].items()
                    if key not in {"workspace_id", "commit_id"}
                } | {"analysis_id": "a1"}
        elif spec == "timestamp":
            value[field] = NOW
        elif spec == "integer":
            value[field] = 1
        elif spec == "boolean":
            value[field] = False
        elif spec == "map":
            value[field] = {}
        elif spec == "string":
            value[field] = "a" * 64 if field.endswith(("digest", "hash")) else field
        elif spec in BLOCKS:
            value[field] = make(spec)
        else:
            value[field] = spec.split(" | ")[0]
    if "workspace_id" in value:
        value["workspace_id"] = "ws1"
    if "commit_id" in value:
        value["commit_id"] = "c1"
    if "program_id" in value:
        value["program_id"] = "program1"
    if name == "CodeWorkspace":
        value.update(analysis_id="a1", commit_id=None)
    if name == "RuleExecutionRecord":
        value["rules"] = [
            dict(
                rule_id="r1",
                selection_status="SELECTED",
                execution_status="EXECUTED",
                hit_count=0,
                reason=None,
                detail=None,
            )
        ]
    if name == "HypothesisDuplicateReview":
        value["candidate_hypothesis_refs"] = [ref("vulnerability_hypothesis")]
    if name == "PrimitiveAdmissionDecision":
        value["rule_scope_review_ref"] = ref("rule_scope_impact_review")
    if name == "Primitive":
        draft = make("PrimitiveDraft")
        draft["evidence_refs"] = [ref("code", record=False)]
        value.update(
            inputs=[draft],
            source_hypothesis_id="h1",
            evidence_refs=draft["evidence_refs"],
        )
    if name == "SandboxPolicyDecision":
        value["reason_codes"] = ["LOCAL_BOUNDARY_OK"]
    if name == "SandboxCommandRecord":
        # Canonical SHA-256 of the exact hand-written empty command fixture.
        value.update(
            executable="python",
            arguments=[],
            working_directory="/sandbox",
            environment_binding_refs=[],
            stdin_ref=None,
            secret_refs=[],
            command_digest="e554d505be5cc3011c3ba65661fa4dd9b54516470937c8350e1cbc99e4e6d7c7",
        )
    if name == "AgentLog":
        value["events"] = [event()]
    if name in {"PoCBundle", "CWELabel"}:
        value["evidence_refs"] = [ref("observation", record=False)]
    if name == "RunPolicyState":
        value["meta"] = meta(kind, attempt=None)
    if name == "PolicyParserResult":
        value["parsed_output_ref"] = ref("parser_output", record=False)
    if name == "PolicyCollectionResult":
        value.update(
            official_source_refs=[ref("official_source", record=False)],
            parser_result_refs=[ref("policy_parser_result")],
            policy_record_ref=ref("program_policy_record"),
        )
    if name == "ProgramPolicyRecord":
        value.update(
            freshness_status="UNVERIFIED",
            parser_result_refs=[ref("policy_parser_result")],
        )
    if name == "PolicyCacheRecord":
        value.update(
            policy_record_ref=ref("program_policy_record"),
            parser_result_refs=[ref("policy_parser_result")],
            freshness_evidence_refs=[ref("freshness", record=False)],
            freshness_valid_until="2026-09-09T00:00:00Z",
        )
    if name == "RuleScopeImpactReview":
        value["evidence_links"] = [
            dict(
                link_id=area,
                area=area,
                policy_item_ids=[],
                evidence_refs=[ref("official_source", record=False)],
            )
            for area in ["RULE", "SCOPE", "IMPACT", "TESTING_RESTRICTION"]
        ]
    if name == "BudgetReservation":
        value["meta"] = meta(kind, run=True)
        value["budget_binding_ref"] = {
            key: item
            for key, item in ref("execution_budget_profile").items()
            if key not in {"workspace_id", "commit_id"}
        } | {"analysis_id": "a1"}
        value["action_ref"] = {
            key: item
            for key, item in ref("action_request").items()
            if key not in {"workspace_id", "commit_id"}
        } | {"analysis_id": "a1"}
        value["work_ref"] = {
            key: item
            for key, item in ref("work_execution_state").items()
            if key not in {"workspace_id", "commit_id"}
        } | {"analysis_id": "a1"}
    if name == "BudgetLedgerEntry":
        value["meta"] = meta(kind, run=True)
        for field, ref_kind in [
            ("budget_binding_ref", "execution_budget_profile"),
            ("reservation_ref", "budget_reservation"),
            ("action_ref", "action_request"),
            ("work_ref", "work_execution_state"),
        ]:
            value[field] = {
                key: item
                for key, item in ref(ref_kind).items()
                if key not in {"workspace_id", "commit_id"}
            } | {"analysis_id": "a1"}
    if name == "ResourceUsageSummary":
        value.update(usage_complete=False, unavailable_reasons=["Cost not reported"])
    if name == "AnalysisRunResult":
        value.update(
            status="FAILED",
            workspace_id=None,
            commit_id=None,
            failed_hypothesis_count=0,
        )
    return value
