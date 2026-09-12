"""Deterministic JSON Schema 2020-12 exports; generated files are never hand edited."""

import argparse
import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from pydantic import BaseModel

from .actions import ActionCheck, ActionDecision, ActionRequest
from .budget import (
    BudgetLedgerEntry,
    BudgetProfileBinding,
    BudgetRemaining,
    BudgetReservation,
    BudgetUnits,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    VerificationBudgetProfile,
    WorkBudgetLimit,
    WorkBudgetProfile,
)
from .capabilities import CapabilityApprovalEvidence, RuntimeCapabilityProfile
from .chaining import PrimitiveIndexState
from .dynamic import DynamicReproductionState, SandboxProfile
from .evaluation import EvaluationRunConfig
from .hypothesis import VulnerabilityHypothesis
from .llm import (
    ClientExecutionProfile,
    ExecutionLimits,
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptPayload,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from .records import PolicyCacheMeta, RecordMeta, RunMeta
from .refs import HostConfigurationRef, PolicyCacheRef, RunStoredDataRef, StoredDataRef
from .reporting import FindingIndexState, ReportProcessState
from .result_registry import RESULT_REGISTRY
from .static import (
    CodeContextRequest,
    RepositoryExecutionSelection,
    RepositoryProfile,
    StaticToolProfile,
)
from .verification import PlaybookApplication, PlaybookPolicy, VerificationPlaybook
from .work import StateTransition, TransitionCommit, WorkAttempt, WorkExecutionState

CORE_SCHEMAS: Mapping[str, type[BaseModel]] = MappingProxyType(
    {
        "run_meta": RunMeta,
        "record_meta": RecordMeta,
        "policy_cache_meta": PolicyCacheMeta,
        "run_stored_data_ref": RunStoredDataRef,
        "stored_data_ref": StoredDataRef,
        "host_configuration_ref": HostConfigurationRef,
        "policy_cache_ref": PolicyCacheRef,
        "work_execution_state": WorkExecutionState,
        "work_attempt": WorkAttempt,
        "state_transition": StateTransition,
        "transition_commit": TransitionCommit,
        "action_request": ActionRequest,
        "action_check": ActionCheck,
        "action_decision": ActionDecision,
        "sandbox_profile": SandboxProfile,
        "code_context_request": CodeContextRequest,
        "static_tool_profile": StaticToolProfile,
        "repository_profile": RepositoryProfile,
        "repository_execution_selection": RepositoryExecutionSelection,
        "tool_capability_evidence": CapabilityApprovalEvidence,
        "runtime_capability_profile": RuntimeCapabilityProfile,
        "vulnerability_hypothesis": VulnerabilityHypothesis,
        "playbook_application": PlaybookApplication,
        "dynamic_reproduction_state": DynamicReproductionState,
        "primitive_index_state": PrimitiveIndexState,
        "finding_index_state": FindingIndexState,
        "report_process_state": ReportProcessState,
        "provider_validation_evidence": ProviderValidationEvidence,
        "client_execution_profile": ClientExecutionProfile,
        "provider_profile": ProviderProfile,
        "execution_limits": ExecutionLimits,
        "llm_retry_policy": LLMRetryPolicy,
        "llm_tool_policy": LLMToolPolicy,
        "prompt_redaction_policy": PromptRedactionPolicy,
        "output_schema_spec": OutputSchemaSpec,
        "semantic_validator_spec": SemanticValidatorSpec,
        "prompt_registry_entry": PromptRegistryEntry,
        "prompt_payload": PromptPayload,
        "llm_call_spec": LLMCallSpec,
        "llm_invocation_request": LLMInvocationRequest,
        "llm_invocation_result": LLMInvocationResult,
        "llm_invocation_log": LLMInvocationLog,
        "evaluation_run_config": EvaluationRunConfig,
        "playbook_policy": PlaybookPolicy,
        "verification_playbook": VerificationPlaybook,
        "execution_budget_profile": ExecutionBudgetProfile,
        "work_budget_limit": WorkBudgetLimit,
        "work_budget_profile": WorkBudgetProfile,
        "verification_budget_profile": VerificationBudgetProfile,
        "dynamic_reproduction_lifecycle_profile": DynamicReproductionLifecycleProfile,
        "budget_profile_binding": BudgetProfileBinding,
        "budget_units": BudgetUnits,
        "budget_reservation": BudgetReservation,
        "budget_ledger_entry": BudgetLedgerEntry,
        "budget_remaining": BudgetRemaining,
    }
)


def schema_documents() -> dict[str, bytes]:
    documents = {}
    schemas = dict(CORE_SCHEMAS)
    schemas.update({kind: binding.model for kind, binding in RESULT_REGISTRY.items()})
    for kind, model in sorted(schemas.items()):
        schema = model.model_json_schema(by_alias=False, mode="validation")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        documents[f"{kind}/1.schema.json"] = (
            json.dumps(schema, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
    return documents


def check_schemas(root: Path) -> None:
    expected = schema_documents()
    actual = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    drift = sorted(
        name
        for name in expected.keys() & actual.keys()
        if expected[name] != actual[name]
    )
    if missing or extra or drift:
        raise ValueError(f"Schema missing={missing}, extra={extra}, drift={drift}")


def export_schemas(root: Path) -> None:
    for name, data in schema_documents().items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    # Unknown files are preserved and reported, never silently removed.
    check_schemas(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("schemas/generated"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            check_schemas(args.root)
        else:
            export_schemas(args.root)
    except ValueError as error:
        parser.exit(1, f"{error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
