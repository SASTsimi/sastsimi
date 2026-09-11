"""Build one valid executed-candidate chain; mutations live in individual tests."""

from typing import Any

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import (
    POC_RUNTIME_PATH,
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

from .canonical_fixtures import make
from .fixtures import event, ref, wire


def bound(record: ContractModel) -> dict[str, Any]:
    metadata = record.model_dump(mode="json")["meta"]
    return ref(metadata["record_type"]) | {
        "record_id": metadata["record_id"],
        "content_hash": content_hash(record),
        "workspace_id": metadata["workspace_id"],
        "commit_id": metadata["commit_id"],
    }


def dynamic_success() -> dict[str, Any]:
    request = wire(DynamicReproductionRequest, make("DynamicReproductionRequest"))
    request_ref = bound(request)
    requirements = wire(
        EnvironmentRequirements,
        make("EnvironmentRequirements") | dict(request_ref=request_ref),
    )
    plan = wire(
        ReproductionPlan,
        make("ReproductionPlan")
        | dict(
            request_ref=request_ref,
            hypothesis_ref=request.hypothesis_ref.model_dump(mode="json"),
            environment_requirements_ref=bound(requirements),
        ),
    )
    recipe = wire(
        EnvironmentRecipe,
        make("EnvironmentRecipe")
        | dict(
            request_ref=request_ref, environment_requirements_ref=bound(requirements)
        ),
    )
    environment = wire(
        SandboxEnvironment,
        make("SandboxEnvironment")
        | dict(
            request_ref=request_ref,
            reproduction_plan_ref=bound(plan),
            environment_recipe_ref=bound(recipe),
            requirements_ref=bound(requirements),
        ),
    )
    policy = wire(
        SandboxPolicyDecision,
        make("SandboxPolicyDecision") | dict(request_ref=request_ref),
    )
    candidate = wire(
        PoCCandidate,
        make("PoCCandidate", "poc_candidate")
        | dict(request_ref=request_ref, reproduction_plan_ref=bound(plan)),
    )
    command_input = make("SandboxCommandInput") | {
        "executable": "/bin/sh",
        "arguments": [POC_RUNTIME_PATH],
        "working_directory": "/workspace",
    }
    tool = wire(
        DynamicReproductionToolRequest,
        make("DynamicReproductionToolRequest")
        | dict(
            request_ref=request_ref,
            reproduction_plan_ref=bound(plan),
            environment_ref=bound(environment),
            action="RUN_COMMAND",
            command=command_input,
        ),
    )
    command = wire(
        SandboxCommandRecord,
        make("SandboxCommandRecord")
        | command_input
        | dict(
            request_ref=request_ref,
            reproduction_plan_ref=bound(plan),
            environment_recipe_ref=bound(recipe),
            environment_ref=bound(environment),
            tool_request_ref=bound(tool),
            command_digest=content_hash(command_input),
            action_id="execute",
        ),
    )
    events = []
    for number, (event_type, action) in enumerate(
        [
            ("SESSION_STARTED", "session"),
            ("AGENT_STARTED", "agent"),
            ("POC_CANDIDATE_CREATED", "candidate"),
            ("POC_EXECUTION_STARTED", "execute"),
            ("COMMAND_STARTED", "execute"),
            ("COMMAND_FINISHED", "execute"),
            ("POC_EXECUTION_FINISHED", "execute"),
            ("AGENT_FINISHED", "agent"),
            ("SESSION_FINISHED", "session"),
        ],
        1,
    ):
        item = event() | dict(
            event_id=f"event{number}",
            sequence=number,
            event_type=event_type,
            action_id=action,
            environment_ref=bound(environment),
            environment_recipe_ref=bound(recipe),
        )
        if event_type == "SESSION_STARTED":
            item["input_refs"] = [bound(policy)]
        if event_type.startswith("POC_"):
            item["poc_candidate_ref"] = bound(candidate)
        if event_type.startswith("POC_EXECUTION_") or event_type.startswith(
            "COMMAND_"
        ):
            item.update(
                actor="TOOL_RUNTIME",
                poc_candidate_ref=bound(candidate),
                tool_request_ref=bound(tool),
                command_ref=bound(command),
                command_digest=command.command_digest,
                redaction_status=command.redaction_status,
            )
        if event_type.startswith("POC_EXECUTION_"):
            item["input_refs"] = [candidate.content_ref.model_dump(mode="json")]
        if event_type in {"POC_EXECUTION_FINISHED", "COMMAND_FINISHED"}:
            item["exit_code"] = 0
            item["output_refs"] = [ref("observation", record=False)]
        events.append(item)
    log = wire(
        AgentLog, make("AgentLog") | dict(request_ref=request_ref, events=events)
    )
    conclusion = wire(
        DynamicReproductionConclusion,
        make("DynamicReproductionConclusion")
        | dict(
            request_ref=request_ref,
            reproduction_plan_ref=bound(plan),
            environment_ref=bound(environment),
            poc_candidate_ref=bound(candidate),
            observation_refs=[ref("observation", record=False)],
            hypothesis_evidence_refs=[ref("observation", record=False)],
        ),
    )
    poc = wire(
        PoCBundle,
        make("PoCBundle", "poc_bundle")
        | dict(
            request_ref=request_ref,
            reproduction_plan_ref=bound(plan),
            environment_recipe_ref=bound(recipe),
            environment_ref=bound(environment),
            agent_log_ref=bound(log),
            candidate_ref=bound(candidate),
            execution_action_id="execute",
            evidence_refs=[ref("observation", record=False)],
        ),
    )
    cleanup = wire(
        CleanupResult,
        make("CleanupResult")
        | dict(request_ref=request_ref, environment_refs=[bound(environment)]),
    )
    result = wire(
        DynamicReproductionResult,
        make("DynamicReproductionResult")
        | dict(
            request_ref=request_ref,
            reproduction_plan_ref=bound(plan),
            action_decision_ref=ref("action_decision"),
            policy_decision_ref=bound(policy),
            agent_invoked=True,
            agent_log_ref=bound(log),
            agent_conclusion_ref=bound(conclusion),
            environment_recipe_ref=bound(recipe),
            environment_ref=bound(environment),
            poc_candidate_ref=bound(candidate),
            poc_ref=bound(poc),
            observation_refs=[ref("observation", record=False)],
            status="SUCCEEDED",
            failure_category="NONE",
            failure_reason=None,
            plan_issues=[],
            hypothesis_outcome="SUPPORTED",
            hypothesis_evidence_refs=[ref("observation", record=False)],
            hypothesis_linkage=conclusion.hypothesis_linkage,
            plan_execution_status="EXECUTABLE",
            limitations=[],
            cleanup_required=True,
            cleanup_status="SUCCEEDED",
            cleanup_ref=bound(cleanup),
        ),
    )
    return dict(
        request=request,
        requirements=requirements,
        plan=plan,
        recipe=recipe,
        environment=environment,
        policy=policy,
        candidate=candidate,
        log=log,
        conclusion=conclusion,
        poc=poc,
        cleanup=cleanup,
        result=result,
        command_records=(command,),
        tool_requests=(tool,),
    )
