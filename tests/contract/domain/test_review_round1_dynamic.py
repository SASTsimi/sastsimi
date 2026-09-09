from typing import Any

import pytest

from sastsimi.contracts.dynamic import AgentLog, DynamicReproductionResult, PoCBundle

from .canonical_fixtures import make
from .fixtures import ref, wire
from .success_fixture import bound, dynamic_success
from .test_success_closure import check_dynamic


def rebind_log(chain: dict[str, Any], events: list[dict[str, Any]]) -> None:
    chain["log"] = wire(
        AgentLog, chain["log"].model_dump(mode="json") | dict(events=events)
    )
    chain["poc"] = wire(
        PoCBundle,
        chain["poc"].model_dump(mode="json") | dict(agent_log_ref=bound(chain["log"])),
    )
    chain["result"] = wire(
        DynamicReproductionResult,
        chain["result"].model_dump(mode="json")
        | dict(agent_log_ref=bound(chain["log"]), poc_ref=bound(chain["poc"])),
    )


@pytest.mark.parametrize(
    "field", ["environment_ref", "environment_recipe_ref", "output_refs"]
)
def test_r5_poc_execution_requires_bound_environment_and_supporting_output(
    field: str,
) -> None:
    chain = dynamic_success()
    check_dynamic(chain)
    events = chain["log"].model_dump(mode="json")["events"]
    for event in events:
        if event["event_type"].startswith("POC_EXECUTION_"):
            event[field] = (
                []
                if field == "output_refs"
                else event[field] | {"record_id": "unrelated"}
            )
    rebind_log(chain, events)
    with pytest.raises(
        ValueError, match="POC_EXECUTION_(ENVIRONMENT|EVIDENCE)_MISMATCH"
    ):
        check_dynamic(chain)


@pytest.mark.parametrize(
    "field,kind",
    [
        ("command_ref", "sandbox_command_record"),
        ("tool_request_ref", "dynamic_reproduction_tool_request"),
    ],
)
def test_r6_command_events_require_stored_typed_refs(field: str, kind: str) -> None:
    from sastsimi.contracts.dynamic import AgentLogEvent

    value = make("AgentLogEvent") | dict(
        event_type="COMMAND_STARTED",
        tool_request_ref=ref("dynamic_reproduction_tool_request"),
        command_ref=ref("sandbox_command_record"),
        command_digest="a" * 64,
        redaction_status="NOT_REQUIRED",
        environment_ref=ref("sandbox_environment"),
        environment_recipe_ref=ref("environment_recipe"),
    )
    value[field] = ref(kind, record=False)
    with pytest.raises(ValueError, match="record_id"):
        wire(AgentLogEvent, value)


def test_r6_resolved_command_pair_matches_tool_request_content() -> None:
    from sastsimi.contracts.canonical_json import content_hash
    from sastsimi.contracts.dynamic import (
        AgentLogEvent,
        DynamicReproductionToolRequest,
        SandboxCommandRecord,
        validate_command_closure,
    )

    chain = dynamic_success()
    command = make("SandboxCommandInput") | dict(
        executable="python", arguments=["check.py"], working_directory="/workspace"
    )
    tool = wire(
        DynamicReproductionToolRequest,
        make("DynamicReproductionToolRequest")
        | dict(
            request_ref=bound(chain["request"]),
            reproduction_plan_ref=bound(chain["plan"]),
            environment_ref=bound(chain["environment"]),
            action="RUN_COMMAND",
            command=command,
        ),
    )
    record = wire(
        SandboxCommandRecord,
        make("SandboxCommandRecord")
        | command
        | dict(
            request_ref=bound(chain["request"]),
            reproduction_plan_ref=bound(chain["plan"]),
            environment_ref=bound(chain["environment"]),
            environment_recipe_ref=bound(chain["recipe"]),
            tool_request_ref=bound(tool),
            command_digest=content_hash(command),
            action_id="cmd1",
        ),
    )
    event_data = make("AgentLogEvent") | dict(
        action_id="cmd1",
        event_type="COMMAND_STARTED",
        tool_request_ref=bound(tool),
        command_ref=bound(record),
        command_digest=record.command_digest,
        redaction_status=record.redaction_status,
        environment_ref=bound(chain["environment"]),
        environment_recipe_ref=bound(chain["recipe"]),
    )
    start = wire(AgentLogEvent, event_data)
    finish = wire(
        AgentLogEvent, event_data | dict(event_type="COMMAND_FINISHED", sequence=2)
    )
    validate_command_closure(
        start,
        finish,
        tool,
        record,
        chain["request"],
        chain["plan"],
        chain["environment"],
        chain["recipe"],
    )
    events = chain["log"].model_dump(mode="json")["events"]
    events[2:2] = [
        start.model_dump(mode="json") | dict(event_id="command-start"),
        finish.model_dump(mode="json")
        | dict(
            event_id="command-finish", output_refs=[ref("observation", record=False)]
        ),
    ]
    for sequence, event in enumerate(events, 1):
        event["sequence"] = sequence
    rebind_log(chain, events)
    chain["command_records"] = (record,)
    chain["tool_requests"] = (tool,)
    check_dynamic(chain)
    chain["command_records"] = ()
    with pytest.raises(ValueError, match="COMMAND_CLOSURE_MISSING"):
        check_dynamic(chain)
    chain["command_records"] = (record,)
    changed = wire(
        SandboxCommandRecord,
        record.model_dump(mode="json")
        | dict(
            arguments=["other.py"],
            command_digest=content_hash(command | dict(arguments=["other.py"])),
        ),
    )
    start = wire(
        AgentLogEvent,
        event_data
        | dict(command_ref=bound(changed), command_digest=changed.command_digest),
    )
    finish = wire(
        AgentLogEvent,
        start.model_dump(mode="json") | dict(event_type="COMMAND_FINISHED", sequence=2),
    )
    with pytest.raises(ValueError, match="COMMAND_CONTENT_MISMATCH"):
        validate_command_closure(
            start,
            finish,
            tool,
            changed,
            chain["request"],
            chain["plan"],
            chain["environment"],
            chain["recipe"],
        )


@pytest.mark.parametrize(
    "name,patch",
    [
        ("EnvironmentRequirement", {"expected": "password=plaintext"}),
        ("EnvironmentRequirement", {"alternatives": ["token=plaintext"]}),
        ("EnvironmentCheck", {"actual": "Bearer plaintext"}),
        ("SandboxCommandInput", {"executable": "C:\\Users\\user\\run.exe"}),
        ("SandboxCommandInput", {"arguments": ["--password", "plaintext"]}),
        ("SandboxCommandInput", {"working_directory": "C:\\Users\\user"}),
        (
            "SandboxCommandInput",
            {
                "stdin_ref": ref("stdin", record=False)
                | {"stored_data_id": "password=plaintext"}
            },
        ),
    ],
)
def test_r7_persisted_environment_and_command_strings_are_safe(
    name: str, patch: dict[str, Any]
) -> None:
    import sastsimi.contracts.dynamic as dynamic

    value = make(name)
    if name == "EnvironmentCheck":
        value.update(actual="public", evidence_refs=[ref("check", record=False)])
    with pytest.raises(ValueError, match="UNSAFE_DIAGNOSTIC"):
        wire(getattr(dynamic, name), value | patch)


def test_r8_mandatory_needs_survive_requirements_expansion() -> None:
    from sastsimi.contracts.dynamic import (
        DynamicReproductionRequest,
        EnvironmentRequirements,
        validate_environment_requirements,
    )

    chain = dynamic_success()
    request = wire(
        DynamicReproductionRequest,
        chain["request"].model_dump(mode="json")
        | dict(
            environment_needs=[
                dict(
                    need_id="auth",
                    kind="AUTH",
                    description="test user",
                    required=True,
                    source_refs=[ref("auth_source", record=False)],
                )
            ]
        ),
    )
    item = make("EnvironmentRequirement") | dict(
        requirement_id="auth",
        kind="AUTH",
        name="test user",
        required=True,
        source_refs=[ref("auth_source", record=False)],
    )
    requirements = wire(
        EnvironmentRequirements,
        chain["requirements"].model_dump(mode="json")
        | dict(request_ref=bound(request), items=[item]),
    )
    validate_environment_requirements(request, requirements)
    for items in ([], [item | dict(required=False)], [item | dict(kind="DATA")]):
        changed = wire(
            EnvironmentRequirements,
            requirements.model_dump(mode="json") | dict(items=items),
        )
        with pytest.raises(ValueError, match="ENVIRONMENT_NEED_COVERAGE"):
            validate_environment_requirements(request, changed)


@pytest.mark.parametrize("field", ["action_decision_ref", "sandbox_profile_ref"])
def test_r9_boundary_decision_binds_action_and_request_profile(field: str) -> None:
    from sastsimi.contracts.dynamic import SandboxPolicyDecision

    chain = dynamic_success()
    changed = chain["policy"].model_dump(mode="json")
    changed[field]["record_id"] = "unrelated"
    chain["policy"] = wire(SandboxPolicyDecision, changed)
    result_data = chain["result"].model_dump(mode="json")
    old_ref = result_data["policy_decision_ref"]
    chain["result"] = wire(
        DynamicReproductionResult,
        result_data | dict(policy_decision_ref=bound(chain["policy"])),
    )
    events = chain["log"].model_dump(mode="json")["events"]
    for event in events:
        event["input_refs"] = [
            bound(chain["policy"]) if item == old_ref else item
            for item in event["input_refs"]
        ]
    rebind_log(chain, events)
    with pytest.raises(ValueError, match="SANDBOX_POLICY_BINDING_MISMATCH"):
        check_dynamic(chain)


@pytest.mark.parametrize(
    "field", ["reproduction_plan_ref", "environment_ref", "poc_candidate_ref"]
)
def test_r10_conclusion_interprets_the_final_attempt_artifacts(field: str) -> None:
    from sastsimi.contracts.dynamic import DynamicReproductionConclusion

    chain = dynamic_success()
    changed = chain["conclusion"].model_dump(mode="json")
    changed[field]["record_id"] = "unrelated"
    chain["conclusion"] = wire(DynamicReproductionConclusion, changed)
    chain["result"] = wire(
        DynamicReproductionResult,
        chain["result"].model_dump(mode="json")
        | dict(agent_conclusion_ref=bound(chain["conclusion"])),
    )
    with pytest.raises(ValueError, match="DYNAMIC_CONCLUSION_ARTIFACT_MISMATCH"):
        check_dynamic(chain)


def test_r11_successful_cleanup_cannot_omit_created_environment() -> None:
    from sastsimi.contracts.dynamic import CleanupResult

    chain = dynamic_success()
    chain["cleanup"] = wire(
        CleanupResult,
        chain["cleanup"].model_dump(mode="json") | dict(environment_refs=[]),
    )
    chain["result"] = wire(
        DynamicReproductionResult,
        chain["result"].model_dump(mode="json")
        | dict(cleanup_ref=bound(chain["cleanup"])),
    )
    with pytest.raises(ValueError, match="CLEANUP_COVERAGE_MISMATCH"):
        check_dynamic(chain)


@pytest.mark.parametrize("logged", [True, False])
def test_r11_cleanup_covers_earlier_session_environment_and_resources(
    logged: bool,
) -> None:
    from sastsimi.contracts.dynamic import CleanupResult, SandboxEnvironment
    from sastsimi.contracts.refs import StoredDataRef

    chain = dynamic_success()
    old_data = chain["environment"].model_dump(mode="json")
    old_data["meta"]["record_id"] = "earlier-env"
    old = wire(
        SandboxEnvironment, old_data | dict(container_instance_id="earlier-container")
    )
    chain["attempt_environments"] = (old,)
    resource = wire(StoredDataRef, ref("temporary_resource", record=False))
    chain["attempt_resource_refs"] = (resource,)
    events = chain["log"].model_dump(mode="json")["events"]
    if logged:
        events[0]["environment_ref"] = bound(old)
    rebind_log(chain, events)
    cleanup_data = chain["cleanup"].model_dump(mode="json") | dict(
        environment_refs=[bound(old), bound(chain["environment"])],
        resource_refs=[resource.model_dump(mode="json")],
    )
    chain["cleanup"] = wire(CleanupResult, cleanup_data)
    chain["result"] = wire(
        DynamicReproductionResult,
        chain["result"].model_dump(mode="json")
        | dict(cleanup_ref=bound(chain["cleanup"])),
    )
    check_dynamic(chain)
    patch: dict[str, Any]
    for patch in (
        dict(environment_refs=[bound(chain["environment"])]),
        dict(resource_refs=[]),
    ):
        chain["cleanup"] = wire(CleanupResult, cleanup_data | patch)
        chain["result"] = wire(
            DynamicReproductionResult,
            chain["result"].model_dump(mode="json")
            | dict(cleanup_ref=bound(chain["cleanup"])),
        )
        with pytest.raises(ValueError, match="CLEANUP_COVERAGE_MISMATCH"):
            check_dynamic(chain)


def test_r12_partial_requires_hypothesis_evidence_not_just_observations() -> None:
    chain = dynamic_success()
    value = chain["result"].model_dump(mode="json") | dict(
        status="PARTIAL",
        hypothesis_outcome="INCONCLUSIVE",
        poc_ref=None,
        limitations=["optional service unavailable"],
        hypothesis_evidence_refs=[],
    )
    with pytest.raises(ValueError, match="PARTIAL_EVIDENCE_REQUIRED"):
        wire(DynamicReproductionResult, value)
