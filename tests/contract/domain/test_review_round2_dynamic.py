from typing import Any

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import (
    AgentLog,
    DynamicReproductionConclusion,
    DynamicReproductionResult,
    DynamicReproductionToolRequest,
    PoCBundle,
    SandboxCommandInput,
    SandboxCommandRecord,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import ToolRunResult
from sastsimi.contracts.verification import EvidenceAgentResult

from .canonical_fixtures import make
from .fixtures import event, ref, wire
from .success_fixture import bound, dynamic_success
from .test_review_round1_dynamic import rebind_log
from .test_success_closure import check_dynamic


@pytest.mark.parametrize(
    "scope", ["current", "other-hypothesis", "other-pro-hypothesis", "old-attempt"]
)
def test_round2_transitive_dynamic_evidence_cannot_cross_scope(scope: str) -> None:
    chain = dynamic_success()
    nested_data = chain["poc"].model_dump(mode="json")
    nested_data["meta"]["record_id"] = "supporting-execution"
    if scope == "other-hypothesis":
        nested_data["meta"]["hypothesis_id"] = "h2"
    elif scope == "old-attempt":
        nested_data["meta"]["attempt_id"] = "old-attempt"
    nested = wire(PoCBundle, nested_data)
    static_data = make("ToolRunResult")
    static_data["meta"]["attempt_id"] = "static-attempt"
    static = wire(ToolRunResult, static_data)
    supporting_data = make("EvidenceAgentResult")
    supporting_data["meta"]["attempt_id"] = "pro-attempt"
    if scope == "other-pro-hypothesis":
        supporting_data["meta"]["hypothesis_id"] = "h2"
    supporting_data["evidence"][0]["evidence_refs"] = [bound(nested), bound(static)]
    supporting = wire(EvidenceAgentResult, supporting_data)
    roots = [bound(supporting)]
    chain["poc"] = wire(
        PoCBundle, chain["poc"].model_dump(mode="json") | dict(evidence_refs=roots)
    )
    chain["conclusion"] = wire(
        DynamicReproductionConclusion,
        chain["conclusion"].model_dump(mode="json")
        | dict(hypothesis_evidence_refs=roots),
    )
    chain["result"] = wire(
        DynamicReproductionResult,
        chain["result"].model_dump(mode="json")
        | dict(
            poc_ref=bound(chain["poc"]),
            agent_conclusion_ref=bound(chain["conclusion"]),
            hypothesis_evidence_refs=roots,
        ),
    )
    chain["resolved_evidence"] = {
        wire(StoredDataRef, bound(record)): record
        for record in (supporting, nested, static)
    }
    if scope == "current":
        check_dynamic(chain)
    else:
        with pytest.raises(ValueError, match="RECORD_SCOPE_MISMATCH"):
            check_dynamic(chain)


def add_started_command(chain: dict[str, Any]) -> dict[str, Any]:
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
            action_id="interrupted-command",
        ),
    )
    chain["command_records"] = (record,)
    chain["tool_requests"] = (tool,)
    return event() | dict(
        event_id="command-start",
        action_id=record.action_id.root,
        event_type="COMMAND_STARTED",
        tool_request_ref=bound(tool),
        command_ref=bound(record),
        command_digest=record.command_digest,
        redaction_status=record.redaction_status,
        environment_ref=bound(chain["environment"]),
        environment_recipe_ref=bound(chain["recipe"]),
    )


@pytest.mark.parametrize("failure", ["TIMEOUT", "INTERNAL", "EXECUTION"])
def test_round2_interrupted_command_preserves_failed_audit_history(
    failure: str,
) -> None:
    chain = dynamic_success()
    start = add_started_command(chain)
    events = chain["log"].model_dump(mode="json")["events"][:2]
    events.extend(
        [
            start,
            event()
            | dict(event_id="interrupted", safe_message="Execution interrupted"),
        ]
    )
    for sequence, item in enumerate(events, 1):
        item["sequence"] = sequence
    chain["log"] = wire(
        AgentLog, chain["log"].model_dump(mode="json") | dict(events=events)
    )
    chain["poc"] = chain["candidate"] = chain["conclusion"] = None
    chain["result"] = wire(
        DynamicReproductionResult,
        chain["result"].model_dump(mode="json")
        | dict(
            agent_log_ref=bound(chain["log"]),
            agent_conclusion_ref=None,
            poc_ref=None,
            poc_candidate_ref=None,
            status="FAILED",
            failure_category=failure,
            failure_reason="Execution interrupted",
            hypothesis_outcome="INCONCLUSIVE",
            observation_refs=[],
            hypothesis_evidence_refs=[],
        ),
    )
    check_dynamic(chain)
    chain["command_records"] = ()
    with pytest.raises(ValueError, match="COMMAND_CLOSURE_MISSING"):
        check_dynamic(chain)
    with pytest.raises(ValueError, match="VALIDATED_POC_STATUS_MISMATCH"):
        wire(
            DynamicReproductionResult,
            chain["result"].model_dump(mode="json") | dict(poc_ref=ref("poc_bundle")),
        )


@pytest.mark.parametrize("status", ["SUCCEEDED", "PARTIAL"])
def test_round2_success_cannot_hide_an_unfinished_command(status: str) -> None:
    chain = dynamic_success()
    start = add_started_command(chain)
    events = chain["log"].model_dump(mode="json")["events"]
    events.insert(2, start)
    for sequence, item in enumerate(events, 1):
        item["sequence"] = sequence
    rebind_log(chain, events)
    if status == "PARTIAL":
        chain["poc"] = None
        chain["conclusion"] = wire(
            DynamicReproductionConclusion,
            chain["conclusion"].model_dump(mode="json")
            | dict(
                proposed_outcome="INCONCLUSIVE", limitations=["Execution incomplete"]
            ),
        )
        chain["result"] = wire(
            DynamicReproductionResult,
            chain["result"].model_dump(mode="json")
            | dict(
                status="PARTIAL",
                hypothesis_outcome="INCONCLUSIVE",
                poc_ref=None,
                agent_conclusion_ref=bound(chain["conclusion"]),
                limitations=["Execution incomplete"],
            ),
        )
    with pytest.raises(ValueError, match="COMMAND_CLOSURE_MISSING"):
        check_dynamic(chain)


@pytest.mark.parametrize(
    "patch",
    [
        {"working_directory": "/tmp/reproduction"},
        {"working_directory": "/home/app/reproduction"},
        {"working_directory": "../fixtures"},
        {"executable": "/home/app/.venv/bin/python"},
        {
            "arguments": [
                "/tmp/reproduction/check.py",
                "--config",
                "/etc/app/config.json",
            ]
        },
        {"arguments": ["/home/app/fixture", "/var/tmp/output", "relative.txt", ""]},
    ],
)
def test_round2_container_command_paths_are_not_host_paths(
    patch: dict[str, Any],
) -> None:
    command = wire(SandboxCommandInput, make("SandboxCommandInput") | patch)
    for field, expected in patch.items():
        assert command.model_dump(mode="json")[field] == expected


@pytest.mark.parametrize(
    "patch",
    [
        {"working_directory": "C:\\Users\\operator"},
        {"executable": "\\\\host\\share\\run.exe"},
        {"arguments": ["--password", "plaintext"]},
        {"arguments": ["token=plaintext"]},
        {"arguments": ["--unix-socket", "/run/docker.sock"]},
        {"arguments": ["unix:///var/run/docker.sock"]},
        {"arguments": ["--volume", "/:/host"]},
        {"working_directory": "/proc/1/root"},
        {"arguments": ["--pid=host"]},
        {"arguments": ["--pid", "host"]},
        {"arguments": ["--mount", "type=bind,source=/,target=/mnt"]},
    ],
)
def test_round2_command_context_retains_secret_and_escape_rejection(
    patch: dict[str, Any],
) -> None:
    with pytest.raises(ValueError, match="UNSAFE_DIAGNOSTIC"):
        wire(SandboxCommandInput, make("SandboxCommandInput") | patch)
