from __future__ import annotations

from typing import Any

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import (
    AgentLog,
    DynamicReproductionConclusion,
    DynamicReproductionResult,
    DynamicReproductionToolRequest,
    PoCCandidate,
    SandboxCommandRecord,
    SandboxPolicyDecision,
)
from sastsimi.contracts.refs import reference
from sastsimi.sandbox.session_manager import (
    DynamicFinalizationInput,
    ReproductionSessionManager,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import event, ref, wire
from tests.contract.domain.success_fixture import bound, dynamic_success
from tests.integration.runtime_support import TestClock, TestIds


def _manager() -> ReproductionSessionManager:
    return ReproductionSessionManager(clock=TestClock(), ids=TestIds())


def _add_command_pair(
    chain: dict[str, Any],
    *,
    executable: str = "/bin/sh",
    arguments: tuple[str, ...] = ("/tmp/sastsimi-poc-candidate",),
) -> None:
    command_input = make("SandboxCommandInput") | {
        "executable": executable,
        "arguments": list(arguments),
        "working_directory": "/workspace",
    }
    tool = wire(
        DynamicReproductionToolRequest,
        make("DynamicReproductionToolRequest")
        | {
            "request_ref": bound(chain["request"]),
            "reproduction_plan_ref": bound(chain["plan"]),
            "environment_ref": bound(chain["environment"]),
            "action": "RUN_COMMAND",
            "command": command_input,
        },
    )
    command = wire(
        SandboxCommandRecord,
        make("SandboxCommandRecord")
        | command_input
        | {
            "request_ref": bound(chain["request"]),
            "reproduction_plan_ref": bound(chain["plan"]),
            "environment_recipe_ref": bound(chain["recipe"]),
            "environment_ref": bound(chain["environment"]),
            "tool_request_ref": bound(tool),
            "command_digest": content_hash(command_input),
            "action_id": "execute",
        },
    )
    raw_events = chain["log"].model_dump(mode="json")["events"]
    for item in raw_events:
        if item["event_type"] == "POC_CANDIDATE_CREATED":
            item["actor"] = "DYNAMIC_REPRODUCTION"
        elif item["event_type"].startswith(("POC_EXECUTION_", "COMMAND_")):
            item["actor"] = "TOOL_RUNTIME"
            item["tool_request_ref"] = bound(tool)
            item["command_ref"] = bound(command)
            item["command_digest"] = command.command_digest
            item["redaction_status"] = command.redaction_status
            if item["event_type"].startswith("POC_EXECUTION_"):
                item["input_refs"] = [
                    chain["candidate"].content_ref.model_dump(mode="json")
                ]
    for sequence, item in enumerate(raw_events, 1):
        item["sequence"] = sequence
    chain["log"] = wire(
        AgentLog,
        chain["log"].model_dump(mode="json") | {"events": raw_events},
    )
    chain["command_records"] = (command,)
    chain["tool_requests"] = (tool,)


def _input(chain: dict[str, Any]) -> DynamicFinalizationInput:
    return DynamicFinalizationInput(
        request=chain["request"],
        requirements=chain["requirements"],
        plan=chain["plan"],
        policy=chain["policy"],
        recipe=chain["recipe"],
        environment=chain["environment"],
        candidate=chain["candidate"],
        conclusion=chain["conclusion"],
        cleanup=chain["cleanup"],
        observation_refs=chain["result"].observation_refs,
        status="SUCCEEDED",
        failure_category="NONE",
        failure_reason=None,
        plan_issues=(),
        started_at=chain["result"].started_at,
        finished_at=chain["result"].finished_at,
        command_records=chain["command_records"],
        tool_requests=chain["tool_requests"],
    )


def _complete_supported_attempt() -> dict[str, Any]:
    chain = dynamic_success()
    _add_command_pair(chain)
    return chain


def test_supported_execution_promotes_exact_candidate_once() -> None:
    chain = _complete_supported_attempt()
    finalized = _manager().finalize(
        data=_input(chain), log=chain["log"], meta=chain["result"].meta
    )

    assert finalized.result.status == "SUCCEEDED"
    assert finalized.result.hypothesis_outcome == "SUPPORTED"
    assert finalized.poc is not None
    assert finalized.result.poc_ref == reference(finalized.poc)
    assert finalized.poc.candidate_digest == chain["candidate"].content_digest
    assert finalized.poc.execution_action_id.root == "execute"


def test_unrelated_successful_command_cannot_promote_candidate() -> None:
    chain = dynamic_success()
    _add_command_pair(chain, arguments=("unrelated.py",))

    finalized = _manager().finalize(
        data=_input(chain), log=chain["log"], meta=chain["result"].meta
    )

    assert finalized.poc is None
    assert finalized.result.poc_ref is None
    assert finalized.result.hypothesis_outcome == "INCONCLUSIVE"


def test_path_as_unused_argument_cannot_promote_candidate() -> None:
    chain = dynamic_success()
    _add_command_pair(
        chain,
        executable="/bin/sh",
        arguments=("-c", "true", "/tmp/sastsimi-poc-candidate"),
    )

    finalized = _manager().finalize(
        data=_input(chain), log=chain["log"], meta=chain["result"].meta
    )

    assert finalized.poc is None
    assert finalized.result.poc_ref is None


def test_changed_materialized_candidate_digest_cannot_promote() -> None:
    chain = _complete_supported_attempt()
    command = chain["command_records"][0]
    tool = chain["tool_requests"][0]
    wrong_content_ref = chain["candidate"].content_ref.model_copy(
        update={"content_hash": "f" * 64}
    )
    events = tuple(
        item.model_copy(
            update={
                "command_ref": bound(command),
                "tool_request_ref": bound(tool),
                "command_digest": command.command_digest,
                "redaction_status": command.redaction_status,
                "input_refs": (wrong_content_ref,),
            }
        )
        if item.event_type.startswith("POC_EXECUTION_")
        else item
        for item in chain["log"].events
    )
    chain["log"] = chain["log"].model_copy(update={"events": events})

    finalized = _manager().finalize(
        data=_input(chain), log=chain["log"], meta=chain["result"].meta
    )

    assert finalized.poc is None
    assert finalized.result.poc_ref is None


@pytest.mark.parametrize(
    "mutation",
    [
        "NOT_EXECUTED",
        "EXIT_NONZERO",
        "INCONCLUSIVE",
        "OLD_ATTEMPT",
        "WRONG_DIGEST",
        "UNFINISHED_SESSION",
        "FORGED_ACTOR",
    ],
)
def test_candidate_is_not_promoted_without_same_attempt_support(mutation: str) -> None:
    chain = _complete_supported_attempt()
    if mutation in {
        "NOT_EXECUTED",
        "EXIT_NONZERO",
        "WRONG_DIGEST",
        "UNFINISHED_SESSION",
        "FORGED_ACTOR",
    }:
        raw_events = chain["log"].model_dump(mode="json")["events"]
        if mutation == "NOT_EXECUTED":
            raw_events = [
                item
                for item in raw_events
                if item["event_type"]
                not in {
                    "POC_EXECUTION_STARTED",
                    "POC_EXECUTION_FINISHED",
                    "COMMAND_STARTED",
                    "COMMAND_FINISHED",
                }
            ]
        elif mutation == "EXIT_NONZERO":
            for item in raw_events:
                if item["event_type"] in {
                    "POC_EXECUTION_FINISHED",
                    "COMMAND_FINISHED",
                }:
                    item["exit_code"] = 1
        elif mutation == "UNFINISHED_SESSION":
            raw_events = [
                item for item in raw_events if item["event_type"] != "SESSION_FINISHED"
            ]
        elif mutation == "FORGED_ACTOR":
            for item in raw_events:
                if item["event_type"] == "POC_EXECUTION_FINISHED":
                    item["actor"] = "DYNAMIC_REPRODUCTION"
        else:
            for item in raw_events:
                if item["event_type"].startswith("POC_") or item[
                    "event_type"
                ].startswith("COMMAND_"):
                    if item["poc_candidate_ref"] is not None:
                        item["poc_candidate_ref"]["content_hash"] = "f" * 64
        for sequence, item in enumerate(raw_events, 1):
            item["sequence"] = sequence
        chain["log"] = wire(
            AgentLog,
            chain["log"].model_dump(mode="json") | {"events": raw_events},
        )
    elif mutation == "INCONCLUSIVE":
        chain["conclusion"] = wire(
            DynamicReproductionConclusion,
            chain["conclusion"].model_dump(mode="json")
            | {
                "proposed_outcome": "INCONCLUSIVE",
                "limitations": ["Observed behavior is inconclusive"],
            },
        )
    else:
        candidate_data = chain["candidate"].model_dump(mode="json")
        candidate_data["meta"]["attempt_id"] = "old-attempt"
        chain["candidate"] = wire(PoCCandidate, candidate_data)

    finalized = _manager().finalize(
        data=_input(chain), log=chain["log"], meta=chain["result"].meta
    )

    assert finalized.poc is None
    assert finalized.result.poc_ref is None
    assert finalized.result.hypothesis_outcome == "INCONCLUSIVE"


def test_disproved_requires_actual_successful_observation() -> None:
    chain = _complete_supported_attempt()
    raw_events = [
        item
        for item in chain["log"].model_dump(mode="json")["events"]
        if item["event_type"]
        not in {
            "POC_EXECUTION_STARTED",
            "POC_EXECUTION_FINISHED",
            "COMMAND_STARTED",
            "COMMAND_FINISHED",
        }
    ]
    for sequence, item in enumerate(raw_events, 1):
        item["sequence"] = sequence
    chain["log"] = wire(
        AgentLog,
        chain["log"].model_dump(mode="json") | {"events": raw_events},
    )
    chain["conclusion"] = wire(
        DynamicReproductionConclusion,
        chain["conclusion"].model_dump(mode="json") | {"proposed_outcome": "DISPROVED"},
    )

    finalized = _manager().finalize(
        data=_input(chain), log=chain["log"], meta=chain["result"].meta
    )

    assert finalized.result.status == "FAILED"
    assert finalized.result.hypothesis_outcome == "INCONCLUSIVE"
    assert finalized.result.hypothesis_disproved is False


def test_conclusion_cannot_replace_the_runtime_observation_set() -> None:
    chain = _complete_supported_attempt()
    data = _input(chain)
    changed = DynamicFinalizationInput(
        **{
            **data.__dict__,
            "observation_refs": (
                wire(type(data.observation_refs[0]), ref("other", record=False)),
            ),
        }
    )

    with pytest.raises(ValueError, match="RECORD_REVISION_MISMATCH"):
        _manager().finalize(data=changed, log=chain["log"], meta=chain["result"].meta)


@pytest.mark.parametrize(
    "status,failure_category",
    [("FAILED", "TIMEOUT"), ("FAILED", "EXECUTION")],
)
def test_operational_failure_never_creates_poc_or_r6_verdict(
    status: str, failure_category: str
) -> None:
    chain = _complete_supported_attempt()
    data = _input(chain)
    failed = DynamicFinalizationInput(
        **{
            **data.__dict__,
            "status": status,
            "failure_category": failure_category,
            "failure_reason": "Dynamic reproduction did not complete",
        }
    )

    finalized = _manager().finalize(
        data=failed, log=chain["log"], meta=chain["result"].meta
    )

    assert finalized.poc is None
    assert finalized.result.poc_ref is None
    assert finalized.result.hypothesis_outcome == "INCONCLUSIVE"
    assert isinstance(finalized.result, DynamicReproductionResult)
    assert not hasattr(finalized.result, "verdict")


def test_policy_block_before_agent_has_no_poc_or_r6_verdict() -> None:
    chain = _complete_supported_attempt()
    policy = wire(
        SandboxPolicyDecision,
        chain["policy"].model_dump(mode="json")
        | {
            "decision": "DENY",
            "reason_codes": ["HOST_BOUNDARY_DENIED"],
        },
    )
    raw_events = chain["log"].model_dump(mode="json")["events"]
    session_started = raw_events[0]
    session_started.update(
        input_refs=[bound(policy)],
        environment_ref=None,
        environment_recipe_ref=None,
    )
    policy_blocked = event() | {
        "event_id": "policy-blocked",
        "sequence": 2,
        "action_id": "boundary",
        "event_type": "POLICY_BLOCKED",
        "actor": "SANDBOX_CONTROLLER",
        "input_refs": [bound(policy)],
        "safe_message": "Sandbox boundary denied",
    }
    session_finished = raw_events[-1]
    session_finished.update(
        sequence=3,
        input_refs=[bound(policy)],
        environment_ref=None,
        environment_recipe_ref=None,
    )
    log = wire(
        AgentLog,
        chain["log"].model_dump(mode="json")
        | {"events": [session_started, policy_blocked, session_finished]},
    )
    data = _input(chain)
    blocked = DynamicFinalizationInput(
        **{
            **data.__dict__,
            "policy": policy,
            "recipe": None,
            "environment": None,
            "candidate": None,
            "conclusion": None,
            "cleanup": None,
            "observation_refs": (),
            "status": "BLOCKED",
            "failure_category": "POLICY_BLOCKED",
            "failure_reason": "Sandbox boundary denied",
            "command_records": (),
            "tool_requests": (),
        }
    )

    finalized = _manager().finalize(data=blocked, log=log, meta=chain["result"].meta)

    assert finalized.result.status == "BLOCKED"
    assert finalized.result.agent_invoked is False
    assert finalized.result.hypothesis_outcome == "INCONCLUSIVE"
    assert finalized.result.poc_ref is None
    assert not hasattr(finalized.result, "verdict")
