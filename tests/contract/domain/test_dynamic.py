from typing import Any

import pytest
from pydantic import ValidationError

from .fixtures import (
    dynamic_failure,
    dynamic_request,
    event,
    meta,
    mutations,
    ref,
    wire,
)


def test_dynamic_failure_never_promotes_candidate_or_verdict() -> None:
    from sastsimi.contracts.dynamic import (
        DynamicReproductionRequest,
        DynamicReproductionResult,
    )

    wire(DynamicReproductionRequest, dynamic_request())
    value = dynamic_failure()
    wire(DynamicReproductionResult, value)
    for field in value:
        with pytest.raises(ValidationError):
            wire(
                DynamicReproductionResult,
                {k: v for k, v in value.items() if k != field},
            )
    for patch in mutations(
        dict(poc_ref=ref("poc_bundle")),
        dict(hypothesis_outcome="SUPPORTED"),
        dict(hypothesis_outcome="FALSE"),
        dict(status="SUCCEEDED"),
        dict(cleanup_status="SUCCEEDED"),
        dict(environment_ref=ref("sandbox_environment")),
        dict(agent_conclusion_ref=ref("dynamic_reproduction_conclusion")),
    ):
        with pytest.raises(ValidationError):
            wire(DynamicReproductionResult, value | patch)


def test_agent_log_append_only_sequences_and_command_pairs() -> None:
    from sastsimi.contracts.dynamic import AgentLog, validate_log_revision

    value: dict[str, Any] = dict(
        meta=meta("agent_log", hypothesis="h1"),
        request_ref=ref("dynamic_reproduction_request"),
        events=[event()],
    )
    first = wire(AgentLog, value)
    second_data = value | dict(
        meta=value["meta"]
        | dict(record_id="r2", revision_number=2, previous_record_id="agent_log-r1"),
        events=[event(), event() | dict(event_id="event2", sequence=2)],
    )
    second = wire(AgentLog, second_data)
    validate_log_revision(first, second)
    with pytest.raises(ValueError, match="APPEND_ONLY"):
        validate_log_revision(
            first,
            wire(
                AgentLog,
                second_data
                | {
                    "events": [
                        event() | {"safe_message": "Changed"},
                        second_data["events"][1],
                    ]
                },
            ),
        )
    with pytest.raises(ValidationError, match="SEQUENCE"):
        wire(AgentLog, value | {"events": [event() | {"sequence": 2}]})
    with pytest.raises(ValidationError, match="COMMAND"):
        wire(
            AgentLog, value | {"events": [event() | {"event_type": "COMMAND_FINISHED"}]}
        )


def test_r6_request_attempt_is_not_r7_attempt() -> None:
    from sastsimi.contracts.canonical_json import content_hash
    from sastsimi.contracts.dynamic import (
        AgentLog,
        DynamicReproductionRequest,
        DynamicReproductionResult,
        validate_dynamic_closure,
    )

    request = wire(DynamicReproductionRequest, dynamic_request())
    request_ref = ref("dynamic_reproduction_request") | {
        "content_hash": content_hash(request)
    }
    log = wire(
        AgentLog,
        dict(
            meta=meta("agent_log", hypothesis="h1"),
            request_ref=request_ref,
            events=[event()],
        ),
    )
    result = wire(
        DynamicReproductionResult,
        dynamic_failure()
        | dict(
            request_ref=request_ref,
            agent_log_ref=ref("agent_log") | {"content_hash": content_hash(log)},
        ),
    )
    validate_dynamic_closure(result, request, log, generation=1)
    with pytest.raises(ValueError, match="STALE_RESULT"):
        validate_dynamic_closure(result, request, log, generation=2)
    with pytest.raises(ValueError):
        validate_dynamic_closure(
            result,
            request,
            wire(
                AgentLog,
                log.model_dump(mode="json")
                | {"meta": meta("agent_log", hypothesis="h1", attempt="old")},
            ),
            generation=1,
        )
