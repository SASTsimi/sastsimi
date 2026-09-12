"""Exact PoC execution provenance at the deterministic fake seam."""

from typing import cast

import pytest

from sastsimi.contracts.dynamic import (
    AgentLog,
    AgentLogEvent,
    PoCCandidate,
    SandboxCommandRecord,
)
from sastsimi.reproduction.fake_closure import require_poc_execution_events
from tests.contract.domain.success_fixture import dynamic_success


def _poc_events(chain: dict[str, object]) -> tuple[AgentLogEvent, ...]:
    log = cast(AgentLog, chain["log"])
    return tuple(
        event for event in log.events if event.event_type.startswith("POC_EXECUTION_")
    )


def test_fake_poc_events_accept_exact_candidate_command_provenance() -> None:
    chain = dynamic_success()
    events = _poc_events(chain)
    candidate = cast(PoCCandidate, chain["candidate"])
    command_records = cast(tuple[SandboxCommandRecord, ...], chain["command_records"])

    assert (
        require_poc_execution_events(
            candidate,
            command_records[0],
            events,
        )
        == events
    )


@pytest.mark.parametrize("case", ["candidate_input", "command_provenance"])
def test_fake_poc_events_reject_content_or_command_mismatch(case: str) -> None:
    chain = dynamic_success()
    events = _poc_events(chain)
    candidate = cast(PoCCandidate, chain["candidate"])
    command_records = cast(tuple[SandboxCommandRecord, ...], chain["command_records"])
    if case == "candidate_input":
        invalid_events = tuple(
            event.model_copy(update={"input_refs": ()}) for event in events
        )
    else:
        invalid_events = tuple(
            event.model_copy(update={"command_digest": "f" * 64}) for event in events
        )

    with pytest.raises(ValueError, match="FAKE_POC_EXECUTION_PROVENANCE_MISMATCH"):
        require_poc_execution_events(
            candidate,
            command_records[0],
            invalid_events,
        )


def test_fake_poc_events_reject_non_runtime_path_command() -> None:
    chain = dynamic_success()
    candidate = cast(PoCCandidate, chain["candidate"])
    command_records = cast(tuple[SandboxCommandRecord, ...], chain["command_records"])
    command = command_records[0]
    invalid_command = command.model_copy(
        update={"executable": "python", "arguments": ("poc.py",)}
    )

    with pytest.raises(ValueError, match="FAKE_POC_EXECUTION_PROVENANCE_MISMATCH"):
        require_poc_execution_events(
            candidate,
            invalid_command,
            _poc_events(chain),
        )
