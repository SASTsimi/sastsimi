"""Each proposal is validated, checked for duplicates and registered on its own.

The branches follow ``03-agent-roles-and-orchestration.md`` exactly: an invalid
proposal costs only itself, no candidate means no model call, a DUPLICATE must
name a candidate, and a failed review registers rather than drops.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from sastsimi.simple_runtime.models import StageFailure
from sastsimi.simple_runtime.proposals import Registry, validate_proposal
from sastsimi.simple_runtime.provider import SimpleLLMCallResult

_LINES = {"app/proxy.py": 60, ".github/check.py": 5}


def _raw(line: int = 10, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "statement": "decode cap bypass",
        "vulnerability_type_candidates": ["PATH_TRAVERSAL", "SSRF"],
        "target_locations": [
            {"file_path": "app/proxy.py", "start_line": line, "end_line": line + 2}
        ],
        "suspected_path": [
            {"file_path": "app/proxy.py", "start_line": line, "end_line": line}
        ],
        "observed_facts": ["decodes eight times"],
        "restrictions": ["rejects a leading .."],
        "assumptions": ["upstream decodes again"],
        "falsification_questions": ["Is a nine-times-encoded path rejected?"],
        "validation_checks": ["Send a path encoded nine times."],
    }
    value.update(overrides)
    return value


def _valid(line: int = 10) -> dict[str, Any]:
    proposal, errors = validate_proposal(_raw(line), lines=_LINES)
    assert proposal is not None, errors
    return proposal


def test_a_complete_proposal_gets_runtime_assigned_ids() -> None:
    proposal = _valid()

    assert proposal["proposal_state"] == "HYPOTHESIS_ONLY"
    assert proposal["assertion_mode"] == "NON_FINAL"
    assert proposal["falsification_questions"][0]["question_id"] == "Q1"
    assert proposal["validation_checks"][0]["validation_id"] == "V1"
    # Still readable by the reproduction environment.
    assert proposal["code_locations"] == ["app/proxy.py:10"]


@pytest.mark.parametrize(
    ("override", "error"),
    [
        ({"statement": ""}, "statement is missing"),
        ({"target_locations": []}, "target_locations is missing"),
        ({"suspected_path": []}, "suspected_path is missing"),
        ({"falsification_questions": []}, "falsification_questions needs"),
        ({"validation_checks": []}, "validation_checks needs"),
        ({"assumptions": "none"}, "assumptions is missing"),
        (
            {"vulnerability_type_candidates": ["SSRF", "SSRF"]},
            "repeats a value",
        ),
    ],
)
def test_a_missing_field_rejects_that_proposal(
    override: dict[str, object], error: str
) -> None:
    proposal, errors = validate_proposal(_raw(**override), lines=_LINES)

    assert proposal is None
    assert any(error in item for item in errors), errors


@pytest.mark.parametrize(
    ("location", "error"),
    [
        ({"file_path": "app/nope.py", "start_line": 1}, "not a file in the checkout"),
        ({"file_path": "app/proxy.py", "start_line": 61}, "outside the file"),
        ({"file_path": "app/proxy.py", "start_line": 0}, "outside the file"),
        ({"file_path": "app/proxy.py"}, "has no start_line"),
    ],
)
def test_a_location_that_does_not_exist_is_rejected(
    location: dict[str, object], error: str
) -> None:
    """The design asks for real locations, so each is checked against the file."""

    proposal, errors = validate_proposal(
        _raw(target_locations=[location]), lines=_LINES
    )

    assert proposal is None
    assert any(error in item for item in errors), errors


def test_a_dotted_directory_keeps_its_dot() -> None:
    proposal, errors = validate_proposal(
        _raw(
            target_locations=[{"file_path": ".github/check.py", "start_line": 2}],
            suspected_path=[{"file_path": "./.github/check.py", "start_line": 2}],
        ),
        lines=_LINES,
    )

    assert proposal is not None, errors
    assert proposal["target_locations"][0]["file_path"] == ".github/check.py"


class _Reviewer:
    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.calls = 0

    async def call(self, **kwargs: object) -> object:
        self.calls += 1
        return self.answer


def _answer(**value: object) -> SimpleLLMCallResult:
    return SimpleLLMCallResult(
        value=dict(value), prompt_digest="a" * 64, output_digest="b" * 64
    )


async def _consider(
    registry: Registry, proposal: dict[str, Any], reviewer: object
) -> Any:
    return await registry.consider(
        proposal,
        proposal_id="p",
        batch=1,
        client=cast(Any, reviewer),
        timeout_ms=1_000,
    )


@pytest.mark.asyncio
async def test_no_overlapping_candidate_registers_without_a_model_call() -> None:
    registry = Registry(bundle_hash="h")
    reviewer = _Reviewer(_answer(decision="DUPLICATE", duplicate_of="x", rationale=""))

    await _consider(registry, _valid(10), reviewer)
    await _consider(registry, _valid(40), reviewer)

    assert len(registry.registered) == 2
    assert reviewer.calls == 0
    assert [s["reason"] for s in registry.states] == ["NO_CANDIDATES", "NO_CANDIDATES"]


@pytest.mark.asyncio
async def test_a_duplicate_naming_a_candidate_is_not_registered() -> None:
    registry = Registry(bundle_hash="h")
    first = await _consider(registry, _valid(10), _Reviewer(None))
    reviewer = _Reviewer(
        _answer(decision="DUPLICATE", duplicate_of=first.hypothesis_id, rationale="")
    )

    second = await _consider(registry, _valid(11), reviewer)

    assert second is None
    assert reviewer.calls == 1
    assert len(registry.registered) == 1
    assert registry.states[-1]["status"] == "DUPLICATE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (_answer(decision="UNIQUE", duplicate_of=None, rationale=""), "UNIQUE"),
        (_answer(decision="UNCERTAIN", duplicate_of=None, rationale=""), "UNCERTAIN"),
        (
            _answer(
                decision="DUPLICATE", duplicate_of="hypothesis-other", rationale=""
            ),
            "INVALID_DUPLICATE_TARGET",
        ),
        (
            StageFailure(code="FAILED", retryable=True, safe_message="down"),
            "CHECK_FAILED",
        ),
    ],
)
async def test_every_other_review_outcome_registers(
    answer: object, reason: str
) -> None:
    """A dropped proposal costs the defect; a duplicate costs one verification."""

    registry = Registry(bundle_hash="h")
    await _consider(registry, _valid(10), _Reviewer(None))

    entry = await _consider(registry, _valid(11), _Reviewer(answer))

    assert entry is not None
    assert len(registry.registered) == 2
    assert registry.states[-1]["reason"] == reason


def test_an_invalid_proposal_is_recorded_not_hidden() -> None:
    registry = Registry(bundle_hash="h")

    registry.record_invalid("B1-P3", 1, ["statement is missing"])

    record = registry.record()
    assert record["outcomes"] == {"INVALID_OUTPUT": 1}
    assert record["states"][0]["errors"] == ["statement is missing"]
