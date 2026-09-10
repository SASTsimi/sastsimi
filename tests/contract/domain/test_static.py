import importlib
from typing import Any

import pytest
from pydantic import ValidationError

from .fixtures import bundle, location, meta, mutations, ref, tool, wire


def test_static_family_is_implemented() -> None:
    assert importlib.util.find_spec("sastsimi.contracts.static") is not None


def test_zero_hits_are_not_nonexecution() -> None:
    from sastsimi.contracts.static import RuleExecutionItem

    zero: dict[str, Any] = dict(
        rule_id="r",
        selection_status="SELECTED",
        execution_status="EXECUTED",
        hit_count=0,
        reason=None,
        detail=None,
    )
    assert wire(RuleExecutionItem, zero).hit_count == 0
    for patch in mutations(
        dict(execution_status="NOT_EXECUTED"),
        dict(selection_status="NOT_SELECTED"),
        dict(hit_count=None),
        dict(reason="OTHER"),
    ):
        with pytest.raises(ValidationError):
            wire(RuleExecutionItem, zero | patch)


def test_static_required_fields_and_scope() -> None:
    from sastsimi.contracts.static import StaticFactBundle, ToolRunResult

    valid = bundle()
    wire(StaticFactBundle, valid)
    for field in valid:
        with pytest.raises(ValidationError):
            wire(StaticFactBundle, {k: v for k, v in valid.items() if k != field})
    for patch in mutations(
        dict(meta=meta("wrong", attempt=None)),
        dict(locations=[location() | {"commit_id": "other"}]),
        dict(meta=meta("static_fact_bundle")),
    ):
        with pytest.raises(ValidationError):
            wire(StaticFactBundle, valid | patch)
    with pytest.raises(ValidationError):
        wire(ToolRunResult, tool() | {"status": "PARTIAL"})


def test_fact_partition_and_producer_are_exact() -> None:
    from sastsimi.contracts.static import StaticFactBundle

    fact: dict[str, Any] = dict(
        fact_id="f1",
        fact_kind="SOURCE",
        symbol_id=None,
        location=location(),
        producer=dict(
            attempt_id="at1",
            tool_name="ast",
            tool_version="1",
            rule_id=None,
            raw_result_ref=ref("raw", record=False),
        ),
    )
    valid = bundle() | dict(source_candidates=[fact])
    wire(StaticFactBundle, valid)
    for patch in mutations(
        dict(sink_candidates=[fact]),
        dict(source_candidates=[fact | {"fact_kind": "SINK"}]),
        dict(
            source_candidates=[
                fact | {"producer": fact["producer"] | {"attempt_id": "old"}}
            ]
        ),
    ):
        with pytest.raises(ValidationError):
            wire(StaticFactBundle, valid | patch)


@pytest.mark.parametrize(
    "path", ["/etc/passwd", "C:/secret", "a/../b", "./x", "a\\b", ""]
)
def test_code_location_rejects_non_git_paths(path: str) -> None:
    from sastsimi.contracts.static import CodeLocation

    with pytest.raises(ValidationError):
        wire(CodeLocation, location() | {"file_path": path})
