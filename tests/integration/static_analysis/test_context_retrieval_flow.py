"""Canonical Context plans bind every authorized request axis."""

from dataclasses import replace

import pytest

from sastsimi.ports.context import RelationQuery
from sastsimi.static_analysis.context_retrieval import (
    context_request_fingerprint,
    decode_context_read_plan,
    encode_context_read_plan,
)
from tests.unit.static_analysis.test_context_retrieval import _fixture, _plan


def test_canonical_plan_round_trip_and_request_fingerprint_are_stable() -> None:
    _, symbols = _fixture()
    plan = _plan("CALLERS", symbols["seed"])
    raw = encode_context_read_plan(plan)

    assert decode_context_read_plan(raw) == plan
    assert context_request_fingerprint(
        plan, "a1", "h1", ("CALLERS",)
    ) == context_request_fingerprint(plan, "a1", "h1", ("CALLERS",))


@pytest.mark.parametrize(
    "changed",
    ("analysis", "hypothesis", "query", "profile", "limits", "paths"),
)
def test_request_fingerprint_changes_with_every_authorized_axis(changed: str) -> None:
    _, symbols = _fixture()
    original = _plan("CALLERS", symbols["seed"])
    plan = original
    analysis_id = "a1"
    hypothesis_id = "h1"
    query: tuple[RelationQuery, ...] = ("CALLERS",)
    if changed == "analysis":
        analysis_id = "a2"
    elif changed == "hypothesis":
        hypothesis_id = "h2"
    elif changed == "query":
        query = ("CALLEES",)
    elif changed == "profile":
        plan = replace(
            plan,
            ceiling_profile_ref=plan.ceiling_profile_ref.model_copy(
                update={"stored_data_id": "f" * 64, "content_hash": "f" * 64}
            ),
        )
    elif changed == "limits":
        plan = replace(
            plan,
            requested_limits=plan.requested_limits.model_copy(
                update={"max_fragments": plan.requested_limits.max_fragments + 1}
            ),
        )
    elif changed == "paths":
        plan = replace(plan, file_paths=(*plan.file_paths, "src/extra.py"))

    assert context_request_fingerprint(
        plan, analysis_id, hypothesis_id, query
    ) != context_request_fingerprint(original, "a1", "h1", ("CALLERS",))
