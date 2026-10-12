"""The v4 Agent contract must expose the exact pinned context hash."""

import pytest

from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.surface_evidence_validation_v4 import (
    v4_reviewable_parts,
)


def test_navigation_only_graph_has_no_reviewable_security_role() -> None:
    assert (
        v4_reviewable_parts(
            [{"role": "CANDIDATE"}, {"role": "CALL"}, {"role": "CALLEE_BODY_LINE"}]
        )
        == frozenset()
    )
    assert v4_reviewable_parts(
        [{"role": "ROUTE_ENTRY"}, {"role": "REQUEST_CONTEXT"}, {"role": "SINK"}]
    ) == frozenset({"ENTRY", "TRUST_BOUNDARY", "SENSITIVE_OPERATION"})


def test_v4_schema_pins_review_context_hash() -> None:
    context_hash = "a" * 64
    schema = DirectHypothesisBootstrap._surface_schema(
        "surface-id",
        "context-id",
        version=4,
        context_hash=context_hash,
        eligible_review_parts=frozenset({"ENTRY"}),
    )

    review = schema["properties"]["review_evidence"]["items"]
    assert review["properties"]["context_hash"] == {
        "type": "string",
        "enum": [context_hash],
    }
    assert review["properties"]["part"]["enum"] == ["ENTRY"]


def test_v4_schema_forbids_review_claims_without_graph_roles() -> None:
    schema = DirectHypothesisBootstrap._surface_schema(
        "surface-id",
        "context-id",
        version=4,
        context_hash="a" * 64,
        eligible_review_parts=frozenset(),
    )

    assert schema["properties"]["review_evidence"]["maxItems"] == 0


def test_v4_schema_rejects_missing_context_hash() -> None:
    with pytest.raises(ValueError, match="HYPOTHESIS_SURFACE_CONTEXT_INVALID"):
        DirectHypothesisBootstrap._surface_schema(
            "surface-id",
            "context-id",
            version=4,
            eligible_review_parts=frozenset(),
        )
