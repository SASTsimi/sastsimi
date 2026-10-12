"""v8 coverage must not promote local evidence into attack-path coverage."""

from __future__ import annotations

from sastsimi.simple_runtime.surface_coverage_v6 import (
    _relevant_anchor_path_ids,
    _target_reasons,
    _usable_v8_path_id,
)
from sastsimi.simple_runtime.surface_enrichment_v8 import V8ValidatedResponse


def test_relevant_anchor_paths_keep_distinct_route_alternatives() -> None:
    graph = {
        "paths": [
            {
                "path_id": "route-a",
                "steps": [
                    {"role": "ROUTE_ENTRY", "path": "api.py", "line": 1},
                    {"role": "SINK", "path": "auth.py", "line": 9},
                ],
            },
            {
                "path_id": "route-b",
                "steps": [
                    {"role": "ROUTE_ENTRY", "path": "api.py", "line": 2},
                    {"role": "SINK", "path": "auth.py", "line": 9},
                ],
            },
            {
                "path_id": "other-anchor",
                "steps": [
                    {"role": "ROUTE_ENTRY", "path": "api.py", "line": 3},
                    {"role": "SINK", "path": "auth.py", "line": 10},
                ],
            },
        ]
    }

    assert _relevant_anchor_path_ids(graph, "auth.py", 9) == {
        "route-a",
        "route-b",
    }


def test_target_reasons_do_not_cover_local_only_or_unreviewed_route() -> None:
    inherited = {"CONNECTED_ROLE_PROOF_MISSING", "SURFACE_EVIDENCE_INSUFFICIENT"}

    assert "LOCAL_ONLY_ATTACK_PATH_UNVERIFIED" in _target_reasons(
        inherited,
        relevant_paths={"route-a"},
        verified_paths=set(),
        all_parts_present=True,
        unavailable_items=False,
        local_reviewed=True,
        child_reasons=set(),
    )
    assert "UNREVIEWED_RELEVANT_PATH" in _target_reasons(
        inherited,
        relevant_paths={"route-a", "route-b"},
        verified_paths={"route-a"},
        all_parts_present=True,
        unavailable_items=False,
        local_reviewed=False,
        child_reasons=set(),
    )


def test_target_reasons_clear_only_superseded_graph_reasons() -> None:
    assert (
        _target_reasons(
            {"CONNECTED_ROLE_PROOF_MISSING", "SURFACE_EVIDENCE_INSUFFICIENT"},
            relevant_paths={"route-a"},
            verified_paths={"route-a"},
            all_parts_present=True,
            unavailable_items=False,
            local_reviewed=False,
            child_reasons=set(),
        )
        == set()
    )
    assert _target_reasons(
        {"CONNECTED_ROLE_PROOF_MISSING", "STATIC_SCAN_UNVERIFIED"},
        relevant_paths={"route-a"},
        verified_paths={"route-a"},
        all_parts_present=True,
        unavailable_items=False,
        local_reviewed=False,
        child_reasons=set(),
    ) == {"STATIC_SCAN_UNVERIFIED"}


def test_target_reasons_reject_claimed_path_absent_from_graph_inventory() -> None:
    assert "CONNECTED_ROLE_PROOF_MISSING" in _target_reasons(
        set(),
        relevant_paths=set(),
        verified_paths={"stale-route"},
        all_parts_present=True,
        unavailable_items=False,
        local_reviewed=False,
        child_reasons=set(),
    )


def test_insufficient_agent_verdict_does_not_certify_complete_route() -> None:
    checked = V8ValidatedResponse(
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        reason="Missing exploit precondition",
        qualified=(),
        verified_roles=(),
        reviewed_parts=frozenset({"ENTRY", "TRUST_BOUNDARY", "ANCHOR"}),
        evidence_locations=("app.py:3",),
        verified_path_id="route-a",
        proof_level="CONNECTED",
    )

    assert _usable_v8_path_id(checked) is None
