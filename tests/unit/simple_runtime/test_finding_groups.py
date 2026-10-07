from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any, cast

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.candidates import CandidateOrigin
from sastsimi.simple_runtime.finding_flow import FlowAnchor
from sastsimi.simple_runtime.finding_groups import (
    VerifiedFindingMember,
    group_verified_findings,
)


def _ref(digit: str) -> StoredDataRef:
    digest = digit * 64
    return StoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("commit"),
        record_id=None,
    )


def _anchor(*, key: str = "target", sink_line: int = 8) -> FlowAnchor:
    return FlowAnchor(
        route="/ping",
        function="ping",
        source_file="app.py",
        source_line=7,
        source_access="request.args",
        source_key=key,
        def_use_nodes=("target@7",),
        sink_file="app.py",
        sink_line=sink_line,
        sink_callee="os.system",
        sink_argument=0,
        branch_nodes=(),
        cwe="CWE-78",
    )


def _member(
    display_id: str,
    anchor: FlowAnchor | None = None,
    *,
    engine: str = "codeql",
    scope: str = "UNCERTAIN",
) -> VerifiedFindingMember:
    return VerifiedFindingMember(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        display_id=display_id,
        finding_ref=_ref("a"),
        hypothesis_id=f"hyp-{display_id}",
        validated_poc_ref=_ref("b"),
        proposal_ref=_ref("c"),
        cwe_ref=_ref("d"),
        candidate_ids=(f"candidate-{display_id}",),
        candidate_origins=(
            CandidateOrigin(
                engine=engine, rule_id="rule", artifact_ref=_ref("e"), result_index=1
            ),
        ),
        scope_status=scope,
        anchor=anchor,
        undetermined_reason=None if anchor else "FLOW_NOT_RESOLVED",
    )


def test_same_verified_flow_groups_cross_engine_and_keeps_original_evidence() -> None:
    codeql = _member("F-009", _anchor())
    opengrep = _member("F-002", _anchor(), engine="opengrep")
    surface = replace(
        _member("F-010", _anchor()), candidate_ids=(), candidate_origins=()
    )
    result = group_verified_findings((codeql, surface, opengrep))
    assert (
        result.raw_count,
        result.visible_group_count,
        result.undetermined_count,
    ) == (3, 1, 0)
    group = result.groups[0]
    assert group.representative_id == "F-002"
    assert group.member_ids == ("F-002", "F-009", "F-010")
    assert group.status == "PROVEN_SAME_FLOW"
    assert group.members[0].validated_poc_ref == opengrep.validated_poc_ref
    assert group.members[0].candidate_origins[0].engine == "opengrep"
    assert group.members[2].candidate_ids == ()


def test_one_codeql_trace_and_an_untraced_flow_remain_separate() -> None:
    traced = replace(_anchor(), trace_nodes=("app.py:7:5", "app.py:8:5"))
    result = group_verified_findings(
        (
            _member("F-001", traced, engine="codeql"),
            _member("F-002", _anchor(), engine="opengrep"),
        )
    )

    assert result.raw_count == 2
    assert result.visible_group_count == 2
    assert tuple(group.member_ids for group in result.groups) == (
        ("F-001",),
        ("F-002",),
    )


def test_untraced_flow_does_not_bridge_distinct_codeql_trace_paths() -> None:
    first = replace(_anchor(), trace_nodes=("app.py:7:5", "app.py:8:5"))
    second = replace(_anchor(), trace_nodes=("app.py:7:5", "app.py:9:5"))
    result = group_verified_findings(
        (
            _member("F-001", first),
            _member("F-002", second),
            _member("F-003", _anchor(), engine="opengrep"),
        )
    )

    assert result.raw_count == result.visible_group_count == 3
    assert all(len(group.member_ids) == 1 for group in result.groups)


def test_distinct_path_and_undetermined_stay_separate() -> None:
    entries = (
        _member("F-001", _anchor()),
        _member("F-002", _anchor(key="other")),
        _member("F-003", _anchor(sink_line=9)),
        _member("F-004"),
        _member("F-005"),
    )
    result = group_verified_findings(entries)
    assert (
        result.raw_count,
        result.visible_group_count,
        result.undetermined_count,
    ) == (5, 5, 2)
    assert result.groups[-2].group_id != result.groups[-1].group_id
    assert all(
        group.member_ids == (member.display_id,)
        for group, member in zip(result.groups, entries, strict=True)
    )


def test_scope_is_not_upgraded_and_projection_is_stable_across_reads() -> None:
    members = (
        _member("F-010", _anchor(), scope="IN_SCOPE"),
        _member("F-002", _anchor(), scope="UNCERTAIN"),
    )
    first = group_verified_findings(members)
    reversed_result = group_verified_findings(tuple(reversed(members)))
    repeated = group_verified_findings(members)
    assert first == reversed_result == repeated
    assert first.groups[0].scope_status == "MIXED"
    assert {member.scope_status for member in first.groups[0].members} == {
        "IN_SCOPE",
        "UNCERTAIN",
    }


def test_workspace_and_commit_are_part_of_group_identity() -> None:
    members = (
        _member("F-001", _anchor()),
        replace(_member("F-002", _anchor()), commit_id="different-commit"),
    )
    result = group_verified_findings(members)
    assert result.visible_group_count == 2
    assert result.groups[0].group_id != result.groups[1].group_id


@pytest.mark.parametrize(
    "change",
    [
        {"source_key": "other"},
        {"source_access": "request.form"},
        {"source_line": 6},
        {"route": "/different"},
        {"function": "other_handler"},
        {"def_use_nodes": ("other@7",)},
        {"sink_line": 9},
        {"sink_callee": "subprocess.run"},
        {"branch_nodes": ("if:8:yes",)},
        {"cwe": "CWE-89"},
    ],
)
def test_different_proven_flow_dimensions_never_merge(
    change: dict[str, object],
) -> None:
    first = _anchor()
    second = replace(first, **cast(Any, change))
    result = group_verified_findings(
        (_member("F-001", first), _member("F-002", second))
    )
    assert result.raw_count == result.visible_group_count == 2


def test_existing_command_flow_group_id_remains_stable_on_resume() -> None:
    anchor = _anchor()
    key = {
        "version": "verified-python-flow-v1",
        "analysis_id": "analysis",
        "workspace_id": "workspace",
        "commit_id": "commit",
        "flow": {
            key: value for key, value in asdict(anchor).items() if key != "trace_nodes"
        },
    }
    expected = hashlib.sha256(
        json.dumps(
            key, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    result = group_verified_findings((_member("F-001", anchor),))
    assert result.groups[0].group_id == expected


def test_existing_undetermined_singleton_group_id_remains_stable() -> None:
    member = _member("F-001")
    key = {
        "version": "verified-python-flow-v1",
        "analysis_id": "analysis",
        "workspace_id": "workspace",
        "commit_id": "commit",
        "singleton_display_id": "F-001",
        "hypothesis_id": member.hypothesis_id,
        "finding_hash": member.finding_ref.content_hash,
    }
    expected = hashlib.sha256(
        json.dumps(
            key, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    result = group_verified_findings((member,))
    assert result.groups[0].group_id == expected
