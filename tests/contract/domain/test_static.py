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


def static_tool_profile(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "meta": meta("static_tool_profile", attempt=None),
        "profile_key": "python-ast-fixture",
        "purpose": "FIXTURE",
        "status": "APPROVED",
        "adapter_key": "PYTHON_AST",
        "tool_name": "AST",
        "tool_kind": "STRUCTURE",
        "executable_key": "trusted-python",
        "executable_sha256": "a" * 64,
        "expected_version": "3.12.0",
        "capability_evidence_ref": None,
        "probe_timeout_ms": 1_000,
        "run_timeout_ms": 30_000,
        "stdout_limit_bytes": 1_024,
        "stderr_limit_bytes": 1_024,
        "max_attempt_output_bytes": 4_096,
        "max_output_file_bytes": 2_048,
        "max_artifact_read_bytes": 2_048,
    }
    return value | changes


@pytest.mark.parametrize(
    ("adapter_key", "tool_name", "tool_kind"),
    [
        ("PYTHON_AST", "AST", "STRUCTURE"),
        ("CODEQL", "CODEQL", "RULE_BASED"),
        ("OPENGREP", "OPENGREP", "RULE_BASED"),
    ],
)
def test_static_tool_profile_accepts_only_closed_adapter_tuple(
    adapter_key: str, tool_name: str, tool_kind: str
) -> None:
    from sastsimi.contracts.static import StaticToolProfile

    wire(
        StaticToolProfile,
        static_tool_profile(
            adapter_key=adapter_key,
            tool_name=tool_name,
            tool_kind=tool_kind,
        ),
    )
    with pytest.raises(ValidationError, match="STATIC_TOOL_PROFILE_TUPLE_MISMATCH"):
        wire(
            StaticToolProfile,
            static_tool_profile(
                adapter_key=adapter_key,
                tool_name="AST" if tool_name != "AST" else "CODEQL",
                tool_kind=tool_kind,
            ),
        )


def test_static_tool_profile_enforces_scope_status_and_limits() -> None:
    from sastsimi.contracts.static import StaticToolProfile

    active = static_tool_profile(
        purpose="PRODUCTION",
        status="ACTIVE",
        host_id="host-a",
        capability_evidence_ref={
            "stored_data_id": "tool_capability_evidence-id",
            "data_kind": "tool_capability_evidence",
            "content_hash": "a" * 64,
            "configuration_scope": "HOST",
            "host_id": "host-a",
            "publication_analysis_id": "a1",
            "publication_workspace_id": "ws1",
            "publication_commit_id": "c1",
            "record_id": "tool_capability_evidence-record",
        },
    )
    wire(StaticToolProfile, active)
    invalid = (
        {"meta": meta("static_tool_profile")},
        {"purpose": "PRODUCTION", "status": "ACTIVE"},
        {
            "purpose": "FIXTURE",
            "status": "ACTIVE",
            "capability_evidence_ref": ref("tool_capability_evidence"),
        },
        {"purpose": "PRODUCTION", "status": "APPROVED"},
        {"probe_timeout_ms": 0},
        {"executable_sha256": "not-a-digest"},
        {"expected_version": ""},
    )
    for patch in invalid:
        with pytest.raises(ValidationError):
            wire(StaticToolProfile, static_tool_profile(**patch))


def test_host_capability_evidence_reference_kind_is_exact() -> None:
    from sastsimi.contracts.static import StaticToolProfile

    active = static_tool_profile(
        purpose="PRODUCTION",
        status="ACTIVE",
        host_id="host-a",
        capability_evidence_ref={
            "stored_data_id": "wrong-kind-id",
            "data_kind": "runtime_capability_profile",
            "content_hash": "a" * 64,
            "configuration_scope": "HOST",
            "host_id": "host-a",
            "publication_analysis_id": "a1",
            "publication_workspace_id": "ws1",
            "publication_commit_id": "c1",
            "record_id": "wrong-kind-record",
        },
    )

    with pytest.raises(ValidationError, match="REFERENCE_KIND_MISMATCH"):
        wire(StaticToolProfile, active)
