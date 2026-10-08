"""Strict byte parsing for frozen recall oracles."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from sastsimi.simple_runtime.recall_audit import Oracle, OracleCase
from sastsimi.simple_runtime.recall_oracle import parse_oracle_bytes


def _v2_payload(**case_changes: object) -> bytes:
    case: dict[str, object] = {
        "case_id": "guard-1",
        "cwe": "CWE-862",
        "kind": "MISSING_GUARD",
        "path": "routes/admin.py",
        "source_line": 7,
        "sink_path": "services/account.py",
        "sink_line": 12,
        "rationale": "state change lacks authorization",
        "scope": "PYTHON",
    }
    case.update(case_changes)
    return json.dumps(
        {
            "repository": "https://example.test/repo",
            "commit": "a" * 40,
            "cases": [case],
            "version": 2,
            "completeness": "DOCUMENTED_CASES",
        }
    ).encode("utf-8")


def test_parse_oracle_bytes_preserves_legacy_v1_defaults() -> None:
    payload = (
        b'{"repository":"https://example.test/repo","commit":"'
        + b"a" * 40
        + b'","cases":[{"case_id":"legacy","cwe":"CWE-89",'
        b'"path":"src/app.py","source_line":null,"sink_line":12,'
        b'"rationale":"reviewed","vetted_candidate_ids":["candidate-1"],'
        b'"finding_inventory_reviewed":true}]}'
    )

    parsed = parse_oracle_bytes(payload)

    assert parsed == Oracle(
        repository="https://example.test/repo",
        commit="a" * 40,
        cases=(
            OracleCase(
                case_id="legacy",
                cwe="CWE-89",
                path="src/app.py",
                source_line=None,
                sink_line=12,
                rationale="reviewed",
                vetted_candidate_ids=("candidate-1",),
                finding_inventory_reviewed=True,
            ),
        ),
    )


def test_parse_oracle_bytes_preserves_v2_guard_and_distinct_sink_path() -> None:
    parsed = parse_oracle_bytes(_v2_payload())

    assert parsed == Oracle(
        repository="https://example.test/repo",
        commit="a" * 40,
        cases=(
            OracleCase(
                case_id="guard-1",
                cwe="CWE-862",
                kind="MISSING_GUARD",
                path="routes/admin.py",
                source_line=7,
                sink_path="services/account.py",
                sink_line=12,
                rationale="state change lacks authorization",
            ),
        ),
        version=2,
        completeness="DOCUMENTED_CASES",
    )


@pytest.mark.parametrize(
    "case_changes",
    [
        {"sink_path": "../secret.py"},
        {"vetted_hypothesis_ids": ["post-run-id"]},
        {"sink_line": "12"},
        {"unexpected": "field"},
    ],
)
def test_parse_oracle_bytes_rejects_invalid_v2_case(
    case_changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        parse_oracle_bytes(_v2_payload(**case_changes))


def test_parse_oracle_bytes_rejects_duplicate_case_ids() -> None:
    payload = json.loads(_v2_payload())
    payload["cases"].append(dict(payload["cases"][0]))

    with pytest.raises(ValidationError):
        parse_oracle_bytes(json.dumps(payload).encode("utf-8"))
