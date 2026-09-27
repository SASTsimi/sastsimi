from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.opengrep_rule_batches import (
    RuleBatchPlan,
    aggregate_rule_batches,
    parse_rule_batch,
    plan_rule_batches,
)


def _rules(*ids: str) -> bytes:
    lines = ["rules:"]
    for rule_id in ids:
        lines.extend(
            (
                f"  - id: {rule_id}",
                "    languages: [python]",
                "    message: test",
                "    severity: INFO",
                "    pattern: foo(...)",
            )
        )
    return ("\n".join(lines) + "\n").encode()


def _plan(*ids: str, batch_size: int = 3) -> RuleBatchPlan:
    return plan_rule_batches(
        _rules(*ids),
        tool_version="1.30.0",
        executable_sha256="a" * 64,
        batch_size=batch_size,
    )


def _artifacts(tmp_path: Path) -> SimpleArtifactRepository:
    return SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )


def test_plan_partitions_every_rule_once() -> None:
    plan = _plan(*(f"rule.{index}" for index in range(7)))
    assert plan.rule_languages == (("python",),) * 7

    assert [len(batch.rule_ids) for batch in plan.batches] == [3, 3, 1]
    assert (
        tuple(rule_id for batch in plan.batches for rule_id in batch.rule_ids)
        == plan.rule_ids
    )
    assert len({rule_id for batch in plan.batches for rule_id in batch.rule_ids}) == 7
    assert len({batch.key for batch in plan.batches}) == 3
    for batch in plan.batches:
        assert set(batch.excluded_rule_ids) == set(plan.rule_ids) - set(batch.rule_ids)
    assert (
        plan.fingerprint != _plan(*(f"rule.{index}" for index in range(6))).fingerprint
    )
    assert (
        plan.fingerprint
        != plan_rule_batches(
            _rules(*(f"rule.{index}" for index in range(7))),
            tool_version="1.30.1",
            executable_sha256="a" * 64,
        ).fingerprint
    )
    assert (
        plan.fingerprint
        != _plan(*(f"rule.{index}" for index in range(7)), batch_size=2).fingerprint
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"rules: []\n",
        _rules("rule.dup", "rule.dup"),
        b"rules:\n  - id: 123\n",
        b"rules: !!python/object/apply:os.system ['echo bad']\n",
        b"[]\n",
        b"rules:\n  - id: rule.first\nrules:\n  - id: rule.second\n",
        b"rules:\n  - id: rule.first\n    id: rule.second\n",
    ],
)
def test_invalid_rule_catalog_fails_closed(raw: bytes) -> None:
    with pytest.raises(ValueError, match="OPENGREP_RULE_CATALOG_INVALID"):
        plan_rule_batches(
            raw,
            tool_version="1.30.0",
            executable_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    ("raw", "error_code"),
    [
        (b"{", "OPENGREP_RESULT_INVALID"),
        (b'{"results": {}}', "OPENGREP_RESULT_INVALID"),
        (b'{"results": [4]}', "OPENGREP_RESULT_INVALID"),
        (b'{"results": [{"check_id": "rule.one"}]}', "OPENGREP_RESULT_INVALID"),
        (
            b'{"results": [{"check_id": "rule.one", "path": "a.py", '
            b'"start": {"line": 0}}]}',
            "OPENGREP_RESULT_INVALID",
        ),
        (
            b'{"results": [], "errors": [{"message": "timeout"}], "errors": []}',
            "OPENGREP_RESULT_INVALID",
        ),
        (b'{"results": [], "errors": [], "time": NaN}', "OPENGREP_RESULT_INVALID"),
        (
            b'{"results": [{"check_id": "rule.other"}]}',
            "OPENGREP_BATCH_RULE_MISMATCH",
        ),
        (
            b'{"results": [], "errors": [{"message": "timeout"}]}',
            "OPENGREP_PARTIAL_SCAN",
        ),
    ],
)
def test_parse_rejects_wrong_rule_or_error(raw: bytes, error_code: str) -> None:
    batch = _plan("rule.one", "rule.two").batches[0]
    with pytest.raises(ValueError, match=error_code):
        parse_rule_batch(raw, batch)


def test_partial_json_can_be_inspected_without_weakening_strict_default() -> None:
    batch = _plan("rule.one").batches[0]
    raw = (
        b'{"results": [], "errors": [{"path": "a.py", '
        b'"type": "PartialParsing"}], "paths": {"scanned": '
        b'["a.py"], "skipped": []}}'
    )
    errors = parse_rule_batch(raw, batch, allow_errors=True)["errors"]
    assert isinstance(errors, list)
    assert len(errors) == 1
    with pytest.raises(ValueError, match="OPENGREP_PARTIAL_SCAN"):
        parse_rule_batch(raw, batch)


def test_partial_json_still_rejects_unknown_rule() -> None:
    batch = _plan("rule.one").batches[0]
    raw = (
        b'{"results": [{"check_id": "rule.unknown", '
        b'"path": "a.py", "start": {"line": 1}}], "errors": []}'
    )
    with pytest.raises(ValueError, match="OPENGREP_BATCH_RULE_MISMATCH"):
        parse_rule_batch(raw, batch, allow_errors=True)


def test_round_robin_keeps_later_rule_visible(tmp_path: Path) -> None:
    plan = _plan("rule.first", "rule.later", batch_size=1)
    first_raw = json.dumps(
        {
            "results": [
                {
                    "check_id": "rule.first",
                    "path": "app.py",
                    "start": {"line": line},
                }
                for line in range(1, 502)
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"], "skipped": []},
        }
    ).encode()
    later_raw = json.dumps(
        {
            "results": [
                {
                    "check_id": "rule.later",
                    "path": "other.py",
                    "start": {"line": 3},
                }
            ],
            "errors": [],
            "paths": {"scanned": ["other.py"], "skipped": []},
        }
    ).encode()
    artifacts = _artifacts(tmp_path)
    accepted = (
        (
            plan.batches[0],
            artifacts.put_bytes(first_raw, "application/json"),
            parse_rule_batch(first_raw, plan.batches[0]),
        ),
        (
            plan.batches[1],
            artifacts.put_bytes(later_raw, "application/json"),
            parse_rule_batch(later_raw, plan.batches[1]),
        ),
    )

    aggregate = json.loads(aggregate_rule_batches(plan, accepted))

    assert len(aggregate["results"]) == 502
    assert aggregate["results"][1]["check_id"] == "rule.later"
    assert aggregate["candidate_snippet_limit"] == 500
    assert aggregate["candidate_snippets_truncated"] is True
    assert [batch["rule_ids"] for batch in aggregate["batches"]] == [
        ["rule.first"],
        ["rule.later"],
    ]
    assert aggregate["batches"][0]["paths"]["scanned"] == ["app.py"]
    assert aggregate["batches"][1]["raw_ref"] == accepted[1][1].model_dump(mode="json")


def test_aggregate_rejects_missing_batch(tmp_path: Path) -> None:
    plan = _plan("rule.first", "rule.later", batch_size=1)
    raw = b'{"results": [], "errors": []}'
    accepted = (
        (
            plan.batches[0],
            _artifacts(tmp_path).put_bytes(raw, "application/json"),
            parse_rule_batch(raw, plan.batches[0]),
        ),
    )

    with pytest.raises(ValueError, match="OPENGREP_BATCH_SET_INCOMPLETE"):
        aggregate_rule_batches(plan, accepted)
