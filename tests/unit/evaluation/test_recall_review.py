"""A frozen oracle and an after-run review are different inputs."""

from __future__ import annotations

import json

import pytest

from sastsimi.simple_runtime.recall_audit import Oracle, OracleCase


def _review(**changes: object) -> bytes:
    payload: dict[str, object] = {
        "version": 2,
        "analysis_id": "analysis-1",
        "oracle_sha256": "a" * 64,
        "inventory_reviewed": True,
        "cases": [
            {
                "case_id": "case-1",
                "candidate_ids": ["candidate-1"],
                "hypothesis_ids": ["hypothesis-1"],
                "finding_ids": ["F-001"],
                "rationale": "the exact input and operation match",
            }
        ],
        "findings": [
            {
                "finding_id": "F-001",
                "status": "MATCHED",
                "case_id": "case-1",
                "evidence": "reviewed the current PoC and source path",
            }
        ],
    }
    payload.update(changes)
    return json.dumps(payload).encode("utf-8")


def test_post_run_links_do_not_mutate_frozen_oracle() -> None:
    from sastsimi.simple_runtime.recall_review import load_review, reviewed_oracle

    oracle = Oracle(
        repository="https://example.test/python-repo",
        commit="a" * 40,
        cases=(
            OracleCase(
                case_id="case-1",
                cwe="CWE-89",
                path="app.py",
                source_line=10,
                sink_line=20,
                rationale="known flow",
            ),
        ),
        version=2,
        completeness="DOCUMENTED_CASES",
    )

    reviewed = reviewed_oracle(oracle, load_review(_review()), complete_inventory=True)

    assert oracle.cases[0].vetted_candidate_ids == ()
    assert oracle.cases[0].finding_inventory_reviewed is False
    assert reviewed.cases[0].vetted_candidate_ids == ("candidate-1",)
    assert reviewed.cases[0].vetted_hypothesis_ids == ("hypothesis-1",)
    assert reviewed.cases[0].finding_inventory_reviewed is True


@pytest.mark.parametrize(
    "changes",
    [
        {
            "cases": [
                {"case_id": "case-1", "rationale": "a"},
                {"case_id": "case-1", "rationale": "b"},
            ]
        },
        {
            "findings": [
                {
                    "finding_id": "F-001",
                    "status": "MATCHED",
                    "case_id": "case-1",
                    "evidence": "a",
                },
                {
                    "finding_id": "F-001",
                    "status": "MATCHED",
                    "case_id": "case-1",
                    "evidence": "b",
                },
            ]
        },
        {
            "findings": [
                {"finding_id": "F-001", "status": "FALSE_POSITIVE", "evidence": ""}
            ]
        },
        {
            "findings": [
                {"finding_id": "F-001", "status": "MATCHED", "evidence": "no case"}
            ]
        },
    ],
)
def test_review_rejects_duplicate_or_unsubstantiated_records(
    changes: dict[str, object],
) -> None:
    from sastsimi.simple_runtime.recall_review import load_review

    with pytest.raises(ValueError):
        load_review(_review(**changes))


def test_review_rejects_unknown_case_mapping() -> None:
    from sastsimi.simple_runtime.recall_review import load_review, reviewed_oracle

    oracle = Oracle(
        repository="https://example.test/python-repo",
        commit="a" * 40,
        cases=(OracleCase("case-1", "CWE-89", "app.py", 10, 20, "known flow"),),
        version=2,
    )
    review = load_review(
        _review(
            cases=[{"case_id": "different", "rationale": "wrong case"}], findings=[]
        )
    )

    with pytest.raises(ValueError, match="RECALL_REVIEW_CASE_MISMATCH"):
        reviewed_oracle(oracle, review, complete_inventory=False)


def test_review_rejects_case_finding_without_matching_adjudication() -> None:
    from sastsimi.simple_runtime.recall_review import load_review

    with pytest.raises(ValueError):
        load_review(_review(findings=[]))
