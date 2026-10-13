"""The standing findings index stays within a byte budget, however many
distinct (tool, file, rule) groups a repository has.

Grouping by file and rule already holds the index to a size independent of
how often one rule repeats in one place, but romm's 1195 distinct groups
still made the index 170KB on its own - included, unchanged, in every one of
a run's batches, it pushed every hypothesis-generation call over the
provider's own prompt-length limit regardless of the batch's own file
content, and HYPOTHESIS_DONE came back with zero proposals for the whole
run. Busiest groups (the most repeated rule in one file) are kept first; how
many were dropped is reported rather than left silent.
"""

from __future__ import annotations

import json

from sastsimi.simple_runtime.bootstrap_stages import (
    _FINDINGS_INDEX_BUDGET,
    _findings_index,
)


def _bundle_with_groups(n: int) -> dict[str, object]:
    return {
        "opengrep_findings": [
            {"path": f"app/mod_{index}.py", "rule_id": f"rule.id.r{index}", "line": 1}
            for index in range(n)
        ],
        "codeql_findings": [],
    }


def test_the_index_stays_under_budget_with_many_distinct_groups() -> None:
    index = _findings_index(_bundle_with_groups(2_000))

    # The per-group budget check does not account for the surrounding JSON
    # array's own punctuation or the trailing omission marker, so the real
    # total lands a little above the budget rather than exactly at it - the
    # point is that it stays close, not that it grows unbounded with the
    # group count the way the unbudgeted version did (170KB for 1195 groups).
    size = len(json.dumps(index, ensure_ascii=False).encode("utf-8"))
    assert size <= _FINDINGS_INDEX_BUDGET + 2_000
    assert index[-1] == {"omitted_groups": 2_000 - (len(index) - 1)}


def test_a_small_repository_keeps_every_group_and_no_omission_marker() -> None:
    index = _findings_index(_bundle_with_groups(5))

    assert len(index) == 5
    assert all("omitted_groups" not in entry for entry in index)


def test_the_busiest_rule_in_one_file_survives_before_rare_ones() -> None:
    bundle: dict[str, object] = {
        "opengrep_findings": [
            {"path": "app/hot.py", "rule_id": "rule.hot", "line": line}
            for line in range(1, 400)
        ]
        + [
            {"path": f"app/rare_{index}.py", "rule_id": f"rule.rare.{index}", "line": 1}
            for index in range(2_000)
        ],
        "codeql_findings": [],
    }

    index = _findings_index(bundle)

    assert index[0]["path"] == "app/hot.py"
    assert index[0]["count"] == 399
