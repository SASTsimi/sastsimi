"""Reducing a bundle to fit must never cost the run its tool findings."""

from __future__ import annotations

from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import _fit_document


def _bundle(
    *,
    facts: int,
    opengrep: int,
    codeql: int,
    fact_pad: int = 80,
    finding_pad: int = 200,
) -> bytes:
    return canonical_bytes(
        {
            "kind": "simple_static_fact_bundle",
            # The AST summary dumps the whole checkout, so it dwarfs the rest.
            "ast_summary": {
                "kind": "simple_python_ast",
                "facts": [
                    {"id": index, "node": "Call", "where": "x" * fact_pad}
                    for index in range(facts)
                ],
            },
            "opengrep_findings": [
                {
                    "rule": f"r{index}",
                    "path": "a.py",
                    "line": index,
                    "pad": "y" * finding_pad,
                }
                for index in range(opengrep)
            ],
            "codeql_findings": [
                {"rule_id": "py/path-injection", "path": "a.py", "line": index}
                for index in range(codeql)
            ],
        }
    )


def _counts(value: Any) -> tuple[int, int, int]:
    return (
        len(value["codeql_findings"]),
        len(value["opengrep_findings"]),
        len(value["ast_summary"]["facts"]),
    )


def test_findings_survive_even_when_they_are_the_longest_list() -> None:
    # The reduction picks the longest list, and a findings list can easily be
    # longer than the AST one while being far smaller in bytes.  Length alone
    # must not decide which evidence the run loses.
    raw = _bundle(facts=200, opengrep=2000, codeql=17, fact_pad=500, finding_pad=8)

    value, size, omitted = _fit_document(raw, 160 * 1024)

    assert size <= 160 * 1024
    assert _counts(value)[:2] == (17, 2000)
    assert _counts(value)[2] < 200
    assert set(omitted) == {"ast_summary.facts"}


def test_findings_yield_only_when_nothing_else_is_left() -> None:
    # No AST at all, so the budget can only come out of the findings; the
    # reduction must still fit rather than give up.
    raw = canonical_bytes(
        {
            "kind": "simple_static_fact_bundle",
            "opengrep_findings": [
                {"rule": f"r{index}", "pad": "y" * 400} for index in range(2000)
            ],
            "codeql_findings": [{"rule_id": "py/x", "line": 1}],
        }
    )

    value, size, omitted = _fit_document(raw, 64 * 1024)

    assert size <= 64 * 1024
    assert len(value["codeql_findings"]) == 1
    assert len(value["opengrep_findings"]) < 2000
    assert "opengrep_findings" in omitted


def test_a_bundle_inside_the_budget_is_untouched() -> None:
    raw = _bundle(facts=5, opengrep=3, codeql=2)

    value, size, omitted = _fit_document(raw, 256 * 1024)

    assert size == len(raw)
    assert omitted == {}
    assert _counts(value) == (2, 3, 5)
