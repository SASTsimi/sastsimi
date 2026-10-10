"""Python-only coverage classification shared by static and report layers."""

import pytest


@pytest.mark.parametrize(
    ("path", "reason", "limits"),
    [
        ("web/APP.TSX", "non_python_product_source", False),
        ("scripts/launch.sh", "declared_non_python_entry", False),
        ("api/types.pyi", "declared_non_python_entry", True),
        ("web/app.ts", "manifest_unverified_possible_product", True),
        ("web/app.js", "unknown_exclusion_reason", True),
        ("web/app.txt", "non_python_product_source", True),
    ],
)
def test_out_of_scope_python_coverage_requires_proven_known_source(
    path: str, reason: str, limits: bool
) -> None:
    from sastsimi.contracts.python_coverage_scope import (
        out_of_scope_limits_python_coverage,
    )

    assert out_of_scope_limits_python_coverage(path, reason) is limits
