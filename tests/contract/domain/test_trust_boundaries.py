from typing import Any

import pytest
from pydantic import ValidationError

from sastsimi.contracts.chaining import Primitive
from sastsimi.contracts.static import AnalysisError

from .canonical_fixtures import make
from .fixtures import wire


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer secret-value",
        "failed at C:\\Users\\private\\key",
        "password=secret-value",
        "read /home/private/key",
    ],
)
def test_error_record_rejects_unsafe_diagnostic_text(text: str) -> None:
    value = make("AnalysisError")
    wire(AnalysisError, value)
    with pytest.raises(ValidationError, match="UNSAFE_DIAGNOSTIC"):
        wire(AnalysisError, value | {"safe_message": text})


def test_primitive_body_scope_cannot_disagree_with_metadata() -> None:
    value = make("Primitive")
    wire(Primitive, value)
    with pytest.raises(ValidationError, match="WORKSPACE_MISMATCH"):
        wire(Primitive, value | {"workspace_id": "other-workspace"})


def test_run_summary_counts_are_immutable_after_validation() -> None:
    from sastsimi.contracts.evaluation import AnalysisRunResult

    result = wire(AnalysisRunResult, make("AnalysisRunResult"))
    counts: Any = result.hypothesis_counts
    with pytest.raises(TypeError):
        counts["registered"] = 100
