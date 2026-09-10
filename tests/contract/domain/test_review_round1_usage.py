from typing import Any

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.evaluation import UsageMeasurement

from .canonical_fixtures import make
from .fixtures import wire


@pytest.mark.parametrize("target", ["map", "nested", "list"])
def test_r17_nested_provider_units_cannot_change_after_construction(
    target: str,
) -> None:
    value = make("UsageMeasurement") | dict(
        provider_units={"nested": {"rows": [1, {"count": 2}]}},
        token_source="UNAVAILABLE",
        input_tokens=None,
        output_tokens=None,
        total_tokens=None,
        token_unavailable_reason="not reported",
        cost_source="UNAVAILABLE",
        cost_minor_units=None,
        currency=None,
        pricing_revision_ref=None,
        cost_unavailable_reason="not reported",
    )
    usage = wire(UsageMeasurement, value)
    before = content_hash(usage)
    units: Any = usage.provider_units
    with pytest.raises((TypeError, AttributeError)):
        if target == "map":
            units["new"] = 3
        elif target == "nested":
            units["nested"]["rows"][1]["count"] = 5
        else:
            units["nested"]["rows"].append(9)
    assert content_hash(usage) == before
    assert UsageMeasurement.model_validate_json(usage.model_dump_json()) == usage
    assert UsageMeasurement.model_validate(usage.model_dump()) == usage
