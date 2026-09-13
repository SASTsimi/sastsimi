import pytest
from pydantic import ValidationError

from sastsimi.contracts.analysis import AnalysisRunInput
from sastsimi.contracts.result_registry import RESULT_REGISTRY

from .canonical_fixtures import make
from .fixtures import wire


@pytest.mark.parametrize("kind", tuple(RESULT_REGISTRY))
def test_every_canonical_result_positive_python_wire_and_required_fields(
    kind: str,
) -> None:
    binding = RESULT_REGISTRY[kind]
    payload = make(binding.schema_name, kind)
    parsed = wire(binding.model, payload)
    assert (
        binding.model.model_validate(
            {key: getattr(parsed, key) for key in binding.model.model_fields}
        )
        == parsed
    )
    legacy_optional = (
        {
            "workspace_id",
            "commit_id",
            "production_profile_ref",
            "production_onboarding_ref",
            "production_authority_catalog_ref",
        }
        if binding.model is AnalysisRunInput
        else set()
    )
    assert {
        name
        for name, field in binding.model.model_fields.items()
        if not field.is_required()
    } == legacy_optional
    for field in payload:
        if field in legacy_optional:
            missing = wire(
                binding.model,
                {key: value for key, value in payload.items() if key != field},
            )
            assert getattr(missing, field) is None
            continue
        with pytest.raises(ValidationError):
            wire(
                binding.model,
                {key: value for key, value in payload.items() if key != field},
            )
    with pytest.raises(ValidationError):
        wire(binding.model, payload | {"automated_disclosure": True})
