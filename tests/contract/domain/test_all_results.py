import pytest
from pydantic import ValidationError

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
    for field in payload:
        with pytest.raises(ValidationError):
            wire(
                binding.model,
                {key: value for key, value in payload.items() if key != field},
            )
    with pytest.raises(ValidationError):
        wire(binding.model, payload | {"automated_disclosure": True})
