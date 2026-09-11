import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.prompts.validation import validate_output
from tests.contract.domain.canonical_fixtures import make


def test_provider_output_cannot_set_runtime_owned_metadata_or_ids() -> None:
    forged = make("HypothesisProposal")

    with pytest.raises(ValueError, match="PROMPT_OUTPUT_AUTHORITY_DENIED"):
        validate_output(
            canonical_bytes(forged),
            json_schema={"type": "object", "additionalProperties": True},
            result_kind="hypothesis_proposal",
            agent_role="HYPOTHESIS",
            semantic_validator=lambda _value: None,
        )
