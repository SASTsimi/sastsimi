import pytest
from pydantic import ValidationError

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.dynamic import PoCBundle
from sastsimi.contracts.result_registry import RESULT_REGISTRY, validate_result_owner
from tests.contract.domain.fixtures import meta, ref, wire


@pytest.mark.parametrize("kind", tuple(RESULT_REGISTRY))
def test_every_result_rejects_wrong_owner_before_serialization(kind: str) -> None:
    binding = RESULT_REGISTRY[kind]
    with pytest.raises(ValueError, match="RESULT_OWNER_MISMATCH"):
        validate_result_owner(
            kind, binding.model.model_construct(), RequesterRole.RECOVERY
        )


def test_candidate_reference_cannot_impersonate_validated_poc_parent() -> None:
    value = dict(
        meta=meta("poc_bundle", hypothesis="h1"),
        request_ref=ref("dynamic_reproduction_request"),
        reproduction_plan_ref=ref("reproduction_plan"),
        environment_recipe_ref=ref("environment_recipe"),
        environment_ref=ref("sandbox_environment"),
        agent_log_ref=ref("agent_log"),
        candidate_ref=ref("poc_candidate"),
        candidate_digest="a" * 64,
        execution_action_id="action",
        evidence_refs=[ref("observation", record=False)],
        validated_at="2026-09-08T00:00:00Z",
    )
    wire(PoCBundle, value)
    with pytest.raises(ValidationError, match="REFERENCE_KIND_MISMATCH"):
        wire(PoCBundle, value | {"environment_ref": ref("poc_candidate")})
