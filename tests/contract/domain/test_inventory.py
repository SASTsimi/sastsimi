"""The committed result inventory must match executable models and schemas."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def canonical_inventory() -> dict[str, tuple[str, str]]:
    document = json.loads(
        (ROOT / "schemas/result-owner-inventory.json").read_text(encoding="utf-8")
    )
    return {
        item["result_kind"]: (item["schema_name"], item["owner"])
        for item in document["results"]
    }


def test_every_approved_result_has_model_owner_and_export() -> None:
    expected = canonical_inventory()
    assert len(expected) == 50
    assert importlib.util.find_spec("sastsimi.contracts.result_registry") is not None, (
        f"Missing result registry for {len(expected)} canonical result kinds"
    )
    from sastsimi.contracts.result_registry import RESULT_REGISTRY
    from sastsimi.contracts.schema_export import schema_documents

    assert set(RESULT_REGISTRY) == set(expected)
    for kind, (name, owner) in expected.items():
        binding = RESULT_REGISTRY[kind]
        assert binding.schema_name == name
        assert binding.owner.value == owner
        assert f"{kind}/1.schema.json" in schema_documents()


def test_result_field_names_and_required_nulls_match_canonical_blocks() -> None:
    from sastsimi.contracts.analysis import AnalysisRunInput
    from sastsimi.contracts.result_registry import RESULT_REGISTRY

    for kind, binding in RESULT_REGISTRY.items():
        schema_path = ROOT / "schemas/generated" / kind / "1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema_fields = set(schema["properties"])
        schema_optional = schema_fields - set(schema.get("required", ()))

        assert set(binding.model.model_fields) == schema_fields, kind
        # Only this exact model's five additive restart fields can be absent
        # when reading legacy rows. Nullable fields elsewhere remain required.
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
        actual_optional = {
            name
            for name, field in binding.model.model_fields.items()
            if not field.is_required()
        }
        assert actual_optional == legacy_optional, kind
        assert schema_optional == legacy_optional, kind
        assert all(
            binding.model.model_fields[name].default is None for name in legacy_optional
        ), kind
