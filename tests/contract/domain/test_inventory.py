"""The committed result inventory must match executable models and schemas."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def _field_hint(schema: dict[str, object], definitions: dict[str, object]) -> str:
    """Translate a JSON Schema field into the compact fixture hint vocabulary."""
    reference = schema.get("$ref")
    if isinstance(reference, str):
        name = reference.rsplit("/", 1)[-1]
        target = definitions.get(name)
        if isinstance(target, dict) and "properties" not in target:
            return _field_hint(target, definitions)
        return name

    variants = schema.get("anyOf")
    if isinstance(variants, list):
        hints = [
            "null"
            if isinstance(item, dict) and item.get("type") == "null"
            else _field_hint(item, definitions)
            for item in variants
            if isinstance(item, dict)
        ]
        return " | ".join(hints)

    enum = schema.get("enum")
    if isinstance(enum, list):
        return " | ".join(str(item) for item in enum)

    constant = schema.get("const")
    if constant is not None:
        return str(constant)

    schema_type = schema.get("type")
    if schema_type == "array":
        items = schema.get("items")
        return (
            f"[{_field_hint(items, definitions)}]" if isinstance(items, dict) else "[]"
        )
    if schema_type == "object":
        return "map"
    if schema_type == "string":
        if schema.get("format") == "date-time":
            return "timestamp"
        if schema.get("minLength") == 64 and schema.get("maxLength") == 64:
            return "sha256"
        return "string"
    if schema_type in {"integer", "number", "boolean"}:
        return str(schema_type)
    return "string"


def canonical_fields() -> dict[str, dict[str, str]]:
    """Return fixture field hints derived from executable generated schemas."""
    from sastsimi.contracts.schema_export import schema_documents

    blocks: dict[str, dict[str, str]] = {}
    for raw_document in schema_documents().values():
        document = json.loads(raw_document)
        candidates = [document]
        definitions = document.get("$defs", {})
        if isinstance(definitions, dict):
            candidates.extend(
                definition
                for definition in definitions.values()
                if isinstance(definition, dict)
            )
        for candidate in candidates:
            title = candidate.get("title")
            properties = candidate.get("properties")
            if not isinstance(title, str) or not isinstance(properties, dict):
                continue
            blocks[title] = {
                name: _field_hint(field, definitions)
                for name, field in properties.items()
                if isinstance(name, str) and isinstance(field, dict)
            }
    return blocks


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
