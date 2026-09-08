"""The approved owner registry must have executable schemas for every result."""

import importlib.util
import re
from pathlib import Path


def canonical_inventory() -> dict[str, tuple[str, str]]:
    source = Path("docs/architecture-v5/08-lightweight-data-contracts.md").read_text(
        encoding="utf-8"
    )
    paragraph = next(
        line for line in source.splitlines() if line.startswith("- 핵심 registry")
    )
    return {
        kind: (model, role)
        for kind, model, role in re.findall(
            r"`(\w+) -> (\w+)(?:\(role=\w+\))? -> (\w+)`", paragraph
        )
    }


def test_every_approved_result_has_model_owner_and_export() -> None:
    expected = canonical_inventory()
    assert len(expected) == 41
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


def canonical_fields() -> dict[str, dict[str, str]]:
    source = Path("docs/architecture-v5/08-lightweight-data-contracts.md").read_text(
        encoding="utf-8"
    )
    result: dict[str, dict[str, str]] = {}
    for block in re.findall(r"```yaml\n(.*?)```", source, re.S):
        current: str | None = None
        for line in block.splitlines():
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9]+:", line):
                current = line[:-1]
                result[current] = {}
            elif current and re.match(r"^  [a-z]", line):
                key, value = line.strip().split(":", 1)
                result[current][key] = value.strip()
    return result


def test_result_field_names_and_required_nulls_match_canonical_blocks() -> None:
    from sastsimi.contracts.result_registry import RESULT_REGISTRY

    blocks = canonical_fields()
    for kind, binding in RESULT_REGISTRY.items():
        assert set(binding.model.model_fields) == set(blocks[binding.schema_name]), kind
        assert all(
            field.is_required() for field in binding.model.model_fields.values()
        ), kind
