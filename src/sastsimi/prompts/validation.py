"""Ordered output validation: JSON Schema, contract model, role semantics."""

import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMRole
from sastsimi.contracts.result_registry import RESULT_REGISTRY

_ROLE_RESULT_KINDS: Mapping[str, frozenset[str]] = {
    "HYPOTHESIS": frozenset({"hypothesis_proposal", "hypothesis_duplicate_review"}),
    "PRO": frozenset({"pro_evidence_result"}),
    "CON": frozenset({"con_evidence_result"}),
    "VERIFICATION": frozenset(
        {
            "verification_initial_assessment",
            "dynamic_reproduction_request",
            "verification_result",
        }
    ),
    "POLICY_PARSER": frozenset({"policy_parser_result"}),
    "DYNAMIC_REPRODUCTION": frozenset(
        {
            "environment_requirements",
            "reproduction_plan",
            "poc_candidate",
            "dynamic_reproduction_tool_request",
            "dynamic_reproduction_conclusion",
        }
    ),
    "CHAINING": frozenset({"chaining_result"}),
    "CWE_LABELING": frozenset({"cwe_label"}),
    "TECHNICAL_GATE": frozenset({"technical_evidence_review"}),
    "RULE_SCOPE_GATE": frozenset({"rule_scope_impact_review"}),
    "REPORTER": frozenset({"report_draft"}),
}

_SCHEMA_ANNOTATIONS = frozenset(
    {
        "$anchor",
        "$comment",
        "$id",
        "$schema",
        "default",
        "deprecated",
        "description",
        "examples",
        "readOnly",
        "title",
        "writeOnly",
    }
)
_SCHEMA_KEYWORDS = _SCHEMA_ANNOTATIONS | frozenset(
    {
        "$defs",
        "$ref",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "oneOf",
        "pattern",
        "properties",
        "required",
        "type",
        "uniqueItems",
    }
)
_SUPPORTED_FORMATS = frozenset({"date-time"})
_JSON_TYPES = frozenset(
    {"null", "boolean", "integer", "number", "string", "array", "object"}
)


class _SchemaDefinitionError(ValueError):
    pass


class _SchemaMismatch(ValueError):
    pass


def _schema_sequence(value: object, keyword: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise _SchemaDefinitionError(f"invalid JSON Schema {keyword}")
    return value


def _assert_supported_schema(
    schema: object, root: Mapping[str, object] | None = None
) -> None:
    """Reject unknown assertion keywords instead of silently failing open."""
    if isinstance(schema, bool):
        return
    if not isinstance(schema, Mapping):
        raise _SchemaDefinitionError("invalid JSON Schema")
    root = schema if root is None else root
    unknown = set(schema) - _SCHEMA_KEYWORDS
    if unknown:
        raise _SchemaDefinitionError(
            f"unsupported JSON Schema keyword: {sorted(unknown)[0]}"
        )
    definitions = schema.get("$defs", {})
    if not isinstance(definitions, Mapping):
        raise _SchemaDefinitionError("invalid JSON Schema $defs")
    if any(not isinstance(name, str) for name in definitions):
        raise _SchemaDefinitionError("invalid JSON Schema $defs")
    for child in definitions.values():
        _assert_supported_schema(child, root)
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        raise _SchemaDefinitionError("invalid JSON Schema properties")
    if any(not isinstance(name, str) for name in properties):
        raise _SchemaDefinitionError("invalid JSON Schema properties")
    for child in properties.values():
        _assert_supported_schema(child, root)
    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword in schema:
            children = _schema_sequence(schema[keyword], keyword)
            if not children:
                raise _SchemaDefinitionError(f"invalid JSON Schema {keyword}")
            for child in children:
                _assert_supported_schema(child, root)
    if "items" in schema:
        _assert_supported_schema(schema["items"], root)
    additional = schema.get("additionalProperties", True)
    if not isinstance(additional, bool):
        _assert_supported_schema(additional, root)
    if "$ref" in schema:
        reference = schema["$ref"]
        if not isinstance(reference, str):
            raise _SchemaDefinitionError("invalid JSON Schema reference")
        _pointer(root, reference)
    expected_type = schema.get("type")
    if expected_type is not None:
        types = (expected_type,) if isinstance(expected_type, str) else expected_type
        if (
            not isinstance(types, Sequence)
            or isinstance(types, (str, bytes))
            or not types
            or any(item not in _JSON_TYPES for item in types)
        ):
            raise _SchemaDefinitionError("invalid JSON Schema type")
    required = schema.get("required", ())
    if (
        not isinstance(required, Sequence)
        or isinstance(required, (str, bytes))
        or any(not isinstance(name, str) for name in required)
        or len(set(required)) != len(required)
    ):
        raise _SchemaDefinitionError("invalid JSON Schema required")
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, Sequence) or isinstance(enum, (str, bytes)) or not enum:
            raise _SchemaDefinitionError("invalid JSON Schema enum")
    for keyword in (
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minProperties",
        "maxProperties",
    ):
        limit = schema.get(keyword)
        if limit is not None and (
            not isinstance(limit, int) or isinstance(limit, bool) or limit < 0
        ):
            raise _SchemaDefinitionError(f"invalid JSON Schema {keyword}")
    for keyword in (
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
    ):
        limit = schema.get(keyword)
        if limit is not None and (
            not isinstance(limit, (int, float)) or isinstance(limit, bool)
        ):
            raise _SchemaDefinitionError(f"invalid JSON Schema {keyword}")
    multiple = schema.get("multipleOf")
    if isinstance(multiple, (int, float)) and not isinstance(multiple, bool):
        if multiple <= 0:
            raise _SchemaDefinitionError("invalid JSON Schema multipleOf")
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise _SchemaDefinitionError("invalid JSON Schema uniqueItems")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise _SchemaDefinitionError("invalid JSON Schema pattern")
        try:
            re.compile(schema["pattern"])
        except re.error as error:
            raise _SchemaDefinitionError("invalid JSON Schema pattern") from error
    if "format" in schema and schema["format"] not in _SUPPORTED_FORMATS:
        raise _SchemaDefinitionError("unsupported JSON Schema format")


def _json_type(value: object, expected: str) -> bool:
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }.get(expected, False)


def _json_equal(left: object, right: object) -> bool:
    """Compare JSON values without Python's bool/int equality collapse."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if isinstance(left, (int, float)) or isinstance(right, (int, float)):
        return (
            isinstance(left, (int, float))
            and not isinstance(left, bool)
            and isinstance(right, (int, float))
            and not isinstance(right, bool)
            and left == right
        )
    if isinstance(left, Mapping) or isinstance(right, Mapping):
        return (
            isinstance(left, Mapping)
            and isinstance(right, Mapping)
            and set(left) == set(right)
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(a, b) for a, b in zip(left, right, strict=True))
        )
    return type(left) is type(right) and left == right


def _pointer(root: Mapping[str, object], pointer: str) -> object:
    if not pointer.startswith("#/"):
        raise _SchemaDefinitionError("unsupported JSON Schema reference")
    value: object = root
    for raw in pointer[2:].split("/"):
        name = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, Mapping) or name not in value:
            raise _SchemaDefinitionError("unresolved JSON Schema reference")
        value = value[name]
    return value


def _validate_schema(
    value: object,
    schema: object,
    root: Mapping[str, object],
    path: str = "$",
) -> None:
    if isinstance(schema, bool):
        if not schema:
            raise _SchemaMismatch(path)
        return
    if not isinstance(schema, Mapping):
        raise _SchemaDefinitionError("invalid JSON Schema")
    if "$ref" in schema:
        _validate_schema(value, _pointer(root, str(schema["$ref"])), root, path)
    if "allOf" in schema:
        candidates = _schema_sequence(schema["allOf"], "allOf")
        for candidate in candidates:
            _validate_schema(value, candidate, root, path)
    for keyword in ("anyOf", "oneOf"):
        if keyword not in schema:
            continue
        candidates = _schema_sequence(schema[keyword], keyword)
        matches = 0
        for candidate in candidates:
            try:
                _validate_schema(value, candidate, root, path)
            except _SchemaMismatch:
                continue
            matches += 1
        if matches == 0 or (keyword == "oneOf" and matches != 1):
            raise _SchemaMismatch(path)
    expected_type = schema.get("type")
    if expected_type is not None:
        types: object = (
            (expected_type,) if isinstance(expected_type, str) else expected_type
        )
        if not isinstance(types, Sequence) or not all(
            isinstance(item, str) for item in types
        ):
            raise _SchemaDefinitionError("invalid JSON Schema type")
        if not any(_json_type(value, item) for item in types):
            raise _SchemaMismatch(path)
    if "const" in schema and not _json_equal(value, schema["const"]):
        raise _SchemaMismatch(path)
    if "enum" in schema:
        choices = schema["enum"]
        if not isinstance(choices, Sequence) or isinstance(choices, (str, bytes)):
            raise _SchemaDefinitionError("invalid JSON Schema enum")
        if not any(_json_equal(value, choice) for choice in choices):
            raise _SchemaMismatch(path)
    if isinstance(value, dict):
        required = schema.get("required", ())
        if not isinstance(required, Sequence) or isinstance(required, (str, bytes)):
            raise _SchemaDefinitionError("invalid JSON Schema required")
        if any(not isinstance(name, str) or name not in value for name in required):
            raise _SchemaMismatch(path)
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise _SchemaDefinitionError("invalid JSON Schema properties")
        additional = schema.get("additionalProperties", True)
        for name, item in value.items():
            if name in properties:
                _validate_schema(item, properties[name], root, f"{path}/{name}")
            elif additional is False:
                raise _SchemaMismatch(f"{path}/{name}")
            elif isinstance(additional, Mapping):
                _validate_schema(item, additional, root, f"{path}/{name}")
        if "minProperties" in schema and len(value) < int(schema["minProperties"]):
            raise _SchemaMismatch(path)
        if "maxProperties" in schema and len(value) > int(schema["maxProperties"]):
            raise _SchemaMismatch(path)
    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise _SchemaMismatch(path)
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise _SchemaMismatch(path)
        if schema.get("uniqueItems") is True and len(
            {json.dumps(item, sort_keys=True) for item in value}
        ) != len(value):
            raise _SchemaMismatch(path)
        if "items" in schema:
            for index, item in enumerate(value):
                _validate_schema(item, schema["items"], root, f"{path}/{index}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            raise _SchemaMismatch(path)
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            raise _SchemaMismatch(path)
        if "pattern" in schema and re.search(str(schema["pattern"]), value) is None:
            raise _SchemaMismatch(path)
        if schema.get("format") == "date-time":
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as error:
                raise _SchemaMismatch(path) from error
            if parsed.tzinfo is None:
                raise _SchemaMismatch(path)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            raise _SchemaMismatch(path)
        if isinstance(maximum, (int, float)) and value > maximum:
            raise _SchemaMismatch(path)
        exclusive_minimum = schema.get("exclusiveMinimum")
        exclusive_maximum = schema.get("exclusiveMaximum")
        if isinstance(exclusive_minimum, (int, float)) and value <= exclusive_minimum:
            raise _SchemaMismatch(path)
        if isinstance(exclusive_maximum, (int, float)) and value >= exclusive_maximum:
            raise _SchemaMismatch(path)
        multiple = schema.get("multipleOf")
        if isinstance(multiple, (int, float)):
            if multiple <= 0:
                raise _SchemaDefinitionError("invalid JSON Schema multipleOf")
            quotient = value / multiple
            if abs(quotient - round(quotient)) > 1e-12:
                raise _SchemaMismatch(path)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate output key")
        result[key] = value
    return result


def _invalid_constant(name: str) -> object:
    raise ValueError(f"invalid constant {name}")


def validate_output(
    raw: bytes,
    *,
    json_schema: Mapping[str, object],
    result_kind: str,
    agent_role: LLMRole,
    semantic_validator: Callable[[ContractModel], None],
) -> ContractModel:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_invalid_constant,
        )
        _assert_supported_schema(json_schema)
        _validate_schema(value, json_schema, json_schema)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError("PROMPT_OUTPUT_SCHEMA_INVALID") from error
    binding = RESULT_REGISTRY.get(result_kind)
    if binding is None or result_kind not in _ROLE_RESULT_KINDS.get(agent_role, ()):
        raise ValueError("PROMPT_OUTPUT_ROLE_MISMATCH")
    try:
        result = binding.model.model_validate_json(canonical_bytes(value))
    except ValueError as error:
        raise ValueError("PROMPT_OUTPUT_MODEL_INVALID") from error
    try:
        semantic_validator(result)
    except ValueError as error:
        raise ValueError("PROMPT_OUTPUT_SEMANTIC_INVALID") from error
    return result
