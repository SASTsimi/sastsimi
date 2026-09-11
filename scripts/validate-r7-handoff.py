"""Validate the R7 handoff prompt fixtures without external dependencies."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "docs" / "handoff" / "R7" / "validation"
TASK_CASES = VALIDATION / "prompt-tasks"

TASKS: dict[str, dict[str, Any]] = {
    "DERIVE_ENVIRONMENT": {
        "slug": "derive-environment",
        "slots": {
            "request": "REQUIRED_ONE",
            "dependency_context": "REQUIRED_ONE",
            "dependency_files": "OPTIONAL_MANY",
        },
        "schema": "environment_requirements",
    },
    "PLAN_REPRODUCTION": {
        "slug": "plan-reproduction",
        "slots": {
            "request": "REQUIRED_ONE",
            "requirements": "REQUIRED_ONE",
            "dependency_context": "REQUIRED_ONE",
            "dependency_files": "OPTIONAL_MANY",
        },
        "schema": "reproduction_plan",
    },
    "CREATE_POC_CANDIDATE": {
        "slug": "create-poc-candidate",
        "slots": {
            "request": "REQUIRED_ONE",
            "plan": "REQUIRED_ONE",
            "environment": "REQUIRED_ONE",
        },
        "schema": "poc_candidate",
    },
    "EXECUTE_REPRODUCTION": {
        "slug": "execute-reproduction",
        "slots": {
            "request": "REQUIRED_ONE",
            "requirements": "REQUIRED_ONE",
            "plan": "REQUIRED_ONE",
            "environment": "REQUIRED_ONE",
            "candidate": "OPTIONAL_ONE",
            "agent_log": "REQUIRED_ONE",
            "prior_turns": "OPTIONAL_MANY",
            "observations": "OPTIONAL_MANY",
        },
        "schema": "dynamic_reproduction_tool_request",
    },
    "INTERPRET_ATTEMPT": {
        "slug": "interpret-attempt",
        "slots": {
            "request": "REQUIRED_ONE",
            "plan": "REQUIRED_ONE",
            "environment": "REQUIRED_ONE",
            "candidate": "OPTIONAL_ONE",
            "agent_log": "REQUIRED_ONE",
            "observations": "OPTIONAL_MANY",
        },
        "schema": "dynamic_reproduction_conclusion",
    },
}

REQUIRED_CATEGORIES = {
    "NORMAL_OUTPUT",
    "SCHEMA_ERROR",
    "SEMANTIC_ERROR",
    "PROMPT_INJECTION",
    "STALE_REFERENCE",
}


class ValidationFailure(AssertionError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationFailure(f"{path}: top-level JSON value must be an object")
    return value


def _matches_type(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }[expected]


def validate_schema(
    value: Any,
    schema: dict[str, Any],
    *,
    root_schema: dict[str, Any] | None = None,
    location: str = "$",
) -> None:
    root_schema = root_schema or schema
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise ValidationFailure(f"{location}: external schema ref is unsupported")
        target: Any = root_schema
        for part in ref[2:].split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        validate_schema(value, target, root_schema=root_schema, location=location)
        return
    for keyword in ("oneOf", "anyOf"):
        if keyword in schema:
            matches = 0
            for option in schema[keyword]:
                try:
                    validate_schema(
                        value, option, root_schema=root_schema, location=location
                    )
                except ValidationFailure:
                    continue
                matches += 1
            expected_matches = 1 if keyword == "oneOf" else None
            if matches == 0 or (expected_matches is not None and matches != 1):
                raise ValidationFailure(f"{location}: {keyword} did not match")
            return
    if "const" in schema and value != schema["const"]:
        raise ValidationFailure(f"{location}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValidationFailure(f"{location}: value is outside enum")
    expected_types = schema.get("type")
    if expected_types is not None:
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        if not any(_matches_type(value, item) for item in expected_types):
            raise ValidationFailure(f"{location}: invalid type")
    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        if missing:
            raise ValidationFailure(f"{location}: missing fields {missing}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                validate_schema(
                    item,
                    properties[key],
                    root_schema=root_schema,
                    location=f"{location}.{key}",
                )
            elif isinstance(additional, dict):
                validate_schema(
                    item,
                    additional,
                    root_schema=root_schema,
                    location=f"{location}.{key}",
                )
            elif additional is False:
                raise ValidationFailure(f"{location}: unexpected field {key}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ValidationFailure(f"{location}: too few items")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_schema(
                    item,
                    schema["items"],
                    root_schema=root_schema,
                    location=f"{location}[{index}]",
                )
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValidationFailure(f"{location}: string is too short")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValidationFailure(f"{location}: string does not match pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValidationFailure(f"{location}: number is below minimum")


def _apply_mutations(value: dict[str, Any], mutations: list[dict[str, Any]]) -> None:
    for mutation in mutations:
        parts = [part for part in mutation["path"].split("/") if part]
        parent: Any = value
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        key = parts[-1]
        if mutation["op"] == "remove":
            if isinstance(parent, list):
                parent.pop(int(key))
            else:
                parent.pop(key)
        elif isinstance(parent, list):
            parent[int(key)] = mutation.get("value")
        else:
            parent[key] = mutation.get("value")


def _is_stale(suite: dict[str, Any], scenario: dict[str, Any]) -> bool:
    slots = copy.deepcopy(suite["base_input_slots"])
    for override in scenario.get("input_scope_overrides", []):
        slots[override["slot"]][override["index"]]["scope"][override["field"]] = (
            override["value"]
        )
    expected_scope = suite["scope"]
    return any(
        binding["scope"] != expected_scope
        for bindings in slots.values()
        for binding in bindings
    )


def _single_payload(suite: dict[str, Any], slot: str) -> dict[str, Any]:
    return suite["base_input_slots"][slot][0]["payload"]


def _record_id(reference: Any) -> Any:
    return reference.get("record_id") if isinstance(reference, dict) else reference


def semantic_valid(task: str, suite: dict[str, Any], output: dict[str, Any]) -> bool:
    request = _single_payload(suite, "request")
    if _record_id(output.get("request_ref")) != request["record_id"]:
        return False
    if task == "DERIVE_ENVIRONMENT":
        required_sources = {
            source["record_id"]
            for need in request["environment_needs"]
            if need["required"]
            for source in need["source_refs"]
        }
        covered = {
            source["record_id"]
            for item in output["items"]
            if item["required"]
            for source in item["source_refs"]
        }
        return required_sources <= covered
    if task == "PLAN_REPRODUCTION":
        requirements = _single_payload(suite, "requirements")
        return (
            output["reproduction_goal"] == request["goal"]
            and _record_id(output["environment_requirements_ref"])
            == suite["base_input_slots"]["requirements"][0]["ref"]
            and _record_id(requirements["request_ref"]) == request["record_id"]
        )
    if task == "CREATE_POC_CANDIDATE":
        environment = _single_payload(suite, "environment")
        return (
            environment["status"] == "READY"
            and _record_id(output["reproduction_plan_ref"])
            == suite["base_input_slots"]["plan"][0]["ref"]
            and output["content_digest"] == output["content_ref"]["content_hash"]
        )
    if task == "EXECUTE_REPRODUCTION":
        environment = _single_payload(suite, "environment")
        action = output["action"]
        shape = {
            "RUN_COMMAND": (
                output["command"] is not None
                and output["poc_candidate_ref"] is None
                and output["recreate_reason"] is None
            ),
            "USE_POC_CANDIDATE": (
                output["command"] is None
                and output["poc_candidate_ref"] is not None
                and output["recreate_reason"] is None
            ),
            "REQUEST_SANDBOX_RECREATE": (
                output["command"] is None
                and output["poc_candidate_ref"] is None
                and output["recreate_reason"] is not None
            ),
            "FINISH": (
                output["command"] is None
                and output["poc_candidate_ref"] is None
                and output["recreate_reason"] is None
            ),
        }[action]
        return environment["status"] == "READY" and shape
    if task == "INTERPRET_ATTEMPT":
        observations = [
            item["payload"] for item in suite["base_input_slots"]["observations"]
        ]
        if output["proposed_outcome"] == "SUPPORTED":
            return bool(output["hypothesis_evidence_refs"]) and any(
                item.get("supports_hypothesis") for item in observations
            )
        if output["proposed_outcome"] == "DISPROVED":
            return any(
                item.get("normal_test_completed") and item.get("counterevidence")
                for item in observations
            )
        return bool(output["limitations"])
    raise ValidationFailure(f"Unknown task: {task}")


def _expected_disposition(
    task: str, suite: dict[str, Any], scenario: dict[str, Any]
) -> str:
    if _is_stale(suite, scenario):
        return "BLOCK_STALE_INPUT"
    output = copy.deepcopy(suite["base_candidate_output"])
    _apply_mutations(output, scenario.get("output_mutations", []))
    schema_name = TASKS[task]["schema"]
    schema = load_json(ROOT / "schemas" / "generated" / schema_name / "1.schema.json")
    try:
        validate_schema(output, schema)
    except ValidationFailure:
        return "REJECT_SCHEMA"
    if not semantic_valid(task, suite, output):
        return "REJECT_SEMANTIC"
    if scenario.get("untrusted_injections"):
        serialized = json.dumps(output, sort_keys=True)
        for injection in scenario["untrusted_injections"]:
            if injection["text"] in serialized or '"TRUE"' in serialized:
                return "REJECT_SEMANTIC"
    return "ACCEPT_OUTPUT"


def _check_cardinality(name: str, values: list[Any], cardinality: str) -> None:
    count = len(values)
    valid = {
        "REQUIRED_ONE": count == 1,
        "OPTIONAL_ONE": count <= 1,
        "REQUIRED_MANY": count >= 1,
        "OPTIONAL_MANY": True,
    }[cardinality]
    if not valid:
        raise ValidationFailure(f"{name}: cardinality {cardinality} rejected {count}")


def validate_task_suites() -> int:
    case_schema = load_json(VALIDATION / "prompt-task-case.schema.json")
    expectation_schema = load_json(VALIDATION / "prompt-task-expectation.schema.json")
    count = 0
    for task, config in TASKS.items():
        directory = TASK_CASES / config["slug"]
        suite = load_json(directory / "cases.input.json")
        expected = load_json(directory / "cases.expected.json")
        validate_schema(suite, case_schema)
        validate_schema(expected, expectation_schema)
        if suite["suite_id"] != expected["suite_id"] or suite["task_kind"] != task:
            raise ValidationFailure(f"{task}: suite identity mismatch")
        if expected["task_kind"] != task:
            raise ValidationFailure(f"{task}: expectation task mismatch")
        slots = suite["base_input_slots"]
        if set(slots) != set(config["slots"]):
            raise ValidationFailure(f"{task}: input slot set mismatch")
        for name, cardinality in config["slots"].items():
            _check_cardinality(f"{task}.{name}", slots[name], cardinality)
        scenarios = {item["scenario_id"]: item for item in suite["scenarios"]}
        expected_cases = {item["scenario_id"]: item for item in expected["cases"]}
        if set(scenarios) != set(expected_cases):
            raise ValidationFailure(f"{task}: scenario pair mismatch")
        categories = {item["category"] for item in scenarios.values()}
        if categories != REQUIRED_CATEGORIES:
            raise ValidationFailure(f"{task}: missing required scenario categories")
        for scenario_id, scenario in scenarios.items():
            for injection in scenario.get("untrusted_injections", []):
                if injection["slot"] not in config["slots"]:
                    raise ValidationFailure(f"{task}: injection uses forbidden slot")
            actual = _expected_disposition(task, suite, scenario)
            wanted = expected_cases[scenario_id]["expected_disposition"]
            if actual != wanted:
                raise ValidationFailure(
                    f"{task}.{scenario_id}: expected {wanted}, observed {actual}"
                )
            count += 1
    return count


def validate_lifecycle_pairs() -> int:
    case_schema = load_json(VALIDATION / "validation-case.schema.json")
    expectation_schema = load_json(VALIDATION / "validation-expectation.schema.json")
    inputs = sorted(VALIDATION.glob("*.input.json"))
    count = 0
    for input_path in inputs:
        expected_path = input_path.with_name(
            input_path.name.replace(".input.json", ".expected.json")
        )
        if not expected_path.exists():
            raise ValidationFailure(f"Missing pair for {input_path.name}")
        case = load_json(input_path)
        expected = load_json(expected_path)
        validate_schema(case, case_schema)
        validate_schema(expected, expectation_schema)
        if case["case_id"] != expected["case_id"]:
            raise ValidationFailure(f"{input_path.name}: case_id mismatch")
        for collection_name in ("dependency_files", "project_artifacts"):
            for artifact in case.get("records", {}).get(collection_name, []):
                path = VALIDATION / artifact["path"]
                actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != artifact["content_hash"]:
                    raise ValidationFailure(f"{input_path.name}: hash mismatch {path}")
                if "content" in artifact:
                    embedded = (
                        "sha256:"
                        + hashlib.sha256(artifact["content"].encode()).hexdigest()
                    )
                    if embedded != artifact["content_hash"]:
                        raise ValidationFailure(
                            f"{input_path.name}: embedded content mismatch {path}"
                        )
        count += 1
    return count


def _assert_operator(operator: str, actual: Any, expected: Any = None) -> bool:
    if operator == "EQUALS":
        return actual == expected
    if operator == "NON_NULL":
        return actual is not None
    if operator == "ABSENT":
        return actual is None or actual == [] or actual == {}
    if operator == "CONTAINS":
        return all(item in actual for item in expected)
    if operator == "ALL_EQUAL":
        return all(item == expected for item in actual)
    if operator == "EXCLUDES":
        return all(item not in actual for item in expected)
    if operator == "SAME_SCOPE":
        return all(item == expected for item in actual)
    if operator == "PRODUCED_BY":
        return actual == expected
    raise ValidationFailure(f"Unsupported assertion operator: {operator}")


def exercise_assertion_operators() -> int:
    checks = {
        "EQUALS": _assert_operator("EQUALS", "x", "x"),
        "NON_NULL": _assert_operator("NON_NULL", 0),
        "ABSENT": _assert_operator("ABSENT", None),
        "CONTAINS": _assert_operator("CONTAINS", ["a", "b"], ["a"]),
        "ALL_EQUAL": _assert_operator("ALL_EQUAL", [1, 1], 1),
        "EXCLUDES": _assert_operator("EXCLUDES", ["a"], ["b"]),
        "SAME_SCOPE": _assert_operator("SAME_SCOPE", ["scope", "scope"], "scope"),
        "PRODUCED_BY": _assert_operator(
            "PRODUCED_BY", "DYNAMIC_REPRODUCTION", "DYNAMIC_REPRODUCTION"
        ),
    }
    if not all(checks.values()):
        raise ValidationFailure("Assertion operator self-check failed")
    declared = load_json(VALIDATION / "validation-expectation.schema.json")
    supported = set(
        declared["properties"]["assertions"]["items"]["properties"]["operator"]["enum"]
    )
    if supported != set(checks):
        raise ValidationFailure("Assertion operator implementation drift")
    return len(checks)


def validate_prompt_templates() -> int:
    required_sections = {
        "ROLE_AND_SCOPE",
        "TASK",
        "TRUSTED_RULES",
        "INPUT_SLOTS",
        "UNTRUSTED_DATA_BOUNDARY",
        "DECISION_CRITERIA",
        "OUTPUT_SCHEMA",
        "UNCERTAINTY_AND_ERRORS",
        "FORBIDDEN_BEHAVIOR",
    }
    count = 0
    for config in TASKS.values():
        path = (
            ROOT / "docs" / "handoff" / "R7" / "prompts" / config["slug"] / "1.0.0.md"
        )
        text = path.read_text(encoding="utf-8")
        sections = set(re.findall(r"^## ([A-Z_]+)$", text, re.MULTILINE))
        if sections != required_sections:
            raise ValidationFailure(f"{path}: prompt section mismatch")
        if "common prompt" in text.lower() or "{{TASK_KIND}}" in text:
            raise ValidationFailure(f"{path}: template depends on combined prompt")
        count += 1
    return count


def main() -> None:
    template_count = validate_prompt_templates()
    lifecycle_count = validate_lifecycle_pairs()
    task_case_count = validate_task_suites()
    operator_count = exercise_assertion_operators()
    print(
        "R7 handoff validation passed: "
        f"{template_count} templates, {task_case_count} prompt cases, "
        f"{lifecycle_count} lifecycle pairs, {operator_count} assertion operators"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, TypeError, ValueError, ValidationFailure) as error:
        print(f"R7 handoff validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
