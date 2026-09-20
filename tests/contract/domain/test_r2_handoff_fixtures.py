"""R2 handoff reference fixtures (docs/handoff/R2/) must stay valid against the
real static-fact contracts. Each *.expected.json file holds exactly one
record; PR #138 review (R3) requires this be verified with an automated test
rather than the CI markdown/link audit alone.
"""

from pathlib import Path

from sastsimi.contracts.static import (
    CodeContextResponse,
    RuleExecutionRecord,
    StaticFactBundle,
)

HANDOFF_DIR = Path("docs/handoff/R2")


def _read(name: str) -> str:
    return (HANDOFF_DIR / name).read_text(encoding="utf-8")


def test_normal_static_fact_bundle_is_valid() -> None:
    StaticFactBundle.model_validate_json(_read("normal.expected.json"))


def test_normal_rule_execution_record_is_valid() -> None:
    RuleExecutionRecord.model_validate_json(
        _read("normal.rule_execution_record.expected.json")
    )


def test_normal_code_context_response_is_valid() -> None:
    CodeContextResponse.model_validate_json(
        _read("normal.code_context_response.expected.json")
    )


def test_failure_static_fact_bundle_is_valid() -> None:
    StaticFactBundle.model_validate_json(_read("failure.expected.json"))


def test_failure_rule_execution_record_is_valid() -> None:
    RuleExecutionRecord.model_validate_json(
        _read("failure.rule_execution_record.expected.json")
    )


def test_normal_tool_runs_are_valid_tool_run_results() -> None:
    """Each StaticFactBundle.tool_runs[] entry is itself a standalone
    ToolRunResult; the bundle-level check above validates them only as
    nested fields, so re-check each one directly against the model too."""
    import json

    from sastsimi.contracts.static import ToolRunResult

    bundle = json.loads(_read("normal.expected.json"))
    for tool_run in bundle["tool_runs"]:
        ToolRunResult.model_validate_json(json.dumps(tool_run))


def test_failure_tool_runs_are_valid_tool_run_results() -> None:
    import json

    from sastsimi.contracts.static import ToolRunResult

    bundle = json.loads(_read("failure.expected.json"))
    for tool_run in bundle["tool_runs"]:
        ToolRunResult.model_validate_json(json.dumps(tool_run))
