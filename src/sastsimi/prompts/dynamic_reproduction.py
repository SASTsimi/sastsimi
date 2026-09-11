"""Provider-independent seed metadata for the five T11 prompt stages."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True, slots=True)
class DynamicPromptSeed:
    task_kind: str
    result_kind: str
    template_path: Path
    template_sha256: str
    session_policy: Literal["NEW", "AUTO"]
    sandbox_tools: bool


DYNAMIC_REPRODUCTION_PROMPTS = (
    DynamicPromptSeed(
        "DERIVE_ENVIRONMENT",
        "environment_requirements",
        Path(
            "src/sastsimi/prompts/templates/dynamic-reproduction/"
            "derive-environment/1.0.0.md"
        ),
        "e42066453312daddded880cb325f3ebdcaf2b0d7575969055aeba47990884a83",
        "NEW",
        False,
    ),
    DynamicPromptSeed(
        "PLAN_REPRODUCTION",
        "reproduction_plan",
        Path(
            "src/sastsimi/prompts/templates/dynamic-reproduction/"
            "plan-reproduction/1.0.0.md"
        ),
        "9b8518ed5ad6d6179a6fc7244938b545fb983f5455db71864af439e1e3ab5fcf",
        "NEW",
        False,
    ),
    DynamicPromptSeed(
        "CREATE_POC_CANDIDATE",
        "poc_candidate",
        Path(
            "src/sastsimi/prompts/templates/dynamic-reproduction/"
            "create-poc-candidate/1.0.0.md"
        ),
        "16fa34ba35bc15c28e58163589677ae50fe5680f3a2ce1e05185ad9b93324625",
        "NEW",
        False,
    ),
    DynamicPromptSeed(
        "EXECUTE_REPRODUCTION",
        "dynamic_reproduction_tool_request",
        Path(
            "src/sastsimi/prompts/templates/dynamic-reproduction/"
            "execute-reproduction/1.0.0.md"
        ),
        "2064b4a105dab672dfaba0668dae8eab19ffa271ac2e63a51223652ba60825e3",
        "AUTO",
        True,
    ),
    DynamicPromptSeed(
        "INTERPRET_ATTEMPT",
        "dynamic_reproduction_conclusion",
        Path(
            "src/sastsimi/prompts/templates/dynamic-reproduction/"
            "interpret-attempt/1.0.0.md"
        ),
        "c46923266a672fd07e414fe28e89497aff253f41e30a728a3f933fac8c1b6fde",
        "NEW",
        False,
    ),
)


__all__ = ["DYNAMIC_REPRODUCTION_PROMPTS", "DynamicPromptSeed"]
