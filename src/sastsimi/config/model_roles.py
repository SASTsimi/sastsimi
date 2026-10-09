"""Deterministic Agent model selection within one configured provider."""

from __future__ import annotations

from collections.abc import Mapping

ALL_AGENT_NAMES = frozenset(
    {
        "discovery",
        "hypothesis",
        "hypothesis_survey",
        "hypothesis_batch",
        "hypothesis_surface",
        "hypothesis_page",
        "pro_evidence",
        "con_evidence",
        "initial_verification",
        "poc_candidate",
        "poc_interpretation",
        "verification_result",
        "cwe_label",
        "technical_gate",
        "rule_scope_gate",
        "chaining",
        "report_draft",
        "recovery",
    }
)

LIGHT_AGENT_NAMES = frozenset({"cwe_label", "report_draft"})


def effective_agent_models(
    primary_model: str,
    light_model: str | None,
    overrides: Mapping[str, str],
) -> dict[str, str]:
    """Resolve known roles; an explicit override always wins."""
    return {
        name: overrides.get(
            name,
            light_model
            if light_model is not None and name in LIGHT_AGENT_NAMES
            else primary_model,
        )
        for name in sorted(ALL_AGENT_NAMES)
    }


def model_for_agent(
    primary_model: str, agent_models: Mapping[str, str], agent_name: str
) -> str:
    """Keep unrecognized future roles on the primary model."""
    return agent_models.get(agent_name, primary_model)


__all__ = [
    "ALL_AGENT_NAMES",
    "LIGHT_AGENT_NAMES",
    "effective_agent_models",
    "model_for_agent",
]
