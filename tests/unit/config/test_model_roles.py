from __future__ import annotations

from importlib import import_module

from sastsimi.config.user_config import UserConfig


def test_light_tier_does_not_route_security_decisions_to_light_model() -> None:
    roles = import_module("sastsimi.config.model_roles")
    routes = roles.effective_agent_models("primary", "light", {})

    assert routes["cwe_label"] == "light"
    assert routes["report_draft"] == "light"
    for role in (
        "discovery",
        "hypothesis_survey",
        "hypothesis_batch",
        "hypothesis_surface",
        "hypothesis_page",
        "pro_evidence",
        "poc_candidate",
        "verification_result",
        "technical_gate",
        "rule_scope_gate",
        "recovery",
    ):
        assert routes[role] == "primary"


def test_explicit_override_wins_and_unknown_role_uses_primary_model() -> None:
    roles = import_module("sastsimi.config.model_roles")
    routes = roles.effective_agent_models(
        "primary", "light", {"cwe_label": "special", "discovery": "review"}
    )

    assert roles.model_for_agent("primary", routes, "cwe_label") == "special"
    assert roles.model_for_agent("primary", routes, "discovery") == "review"
    assert roles.model_for_agent("primary", routes, "new_future_agent") == "primary"


def test_all_observed_discovery_roles_accept_explicit_models() -> None:
    overrides = {
        role: "account-model"
        for role in (
            "discovery",
            "hypothesis_survey",
            "hypothesis_batch",
            "hypothesis_surface",
            "hypothesis_page",
        )
    }

    assert UserConfig.safe_agent_models(overrides) == overrides
